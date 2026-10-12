#include "Core/Utility/Header/PrecompiledHeader.h"

#include <intrin.h>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Execution/Routine/StartRoutine.h"
#include "System/Handle/HandleHijack.h"
#include "Injection/Injection.h"

// Hijack-thread launch pipeline (SR_HijackThread backend for StartRoutine).
// What: picks a victim thread (sponsor fast path, then 3-tier snapshot
//   search), stages a W^X split stub (RX code page + RW state page, never
//   RWX), redirects RIP, wakes alertable waiters, polls the remote State to
//   Finished, then proves the context restore. Why: runs the mapping shell on
//   a live game thread without creating a thread (CreateRemoteThread is the
//   loudest Warden telemetry). How: suspend/set/resume with a minimal frozen
//   window (alloc+patch happen before suspend); failures funnel to
//   RECOVERY_REQUIRED leaks rather than frees under a live thread.
// Measured thread-hijack outcome, handed to the host via GetLastThreadExecStats.
// The host previously printed "Thread context restored automatically" as a
// fixed string, which asserted a restore that had not been checked; these are
// the values behind it.
static THREAD_EXEC_STATS g_ThreadExecStats{};

namespace
{
	// g_ThreadExecStats is written by the injection thread (field by field,
	// plus ResetThreadExecStats) and read by the export/UI thread through
	// GetLastThreadExecStats with no other synchronization, exactly like the
	// g_LastMapStats slots in ManualMapping.cpp. A plain struct copy is not
	// atomic, so every whole-struct store/load goes through
	// InterlockedExchange / InterlockedCompareExchange, and each field store is
	// an InterlockedExchange - a compiler intrinsic on x64, no new import.
	// THREAD_EXEC_STATS is four DWORDs (static_assert in InjectionTypes.h), so
	// a LONG-stride walk covers it exactly.
	void StoreThreadExecStat(DWORD & Field, DWORD Value)
	{
		InterlockedExchange(ReCa<volatile LONG *>(&Field), static_cast<LONG>(Value));
	}

	void StoreThreadExecStats(const THREAD_EXEC_STATS & Src)
	{
		static_assert(sizeof(THREAD_EXEC_STATS) % sizeof(LONG) == 0, "THREAD_EXEC_STATS must be a whole number of LONGs");

		volatile LONG * dst = ReCa<volatile LONG *>(&g_ThreadExecStats);
		const LONG * src = ReCa<const LONG *>(&Src);
		for (size_t i = 0; i < sizeof(THREAD_EXEC_STATS) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadThreadExecStats(THREAD_EXEC_STATS & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_ThreadExecStats);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(THREAD_EXEC_STATS) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	// Secure-wipe the W^X hijack stub before its RemoteAllocation guard
	// releases it. The block holds the staged shellcode and the SR_REMOTE_DATA
	// state (pArg/pRoutine), and its code page is RX, so it is promoted to RW
	// first (never RWX; the block is released immediately after, so the
	// temporary protection is not restored). The write is bounded and
	// non-throwing: a failed protect or write leaves the block for the guard to
	// free exactly as before.
	void ScrubRemoteRegion(HANDLE hTargetProc, void * base, SIZE_T size)
	{
		if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !base || !size)
		{
			return;
		}

		DWORD old_protect = 0;
		if (!VirtualProtectEx(hTargetProc, base, size, PAGE_READWRITE, &old_protect))
		{
			return;
		}

		BYTE zeros[0x2000] = { 0 };
		BYTE * cursor = ReCa<BYTE *>(base);
		SIZE_T remaining = size;
		while (remaining)
		{
			const SIZE_T chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
			if (!WriteProcessMemory(hTargetProc, cursor, zeros, chunk, nullptr))
			{
				return;
			}

			cursor += chunk;
			remaining -= chunk;
		}
	}

	// Handle-needing probes per search pass. GetTEB (worker check) plus the
	// alertable check each open the target thread, so an unbounded walk
	// opened a game-thread handle for every candidate in the process - a
	// handle-enumeration fingerprint far louder than any single syscall.
	// Snapshot data (state/reason/TID) needs no handle, so it filters first and
	// at most this many candidates are probed. NOTE: the budget counts probed
	// candidates, not handle opens - one candidate can cost up to two opens
	// (worker check + alertable check), hence the small value.
	constexpr DWORD kMaxHandleProbes = 4;

	// Picks one hijackable TID from the current snapshot cursor. What: one
	// pass over the thread list accepting ONLY Running threads, spending at
	// most kMaxHandleProbes handle opens (worker checks only). Params:
	// processInformation (in snapshot cursor), exclude_tid (a TID to skip,
	// normally the smallest/main - 0 disables). Returns: candidate TID or 0
	// when this pass found none. Side effects: advances the enumeration
	// cursor; opens/closes at most 4 thread handles.
	//
	// Running-only is a correctness requirement, not a preference. A thread
	// suspended inside a kernel wait (any Waiting state, alertable or not)
	// holds a stale user-mode Rax (the syscall number, e.g. 0x34 - verified
	// live via GetThreadContext on a Sleeping thread), which push/pop
	// preserves verbatim. Resuming it at the wait's return address hands its
	// caller garbage instead of an NTSTATUS: mutex/protocol waiters proceed
	// as-if-signaled without holding the object (data race), while message
	// loops merely self-heal by re-waiting. There is no safe way to
	// reconstruct the wait result, so waiting threads are never hijacked -
	// the search fails closed (NO_THREADS) instead of corrupting game logic.
	// Alertability is therefore irrelevant and untested; see the deleted
	// IsThreadInAlertableState (its 5-stub decoder, consensus and win32u
	// machinery were removed with it - dead code that could only reintroduce
	// this class).
	DWORD FindHijackThread(ProcessInformation & processInformation, DWORD exclude_tid = 0)
	{
		// The Running value is download-dependent (see g_DynamicOffsets,
		// resolved from ntdll.pdb enums). Fail-closed when not ready: no
		// static fallback here.
		if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
		{
			LOG(2, "FindAcquireThread: dynamic offsets not ready, refusing\n");
			return 0;
		}
		const KTHREAD_STATE running = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
		DWORD probes = 0;
		do
		{
			KWAIT_REASON reason;
			KTHREAD_STATE state;
			if (!processInformation.GetThreadState(state, reason))
			{
				continue;
			}

		const DWORD candidate = processInformation.GetThreadId();
		if (!candidate || candidate == GetCurrentThreadId() || candidate == exclude_tid)
		{
			continue;
		}

			// Handle-free filter: only Running threads are hijackable (see the
			// header note). Everything else is skipped without spending a
			// probe. Ordering matters - the cheap snapshot test is first.
			if (state != running)
			{
				continue;
			}

			// The worker check reads TEB::SameTebFlags, so it needs a handle.
			// It is counted against the same budget: a process full of loader
			// workers would otherwise open one handle per worker thread just
			// to reject each of them.
			if (probes >= kMaxHandleProbes)
			{
				break;
			}
			++probes;

			if (processInformation.IsThreadWorkerThread())
			{
				continue;
			}

			return candidate;
		}
		while (processInformation.NextThread());

		return 0;
	}
}


// ---------------------------------------------------------------------------
// FP/XSAVE capability probe. Runs once per hijack staging and decides whether
// the stub saves the victim's complete FP/SIMD/XSTATE with XSAVE or the older
// legacy-only FXSAVE. The decision is made here, not in the stub, because the
// answer must be identical for the save and the restore and probing in the
// victim's thread would burn rbx and add host-visible instructions to a stub
// whose shape is otherwise fixed per build.
//
// Rules that keep the decision from faulting inside the foreign thread:
//   - XGETBV executes only after CPUID.1:ECX bit 27 (OSXSAVE) confirms the OS
//     enables it; without that bit the instruction is #UD.
//   - the feature mask handed to XSAVE/XRSTOR must be a subset of XCR0
//     (enabled components) or the instruction #GPs, so the mask is XCR0 & 0x7.
//   - the image area must cover exactly the requested components: the 512-byte
//     legacy area plus the 64-byte XSAVE header, plus the architecturally fixed
//     YMM_Hi128 at offset 576/size 256 when AVX is enabled. Leaf 0Dh sub-leaf 0
//     reports the size XCR0 needs and is used as a sanity check that the CPU
//     reports a usable area at all.
//   - XSAVE requires a 64-byte aligned memory operand, so the area offset
//     inside the (page-aligned) state page is checked, not assumed.
// Anything else falls back to FXSAVE, which every x64 CPU implements and which
// still covers the x87 control word, st0-st7, MXCSR and all sixteen xmm
// registers in the same 512 bytes.
// ---------------------------------------------------------------------------
static void ProbeFpCaps(DWORD & OutFlags, DWORD & OutMask, const BYTE * pStatePage)
{
	OutFlags = 0;
	OutMask = 0;

	int regs[4]{};
	__cpuid(regs, 1);

	if ((regs[2] & (1 << 27)) == 0)
	{
		return; // OSXSAVE clear: the OS does not save extended state, and XGETBV is #UD
	}

	const DWORD xcr0 = static_cast<DWORD>(_xgetbv(0));

	DWORD mask = 0;
	if (xcr0 & 0x1)
	{
		mask |= 0x1; // x87
	}
	if (xcr0 & 0x2)
	{
		mask |= 0x2; // SSE (covers MXCSR)
	}
	if (xcr0 & 0x4)
	{
		mask |= 0x4; // AVX (ymm upper halves)
	}

	// x87 + SSE are the non-negotiable core: without both, FXSAVE covers the
	// same set with fewer preconditions, so the XSAVE path buys nothing.
	if ((mask & 0x3) != 0x3)
	{
		return;
	}

	const DWORD needed = (mask & 0x4) ? (576 + 256) : 576;

	if (needed > SR_FP_AREA_SIZE)
	{
		return;
	}

	__cpuidex(regs, 0xD, 0);
	const DWORD reported = static_cast<DWORD>(regs[1]);

	if (!reported || reported < needed)
	{
		return;
	}

	const ULONG_PTR area = reinterpret_cast<ULONG_PTR>(pStatePage) + SR_FP_AREA;
	if (area & (64 - 1))
	{
		return; // XSAVE #GPs on an unaligned area; FXSAVE is the safe fallback
	}

	OutFlags = SR_FP_FLAG_XSAVE;
	OutMask = mask;
}

// Executes pRoutine(pArg) on a hijacked game thread. What: the full
// suspend/stub/resume/poll/recover pipeline described in the file header.
// Params: hTargetProc (in target handle), pRoutine/pArg (in-target shell
// entry + arg block), Out (out shell Ret when Finished), Timeout (ms to wait
// for Finished), Flags (INJ_HANDLE_HIJACKING/NO_DONOR_SCAN/SKIP_ROUNDTRIP
// steering), SponsorThread/SponsorTid (optional pre-opened victim fast path),
// error_data (out detail). Returns: SR_ERR_SUCCESS (Out valid, context
// proven restored), PENDING_TIMEOUT (proven safe, caller may free),
// RECOVERY_REQUIRED (possibly live - caller must leak), or the staged
// SR_HT_ERR_* failure. Side effects: suspends/resumes the victim, allocates
// and scrubs a remote W^X stub block, records THREAD_EXEC_STATS.
DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_AcquireThread\n");

	ProcessInformation processInformation;
	if (!processInformation.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't initialize ProcessInformation class\n");

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	const DWORD threadAccess = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
	// The hijack working mask. Defined once in InjectionTypes.h so the launcher
	// pre-opens the sponsor with the same rights the runtime (and its donor
	// scan) requests - see the contract on INJ_THREAD_HIJACK_ACCESS. The direct
	// OpenThread below stays on threadAccess on purpose: a wider request there
	// could be denied where the narrow one is granted.
	const DWORD hijackAccess = INJ_THREAD_HIJACK_ACCESS;

	DWORD ThreadID = 0;
	UniqueHandle hThread;

	// Sponsor fast-path: the caller pre-opened a specific target thread in
	// this very process. Duplicate it directly when it is actually
	// hijackable; otherwise discard it and fall through to the runtime
	// search below. The pre-pick (Interface PickHijackThreadTid) scores on
	// Waiting-vs-Running only and cannot know alertable/worker state, so an
	// unvalidated sponsor is how a never-scheduled TID burns the full
	// timeout as SR_HT_ERR_REMOTE_PENDING_TIMEOUT (0x1020000B, State stays
	// Pending). Stealth flags are untouched by this check.
	// Validation re-reads a fresh snapshot a bounded number of times: the
	// interface pick is itself a snapshot, and a live game's threads flip
	// Waiting/Running on millisecond timescales, so a single read can reject
	// a TID the search would accept a moment later (the donor-scan fallback
	// then converges on that same TID anyway, as the extra enumeration
	// buys nothing). Retrying the strict gate on fresh snapshots keeps the
	// zero-enumeration path without weakening it.
	if ((Flags & INJ_HANDLE_HIJACKING) && SponsorThread && SponsorTid)
	{
		const HANDLE Sponsor = ReCa<HANDLE>(SponsorThread);
		const DWORD TargetPidForSponsor = GetProcessId(hTargetProc);
		const DWORD SponsorTidActual = GetThreadId(Sponsor);
		bool sponsor_usable = false;
		HANDLE Duplicated = nullptr;
		if (TargetPidForSponsor && SponsorTidActual && GetProcessIdOfThread(Sponsor) == TargetPidForSponsor
			&& SponsorTidActual == SponsorTid && SponsorTidActual != GetCurrentThreadId()
			&& DuplicateHandle(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
				&Duplicated, hijackAccess, FALSE, 0) && Duplicated)
		{
			// Same bar as the runtime search: not a loader worker, and
			// RUNNING right now. Waiting threads are never accepted - not
			// even alertable ones. A thread suspended inside a kernel wait
			// holds a stale user-mode Rax (the syscall number, verified live:
			// a Sleeping thread shows Rax=0x34, not an NTSTATUS), which the
			// stub preserves verbatim; resuming it at the wait's return
			// address hands its caller garbage instead of a wait result
			// (mutex waiters proceed as-if-signaled without the object).
			// Message loops usually self-heal by re-waiting, which is why
			// waiting hijacks appeared to work - but lock waiters do not, so
			// the policy is Running-only, fail-closed. Reject here and let
			// the search find a Running candidate instead.
			//
			// The Running value is the SAME dynamically-resolved enum the
			// search uses (FindHijackThread). Using the hardcoded
			// KTHREAD_STATE::Running here would let the two acceptance rules
			// drift: a sponsor the search would accept could be rejected by
			// this check (or vice versa) if the PDB ever resolved Running to
			// a different value. Fail-closed either way - a sponsor still
			// must be Running.
			sponsor_usable = false;
			// Same gate as FindHijackThread: the Running value is
			// download-dependent, so when the offsets are not ready the
			// sponsor cannot be proven Running. Refuse it and fall
			// through to the search, which refuses too.
			if (g_DynamicOffsetsReady.load(std::memory_order_acquire) && processInformation.SetProcess(hTargetProc))
			{
				const KTHREAD_STATE running_state = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
				// Bounded re-validation on fresh snapshots. A TID seen as a
				// loader worker gets exactly one verdict (stable property -
				// retrying cannot change it). Absence or a non-Running state
				// is transient on a churning target, so those re-read (same
				// cadence as the search loop below: refresh + 25 ms). No new
				// handles on any pass: the borrowed dup is reused, and
				// everything before the suspend runs while the victim is
				// unfrozen, so the retries cost no frozen-window time. No
				// alertability probe: Running is proven from the snapshot
				// alone, and alertable-but-waiting is still rejected (see the
				// header note), so the suspend+context probe it required is
				// gone with it.
				constexpr int kSponsorValidationPasses = 6;
				bool sponsor_worker = false;
				for (int sponsor_pass = 0;
					sponsor_pass < kSponsorValidationPasses && !sponsor_usable && !sponsor_worker;
					++sponsor_pass)
				{
					if (sponsor_pass > 0)
					{
						Sleep(25);
						if (!processInformation.RefreshInformation() || !processInformation.SetProcess(hTargetProc))
						{
							break;
						}
					}
					// Publish the duplicate we already validated so GetTEB
					// reuses it instead of opening a second handle on the same
					// target thread.
					processInformation.SetCurrentThreadHandle(Duplicated, SponsorTidActual);
					do
					{
					// Only the enumeration entry whose TID matches the sponsor is
					// interesting. Written as a positive test rather than
					// "continue" on mismatch: continue re-evaluates the while
					// condition, which does advance the enumeration and is
					// bounded by the thread count, but reads like a loop-next
					// and invites a real spin if the condition ever changes.
						if (processInformation.GetThreadId() == SponsorTidActual)
						{
							if (processInformation.IsThreadWorkerThread())
							{
								sponsor_worker = true;
								LOG(2, "Sponsor TID %06X is a loader worker; ignoring sponsor\n", SponsorTidActual);
								break;
							}
							KTHREAD_STATE st{};
							KWAIT_REASON wr{};
							const bool have_state = processInformation.GetThreadState(st, wr);
							if (have_state && st == running_state)
							{
								sponsor_usable = true;
							}
							else if (sponsor_pass + 1 < kSponsorValidationPasses)
							{
								LOG(2, "Sponsor TID %06X not Running (state=%d); re-checking\n",
									SponsorTidActual, have_state ? static_cast<int>(st) : -1);
							}
							else
							{
								LOG(2, "Sponsor TID %06X not Running (state=%d); ignoring sponsor\n",
									SponsorTidActual, have_state ? static_cast<int>(st) : -1);
							}
							break;
						}
					}
					while (processInformation.NextThread());
					// No verdict this pass (TID unseen or transient state):
					// the next pass refreshes. Usable/worker verdicts and an
					// exhausted budget leave via the loop condition.
				}
			}
			else
			{
				// Snapshot unusable: cannot prove the sponsor is safe, so
				// do not burn the timeout on it. Fall through to search.
				LOG(2, "Sponsor validation snapshot failed; ignoring sponsor\n");
			}

			processInformation.SetCurrentThreadHandle(nullptr, 0);

			if (sponsor_usable)
			{
				ThreadID = SponsorTidActual;
				hThread.reset(Duplicated);
				Duplicated = nullptr;

				HijackStats Stats{ };
				Stats.Attempted = 1;
				Stats.Success = 1;
				Stats.Source = static_cast<DWORD>(HijackSource::Sponsor);
				Stats.DonorPid = GetCurrentProcessId();
				Stats.DonorHandle = PtrToUlong(Sponsor);
				Stats.GrantedAccess = hijackAccess;
				Stats.NewHandle = PtrToUlong(hThread.get());
				// Same sponsor telemetry shape as the process path
				// (Injection.cpp): the identity/state check passed and the
				// sponsor was used.
				Stats.SponsorValidated = 1;

				// SponsorProbed is reported from what actually ran, not from
				// the flag. It previously read
				//   (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 1
				// which asserted a memory round-trip proof that this thread
				// path never performs - ProbeMemoryRoundtrip is only called on
				// the PROCESS sponsor (Injection.cpp), so with the roundtrip
				// enabled the operator's trace showed "probed" for a probe that
				// did not happen. Honesty matters more than symmetry here: a
				// telemetry field that can claim a check it skipped is worse
				// than one that always reads 0 on this path.
				Stats.SponsorProbed = 0;
				Stats.FailCode = INJ_ERR_SUCCESS;
				RecordHijackOutcome(Stats, true);
				LOG(2, "Acquired target thread handle from sponsor\n");
			}
			else if (Duplicated)
			{
				CloseHandle(Duplicated);
				Duplicated = nullptr;
			}
		}
		else
		{
			if (Duplicated)
			{
				CloseHandle(Duplicated);
			}

			LOG(2, "Sponsor thread failed validation\n");
		}
	}

	if (!ThreadID)
	{
		// Sponsor validation above moved the ProcessInformation cursor (it
		// walks the thread list looking for the sponsor TID). Reset it so
		// the tiered search below starts at Threads[0], not mid-list.
		processInformation.SetProcess(hTargetProc);

		// The smallest TID is almost always the main thread: the most
		// timing-sensitive and watchdog-watched thread in a live game, and
		// therefore the worst hijack victim for stealth (a fail-safe Pending
		// timeout on a pool thread beats a detection on the render thread).
		// Exclude it while alternatives exist; the last attempt includes it
		// so a single-threaded target never fails closed here. The pre-walk
		// below is snapshot-only (GetThreadId needs no handle), so finding it
		// costs no probes. A stale exclusion (thread churned between refresh
		// and search) is harmless: it excludes a dead TID or misses a new
		// smallest, degrading to the original behavior, never to a failure.
		DWORD smallest_tid = 0;
		do
		{
			const DWORD seen = processInformation.GetThreadId();
			if (seen && seen != GetCurrentThreadId() && (!smallest_tid || seen < smallest_tid))
			{
				smallest_tid = seen;
			}
		} while (processInformation.NextThread());
		processInformation.SetProcess(hTargetProc);

		for (int attempt = 0; attempt < 8 && !ThreadID; ++attempt)
		{
			if (attempt > 0)
			{
				Sleep(25);

				if (!processInformation.RefreshInformation() || !processInformation.SetProcess(hTargetProc))
				{
					break;
				}
			}

		// Attempts 0-6 avoid the main thread; attempt 7 is the fallback
		// that takes it when nothing else qualified (or when the
		// smallest-TID heuristic found nothing to exclude). Single Running
		// tier (see FindHijackThread): waiting threads are never accepted,
		// so a pass that finds no Running thread simply retries on a fresh
		// snapshot next attempt (which re-anchors via Refresh+SetProcess).
		const DWORD exclude_tid = (attempt < 7) ? smallest_tid : 0;

		ThreadID = FindHijackThread(processInformation, exclude_tid);
	}

		if (!ThreadID)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "No compatible thread found\n");

			return SR_HT_ERR_NO_THREADS;
		}
	}

	LOG(2, "Target thread %06X\n", ThreadID);

	if (!hThread)
	{
		// Seed the scan record. It is only recorded if no handle is acquired
		// below; a successful scan records its own ScanStats instead, and a
		// missing INJ_HANDLE_HIJACKING flag takes the Direct branch. So the UI
		// can tell "flag set but scan produced nothing" from "flag never
		// arrived".
		if (Flags & INJ_HANDLE_HIJACKING)
		{
			HijackStats Stats{ };
			Stats.Attempted = 1;
			Stats.Source = static_cast<DWORD>(HijackSource::Scan);
			Stats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;

			if (!(Flags & INJ_NO_DONOR_SCAN))
			{
				HANDLE Hijacked = nullptr;
				const DWORD TargetPid = GetProcessId(hTargetProc);
				HijackStats ScanStats{ };
				ScanStats.Attempted = 1;
				const DWORD HijackRet = TargetPid
					? HijackThreadHandle(TargetPid, ThreadID, hijackAccess, Hijacked, &ScanStats, hTargetProc)
					: INJ_ERR_HANDLE_HIJACK_FAILED;
				if (HijackRet == INJ_ERR_SUCCESS && Hijacked)
				{
					ScanStats.Source = static_cast<DWORD>(HijackSource::Scan);
					RecordHijackOutcome(ScanStats, true);
					hThread.reset(Hijacked);
					LOG(2, "Acquired target thread handle via acquisition\n");
				}
				else
				{
					if (ScanStats.FailCode == INJ_ERR_SUCCESS)
					{
						ScanStats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
					}
					ScanStats.Source = static_cast<DWORD>(HijackSource::Scan);
					// Carry the final scan counters into Stats; the single
					// RecordHijackOutcome below records them once, rather
					// than recording ScanStats and then Stats again.
					Stats = ScanStats;
					LOG(2, "Thread handle acquisition found no donor\n");
				}
			}

			if (!hThread)
			{
				// No donor: fail closed. There is no direct OpenThread
				// fallback - a fresh OpenThread is the loudest acquisition
				// telemetry and the whole point of this path is to avoid it.
				Stats.Source = static_cast<DWORD>(HijackSource::Scan);
				RecordHijackOutcome(Stats, true);

				INIT_ERROR_DATA(error_data, INJ_ERR_HANDLE_HIJACK_FAILED);

				LOG(2, "Thread handle acquisition found no donor; refusing (no direct fallback)\n");

				return SR_HT_ERR_OPEN_REFUSED;
			}
		}
		else
		{
			HijackStats Entry{ };
			Entry.Attempted = 1;
			Entry.Source = static_cast<DWORD>(HijackSource::Direct);
			Entry.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
			RecordHijackOutcome(Entry, true);
		}
	}

	if (!hThread)
	{
		// Reached only when INJ_HANDLE_HIJACKING is clear (the explicit
		// direct-open mode); the hijacking path above never falls through
		// without a handle.
		hThread.reset(OpenThread(threadAccess, FALSE, ThreadID));
	}
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "OpenThread failed: %08X\n", error_data.AdvErrorCode);

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}


// W^X: 2-page split -- page0 RX code, page1 RW state. No RWX ever.
// Layout: single 0x2000 reservation keeps RIP-relative reach (<2GB).
// Code [0, state_offset) at pCode, state at 0x1000 boundary at pState.
// lea rbx,[State] + jmp [ReturnTarget] disp32 are patched by +pad.
constexpr size_t kWxCodePage = 0x1000;
constexpr size_t kWxAllocSize = 0x2000;

// The XSAVE image plus its ReturnTarget neighbour must fit in the RW state page
// the W^X split reserves, or the stub's FP save would write past the staging
// copy. SR_FP_AREA_SIZE is the 512-byte legacy area + 64-byte XSAVE header +
// 256-byte YMM_Hi128, which is everything this build ever requests.
static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kWxCodePage,
	"the FP/XSAVE image does not fit the RW state page - raise kWxAllocSize and re-split the pages");

	// Allocate both staging vectors BEFORE suspending the victim. std::vector's
	// allocator can throw std::bad_alloc, and an exception unwinding past a live
	// SuspendThread would reach Inject_Internal's catch(...) and leave the target
	// thread suspended forever. Nothing between the suspend below and the final
	// resume allocates, so no throw can escape while the thread is held. The
	// buffers are filled in place below; the sizes computed here equal the
	// shellcode_size/state_offset/data_size recomputed there.
	const size_t pre_shellcode_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_data_size = pre_shellcode_size > pre_state_offset ? pre_shellcode_size - pre_state_offset : 0;
	std::vector<BYTE> shellcode(pre_shellcode_size);
	std::vector<BYTE> staged(kWxCodePage + pre_data_size, 0xCC);

	// Timing: the remote staging allocation plus all host-side stub
	// preparation complete BEFORE the victim is suspended, so the frozen
	// window holds only GetThreadContext, one WPM, one RX promotion and
	// SetThreadContext (four syscalls). A GetTickCount64 delta heuristic
	// keys on frozen-thread time, so every remote round-trip moved out of
	// the window directly shrinks the observable stall. QueueUserAPC was
	// evaluated and rejected for this stub: it terminates with jmp to the
	// saved ReturnTarget instead of ret, which would abandon the kernel APC
	// dispatch (RtlDispatchAPC expects the routine to return) and corrupt
	// the thread. Suspend-then-minimal-window is the stealth-maximum for
	// this stub contract. No C++ allocation happens below that could throw
	// past a live suspend: VirtualAllocEx/WPM/memcpy cannot throw.
	void * pMem = VirtualAllocEx(hTargetProc, nullptr, kWxAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	// pMem is only the W^X hijack stub: a code page plus an SR_REMOTE_DATA
	// state page whose pArg/pRoutine fields merely point at the caller's
	// argument block (allocated and owned by ManualMapping's own guard). The
	// operator's DLL path lives in that argument block, not here, so freeing
	// pMem would not scrub the path. The guard is released on the recovery
	// paths below whenever the remote stub may still be executing from pMem,
	// or when the thread is parked with RIP inside it; in both cases the
	// memory must stay mapped and is deliberately leaked (reclaimed only when
	// the target exits).
	RemoteAllocation allocation_guard(hTargetProc, pMem);

	// Wipe the stub before the guard releases it, but only when the guard will
	// actually free it: on the recovery paths below the guard is release()d
	// (the stub may still be executing from the block, or the thread is parked
	// inside it) and the wipe is skipped, preserving the documented leak.
	auto scrub_guard = MakeScopeExit([&]() noexcept {
		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pMem, kWxAllocSize);
		}
	});

	const ULONG_PTR shellcode_begin = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin);
	const ULONG_PTR shellcode_end = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd);
	const size_t shellcode_size = static_cast<size_t>(shellcode_end - shellcode_begin);
	if (!shellcode_size || shellcode_size > 0x1000)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	memcpy(shellcode.data(), RemoteThreadHijackBegin, shellcode_size);

	const size_t return_target_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - shellcode_begin);
	const size_t state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - shellcode_begin);
	// The asm template's state area must hold the control block, the FP/XSAVE
	// image at SR_FP_AREA and the trailing ReturnTarget slot. A shrink there
	// would make the stub write past the staged copy, so fail closed instead of
	// truncating an image.
	const size_t state_area_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadState));
	if (return_target_offset + sizeof(ULONG_PTR) > shellcode_size || state_offset + sizeof(SR_REMOTE_DATA) > shellcode_size ||
		state_area_size < SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	// Split: code_size = bytes before state, data_size = state..end.
	const size_t code_size = state_offset;
	const size_t data_size = shellcode_size - state_offset;
	const size_t pad = kWxCodePage - code_size;
	if (code_size >= kWxCodePage || data_size > kWxCodePage)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	memcpy(staged.data(), shellcode.data(), code_size);
	memcpy(staged.data() + kWxCodePage, shellcode.data() + state_offset, data_size);

	// Patch lea rbx,[State] (48 8D 1D disp32) and
	// jmp qword ptr [ReturnTarget] (FF 25 disp32) by +pad.
	// Note: one template cast per line to keep line debuggers clean.
	{
		bool lea_patched = false;
		bool jmp_patched = false;
		const int pad32 = static_cast<int>(pad);
		for (size_t i = 0; i + 7 <= code_size; ++i)
		{
			const bool is_lea = staged[i] == 0x48 && staged[i + 1] == 0x8D && staged[i + 2] == 0x1D;
			if (!lea_patched && is_lea)
			{
				int disp = 0;
				memcpy(&disp, staged.data() + i + 3, sizeof(disp));
				disp += pad32;
				memcpy(staged.data() + i + 3, &disp, sizeof(disp));
				lea_patched = true;
			}
		}
		for (size_t i = 0; i + 6 <= code_size; ++i)
		{
			const bool is_jmp = staged[i] == 0xFF && staged[i + 1] == 0x25;
			if (is_jmp)
			{
				int disp = 0;
				memcpy(&disp, staged.data() + i + 2, sizeof(disp));
				disp += pad32;
				memcpy(staged.data() + i + 2, &disp, sizeof(disp));
				jmp_patched = true;
				break;
			}
		}
		if (!lea_patched || !jmp_patched)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	// Patch the gs:[LastError] disp32 sites in the copied stub with the
	// PDB-resolved TEB::LastErrorValue. Unlike the two RIP-relative sites
	// above these are absolute segment offsets, so each disp32 is overwritten
	// (not adjusted by +pad). Two read sites share one encoding
	// (mov r11d, gs:[TEB_LAST_ERROR] = 65 44 8B 1C 25 disp32: entry save +
	// exit report) and one write site uses another
	// (mov gs:[TEB_LAST_ERROR], r11d = 65 44 89 1C 25 disp32: exit restore).
	// Every read occurrence is patched (they are indistinguishable and share
	// the value); the write must occur exactly once. Fail-closed: never let
	// the assembled 68H placeholder reach the target when the offset was not
	// resolved, and never run a stub whose restore site is missing (it would
	// leave the shell's LastError residue in the victim) or duplicated (an
	// ambiguous template).
	{
		// Acquire before reading the field: pairs with the producer's release
		// store so the offset read below cannot be observed stale.
		const bool dyno_ready = g_DynamicOffsetsReady.load(std::memory_order_acquire);
		const DWORD teb_last_error = g_DynamicOffsets.TebLastErrorValue;
		size_t last_error_reads = 0;
		size_t last_error_writes = 0;
		if (dyno_ready && teb_last_error)
		{
			for (size_t i = 0; i + 9 <= code_size; ++i)
			{
				const bool is_read =
					staged[i] == 0x65 && staged[i + 1] == 0x44 && staged[i + 2] == 0x8B &&
					staged[i + 3] == 0x1C && staged[i + 4] == 0x25;
				if (is_read)
				{
					memcpy(staged.data() + i + 5, &teb_last_error, sizeof(teb_last_error));
					++last_error_reads;
					continue;
				}
				const bool is_write =
					staged[i] == 0x65 && staged[i + 1] == 0x44 && staged[i + 2] == 0x89 &&
					staged[i + 3] == 0x1C && staged[i + 4] == 0x25;
				if (is_write)
				{
					memcpy(staged.data() + i + 5, &teb_last_error, sizeof(teb_last_error));
					++last_error_writes;
				}
			}
		}
		if (!last_error_reads || last_error_writes != 1)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	const DWORD sr_suspend = SuspendThread(hThread);
	if (sr_suspend == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SuspendThread failed: %08X\n", error_data.AdvErrorCode);

		

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	// SuspendThread returns the PREVIOUS count. Non-zero means someone else
	// already held the thread suspended: a single ResumeThread later would
	// leave it still suspended, so the stub would stay Pending until the
	// 60 s timeout (SR_HT_ERR_REMOTE_PENDING_TIMEOUT 0x1020000B) even
	// though the hijack itself was fine. Fail fast so the caller can try
	// the next TID instead of burning the full timeout on a parked thread.
	if (sr_suspend > 0)
	{
		LOG(2, "Thread was already suspended (previous count %u); skipping it\n", sr_suspend);

		ResumeThread(hThread);

		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	LOG(2, "Target thread suspended\n");

	CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_ALL;

	// Attempted and HijackedTid are published HERE, before GetThreadContext,
	// not after it.
	//
	// They used to be set on the line after the suspend completed, which meant
	// every selection and staging failure left Attempted == 0 and the operator
	// could not tell "no hijack was ever attempted" from "a hijack was
	// attempted and failed". The freeze has not started until GetThreadContext
	// is issued, so suspending successfully is the true start of the attempt.
	// Recording it here is both earlier and more accurate; the success/fail
	// codes are still written by the terminal paths below.
	StoreThreadExecStat(g_ThreadExecStats.Attempted, 1);
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

	if (!GetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "GetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		

		return SR_HT_ERR_GET_CONTEXT_FAIL;
	}

	// The stub body (alloc, patch) is already staged above while the victim
	// ran free; only the ReturnTarget slot needs the captured RIP, so it is
	// patched below inside the frozen window.
	const size_t staged_return_offset = kWxCodePage + (return_target_offset - state_offset);
	const size_t staged_state_offset = kWxCodePage;

	const auto OldRIP = OldContext.Rip;
	*reinterpret_cast<ULONG_PTR *>(staged.data() + staged_return_offset) = OldRIP;
	auto * remote_data = reinterpret_cast<SR_REMOTE_DATA *>(staged.data() + staged_state_offset);
	remote_data->pArg = pArg;
	remote_data->pRoutine = pRoutine;

	BYTE * pCode = ReCa<BYTE *>(pMem);
	BYTE * pState = ReCa<BYTE *>(pMem) + kWxCodePage;

	// Decide here (host side, before the frozen window) whether the stub may
	// use XSAVE, and publish the decision with the feature mask the stub passes
	// to the instruction. The staged copy already carries the exception-masked
	// shell words from the assembled template; they are restated so a layout
	// drift between the asm and this struct fails visibly rather than running
	// the shell with a zeroed control word (which would unmask every FP
	// exception).
	ProbeFpCaps(remote_data->FpFlags, remote_data->FpMask, pState);
	remote_data->ShellCw = 0x037F;
	remote_data->ShellMxcsr = 0x01F80;

	void * pRemoteFunc = pCode;
	OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteFunc);

	LOG(2, "Remote thread shell prepared (W^X split: code RX 0x1000, state RW)\n");

	LOG(2, "Acquiring thread with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pArg);

	if (!WriteProcessMemory(hTargetProc, pMem, staged.data(), staged.size(), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		
		

		return SR_HT_ERR_WPM_FAIL;
	}

	// W^X promotion: code page RW->RX only. State page stays RW.
	// No RWX exists at any point; VCheck RWX scans see RW + RX.
	{
		DWORD old_protect = 0;
		if (!VirtualProtectEx(hTargetProc, pCode, kWxCodePage, PAGE_EXECUTE_READ, &old_protect))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "VirtualProtectEx(RX) failed: %08X\n", error_data.AdvErrorCode);

			ResumeThread(hThread);

			return SR_HT_ERR_WPM_FAIL;
		}

		// Best-effort: the RX promotion above is the correctness boundary, but a
		// failure here means the CPU may run stale code, so at least record it.
		if (!FlushInstructionCache(hTargetProc, pCode, code_size))
		{
			LOG(2, "FlushInstructionCache failed: %08X\n", GetLastError());
		}
		LOG(2, "Acquired code promoted RW->RX, state stays RW\n");
	}

	if (!SetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "SetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);
		
		

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	LOG(2, "RIP replaced\n");

	// The hijacked RIP is now live. The original RIP goes back in once the
	// remote shell has run, so from the host's point of view the context is
	// restored at that point - not here.
	const DWORD sr_resume = ResumeThread(hThread);
	if (sr_resume == (DWORD)-1)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "ResumeThread failed: %08X\n", error_data.AdvErrorCode);

		OldContext.Rip = OldRIP;
		if (!SetThreadContext(hThread, &OldContext))
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");

			allocation_guard.release();
			return SR_HT_ERR_RECOVERY_REQUIRED;
		}

		if (ResumeThread(hThread) == (DWORD)-1)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "Recovered thread could not be resumed: %08X\n", error_data.AdvErrorCode);

			
			

			return SR_HT_ERR_RESUME_FAIL;
		}

		
		

		return SR_HT_ERR_RESUME_FAIL;
	}

	LOG(2, "Thread resumed\n");

	// Wake the resumed victim. The hijack accepts a thread that is either
	// Running or in an alertable wait (the sponsor/search gate). A Running
	// thread runs the redirected RIP as soon as it is scheduled, but a thread
	// parked in an alertable/message wait is still inside its kernel wait after
	// ResumeThread and will not execute the stub until that wait is satisfied.
	// WM_NULL is that wake, posted only after ResumeThread succeeded and before
	// the completion poll, so it cannot mask a failed hijack; without it an
	// alertable victim would stay Pending until the full timeout.
	//
	// The result was previously discarded with a bare (void) cast, so a victim
	// with no message queue - which is a normal state, not an error - produced
	// a silent no-post, and the run then burned the whole timeout before
	// reporting SR_HT_ERR_REMOTE_PENDING_TIMEOUT. That diagnosis pointed at the
	// target when the cause was here. Log the failure instead of hiding it; the
	// wake is best-effort by design, so this does not change control flow.
	if (!PostThreadMessageW(ThreadID, WM_NULL, 0, 0))
	{
		const DWORD post_error = GetLastError();
		LOG(2, "PostThreadMessageW(WM_NULL) failed for TID %06X (0x%08X); "
			   "the victim may have no message queue and will rely on the poll alone\n",
			ThreadID, post_error);
		INIT_ERROR_DATA(error_data, post_error);
	}

	Sleep(SR_REMOTE_DELAY);

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	LOG(2, "Entering wait state\n");

	// Forced recovery for the error paths below. The saved RIP is only written
	// back when the stub's own frame is provably unwound - either the thread
	// is back on its exact saved RIP, or its RSP is back at the captured
	// baseline inside the stub page (reached only before its first push or
	// after popping every register, immediately before jmp [ReturnTarget]).
	// Mid-call the RSP sits in the stub's aligned scratch frame and the
	// victim's registers are clobbered, so relocating RIP there would resume
	// the victim with a corrupt stack (the "ghost thread" crash). The polled
	// `data` state that selected this path may be stale (a Pending read taken
	// before the stub finished while the thread has since entered the
	// separate mapping allocation), so the state is re-read fresh under each
	// suspend while the victim is frozen. An RIP merely outside the hijack
	// page is NOT proof of restore: it includes the mapping shell/staging
	// range, and freeing both allocations on that basis crashes the target.
	// Only RIP == OldRIP, or a fresh Finished state with RIP outside the stub
	// page, counts as restored; anything else is resumed untouched and
	// reported not-restored, escalating to recovery-required (leak) instead
	// of a blind forced restore. Every iteration balances exactly one
	// SuspendThread with one ResumeThread. The fresh RPM uses the existing
	// ReadProcessMemory import, runs only on failure paths (max 3 polls), and
	// adds no handle, RWX, or timing-telemetry surface.
	constexpr int kForceRestorePolls = 3;
	auto ForceRestoreContext = [&](bool & restored, bool & resumed) -> void
	{
		restored = false;
		resumed = false;

		const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);
		const ULONG_PTR code_end = code_base + kWxCodePage;

		for (int poll = 0; poll < kForceRestorePolls; ++poll)
		{
			if (poll > 0)
			{
				Sleep(2);
			}

			if (SuspendThread(hThread) == (DWORD)-1)
			{
				// Thread is gone: it can no longer be running our code.
				return;
			}

			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			bool settled = false;
			if (GetThreadContext(hThread, &ctx))
			{
				// Fresh state under suspend; the outer `data` may be stale.
				SR_REMOTE_DATA fresh{ };
				fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
				const BOOL fresh_ok = ReadProcessMemory(hTargetProc, pState, &fresh, sizeof(fresh), nullptr);
				const bool finished = fresh_ok && fresh.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished;

				if (ctx.Rip < code_base || ctx.Rip >= code_end)
				{
					// Outside the hijack stub page. This alone proves nothing:
					// the thread may be executing the separate mapping
					// staging/shell (a different remote allocation) while a
					// stale Pending read is still cached outside. Claim
					// restored only for the exact saved RIP (stub never ran
					// or already jumped home - no live frame on either
					// allocation) or for a freshly observed Finished state
					// (stub provably returned; mapping call already joined).
					// Any other outside RIP with a non-Finished fresh state
					// stays not-restored so both allocations leak instead of
					// being freed under a live thread.
					if (finished || ctx.Rip == OldRIP)
					{
						restored = true;
						settled = true;
					}
					// else: ambiguous outside RIP; leave running, re-poll.
				}
				else if (ctx.Rsp == OldContext.Rsp)
				{
					// Frame unwound (or never pushed): the only in-code-page
					// state where relocating RIP is safe.
					ctx.Rip = OldRIP;
					restored = SetThreadContext(hThread, &ctx) != FALSE;
					settled = true;
				}
				// else: still inside the stub with an inconsistent stack; leave
				// RIP alone and re-poll.
			}

			resumed = ResumeThread(hThread) != (DWORD)-1;
			if (!resumed)
			{
				restored = false;
				return;
			}

			if (settled)
			{
				return;
			}
		}
	};

	auto Timer = GetTickCount64();
	DWORD consecutive_read_failures = 0;
	// Adaptive poll cadence: 1 ms while completion is still plausible, then
	// 5 ms, then a 25 ms cap, so a long stub run costs far fewer wakeups than
	// a fixed 1 ms spin. The overall deadline (the loop bound below) is
	// unchanged, the interrupt event is still waited on every iteration so an
	// interrupt is noticed within one poll interval, and a completed stub
	// breaks out immediately.
	DWORD poll_wait_ms = 1;
	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, poll_wait_ms);
		poll_wait_ms = poll_wait_ms < 5 ? 5 : 25;

		BOOL bRet = ReadProcessMemory(hTargetProc, pState, &data, sizeof(data), nullptr);
		if (bRet)
		{
			consecutive_read_failures = 0;

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				LOG(2, "Shelldata retrieved\n");

				break;
			}
		}

		if (dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "Interrupt!\n");

			bool context_restored = false;
			bool resumed = false;
			if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

			if (!context_restored)
			{
				LOG(2, "Thread context recovery failed; remote allocation retained\n");
				allocation_guard.release();
			}

			// The interrupt path reinstates the saved context from here, unlike
			// the normal path where the remote shell does it. Only a restore
			// that observed the stub frame unwound counts; a thread still inside
			// the stub means the shell may still be live, so escalate to
			// recovery-required instead of claiming a clean abort.
			StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? error_data.AdvErrorCode : SR_HT_ERR_RECOVERY_REQUIRED);

			SetEvent(g_hInterruptedEvent);

			return context_restored ? SR_ERR_INTERRUPT : SR_HT_ERR_RECOVERY_REQUIRED;
		}

		if (!bRet)
		{
			DWORD target_exit = 0;
			if (GetExitCodeProcess(hTargetProc, &target_exit) && target_exit != STILL_ACTIVE)
			{
				INIT_ERROR_DATA(error_data, target_exit);

				LOG(2, "Target process exited during load\n");

				allocation_guard.release();

				return SR_ERR_TARGET_EXITED;
			}

			if (++consecutive_read_failures <= 100)
			{
				continue;
			}

			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			bool context_restored = false;
			bool resumed = false;
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

		if (!context_restored)
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");
			allocation_guard.release();
		}

		// Forced recovery is only performed when the stub frame was observed
		// unwound (see ForceRestoreContext). A thread still inside the stub is
		// left running, so the mode stays unverified and the outcome escalates
		// to recovery-required rather than reporting a restore that did not
		// happen.
		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED);

		return context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED;
		}

	}
	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		bool context_restored = false;
		bool resumed = false;
		if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
		{
			LOG(2, "Shell timed out\n");

			ForceRestoreContext(context_restored, resumed);
		}

		if (!context_restored)
		{
			LOG(2, "Thread context recovery failed; remote allocation retained\n");
			allocation_guard.release();
		}

		// Forced recovery, same as the RPM-failure path: only a restore that
		// observed the stub frame unwound is reported as pending-timeout; a
		// thread still inside the stub escalates to recovery-required because
		// the shell may still be live in the target.
		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_REMOTE_PENDING_TIMEOUT : SR_HT_ERR_RECOVERY_REQUIRED);

		if (context_restored)
		{
			return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
		}

		return SR_HT_ERR_RECOVERY_REQUIRED;
	}

	

	

	LOG(2, "pRoutine returned: %08X\n", data.Ret);

	Out	= data.Ret;

	bool context_restored = false;
	for (int check = 0; check < 5 && !context_restored; ++check)
	{
		if (check > 0)
		{
			Sleep(10);
		}

		if (SuspendThread(hThread) == (DWORD)-1)
		{
			// Suspend failed. The old code counted this as restored ("thread
			// is gone"), but a failed suspend does NOT prove death: an
			// invalid/revoked handle fails too, while the thread may still be
			// alive inside our code. Claiming restored then frees both remote
			// allocations under a live thread (target crash). Verify death
			// directly instead: a thread object is signaled iff terminated,
			// so a zero-timeout wait is proof; anything else stays
			// not-restored and escalates to a safe leak below.
			if (WaitForSingleObject(hThread, 0) == WAIT_OBJECT_0)
			{
				context_restored = true;
			}

			break;
		}

		CONTEXT check_context{ 0 };
		check_context.ContextFlags = CONTEXT_CONTROL;

		bool resumed_check = false;
		if (GetThreadContext(hThread, &check_context))
		{
			const ULONG_PTR check_rip = check_context.Rip;
			const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);
			const ULONG_PTR code_end = code_base + kWxCodePage;
			const bool outside_code = check_rip < code_base || check_rip >= code_end;
			// Safe here (and ONLY here): this loop is reached solely after a
			// freshly observed Finished state, which the stub sets only after
			// its pRoutine call joined - the mapping shell has returned, so no
			// live frame remains on either allocation. Contrast
			// ForceRestoreContext above, where the state is still Pending and
			// an outside RIP may be the live mapping shell.
			if (outside_code)
			{
				context_restored = true;
			}
			else if (check_context.Rsp == OldContext.Rsp)
			{
				// Frame unwound (all registers popped, or none pushed yet): the
				// only in-code-page state where relocating RIP is safe. A thread
				// mid-frame is left for the next retry, then escalates.
				check_context.Rip = OldRIP;
				context_restored = SetThreadContext(hThread, &check_context) != FALSE;
			}

			resumed_check = ResumeThread(hThread) != (DWORD)-1;
		}
		else
		{
			resumed_check = ResumeThread(hThread) != (DWORD)-1;
		}

		if (!resumed_check)
		{
			context_restored = false;
		}
	}

	if (context_restored)
	{
		LOG(2, "Thread context restored automatically\n");
	}
	else
	{
		LOG(2, "Thread context recovery failed; remote allocation retained\n");
		allocation_guard.release();
	}

	// The RIP was observed back outside the hijack code page (or the thread was
	// already gone, which also means it is no longer running our code), or an
	// in-page RIP was relocated only after the RSP baseline proved the stub
	// frame unwound. Recorded here rather than at the call site so the host
	// reports this measured outcome instead of a hardcoded "restored
	// automatically".
	StoreThreadExecStat(g_ThreadExecStats.Success, context_restored ? 1 : 0);
	StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? ERROR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED);

	return context_restored ? SR_ERR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED;
}

void ResetThreadExecStats()
{
	const THREAD_EXEC_STATS Empty{};
	StoreThreadExecStats(Empty);
}

void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreExecStats", __FUNCDNAME__)

	if (Out)
	{
		LoadThreadExecStats(*Out);
	}
}
