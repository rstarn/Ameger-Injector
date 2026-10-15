#include "Core/Utility/Header/PrecompiledHeader.h"

#include <intrin.h>
#include <TlHelp32.h>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Execution/Routine/StartRoutine.h"
#include "System/Handle/HandleHijack.h"
#include "Injection/Injection.h"
#include "Native/Syscall.h"

static THREAD_EXEC_STATS g_ThreadExecStats{};

namespace
{

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

	// The shared scrub helper lives in the syscall layer. The trampoline is at most a couple of pages,
	// so it is wiped in 8 KiB chunks, matching the stack buffer the previous local copy used.
	constexpr SIZE_T kScrubChunk = 0x2000;

	constexpr DWORD kMaxHandleProbes = 4;

	constexpr DWORD kStartupProbeMs = 2000;

	constexpr int kMaxDonorRounds = 16;

	bool IsSafeWaitReason(KWAIT_REASON reason)
	{
		const auto v = static_cast<unsigned char>(reason);
		return v == 4 || v == 6 || v == 11 || v == 13 || v == 15;
	}

	bool IsWorkerTid(HANDLE hTargetProc, DWORD tid)
	{
		if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !tid)
		{
			return true;
		}
		if (!g_DynamicOffsetsReady.load(std::memory_order_acquire) || !g_DynamicOffsets.TebSameTebFlags)
		{
			return true;
		}
		UniqueHandle hThread(ScOpenThread(tid, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION));
		if (!hThread)
		{
			return true;
		}
		THREAD_BASIC_INFORMATION tbi{ 0 };
		if (NT_FAIL(ScNtQueryInformationThread(hThread.get(), THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)) || !tbi.TebBaseAddress)
		{
			return true;
		}
		USHORT flags = 0;
		if (!ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(tbi.TebBaseAddress) + g_DynamicOffsets.TebSameTebFlags, &flags, sizeof(flags), nullptr))
		{
			return true;
		}
		return (flags & g_DynamicOffsets.SameTebFlagsLoaderWorkerMask) != 0;
	}

	bool IsExcluded(const std::vector<DWORD> & excluded, DWORD tid)
	{
		if (!tid)
		{
			return true;
		}

		return std::find(excluded.begin(), excluded.end(), tid) != excluded.end();
	}

	void LogThreadCensus(HANDLE hTargetProc, ProcessInformation & pi, const std::vector<DWORD> & excluded, DWORD selected_tid)
	{
		LOG(1, "[HIJACK] [*] Candidate Thread Census:\n");
		LOG(1, "  TID      STATE    WAIT REASON   TEB ADDRESS         LOADER WORKER?  DECISION\n");
		if (!pi.SetProcess(hTargetProc))
		{
			LOG(1, "[HIJACK] [!] Census unavailable: SetProcess failed\n");
			return;
		}
		do
		{
			const DWORD tid = pi.GetThreadId();
			if (!tid)
			{
				continue;
			}
			KTHREAD_STATE st{};
			KWAIT_REASON wr{};
			const bool have_state = pi.GetThreadState(st, wr);
			void * teb = nullptr;
			{
				THREAD_BASIC_INFORMATION tbi{};
				UniqueHandle ht(ScOpenThread(tid, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION));
				if (ht && NT_SUCCESS(ScNtQueryInformationThread(ht.get(), THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)))
				{
					teb = tbi.TebBaseAddress;
				}
			}
			USHORT flags = 0;
			bool is_worker = true;
			if (teb && g_DynamicOffsetsReady.load(std::memory_order_acquire) && g_DynamicOffsets.TebSameTebFlags)
			{
				if (ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(teb) + g_DynamicOffsets.TebSameTebFlags, &flags, sizeof(flags), nullptr))
				{
					is_worker = (flags & g_DynamicOffsets.SameTebFlagsLoaderWorkerMask) != 0;
				}
			}
			const char * state_name = "Unknown";
			if (have_state)
			{
				switch (static_cast<int>(st))
				{
				case 0: state_name = "Init"; break;
				case 1: state_name = "Ready"; break;
				case 2: state_name = "Running"; break;
				case 3: state_name = "Standby"; break;
				case 4: state_name = "Term"; break;
				case 5: state_name = "Waiting"; break;
				case 6: state_name = "Transition"; break;
				default: state_name = "Other"; break;
				}
			}
			const char * verdict = "SKIPPED";
			if (tid == selected_tid)
			{
				verdict = "SELECTED";
			}
			else if (tid == GetCurrentThreadId() || IsExcluded(excluded, tid))
			{
				verdict = "EXCLUDED";
			}
			else if (is_worker)
			{
				verdict = "EXCLUDED (Worker)";
			}
			LOG(1, "  0x%04X   %-8s %-11d %p   %s (0x%04X)  %s\n",
				tid, state_name, have_state ? static_cast<int>(wr) : -1, teb,
				is_worker ? "Yes" : "No", flags, verdict);
		} while (pi.NextThread());
	}

	DWORD FindHijackThreadToolhelp(HANDLE hTargetProc, const std::vector<DWORD> & excluded)
	{
		if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		const DWORD target_pid = GetProcessId(hTargetProc);
		if (!target_pid)
		{
			return 0;
		}
		ULONG_PTR exe_base = 0;
		SIZE_T exe_size = 0;
		{
			UniqueHandle msnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid));
			if (msnap && msnap.get() != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32 mod{ 0 };
				mod.dwSize = sizeof(mod);
				if (Module32First(msnap.get(), &mod))
				{
					exe_base = ReCa<ULONG_PTR>(mod.modBaseAddr);
					exe_size = static_cast<SIZE_T>(mod.modBaseSize);
				}
			}
		}
		UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
		if (!snap || snap.get() == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
		THREADENTRY32 entry{ 0 };
		entry.dwSize = sizeof(entry);
		if (!Thread32First(snap.get(), &entry))
		{
			return 0;
		}
		DWORD best = 0;
		DWORD best_exe = 0;
		DWORD probes = 0;
		do
		{
			if (entry.th32OwnerProcessID != target_pid)
			{
				continue;
			}
			const DWORD tid = entry.th32ThreadID;
			if (!tid || tid == GetCurrentThreadId() || IsExcluded(excluded, tid))
			{
				continue;
			}
			if (probes >= kMaxHandleProbes * 4)
			{
				break;
			}
			++probes;
			if (IsWorkerTid(hTargetProc, tid))
			{
				continue;
			}
			bool exe_start = false;
			if (exe_base && exe_size)
			{
				UniqueHandle ht(ScOpenThread(tid, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION));
				if (ht)
				{
					PVOID start = nullptr;
					if (!NT_FAIL(ScNtQueryInformationThread(ht.get(), static_cast<THREADINFOCLASS>(9), &start, sizeof(start), nullptr)) && start)
					{
						const auto addr = ReCa<ULONG_PTR>(start);
						exe_start = addr >= exe_base && addr < exe_base + exe_size;
					}
				}
			}
			if (exe_start && (!best_exe || tid < best_exe))
			{
				best_exe = tid;
			}
			if (!best || tid < best)
			{
				best = tid;
			}
		} while (Thread32Next(snap.get(), &entry));
		return best_exe ? best_exe : best;
	}

	DWORD FindHijackThread(ProcessInformation & processInformation, const std::vector<DWORD> & excluded, bool * out_was_running = nullptr, bool allow_waiting = true)
	{

		if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
		{
			LOG(2, "FindAcquireThread: dynamic offsets not ready, refusing\n");
			return 0;
		}
		const KTHREAD_STATE running = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
		const KTHREAD_STATE waiting = KTHREAD_STATE::Waiting;
		DWORD probes = 0;
		DWORD fallback = 0;
		DWORD fallback_probes = 0;
		do
		{
			KWAIT_REASON reason;
			KTHREAD_STATE state;
			if (!processInformation.GetThreadState(state, reason))
			{
				continue;
			}

		const DWORD candidate = processInformation.GetThreadId();
		if (!candidate || candidate == GetCurrentThreadId() || IsExcluded(excluded, candidate))
		{
			continue;
		}

			if (state == running)
			{
				if (probes >= kMaxHandleProbes)
				{
					break;
				}
				++probes;

				if (processInformation.IsThreadWorkerThread())
				{
					continue;
				}

				if (out_was_running)
				{
					*out_was_running = true;
				}
				return candidate;
			}

			if (allow_waiting && !fallback && state == waiting && IsSafeWaitReason(reason))
			{
				if (fallback_probes >= kMaxHandleProbes)
				{
					continue;
				}
				++fallback_probes;

				if (processInformation.IsThreadWorkerThread())
				{
					continue;
				}

				fallback = candidate;
			}
		}
		while (processInformation.NextThread());

		if (out_was_running)
		{
			*out_was_running = false;
		}
		return fallback;
	}
}

static void ProbeFpCaps(DWORD & OutFlags, DWORD & OutMask, const BYTE * pStatePage)
{
	OutFlags = 0;
	OutMask = 0;

	int regs[4]{};
	__cpuid(regs, 1);

	if ((regs[2] & (1 << 27)) == 0)
	{
		return;
	}

	const DWORD xcr0 = static_cast<DWORD>(_xgetbv(0));

	DWORD mask = 0;
	if (xcr0 & 0x1)
	{
		mask |= 0x1;
	}
	if (xcr0 & 0x2)
	{
		mask |= 0x2;
	}
	if (xcr0 & 0x4)
	{
		mask |= 0x4;
	}

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
		return;
	}

	OutFlags = SR_FP_FLAG_XSAVE;
	OutMask = mask;
}

static DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)
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

	const DWORD hijackAccess = INJ_THREAD_HIJACK_ACCESS;

	DWORD ThreadID = 0;
	UniqueHandle hThread;
	bool selected_was_running = false;

	if ((Flags & INJ_HANDLE_HIJACKING) && SponsorThread && SponsorTid)
	{
		const HANDLE Sponsor = ReCa<HANDLE>(SponsorThread);
		const DWORD TargetPidForSponsor = ScGetProcessId(hTargetProc);
		const DWORD SponsorTidActual = ScGetThreadId(Sponsor);
		bool sponsor_usable = false;
		HANDLE Duplicated = nullptr;
		if (TargetPidForSponsor && SponsorTidActual && ScGetProcessIdOfThread(Sponsor) == TargetPidForSponsor
			&& SponsorTidActual == SponsorTid && SponsorTidActual != GetCurrentThreadId()
			&& NT_SUCCESS(ScNtDuplicateObject(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
				&Duplicated, hijackAccess, FALSE, 0)) && Duplicated)
		{

			sponsor_usable = false;

			if (g_DynamicOffsetsReady.load(std::memory_order_acquire) && processInformation.SetProcess(hTargetProc))
			{
				const KTHREAD_STATE running_state = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
				const KTHREAD_STATE waiting_state = KTHREAD_STATE::Waiting;

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

					processInformation.SetCurrentThreadHandle(Duplicated, SponsorTidActual);
					do
					{

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
							else if (have_state && st == waiting_state && IsSafeWaitReason(wr))
							{
								// A Waiting sponsor on a safe wait reason is as usable as any other
								// thread this file selects: the census path already picks Waiting
								// threads on exactly this allowlist (FindHijackThread, reason
								// 4/6/11/13/15). Demanding Running here made the runtime discard a
								// handle the launcher had already opened with the correct access and
								// then fall through to the budget-limited donor scan, which on an idle
								// target exhausts its budget and fails the whole injection with
								// SR_HT_ERR_OPEN_REFUSED. Wait reasons outside the allowlist (e.g. 37,
								// observed on notepad) are still refused: those threads are not
								// reliably scheduled and stall the 2s startup probe.
								sponsor_usable = true;
								LOG(2, "Sponsor TID %06X Waiting on safe reason %d; accepting sponsor\n",
									SponsorTidActual, static_cast<int>(wr));
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

				}
			}
			else
			{

				LOG(2, "Sponsor validation snapshot failed; ignoring sponsor\n");
			}

			processInformation.SetCurrentThreadHandle(nullptr, 0);

			if (sponsor_usable)
			{
				bool sponsor_still_running = false;
				const KTHREAD_STATE rerun_running = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
				if (processInformation.RefreshInformation() && processInformation.SetProcess(hTargetProc))
				{
					processInformation.SetCurrentThreadHandle(Duplicated, SponsorTidActual);
					do
					{
						if (processInformation.GetThreadId() == SponsorTidActual)
						{
							KTHREAD_STATE rst{};
							KWAIT_REASON rwr{};
							if (processInformation.GetThreadState(rst, rwr) && rst == rerun_running)
							{
								sponsor_still_running = true;
							}
							break;
						}
					} while (processInformation.NextThread());
					processInformation.SetCurrentThreadHandle(nullptr, 0);
				}
				if (!sponsor_still_running)
				{
					LOG(2, "Sponsor TID %06X left Running; falling back to search\n", SponsorTidActual);
					sponsor_usable = false;
				}
			}

			if (sponsor_usable)
			{
				ThreadID = SponsorTidActual;
				selected_was_running = true;
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
				Stats.SponsorValidated = 1;

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

		processInformation.SetProcess(hTargetProc);

		DWORD smallest_tid = 0;
		do
		{
			const DWORD seen = processInformation.GetThreadId();
			if (seen && seen != GetCurrentThreadId() && !IsExcluded(excluded, seen) && (!smallest_tid || seen < smallest_tid))
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

		const DWORD exclude_tid = (attempt < 7) ? smallest_tid : 0;

		ThreadID = FindHijackThread(processInformation, excluded, &selected_was_running, attempt >= 7);

		if (!ThreadID && exclude_tid)
		{
			ThreadID = FindHijackThreadToolhelp(hTargetProc, excluded);
			selected_was_running = false;
			if (ThreadID)
			{
				LOG(2, "Second-pass snapshot fallback: %06X\n", ThreadID);
			}
		}
	}

		if (!ThreadID)
		{
			ThreadID = FindHijackThreadToolhelp(hTargetProc, excluded);
			selected_was_running = false;
			if (ThreadID)
			{
				LOG(2, "Acquired target thread via snapshot fallback: %06X\n", ThreadID);
			}
		}

		if (!ThreadID)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "No compatible thread found\n");

			return SR_HT_ERR_NO_THREADS;
		}
	}

	LOG(2, "Target thread %06X\n", ThreadID);
	{
		ProcessInformation census_pi;
		LogThreadCensus(hTargetProc, census_pi, excluded, ThreadID);
		processInformation.SetProcess(hTargetProc);
	}

	if (!hThread)
	{

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

					Stats = ScanStats;
					LOG(2, "Thread handle acquisition found no donor\n");
				}
			}

			if (!hThread)
			{

				Stats.Source = static_cast<DWORD>(HijackSource::Scan);
				RecordHijackOutcome(Stats, true);

				if (!AllowDirectHandleFallback())
				{
					INIT_ERROR_DATA(error_data, INJ_ERR_HANDLE_HIJACK_FAILED);

					LOG(2, "Thread handle acquisition found no donor; refusing (no direct fallback)\n");

					return SR_HT_ERR_OPEN_REFUSED;
				}

				LOG(2, "Thread handle acquisition found no donor; direct fallback enabled by INJ_ALLOW_DIRECT_FALLBACK\n");
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

		hThread.reset(ScOpenThread(ThreadID, threadAccess));
	}
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "OpenThread failed\n");

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

	constexpr size_t kWxCodePage = 0x1000;
	constexpr size_t kWxAllocSize = 0x2000;

	static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kWxCodePage,
		"the FP/XSAVE image does not fit the RW state page - raise kWxAllocSize and re-split the pages");

	// Every offset used below is derived once, from the exported assembler labels, and validated before
	// a single byte is written. Deriving them in two places (once to size the buffers, once to place
	// the fields) is how the two sets drift apart.
	const ULONG_PTR shellcode_begin = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin);
	const ULONG_PTR shellcode_end = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd);

	const size_t shellcode_size = static_cast<size_t>(shellcode_end - shellcode_begin);
	if (!shellcode_size || shellcode_size > kWxCodePage)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_STUB_PATCH_FAIL;
	}

	const size_t state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - shellcode_begin);
	const size_t return_target_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - shellcode_begin);
	const size_t state_area_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadState));

	// The return target has to live inside the state area, behind the FP save area, and the state area
	// has to carry the routine descriptor. Both bounds are checked on both sides: the upper bound is
	// what the size assert already covers, but a return target that appears *before* RemoteThreadState
	// would make the state offset below wrap around into the code page and overwrite live shellcode
	// bytes with the restored RIP. A changed assembler layout has to fail closed here.
	if (return_target_offset < state_offset ||
		return_target_offset + sizeof(ULONG_PTR) > shellcode_size ||
		state_offset + sizeof(SR_REMOTE_DATA) > shellcode_size ||
		state_area_size < SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Shellcode state layout rejected (code=%llx state=%llx return=%llx area=%llx)\n",
			static_cast<unsigned long long>(shellcode_size),
			static_cast<unsigned long long>(state_offset),
			static_cast<unsigned long long>(return_target_offset),
			static_cast<unsigned long long>(state_area_size));

		return SR_HT_ERR_STUB_PATCH_FAIL;
	}

	const size_t code_size = state_offset;
	const size_t data_size = shellcode_size - state_offset;
	const size_t pad = kWxCodePage - code_size;
	if (code_size >= kWxCodePage || data_size > kWxCodePage)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_STUB_PATCH_FAIL;
	}

	std::vector<BYTE> shellcode(shellcode_size);
	memcpy(shellcode.data(), RemoteThreadHijackBegin, shellcode_size);

	// The pad behind the stub is filled with zeroes rather than breakpoints. An executable page carrying
	// a long unbroken run of 0xCC is the signature of a breakpoint trampoline, which is precisely the
	// construct an anti-cheat that emulates INT3 inside its own vectored handler looks for. Zeroed tail
	// is what a normally allocated and partially written page looks like.
	std::vector<BYTE> staged(kWxCodePage + data_size, 0x00);

	void * pMem = ScAllocateMemory(hTargetProc, kWxAllocSize, PAGE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	RemoteAllocation allocation_guard(hTargetProc, pMem);

	auto scrub_guard = MakeScopeExit([&]() noexcept {
		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pMem, kWxAllocSize, kScrubChunk);
		}
	});

	memcpy(staged.data(), shellcode.data(), code_size);
	memcpy(staged.data() + kWxCodePage, shellcode.data() + state_offset, data_size);

	{
		// Patch sites are located through the exported labels in RemoteThreadHijack.asm
		// (RemoteThreadLeaStateIn/Out, RemoteThreadJmpReturn, RemoteThreadTeb*). Deriving
		// the offset from the assembler layout keeps the RIP-relative relocation correct no
		// matter how the toolset encodes the displacement; the opcode prefix at the named
		// site is still validated so any encoding drift fails closed at a named location.
		const int pad32 = static_cast<int>(pad);
		const BYTE lea_prefix[3] = { 0x48, 0x8D, 0x1D };
		const BYTE jmp_prefix[2] = { 0xFF, 0x25 };

		auto patch_rel32 = [&](const BYTE * label, const BYTE * prefix, size_t prefix_len, const char * site) -> bool
		{
			(void)site;
			const size_t site_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(label) - shellcode_begin);
			if (site_offset + prefix_len + sizeof(int) > code_size)
			{
				LOG(2, "Patch site %s out of range\n", site);
				return false;
			}
			if (memcmp(staged.data() + site_offset, prefix, prefix_len) != 0)
			{
				LOG(2, "Patch site %s opcode mismatch\n", site);
				return false;
			}
			int disp = 0;
			memcpy(&disp, staged.data() + site_offset + prefix_len, sizeof(disp));
			disp += pad32;
			memcpy(staged.data() + site_offset + prefix_len, &disp, sizeof(disp));
			return true;
		};

		if (!patch_rel32(RemoteThreadLeaStateIn, lea_prefix, sizeof(lea_prefix), "lea-state-in") ||
			!patch_rel32(RemoteThreadLeaStateOut, lea_prefix, sizeof(lea_prefix), "lea-state-out") ||
			!patch_rel32(RemoteThreadJmpReturn, jmp_prefix, sizeof(jmp_prefix), "jmp-return"))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	{

		const bool dyno_ready = g_DynamicOffsetsReady.load(std::memory_order_acquire);
		const DWORD teb_last_error = g_DynamicOffsets.TebLastErrorValue;
		const BYTE teb_read_prefix[5] = { 0x65, 0x44, 0x8B, 0x1C, 0x25 };
		const BYTE teb_write_prefix[5] = { 0x65, 0x44, 0x89, 0x1C, 0x25 };
		bool teb_patched = false;
		if (dyno_ready && teb_last_error)
		{
			auto patch_teb = [&](const BYTE * label, const BYTE * prefix, const char * site) -> bool
			{
				(void)site;
				const size_t site_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(label) - shellcode_begin);
				if (site_offset + sizeof(teb_read_prefix) + sizeof(DWORD) > code_size)
				{
					LOG(2, "Patch site %s out of range\n", site);
					return false;
				}
				if (memcmp(staged.data() + site_offset, prefix, sizeof(teb_read_prefix)) != 0)
				{
					LOG(2, "Patch site %s opcode mismatch\n", site);
					return false;
				}
				memcpy(staged.data() + site_offset + sizeof(teb_read_prefix), &teb_last_error, sizeof(teb_last_error));
				return true;
			};

			teb_patched =
				patch_teb(RemoteThreadTebReadIn, teb_read_prefix, "teb-read-in") &&
				patch_teb(RemoteThreadTebReadOut, teb_read_prefix, "teb-read-out") &&
				patch_teb(RemoteThreadTebWrite, teb_write_prefix, "teb-write");
		}
		if (!teb_patched)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return SR_HT_ERR_STUB_PATCH_FAIL;
		}
	}

	ULONG sr_suspend = 0;
	if (NT_FAIL(ScNtSuspendThread(hThread, &sr_suspend)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "SuspendThread failed\n");

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	if (sr_suspend > 0)
	{
		LOG(2, "Thread was already suspended (previous count %u); skipping it\n", sr_suspend);

		ScNtResumeThread(hThread, nullptr);

		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	LOG(2, "Target thread suspended\n");

	CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_ALL;

	StoreThreadExecStat(g_ThreadExecStats.Attempted, 1);
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

	if (NT_FAIL(ScNtGetContextThread(hThread, &OldContext)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "GetThreadContext failed\n");

		ScNtResumeThread(hThread, nullptr);

		return SR_HT_ERR_GET_CONTEXT_FAIL;
	}

	const size_t staged_return_offset = kWxCodePage + (return_target_offset - state_offset);
	const size_t staged_state_offset = kWxCodePage;

	const auto OldRIP = OldContext.Rip;
	*reinterpret_cast<ULONG_PTR *>(staged.data() + staged_return_offset) = OldRIP;
	auto * remote_data = reinterpret_cast<SR_REMOTE_DATA *>(staged.data() + staged_state_offset);
	remote_data->pArg = pArg;
	remote_data->pRoutine = pRoutine;

	BYTE * pCode = ReCa<BYTE *>(pMem);
	BYTE * pState = ReCa<BYTE *>(pMem) + kWxCodePage;

	ProbeFpCaps(remote_data->FpFlags, remote_data->FpMask, pState);
	remote_data->ShellCw = 0x037F;
	remote_data->ShellMxcsr = 0x01F80;
	remote_data->RoutineCyclesDelta = 0;
	remote_data->StackScrubbedBytes = 0;

	void * pRemoteFunc = pCode;
	OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteFunc);

	InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.OldRip), static_cast<LONG64>(OldRIP));
	StoreThreadExecStat(g_ThreadExecStats.FpMode, remote_data->FpFlags);
	StoreThreadExecStat(g_ThreadExecStats.FpMask, remote_data->FpMask);
	LOG(1, "[HIJACK] [*] Context Captured: Target RIP=0x%llX RSP=0x%llX\n", (unsigned long long)OldRIP, (unsigned long long)OldContext.Rsp);
	LOG(1, "[HIJACK] [*] Floating-Point State: Mode=%s Mask=0x%X Area=%u bytes\n", remote_data->FpFlags ? "XSAVE" : "FXSAVE", remote_data->FpMask, SR_FP_AREA_SIZE);
	LOG(1, "[HIJACK] [*] Staging: VA=%p RX=0x1000 RW=0x%llX\n", pMem, (unsigned long long)(kWxAllocSize - kWxCodePage));
	LOG(1, "[HIJACK] [*] RIP Redirection: 0x%llX -> %p\n", (unsigned long long)OldRIP, pRemoteFunc);
	LOG(2, "Remote thread shell prepared (W^X split: code RX 0x1000, state RW)\n");

	LOG(2, "Acquiring thread with:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pArg);

	if (!ScWriteProcessMemory(hTargetProc, pMem, staged.data(), staged.size(), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "WriteProcessMemory failed\n");

		ScNtResumeThread(hThread, nullptr);

		return SR_HT_ERR_WPM_FAIL;
	}

	{
		if (!ScProtectMemory(hTargetProc, pCode, kWxCodePage, PAGE_EXECUTE_READ))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "Protect(RX) failed\n");

			ScNtResumeThread(hThread, nullptr);

			return SR_HT_ERR_WPM_FAIL;
		}

		if (!FlushInstructionCache(hTargetProc, pCode, code_size))
		{
			LOG(2, "FlushInstructionCache failed\n");
		}
		LOG(2, "Acquired code promoted RW->RX, state stays RW\n");
	}

	if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "SetThreadContext failed\n");

		ScNtResumeThread(hThread, nullptr);

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	LOG(2, "RIP replaced\n");

	{
		ULONG sr_resume = 0;
		if (NT_FAIL(ScNtResumeThread(hThread, &sr_resume)))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "ResumeThread failed\n");

			OldContext.Rip = OldRIP;
			if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
			{
				LOG(2, "Thread context recovery failed; remote allocation retained\n");

				allocation_guard.release();
				return SR_HT_ERR_RECOVERY_REQUIRED;
			}

			if (NT_FAIL(ScNtResumeThread(hThread, nullptr)))
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				LOG(2, "Recovered thread could not be resumed\n");

				return SR_HT_ERR_RESUME_FAIL;
			}

			return SR_HT_ERR_RESUME_FAIL;
		}
	}

	LOG(2, "Thread resumed\n");

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	LOG(2, "Entering wait state\n");

	// The stub restores the victim's registers itself and then jumps back to the original RIP, so a
	// forced restore only has to cover the window between suspending the thread and that return. The
	// retry window is deliberately generous, with a short backoff, because a single missed poll used
	// to leak the trampoline and leave the victim inside the stub.
	constexpr int kForceRestorePolls = 24;
	// Widest distance our stub can place RSP below the victim's original RSP while RIP is still inside
	// the code page: pushfq + 15 GPRs (0x80), then `and rsp,-16` (up to 0xF) and `sub rsp,0x40`.
	// Comparing RSP for equality instead of against this window only matched the single instruction
	// before pushfq, so the forced restore never fired and the trampoline was retained every time.
	constexpr ULONG_PTR kStubFrameWindow = 0x100;

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
				// Short at first so a fast return is noticed immediately, then a steady cadence so a
				// slow one is not polled in a tight spin.
				Sleep(poll < 8 ? 2 : 10);
			}

			if (NT_FAIL(ScNtSuspendThread(hThread, nullptr)))
			{

				return;
			}

			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			bool settled = false;
			if (NT_SUCCESS(ScNtGetContextThread(hThread, &ctx)))
			{

				SR_REMOTE_DATA fresh{ };
				fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
				const bool fresh_ok = ScReadProcessMemory(hTargetProc, pState, &fresh, sizeof(fresh), nullptr);
				const bool finished = fresh_ok && fresh.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished;

				if (ctx.Rip < code_base || ctx.Rip >= code_end)
				{

					if (finished || ctx.Rip == OldRIP)
					{
						restored = true;
						settled = true;
					}

				}
				else if (ctx.Rsp <= OldContext.Rsp && (OldContext.Rsp - ctx.Rsp) <= kStubFrameWindow)
				{

					ctx.Rip = OldRIP;
					ctx.Rsp = OldContext.Rsp;
					restored = NT_SUCCESS(ScNtSetContextThread(hThread, &ctx)) != FALSE;
					settled = true;
				}

			}

			resumed = NT_SUCCESS(ScNtResumeThread(hThread, nullptr));
			// If resume fails, the thread stays suspended but context may have been restored.
			// The caller must handle this case (e.g., by retaining the trampoline allocation).
			if (!resumed)
			{
				return;
			}

			if (settled)
			{
				return;
			}
		}
	};

	// Decides whether the trampoline can be reclaimed safely after an unrecoverable restore failure.
	// That is only true once the victim can no longer be executing inside the stub: either it has
	// exited, or its instruction pointer has left the code page. Otherwise freeing the region would
	// take the victim's instruction pointer with it, so it is deliberately retained.
	auto StubRegionFreeToRelease = [&]() -> bool
	{
		if (WaitForSingleObject(hThread, 0) == WAIT_OBJECT_0)
		{
			return true;
		}

		CONTEXT probe{ 0 };
		probe.ContextFlags = CONTEXT_CONTROL;
		if (!NT_SUCCESS(ScNtGetContextThread(hThread, &probe)))
		{
			return false;
		}

		const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);

		return probe.Rip < code_base || probe.Rip >= code_base + kWxCodePage;
	};

	// Releases the trampoline when the victim is provably out of it, and retains it only when the
	// victim may still be executing inside. On the failure paths this is the last chance to avoid
	// leaking the allocation; the returned error code is unaffected.
	auto ReclaimOrRetainTrampoline = [&](bool context_restored) -> void
	{
		if (context_restored)
		{
			return;
		}

		if (StubRegionFreeToRelease())
		{
			LOG(2, "Thread is no longer inside the stub; remote allocation reclaimed\n");
			return;
		}

		LOG(2, "Thread context recovery failed; remote allocation retained\n");
		allocation_guard.release();
	};

	auto Timer = GetTickCount64();
	DWORD consecutive_read_failures = 0;
	DWORD poll_iterations = 0;

	DWORD poll_wait_ms = 1;

	// The victim thread is only ever nudged when it has visibly failed to be scheduled. A message posted
	// unconditionally lands in the target's queue and is visible to any queue monitor, and the fixed
	// pre-poll delay cost the victim a guaranteed multi tens of milliseconds of wall time, which is
	// exactly the shape a delta based timing check is written to catch.
	bool nudge_sent = false;
	DWORD nudge_after_ms = 250;

	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForSingleObject(g_hInterruptEvent, poll_wait_ms);
		poll_wait_ms = poll_wait_ms < 5 ? 5 : 25;
		++poll_iterations;

		BOOL bRet = ScReadProcessMemory(hTargetProc, pState, &data, sizeof(data), nullptr);
		if (bRet)
		{
			consecutive_read_failures = 0;

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				LOG(2, "Shelldata retrieved\n");
				const DWORD exec_ms = static_cast<DWORD>(GetTickCount64() - Timer);
				StoreThreadExecStat(g_ThreadExecStats.PollIterations, poll_iterations);
				StoreThreadExecStat(g_ThreadExecStats.ExecMs, exec_ms);
				StoreThreadExecStat(g_ThreadExecStats.RoutineRet, data.Ret);
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.RoutineCyclesDelta), static_cast<LONG64>(data.RoutineCyclesDelta));
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.StackScrubbedBytes), static_cast<LONG64>(data.StackScrubbedBytes));
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.SavedRsp), 0);
				{
					ULONG_PTR saved_rsp = 0;
					if (ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(pState) + SR_SAVED_RSP, &saved_rsp, sizeof(saved_rsp), nullptr) && saved_rsp)
					{
						InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.SavedRsp), static_cast<LONG64>(saved_rsp));
						if (data.StackScrubbedBytes && saved_rsp >= data.StackScrubbedBytes)
						{
							InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.StackLimit), static_cast<LONG64>(saved_rsp - data.StackScrubbedBytes));
						}
					}
				}
				LOG(1, "[HIJACK] [*] Polling Execution: state=Finished iters=%u elapsed=%u ms ret=0x%08X\n", poll_iterations, exec_ms, data.Ret);
// Marker follows the value: a 0-byte result means nothing was reported scrubbed, which is an
				// absent measurement rather than a successful scrub.
				if (data.StackScrubbedBytes)
				{
					LOG(1, "[HIJACK] [+] Stack Sanitization: scrubbed=%llu bytes cycles=%llu\n",
						(unsigned long long)data.StackScrubbedBytes,
						(unsigned long long)data.RoutineCyclesDelta);
				}
				else
				{
					LOG(1, "[HIJACK] [*] Stack Sanitization: 0 bytes scrubbed (no sanitization result reported)\n");
				}

				break;
			}

			const ULONGLONG waited = GetTickCount64() - Timer;

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= kStartupProbeMs)
			{
				LOG(2, "Stub not scheduled within %u ms (sampled state was %s); failing fast\n",
					kStartupProbeMs, selected_was_running ? "Running" : "Waiting");

				break;
			}

			if (!nudge_sent && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= nudge_after_ms)
			{
				nudge_sent = true;

				if (!PostThreadMessageW(ThreadID, WM_NULL, 0, 0))
				{
					LOG(2, "Wake nudge failed for TID %06X; relying on the poll alone\n", ThreadID);
				}
				else
				{
					LOG(2, "Stub unscheduled for %u ms; wake nudge sent\n", nudge_after_ms);
				}
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

			ReclaimOrRetainTrampoline(context_restored);

			StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? error_data.AdvErrorCode : SR_HT_ERR_RECOVERY_REQUIRED);

			SetEvent(g_hInterruptedEvent);

			return context_restored ? SR_ERR_INTERRUPT : SR_HT_ERR_RECOVERY_REQUIRED;
		}

		if (!bRet)
		{
			DWORD target_exit = 0;
			if (ScGetExitCodeProcess(hTargetProc, target_exit) && target_exit != STILL_ACTIVE)
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

			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "ReadProcessMemory failed\n");

			bool context_restored = false;
			bool resumed = false;
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

		ReclaimOrRetainTrampoline(context_restored);

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

		ReclaimOrRetainTrampoline(context_restored);

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

		if (NT_FAIL(ScNtSuspendThread(hThread, nullptr)))
		{

			if (WaitForSingleObject(hThread, 0) == WAIT_OBJECT_0)
			{
				context_restored = true;
			}

			break;
		}

		CONTEXT check_context{ 0 };
		check_context.ContextFlags = CONTEXT_CONTROL;

		bool resumed_check = false;
		if (NT_SUCCESS(ScNtGetContextThread(hThread, &check_context)))
		{
			const ULONG_PTR check_rip = check_context.Rip;
			const ULONG_PTR code_base = ReCa<ULONG_PTR>(pCode);
			const ULONG_PTR code_end = code_base + kWxCodePage;
			const bool outside_code = check_rip < code_base || check_rip >= code_end;

			if (outside_code)
			{
				context_restored = true;
			}
			else if (check_context.Rsp <= OldContext.Rsp &&
				(OldContext.Rsp - check_context.Rsp) <= kStubFrameWindow)
			{

				check_context.Rip = OldRIP;
				check_context.Rsp = OldContext.Rsp;
				context_restored = NT_SUCCESS(ScNtSetContextThread(hThread, &check_context)) != FALSE;
			}

			resumed_check = NT_SUCCESS(ScNtResumeThread(hThread, nullptr));
		}
		else
		{
			resumed_check = NT_SUCCESS(ScNtResumeThread(hThread, nullptr));
		}

		if (!resumed_check)
		{
			context_restored = false;
		}
	}

	if (context_restored)
	{
		LOG(2, "Thread context restored automatically\n");
		LOG(1, "[HIJACK] [+] Context Verification: restored RIP=0x%llX thread resumed\n", (unsigned long long)OldRIP);
	}
	else
	{
		LOG(1, "[HIJACK] [x] Context Verification FAILED: RIP=0x%llX not restored\n", (unsigned long long)OldRIP);
	}

	ReclaimOrRetainTrampoline(context_restored);

	StoreThreadExecStat(g_ThreadExecStats.Success, context_restored ? 1 : 0);
	StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? ERROR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED);

	return context_restored ? SR_ERR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED;
}

static bool IsRetryableHijackFailure(DWORD code)
{
	switch (code)
	{
	case SR_HT_ERR_REMOTE_PENDING_TIMEOUT:
	case SR_HT_ERR_NO_THREADS:
	case SR_HT_ERR_SUSPEND_FAIL:
	case SR_HT_ERR_OPEN_THREAD_FAIL:
	case SR_HT_ERR_OPEN_REFUSED:
		return true;
	default:
		return false;
	}
}

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	const ULONGLONG budget_start = GetTickCount64();
	std::vector<DWORD> excluded;
	DWORD last_code = SR_HT_ERR_NO_THREADS;

	for (int round = 0; round < kMaxDonorRounds; ++round)
	{
		const ULONGLONG elapsed = GetTickCount64() - budget_start;
		if (elapsed >= Timeout)
		{
			break;
		}

		const DWORD remaining = Timeout - static_cast<DWORD>(elapsed);
		const bool sponsor_round = (round == 0);
		const ULONG_PTR sponsor_handle = sponsor_round ? SponsorThread : 0;
		const DWORD sponsor_tid = sponsor_round ? SponsorTid : 0;

		LOG(2, "Donor round %d/%d, %u ms remaining, %u candidate(s) excluded\n",
			round + 1, kMaxDonorRounds, remaining, static_cast<DWORD>(excluded.size()));

		StoreThreadExecStat(g_ThreadExecStats.DonorRounds, round + 1);

		ERROR_DATA round_error{ };
		DWORD round_out = 0;
		last_code = SR_HijackThreadOnce(hTargetProc, pRoutine, pArg, round_out, remaining, Flags,
			sponsor_handle, sponsor_tid, excluded, round_error);

		if (last_code == SR_ERR_SUCCESS)
		{
			Out = round_out;
			error_data = round_error;

			return SR_ERR_SUCCESS;
		}

		if (!IsRetryableHijackFailure(last_code))
		{
			error_data = round_error;

			return last_code;
		}

		if (last_code != SR_HT_ERR_NO_THREADS)
		{
			THREAD_EXEC_STATS round_stats{ };
			LoadThreadExecStats(round_stats);

			const DWORD failed_tid = round_stats.HijackedTid;
			if (failed_tid && !IsExcluded(excluded, failed_tid))
			{
				excluded.push_back(failed_tid);
				LOG(2, "Excluding donor TID %06X after code %08X\n", failed_tid, last_code);
			}
		}
	}

	LOG(2, "Donor search exhausted after %u round(s)\n", static_cast<DWORD>(excluded.size()));

	INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

	return last_code;
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
