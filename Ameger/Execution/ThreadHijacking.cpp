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

	// Chunk size used when zeroing a remote region before it is released.
	constexpr SIZE_T kScrubChunk = 0x2000;

	// How many threads may be probed per candidate before the scan gives up on
	// finding a running one and falls back to a waiting thread.
	constexpr DWORD kMaxHandleProbes = 4;

	constexpr DWORD kStartupProbeMs = 2000;

	constexpr int kMaxDonorRounds = 16;

	bool IsSafeWaitReason(KWAIT_REASON reason)
	{
		const auto v = static_cast<unsigned char>(reason);
		return v == 4 || v == 6 || v == 11 || v == 13 || v == 15;
	}

	bool ResumeThreadWithRetry(HANDLE hThread)
	{
		if (!hThread || hThread == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		for (int attempt = 0; attempt < 4; ++attempt)
		{
			const NTSTATUS status = ScNtResumeThread(hThread, nullptr);
			if (NT_SUCCESS(status))
			{
				return true;
			}

			if (status == STATUS_INVALID_HANDLE || status == STATUS_ACCESS_DENIED)
			{
				return false;
			}

			if (attempt + 1 < 4)
			{
				Sleep(1);
			}
		}

		return false;
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
		UniqueHandle hThread(ScOpenThread(tid, THREAD_QUERY_LIMITED_INFORMATION));
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
		LOG(1, "[ThreadHijack] [*] Candidate Thread Census:\n");
		LOG(1, "  TID      State    Wait Reason   TEB Address         Loader Worker?  Decision\n");
		if (!pi.SetProcess(hTargetProc))
		{
			LOG(1, "[ThreadHijack] [!] Census Unavailable: SetProcess Failed\n");
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
				UniqueHandle ht(ScOpenThread(tid, THREAD_QUERY_LIMITED_INFORMATION));
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
			const char * verdict = "Skipped";
			if (tid == selected_tid)
			{
				verdict = "Selected";
			}
			else if (tid == GetCurrentThreadId() || IsExcluded(excluded, tid))
			{
				verdict = "Excluded";
			}
			else if (is_worker)
			{
				verdict = "Excluded (Worker)";
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
		ProcessInformation wait_probe;
		const bool wait_probe_ready = wait_probe.SetProcess(hTargetProc);
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
			if (wait_probe_ready)
			{
				UniqueHandle probe_thread(ScOpenThread(tid, THREAD_QUERY_LIMITED_INFORMATION));
				if (probe_thread)
				{
					bool wait_ok = true;
					wait_probe.SetCurrentThreadHandle(probe_thread.get(), tid);

					KTHREAD_STATE probe_state{};
					KWAIT_REASON probe_reason{};
					if (wait_probe.GetThreadState(probe_state, probe_reason) &&
						probe_state == KTHREAD_STATE::Waiting &&
						!IsSafeWaitReason(probe_reason))
					{
						wait_ok = false;
					}

					wait_probe.SetCurrentThreadHandle(nullptr, 0);

					if (!wait_ok)
					{
						continue;
					}
				}
			}
			bool exe_start = false;
			if (exe_base && exe_size)
			{
				UniqueHandle ht(ScOpenThread(tid, THREAD_QUERY_LIMITED_INFORMATION));
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
			LOG(2, "FindAcquireThread: Dynamic Offsets Not Ready, Refusing\n");
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
					continue;
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

	struct DeferredTrampoline
	{
		HANDLE	Process = nullptr;
		HANDLE	Thread	= nullptr;
		void *	Base	= nullptr;
	};

	constexpr SIZE_T kDeferredTrampolineSize = 0x2000;
	constexpr SIZE_T kDeferredCodePage = 0x1000;

	SRWLOCK g_DeferredTrampolineLock = SRWLOCK_INIT;
	std::vector<DeferredTrampoline> g_DeferredTrampolines;

	void CloseDeferredTrampoline(DeferredTrampoline & Entry)
	{
		if (Entry.Thread && Entry.Thread != INVALID_HANDLE_VALUE)
		{
			CloseHandle(Entry.Thread);
		}

		if (Entry.Process && Entry.Process != INVALID_HANDLE_VALUE)
		{
			CloseHandle(Entry.Process);
		}

		Entry.Process = nullptr;
		Entry.Thread	= nullptr;
		Entry.Base		= nullptr;
	}

	bool EnqueueDeferredTrampoline(HANDLE Process, HANDLE Thread, void * Base)
	{
		HANDLE DupProcess = nullptr;
		HANDLE DupThread	= nullptr;
		DWORD DupError	= ERROR_SUCCESS;

		if (!Process || Process == INVALID_HANDLE_VALUE || !Thread || Thread == INVALID_HANDLE_VALUE || !Base)
		{
			DupError = ERROR_INVALID_HANDLE;
		}
		else if (!DuplicateHandle(GetCurrentProcess(), Process, GetCurrentProcess(), &DupProcess, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			DupError = GetLastError();
		}
		else if (!DuplicateHandle(GetCurrentProcess(), Thread, GetCurrentProcess(), &DupThread, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			DupError = GetLastError();
		}

		if (DupError != ERROR_SUCCESS)
		{
			if (DupThread)
			{
				CloseHandle(DupThread);
			}

			if (DupProcess)
			{
				CloseHandle(DupProcess);
			}

			LOG(2, "Deferred Trampoline Handles Not Duplicated (Error = %u); Remote Allocation Retained\n", DupError);
			return false;
		}

		bool lock_held = false;
		bool queued = false;
		try
		{
			AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
			lock_held = true;
			g_DeferredTrampolines.push_back(DeferredTrampoline{ DupProcess, DupThread, Base });
			queued = true;
		}
		catch (...)
		{
			queued = false;
		}

		if (lock_held)
		{
			ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
		}

		if (!queued)
		{
			CloseHandle(DupThread);
			CloseHandle(DupProcess);

			LOG(2, "Deferred Trampoline Enqueue Failed; Remote Allocation Retained\n");
			return false;
		}

		LOG(2, "Remote Allocation Deferred For Reclaim (Base = %p)\n", Base);
		return true;
	}

	bool DeferredProcessGone(HANDLE Process)
	{
		const DWORD wait = WaitForSingleObject(Process, 0);
		if (wait == WAIT_OBJECT_0)
		{
			return true;
		}

		if (wait == WAIT_TIMEOUT)
		{
			return false;
		}

		DWORD exit_code = STILL_ACTIVE;
		return GetExitCodeProcess(Process, &exit_code) && exit_code != STILL_ACTIVE;
	}

	void ReapDeferredTrampolines()
	{
		std::vector<DeferredTrampoline> pending;
		{
			AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
			pending.swap(g_DeferredTrampolines);
			ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
		}

		if (pending.empty())
		{
			return;
		}

		std::vector<DeferredTrampoline> retained;

		for (DeferredTrampoline & Entry : pending)
		{
			if (DeferredProcessGone(Entry.Process))
			{
				LOG(2, "Deferred Trampoline Dropped: Target Process Gone (Base = %p)\n", Entry.Base);

				CloseDeferredTrampoline(Entry);
				continue;
			}

			if (WaitForSingleObject(Entry.Thread, 0) == WAIT_OBJECT_0)
			{
				ScrubRemoteRegion(Entry.Process, Entry.Base, kDeferredTrampolineSize, kScrubChunk);
				if (!VirtualFreeEx(Entry.Process, Entry.Base, 0, MEM_RELEASE))
				{
					const DWORD free_error = GetLastError();

					LOG(2, "Deferred Trampoline Free Failed (Error = %u); Retained (Base = %p)\n", free_error, Entry.Base);

					retained.push_back(Entry);
					continue;
				}

				LOG(2, "Deferred Trampoline Reclaimed: Donor Thread Exited (Base = %p)\n", Entry.Base);

				CloseDeferredTrampoline(Entry);
				continue;
			}

			SR_REMOTE_STATE state = SR_REMOTE_STATE::SR_RS_ExecutionPending;
			if (!ScReadProcessMemory(Entry.Process, ReCa<BYTE *>(Entry.Base) + kDeferredCodePage, &state, sizeof(state), nullptr) ||
				!RemoteRoutineSettled(state))
			{
				retained.push_back(Entry);
				continue;
			}

			ULONG previous = 0;
			if (NT_FAIL(ScNtSuspendThread(Entry.Thread, &previous)))
			{
				retained.push_back(Entry);
				continue;
			}

			if (previous > 0)
			{
				ResumeThreadWithRetry(Entry.Thread);
				retained.push_back(Entry);
				continue;
			}

			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			const bool have_context = NT_SUCCESS(ScNtGetContextThread(Entry.Thread, &ctx)) != FALSE;
			ResumeThreadWithRetry(Entry.Thread);

			const ULONG_PTR base = ReCa<ULONG_PTR>(Entry.Base);
			if (!have_context || (ctx.Rip >= base && ctx.Rip < base + kDeferredCodePage))
			{
				retained.push_back(Entry);
				continue;
			}

			ScrubRemoteRegion(Entry.Process, Entry.Base, kDeferredTrampolineSize, kScrubChunk);
			if (!VirtualFreeEx(Entry.Process, Entry.Base, 0, MEM_RELEASE))
			{
				const DWORD free_error = GetLastError();

				LOG(2, "Deferred Trampoline Free Failed (Error = %u); Retained (Base = %p)\n", free_error, Entry.Base);

				retained.push_back(Entry);
				continue;
			}

			LOG(2, "Deferred Trampoline Reclaimed: Thread Outside Stub (Base = %p)\n", Entry.Base);

			CloseDeferredTrampoline(Entry);
		}

		if (!retained.empty())
		{
			bool lock_held = false;
			bool inserted = false;
			try
			{
				AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
				lock_held = true;
				g_DeferredTrampolines.insert(g_DeferredTrampolines.end(), retained.begin(), retained.end());
				inserted = true;
			}
			catch (...)
			{
				inserted = false;
			}

			if (lock_held)
			{
				ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
			}

			if (!inserted)
			{
				for (DeferredTrampoline & Entry : retained)
				{
					LOG(2, "Deferred Trampoline Requeue Failed; Dropping Handles (Base = %p)\n", Entry.Base);

					CloseDeferredTrampoline(Entry);
				}
			}
		}
	}
}

static void ProbeFpCaps(DWORD & OutFlags, DWORD & OutMask, const BYTE * pStatePage)
{
	OutFlags = 0;
	OutMask = 0;

	int regs[4]{};
	__cpuid(regs, 1);

	// CPUID.1:ECX bit 26 reports XSAVE support, bit 27 reports that the OS has
	// actually enabled the XSAVE state management (OSXSAVE).
	const bool cpu_has_xsave = (regs[2] & (1 << 26)) != 0;
	const bool os_has_xsave = (regs[2] & (1 << 27)) != 0;

	if (!cpu_has_xsave || !os_has_xsave)
	{
		// No XSAVE: the stub falls back to FXSAVE64. That form cannot carry AVX
		// state, but it also never writes the YMM registers, so they survive.
		return;
	}

	// CPUID.0Dh.0:EAX reports which XCR0 bits this CPU is willing to have enabled.
	__cpuidex(regs, 0xD, 0);
	const DWORD supported = static_cast<DWORD>(regs[0]) & SR_FP_XCR0_MASK;
	if (!supported)
	{
		return;
	}

	// Size the XSAVE image for the widest mask the victim could legally have: the
	// legacy region plus the YMM region when the CPU supports AVX. AVX-512 is never
	// requested, and XRSTOR with a mask that omits a component leaves that
	// component's registers untouched, so the victim's ZMM state passes through.
	const DWORD needed = (supported & SR_FP_XCR0_AVX)
		? (SR_FP_XSAVE_LEGACY_BYTES + SR_FP_AVX_BYTES)
		: SR_FP_XSAVE_LEGACY_BYTES;

	if (needed > SR_FP_AREA_SIZE)
	{
		return;
	}

	const ULONG_PTR area = reinterpret_cast<ULONG_PTR>(pStatePage) + SR_FP_AREA;
	if (area & (64 - 1))
	{
		// XSAVE64 requires a 64-byte aligned destination.
		return;
	}

	OutFlags = SR_FP_FLAG_XSAVE;

	// This is only the capability ceiling. The stub recomputes the effective mask
	// from the victim's own XCR0 (XGETBV) and stores it back here before XSAVE, so
	// the value never leaks a mask the victim cannot legally honour.
	OutMask = supported;
}

static DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_AcquireThread\n");

	ProcessInformation processInformation;
	if (!processInformation.SetProcess(hTargetProc))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Can't Initialize ProcessInformation Class\n");

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	const DWORD threadAccess = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | SYNCHRONIZE;

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
								LOG(2, "Sponsor TID %06X Is A Loader Worker; Ignoring Sponsor\n", SponsorTidActual);
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
								// A thread parked on a wait reason that cannot be re-armed by an
								// unrelated wakeup is a good donor: it will not race the hijack,
								// and it is not the loader's own housekeeping thread.
								//
								// A running thread is preferred, but a parked one is still
								// usable: the stub is scheduled onto it either way, and the
								// context restore path can roll it back.
								
								sponsor_usable = true;
								LOG(2, "Sponsor TID %06X Waiting On Safe Reason %d; Accepting Sponsor\n",
									SponsorTidActual, static_cast<int>(wr));
							}
							else if (sponsor_pass + 1 < kSponsorValidationPasses)
							{
								LOG(2, "Sponsor TID %06X Not Running (State = %d); Re-Checking\n",
									SponsorTidActual, have_state ? static_cast<int>(st) : -1);
							}
							else
							{
								LOG(2, "Sponsor TID %06X Not Running (State = %d); Ignoring Sponsor\n",
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

				LOG(2, "Sponsor Validation Snapshot Failed; Ignoring Sponsor\n");
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
					LOG(2, "Sponsor TID %06X Left Running; Falling Back To Search\n", SponsorTidActual);
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
				Stats.FailCode = INJ_ERR_SUCCESS;
				RecordHijackOutcome(Stats, true);
				LOG(2, "Acquired Target Thread Handle From Sponsor\n");
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

			LOG(2, "Sponsor Thread Failed Validation\n");
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

		std::vector<DWORD> attempt_excluded = excluded;
		if (exclude_tid)
		{
			attempt_excluded.push_back(exclude_tid);
		}

		ThreadID = FindHijackThread(processInformation, attempt_excluded, &selected_was_running, attempt >= 7);

		if (!ThreadID && exclude_tid)
		{
			ThreadID = FindHijackThreadToolhelp(hTargetProc, attempt_excluded);
			selected_was_running = false;
			if (ThreadID)
			{
				LOG(2, "Second-Pass Snapshot Fallback = %06X\n", ThreadID);
			}
		}
	}

		if (!ThreadID)
		{
			ThreadID = FindHijackThreadToolhelp(hTargetProc, excluded);
			selected_was_running = false;
			if (ThreadID)
			{
				LOG(2, "Acquired Target Thread Via Snapshot Fallback = %06X\n", ThreadID);
			}
		}

		if (!ThreadID)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "No Compatible Thread Found\n");

			return SR_HT_ERR_NO_THREADS;
		}
	}

	LOG(2, "Target Thread = %06X\n", ThreadID);
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
					LOG(2, "Acquired Target Thread Handle Via Acquisition\n");
				}
				else
				{
					if (ScanStats.FailCode == INJ_ERR_SUCCESS)
					{
						ScanStats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
					}
					ScanStats.Source = static_cast<DWORD>(HijackSource::Scan);

					Stats = ScanStats;
					LOG(2, "Thread Handle Acquisition Found No Donor\n");
				}
			}

			if (!hThread)
			{

				Stats.Source = static_cast<DWORD>(HijackSource::Scan);
				RecordHijackOutcome(Stats, true);

				if (!AllowDirectHandleFallback())
				{
					INIT_ERROR_DATA(error_data, INJ_ERR_HANDLE_HIJACK_FAILED);

					LOG(2, "Thread Handle Acquisition Found No Donor; Refusing (No Direct Fallback)\n");

					return SR_HT_ERR_OPEN_REFUSED;
				}

				LOG(2, "Thread Handle Acquisition Found No Donor; Direct Fallback Enabled By INJ_ALLOW_DIRECT_FALLBACK\n");
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

		if (hThread && ScGetProcessIdOfThread(hThread.get()) != GetProcessId(hTargetProc))
		{
			LOG(2, "Opened Thread %06X No Longer Belongs To The Target Process; Discarding\n", ThreadID);

			hThread.reset();
		}
	}
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "OpenThread Failed\n");

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

	auto ResumeDonorThread = [&](const char * site) -> bool
	{
		if (ResumeThreadWithRetry(hThread.get()))
		{
			return true;
		}

		LOG(1, "[ThreadHijack] [!] ResumeThread Failed Permanently (%s); Donor Thread Left Suspended\n", site);

		return false;
	};

	constexpr size_t kWxCodePage = 0x1000;
	constexpr size_t kWxAllocSize = 0x2000;

	static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kWxCodePage,
		"the FP/XSAVE image does not fit the RW state page - raise kWxAllocSize and re-split the pages");
	// The stub is copied out of this image and re-laid out in the target: the
	// executable part goes on an execute-read page and the state block goes on a
	// read-write page, so the target never holds a writable page of code.
	const ULONG_PTR shellcode_begin = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin);
	const ULONG_PTR shellcode_end = reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd);

	const size_t shellcode_size = static_cast<size_t>(shellcode_end - shellcode_begin);
	if (!shellcode_size)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_STUB_PATCH_FAIL;
	}

	const size_t state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - shellcode_begin);
	const size_t return_target_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - shellcode_begin);
	const size_t state_area_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadState));
	// The state block has to sit behind the code, and it has to be large enough
	// for the FP image plus the slot that holds the thread's return address.
	// The state block has to sit behind the code, and it has to be large enough
	// for the FP image plus the slot that holds the thread's return address.
	// Anything else means the assembler layout drifted away from what this
	// code expects, and the stub must not be staged.
	if (return_target_offset < state_offset ||
		return_target_offset + sizeof(ULONG_PTR) > shellcode_size ||
		state_area_size < SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "Shellcode State Layout Rejected (Code = %llx | State = %llx | Return = %llx | Area = %llx)\n",
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
	// The staged image is split across two pages: code on the first, the state
	// block on the second.
	// The staged image is split across two pages: code on the first, the state
	// block on the second.
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
		// The RIP-relative displacements in the stub were computed for the layout
		// of this image. The state block moves to a different page in the target,
		// so every displacement that points at it is shifted by the same amount.
		// The RIP-relative displacements in the stub were computed for the layout
		// of this image. The state block moves to a different page in the target,
		// so every displacement that points at it is shifted by the same amount.
		const int pad32 = static_cast<int>(pad);
		const BYTE lea_prefix[3] = { 0x48, 0x8D, 0x1D };
		const BYTE jmp_prefix[2] = { 0xFF, 0x25 };

		auto patch_rel32 = [&](const BYTE * label, const BYTE * prefix, size_t prefix_len, const char * site) -> bool
		{
			(void)site;
			const size_t site_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(label) - shellcode_begin);
			if (site_offset + prefix_len + sizeof(int) > code_size)
			{
				LOG(2, "Patch Site %s Out Of Range\n", site);
				return false;
			}
			if (memcmp(staged.data() + site_offset, prefix, prefix_len) != 0)
			{
				LOG(2, "Patch Site %s Opcode Mismatch\n", site);
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
					LOG(2, "Patch Site %s Out Of Range\n", site);
					return false;
				}
				if (memcmp(staged.data() + site_offset, prefix, sizeof(teb_read_prefix)) != 0)
				{
					LOG(2, "Patch Site %s Opcode Mismatch\n", site);
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

	StoreThreadExecStat(g_ThreadExecStats.Attempted, 1);
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

	ULONG sr_suspend = 0;
	if (NT_FAIL(ScNtSuspendThread(hThread, &sr_suspend)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "SuspendThread Failed\n");

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	if (sr_suspend > 0)
	{
		LOG(2, "Thread Was Already Suspended (Previous Count %u); Skipping It\n", sr_suspend);

		ResumeDonorThread("already-suspended");

		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_SUSPEND_FAIL;
	}

	LOG(2, "Target Thread Suspended\n");

	CONTEXT OldContext{ 0 };
	OldContext.ContextFlags = CONTEXT_ALL;

	if (NT_FAIL(ScNtGetContextThread(hThread, &OldContext)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "GetThreadContext Failed\n");

		ResumeDonorThread("get-context");

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
	InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.OldRsp), static_cast<LONG64>(OldContext.Rsp));
	StoreThreadExecStat(g_ThreadExecStats.FpMode, remote_data->FpFlags);
	StoreThreadExecStat(g_ThreadExecStats.FpMask, remote_data->FpMask);
	LOG(1, "[ThreadHijack] [*] Context Captured: Target RIP = 0x%llX | RSP = 0x%llX\n", (unsigned long long)OldRIP, (unsigned long long)OldContext.Rsp);
	LOG(1, "[ThreadHijack] [*] Floating-Point State: Mode = %s | Ceiling Mask = 0x%X | Area = %u Bytes\n", remote_data->FpFlags ? "XSAVE" : "FXSAVE", remote_data->FpMask, SR_FP_AREA_SIZE);
	LOG(1, "[ThreadHijack] [*] Staging: VA = %p | RX = 0x1000 | RW = 0x%llX\n", pMem, (unsigned long long)(kWxAllocSize - kWxCodePage));
	LOG(1, "[ThreadHijack] [*] RIP Redirection: 0x%llX -> %p\n", (unsigned long long)OldRIP, pRemoteFunc);
	LOG(2, "Remote Thread Shell Prepared (W^X Split: Code RX 0x1000, State RW)\n");

	LOG(2, "Acquiring Thread With:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pArg);

	if (!ScWriteProcessMemory(hTargetProc, pMem, staged.data(), staged.size(), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "WriteProcessMemory Failed\n");

		ResumeDonorThread("write-memory");

		return SR_HT_ERR_WPM_FAIL;
	}

	{
		if (!ScProtectMemory(hTargetProc, pCode, kWxCodePage, PAGE_EXECUTE_READ))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "Protect(RX) Failed\n");

			ResumeDonorThread("protect-rx");

			return SR_HT_ERR_WPM_FAIL;
		}

		if (!FlushInstructionCache(hTargetProc, pCode, code_size))
		{
			LOG(2, "FlushInstructionCache Failed\n");
		}
		LOG(2, "Acquired Code Promoted RW->RX, State Stays RW\n");
	}

	if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "SetThreadContext Failed\n");

		ResumeDonorThread("set-context");

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	LOG(2, "RIP Replaced\n");

	{
		ULONG sr_resume = 0;
		if (NT_FAIL(ScNtResumeThread(hThread, &sr_resume)))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "ResumeThread Failed\n");

			OldContext.Rip = OldRIP;
			if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
			{
				LOG(2, "Thread Context Recovery Failed; Remote Allocation Retained\n");

				if (!EnqueueDeferredTrampoline(hTargetProc, hThread, pMem))
				{
					LOG(1, "[ThreadHijack] [!] Deferred Tracking Unavailable; Remote Allocation Retained Untracked (Base = %p)\n", pMem);
				}

				allocation_guard.release();
				return SR_HT_ERR_RECOVERY_REQUIRED;
			}

			ResumeDonorThread("rollback-resume");

			return SR_HT_ERR_RESUME_FAIL;
		}
	}

	LOG(2, "Thread Resumed\n");

	SR_REMOTE_DATA data{ };
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	LOG(2, "Entering Wait State\n");
	// The thread can be interrupted at any point. When that happens the context
	// is rolled back if the thread is still inside a recoverable frame, and the
	// remote allocation is reclaimed or deferred otherwise.
	constexpr int kForceRestorePolls = 24;

	// The stub pushes sixteen registers plus the flags, so the stack pointer sits
	// at most a couple of hundred bytes below the victim's RSP while it runs.
	// A thread whose RSP is still inside that window can be rewound safely.
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

					ctx = OldContext;
					ctx.Rip = OldRIP;	
					restored = NT_SUCCESS(ScNtSetContextThread(hThread, &ctx)) != FALSE;
					settled = true;
				}

			}

			resumed = ResumeDonorThread("force-restore");
			
			
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

	
	// The remote allocation may only be released once the hijacked thread is
	// provably no longer executing from it.
	
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

	
	// Decide what happens to the trampoline: reclaim it now, or hand it to the
	// deferred reaper that will try again later.
	
	auto ReclaimOrRetainTrampoline = [&](bool context_restored, SR_REMOTE_STATE State) -> void
	{
		if (context_restored)
		{
			return;
		}

		if (RemoteRoutineSettled(State) && StubRegionFreeToRelease())
		{
			LOG(2, "Thread Is No Longer Inside The Stub; Remote Allocation Reclaimed\n");
			return;
		}

		if (!RemoteRoutineSettled(State))
		{
			LOG(2, "Stub State Not Settled (State = %d); Remote Allocation Deferred For Reclaim\n", static_cast<int>(State));
		}
		else
		{
			LOG(2, "Thread Context Recovery Failed; Remote Allocation Deferred For Reclaim\n");
		}

		if (EnqueueDeferredTrampoline(hTargetProc, hThread, pMem))
		{
			allocation_guard.release();
		}
		else if (StubRegionFreeToRelease())
		{
			LOG(2, "Deferred Tracking Unavailable; Thread Outside Stub, Reclaiming Now\n");
		}
		else
		{
			LOG(1, "[ThreadHijack] [!] Deferred Tracking Unavailable; Remote Allocation Retained Untracked (Base = %p)\n", pMem);

			allocation_guard.release();
		}
	};

	auto Timer = GetTickCount64();
	DWORD consecutive_read_failures = 0;
	DWORD poll_iterations = 0;

	DWORD poll_wait_ms = 1;

	// A stub that never got scheduled is a common failure: the donor thread was
	// parked on something the OS would not wake for us. A single posted message
	// nudges it once before the whole attempt is abandoned.
	
	
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

			if (RemoteRoutineSettled(data.State))
			{
				LOG(2, "ShellData Retrieved\n");
				const DWORD exec_ms = static_cast<DWORD>(GetTickCount64() - Timer);
				StoreThreadExecStat(g_ThreadExecStats.PollIterations, poll_iterations);
				StoreThreadExecStat(g_ThreadExecStats.ExecMs, exec_ms);
				StoreThreadExecStat(g_ThreadExecStats.RoutineRet, data.Ret);
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.RoutineCyclesDelta), static_cast<LONG64>(data.RoutineCyclesDelta));
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.StackScrubbedBytes), static_cast<LONG64>(data.StackScrubbedBytes));
				{
					// The stub rewrote SR_FP_MASK with the mask it actually used, which
					// is the intersection of the CPU ceiling and the victim's own XCR0.
					// Report that effective mask rather than the staged ceiling.
					StoreThreadExecStat(g_ThreadExecStats.FpMask, data.FpMask);
				}
				{
					ULONG_PTR saved_rsp = 0;
					if (ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(pState) + SR_SAVED_RSP, &saved_rsp, sizeof(saved_rsp), nullptr) && saved_rsp)
					{
						if (data.StackScrubbedBytes && saved_rsp >= data.StackScrubbedBytes)
						{
							InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.StackLimit), static_cast<LONG64>(saved_rsp - data.StackScrubbedBytes));
						}
					}
				}
				LOG(1, "[ThreadHijack] [*] Polling Execution: State = Finished | Iterations = %u | Elapsed = %u ms | Return Value = 0x%08X\n", poll_iterations, exec_ms, data.Ret);

				
				if (data.StackScrubbedBytes)
				{
					LOG(1, "[ThreadHijack] [+] Stack Sanitization: Scrubbed = %llu Bytes | Cycles = %llu\n",
						(unsigned long long)data.StackScrubbedBytes,
						(unsigned long long)data.RoutineCyclesDelta);
				}
				else
				{
					LOG(1, "[ThreadHijack] [*] Stack Sanitization: 0 Bytes Scrubbed (No Sanitization Result Reported)\n");
				}

				break;
			}

			const ULONGLONG waited = GetTickCount64() - Timer;

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= kStartupProbeMs)
			{
				LOG(2, "Stub Not Scheduled Within %u ms (Sampled State Was %s); Failing Fast\n",
					kStartupProbeMs, selected_was_running ? "Running" : "Waiting");

				break;
			}

			if (!nudge_sent && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= nudge_after_ms)
			{
				nudge_sent = true;

				if (!PostThreadMessageW(ThreadID, WM_NULL, 0, 0))
				{
					LOG(2, "Wake Nudge Failed For TID %06X; Relying On The Poll Alone\n", ThreadID);
				}
				else
				{
					LOG(2, "Stub Unscheduled For %u ms; Wake Nudge Sent\n", nudge_after_ms);
				}
			}
		}

		if (dwWaitRet == WAIT_OBJECT_0)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_INTERRUPT);

			LOG(2, "Interrupt!\n");

			bool context_restored = false;
			bool resumed = false;
			if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

			ReclaimOrRetainTrampoline(context_restored, data.State);

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

				LOG(2, "Target Process Exited During Load\n");

				allocation_guard.release();

				return SR_ERR_TARGET_EXITED;
			}

			if (++consecutive_read_failures <= 100)
			{
				continue;
			}

			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "ReadProcessMemory Failed\n");

			bool context_restored = false;
			bool resumed = false;
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ForceRestoreContext(context_restored, resumed);
			}

		ReclaimOrRetainTrampoline(context_restored, data.State);

		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED);

		return context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED;
		}

	}
	if (!RemoteRoutineSettled(data.State))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		bool context_restored = false;
		bool resumed = false;
		if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
		{
			LOG(2, "Shell Timed Out\n");

			ForceRestoreContext(context_restored, resumed);
		}

		ReclaimOrRetainTrampoline(context_restored, data.State);

		StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
		StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_REMOTE_PENDING_TIMEOUT : SR_HT_ERR_RECOVERY_REQUIRED);

		if (context_restored)
		{
			return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
		}

		return SR_HT_ERR_RECOVERY_REQUIRED;
	}

	LOG(2, "pRoutine Returned = %08X\n", data.Ret);

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

				check_context = OldContext;
				check_context.Rip = OldRIP;	
				context_restored = NT_SUCCESS(ScNtSetContextThread(hThread, &check_context)) != FALSE;
			}

			resumed_check = ResumeDonorThread("exec-verify");
		}
		else
		{
			resumed_check = ResumeDonorThread("exec-verify-no-context");
		}

		if (!resumed_check)
		{
			context_restored = false;
		}
	}

	if (context_restored)
	{
		LOG(2, "Thread Context Restored Automatically\n");
		LOG(1, "[ThreadHijack] [+] Context Verification: Restored RIP = 0x%llX | Thread Resumed\n", (unsigned long long)OldRIP);
	}
	else
	{
		LOG(1, "[ThreadHijack] [x] Context Verification Failed: RIP = 0x%llX | Not Restored\n", (unsigned long long)OldRIP);
	}

	ReclaimOrRetainTrampoline(context_restored, data.State);

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
		ReapDeferredTrampolines();

		const ULONGLONG elapsed = GetTickCount64() - budget_start;
		if (elapsed >= Timeout)
		{
			break;
		}

		StoreThreadExecStat(g_ThreadExecStats.HijackedTid, 0);

		const DWORD remaining = Timeout - static_cast<DWORD>(elapsed);
		const bool sponsor_round = (round == 0);
		const ULONG_PTR sponsor_handle = sponsor_round ? SponsorThread : 0;
		const DWORD sponsor_tid = sponsor_round ? SponsorTid : 0;

		LOG(2, "Donor Round %d/%d, %u ms Remaining, %u Candidate(s) Excluded\n",
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
				LOG(2, "Excluding Donor TID %06X After Code %08X\n", failed_tid, last_code);
			}
		}
	}

	LOG(2, "Donor Search Exhausted After %u Round(s)\n", static_cast<DWORD>(excluded.size()));

	ReapDeferredTrampolines();

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
