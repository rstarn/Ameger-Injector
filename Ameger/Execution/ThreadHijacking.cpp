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

		// The block is published a word at a time so that a reader never sees
		// a half-written value. The copy is taken through a value-initialised
		// instance first, so every word that is published is a defined value.
		THREAD_EXEC_STATS copy{};
		copy = Src;

		volatile LONG * dst = ReCa<volatile LONG *>(&g_ThreadExecStats);
		const LONG * src = ReCa<const LONG *>(&copy);
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

	// Hijack staging geometry, mirrored by SR_SHELL_* in Execution/Routine/StartRoutine.h
	// and RemoteShell.inc: an execute-read code page, a read-write state page, then
	// the dedicated shell stack the stub pivots onto before it calls the routine.
	constexpr SIZE_T kHijackCodePage = 0x1000;
	constexpr SIZE_T kHijackStatePage = 0x1000;
	constexpr SIZE_T kHijackGuardPage = 0x1000;
	constexpr SIZE_T kHijackShellStack = SR_SHELL_STACK_SIZE;
	constexpr SIZE_T kHijackAllocationSize = kHijackCodePage + kHijackStatePage + kHijackGuardPage + kHijackShellStack;

	// The stub pushes RFLAGS plus all sixteen general-purpose registers on the
	// victim stack before it pivots. Those 136 bytes hold the victim's own
	// register values; nothing belonging to the injector is ever placed there.
	constexpr DWORD kHijackVictimStackBytes = 17 * sizeof(ULONG_PTR);

	static_assert(SR_SHELL_STACK_BASE == kHijackStatePage + kHijackGuardPage,
		"the shell stack must start after the guard page");
	static_assert(SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE == kHijackStatePage + kHijackGuardPage + kHijackShellStack,
		"the stub shell stack geometry must match the host allocation");
	static_assert(SR_SHELL_STACK_TOP + 0x20 <= SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE,
		"the stub pivot address must stay inside the shell stack");
	static_assert(SR_SHELL_STACK_TOP % 16 == 0,
		"the shell stack top must be 16-byte aligned");

	// How many threads may be probed per candidate before the scan gives up on
	// finding a running one and falls back to a waiting thread.
	constexpr DWORD kMaxHandleProbes = 4;

	constexpr DWORD kStartupProbeMs = 2000;

	constexpr int kMaxDonorRounds = 16;

	bool IsSafeWaitReason(KWAIT_REASON reason)
	{
		return WAIT_REASON_SAFE::IsSafe(static_cast<unsigned char>(reason));
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

	// B4: the thread census is pure diagnostics - it opens every thread of the
	// target once to print a table - and each of those opens is a handle-table
	// entry an onlooker can count. It only runs when it was asked for; a quiet
	// run performs no thread opens for the census at all.
	bool ThreadCensusEnabled()
	{
		static const bool enabled = []() -> bool
		{
			wchar_t buffer[8] = {};
			const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_CENSUS").get(), buffer, 4);
			return got == 1 && buffer[0] == L'1';
		}();
		return enabled;
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

	// The runtime's donor-selection policy. The launcher keeps a second,
	// advisory copy of this policy (PickHijackThreadTid in
	// Interface/Source/Main.cpp) to pre-open a sponsor thread; the runtime
	// re-validates whatever it is handed here, but the two implementations
	// express the same preference order and must be moved together.
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
	DWORD delay_fallback = 0;
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

		// B2: within the safe waits, the event-driven reasons are preferred
		// over the delay reasons: a delay wait only wakes when its timer
		// expires, and how long that timer still has to run cannot be known
		// from outside. A delay wait is still taken when nothing else
		// qualified, so the search's reach is not narrowed.
		if (allow_waiting && state == waiting && IsSafeWaitReason(reason))
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

			if (!WAIT_REASON_SAFE::IsDelay(static_cast<unsigned char>(reason)))
			{
				if (!fallback)
				{
					fallback = candidate;
				}
			}
			else if (!delay_fallback)
			{
				delay_fallback = candidate;
			}
		}
	}
	while (processInformation.NextThread());

	if (out_was_running)
	{
		*out_was_running = false;
	}
	return fallback ? fallback : delay_fallback;
	}

	struct DeferredTrampoline
	{
		HANDLE	Process = nullptr;
		HANDLE	Thread	= nullptr;
		void *	Base	= nullptr;
	};

	constexpr SIZE_T kDeferredTrampolineSize = kHijackAllocationSize;
	constexpr SIZE_T kDeferredCodePage = kHijackCodePage;

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

		// Both handles are duplicated the same way, so the duplication is
		// done through one helper and the two failures cannot drift apart.
		const auto duplicate = [](HANDLE source, HANDLE & out) -> DWORD
		{
			if (DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				return ERROR_SUCCESS;
			}
			return GetLastError();
		};

		if (!Process || Process == INVALID_HANDLE_VALUE || !Thread || Thread == INVALID_HANDLE_VALUE || !Base)
		{
			DupError = ERROR_INVALID_HANDLE;
		}
		else
		{
			DupError = duplicate(Process, DupProcess);
			if (DupError == ERROR_SUCCESS)
			{
				DupError = duplicate(Thread, DupThread);
			}
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
			if (!ScReadProcessMemory(Entry.Process, ReCa<BYTE *>(Entry.Base) + kDeferredCodePage, &state, sizeof(state), nullptr))
			{
				retained.push_back(Entry);
				continue;
			}

			// B7: a trampoline whose stub never started - state still Pending,
			// RIP still at the stub entry, RSP still the victim's own - can be
			// unwound from the state page itself. The saved RSP and the return
			// target are both stored there, the hijack only ever changed RIP,
			// and nothing was pushed. The donor is put back at its original
			// instruction and the allocation is reclaimed instead of being
			// carried as a permanent private region.
			if (state == SR_REMOTE_STATE::SR_RS_ExecutionPending)
			{
				ULONG rewind_previous = 0;
				const NTSTATUS rewind_suspend = ScNtSuspendThread(Entry.Thread, &rewind_previous);
				bool rewind_reclaimed = false;
				bool rewind_resumed = false;
				if (!NT_FAIL(rewind_suspend) && rewind_previous == 0)
				{
					CONTEXT rewind{ 0 };
					rewind.ContextFlags = CONTEXT_CONTROL;
					if (NT_SUCCESS(ScNtGetContextThread(Entry.Thread, &rewind)))
					{
						const size_t state_off = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
						const size_t return_off = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
						const BYTE * state_page = ReCa<const BYTE *>(Entry.Base) + kDeferredCodePage;
						ULONG_PTR saved_rsp = 0;
						ULONG_PTR return_target = 0;
						if (rewind.Rip == ReCa<ULONG_PTR>(Entry.Base) &&
							ScReadProcessMemory(Entry.Process, state_page + SR_SAVED_RSP, &saved_rsp, sizeof(saved_rsp), nullptr) &&
							rewind.Rsp == saved_rsp &&
							ScReadProcessMemory(Entry.Process, state_page + (return_off - state_off), &return_target, sizeof(return_target), nullptr) &&
							return_target)
						{
							rewind.Rip = return_target;
							if (NT_SUCCESS(ScNtSetContextThread(Entry.Thread, &rewind)))
							{
								rewind_reclaimed = true;
							}
						}
					}
					rewind_resumed = ResumeThreadWithRetry(Entry.Thread);
				}
				else if (!NT_FAIL(rewind_suspend))
				{
					// Suspended by somebody else; leave it exactly as found.
					ResumeThreadWithRetry(Entry.Thread);
				}

				if (rewind_reclaimed && rewind_resumed)
				{
					LOG(2, "Deferred Trampoline Reclaimed: Stub Never Started; Donor Rewound (Base = %p)\n", Entry.Base);

					ScrubRemoteRegion(Entry.Process, Entry.Base, kDeferredTrampolineSize, kScrubChunk);
					if (VirtualFreeEx(Entry.Process, Entry.Base, 0, MEM_RELEASE))
					{
						CloseDeferredTrampoline(Entry);
						continue;
					}

					LOG(2, "Deferred Trampoline Free Failed; Retained (Base = %p)\n", Entry.Base);
					retained.push_back(Entry);
					continue;
				}

				retained.push_back(Entry);
				continue;
			}

			if (!RemoteRoutineSettled(state))
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

static DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)
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
		bool sponsor_still_running = false;
		bool sponsor_still_usable = false;
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
								// context restore path can roll it back. A delay wait is
								// called out in the log because its wake time is unknown and
								// the startup probe may roll it back into a retry.
								sponsor_usable = true;
								LOG(2, "Sponsor TID %06X Waiting On Safe Reason %d (%s Wait); Accepting Sponsor\n",
									SponsorTidActual, static_cast<int>(wr),
									WAIT_REASON_SAFE::IsDelay(static_cast<unsigned char>(wr)) ? "Delay, Wake Time Unknown" : "Event");
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
							if (processInformation.GetThreadState(rst, rwr))
							{
								if (rst == rerun_running)
								{
									sponsor_still_running = true;
									sponsor_still_usable = true;
								}
								else if (rst == KTHREAD_STATE::Waiting && IsSafeWaitReason(rwr))
								{
									// A sponsor accepted because it was parked on a safe wait
									// is parked here as well; the confirmation has to accept
									// that same state, otherwise the safe-wait acceptance
									// above is undone by a running-only re-check.
									sponsor_still_usable = true;
								}
							}
							break;
						}
					} while (processInformation.NextThread());
					processInformation.SetCurrentThreadHandle(nullptr, 0);
				}
				if (!sponsor_still_usable)
				{
					LOG(2, "Sponsor TID %06X Not Usable On Re-Check; Falling Back To Search\n", SponsorTidActual);
					sponsor_usable = false;
				}
			}

			if (sponsor_usable)
			{
				ThreadID = SponsorTidActual;
				selected_was_running = sponsor_still_running;
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
	if (ThreadCensusEnabled())
	{
		ProcessInformation census_pi;
		LogThreadCensus(hTargetProc, census_pi, excluded, ThreadID);
		processInformation.SetProcess(hTargetProc);
	}
	else
	{
		LOG(2, "[ThreadHijack] [*] Census Skipped (Not Requested; No Thread Opens)\n");
	}

	// The chosen thread is recorded before its handle is acquired. A thread
	// that cannot be opened, or that turns out to belong to another process,
	// is then excluded from the next round. Without this the same dead
	// thread is picked again on every round and the search never moves on.
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

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

	static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kHijackStatePage,
		"the FP/XSAVE image does not fit the RW state page - raise kHijackAllocationSize and re-split the pages");
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
	const size_t pad = kHijackCodePage - code_size;
	if (code_size >= kHijackCodePage || data_size > kHijackCodePage)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_STUB_PATCH_FAIL;
	}

	std::vector<BYTE> shellcode(shellcode_size);
	memcpy(shellcode.data(), RemoteThreadHijackBegin, shellcode_size);
	// Three page groups: the executable stub, the state block, then the shell
	// stack. Only the first two are staged; the stack is left zero, which is
	// what the allocator already guarantees.
	std::vector<BYTE> staged(kHijackCodePage + data_size, 0x00);

	void * pMem = ScAllocateMemory(hTargetProc, kHijackAllocationSize, PAGE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	RemoteAllocation allocation_guard(hTargetProc, pMem);

	auto scrub_guard = MakeScopeExit([&]() noexcept {
		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pMem, kHijackAllocationSize, kScrubChunk);
		}
	});

	memcpy(staged.data(), shellcode.data(), code_size);
	memcpy(staged.data() + kHijackCodePage, shellcode.data() + state_offset, data_size);

	{
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

	const size_t staged_return_offset = kHijackCodePage + (return_target_offset - state_offset);
	const size_t staged_state_offset = kHijackCodePage;

	const auto OldRIP = OldContext.Rip;
	*reinterpret_cast<ULONG_PTR *>(staged.data() + staged_return_offset) = OldRIP;
	auto * remote_data = reinterpret_cast<SR_REMOTE_DATA *>(staged.data() + staged_state_offset);
	remote_data->pArg = pArg;
	remote_data->pRoutine = pRoutine;

	BYTE * pCode = ReCa<BYTE *>(pMem);
	BYTE * pState = ReCa<BYTE *>(pMem) + kHijackCodePage;

	ProbeFpCaps(remote_data->FpFlags, remote_data->FpMask, pState);
	remote_data->ShellCw = 0x037F;
	remote_data->ShellMxcsr = 0x01F80;
	remote_data->RoutineCyclesDelta = 0;
	remote_data->ShellStackTop = 0;

	{
		const ULONG_PTR shell_stack_base = ReCa<ULONG_PTR>(pState) + SR_SHELL_STACK_BASE;
		InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.ShellStackBase), static_cast<LONG64>(shell_stack_base));
		StoreThreadExecStat(g_ThreadExecStats.ShellStackSize, static_cast<DWORD>(kHijackShellStack));
		StoreThreadExecStat(g_ThreadExecStats.VictimStackBytes, kHijackVictimStackBytes);
		StoreThreadExecStat(g_ThreadExecStats.ShellStackResumeCount, 0);
	}

	void * pRemoteFunc = pCode;
	OldContext.Rip = reinterpret_cast<ULONG_PTR>(pRemoteFunc);

	InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.OldRip), static_cast<LONG64>(OldRIP));
	InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.OldRsp), static_cast<LONG64>(OldContext.Rsp));
	StoreThreadExecStat(g_ThreadExecStats.FpMode, remote_data->FpFlags);
	StoreThreadExecStat(g_ThreadExecStats.FpMask, remote_data->FpMask);
	LOG(1, "[ThreadHijack] [*] Context Captured: Target RIP = 0x%llX | RSP = 0x%llX\n", (unsigned long long)OldRIP, (unsigned long long)OldContext.Rsp);
	LOG(1, "[ThreadHijack] [*] Floating-Point State: Mode = %s | Ceiling Mask = 0x%X | Area = %u Bytes\n", remote_data->FpFlags ? "XSAVE" : "FXSAVE", remote_data->FpMask, SR_FP_AREA_SIZE);
	LOG(1, "[ThreadHijack] [*] Staging: VA = %p | Code RX = 0x1000 | State RW = 0x1000 | Shell Stack RW = %llu Bytes\n",
		pMem, static_cast<unsigned long long>(kHijackShellStack));
	LOG(1, "[ThreadHijack] [*] RIP Redirection: 0x%llX -> %p\n", (unsigned long long)OldRIP, pRemoteFunc);
	LOG(2, "Remote Thread Shell Prepared (W^X Split: Code RX 0x1000, State RW)\n");

	LOG(2, "Acquiring Thread With:\n");
	LOG(3, "pRoutine = %p\n", pRemoteFunc);
	LOG(3, "pArg     = %p\n", pArg);

	{
		// Every byte has to land: the shell is about to be executed in the
		// target, so a short write is a failure and not a warning.
		SIZE_T staged_written = 0;
		const bool staged_ok = ScWriteProcessMemory(hTargetProc, pMem, staged.data(), staged.size(), &staged_written) &&
			staged_written == staged.size();
		if (!staged_ok)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(2, "WriteProcessMemory Failed (Wrote %llu Of %llu Bytes)\n",
				(unsigned long long)staged_written, (unsigned long long)staged.size());

			ResumeDonorThread("write-memory");

			return SR_HT_ERR_WPM_FAIL;
		}
	}

	{
		// M3: guard page between the state page and the shell stack.
		const BOOL guard_page_ok = ScProtectMemory(hTargetProc, ReCa<BYTE *>(pMem) + kHijackCodePage + kHijackStatePage, kHijackGuardPage, PAGE_NOACCESS);
		if (!guard_page_ok)
		{
			LOG(2, "Guard Page Protect(NOACCESS) Failed\n");
		}
		else
		{
			LOG(2, "Guard Page Established (NOACCESS) Between State Page And Shell Stack\n");
		}

		if (!ScProtectMemory(hTargetProc, pCode, kHijackCodePage, PAGE_EXECUTE_READ))
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
		const ULONG_PTR code_end = code_base + kHijackCodePage;

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

		return probe.Rip < code_base || probe.Rip >= code_base + kHijackCodePage;
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

	// A6: the shell signals this event immediately before it returns, so the
	// state page settles a handful of instructions later. Waiting on both
	// handles lets the host observe that transition at once instead of on the
	// next backoff tick; the grace bound keeps a lost completion from turning
	// the loop into an unbounded spin.
	// M1: a manual-reset completion event is shared across donor rounds, so
	// reset it here for every attempt; otherwise a stale signal makes the wait
	// return immediately. The grace break below is also removed, so a signaled
	// event never aborts polling before the state page settles or the timeout
	// expires.
	if (CompletionEvent)
	{
		ResetEvent(CompletionEvent);
	}

	bool completion_seen = false;
	ULONGLONG completion_seen_at = 0;
	HANDLE wait_handles[2] = { g_hInterruptEvent, CompletionEvent };
	const DWORD wait_count = CompletionEvent ? 2 : 1;

	// A stub that never got scheduled is a common failure: the donor thread was
	// parked on something the OS would not wake for us. A single posted message
	// nudges it once before the whole attempt is abandoned.
	bool nudge_sent = false;
	DWORD nudge_after_ms = 250;

	// Shell stack geometry, computed once: the state page sits at pState and
	// the shell stack begins SR_SHELL_STACK_BASE bytes into it. These values
	// are used both for the observation counter (below) and for the final
	// pivot verification.
	const ULONG_PTR shell_base = ReCa<ULONG_PTR>(pState) + SR_SHELL_STACK_BASE;
	const ULONG_PTR shell_end = shell_base + SR_SHELL_STACK_SIZE;

	while (GetTickCount64() - Timer < Timeout)
	{
		auto dwWaitRet = WaitForMultipleObjects(wait_count, wait_handles, FALSE, poll_wait_ms);
		const bool completion_signaled = CompletionEvent && dwWaitRet == WAIT_OBJECT_0 + 1;

		if (completion_signaled)
		{
			if (!completion_seen)
			{
				completion_seen = true;
				completion_seen_at = GetTickCount64();

				LOG(2, "Completion Event Signaled; Polling The State Page At Full Speed\n");
			}
			else if (GetTickCount64() - completion_seen_at > 1000)
			{
				LOG(2, "Completion Event Signaled But The Stub State Has Not Settled Yet; Continuing To Poll\n");
			}

			poll_wait_ms = 1;
		}
		else
		{
			poll_wait_ms = poll_wait_ms < 5 ? 5 : 25;
		}

		++poll_iterations;

		BOOL bRet = ScReadProcessMemory(hTargetProc, pState, &data, sizeof(data), nullptr);
		if (bRet)
		{
			consecutive_read_failures = 0;

			// Count live observations of the thread executing on the shell
			// stack: each poll that sees State == Executing with RSP inside
			// the window is an independent confirmation that the pivot held.
			// A counter > 0 means the host directly observed the thread
			// resumed on the shell stack, not merely that the staging
			// allocation was set up.
			if (data.State == SR_REMOTE_STATE::SR_RS_Executing &&
				data.ShellStackTop >= shell_base && data.ShellStackTop < shell_end)
			{
				InterlockedIncrement(ReCa<volatile LONG *>(&g_ThreadExecStats.ShellStackResumeCount));
			}

			if (RemoteRoutineSettled(data.State))
			{
				LOG(2, "ShellData Retrieved\n");
				const DWORD exec_ms = static_cast<DWORD>(GetTickCount64() - Timer);
				StoreThreadExecStat(g_ThreadExecStats.PollIterations, poll_iterations);
				StoreThreadExecStat(g_ThreadExecStats.ExecMs, exec_ms);
				StoreThreadExecStat(g_ThreadExecStats.RoutineRet, data.Ret);
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.RoutineCyclesDelta), static_cast<LONG64>(data.RoutineCyclesDelta));
				InterlockedExchange64(ReCa<volatile LONG64 *>(&g_ThreadExecStats.ShellStackTop), static_cast<LONG64>(data.ShellStackTop));
				{
					// The stub rewrote SR_FP_MASK with the mask it actually used, which
					// is the intersection of the CPU ceiling and the victim's own XCR0.
					// Report that effective mask rather than the staged ceiling.
					StoreThreadExecStat(g_ThreadExecStats.FpMask, data.FpMask);
				}
				const bool shell_pivot_ok = data.ShellStackTop >= shell_base && data.ShellStackTop < shell_end;
				LOG(1, "[ThreadHijack] [*] Polling Execution: State = Finished | Iterations = %u | Elapsed = %u ms | Return Value = 0x%08X\n", poll_iterations, exec_ms, data.Ret);

				if (CompletionEvent)
				{
					LOG(1, "[ThreadHijack] [%s] Completion Event: %s | Iterations = %u\n",
						completion_seen ? "+" : "*",
						completion_seen ? "Signaled Before The State Page Settled" : "Not Observed Before Settlement",
						poll_iterations);
				}

				if (shell_pivot_ok)
				{
					StoreThreadExecStat(g_ThreadExecStats.Success, 1);
					LOG(1, "[ThreadHijack] [+] Shell Stack Pivot: RSP = 0x%llX Inside 0x%llX..0x%llX | Victim Stack Spill = %u Bytes (Register Values Only) | Cycles = %llu\n",
						(unsigned long long)data.ShellStackTop,
						(unsigned long long)shell_base, (unsigned long long)shell_end,
						static_cast<unsigned>(kHijackVictimStackBytes),
						(unsigned long long)data.RoutineCyclesDelta);
				}
				else
				{
					StoreThreadExecStat(g_ThreadExecStats.Success, 0);
					StoreThreadExecStat(g_ThreadExecStats.FailCode, SR_HT_ERR_SHELL_PIVOT_INVALID);
					LOG(1, "[ThreadHijack] [x] Shell Stack Pivot Not Verified: RSP = 0x%llX Outside 0x%llX..0x%llX; The Victim Stack May Have Been Used\n",
						(unsigned long long)data.ShellStackTop,
						(unsigned long long)shell_base, (unsigned long long)shell_end);
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

		// A shell that began finishing while the rollback was polling is a
		// late success, not a timeout. The state page is re-read here so the
		// completion flow below owns the round, and the caller can never
		// launch a retry against an image the shell has already executed.
		if (context_restored)
		{
			SR_REMOTE_DATA fresh{ };
			fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
			if (ScReadProcessMemory(hTargetProc, pState, &fresh, sizeof(fresh), nullptr) &&
				RemoteRoutineSettled(fresh.State))
			{
				data = fresh;
			}
		}

		if (!RemoteRoutineSettled(data.State))
		{
			ReclaimOrRetainTrampoline(context_restored, data.State);

			StoreThreadExecStat(g_ThreadExecStats.Success, (context_restored && resumed) ? 1 : 0);
			StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_REMOTE_PENDING_TIMEOUT : SR_HT_ERR_RECOVERY_REQUIRED);

			if (context_restored)
			{
				return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
			}

			return SR_HT_ERR_RECOVERY_REQUIRED;
		}

		// The round settled late: fall through to the completion flow with the
		// freshest state.
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
			const ULONG_PTR code_end = code_base + kHijackCodePage;
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
	// M2: a pending-timeout round is returned only after the donor's context
	// was confirmed rewound (or the donor died) with the state page still
	// Pending, so the shell provably never started and the image is exactly
	// as it was staged. A round that was finishing late is converted to a
	// success before the return and never reaches this code, so a retry
	// cannot run a second shell against an already-executed image.
	// SR_HT_ERR_RECOVERY_REQUIRED stays non-retryable: that donor may still
	// be inside the stub, and its image belongs to the shell now.
	case SR_HT_ERR_NO_THREADS:
	case SR_HT_ERR_SUSPEND_FAIL:
	case SR_HT_ERR_OPEN_THREAD_FAIL:
	case SR_HT_ERR_OPEN_REFUSED:
	case SR_HT_ERR_REMOTE_PENDING_TIMEOUT:
		return true;
	default:
		return false;
	}
}

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data)
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
			sponsor_handle, sponsor_tid, CompletionEvent, excluded, round_error);

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
	EXPORT_FUNCTION("CoreExecStats", __FUNCDNAME__)

	if (Out)
	{
		LoadThreadExecStats(*Out);
	}
}
