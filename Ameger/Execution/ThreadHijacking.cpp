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


	constexpr SIZE_T kScrubChunk = 0x2000;




	constexpr SIZE_T kHijackCodePage = 0x1000;
	constexpr SIZE_T kHijackStatePage = 0x1000;
	constexpr SIZE_T kHijackGuardPage = 0x1000;
	constexpr SIZE_T kHijackShellStack = SR_SHELL_STACK_SIZE;
	constexpr SIZE_T kHijackAllocationSize = kHijackCodePage + kHijackStatePage + kHijackGuardPage + kHijackShellStack;




	constexpr DWORD kHijackVictimStackBytes = 17 * sizeof(ULONG_PTR);

	static_assert(SR_SHELL_STACK_BASE == kHijackStatePage + kHijackGuardPage,
		"the shell stack must start after the guard page");
	static_assert(SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE == kHijackStatePage + kHijackGuardPage + kHijackShellStack,
		"the stub shell stack geometry must match the host allocation");
	static_assert(SR_SHELL_STACK_TOP + 0x20 <= SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE,
		"the stub pivot address must stay inside the shell stack");
	static_assert(SR_SHELL_STACK_TOP % 16 == 0,
		"the shell stack top must be 16-byte aligned");



	constexpr DWORD kMaxHandleProbes = 4;

	// How long a donor may take to reach the stub before the round gives up on it. A nudgeable
	// (WrUserRequest) donor and a self-expiring (DelayExecution) donor are both allowed the full
	// probe: the first is woken by the nudge, the second by its own timer. A UserRequest donor is
	// neither - and a PostThreadMessageW that returns TRUE only queues a message, it does not end
	// the wait - so it gets a short probe instead of the full one.
	constexpr DWORD kStartupProbeMs = 2000;
	constexpr DWORD kUnwakeableProbeMs = 500;

	constexpr int kMaxDonorRounds = 16;

	const char * DiagMemState(DWORD State)
	{
		switch (State)
		{
		case MEM_COMMIT:	return "MEM_COMMIT";
		case MEM_RESERVE:	return "MEM_RESERVE";
		case MEM_FREE:		return "MEM_FREE";
		default:			return "MEM_OTHER";
		}
	}

	const char * DiagProtect(DWORD Protect)
	{
		switch (Protect & 0xFF)
		{
		case PAGE_NOACCESS:				return "PAGE_NOACCESS";
		case PAGE_READONLY:				return "PAGE_READONLY";
		case PAGE_READWRITE:			return "PAGE_READWRITE";
		case PAGE_WRITECOPY:			return "PAGE_WRITECOPY";
		case PAGE_EXECUTE:				return "PAGE_EXECUTE";
		case PAGE_EXECUTE_READ:			return "PAGE_EXECUTE_READ";
		case PAGE_EXECUTE_READWRITE:	return "PAGE_EXECUTE_READWRITE";
		case PAGE_EXECUTE_WRITECOPY:	return "PAGE_EXECUTE_WRITECOPY";
		default:						return "PAGE_OTHER";
		}
	}

	void DiagRegion(HANDLE hProcess, const void * Address, const char * Label)
	{
		MEMORY_BASIC_INFORMATION mbi{ };
		if (!VirtualQueryEx(hProcess, Address, &mbi, sizeof(mbi)))
		{
			LOG(1, "[ThreadHijack] [*] Hijack Diag: region=%s addr=0x%llX query=fail err=%u\n",
				Label, static_cast<unsigned long long>(ReCa<ULONG_PTR>(Address)), GetLastError());

			return;
		}

		const DWORD prot = mbi.Protect & 0xFF;
		const bool readable = prot == PAGE_READONLY || prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
			prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
		const bool writable = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
			prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
		const bool executable = prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
			prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;

		LOG(1, "[ThreadHijack] [*] Hijack Diag: region=%s addr=0x%llX base=0x%llX size=0x%llX state=%s protect=%s(0x%X) commit=%d read=%d write=%d exec=%d\n",
			Label, static_cast<unsigned long long>(ReCa<ULONG_PTR>(Address)),
			static_cast<unsigned long long>(ReCa<ULONG_PTR>(mbi.BaseAddress)),
			static_cast<unsigned long long>(mbi.RegionSize),
			DiagMemState(mbi.State), DiagProtect(prot), prot,
			mbi.State == MEM_COMMIT ? 1 : 0, readable ? 1 : 0, writable ? 1 : 0, executable ? 1 : 0);
	}

	void DiagMitigations(HANDLE hProcess)
	{
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{ };
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{ };
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{ };

		const BOOL cfg_ok = GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
		const BOOL sig_ok = GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy, &sig, sizeof(sig));
		const BOOL dyn_ok = GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &dyn, sizeof(dyn));

		LOG(1, "[ThreadHijack] [*] Hijack Diag: mitigations cfg_query=%d cfg_guard=%d cfg_strict=%d acg_query=%d acg_microsoft_signed_only=%d acg_store_signed_only=%d dyn_query=%d dynamic_code_prohibited=%d\n",
			cfg_ok ? 1 : 0, (cfg.Flags & 0x1) ? 1 : 0, (cfg.Flags & 0x4) ? 1 : 0,
			sig_ok ? 1 : 0, (sig.Flags & 0x1) ? 1 : 0, (sig.Flags & 0x2) ? 1 : 0,
			dyn_ok ? 1 : 0, (dyn.Flags & 0x1) ? 1 : 0);
	}

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

	DWORD FindHijackThread(ProcessInformation & processInformation, const std::vector<DWORD> & excluded,
		bool * out_was_running = nullptr, bool allow_waiting = true, unsigned char * out_reason = nullptr)
	{

		if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
		{
			LOG(2, "FindAcquireThread: Dynamic Offsets Not Ready, Refusing\n");
			return 0;
		}
	// Rank by wakeability, not by TID: a GUI thread parked in GetMessage (WrUserRequest) is the
	// only waiter a PostThreadMessageW nudge reliably wakes, a delay waiter wakes on its own
	// timer, and a UserRequest waiter does neither - so it is the last resort. The ranking is
	// WAIT_REASON_SAFE::Classify, shared with the launcher's own picker so the two cannot disagree.
	DWORD probes = 0;
	DWORD fallback_probes = 0;
	DWORD best = 0;
	int best_rank = static_cast<int>(WAIT_REASON_SAFE::WAKE_CLASS::Reject);
	unsigned char best_reason = 0;
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

		const WAIT_REASON_SAFE::WAIT_CANDIDATE entry{ static_cast<unsigned char>(state),
			static_cast<unsigned char>(reason) };
		const WAIT_REASON_SAFE::WAKE_CLASS wake_class = WAIT_REASON_SAFE::Classify(entry);

		if (wake_class == WAIT_REASON_SAFE::WAKE_CLASS::Reject)
		{
			continue;
		}

		if (wake_class != WAIT_REASON_SAFE::WAKE_CLASS::Running && !allow_waiting)
		{
			continue;
		}

		if (wake_class == WAIT_REASON_SAFE::WAKE_CLASS::Running)
		{
			if (probes >= kMaxHandleProbes)
			{
				continue;
			}
			++probes;
		}
		else
		{
			if (fallback_probes >= kMaxHandleProbes)
			{
				continue;
			}
			++fallback_probes;
		}

		if (processInformation.IsThreadWorkerThread())
		{
			continue;
		}

		// The first candidate of the best wakeability class wins; a later, harder-to-wake
		// candidate never displaces it.
		const int rank = static_cast<int>(wake_class);
		if (best && rank >= best_rank)
		{
			continue;
		}

		best = candidate;
		best_rank = rank;
		best_reason = entry.Reason;
	}
	while (processInformation.NextThread());

	if (!best)
	{
		if (out_was_running)
		{
			*out_was_running = false;
		}

		return 0;
	}

	if (out_was_running)
	{
		*out_was_running = best_rank == static_cast<int>(WAIT_REASON_SAFE::WAKE_CLASS::Running);
	}

	if (out_reason)
	{
		*out_reason = best_reason;
	}

	return best;
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



	const bool cpu_has_xsave = (regs[2] & (1 << 26)) != 0;
	const bool os_has_xsave = (regs[2] & (1 << 27)) != 0;

	if (!cpu_has_xsave || !os_has_xsave)
	{


		return;
	}


	__cpuidex(regs, 0xD, 0);
	const DWORD supported = static_cast<DWORD>(regs[0]) & SR_FP_XCR0_MASK;
	if (!supported)
	{
		return;
	}





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

		return;
	}

	OutFlags = SR_FP_FLAG_XSAVE;




	OutMask = supported;
}

static DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)
{
	LOG(2, "Begin SR_AcquireThread\n");

	{
		static DWORD diag_mitigation_pid = 0;
		const DWORD diag_pid = AmegerDiagEnabled() ? GetProcessId(hTargetProc) : 0;
		if (diag_pid && diag_pid != diag_mitigation_pid)
		{
			diag_mitigation_pid = diag_pid;

			DiagMitigations(hTargetProc);
		}
	}

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
	// How the selected donor can be woken, so a failed nudge can decide between waiting for the
	// poll and abandoning the donor. Reject means "unknown" (the snapshot fallback carries no
	// wait reason); an unknown donor is never abandoned early.
	WAIT_REASON_SAFE::WAKE_CLASS donor_wake = WAIT_REASON_SAFE::WAKE_CLASS::Reject;

	if ((Flags & INJ_HANDLE_HIJACKING) && SponsorThread && SponsorTid)
	{
		const HANDLE Sponsor = ReCa<HANDLE>(SponsorThread);
		const DWORD TargetPidForSponsor = ScGetProcessId(hTargetProc);
		const DWORD SponsorTidActual = ScGetThreadId(Sponsor);
		bool sponsor_usable = false;
		bool sponsor_still_running = false;
		bool sponsor_still_usable = false;
		unsigned char sponsor_reason = 0;
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




									sponsor_still_usable = true;
									sponsor_reason = static_cast<unsigned char>(rwr);
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
				donor_wake = WAIT_REASON_SAFE::Classify(WAIT_REASON_SAFE::WAIT_CANDIDATE{
					sponsor_still_running ? static_cast<unsigned char>(KTHREAD_STATE::Running)
						: static_cast<unsigned char>(KTHREAD_STATE::Waiting),
					sponsor_reason });
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

		unsigned char selected_reason = 0;
		ThreadID = FindHijackThread(processInformation, attempt_excluded, &selected_was_running, attempt >= 7,
			&selected_reason);

		if (ThreadID)
		{
			donor_wake = WAIT_REASON_SAFE::Classify(WAIT_REASON_SAFE::WAIT_CANDIDATE{
				selected_was_running ? static_cast<unsigned char>(KTHREAD_STATE::Running)
					: static_cast<unsigned char>(KTHREAD_STATE::Waiting),
				selected_reason });
		}

		if (!ThreadID && exclude_tid)
		{
			ThreadID = FindHijackThreadToolhelp(hTargetProc, attempt_excluded);
			selected_was_running = false;
			donor_wake = WAIT_REASON_SAFE::WAKE_CLASS::Reject;
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
			donor_wake = WAIT_REASON_SAFE::WAKE_CLASS::Reject;
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

	{
		static bool diag_census_done = false;
		if (!diag_census_done && AmegerDiagEnabled())
		{
			diag_census_done = true;

			ProcessInformation diag_pi;
			if (diag_pi.SetProcess(hTargetProc))
			{
				LOG(1, "[ThreadHijack] [*] Hijack Diag: donor_census_begin\n");

				do
				{
					const DWORD diag_tid = diag_pi.GetThreadId();
					if (!diag_tid)
					{
						continue;
					}

					KTHREAD_STATE diag_state{ };
					KWAIT_REASON diag_reason{ };
					const bool diag_have = diag_pi.GetThreadState(diag_state, diag_reason);

					LOG(1, "[ThreadHijack] [*] Hijack Diag: donor tid=0x%04X state=%d reason=%d safe=%d delay=%d\n",
						diag_tid,
						diag_have ? static_cast<int>(diag_state) : -1,
						diag_have ? static_cast<int>(diag_reason) : -1,
						(diag_have && IsSafeWaitReason(diag_reason)) ? 1 : 0,
						(diag_have && WAIT_REASON_SAFE::IsDelay(static_cast<unsigned char>(diag_reason))) ? 1 : 0);
				}
				while (diag_pi.NextThread());

				LOG(1, "[ThreadHijack] [*] Hijack Diag: donor_census_end\n");
			}
		}
	}





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

	if (AmegerDiagEnabled())
	{
		LOG(1, "[ThreadHijack] [*] Hijack Diag: stub_base=0x%llX state_page=0x%llX code_size=0x%llX staged=0x%llX return_target=0x%llX\n",
			static_cast<unsigned long long>(ReCa<ULONG_PTR>(pCode)),
			static_cast<unsigned long long>(ReCa<ULONG_PTR>(pState)),
			static_cast<unsigned long long>(code_size),
			static_cast<unsigned long long>(staged.size()),
			static_cast<unsigned long long>(OldRIP));

		DiagRegion(hTargetProc, pCode, "stub_code");
		DiagRegion(hTargetProc, pState, "state_page");
		DiagRegion(hTargetProc, ReCa<BYTE *>(pMem) + kHijackCodePage + kHijackStatePage, "guard_page");

		std::vector<BYTE> readback(staged.size(), 0x00);
		SIZE_T readback_size = 0;
		const bool readback_ok = ScReadProcessMemory(hTargetProc, pMem, readback.data(), readback.size(), &readback_size) &&
			readback_size == readback.size();

		long long first_diff = -1;
		if (readback_ok)
		{
			for (size_t i = 0; i < staged.size(); ++i)
			{
				if (readback[i] != staged[i])
				{
					first_diff = static_cast<long long>(i);
					break;
				}
			}
		}

		LOG(1, "[ThreadHijack] [*] Hijack Diag: stub_readback ok=%d read=0x%llX expect=0x%llX match=%d first_diff=%lld\n",
			readback_ok ? 1 : 0,
			static_cast<unsigned long long>(readback_size),
			static_cast<unsigned long long>(staged.size()),
			first_diff < 0 ? 1 : 0,
			first_diff);

		if (readback_ok)
		{
			DWORD head[12] = { };
			memcpy(head, readback.data(), sizeof(head));

			LOG(1, "[ThreadHijack] [*] Hijack Diag: stub_bytes=%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
				head[0], head[1], head[2], head[3], head[4], head[5],
				head[6], head[7], head[8], head[9], head[10], head[11]);
		}
	}

	const NTSTATUS set_context_status = ScNtSetContextThread(hThread, &OldContext);
	if (NT_FAIL(set_context_status))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(2, "SetThreadContext Failed\n");

		ResumeDonorThread("set-context");

		return SR_HT_ERR_SET_CONTEXT_FAIL;
	}

	if (AmegerDiagEnabled())
	{
		CONTEXT verify{ };
		verify.ContextFlags = CONTEXT_CONTROL;
		const NTSTATUS verify_status = ScNtGetContextThread(hThread, &verify);

		LOG(1, "[ThreadHijack] [*] Hijack Diag: set_context status=0x%08X want_rip=0x%llX get_status=0x%08X rip_after=0x%llX stuck=%d\n",
			static_cast<unsigned>(set_context_status),
			static_cast<unsigned long long>(OldContext.Rip),
			static_cast<unsigned>(verify_status),
			static_cast<unsigned long long>(verify.Rip),
			(NT_SUCCESS(verify_status) && verify.Rip == OldContext.Rip) ? 1 : 0);
	}

	LOG(2, "RIP Replaced\n");

	{
		ULONG sr_resume = 0;
		const NTSTATUS resume_status = ScNtResumeThread(hThread, &sr_resume);

		if (AmegerDiagEnabled())
		{
			LOG(1, "[ThreadHijack] [*] Hijack Diag: resume status=0x%08X previous_suspend=%u\n",
				static_cast<unsigned>(resume_status), sr_resume);
		}

		if (NT_FAIL(resume_status))
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



	constexpr int kForceRestorePolls = 24;




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

	// The donor's wake class decides how long its stub may stay unscheduled (see kStartupProbeMs).
	const DWORD startup_probe_ms =
		donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::Unwakeable ? kUnwakeableProbeMs : kStartupProbeMs;

	DWORD poll_wait_ms = 1;
	DWORD diag_probe = 0;
	const DWORD kDiagProbeMs[] = { 600, 1900 };











	if (CompletionEvent)
	{
		ResetEvent(CompletionEvent);
	}

	bool completion_seen = false;
	ULONGLONG completion_seen_at = 0;
	HANDLE wait_handles[2] = { g_hInterruptEvent, CompletionEvent };
	const DWORD wait_count = CompletionEvent ? 2 : 1;




	bool nudge_sent = false;
	DWORD nudge_after_ms = 250;





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

			if (AmegerDiagEnabled() &&
				data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending &&
				diag_probe < sizeof(kDiagProbeMs) / sizeof(kDiagProbeMs[0]) &&
				waited >= kDiagProbeMs[diag_probe])
			{
				++diag_probe;

				CONTEXT live{ };
				live.ContextFlags = CONTEXT_CONTROL;
				const NTSTATUS live_context = ScNtGetContextThread(hThread, &live);

				DWORD live_exit = 0;
				const bool live_alive = ScGetExitCodeProcess(hTargetProc, live_exit) && live_exit == STILL_ACTIVE;

				KTHREAD_STATE live_state{ };
				KWAIT_REASON live_reason{ };
				bool live_have = false;
				{
					ProcessInformation live_pi;
					if (live_pi.SetProcess(hTargetProc))
					{
						do
						{
							if (live_pi.GetThreadId() == ThreadID)
							{
								live_have = live_pi.GetThreadState(live_state, live_reason);
								break;
							}
						}
						while (live_pi.NextThread());
					}
				}

				LOG(1, "[ThreadHijack] [*] Hijack Diag: pending t=%llu rip=0x%llX rip_at_stub=%d ctx_status=0x%08X thread_state=%d wait_reason=%d target_alive=%d exit=0x%08X\n",
					static_cast<unsigned long long>(waited),
					static_cast<unsigned long long>(live.Rip),
					(NT_SUCCESS(live_context) && live.Rip == ReCa<ULONG_PTR>(pCode)) ? 1 : 0,
					static_cast<unsigned>(live_context),
					live_have ? static_cast<int>(live_state) : -1,
					live_have ? static_cast<int>(live_reason) : -1,
					live_alive ? 1 : 0, live_exit);
			}

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= startup_probe_ms)
			{
				LOG(2, "Stub Not Scheduled Within %u ms (Sampled State Was %s, %s Donor); Failing Fast\n",
					startup_probe_ms, selected_was_running ? "Running" : "Waiting",
					donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::Unwakeable ? "UserRequest"
						: donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::SelfExpiring ? "Delay"
						: donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::Nudgeable ? "WrUserRequest"
						: "Unclassified");

				break;
			}

			if (!nudge_sent && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= nudge_after_ms)
			{
				nudge_sent = true;

				if (!PostThreadMessageW(ThreadID, WM_NULL, 0, 0))
				{
					// A UserRequest waiter is neither nudgeable nor self-expiring: with the wake
					// gone nothing will schedule the stub, so waiting out kStartupProbeMs only
					// delays the next (wakeable) donor. Advance immediately instead. A delay
					// waiter still wakes on its own timer, so the poll keeps its bound.
					if (donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::Unwakeable)
					{
						LOG(2, "Wake Nudge Failed For TID %06X (UserRequest Waiter, Not Self-Expiring); Abandoning Donor\n", ThreadID);

						break;
					}

					LOG(2, "Wake Nudge Failed For TID %06X (%s Waiter); Relying On The Poll Alone\n", ThreadID,
						donor_wake == WAIT_REASON_SAFE::WAKE_CLASS::SelfExpiring ? "Delay" : "Unclassified");
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
