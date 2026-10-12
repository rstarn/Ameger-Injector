#include "Core/Utility/Header/PrecompiledHeader.h"

#include <intrin.h>
#include <TlHelp32.h>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Execution/Routine/StartRoutine.h"
#include "System/Handle/HandleHijack.h"
#include "Injection/Injection.h"

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
		UniqueHandle hThread(OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
		if (!hThread)
		{
			return true;
		}
		auto ntdll_name = KC_WSTR(L"ntdll.dll");
		HMODULE hNtdll = GetModuleHandleW(ntdll_name.c_str());
		if (!hNtdll)
		{
			return true;
		}
		auto api_name = XOR_STR_A("NtQueryInformationThread");
		auto query = ReCa<f_NtQueryInformationThread>(GetProcAddress(hNtdll, api_name.get()));
		if (!query)
		{
			return true;
		}
		THREAD_BASIC_INFORMATION tbi{ 0 };
		if (NT_FAIL(query(hThread.get(), THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)) || !tbi.TebBaseAddress)
		{
			return true;
		}
		USHORT flags = 0;
		if (!ReadProcessMemory(hTargetProc, ReCa<BYTE *>(tbi.TebBaseAddress) + g_DynamicOffsets.TebSameTebFlags, &flags, sizeof(flags), nullptr))
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
		auto ntdll_name = KC_WSTR(L"ntdll.dll");
		HMODULE hNtdll = GetModuleHandleW(ntdll_name.c_str());
		auto api_name = XOR_STR_A("NtQueryInformationThread");
		auto query = hNtdll ? ReCa<f_NtQueryInformationThread>(GetProcAddress(hNtdll, api_name.get())) : nullptr;
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
			if (query && exe_base && exe_size)
			{
				UniqueHandle ht(OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
				if (ht)
				{
					PVOID start = nullptr;
					if (!NT_FAIL(query(ht.get(), static_cast<THREADINFOCLASS>(9), &start, sizeof(start), nullptr)) && start)
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
		const DWORD TargetPidForSponsor = GetProcessId(hTargetProc);
		const DWORD SponsorTidActual = GetThreadId(Sponsor);
		bool sponsor_usable = false;
		HANDLE Duplicated = nullptr;
		if (TargetPidForSponsor && SponsorTidActual && GetProcessIdOfThread(Sponsor) == TargetPidForSponsor
			&& SponsorTidActual == SponsorTid && SponsorTidActual != GetCurrentThreadId()
			&& DuplicateHandle(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
				&Duplicated, hijackAccess, FALSE, 0) && Duplicated)
		{

			sponsor_usable = false;

			if (g_DynamicOffsetsReady.load(std::memory_order_acquire) && processInformation.SetProcess(hTargetProc))
			{
				const KTHREAD_STATE running_state = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);

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

		hThread.reset(OpenThread(threadAccess, FALSE, ThreadID));
	}
	if (!hThread)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "OpenThread failed: %08X\n", error_data.AdvErrorCode);

		return SR_HT_ERR_OPEN_THREAD_FAIL;
	}

constexpr size_t kWxCodePage = 0x1000;
constexpr size_t kWxAllocSize = 0x2000;

static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kWxCodePage,
	"the FP/XSAVE image does not fit the RW state page - raise kWxAllocSize and re-split the pages");

	const size_t pre_shellcode_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - reinterpret_cast<ULONG_PTR>(RemoteThreadHijackBegin));
	const size_t pre_data_size = pre_shellcode_size > pre_state_offset ? pre_shellcode_size - pre_state_offset : 0;
	std::vector<BYTE> shellcode(pre_shellcode_size);
	std::vector<BYTE> staged(kWxCodePage + pre_data_size, 0xCC);

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, kWxAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

	RemoteAllocation allocation_guard(hTargetProc, pMem);

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

	const size_t state_area_size = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadHijackEnd) - reinterpret_cast<ULONG_PTR>(RemoteThreadState));
	if (return_target_offset + sizeof(ULONG_PTR) > shellcode_size || state_offset + sizeof(SR_REMOTE_DATA) > shellcode_size ||
		state_area_size < SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return SR_HT_ERR_CANT_ALLOC_MEM;
	}

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

	{
		bool lea_patched = false;
		bool jmp_patched = false;
		const int pad32 = static_cast<int>(pad);
		for (size_t i = 0; i + 7 <= code_size; ++i)
		{
			const bool is_lea = staged[i] == 0x48 && staged[i + 1] == 0x8D && staged[i + 2] == 0x1D;
			if (is_lea)
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

	{

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

	StoreThreadExecStat(g_ThreadExecStats.Attempted, 1);
	StoreThreadExecStat(g_ThreadExecStats.HijackedTid, ThreadID);

	if (!GetThreadContext(hThread, &OldContext))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(2, "GetThreadContext failed: %08X\n", error_data.AdvErrorCode);

		ResumeThread(hThread);

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

	{
		DWORD old_protect = 0;
		if (!VirtualProtectEx(hTargetProc, pCode, kWxCodePage, PAGE_EXECUTE_READ, &old_protect))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(2, "VirtualProtectEx(RX) failed: %08X\n", error_data.AdvErrorCode);

			ResumeThread(hThread);

			return SR_HT_ERR_WPM_FAIL;
		}

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

				return;
			}

			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_CONTROL;
			bool settled = false;
			if (GetThreadContext(hThread, &ctx))
			{

				SR_REMOTE_DATA fresh{ };
				fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
				const BOOL fresh_ok = ReadProcessMemory(hTargetProc, pState, &fresh, sizeof(fresh), nullptr);
				const bool finished = fresh_ok && fresh.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished;

				if (ctx.Rip < code_base || ctx.Rip >= code_end)
				{

					if (finished || ctx.Rip == OldRIP)
					{
						restored = true;
						settled = true;
					}

				}
				else if (ctx.Rsp == OldContext.Rsp)
				{

					ctx.Rip = OldRIP;
					restored = SetThreadContext(hThread, &ctx) != FALSE;
					settled = true;
				}

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

			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending &&
				GetTickCount64() - Timer >= kStartupProbeMs)
			{
				LOG(2, "Stub not scheduled within %u ms (sampled state was %s); failing fast\n",
					kStartupProbeMs, selected_was_running ? "Running" : "Waiting");

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

			if (outside_code)
			{
				context_restored = true;
			}
			else if (check_context.Rsp == OldContext.Rsp)
			{

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
