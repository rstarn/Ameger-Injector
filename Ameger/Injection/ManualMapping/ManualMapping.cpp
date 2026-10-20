
#include "Core/Utility/Header/PrecompiledHeader.h"

#include <intrin.h>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection/ManualMapping/ManualMappingCore.h"

using namespace NATIVE;
using namespace MMAP_NATIVE;

namespace
{

	MAP_STATS g_LastMapStats{};
	VERIFIABLE_EXEC_TELEMETRY g_LastExecTelemetry{};

	void StoreMapStats(const MAP_STATS & Src)
	{
		static_assert(sizeof(MAP_STATS) % sizeof(LONG) == 0, "MAP_STATS must be a whole number of LONGs");

		LONG * dst = ReCa<LONG *>(&g_LastMapStats);
		const LONG * src = ReCa<const LONG *>(&Src);
		for (size_t i = 0; i < sizeof(MAP_STATS) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadMapStats(MAP_STATS & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_LastMapStats);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(MAP_STATS) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	void StoreExecTelemetry(const VERIFIABLE_EXEC_TELEMETRY & Src)
	{
		static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0, "telemetry must be LONG-multiple");
		LONG * dst = ReCa<LONG *>(&g_LastExecTelemetry);
		const LONG * src = ReCa<const LONG *>(&Src);
		for (size_t i = 0; i < sizeof(VERIFIABLE_EXEC_TELEMETRY) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadExecTelemetry(VERIFIABLE_EXEC_TELEMETRY & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_LastExecTelemetry);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(VERIFIABLE_EXEC_TELEMETRY) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	constexpr SIZE_T kScrubChunk = 0x100000;

	// Resolves the target process's ntdll.dll base by walking its PEB loader list.
	//
	// The remote shell's dispatch table holds absolute addresses taken from this
	// process's ntdll image (see MANUAL_MAPPING_FUNCTION_TABLE), and the remote
	// syscall stubs jump through a gadget inside that same image. Both are only
	// meaningful in the target while ntdll sits at the same base in both
	// processes, so the base has to be confirmed rather than assumed.
	//
	// Returns false when the target's loader state cannot be inspected; the caller
	// treats that as a refusal, never as a pass.
	bool ResolveRemoteNtdllBase(HANDLE hTargetProc, ULONG_PTR & base_out)
	{
		base_out = 0;

		PROCESS_BASIC_INFORMATION basic{ };
		if (NT_FAIL(ScNtQueryInformationProcess(hTargetProc, PROCESSINFOCLASS::ProcessBasicInformation, &basic, sizeof(basic), nullptr)) || !basic.pPEB)
		{
			return false;
		}

		const DYNAMIC_NT_OFFSETS & dyno = g_DynamicOffsets;

		const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
		const DWORD ldr_base_offset = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
		const DWORD ldr_name_offset = dyno.LdrEntryBaseDllName ? dyno.LdrEntryBaseDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, BaseDllName));

		if (peb_ldr_offset + sizeof(void *) > 0x800 ||
			ldr_base_offset + sizeof(void *) > 0x800 ||
			ldr_name_offset + sizeof(UNICODE_STRING) > 0x800)
		{
			return false;
		}

		PEB_LDR_DATA * ldr = nullptr;
		if (!ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(basic.pPEB) + peb_ldr_offset, &ldr, sizeof(ldr), nullptr) || !ldr)
		{
			return false;
		}

		LIST_ENTRY head{ };
		if (!ScReadProcessMemory(hTargetProc, &ldr->InLoadOrderModuleListHead, &head, sizeof(head), nullptr))
		{
			return false;
		}

		// The list links are addresses inside the target, so the walk compares
		// target addresses, not the address of the local copy of the head.
		const LIST_ENTRY * head_address = &ldr->InLoadOrderModuleListHead;
		LIST_ENTRY * current = head.Flink;

		for (ULONG depth = 0; current && current != head_address && depth < 4096; ++depth)
		{
			LIST_ENTRY link{ };
			if (!ScReadProcessMemory(hTargetProc, current, &link, sizeof(link), nullptr))
			{
				return false;
			}

			// The list link is embedded in the loader entry; walk back from the
			// link's target address to the start of the entry.
			const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);

			UNICODE_STRING name{ };
			if (ScReadProcessMemory(hTargetProc, entry + ldr_name_offset, &name, sizeof(name), nullptr) &&
				name.Length == sizeof(L"ntdll.dll") - sizeof(wchar_t) && name.szBuffer)
			{
				wchar_t buffer[16]{ 0 };
				if (ScReadProcessMemory(hTargetProc, name.szBuffer, buffer, sizeof(L"ntdll.dll"), nullptr) &&
					_wcsicmp(buffer, L"ntdll.dll") == 0)
				{
					ULONG_PTR base = 0;
					if (!ScReadProcessMemory(hTargetProc, entry + ldr_base_offset, &base, sizeof(base), nullptr))
					{
						return false;
					}

					base_out = base;

					return base_out != 0;
				}
			}

			current = link.Flink;
		}

		return false;
	}
}

DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	LOG(1, "Begin In-Memory Load\n");

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}
	// The payload is validated here, on this side, before a single byte is
	// written into the target. The shell validates it again once it has been
	// decoded in place over there.
	const DWORD remote_flags = Flags;
	INJECTION_SOURCE source = Source;
	PE_IMAGE::VIEW source_view;
	DWORD validation_result = FILE_ERR_SUCCESS;

	try
	{
		validation_result = PE_IMAGE::Validate(source.RawData, source.RawSize, IMAGE_FILE_MACHINE_AMD64, BuildPeValidationOptions(remote_flags), source_view);
	}
	catch (const std::bad_alloc &)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	if (validation_result != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, validation_result);

		LOG(1, "Strict PE Validation Failed = %08X\n", validation_result);

		return validation_result;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags = remote_flags;
	data.RawSize = source.RawSize;

	if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Dynamic OS Offsets Not Ready, Refusing In-Memory Load\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	data.NtOffsets = g_DynamicOffsets;

	// The remote shell is assembled from *this* process's ntdll addresses: the
	// loader internals are resolved by symbol against the local ntdll and their
	// absolute addresses are written straight into the target's dispatch table.
	// That is only correct while both processes have ntdll mapped at the same base,
	// which is the normal case on Windows but is not something the loader may rely
	// on. Verify it explicitly and fail closed instead of executing the remote
	// shell against a function table full of foreign addresses.
	{
		const ULONG_PTR local_ntdll = reinterpret_cast<ULONG_PTR>(g_hNTDLL);
		if (!local_ntdll)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Local ntdll Base Is Unknown; Refusing In-Memory Load\n");

			return INJ_ERR_GET_MODULE_HANDLE_FAIL;
		}

		ULONG_PTR remote_ntdll = 0;
		if (!ResolveRemoteNtdllBase(hTargetProc, remote_ntdll))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Could Not Resolve The Target's ntdll Base; Refusing In-Memory Load\n");

			return INJ_ERR_GET_MODULE_HANDLE_FAIL;
		}

		if (remote_ntdll != local_ntdll)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Target ntdll Base Mismatch (Local = %p | Target = %p); Refusing In-Memory Load\n",
				ReCa<void *>(local_ntdll), ReCa<void *>(remote_ntdll));

			return INJ_ERR_NTDLL_LAYOUT_MISMATCH;
		}

		LOG(1, "Target ntdll Base Matches The Local Image (%p)\n", ReCa<void *>(local_ntdll));
	}

	LOG(1, "Shell Data Initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(MMAP_SEC_END) - ReCa<ULONG_PTR>(ManualMapping_Shell);

	constexpr SIZE_T kStagePage = 0x1000;

	const DWORD remote_stub_hashes[SC_REMOTE_STUB_COUNT] =
	{
		SC_NtAllocateVirtualMemory,
		SC_NtProtectVirtualMemory,
		SC_NtFreeVirtualMemory,
		SC_NtQueryInformationProcess,
	};

	// The remote stub table is followed by an eight byte slot that holds the ntdll
	// gadget address. Every remote stub jumps through that slot instead of
	// embedding a `syscall` instruction, so the target never holds a `0F 05`
	// pattern in memory of its own.
	const SIZE_T stub_table_size	= static_cast<SIZE_T>(SC_REMOTE_STUB_COUNT) * SC_STUB_SIZE;
	const SIZE_T stub_area_size		= stub_table_size + sizeof(void *);
	const SIZE_T exec_area_size		= static_cast<SIZE_T>(ShellSize) + stub_area_size;

	const SIZE_T raw_span = ALIGN_UP(static_cast<SIZE_T>(source.RawSize), kStagePage);

	SIZE_T AllocationSize = 0;
	const SIZE_T allocation_parts[] =
	{
		sizeof(MANUAL_MAPPING_DATA),
		exec_area_size + (kStagePage * 2),
		sizeof(MANUAL_MAPPING_FUNCTION_TABLE) + (kStagePage * 2),
		raw_span + kStagePage
	};

	for (SIZE_T part : allocation_parts)
	{
		if (part > static_cast<SIZE_T>(-1) - AllocationSize)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Allocation Size Overflow\n");

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		AllocationSize += part;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(ScAllocateMemory(hTargetProc, AllocationSize, PAGE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Memory Allocation Failed\n");

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	RemoteAllocation allocation_guard(hTargetProc, pAllocBase);
	// The staging allocation is released and zeroed on every exit path unless
	// the remote shell is still running and must be left alone.
	bool leak_staging = false;

	auto cleanup_guard = MakeScopeExit([&]() noexcept {
		if (leak_staging)
		{
			return;
		}

		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pAllocBase, AllocationSize, kScrubChunk);
			allocation_guard.reset();
		}
	});

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				kStagePage));
	BYTE * pStubArea		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								SC_STUB_AREA_ALIGN));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pStubArea)		+ stub_area_size,							kStagePage));
	// The raw payload copy lands after the dispatch table, on its own page so
	// that the shell can protect it independently of the rest of the staging
	// area.
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE), kStagePage));

	std::unique_ptr<MANUAL_MAPPING_FUNCTION_TABLE> table_local(new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE());

	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Operator New Failed = %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	BYTE * mmap_sec_base = ReCa<BYTE *>(ManualMapping_Shell);

	table_local->MMP_Shell = ReCa<f_MMI_FUNCTION>(pShells);
	table_local->MMIP_MapSections			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_MapSections)				- mmap_sec_base));
	table_local->MMIP_RelocateImage			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RelocateImage)			- mmap_sec_base));
	table_local->MMIP_InitializeCookie		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_InitializeCookie)		- mmap_sec_base));
	table_local->MMIP_LoadImports			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadImports)				- mmap_sec_base));
	table_local->MMIP_LoadDelayImports		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadDelayImports)		- mmap_sec_base));
	table_local->MMIP_SetPageProtections	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_SetPageProtections)		- mmap_sec_base));
	table_local->MMIP_EnableExceptions		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_EnableExceptions)		- mmap_sec_base));
	table_local->MMIP_HandleTLS				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_HandleTLS)				- mmap_sec_base));
	table_local->MMIP_RunTlsCallbacks		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RunTlsCallbacks)			- mmap_sec_base));
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));

	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));
	// The two module helpers are addressed the same way as the stages: an
	// offset relative to the start of the shell, rebased onto the copy that
	// lives in the target.
	{
		// The staging buffer mirrors the remote layout exactly: the stub table
		// followed by the eight byte gadget slot. The stubs are emitted against the
		// remote base address so their RIP-relative jump displacements are already
		// correct once the buffer lands in the target.
		BYTE stub_slab[SC_REMOTE_STUB_COUNT * SC_STUB_SIZE + sizeof(void *)]
		{
			0
		};

		const DWORD Built = BuildSyscallStubs(stub_slab, sizeof(stub_slab), remote_stub_hashes, SC_REMOTE_STUB_COUNT,
			reinterpret_cast<ULONG_PTR>(pStubArea));

		if (Built != SC_REMOTE_STUB_COUNT)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_SYSCALL_RESOLVE_FAILED);

			LOG(1, "Remote Syscall Stubs Only Partially Built = %u/%u\n", Built, SC_REMOTE_STUB_COUNT);

			return INJ_ERR_SYSCALL_STUB_BUILD_FAILED;
		}

		for (DWORD i = 0; i < SC_REMOTE_STUB_COUNT; ++i)
		{
			if (SyscallServiceOfStub(stub_slab + (i * SC_STUB_SIZE)) == 0)
			{
				continue;
			}

			switch (i)
			{
				case 0: table_local->NtAllocateVirtualMemory	= ReCa<f_NtAllocateVirtualMemory>(pStubArea + i * SC_STUB_SIZE); break;
				case 1: table_local->NtProtectVirtualMemory	= ReCa<f_NtProtectVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 2: table_local->NtFreeVirtualMemory		= ReCa<f_NtFreeVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 3: table_local->NtQueryInformationProcess = ReCa<f_NtQueryInformationProcess>(pStubArea + i * SC_STUB_SIZE); break;
				default: break;
			}
		}

		// The gadget slot travels with the stubs: it holds the ntdll `syscall ; ret`
		// address that every remote stub jumps through.
		if (!ScWriteProcessMemory(hTargetProc, pStubArea, stub_slab, sizeof(stub_slab), nullptr))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Remote Syscall Stubs Could Not Be Staged\n");

			return INJ_ERR_WPM_FAIL;
		}
	}

	if (!table_local->IsValid())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Staging Dispatch Has Unresolved Entries\n");

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	data.FunctionTable = ReCa<MANUAL_MAPPING_FUNCTION_TABLE *>(pFunctionTable);

	data.pRawData = pRawData;
	// The payload is masked with a keystream before it is transferred. The seed
	// is derived from the tick counter and the allocation address, so two loads
	// of the same payload never produce the same bytes on the wire.
	DWORD64 payload_seed0 = 0;
	DWORD64 payload_seed1 = 0;
	{
		const DWORD64 Entropy = __rdtsc() ^ (static_cast<DWORD64>(GetTickCount64()) << 32);

		payload_seed0 = Entropy ^ MMI_KeyBlock(ReCa<DWORD64>(pAllocBase), ReCa<DWORD64>(table_local.get()), 0x5EED);
		payload_seed1 = MMI_KeyBlock(payload_seed0, static_cast<DWORD64>(GetCurrentProcessId()) << 48, 0x0BADF00D) ^ MMI_RotateRight64(Entropy, 29);

		if (!payload_seed0)
		{
			payload_seed0 = 0x9E3779B97F4A7C15ULL;
		}

		if (!payload_seed1)
		{
			payload_seed1 = 0xC2B2AE3D27D4EB4FULL;
		}
	}

	std::vector<BYTE> transfer_image;
	if (source.RawSize)
	{
		try
		{
			transfer_image.resize(static_cast<size_t>(source.RawSize));
			MMI_KeyTransformCopy(transfer_image.data(), source.RawData, static_cast<size_t>(source.RawSize), payload_seed0, payload_seed1);
		}
		catch (const std::bad_alloc &)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		data.PayloadSeed0	= payload_seed0;
		data.PayloadSeed1	= payload_seed1;
		data.PayloadEncoded	= 1;
	}

	LOG(2, "ShellSize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total Size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	LOG(2, "pDispatch      = %p\n", pFunctionTable);

	if (!ScWriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "ShellData Written To Memory\n");

	if (!ScWriteProcessMemory(hTargetProc, pShells, mmap_sec_base, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells Written To Memory\n");

	if (!ScWriteProcessMemory(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE), nullptr))

	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Staging Dispatch Written To Memory\n");

	if (!transfer_image.empty())
	{
		if (!ScWriteProcessMemory(hTargetProc, pRawData, transfer_image.data(), transfer_image.size(), nullptr))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "WriteProcessMemory Failed\n");

			return INJ_ERR_WPM_FAIL;
		}

		SecureZeroMemory(transfer_image.data(), transfer_image.size());
		std::vector<BYTE>().swap(transfer_image);

		LOG(1, "Raw Data Written To Memory\n");
	}

	if (data.PayloadEncoded && data.RawSize)
	{
		SIZE_T protected_span = 0;
		const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pRawData, raw_span, PAGE_READONLY, nullptr, &protected_span);

		if (NT_FAIL(protect_status))
		{
			INIT_ERROR_DATA(error_data, (DWORD)protect_status);

			LOG(1, "Protect(RO Raw) Failed = %08X | Span = %llx/%llx | Base = %p\n",
				protect_status,
				(unsigned long long)protected_span,
				(unsigned long long)raw_span,
				pRawData);

			return INJ_ERR_UPDATE_PROTECTION_FAILED;
		}
	}

	{
		// The RX span covers the shell *and* the whole remote stub area (the stub
		// table plus the trailing gadget slot). It is measured from the actual
		// layout rather than from exec_area_size, because the stub area starts at a
		// 16-byte aligned offset that can sit past the end of a page-rounded size.
		const SIZE_T code_bytes = static_cast<SIZE_T>((pStubArea + stub_area_size) - pShells);
		if (code_bytes)
		{
			const SIZE_T rx_span = ALIGN_UP(code_bytes, kStagePage);
			SIZE_T protected_code = 0;
			const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pShells, rx_span, PAGE_EXECUTE_READ, nullptr, &protected_code);
			if (NT_FAIL(protect_status))
			{
				INIT_ERROR_DATA(error_data, (DWORD)protect_status);

				LOG(1, "Protect(RX) Failed = %08X | Span = %llx | Base = %p\n",
					protect_status, (unsigned long long)protected_code, pShells);

				return INJ_ERR_UPDATE_PROTECTION_FAILED;
			}

			if (!FlushInstructionCache(hTargetProc, pShells, rx_span))
			{
				LOG(1, "FlushInstructionCache Failed\n");
			}
			LOG(1, "Staging Code Promoted RW->RX\n");
		}
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, error_data);

	LOG(1, "Return From StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine Failed = %08X\n", dwRet);

		if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED ||
			dwRet == SR_HT_ERR_REMOTE_PENDING_TIMEOUT)
		{
			leak_staging = true;
		}

		return dwRet;

	}

	LOG(1, "Fetching Routine Data\n");

	if (!ScReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "ReadProcessMemory Failed\n");

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	StoreMapStats(data.MapStats);
	StoreExecTelemetry(data.ExecTelemetry);
	// Everything below is telemetry that the shell wrote back into the shared
	// data block. It is the only way to tell a clean load from a partial one,
	// because the shell itself runs in the target and cannot report back.
	if (data.pImageBase && data.CachedSectionCount)
	{
		LOG(1, "[ManualMap] [+] Image Relocation: Base = %p | Sections = %u\n", ReCa<void *>(data.pImageBase), data.CachedSectionCount);
	}
	else
	{
		LOG(1, "[ManualMap] [x] Image Relocation Produced Nothing (Base = %p | Sections = %u)\n",
			ReCa<void *>(data.pImageBase), data.CachedSectionCount);
	}
	// A zero cycle delta means the entry point was never reached, which is
	// either an image without an entry point or an earlier stage that aborted.
	if (data.ExecTelemetry.DllMainCyclesDelta == 0)
	{
	// A zero cycle delta means the entry point was never reached.
		LOG(1, "[ManualMap] [*] DllMain: Not Entered (No Entry Point In Image, Or An Earlier Stage Aborted)\n");
	}
	else if (data.ExecTelemetry.DllMainResult == 0)
	{
		LOG(1, "[ManualMap] [x] DllMain: Result = 0 (False) | Win32 = 0x%08X | Cycles = %llu -- Payload Refused To Initialize\n",
			data.ExecTelemetry.DllMainLastWin32Error,
			(unsigned long long)data.ExecTelemetry.DllMainCyclesDelta);
	}
	else
	{
		LOG(1, "[ManualMap] [+] DllMain: Result = 1 | Win32 = 0x%08X | Cycles = %llu\n",
			data.ExecTelemetry.DllMainLastWin32Error,
			(unsigned long long)data.ExecTelemetry.DllMainCyclesDelta);
	}

	if (data.ExecTelemetry.LdrLockStatus == 0 && data.ExecTelemetry.LdrUnlockStatus == 0)
	{
		LOG(1, "[ManualMap] [+] LoaderLock: Lock = 0x%08X | State = %u | Cookie = 0x%llX | Unlock = 0x%08X\n",
			(unsigned)data.ExecTelemetry.LdrLockStatus, data.ExecTelemetry.LoaderLockState,
			(unsigned long long)data.ExecTelemetry.LoaderLockCookie,
			(unsigned)data.ExecTelemetry.LdrUnlockStatus);
	}
	else
	{
		LOG(1, "[ManualMap] [x] LoaderLock NTSTATUS Non-Zero: Lock = 0x%08X | Unlock = 0x%08X | State = %u\n",
			(unsigned)data.ExecTelemetry.LdrLockStatus,
			(unsigned)data.ExecTelemetry.LdrUnlockStatus,
			data.ExecTelemetry.LoaderLockState);
	}

	const bool tls_ok = data.ExecTelemetry.TlsCallbacksConfigured == data.ExecTelemetry.TlsCallbacksExecuted &&
		data.ExecTelemetry.TlsCallbacksFailed == 0;
	LOG(1, "[ManualMap] [%s] TLS: Configured = %u | Executed = %u | Failed = %u | Last = %p\n",
		tls_ok ? "+" : "x",
		data.ExecTelemetry.TlsCallbacksConfigured, data.ExecTelemetry.TlsCallbacksExecuted,
		data.ExecTelemetry.TlsCallbacksFailed, data.ExecTelemetry.TlsLastExecutedAddress);
	// Either exception table flavour counts as covered; neither means the
	// payload's own fault handling is not registered.
	const bool seh_ok = data.ExecTelemetry.DynamicTableInstalled || data.ExecTelemetry.InvertedTableInstalled;
	LOG(1, "[ManualMap] [%s] SEH: Dynamic = %d | Inverted = %d | Entry = %p%s\n",
		seh_ok ? "+" : "*",
		(int)data.ExecTelemetry.DynamicTableInstalled, (int)data.ExecTelemetry.InvertedTableInstalled,
		data.ExecTelemetry.InvertedTableEntryBase,
		seh_ok ? "" : " (None Installed - Payload Exceptions Not Covered)");

	if (data.ExecTelemetry.PreSectionSpanWiped == 0)
	{
		LOG(1, "[HeaderCloak] [*] Wipe: Not Executed (Shell Aborted Before Cloak)\n");
	}
	else
	{
		LOG(1, "[HeaderCloak] [+] Wipe: Span = %llu | MZ = %u | PE = %u | Prot = 0x%08X\n", (unsigned long long)data.ExecTelemetry.PreSectionSpanWiped, data.ExecTelemetry.MZRemnantsFound, data.ExecTelemetry.PERemnantsFound, data.ExecTelemetry.PostWipeProtection);
	}

	if (data.SectionProtCount == 0)
	{
		LOG(1, "[ManualMap] [*] PageProtections: Not Applied (Shell Aborted Before Protections)\n");
	}
	else
	{
		LOG(1, "[ManualMap] [+] PageProtections: %u Section Records\n", data.SectionProtCount);
	}

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

		if (remote_ret == INJ_MM_ERR_TLS_CALLBACK_RANGE)
		{
			LOG(1, "TLS Callback #%u Rejected (Address %p)\n",
				data.TlsCallbackIndex, ReCa<void *>(data.TlsCallbackAddress));
		}

		LOG(1, "Shell Failed = %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell Failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell Returned Successfully\n");

	hOut = data.hRet;

	LOG(1, "ImageBase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

#pragma region inlined dependency record functions

__forceinline MM_DEPENDENCY_RECORD * BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle)
{
	if (!head)
	{
		return nullptr;
	}

	if (!(*head))
	{
		*head = NewObject<MM_DEPENDENCY_RECORD>(f);

		if (!(*head))
		{
			return nullptr;
		}

		(*head)->Next = *head;
		(*head)->Prev = *head;
		(*head)->DllHandle = DllHandle;

		return (*head);
	}

	auto next = NewObject<MM_DEPENDENCY_RECORD>(f);
	if (next)
	{
		next->Next			= (*head);
		next->Prev			= (*head)->Prev;

		(*head)->Prev->Next	= next;
		(*head)->Prev		= next;

		next->DllHandle = DllHandle;
	}

	return next;
}

__forceinline MM_DEPENDENCY_RECORD * SearchDependencyRecordByHandle(MM_DEPENDENCY_RECORD * head, HANDLE hDll)
{
	if (!head)
	{
		return nullptr;
	}

	auto cur = head;

	do
	{
		if (cur->DllHandle == hDll)
		{
			return cur;
		}

		cur = cur->Next;
	} while (cur != head);

	return nullptr;
}

__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)
{
	if (!head)
	{
		return;
	}

	while (head->Prev != head)
	{
		auto cur = head->Prev;
		auto prev = cur->Prev;
		auto next = cur->Next;

		prev->Next = next;
		next->Prev = prev;

		f->LdrUnloadDll(cur->DllHandle);
		DeleteObject(f, cur);
	}

	f->LdrUnloadDll(head->DllHandle);
	DeleteObject(f, head);
}

__forceinline void FreeDependencyNodeList(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * & head)
{
	if (!head)
	{
		return;
	}

	while (head->Prev != head)
	{
		auto cur = head->Prev;
		cur->Prev->Next = cur->Next;
		cur->Next->Prev = cur->Prev;
		DeleteObject(f, cur);
	}

	DeleteObject(f, head);
	head = nullptr;
}

#pragma endregion

#pragma region manual mapping internal helper functions

DWORD __declspec(code_seg(".code$05")) __stdcall MMI_SetExecProtections(MANUAL_MAPPING_DATA * pData, DWORD NewState)
{
	if (!pData || !pData->FunctionTable || !pData->pNtHeaders || !pData->pFileHeader)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	if (pData->ExecProtectionState == NewState)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	const ULONG NewProtect = NewState == MM_EXEC_STATE_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READWRITE;

	auto * pSec = MMI_Sections(pData);
	for (UINT i = 0; i != MMI_SectionCount(pData); ++i, ++pSec)
	{
		if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{
			continue;
		}

		void * base = pData->pImageBase + pSec->VirtualAddress;
		SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;

		if (!sec_size)
		{
			continue;
		}

		ULONG old_prot = 0;
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, NewProtect, &old_prot);
		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	pData->ExecProtectionState = NewState;

	return INJ_ERR_SUCCESS;
}

bool __declspec(code_seg(".code$11")) __stdcall MMI_FindLoadedModule(MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule)
{
	*hModule = nullptr;

	if (!pData || !pData->FunctionTable || !FullName || !FullName->szBuffer || !FullName->Length)
	{
		return false;
	}

	if (!pData->FunctionTable->NtQueryInformationProcess)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return false;
	}

	if (!Basic.pPEB)
	{
		return false;
	}

	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	const DWORD ldr_name_off = dyno.LdrEntryFullDllName ? dyno.LdrEntryFullDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, FullDllName));
	const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));

	if (ldr_name_off + sizeof(UNICODE_STRING) > 0x800 || ldr_base_off + sizeof(void *) > 0x800)
	{
		return false;
	}

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
	auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

	if (!pLdr)
	{
		return false;
	}

	const LIST_ENTRY * head = &pLdr->InLoadOrderModuleListHead;
	LIST_ENTRY * current = head->Flink;

	for (ULONG depth = 0; current && current != head && depth < 4096; ++depth)
	{
		const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
		const auto * EntryName = ReCa<const UNICODE_STRING *>(entry + ldr_name_off);
	// The shell reports which sections it mapped and where the image landed.
		if (EntryName->Length == FullName->Length && EntryName->szBuffer)
		{
			bool equal = true;

			const DWORD chars = FullName->Length / sizeof(wchar_t);
			for (DWORD i = 0; i < chars; ++i)
			{
				wchar_t a = EntryName->szBuffer[i];
				wchar_t b = FullName->szBuffer[i];

				if (a >= L'A' && a <= L'Z')
				{
					a = static_cast<wchar_t>(a - L'A' + L'a');
				}

				if (b >= L'A' && b <= L'Z')
				{
					b = static_cast<wchar_t>(b - L'A' + L'a');
				}

				if (a != b)
				{
					equal = false;
					break;
				}
			}

			if (equal)
			{
				*hModule = ReCa<HINSTANCE>(*ReCa<void * const *>(entry + ldr_base_off));

				return *hModule != nullptr;
			}
		}

		current = current->Flink;
	}

	return false;
}

bool __declspec(code_seg(".code$11")) __stdcall MMI_AddressInLoadedImage(MANUAL_MAPPING_DATA * pData, const void * Address)
{
	if (!pData || !pData->FunctionTable || !pData->FunctionTable->NtQueryInformationProcess || !Address)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)) || !Basic.pPEB)
	{
		return false;
	}

	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
	const DWORD ldr_image_off = dyno.LdrEntrySizeOfImage ? dyno.LdrEntrySizeOfImage : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage));

	if (ldr_base_off + sizeof(void *) > 0x800 || ldr_image_off + sizeof(ULONG) > 0x800)
	{
		return false;
	}

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
	auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

	if (!pLdr)
	{
		return false;
	}

	const ULONG_PTR Target = ReCa<ULONG_PTR>(Address);
	const LIST_ENTRY * head = &pLdr->InLoadOrderModuleListHead;
	LIST_ENTRY * current = head->Flink;

	for (ULONG depth = 0; current && current != head && depth < 4096; ++depth)
	{
		const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
		const ULONG_PTR Base = ReCa<ULONG_PTR>(*ReCa<void * const *>(entry + ldr_base_off));
		const ULONG Size = *ReCa<const ULONG *>(entry + ldr_image_off);

		if (Base && Size && Target >= Base && Target - Base < Size)
		{
			return true;
		}

		current = current->Flink;
	}

	return false;
}

#pragma endregion

#pragma region manual mapping internal helper functions

NTSTATUS __declspec(code_seg(".code$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
{
	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	auto * ModNameA = NewObject<ANSI_STRING>(f);
	if (!ModNameA)
	{
		return STATUS_NO_MEMORY;
	}

	const size_t module_name_length = MMI_ImageStringLength(pData, szModule);
	if (!module_name_length || !InitAnsiString(f, ModNameA, szModule, module_name_length))
	{
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	auto * ModNameW = NewObject<UNICODE_STRING>(f);
	if (!ModNameW)
	{
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	ModNameW->szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
	ModNameW->MaxLength = sizeof(wchar_t[MAX_PATH]);

	if (!ModNameW->szBuffer)
	{
		DeleteObject(f, ModNameW);
		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return STATUS_NO_MEMORY;
	}

	ntRet = f->RtlAnsiStringToUnicodeString(ModNameW, ModNameA, FALSE);
	if (NT_FAIL(ntRet))
	{
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		DeleteObject(f, ModNameA->szBuffer);
		DeleteObject(f, ModNameA);

		return ntRet;
	}

	DeleteObject(f, ModNameA->szBuffer);
	DeleteObject(f, ModNameA);

	LDRP_UNICODE_STRING_BUNDLE * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f);
	if (!pModPathW)
	{
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		return STATUS_NO_MEMORY;
	}

	pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
	pModPathW->String.szBuffer	= pModPathW->StaticBuffer;

	ntRet = f->LdrpPreprocessDllName(ModNameW, pModPathW, nullptr, CtxFlags);

	if (NT_SUCCESS(ntRet))
	{

		Module->Length		= pModPathW->String.Length;
		Module->MaxLength	= pModPathW->String.MaxLength;
		Module->szBuffer	= NewObject<wchar_t>(f, Module->MaxLength / sizeof(wchar_t));

		if (!Module->szBuffer)
		{
			DeleteObject(f, pModPathW);
			DeleteObject(f, ModNameW->szBuffer);
			DeleteObject(f, ModNameW);

			return STATUS_NO_MEMORY;
		}
		else
		{
			f->memmove(Module->szBuffer, pModPathW->StaticBuffer, Module->Length);
		}
	}
	else
	{
		DeleteObject(f, pModPathW);
		DeleteObject(f, ModNameW->szBuffer);
		DeleteObject(f, ModNameW);

		return ntRet;
	}

	DeleteObject(f, pModPathW);
	DeleteObject(f, ModNameW->szBuffer);
	DeleteObject(f, ModNameW);

	return STATUS_SUCCESS;
}

NTSTATUS __declspec(code_seg(".code$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
{
	auto f = pData->FunctionTable;
	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	NTSTATUS ntRet = STATUS_SUCCESS;

	void * entry_out = nullptr;

	const DWORD ctx_size = dyno.LdrpPathSearchContextSize ? dyno.LdrpPathSearchContextSize : sizeof(LDRP_PATH_SEARCH_CONTEXT);
	const DWORD ctx_name_off = dyno.LdrpPathSearchOriginalFullDllName;
	void * ctx = NewBytes(f, ctx_size);
	if (!ctx)
	{
		return STATUS_NO_MEMORY;
	}

	if (ctx_name_off + sizeof(void *) <= ctx_size)
	{
		WritePtrField(ctx, ctx_name_off, Module->szBuffer);
	}
	else
	{

		ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx)->OriginalFullDllName = Module->szBuffer;
	}

	f->LdrpLoadDllInternal(Module, ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx), CtxFlag, 4, nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &ntRet, 0);

	DeleteObject(f, ctx);

	if (NT_SUCCESS(ntRet))
	{
		if (entry_out)
		{
			void * dll_base = ReadPtrField(entry_out, dyno.LdrEntryDllBase);
			*hModule = ReCa<HINSTANCE>(dll_base);

			MM_DEPENDENCY_RECORD * entry = nullptr;

			if (head)
			{
				entry = SearchDependencyRecordByHandle(*head, ReCa<HANDLE>(dll_base));
			}

			if (!entry)
			{
				entry = BuildDependencyRecord(f, head, ReCa<HANDLE>(*hModule));

				if (!entry)
				{
					f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));

					return STATUS_NO_MEMORY;
				}
			}

			f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));
		}
		else
		{
			ntRet = STATUS_DLL_NOT_FOUND;
		}
	}

	return ntRet;
}

#pragma endregion

DWORD __declspec(code_seg(".code$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	auto * f = pData->FunctionTable;

	if (!f->LdrpHeap || !*f->LdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}

	auto ret = f->MMIP_MapSections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_RelocateImage(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_InitializeCookie(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_LoadImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_LoadDelayImports(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_EnableExceptions(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_HandleTLS(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_RunTlsCallbacks(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_ExecuteDllMain(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}
	// The header is destroyed last, once everything that still needs it has
	// run. Everything after this point reads the cached copy of the section
	// table and the data directories instead of the mapped image.
	ret = f->MMIP_CloakHeader(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_CleanDataDirectories(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	ret = f->MMIP_SetPageProtections(pData);
	if (ret != INJ_ERR_SUCCESS)
	{
		f->MMIP_CleanUp(pData);

		return ret;
	}

	FreeDependencyNodeList(f, pData->pImportsHead);
	FreeDependencyNodeList(f, pData->pDelayImportsHead);

	pData->hRet = ReCa<HINSTANCE>(pData->pImageBase);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$02")) __stdcall MMI_MapSections(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	if (!(pData->Flags & INJ_MM_MAP_FROM_MEMORY) || !pData->pRawData || !pData->RawSize)
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}
	// The payload arrives masked. The span is rounded up to a page because the
	// protection call works in whole pages, while the transform itself only
	// covers the bytes that were actually transferred.
	const SIZE_T encoded_span = ALIGN_UP(static_cast<SIZE_T>(pData->RawSize), 0x1000);
	const SIZE_T aligned_raw = static_cast<SIZE_T>(pData->RawSize);

	if (pData->PayloadEncoded)
	{
		if (!f->NtProtectVirtualMemory)
		{
			return INJ_MM_ERR_INVALID_HEAP_HANDLE;
		}

		void * raw_base = pData->pRawData;
		SIZE_T raw_size = encoded_span;
		ULONG raw_old = 0;

		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &raw_base, &raw_size, PAGE_READWRITE, &raw_old);
		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}

		MMI_KeyTransformInPlace(pData->pRawData, aligned_raw, pData->PayloadSeed0, pData->PayloadSeed1);
	}

	PE_IMAGE::OPTIONS options = BuildPeValidationOptions(pData->Flags);

	PE_IMAGE::VIEW view;
	if (PE_IMAGE::Validate(pData->pRawData, pData->RawSize, IMAGE_FILE_MACHINE_AMD64, options, view) != FILE_ERR_SUCCESS)
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	pData->pDosHeader = ReCa<IMAGE_DOS_HEADER *>(pData->pRawData);
	pData->pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(pData->pRawData + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader = &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader = &pData->pNtHeaders->FileHeader;
	// The section table and the data directories are copied out of the raw
	// image before the header is destroyed, so the later stages can still
	// find them.
	{
		auto * raw_nt = pData->pNtHeaders;

		DWORD section_count = raw_nt->FileHeader.NumberOfSections;
		if (section_count > MM_MAX_CACHED_SECTIONS)
		{
			section_count = MM_MAX_CACHED_SECTIONS;
		}

		pData->CachedSizeOfImage	= raw_nt->OptionalHeader.SizeOfImage;
		pData->CachedSizeOfHeaders	= raw_nt->OptionalHeader.SizeOfHeaders;
		pData->CachedEntryPoint		= raw_nt->OptionalHeader.AddressOfEntryPoint;
		pData->CachedSectionCount	= section_count;

		f->memmove(pData->CachedSections, IMAGE_FIRST_SECTION(raw_nt),
			static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER));
		f->memmove(pData->CachedDataDirectory, &raw_nt->OptionalHeader.DataDirectory,
			sizeof(pData->CachedDataDirectory));
	}

	SIZE_T ImgSize = static_cast<SIZE_T>(MMI_SizeOfImage(pData));
	// The image is allocated execute-read first and only then made writable.
	// It is never writable and executable at the same time; the final
	// protections are applied once the payload has been copied in.
	pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	{
		ULONG OldProtection = 0;
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &ImgSize, PAGE_READWRITE, &OldProtection);
		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
		}
	}

	pData->pImageBase = pData->pAllocationBase;
	pData->ExecProtectionState = MM_EXEC_STATE_MAPPABLE;

	f->memmove(pData->pImageBase, pData->pRawData, MMI_SizeOfHeaders(pData));

	auto * pCurrentSectionHeader = MMI_Sections(pData);
	for (UINT i = 0; i != MMI_SectionCount(pData); ++i, ++pCurrentSectionHeader)
	{

		if (pCurrentSectionHeader->VirtualAddress < MMI_SizeOfHeaders(pData))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			f->memmove(pData->pImageBase + pCurrentSectionHeader->VirtualAddress, pData->pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	pData->pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pData->pImageBase);
	pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pImageBase + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader		= &pData->pNtHeaders->FileHeader;

	if (pData->PayloadEncoded && f->NtProtectVirtualMemory)
	{
		SecureZeroMemory(pData->pRawData, static_cast<size_t>(pData->RawSize));

		void * raw_base = pData->pRawData;
		SIZE_T raw_size = encoded_span;
		ULONG raw_old = 0;

		f->NtProtectVirtualMemory(NtCurrentProcess(), &raw_base, &raw_size, PAGE_NOACCESS, &raw_old);
	}

	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		auto * pSec = MMI_Sections(pData);
		for (UINT i = 0; i < MMI_SectionCount(pData); ++i, ++pSec)
		{
			const DWORD characteristics = pSec->Characteristics;

			const bool is_writable_data =
				(characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 &&
				(characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
				(characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;

			if (is_writable_data)
			{
				pSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
			}
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$03")) __stdcall MMI_RelocateImage(MANUAL_MAPPING_DATA * pData)
{
	BYTE * LocationDelta = pData->pImageBase - pData->pOptionalHeader->ImageBase;

	if (LocationDelta)
	{
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (!pRelocDir->Size || pRelocDir->Size < sizeof(IMAGE_BASE_RELOCATION))
		{
			return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
		}

		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pRelocDir->VirtualAddress), pRelocDir->Size))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pRelocDir->VirtualAddress);
		auto * pRelocEnd = ReCa<BYTE *>(pRelocData) + pRelocDir->Size;

		while (ReCa<BYTE *>(pRelocData) + sizeof(IMAGE_BASE_RELOCATION) <= pRelocEnd)
		{
			if (pRelocData->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
				pRelocData->SizeOfBlock > static_cast<DWORD>(pRelocEnd - ReCa<BYTE *>(pRelocData)) ||
				((pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0)
			{
				return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
			}

			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (UINT i = 0; i < RelocCount; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					const ULONGLONG patch_rva = static_cast<ULONGLONG>(pRelocData->VirtualAddress) + (*pRelativeInfo & 0xFFF);
					if (patch_rva + sizeof(ULONG_PTR) > MMI_SizeOfImage(pData))
					{
						return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
					}

					ULONG_PTR * pPatch = ReCa<ULONG_PTR *>(pData->pImageBase + static_cast<SIZE_T>(patch_rva));
					*pPatch += ReCa<ULONG_PTR>(LocationDelta);
				}
			}

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		pData->pOptionalHeader->ImageBase += ReCa<ULONG_PTR>(LocationDelta);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$04")) __stdcall MMI_InitializeCookie(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_INIT_SECURITY_COOKIE) || !MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
	{

		return INJ_ERR_SUCCESS;
	}

	ULONGLONG new_cookie = ((UINT_PTR)pData->pImageBase) & 0x0000FFFFFFFFFFFF;
	if (new_cookie == 0x2B992DDFA232)
	{
		++new_cookie;
	}
	else if (!(new_cookie & 0x0000FFFF00000000))
	{
		new_cookie |= (new_cookie | 0x4711) << 0x10;
	}

	const IMAGE_DATA_DIRECTORY & load_config = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (load_config.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR) ||
		!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + load_config.VirtualAddress), sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto pLoadConfigData = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY *>(pData->pImageBase + load_config.VirtualAddress);

	if (!pLoadConfigData->SecurityCookie)
	{
		return INJ_ERR_SUCCESS;
	}
	if (!MMI_InImage(pData, ReCa<void *>(pLoadConfigData->SecurityCookie), sizeof(ULONG_PTR)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}
	*ReCa<ULONG_PTR *>(pLoadConfigData->SecurityCookie) = static_cast<ULONG_PTR>(new_cookie);

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;
	IMAGE_IMPORT_DESCRIPTOR * const pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size);

	if (pImportDir->Size)
	{
		pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress);

		if (!MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}
	}

	bool ErrorBreak = false;

	while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
	{

		auto * szModule = ReCa<const char *>(pData->pImageBase + pImportDescr->Name);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;
		// A module that is already loaded is reused as is. Loading it a second
		// time would give the payload a second copy of its dependencies and a
		// second set of static initialisers.
		if (!MMI_FindLoadedModule(pData, &ModNameW, &hDll) || !hDll)
		{
			pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);
		}
		else
		{
			pData->ntRet = STATUS_SUCCESS;
		}

		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		DeleteObject(f, ModNameW.szBuffer);

		if (!pImportDescr->FirstThunk)
		{
			ErrorBreak = true;
			break;
		}

		IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
		IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

		if (!pImportDescr->OriginalFirstThunk)
		{
			pThunk = pIAT;
		}

		if (!MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pThunk, sizeof(*pThunk)))
		{
			ErrorBreak = true;
			break;
		}

		for (; pThunk && MMI_InImage(pData, pThunk, sizeof(*pThunk)) && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
		{
			UINT_PTR * pFuncRef = ReCa<UINT_PTR *>(pIAT);

			IMAGE_IMPORT_BY_NAME * pImport;
			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
			}
			else
			{

			if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
			{
				ErrorBreak = true;
				break;
			}

			pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));

			const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);

			auto * ansi_import = NewObject<ANSI_STRING>(f);
			if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
			{
				DeleteObject(f, ansi_import);
				ErrorBreak = true;
				break;
			}

			ansi_import->szBuffer	= pImport->Name;
			ansi_import->Length		= static_cast<WORD>(import_name_length);
			ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pFuncRef));

				DeleteObject(f, ansi_import);
			}

			if (NT_FAIL(pData->ntRet))
			{

				ErrorBreak = true;
				break;
			}
		}

		if (!ErrorBreak)
		{
			if (!pThunk || !MMI_InImage(pData, pThunk, sizeof(*pThunk)) || !MMI_InImage(pData, pIAT, sizeof(*pIAT)) || pThunk->u1.AddressOfData)
			{
				ErrorBreak = true;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pImportDescr;

		if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY		* pDelayImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	IMAGE_DELAYLOAD_DESCRIPTOR	* pDelayImportDescr = nullptr;
	IMAGE_DELAYLOAD_DESCRIPTOR	* const pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size);

	if (pDelayImportDir->Size)
	{
		pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress);

		if (!MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}
	}

	bool ErrorBreak = false;

	while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
	{
		auto * szModule = ReCa<const char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;
		// Delay imports follow the same rule as regular imports: reuse what is
		// already mapped, load the rest through the loader.
		if (!MMI_FindLoadedModule(pData, &ModNameW, &hDll) || !hDll)
		{
			pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pDelayImportsHead);
		}
		else
		{
			pData->ntRet = STATUS_SUCCESS;
		}

		if (NT_FAIL(pData->ntRet))
		{
			DeleteObject(f, ModNameW.szBuffer);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		DeleteObject(f, ModNameW.szBuffer);

		if (pDelayImportDescr->ModuleHandleRVA)
		{
			if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pDelayImportDescr->ModuleHandleRVA), sizeof(HINSTANCE)))
			{
				ErrorBreak = true;
				break;
			}

			HINSTANCE * pModule = ReCa<HINSTANCE *>(pData->pImageBase + pDelayImportDescr->ModuleHandleRVA);
			*pModule = hDll;
		}

		if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
		{
			ErrorBreak = true;
			break;
		}

		IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
		IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

		if (!MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pNameTable, sizeof(*pNameTable)))
		{
			ErrorBreak = true;
			break;
		}

		for (; pIAT && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) && pIAT->u1.Function; ++pIAT, ++pNameTable)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
			{
				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
			}
			else
			{
				if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					ErrorBreak = true;
					break;
				}

				auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));

				const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);

				auto * ansi_import= NewObject<ANSI_STRING>(f);
				if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
				{
					DeleteObject(f, ansi_import);
					ErrorBreak = true;
					break;
				}

				ansi_import->szBuffer	= pImport->Name;
				ansi_import->Length		= static_cast<WORD>(import_name_length);
				ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pIAT));

				DeleteObject(f, ansi_import);
			}

			if (NT_FAIL(pData->ntRet))
			{
				ErrorBreak = true;
				break;
			}
		}

		if (!ErrorBreak)
		{
			if (!pIAT || !MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) || pIAT->u1.Function)
			{
				ErrorBreak = true;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pDelayImportDescr;

		if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_DELAY_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	ULONG OldProtection = 0;
	// The header page is made read-only when it is not being erased. With
	// erasure on, the header has already been zeroed and locked down by the
	// cloak stage and must not be touched again.
	if (!(pData->Flags & INJ_ERASE_HEADER))
	{
		SIZE_T SizeOut = MMI_SizeOfHeaders(pData);
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pImageBase), &SizeOut, PAGE_READONLY, &OldProtection);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}
	// Each section gets the protection its characteristics ask for. The first
	// failure is recorded but the loop continues, so a single uncooperative
	// section does not leave the rest of the image unprotected.
	bool section_failure = false;

	auto pCurrentSectionHeader = MMI_Sections(pData);
	const DWORD section_count = MMI_SectionCount(pData);

	pData->SectionProtCount = 0;

	for (UINT i = 0; i != section_count; ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pData->pImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		SIZE_T SectionSize		= (std::max)(static_cast<SIZE_T>(pCurrentSectionHeader->Misc.VirtualSize), static_cast<SIZE_T>(pCurrentSectionHeader->SizeOfRawData));

		ULONG NewProtection = PAGE_NOACCESS;
		NTSTATUS prot_status = STATUS_SUCCESS;

		if (SectionSize)
		{

			if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_EXECUTE_READ;
				}
				else
				{
					NewProtection = PAGE_EXECUTE;
				}
			}
			else
			{
				if (characteristics & IMAGE_SCN_MEM_WRITE)
				{
					NewProtection = PAGE_READWRITE;
				}
				else if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_READONLY;
				}
			}

			pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &pSectionBase, &SectionSize, NewProtection, &OldProtection);
			prot_status = pData->ntRet;
			if (NT_FAIL(pData->ntRet))
			{
				section_failure = true;
			}
		}

		pData->SectionProtCount = i + 1;

		if (NT_FAIL(prot_status))
		{
			section_failure = true;
			break;
		}
	}

	if (section_failure)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
{

	if (!(pData->Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

#ifdef _WIN64
	const IMAGE_DATA_DIRECTORY & exc_dir = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (exc_dir.Size)
	{
		if (exc_dir.Size % sizeof(RUNTIME_FUNCTION) != 0)
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}

		auto * pExceptionHandlers = ReCa<RUNTIME_FUNCTION *>(pData->pImageBase + exc_dir.VirtualAddress);
		const DWORD EntryCount = exc_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));

		if (!MMI_InImage(pData, pExceptionHandlers, exc_dir.Size))
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}

		if (!f->RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), ReCa<DWORD64>(pData->pImageBase)))
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}
		pData->pDynamicFunctionTable = pExceptionHandlers;
		pData->ExecTelemetry.DynamicTableInstalled = TRUE;

		bool dynamic_ok = true;
		if (f->RtlLookupFunctionEntry && EntryCount)
		{
			const RUNTIME_FUNCTION & first = pExceptionHandlers[0];
			const ULONGLONG probe = ReCa<ULONGLONG>(pData->pImageBase) + first.BeginAddress;
			ULONGLONG lookup_base = 0;
			BYTE history[312]{};
			RUNTIME_FUNCTION * found = f->RtlLookupFunctionEntry(probe, &lookup_base, history);
			dynamic_ok = (found != nullptr && lookup_base == ReCa<ULONGLONG>(pData->pImageBase));
		}
		if (!dynamic_ok)
		{
			pData->ExecTelemetry.DynamicTableInstalled = FALSE;
		}

		if (!dynamic_ok)
		{

			const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;
			const bool inv_ok =
				!!f->RtlInsertInvertedFunctionTable && !!f->LdrpInvertedFunctionTable && !!f->LdrProtectMrdata &&
				dyno.InvertedEntryImageBase + sizeof(void *) <= dyno.InvertedEntrySize &&
				dyno.InvertedEntryExceptionDirectory + sizeof(void *) <= dyno.InvertedEntrySize &&
				dyno.InvertedEntryExceptionDirectorySize + sizeof(DWORD) <= dyno.InvertedEntrySize &&
				dyno.KuserCookie + sizeof(DWORD) <= 0x1000 &&
				dyno.InvertedTableCount + sizeof(DWORD) <= 0x100 && dyno.InvertedTableEntries < 0x100 &&
				dyno.InvertedEntrySize >= 8 && dyno.InvertedEntrySize < 0x100;
			if (!inv_ok)
			{
				pData->ntRet = STATUS_UNSUCCESSFUL;
				return INJ_MM_ERR_ENABLING_SEH_FAILED;
			}

			f->RtlInsertInvertedFunctionTable(pData->pImageBase, MMI_SizeOfImage(pData));
			const BYTE * table_base = ReCa<const BYTE *>(f->LdrpInvertedFunctionTable);
			const DWORD inv_count = *ReCa<const DWORD *>(table_base + dyno.InvertedTableCount);
			const BYTE * entries_base = table_base + dyno.InvertedTableEntries;
			bool inv_entry = false;
			for (ULONG i = 0; i < inv_count; ++i)
			{
				const BYTE * entry = entries_base + static_cast<SIZE_T>(i) * dyno.InvertedEntrySize;
				void * entry_base = *ReCa<void * const *>(entry + dyno.InvertedEntryImageBase);
				if (entry_base != pData->pImageBase)
				{
					continue;
				}
				inv_entry = true;

				pData->InvertedTableInstalled = 1;
				pData->ExecTelemetry.InvertedTableInstalled = TRUE;
				pData->ExecTelemetry.InvertedTableEntryBase = pData->pImageBase;
				const DWORD exc_size = *ReCa<const DWORD *>(entry + dyno.InvertedEntryExceptionDirectorySize);
				if (!exc_size)
				{

					SIZE_T FakeDirSize = 0x800 * sizeof(void *);
					pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), &pData->pFakeSEHDirectory, 0, &FakeDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (NT_FAIL(pData->ntRet))
					{
						break;
					}
					// The fake exception directory has to outlive this image: the
					// inverted table entry still points at it. It is deliberately
					// not freed here and is tracked in the map statistics instead.
					pData->MapStats.RetainedAllocBase = ReCa<ULONG_PTR>(pData->pFakeSEHDirectory);
					pData->MapStats.RetainedAllocSize = static_cast<DWORD>(FakeDirSize);

					UINT_PTR pRaw = ReCa<UINT_PTR>(pData->pFakeSEHDirectory);
					const DWORD cookie = *ReCa<volatile DWORD *>(ReCa<BYTE *>(static_cast<UINT_PTR>(KUSER_SHARED_DATA)) + dyno.KuserCookie);
					UINT_PTR pEncoded = static_cast<UINT_PTR>(MMI_RotateRight64(cookie ^ pRaw, cookie & 0x3F));
					f->LdrProtectMrdata(FALSE);
					*ReCa<void **>(ReCa<BYTE *>(const_cast<BYTE *>(entry)) + dyno.InvertedEntryExceptionDirectory) = ReCa<void *>(pEncoded);
					f->LdrProtectMrdata(TRUE);
				}
				break;
			}
			if (!inv_entry)
			{
				pData->ntRet = STATUS_UNSUCCESSFUL;
				return INJ_MM_ERR_ENABLING_SEH_FAILED;
			}
		}
	}
#endif

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_EXECUTE_TLS))
	{
		return INJ_ERR_SUCCESS;
	}

	if (!MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	const DWORD ldr_size = pData->NtOffsets.LdrEntrySize ? pData->NtOffsets.LdrEntrySize : sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
	const DWORD ldr_base_off = pData->NtOffsets.LdrEntryDllBase ? pData->NtOffsets.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
	const DWORD ldr_image_off = pData->NtOffsets.LdrEntrySizeOfImage ? pData->NtOffsets.LdrEntrySizeOfImage : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage));
	const DWORD ddag_off = pData->NtOffsets.LdrEntryDdagNode ? pData->NtOffsets.LdrEntryDdagNode : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DdagNode));
	const DWORD ddag_state_off = pData->NtOffsets.LdrDdagNodeState ? pData->NtOffsets.LdrDdagNodeState : static_cast<DWORD>(offsetof(LDR_DDAG_NODE_WIN11, State));
	const DWORD ddag_size = pData->NtOffsets.LdrDdagNodeSize ? pData->NtOffsets.LdrDdagNodeSize : sizeof(LDR_DDAG_NODE_WIN11);

	if (!ldr_size || ldr_size > 0x1000 || ldr_base_off + sizeof(void *) > ldr_size)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	void * pDummyLdrRaw = NewBytes(f, ldr_size);
	if (!pDummyLdrRaw)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	WritePtrField(pDummyLdrRaw, ldr_base_off, pData->pImageBase);
	if (ldr_image_off + sizeof(ULONG) <= ldr_size)
	{
		*ReCa<ULONG *>(ReCa<BYTE *>(pDummyLdrRaw) + ldr_image_off) = MMI_SizeOfImage(pData);
	}
	// The loader keeps its own bookkeeping for every module. TLS handling
	// needs a plausible loader entry, so a minimal one is fabricated.
	void * pDdagRaw = nullptr;
	if (ddag_off + sizeof(void *) <= ldr_size && ddag_state_off + sizeof(int) <= ddag_size && ddag_size <= 0x800)
	{
		pDdagRaw = NewBytes(f, ddag_size);
		if (!pDdagRaw)
		{
			DeleteObject(f, pDummyLdrRaw);

			return INJ_MM_ERR_HEAP_ALLOC;
		}

		*ReCa<int *>(ReCa<BYTE *>(pDdagRaw) + ddag_state_off) = static_cast<int>(LdrModulesReadyToInit);
			// The DDAG node describes the state of the load. It claims the
			// modules are ready to initialise, which is what the TLS path
			// expects to see, and its module list points at itself so that
			// the loader's own walks terminate.
		WritePtrField(pDdagRaw, offsetof(LDR_DDAG_NODE_WIN11, Modules), pDdagRaw);
		WritePtrField(pDdagRaw, offsetof(LDR_DDAG_NODE_WIN11, Modules) + sizeof(void *), pDdagRaw);

		WritePtrField(pDummyLdrRaw, ddag_off, pDdagRaw);
	}

	auto * pDummyLdr = ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);

	pData->ntRet = f->LdrpHandleTlsData(pDummyLdr);
	if (NT_FAIL(pData->ntRet))
	{
		DeleteObject(f, pDdagRaw);
		DeleteObject(f, pDummyLdrRaw);

		return static_cast<DWORD>(pData->ntRet);
	}
	// The fabricated loader entry and DDAG node are kept alive in the shared
	// data block: the TLS callback stage still needs them, and it releases
	// them itself.
	pData->TlsDirectory = pTLS;
	pData->TlsDummyLdr  = pDummyLdrRaw;
	pData->TlsDdagNode  = pDdagRaw;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0F")) __stdcall MMI_RunTlsCallbacks(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	auto * pDummyLdrRaw	= ReCa<BYTE *>(pData->TlsDummyLdr);
	auto * pDummyLdr	= ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);
	void * pDdagRaw		= pData->TlsDdagNode;
	auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->TlsDirectory);
	// Without a TLS directory or a fabricated loader entry there is nothing
	// to do here; the image simply has no TLS callbacks to run.
	if (!pTLS || !pDummyLdrRaw)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG callback_count = 0;
	ULONG configured_count = 0;
	DWORD tls_result = INJ_ERR_SUCCESS;
	auto * pScan = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pScan)
	{
		if (!MMI_InImage(pData, pScan, sizeof(*pScan)))
		{
			break;
		}
		if (!(*pScan))
		{
			break;
		}
		++configured_count;
		++pScan;
		if (configured_count >= 1025)
		{
			break;
		}
	}
	pData->ExecTelemetry.TlsCallbacksConfigured = configured_count;

	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pCallback)
	{

		if (!MMI_InImage(pData, pCallback, sizeof(*pCallback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(pCallback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		auto Callback = *pCallback;
		if (!Callback)
		{

			break;
		}

		if (callback_count >= 1024)
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(Callback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}
			// A callback that points outside the image is refused. A payload may
			// legitimately point at a callback in another already-loaded module,
			// so that case is allowed, but a dangling pointer is not.
		const bool callback_in_image = MMI_InImage(pData, ReCa<void *>(Callback), sizeof(BYTE));
		if (!callback_in_image && !MMI_AddressInLoadedImage(pData, ReCa<void *>(Callback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(Callback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
		pData->ExecTelemetry.TlsLastExecutedAddress = ReCa<PVOID>(Callback);
		++callback_count;
		++pCallback;
	}
	if (tls_result == INJ_ERR_SUCCESS)
	{
		pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
		pData->ExecTelemetry.TlsCallbacksFailed = 0;
	}

	bool unlinked = false;
	// The loader registers a TLS entry for the fabricated module. It has to
	// be removed again afterwards, otherwise the loader keeps a slot for a
	// module that is not in its module list.
	BYTE * pAllocatedTlsEntry = nullptr;

	const bool tls_off_ok = pData->NtOffsets.TlsEntryModuleEntry + sizeof(void *) <= pData->NtOffsets.TlsEntrySize &&
		pData->NtOffsets.TlsEntrySize >= sizeof(LIST_ENTRY) + sizeof(void *) &&
		pData->NtOffsets.TlsEntrySize < 0x1000;
	if (f->LdrpTlsList && tls_off_ok)
	{
		auto current = f->LdrpTlsList->Flink;
		while (current && current != f->LdrpTlsList)
		{
			auto entry_bytes = ReCa<BYTE *>(current);
			current = current->Flink;
			void * tls_mod = ReadPtrField(entry_bytes, pData->NtOffsets.TlsEntryModuleEntry);
			if (tls_mod == pDummyLdr)
			{
				auto list_entry = ReCa<LIST_ENTRY *>(entry_bytes);
				if (list_entry->Blink && list_entry->Flink)
				{
					list_entry->Blink->Flink = list_entry->Flink;
					list_entry->Flink->Blink = list_entry->Blink;
					unlinked = true;
					pAllocatedTlsEntry = entry_bytes;
				}

				break;
			}
		}
	}
	// The entry was allocated by the loader, so it is released with the
	// loader's heap once it has been unlinked.
	if (pAllocatedTlsEntry)
	{
		DeleteObject(f, pAllocatedTlsEntry);
		pAllocatedTlsEntry = nullptr;
	}

	if (!unlinked)
	{
		LOG(1, "MMI_RunTlsCallbacks: Loader TLS Entry Not Found; Released The Fake Nodes Only\n");
	}

	DeleteObject(f, pDummyLdrRaw);
	DeleteObject(f, pDdagRaw);

	pData->TlsDirectory = nullptr;
	pData->TlsDummyLdr  = nullptr;
	pData->TlsDdagNode  = nullptr;
	// The fabricated nodes are released here. The TLS directory itself is
	// left alone; the data directory scrub is what removes it.
	return tls_result;
}

DWORD __declspec(code_seg(".code$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RUN_DLL_MAIN))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_EntryPoint(pData))
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG		State	= 0;
	ULONG_PTR	Cookie	= 0;
	bool		locked	= false;

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	if (pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK)
	{
		pData->ntRet = f->LdrLockLoaderLock(NULL, &State, &Cookie);
		pData->ExecTelemetry.LdrLockStatus = pData->ntRet;
		pData->ExecTelemetry.LoaderLockState = State;
		pData->ExecTelemetry.LoaderLockCookie = Cookie;

		locked = NT_SUCCESS(pData->ntRet);
		if (!locked)
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + MMI_EntryPoint(pData));
	const unsigned __int64 dll_t0 = __rdtsc();
	const BOOL dll_result = DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_ATTACH, nullptr);
	const unsigned __int64 dll_t1 = __rdtsc();
	// The payload's DllMain is called with the image base as its instance
	// handle, exactly like the loader would. The tick counter brackets the
	// call so the launcher can report how long the payload took to
	// initialise.
	DWORD dll_win32 = 0;
	{
		const DWORD teb_last_error = pData->NtOffsets.TebLastErrorValue;
		if (teb_last_error && teb_last_error + sizeof(DWORD) <= 0x2000)
		{
			const ULONG_PTR teb = static_cast<ULONG_PTR>(__readgsqword(0x30));
			if (teb)
			{
				dll_win32 = *ReCa<DWORD *>(ReCa<BYTE *>(teb) + teb_last_error);
			}
		}
	}
	pData->ExecTelemetry.DllMainResult = dll_result;
	pData->ExecTelemetry.DllMainLastWin32Error = dll_win32;
	pData->ExecTelemetry.DllMainCyclesDelta = (dll_t1 >= dll_t0) ? (dll_t1 - dll_t0) : 0;
	if (!dll_result)
	{

		DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_DETACH, nullptr);

		if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
		{
			const NTSTATUS unlock_st = f->LdrUnlockLoaderLock(NULL, Cookie);
			pData->ExecTelemetry.LdrUnlockStatus = unlock_st;
			if (!NT_SUCCESS(unlock_st))
			{
				return INJ_MM_ERR_LOADER_LOCK_FAILED;
			}
		}

		return INJ_MM_ERR_DLLMAIN_FAILED;
	}

	if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
	{
		const NTSTATUS unlock_st = f->LdrUnlockLoaderLock(NULL, Cookie);
		pData->ExecTelemetry.LdrUnlockStatus = unlock_st;
		if (!NT_SUCCESS(unlock_st))
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_CLEAN_DATA_DIR))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	pData->MapStats.ImportSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	pData->MapStats.DelayImportSize	= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	pData->MapStats.DebugSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	pData->MapStats.RelocSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	pData->MapStats.TlsSize			= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	pData->MapStats.ExportSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pData->MapStats.CleanedMask		=
		((pData->MapStats.ImportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_IMPORT) |
		((pData->MapStats.DelayImportSize	? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) |
		((pData->MapStats.DebugSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DEBUG) |
		((pData->MapStats.RelocSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_BASERELOC) |
		((pData->MapStats.TlsSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_TLS) |
		((pData->MapStats.ExportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_EXPORT);

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_WRITABLE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	DWORD Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto * pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + Size);
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pImportDescr->Name));

			if (mod_length && MMI_InImage(pData, pData->pImageBase + pImportDescr->Name, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pImportDescr->Name, mod_length + 1);
			}
			pImportDescr->Name = 0;

			if (!pImportDescr->OriginalFirstThunk && !pImportDescr->FirstThunk)
			{
				break;
			}

			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunk = pIAT;
			}

			for (; pThunk && MMI_InImage(pData, pThunk, sizeof(*pThunk)) && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{
					pThunk->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);

					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pImportDescr->OriginalFirstThunk = 0;
			pImportDescr->FirstThunk = 0;

			++pImportDescr;
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	if (Size)
	{
		auto * pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + Size);
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA));

			if (mod_length && MMI_InImage(pData, pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1);
			}
			pDelayImportDescr->DllNameRVA = 0;

			pDelayImportDescr->ModuleHandleRVA = 0;

			if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
			{
				break;
			}

			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) && pIAT->u1.Function; ++pIAT, ++pNameTable)
			{

				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					pNameTable->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);

					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pDelayImportDescr->ImportAddressTableRVA = 0;
			pDelayImportDescr->ImportNameTableRVA = 0;

			++pDelayImportDescr;
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (Size)
	{
		auto * pExportDir = ReCa<IMAGE_EXPORT_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (!MMI_InImage(pData, pExportDir, sizeof(*pExportDir)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		if (pExportDir->Name)
		{
			const size_t dll_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pExportDir->Name));
			if (dll_length && MMI_InImage(pData, pData->pImageBase + pExportDir->Name, dll_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pExportDir->Name, dll_length + 1);
			}
			pExportDir->Name = 0;
		}

		const DWORD name_count = pExportDir->NumberOfNames;
		const DWORD func_count = pExportDir->NumberOfFunctions;

		if (name_count || func_count)
		{

			if (name_count >= 4096 || func_count >= 4096)
			{
				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			if ((name_count && (!pExportDir->AddressOfNames || !pExportDir->AddressOfNameOrdinals)) ||
				(func_count && !pExportDir->AddressOfFunctions))
			{
				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			if (name_count)
			{
				auto * pNameRVAs = ReCa<DWORD *>(pData->pImageBase + pExportDir->AddressOfNames);
				auto * pOrdinals = ReCa<WORD *>(pData->pImageBase + pExportDir->AddressOfNameOrdinals);
				if (!MMI_InImage(pData, pNameRVAs, name_count * sizeof(DWORD)) ||
					!MMI_InImage(pData, pOrdinals, name_count * sizeof(WORD)))
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				for (DWORD i = 0; i < name_count; ++i)
				{
					if (!pNameRVAs[i])
					{
						continue;
					}
					const size_t func_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pNameRVAs[i]));
					if (func_length && MMI_InImage(pData, pData->pImageBase + pNameRVAs[i], func_length + 1))
					{
						f->RtlZeroMemory(pData->pImageBase + pNameRVAs[i], func_length + 1);
					}
					pNameRVAs[i] = 0;
				}

				f->RtlZeroMemory(pOrdinals, name_count * sizeof(WORD));
			}

			if (func_count)
			{
				auto * pFuncRVAs = ReCa<DWORD *>(pData->pImageBase + pExportDir->AddressOfFunctions);
				if (!MMI_InImage(pData, pFuncRVAs, func_count * sizeof(DWORD)))
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				f->RtlZeroMemory(pFuncRVAs, func_count * sizeof(DWORD));
			}
		}

		f->RtlZeroMemory(pExportDir, sizeof(*pExportDir));

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		if (!MMI_InImage(pData, pDebugDir, sizeof(*pDebugDir)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		BYTE * pDebugData = pData->pImageBase + pDebugDir->AddressOfRawData;
		if (pDebugDir->SizeOfData && !MMI_InImage(pData, pDebugData, pDebugDir->SizeOfData))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		f->RtlZeroMemory(pDebugData, pDebugDir->SizeOfData);

		pDebugDir->SizeOfData = 0;
		pDebugDir->AddressOfRawData = 0;
		pDebugDir->PointerToRawData = 0;

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto * pRelocEnd = ReCa<BYTE *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + Size);
		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (ReCa<BYTE *>(pRelocData) + sizeof(IMAGE_BASE_RELOCATION) <= pRelocEnd && pRelocData->VirtualAddress)
		{
			if (pRelocData->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
				pRelocData->SizeOfBlock > static_cast<DWORD>(pRelocEnd - ReCa<BYTE *>(pRelocData)))
			{

				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			f->RtlZeroMemory(pRelativeInfo, RelocCount * sizeof(WORD));

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback	= ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		ULONG callback_count = 0;
		for (; pCallback && MMI_InImage(pData, pCallback, sizeof(*pCallback)) && (*pCallback) && callback_count < 1024; ++pCallback, ++callback_count)
		{
			*pCallback = nullptr;
		}

		pTLS->AddressOfCallBacks	= 0;
		pTLS->AddressOfIndex		= 0;
		pTLS->EndAddressOfRawData	= 0;
		pTLS->SizeOfZeroFill		= 0;
		pTLS->StartAddressOfRawData = 0;

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size			= 0;
	}
					// Resource names are strings; they are wiped along with the rest
					// of the resource metadata.
	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
	if (Size)
	{
		auto * pBound = ReCa<IMAGE_BOUND_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
		if (MMI_InImage(pData, pBound, Size))
		{
			f->RtlZeroMemory(pBound, Size);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	}
					// A directory entry either points at a subdirectory or at a leaf
					// data entry. Both offsets are relative to the resource root.
	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	if (Size)
	{
		BYTE * pResRoot = pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

		if (MMI_InImage(pData, pResRoot, Size))
		{
					// Only the version resource is wiped. It is the one that carries
					// the payload's identity in a form that is trivially readable,
					// and removing it does not break anything the payload uses.
			constexpr int kMaxResourceDepth = 16;
			constexpr DWORD kMaxResourceDirs = 0x2000;
			DWORD visited_dirs = 0;

			auto walk_resource_dir = [&](auto&& self, const BYTE * table, int depth) -> void
			{
				if (depth > kMaxResourceDepth || visited_dirs >= kMaxResourceDirs ||
					!table || table < pResRoot || table >= pResRoot + Size ||
					!MMI_InImage(pData, table, sizeof(IMAGE_RESOURCE_DIRECTORY)))
				{
					return;
				}

				++visited_dirs;

				const auto * pTable = ReCa<const IMAGE_RESOURCE_DIRECTORY *>(table);
				const UINT entries = pTable->NumberOfNamedEntries + pTable->NumberOfIdEntries;

				if (!entries || entries > 0x800)
				{
					return;
				}

				const auto * pEntry = ReCa<const IMAGE_RESOURCE_DIRECTORY_ENTRY *>(table + sizeof(IMAGE_RESOURCE_DIRECTORY));

				for (UINT e = 0; e < entries; ++e)
				{
					if (!MMI_InImage(pData, pEntry + e, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
					{
						break;
					}

					if ((pEntry[e].Name & 0x80000000) != 0)
					{
						const DWORD name_offset = pEntry[e].Name & 0x7FFFFFFF;

						if (MMI_InImage(pData, pResRoot + name_offset, sizeof(IMAGE_RESOURCE_DIRECTORY_STRING)))
						{
							auto * pStr = ReCa<IMAGE_RESOURCE_DIRECTORY_STRING *>(pResRoot + name_offset);

							if (pStr->Length)
							{
								const SIZE_T bytes = static_cast<SIZE_T>(pStr->Length) * sizeof(wchar_t);
								if (MMI_InImage(pData, pStr->NameString, bytes))
								{
									f->RtlZeroMemory(pStr->NameString, bytes);
								}

								pStr->Length = 0;
							}
						}
					}

					const DWORD target = pEntry[e].OffsetToData & 0x7FFFFFFF;

					if (pEntry[e].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
					{
						if (target < Size)
						{
							self(self, pResRoot + target, depth + 1);
						}

						continue;
					}

					if (target + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > Size)
					{
						continue;
					}

					auto * pDataEntry = ReCa<IMAGE_RESOURCE_DATA_ENTRY *>(pResRoot + target);

					if (pEntry[e].Id == 16 && pDataEntry->Size && MMI_InImage(pData, pResRoot + pDataEntry->OffsetToData, pDataEntry->Size))
					{
						f->RtlZeroMemory(pResRoot + pDataEntry->OffsetToData, pDataEntry->Size);

						pDataEntry->Size = 0;
						pDataEntry->OffsetToData = 0;
					}
				}
			};

			walk_resource_dir(walk_resource_dir, pResRoot, 0);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
	}

	if (MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size ||
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].Size)
	{
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	}

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	{
		constexpr DWORD kCleanedDirectories[] = {
			IMAGE_DIRECTORY_ENTRY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_BASERELOC,
			IMAGE_DIRECTORY_ENTRY_TLS,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			IMAGE_DIRECTORY_ENTRY_RESOURCE,
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
			IMAGE_DIRECTORY_ENTRY_IAT,
		};

		auto * dirs = MMI_DataDirectory(pData);
		DWORD residual = 0;
		for (const DWORD entry : kCleanedDirectories)
		{
			if (dirs[entry].VirtualAddress || dirs[entry].Size)
			{
				residual |= 1u << entry;
			}
		}

		pData->MapStats.ResidualMask	= residual;
		pData->MapStats.Verified		= residual ? 0u : 1u;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_ERASE_HEADER))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;
	if (!f || !f->NtProtectVirtualMemory || !f->RtlZeroMemory)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	auto * pDos = pData->pDosHeader;
	auto * pNt = pData->pNtHeaders;
	if (!pDos || !pNt || !pData->pImageBase)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}
	// The structural size covers the DOS header, the NT headers and the
	// section table; the wipe covers everything up to the first section,
	// which is the region a scanner looks at to identify the image.
	const DWORD e_lfanew		= pDos->e_lfanew;
	const DWORD nt_size			= static_cast<DWORD>(sizeof(IMAGE_NT_HEADERS64));						
	const DWORD section_size	= static_cast<DWORD>(sizeof(IMAGE_SECTION_HEADER));						
	const DWORD opt_hdr_off		= static_cast<DWORD>(FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader));	
	const DWORD size_optional	= pNt->FileHeader.SizeOfOptionalHeader;
	DWORD		num_sections	= pNt->FileHeader.NumberOfSections;
	const DWORD size_of_image	= pNt->OptionalHeader.SizeOfImage;
	// The wiped region is scanned for the signatures that identify a PE
	// image. The counts are reported so the launcher can prove the wipe
	// actually happened rather than just claim it did.
	DWORD limit = size_of_image;
	DWORD pre_section = 0;
	if (num_sections)
	{
		const DWORD first_section = IMAGE_FIRST_SECTION(pNt)->VirtualAddress;
		if (first_section && first_section < limit)
		{
			limit = first_section;
		}
		if (first_section)
		{
			pre_section = first_section < size_of_image ? first_section : size_of_image;
		}
	}

	if (!limit)
	{
		return INJ_ERR_SUCCESS;
	}

	DWORD dos_bytes = 0x40;
	if (dos_bytes > limit)
	{
		dos_bytes = limit;
	}

	DWORD nt_bytes = 0;
	if (e_lfanew < limit)
	{
		const DWORD room = limit - e_lfanew;
		nt_bytes = room < nt_size ? room : nt_size;
	}
	// The header is locked down completely. Nothing needs to read it again,
	// and the protection keeps a reader from mapping it.
	DWORD sec_bytes = 0;
	const DWORD sec_off = e_lfanew + opt_hdr_off + size_optional;
	if (sec_off < limit)
	{
		const DWORD max_sections = (limit - sec_off) / section_size;
		if (num_sections > max_sections)
		{
			num_sections = max_sections;
		}
		sec_bytes = num_sections * section_size;
	}

	DWORD structural_size = dos_bytes;
	if (nt_bytes && e_lfanew + nt_bytes > structural_size)
	{
		structural_size = e_lfanew + nt_bytes;
	}
	if (sec_bytes && sec_off + sec_bytes > structural_size)
	{
		structural_size = sec_off + sec_bytes;
	}
	// The image is only released when nothing points into it any more. If
	// the inverted function table refers to it, the image has to stay
	// mapped and the leak is reported in the map statistics.
	DWORD wipe_size = structural_size;
	if (pre_section && pre_section > wipe_size)
	{
		wipe_size = pre_section;
	}

	if (!wipe_size)
	{
		return INJ_ERR_SUCCESS;
	}

	void * base = pData->pImageBase;
	SIZE_T region = wipe_size;
	ULONG old_access = NULL;

	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, PAGE_READWRITE, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}
	// Every module that was loaded on this module's behalf is unloaded
	// again. The records are the loader's own dependency chain, walked
	// from the tail so the list stays consistent while it is unwound.
	f->RtlZeroMemory(pData->pImageBase, wipe_size);
	// The dynamic function table is removed from the runtime. When the
	// inverted table was used instead, the image has to stay mapped, so
	// the table is left in place.
	DWORD scan_mz = 0;
	DWORD scan_pe = 0;
	{
		const BYTE * pScan = ReCa<const BYTE *>(pData->pImageBase);
		for (DWORD i = 0; i + 2 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x4D && pScan[i + 1] == 0x5A)
			{
				++scan_mz;
			}
		}
		for (DWORD i = 0; i + 4 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x50 && pScan[i + 1] == 0x45 && pScan[i + 2] == 0x00 && pScan[i + 3] == 0x00)
			{
				++scan_pe;
			}
		}
	}
	// The header region is made inaccessible rather than merely read-only,
	// so a reader that maps the image gets nothing back.
	const ULONG final_access = PAGE_NOACCESS;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, final_access, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}
	// The wipe is recorded in the map statistics so the launcher can
	// verify the size that was cleared and the protection it was left
	// with, and the residual signature counts.
	pData->MapStats.HeaderStructuralSize	= structural_size;
	pData->MapStats.HeaderWipeSize			= wipe_size;
	pData->MapStats.HeaderWipeProtect		= final_access;
	pData->MapStats.HeaderScanBytes			= wipe_size;
	pData->MapStats.HeaderScanMZ			= scan_mz;
	pData->MapStats.HeaderScanPE			= scan_pe;
	pData->ExecTelemetry.PreSectionSpanWiped = static_cast<SIZE_T>(wipe_size);
	pData->ExecTelemetry.MZRemnantsFound = scan_mz;
	pData->ExecTelemetry.PERemnantsFound = scan_pe;
	pData->ExecTelemetry.PostWipeProtection = final_access;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	auto f = pData->FunctionTable;

	const bool leak_image_for_inverted = (pData->InvertedTableInstalled != 0);
	if (pData->pFakeSEHDirectory && !leak_image_for_inverted)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pFakeSEHDirectory), &Size, MEM_RELEASE);
	}

	if (pData->pDelayImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pDelayImportsHead);
	}

	if (pData->pImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pImportsHead);
	}

	if (pData->pDynamicFunctionTable && f->RtlDeleteFunctionTable)
	{
		f->RtlDeleteFunctionTable(pData->pDynamicFunctionTable);
	}

	if (pData->pAllocationBase && !leak_image_for_inverted)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &Size, MEM_RELEASE);
	}

	return 0;
}

#ifndef AMEGER_MMAP_SENTINEL
#define AMEGER_MMAP_SENTINEL (__LINE__ * 37u + 101u)
#endif

DWORD __declspec(code_seg(".code$14")) MMAP_SEC_END()
{
	return AMEGER_MMAP_SENTINEL;
}

MANUAL_MAPPING_FUNCTION_TABLE::MANUAL_MAPPING_FUNCTION_TABLE()
{
	NT_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	NT_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	NT_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(RtlLookupFunctionEntry);

	NT_FUNC_CONSTRUCTOR_INIT(RtlDeleteFunctionTable);
#endif
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);
}

void ResetMapStats()
{
	const MAP_STATS Empty{};
	StoreMapStats(Empty);
}

void __stdcall GetLastMapStats(MAP_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreLoadStats", __FUNCDNAME__)

	if (Out)
	{
		LoadMapStats(*Out);
	}
}

void ResetExecTelemetry()
{
	const VERIFIABLE_EXEC_TELEMETRY Empty{};
	StoreExecTelemetry(Empty);
}

void __stdcall GetLastExecTelemetry(VERIFIABLE_EXEC_TELEMETRY * Out)
{
#pragma EXPORT_FUNCTION("CoreExecTelemetry", __FUNCDNAME__)

	if (Out)
	{
		LoadExecTelemetry(*Out);
	}
}
