#include "Core/Utility/Header/PrecompiledHeader.h"

#include <intrin.h>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection/ManualMapping/ManualMappingCore.h"

using namespace NATIVE;
using namespace MMAP_NATIVE;

namespace
{

	MAP_STATS g_LastMapStats{};

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

	bool ReadFileForMapping(const std::wstring & path, std::vector<BYTE> & data)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file.good())
		{
			return false;
		}

		const std::streamoff file_size = file.tellg();
		if (file_size <= 0 || static_cast<unsigned long long>(file_size) > PE_IMAGE::MAX_IMAGE_SIZE)
		{
			return false;
		}

		data.resize(static_cast<size_t>(file_size));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char *>(data.data()), file_size);
		return static_cast<bool>(file) && file.gcount() == file_size;
	}

	// The shared scrub helper lives in the syscall layer; this staging region can be large, so it is
	// wiped in 1 MiB chunks rather than requiring a single buffer the size of the whole allocation.
	constexpr SIZE_T kScrubChunk = 0x100000;
}

DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	LOG(1, "Begin in-memory load\n");

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	// INJ_MM_MAP_FROM_MEMORY is forced exactly once, in Memory_InjectBody, so that the remote shell
	// always sees an in-memory payload; the flag is not re-derived here.
	const DWORD remote_flags = Flags;
	INJECTION_SOURCE source = Source;
	std::vector<BYTE> file_data;
	PE_IMAGE::VIEW source_view;
	DWORD validation_result = FILE_ERR_SUCCESS;

	try
	{
		if (source.FromMemory)
		{
			validation_result = PE_IMAGE::Validate(source.RawData, source.RawSize, IMAGE_FILE_MACHINE_AMD64, BuildPeValidationOptions(remote_flags), source_view);
		}
		else
		{
		if (!ReadFileForMapping(source.DllPath, file_data))
		{
			INIT_ERROR_DATA(error_data, FILE_ERR_CANT_OPEN_FILE);

			return FILE_ERR_CANT_OPEN_FILE;
		}

			validation_result = PE_IMAGE::Validate(file_data.data(), file_data.size(), IMAGE_FILE_MACHINE_AMD64, BuildPeValidationOptions(remote_flags), source_view);
			source.FromMemory = true;
			source.RawData = file_data.data();
			source.RawSize = static_cast<DWORD>(file_data.size());
		}
	}
	catch (const std::bad_alloc &)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	if (validation_result != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, validation_result);

		LOG(1, "Strict PE validation failed: %08X\n", validation_result);

		return validation_result;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags = remote_flags;
	data.RawSize = source.RawSize;

	if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Dynamic OS offsets not ready, refusing in-memory load\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	data.NtOffsets = g_DynamicOffsets;

	LOG(1, "Shell data initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(MMAP_SEC_END) - ReCa<ULONG_PTR>(ManualMapping_Shell);

	constexpr SIZE_T kStagePage = 0x1000;

	// The remote side has to run its own operations without ever touching a public ntdll entry point,
	// so a slab of locally built syscall stubs is staged directly behind the shell code and promoted
	// to execute+read together with it. Exactly the entries the shell dispatch table rebinds below are
	// staged; a stub with no rebound slot would only sit in the target as dead bytes.
	const DWORD remote_stub_hashes[SC_REMOTE_STUB_COUNT] =
	{
		SC_NtAllocateVirtualMemory,
		SC_NtProtectVirtualMemory,
		SC_NtFreeVirtualMemory,
		SC_NtClose,
		SC_NtQueryInformationProcess,
	};

	const SIZE_T stub_area_size	= static_cast<SIZE_T>(SC_REMOTE_STUB_COUNT) * SC_STUB_SIZE;
	const SIZE_T exec_area_size	= static_cast<SIZE_T>(ShellSize) + stub_area_size;

	// The payload span is rounded up to a whole number of pages so that the later protection change
	// covers only pages that belong to this allocation.
	const SIZE_T raw_span = source.FromMemory
		? ALIGN_UP(static_cast<SIZE_T>(source.RawSize), kStagePage)
		: 0;

	SIZE_T AllocationSize = 0;
	const SIZE_T allocation_parts[] =
	{
		sizeof(MANUAL_MAPPING_DATA),
		exec_area_size + kStagePage,
		sizeof(MANUAL_MAPPING_FUNCTION_TABLE) + (kStagePage * 2),
		raw_span + kStagePage
	};

	for (SIZE_T part : allocation_parts)
	{
		if (part > static_cast<SIZE_T>(-1) - AllocationSize)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Allocation size overflow\n");

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		AllocationSize += part;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(ScAllocateMemory(hTargetProc, AllocationSize, PAGE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "memory allocation failed\n");

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	RemoteAllocation allocation_guard(hTargetProc, pAllocBase);

	// Raised whenever a remote thread may still be executing inside the staging region. Freeing or
	// wiping that region while a thread is still inside it would take the thread's instruction pointer
	// with it, so those paths deliberately leave it behind.
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

	// The payload is placed on a page boundary and given its own page aligned span. A protect call can
	// only cover pages that belong to a single region, so the region the payload lives in is sized to
	// cover the rounded payload rather than the raw byte count.
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE), kStagePage));

	std::unique_ptr<MANUAL_MAPPING_FUNCTION_TABLE> table_local(new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE());

	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "operator new failed: %08X\n", error_data.AdvErrorCode);

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

	// Rebind the cross boundary entry points onto the staged stubs. The constructor copied the ntdll
	// addresses in, and those are precisely the addresses an inline hook would claim, so they are
	// replaced with addresses that only exist inside this staging allocation.
	{
		BYTE stub_slab[SC_REMOTE_STUB_COUNT][SC_STUB_SIZE]{ };

		const DWORD Built = BuildSyscallStubs(ReCa<BYTE *>(stub_slab), sizeof(stub_slab), remote_stub_hashes, SC_REMOTE_STUB_COUNT);
		if (!Built)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_SYSCALL_RESOLVE_FAILED);

			LOG(1, "Remote syscall stubs could not be built\n");

			return INJ_ERR_SYSCALL_RESOLVE_FAILED;
		}

		for (DWORD i = 0; i < SC_REMOTE_STUB_COUNT; ++i)
		{
			if (SyscallServiceOfStub(stub_slab[i]) == 0)
			{
				continue;
			}

			switch (i)
			{
				case 0: table_local->NtAllocateVirtualMemory	= ReCa<f_NtAllocateVirtualMemory>(pStubArea + i * SC_STUB_SIZE); break;
				case 1: table_local->NtProtectVirtualMemory	= ReCa<f_NtProtectVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 2: table_local->NtFreeVirtualMemory		= ReCa<f_NtFreeVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 3: table_local->NtClose					= ReCa<f_NtClose>				(pStubArea + i * SC_STUB_SIZE); break;
				case 4: table_local->NtQueryInformationProcess = ReCa<f_NtQueryInformationProcess>(pStubArea + i * SC_STUB_SIZE); break;
				default: break;
			}
		}

		if (!ScWriteProcessMemory(hTargetProc, pStubArea, stub_slab, sizeof(stub_slab), nullptr))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Remote syscall stubs could not be staged\n");

			return INJ_ERR_WPM_FAIL;
		}
	}

	if (!table_local->IsValid())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Staging dispatch has unresolved entries\n");

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	data.FunctionTable = ReCa<MANUAL_MAPPING_FUNCTION_TABLE *>(pFunctionTable);

	if (source.FromMemory)
	{
		data.pRawData = pRawData;
	}

	// Per run obfuscation key. The value only has to survive the transfer, so process entropy is
	// enough and no new dependency is introduced.
	DWORD64 payload_seed0 = 0;
	DWORD64 payload_seed1 = 0;
	{
		const DWORD64 Entropy = __rdtsc() ^ (static_cast<DWORD64>(GetTickCount64()) << 32);

		payload_seed0 = Entropy ^ MMI_KeyBlock(ReCa<DWORD64>(pAllocBase), ReCa<DWORD64>(table_local.get()), 0x5EED);
		payload_seed1 = MMI_KeyBlock(payload_seed0, static_cast<DWORD64>(GetCurrentProcessId()) << 48, 0x0BADF00D) ^ MMI_RotateRight64(Entropy, 29);

		// A degenerate seed would leave the payload in the clear, so both halves are forced non zero.
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
	if (source.FromMemory && source.RawSize)
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

	LOG(2, "Shellsize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	LOG(2, "pDispatch      = %p\n", pFunctionTable);

	if (!ScWriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!ScWriteProcessMemory(hTargetProc, pShells, mmap_sec_base, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells written to memory\n");

	if (!ScWriteProcessMemory(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE), nullptr))

	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Staging dispatch written to memory\n");

	if (!transfer_image.empty())
	{
		if (!ScWriteProcessMemory(hTargetProc, pRawData, transfer_image.data(), transfer_image.size(), nullptr))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "WriteProcessMemory failed\n");

			return INJ_ERR_WPM_FAIL;
		}

		SecureZeroMemory(transfer_image.data(), transfer_image.size());
		std::vector<BYTE>().swap(transfer_image);

		LOG(1, "Raw data written to memory\n");
	}

	if (data.PayloadEncoded && data.RawSize)
	{
		SIZE_T protected_span = 0;
		const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pRawData, raw_span, PAGE_READONLY, nullptr, &protected_span);

		if (NT_FAIL(protect_status))
		{
			INIT_ERROR_DATA(error_data, (DWORD)protect_status);

			LOG(1, "Protect(RO raw) failed: %08X span=%llx/%llx base=%p\n",
				protect_status,
				(unsigned long long)protected_span,
				(unsigned long long)raw_span,
				pRawData);

			return INJ_ERR_UPDATE_PROTECTION_FAILED;
		}
	}

	{
		const SIZE_T code_bytes = exec_area_size;
		if (code_bytes)
		{
			SIZE_T protected_code = 0;
			const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pShells, ALIGN_UP(code_bytes, kStagePage), PAGE_EXECUTE_READ, nullptr, &protected_code);
			if (NT_FAIL(protect_status))
			{
				INIT_ERROR_DATA(error_data, (DWORD)protect_status);

				LOG(1, "Protect(RX) failed: %08X span=%llx base=%p\n",
					protect_status, (unsigned long long)protected_code, pShells);

				return INJ_ERR_UPDATE_PROTECTION_FAILED;
			}

			if (!FlushInstructionCache(hTargetProc, pShells, ALIGN_UP(code_bytes, kStagePage)))
			{
				LOG(1, "FlushInstructionCache failed\n");
			}
			LOG(1, "Staging code promoted RW->RX\n");
		}
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, error_data);

	LOG(1, "Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine failed: %08X\n", dwRet);

		if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED ||
			dwRet == SR_HT_ERR_REMOTE_PENDING_TIMEOUT ||
			dwRet == SR_HT_ERR_REMOTE_TIMEOUT)
		{
			leak_staging = true;
		}

		return dwRet;

	}

	LOG(1, "Fetching routine data\n");

	if (!ScReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "ReadProcessMemory failed\n");

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	StoreMapStats(data.MapStats);

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

		if (remote_ret == INJ_MM_ERR_TLS_CALLBACK_RANGE)
		{
			LOG(1, "TLS callback #%u rejected (address %p)\n",
				data.TlsCallbackIndex, ReCa<void *>(data.TlsCallbackAddress));
		}

		LOG(1, "Shell failed: %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell returned successfully\n");

	hOut = data.hRet;

	LOG(1, "Imagebase = %p\n", ReCa<void *>(hOut));

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

// One place where the executable sections are promoted. Every stage that needs executable pages asks
// for them here, and the call is a no-op when the requested state is already in effect. This is what
// keeps the whole map down to two real RW and RX transitions on the same pages instead of six.
DWORD __declspec(code_seg(".mmap_sec$05")) __stdcall MMI_SetExecProtections(MANUAL_MAPPING_DATA * pData, DWORD NewState)
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

// Consults the loader's own module list, so an import that is already resident is reported without
// asking the loader to load anything. Routing an already loaded dependency through
// LdrpLoadDllInternal still takes the loader lock, re-walks the search path, and re-verifies the image
// against its section object; none of that is free, and all of it is observable from a load image
// callback. Resolving a resident dependency from the list avoids touching the loader at all.
//
// This executes inside the target, so the list is read directly. Offsets come from the symbol table
// when present and from this header's layout otherwise.
bool __declspec(code_seg(".mmap_sec$11")) __stdcall MMI_FindLoadedModule(MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule)
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

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(AMEGER_PEB, Ldr));
	auto * pLdr = *ReCa<AMEGER_PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

	if (!pLdr)
	{
		return false;
	}

	const LIST_ENTRY * head = &pLdr->InLoadOrderModuleListHead;
	LIST_ENTRY * current = head->Flink;

	// The walk is bounded rather than trusting the list to terminate.
	for (ULONG depth = 0; current && current != head && depth < 4096; ++depth)
	{
		const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
		const auto * EntryName = ReCa<const UNICODE_STRING *>(entry + ldr_name_off);

		// Only the full path comparison is meaningful: a base name match would be wrong for any module
		// that exists in more than one location.
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

// True when Address falls inside the image span of any module the target has loaded. A TLS callback
// that legitimately lives in another already-loaded module (a forwarder) is accepted by this; an
// address that belongs to no image at all is still rejected. The walk mirrors MMI_FindLoadedModule's:
// it is bounded, and every field is validated before it is dereferenced.
bool __declspec(code_seg(".mmap_sec$11")) __stdcall MMI_AddressInLoadedImage(MANUAL_MAPPING_DATA * pData, const void * Address)
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

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(AMEGER_PEB, Ldr));
	auto * pLdr = *ReCa<AMEGER_PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

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

NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
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

NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
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

DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
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

	// The erase runs only after every step that executes payload code. The payload's entry point - and,
	// for a packed payload, the unpacker that runs as its DllMain - reads the image's own PE header, so
	// erasing the header before the entry point faults the payload with an access violation. The TLS
	// callbacks and the entry point therefore run with intact headers, and the erase sits immediately
	// after them. The finalisation stages that still need header values (clean data directories, page
	// protections) read the snapshot taken in MMI_MapSections, so nothing dereferences the erased pages.
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

DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	if (!(pData->Flags & INJ_MM_MAP_FROM_MEMORY) || !pData->pRawData || !pData->RawSize)
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	// The transfer was obfuscated, so this stage recovers the clear image into the staging buffer
	// first. The plaintext only exists there between here and the end of the section copy, after which
	// the region is wiped and closed to every access.
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

	// Snapshot the header values the post-erase stages still need, here, while the raw headers are
	// guaranteed intact. The accessors in ManualMappingInternal.h serve these to any stage that runs
	// after MMI_CloakHeader, so erasing the headers cannot strand a later step on a zeroed page.
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

	// Reservation protect is execute and read, which is what a real LoadLibrary leaves behind on the
	// VAD. The pages are opened for writing, mapped, and re-protected by MMI_SetPageProtections, so the
	// region ends up with a legitimately shaped AllocationProtect rather than a read and write one.
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

	// The clear image now lives in exactly one place. Wipe the staging copy and close it.
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

DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage(MANUAL_MAPPING_DATA * pData)
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

DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie(MANUAL_MAPPING_DATA * pData)
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

DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
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

		// A dependency the process already has mapped is resolved straight out of the module list.
		// Asking the loader as well would take the loader lock, re-walk the search path and re-verify
		// the section object for a module that is already resident, and every one of those steps shows
		// up in a load image callback.
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

DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
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

		// Same rule as the regular import table: a resident dependency is read out of the module list
		// rather than pushed back through the loader.
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

DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	ULONG OldProtection = 0;

	// When the headers were erased they were already closed to every access by MMI_CloakHeader.
	// Re-protecting the header span to READONLY here would reopen those pages, so the header pass is
	// skipped in that case; only the per-section pass runs.
	if (!(pData->Flags & INJ_ERASE_HEADER))
	{
		SIZE_T SizeOut = MMI_SizeOfHeaders(pData);
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pImageBase), &SizeOut, PAGE_READONLY, &OldProtection);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	// The section walk reports its own result rather than re-reading pData->ntRet at the end: an
	// earlier stage may legitimately have left a non zero status there, and conflating the two would
	// turn a successful protection pass into a failure (or the reverse).
	bool section_failure = false;

	auto pCurrentSectionHeader = MMI_Sections(pData);

	for (UINT i = 0; i != MMI_SectionCount(pData); ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pData->pImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		SIZE_T SectionSize		= (std::max)(static_cast<SIZE_T>(pCurrentSectionHeader->Misc.VirtualSize), static_cast<SIZE_T>(pCurrentSectionHeader->SizeOfRawData));

		if (SectionSize)
		{

			ULONG NewProtection = PAGE_NOACCESS;

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
			if (NT_FAIL(pData->ntRet))
			{
				section_failure = true;
				break;
			}
		}
	}

	if (section_failure)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
{

	if (!(pData->Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	// Registration needs executable pages; the gate handles the already executable case.
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

		bool dynamic_ok = true;
		if (f->RtlLookupFunctionEntry && EntryCount)
		{
			const RUNTIME_FUNCTION & first = pExceptionHandlers[0];
			const ULONGLONG probe = ReCa<ULONGLONG>(pData->pImageBase) + first.BeginAddress;
			ULONGLONG lookup_base = 0;
			BYTE history[128]{};
			RUNTIME_FUNCTION * found = f->RtlLookupFunctionEntry(probe, &lookup_base, history);
			dynamic_ok = (found != nullptr && lookup_base == ReCa<ULONGLONG>(pData->pImageBase));
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
				const DWORD exc_size = *ReCa<const DWORD *>(entry + dyno.InvertedEntryExceptionDirectorySize);
				if (!exc_size)
				{

					SIZE_T FakeDirSize = 0x800 * sizeof(void *);
					pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), &pData->pFakeSEHDirectory, 0, &FakeDirSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (NT_FAIL(pData->ntRet))
					{
						break;
					}
					// The fake SEH directory outlives the injection (the inverted function table keeps
					// a pointer to it), so publish it as a retained target allocation for the host to
					// scan. It is freshly committed zero pages, so the scan is expected to be clean.
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

DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
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
	const DWORD ddag_off = pData->NtOffsets.LdrEntryDdagNode;
	const DWORD ddag_state_off = pData->NtOffsets.LdrDdagNodeState;
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

	// A dependency graph node sitting in a state the loader already considers complete. Without it any
	// path inside the loader that follows DdagNode dereferences a null pointer and takes the victim
	// process down during the TLS phase.
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

		// The node's module list is an empty, self-referential LIST_ENTRY. Modules is the first
		// member, so the list head sits at the node base and both links point back at it. This used
		// to write the self pointer at ddag_state_off, i.e. straight over the State int, which left
		// the loader reading a truncated pointer as the LDR_DDAG_STATE enum.
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

	// Hand the registered TLS state to MMI_RunTlsCallbacks, which drives the callbacks while the
	// headers are still intact: the erase runs only after every payload-code step (TLS callbacks and
	// the entry point). The TLS directory lives in a section, not in the erased headers, so it stays
	// readable across the boundary even though the callback driver itself runs before the erase.
	pData->TlsDirectory = pTLS;
	pData->TlsDummyLdr  = pDummyLdrRaw;
	pData->TlsDdagNode  = pDdagRaw;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0F")) __stdcall MMI_RunTlsCallbacks(MANUAL_MAPPING_DATA * pData)
{
	auto f = pData->FunctionTable;

	auto * pDummyLdrRaw	= ReCa<BYTE *>(pData->TlsDummyLdr);
	auto * pDummyLdr	= ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);
	void * pDdagRaw		= pData->TlsDdagNode;
	auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->TlsDirectory);

	// Nothing was registered - EXECUTE_TLS was off, the image carries no TLS directory, or the setup
	// already released the fake nodes on failure - so there is nothing to drive.
	if (!pTLS || !pDummyLdrRaw)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG callback_count = 0;
	DWORD tls_result = INJ_ERR_SUCCESS;
	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pCallback)
	{

		if (!MMI_InImage(pData, pCallback, sizeof(*pCallback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(pCallback);
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
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		// The callback is legitimate when its entry point sits in the image being mapped, or when it
		// was forwarded into another module the target already has loaded. An address that belongs to
		// no image is still rejected, and the offending entry is recorded for the host to report.
		const bool callback_in_image = MMI_InImage(pData, ReCa<void *>(Callback), sizeof(BYTE));
		if (!callback_in_image && !MMI_AddressInLoadedImage(pData, ReCa<void *>(Callback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(Callback);
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
		++callback_count;
		++pCallback;
	}

	bool unlinked = false;

	// Bookkeeping for the TLS_ENTRY that LdrpHandleTlsData allocated inside the target. The entry has
	// to be unlinked *and* freed: unlinking alone leaves a permanent, observable allocation in the
	// victim's loader heap, and because the fake LDR entry is detached the loader will never reclaim
	// it on its own.
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

	// The loader's TLS bookkeeping, then the fake LDR / DDAG nodes it pointed at. The last two are
	// released unconditionally: they are only reachable through the unlinked entry, so if the unlink
	// did not run there is nothing left to keep them alive for.
	if (pAllocatedTlsEntry)
	{
		DeleteObject(f, pAllocatedTlsEntry);
		pAllocatedTlsEntry = nullptr;
	}

	if (!unlinked)
	{
		LOG(1, "MMI_RunTlsCallbacks: loader TLS entry not found; released the fake nodes only\n");
	}

	DeleteObject(f, pDummyLdrRaw);
	DeleteObject(f, pDdagRaw);

	pData->TlsDirectory = nullptr;
	pData->TlsDummyLdr  = nullptr;
	pData->TlsDdagNode  = nullptr;

	// The loader hands out one TLS index per LdrpHandleTlsData call and there is no public way to give
	// one back for a detached entry. That is a fixed per process budget of 64 slots (TLS_MINIMUM_
	// AVAILABLE), which is ample for a fresh launcher process but is the real ceiling on how many
	// times one host can map a TLS carrying payload.
	return tls_result;
}

DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
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

		locked = NT_SUCCESS(pData->ntRet);
		if (!locked)
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + MMI_EntryPoint(pData));
	if (!DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_ATTACH, nullptr))
	{

		DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_DETACH, nullptr);

		if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
		{

			if (!NT_SUCCESS(f->LdrUnlockLoaderLock(NULL, Cookie)))
			{
				return INJ_MM_ERR_LOADER_LOCK_FAILED;
			}
		}

		return INJ_MM_ERR_DLLMAIN_FAILED;
	}

	if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
	{
		if (!NT_SUCCESS(f->LdrUnlockLoaderLock(NULL, Cookie)))
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
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

	// Bound import directory: a bound import table left behind carries the exact named imports of the
	// payload plus the timestamps they were resolved against, which is a far stronger fingerprint than
	// the import directory itself ever was.
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

	// Resource tree: the directory entries themselves are harmless, but a resource name string and a
	// version information block together are the original file name, product name and build stamp of
	// the payload, verbatim. Every name string is cleared and every RT_VERSION blob is zeroed.
	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	if (Size)
	{
		BYTE * pResRoot = pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

		if (MMI_InImage(pData, pResRoot, Size))
		{
			// Depth-first walk with a hard depth limit and a total-directory budget. The previous
			// implementation kept at most 8 pending directories and silently dropped the remainder, so
			// a payload with a large resource tree (e.g. many icons) kept uncleaned name strings and
			// RT_VERSION blobs. A real PE resource tree is only type -> name -> language deep, so the
			// depth cap plus a visit budget visits every real subdirectory while a cyclic or corrupt
			// tree stays bounded. No allocation is performed, so the staging semantics are unchanged.
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

					// RT_VERSION is 16, and its blob is the only resource carrying identifying text.
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

	// Managed image directory and the informational import address table directory.
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

DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
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

	// Every header field is read before a single byte is overwritten. e_lfanew comes from the DOS
	// header at offset 0x3C; the section count and the optional-header length come from the file
	// header.
	const DWORD e_lfanew		= pDos->e_lfanew;
	const DWORD nt_size			= static_cast<DWORD>(sizeof(IMAGE_NT_HEADERS64));						// 0x108 on x64
	const DWORD section_size	= static_cast<DWORD>(sizeof(IMAGE_SECTION_HEADER));						// 0x28 per section
	const DWORD opt_hdr_off		= static_cast<DWORD>(FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader));	// 0x18
	const DWORD size_optional	= pNt->FileHeader.SizeOfOptionalHeader;
	DWORD		num_sections	= pNt->FileHeader.NumberOfSections;
	const DWORD size_of_image	= pNt->OptionalHeader.SizeOfImage;

	// The header region can never reach past the first section, and never past the mapped image.
	// pre_section is the full pre-section bound [0, first_section_VA) clamped to the image - the whole
	// span a scanner can read before it reaches section data. It is the bound the wipe is extended to;
	// it stays 0 when the image declares no section (or a zero first-section RVA), in which case there
	// is no safe pre-section bound and only the structural span is wiped.
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

	// DOS header: 0x40 bytes at the image base.
	DWORD dos_bytes = 0x40;
	if (dos_bytes > limit)
	{
		dos_bytes = limit;
	}

	// NT headers: 0x108 bytes at image_base + e_lfanew.
	DWORD nt_bytes = 0;
	if (e_lfanew < limit)
	{
		const DWORD room = limit - e_lfanew;
		nt_bytes = room < nt_size ? room : nt_size;
	}

	// Section headers: 0x28 bytes per section, immediately after the optional header. The section
	// count is clamped first, so a corrupt or hostile header can never push the writes past the
	// mapped image.
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

	// The structural header span: DOS stub + NT headers + section table, each already clamped above.
	DWORD structural_size = dos_bytes;
	if (nt_bytes && e_lfanew + nt_bytes > structural_size)
	{
		structural_size = e_lfanew + nt_bytes;
	}
	if (sec_bytes && sec_off + sec_bytes > structural_size)
	{
		structural_size = sec_off + sec_bytes;
	}

	// Extend the wipe from the structural span to the ENTIRE pre-section header region, so no MZ/PE
	// remnant can survive anywhere a scanner can reach before the first section. For a standard image
	// that is the whole first page (0x1000). The extension is bounded by pre_section, which is itself
	// clamped to the mapped image, so a hostile header can never widen the wipe past section data.
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

	// 1) Make the header region writable so it can be overwritten.
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, PAGE_READWRITE, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	// 2) Zero the ENTIRE header region [0, wipe_size) in one pass - DOS stub, the gaps between the
	//    header blocks, the NT headers, the section table and any linker padding up to the first
	//    section. A single call is used deliberately: it also covers the gaps the three structural
	//    blocks leave behind, which is exactly the space a stale MZ/PE remnant could otherwise hide in.
	//    RtlZeroMemory is the shell's own memset; the range is already clamped above.
	f->RtlZeroMemory(pData->pImageBase, wipe_size);

	// 2b) In-shell signature scan of the just-zeroed span. The region is still writable here (NOACCESS
	//     is applied in step 3), so a plain byte read is valid. A sliding window counts the two
	//     sequences a loader or memory scanner would recognise - MZ (0x4D5A) and PE\0\0 (0x50450000) -
	//     across the zeroed span; the counts are surfaced to the host and never fail the injection. The
	//     scan is bounded by wipe_size, so it never reads section data beyond the header region.
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

	// 3) Final protection: NOACCESS for maximum stealth. The now-empty header
	//    cannot be read, written, or executed, shrinking the memory-scan attack
	//    surface to the smallest possible. The control struct lives in a separate
	//    staging allocation, so this does not affect the runtime's read-back of
	//    MANUAL_MAPPING_DATA. The host no longer performs a memory read-back of
	//    this region (it only checks the resulting page protection).
	const ULONG final_access = PAGE_NOACCESS;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, final_access, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	// Publish the true wiped span and the resulting protection to the host verification step. The
	// declared SizeOfHeaders is only the header span the loader would map; the structural span is the
	// DOS stub + NT headers + section table, and the region actually wiped is the whole pre-section
	// header region (a superset), clamped to the image. The protected span is that region rounded up
	// to a page. The scan counts are the in-shell proof that the wiped span carries no MZ/PE remnant.
	pData->MapStats.HeaderStructuralSize	= structural_size;
	pData->MapStats.HeaderWipeSize			= wipe_size;
	pData->MapStats.HeaderWipeProtect		= final_access;
	pData->MapStats.HeaderScanBytes			= wipe_size;
	pData->MapStats.HeaderScanMZ			= scan_mz;
	pData->MapStats.HeaderScanPE			= scan_pe;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
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
#define AMEGER_MMAP_SENTINEL 1337
#endif

DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END()
{
	return AMEGER_MMAP_SENTINEL;
}

MANUAL_MAPPING_FUNCTION_TABLE::MANUAL_MAPPING_FUNCTION_TABLE()
{
	NT_FUNC_CONSTRUCTOR_INIT(NtClose);

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
