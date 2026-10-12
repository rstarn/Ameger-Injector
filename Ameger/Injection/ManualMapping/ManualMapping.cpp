#include "Core/Utility/Header/PrecompiledHeader.h"

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

		constexpr SIZE_T kScrubChunk = 0x100000;
		const SIZE_T chunk = size < kScrubChunk ? size : kScrubChunk;
		BYTE * zeros = ReCa<BYTE *>(VirtualAlloc(nullptr, chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!zeros)
		{
			return;
		}

		BYTE * cursor = ReCa<BYTE *>(base);
		SIZE_T remaining = size;
		while (remaining)
		{
			const SIZE_T this_chunk = remaining < chunk ? remaining : chunk;
			if (!WriteProcessMemory(hTargetProc, cursor, zeros, this_chunk, nullptr))
			{
				break;
			}

			cursor += this_chunk;
			remaining -= this_chunk;
		}

		VirtualFree(zeros, 0, MEM_RELEASE);
	}
}

DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	if (Method != LAUNCH_METHOD::LM_HijackThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Unsupported launch method for in-memory load\n");

		return INJ_ERR_INVALID_INJ_METHOD;
	}

	LOG(1, "Begin in-memory load\n");

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	const DWORD remote_flags = Flags | INJ_MM_MAP_FROM_MEMORY;
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

	SIZE_T AllocationSize = 0;
	const SIZE_T allocation_parts[] =
	{
		sizeof(MANUAL_MAPPING_DATA),
		sizeof(MANUAL_MAPPING_FUNCTION_TABLE),
		static_cast<SIZE_T>(ShellSize),
		static_cast<SIZE_T>(kStagePage) * 4,
		source.FromMemory ? (static_cast<SIZE_T>(source.RawSize) + kStagePage) : 0
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

	BYTE * pAllocBase = ReCa<BYTE *>(VirtualAllocEx(hTargetProc, nullptr, AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "memory allocation failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	RemoteAllocation allocation_guard(hTargetProc, pAllocBase);

	auto scrub_guard = MakeScopeExit([&]() noexcept {
		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pAllocBase, AllocationSize);
		}
	});

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				kStagePage));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								kStagePage));
	BYTE * pRawData			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pFunctionTable) + sizeof(MANUAL_MAPPING_FUNCTION_TABLE),	BASE_ALIGNMENT));

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
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));

	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));

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

	LOG(2, "Shellsize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	LOG(2, "pDispatch      = %p\n", pFunctionTable);

	if (!WriteProcessMemory(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shelldata written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pShells, mmap_sec_base, ShellSize, nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells written to memory\n");

	if (!WriteProcessMemory(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE), nullptr))

	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Staging dispatch written to memory\n");

	if (source.FromMemory)
	{
		if (!WriteProcessMemory(hTargetProc, pRawData, source.RawData, source.RawSize, nullptr))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "WriteProcessMemory failed: %08X\n", error_data.AdvErrorCode);

			return INJ_ERR_WPM_FAIL;
		}

		LOG(1, "Raw data written to memory\n");
	}

	if (source.FromMemory && source.RawSize)
	{
		DWORD old_protect = 0;
		const SIZE_T raw_protect_size = ALIGN_UP(static_cast<SIZE_T>(source.RawSize), kStagePage);
		if (!VirtualProtectEx(hTargetProc, pRawData, raw_protect_size, PAGE_READONLY, &old_protect))
		{
			INIT_ERROR_DATA(error_data, GetLastError());

			LOG(1, "VirtualProtectEx(RO raw) failed: %08X\n", error_data.AdvErrorCode);

			return INJ_ERR_UPDATE_PROTECTION_FAILED;
		}
	}

	{
		const SIZE_T code_bytes = static_cast<SIZE_T>(ShellSize);
		if (code_bytes)
		{
			DWORD old_protect = 0;
			SIZE_T code_size = ALIGN_UP(code_bytes, kStagePage);
			void * code_base = pShells;
			if (!VirtualProtectEx(hTargetProc, code_base, code_size, PAGE_EXECUTE_READ, &old_protect))
			{
				INIT_ERROR_DATA(error_data, GetLastError());

				LOG(1, "VirtualProtectEx(RX) failed: %08X\n", error_data.AdvErrorCode);

				return INJ_ERR_UPDATE_PROTECTION_FAILED;
			}

			if (!FlushInstructionCache(hTargetProc, code_base, code_size))
			{
				LOG(1, "FlushInstructionCache failed: %08X\n", GetLastError());
			}
			LOG(1, "Staging code promoted RW->RX\n");
		}
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, Method, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, error_data);

	LOG(1, "Return from StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine failed: %08X\n", dwRet);

		if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED ||
			dwRet == SR_HT_ERR_REMOTE_PENDING_TIMEOUT ||
			dwRet == SR_HT_ERR_REMOTE_TIMEOUT)
		{
			allocation_guard.release();
		}

		return dwRet;

	}

	LOG(1, "Fetching routine data\n");

	if (!ReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "ReadProcessMemory failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	StoreMapStats(data.MapStats);

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

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

	ret = f->MMIP_ExecuteDllMain(pData);
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

	ret = f->MMIP_CloakHeader(pData);
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

	SIZE_T ImgSize = static_cast<SIZE_T>(pData->pOptionalHeader->SizeOfImage);

	pData->ntRet = f->NtAllocateVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), 0, &ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
	}

	pData->pImageBase = pData->pAllocationBase;

	f->memmove(pData->pImageBase, pData->pRawData, pData->pOptionalHeader->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);
	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{

		if (pCurrentSectionHeader->VirtualAddress < pData->pOptionalHeader->SizeOfHeaders)
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

	if (pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS)
	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
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
		auto * pRelocDir = ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

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
					if (patch_rva + sizeof(ULONG_PTR) > pData->pOptionalHeader->SizeOfImage)
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
	if (!(pData->Flags & INJ_MM_INIT_SECURITY_COOKIE) || !pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
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

	const IMAGE_DATA_DIRECTORY & load_config = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
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

	IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
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

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);

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

	IMAGE_DATA_DIRECTORY		* pDelayImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
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

		pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pDelayImportsHead);

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
	SIZE_T SizeOut = pData->pOptionalHeader->SizeOfHeaders;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pImageBase), &SizeOut, PAGE_READONLY, &OldProtection);

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	auto pCurrentSectionHeader = IMAGE_FIRST_SECTION(pData->pNtHeaders);

	for (UINT i = 0; i != pData->pFileHeader->NumberOfSections; ++i, ++pCurrentSectionHeader)
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
				break;
			}
		}
	}

	if (NT_FAIL(pData->ntRet))
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

	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					ULONG old_prot = 0;
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, PAGE_EXECUTE_READ, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

#ifdef _WIN64
	const IMAGE_DATA_DIRECTORY & exc_dir = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

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

			f->RtlInsertInvertedFunctionTable(pData->pImageBase, pData->pOptionalHeader->SizeOfImage);
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
					UINT_PTR pRaw = ReCa<UINT_PTR>(pData->pFakeSEHDirectory);
					const DWORD cookie = *ReCa<volatile DWORD *>(ReCa<BYTE *>(static_cast<UINT_PTR>(KUSER_SHARED_DATA)) + dyno.KuserCookie);
					UINT_PTR pEncoded = bit_rotate_r(cookie ^ pRaw, cookie & 0x3F);
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

	if (!pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					constexpr ULONG new_prot = PAGE_EXECUTE_READ;
					ULONG old_prot = 0;

					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, new_prot, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

	const DWORD ldr_size = pData->NtOffsets.LdrEntrySize ? pData->NtOffsets.LdrEntrySize : sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
	const DWORD ldr_base_off = pData->NtOffsets.LdrEntryDllBase;
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

	auto * pDummyLdr = ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);

	pData->ntRet = f->LdrpHandleTlsData(pDummyLdr);
	if (NT_FAIL(pData->ntRet))
	{

		return static_cast<DWORD>(pData->ntRet);
	}

	ULONG callback_count = 0;
	DWORD tls_result = INJ_ERR_SUCCESS;
	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pCallback)
	{

		if (!MMI_InImage(pData, pCallback, sizeof(*pCallback)))
		{
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
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		if (!MMI_InImage(pData, ReCa<void *>(Callback), sizeof(BYTE)))
		{

			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
		++callback_count;
		++pCallback;
	}

	bool unlinked = false;

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
				}

				break;
			}
		}
	}

	if (unlinked)
	{
		DeleteObject(f, pDummyLdr);
	}

	return tls_result;
}

DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RUN_DLL_MAIN))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!pData->pOptionalHeader->AddressOfEntryPoint)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG		State	= 0;
	ULONG_PTR	Cookie	= 0;
	bool		locked	= false;

	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					constexpr ULONG new_prot = PAGE_EXECUTE_READ;
					ULONG old_prot = 0;

					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, new_prot, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
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

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + pData->pOptionalHeader->AddressOfEntryPoint);
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

	pData->MapStats.ImportSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	pData->MapStats.DelayImportSize	= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	pData->MapStats.DebugSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	pData->MapStats.RelocSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	pData->MapStats.TlsSize			= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	pData->MapStats.ExportSize		= pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pData->MapStats.CleanedMask		=
		((pData->MapStats.ImportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_IMPORT) |
		((pData->MapStats.DelayImportSize	? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) |
		((pData->MapStats.DebugSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DEBUG) |
		((pData->MapStats.RelocSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_BASERELOC) |
		((pData->MapStats.TlsSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_TLS) |
		((pData->MapStats.ExportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_EXPORT);

	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					ULONG old_prot = 0;
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, PAGE_READWRITE, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
		}
	}

	DWORD Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto * pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + Size);
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	if (Size)
	{
		auto * pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + Size);
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}

	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (Size)
	{
		auto * pExportDir = ReCa<IMAGE_EXPORT_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	}

	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto * pRelocEnd = ReCa<BYTE *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + Size);
		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	Size = pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
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

		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
		pData->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size			= 0;
	}

	{
		auto * pSec = IMAGE_FIRST_SECTION(pData->pNtHeaders);
		for (UINT i = 0; i < pData->pFileHeader->NumberOfSections; ++i, ++pSec)
		{
			if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				void * base = pData->pImageBase + pSec->VirtualAddress;
				SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;
				if (sec_size)
				{
					ULONG old_prot = 0;
					pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, PAGE_EXECUTE_READ, &old_prot);
					if (NT_FAIL(pData->ntRet))
					{
						return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
					}
				}
			}
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
		};

		auto * dirs = pData->pOptionalHeader->DataDirectory;
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

	void * base			= pData->pImageBase;
	SIZE_T header_size	= pData->pOptionalHeader->SizeOfHeaders;
	ULONG old_access	= NULL;

	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, PAGE_READWRITE, &old_access);

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	f->RtlZeroMemory(pData->pImageBase, header_size);

	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &header_size, old_access, &old_access);

	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

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
