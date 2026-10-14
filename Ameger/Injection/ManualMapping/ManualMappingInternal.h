#pragma once

#include <cstdint>

#include "Native/Syscall.h"

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "../../Injection.h"
#include "Execution/Routine/StartRoutine.h"

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#define RELOC_FLAG RELOC_FLAG64

#define BASE_ALIGNMENT 0x10

// Upper bound for the section-table snapshot kept in MANUAL_MAPPING_DATA. The PE format caps the
// section count at 96, so a larger value cannot come from a well-formed image.
#define MM_MAX_CACHED_SECTIONS 96

namespace MMAP_NATIVE
{
	struct MANUAL_MAPPING_DATA;
	struct MANUAL_MAPPING_FUNCTION_TABLE;
}

using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(HINSTANCE hDll, DWORD dwReason, void * pReserved);

using f_MMI_FUNCTION = DWORD(__stdcall *)(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

typedef struct _MM_DEPENDENCY_RECORD
{
	struct _MM_DEPENDENCY_RECORD * Next = nullptr;
	struct _MM_DEPENDENCY_RECORD * Prev = nullptr;

	HANDLE DllHandle = nullptr;
} MM_DEPENDENCY_RECORD;

DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$05")) __stdcall MMI_SetExecProtections	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, DWORD NewState);
bool	__declspec(code_seg(".mmap_sec$11")) __stdcall MMI_FindLoadedModule	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule);
DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0F")) __stdcall MMI_RunTlsCallbacks		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * ModuleName, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags);
NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head);

DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END();

#define MM_EXEC_STATE_MAPPABLE	0
#define MM_EXEC_STATE_EXECUTE	1
#define MM_EXEC_STATE_WRITABLE	2

namespace MMAP_NATIVE
{
	using namespace NATIVE;

	ALIGN struct MANUAL_MAPPING_FUNCTION_TABLE
	{
	ALIGN NT_FUNC_LOCAL(NtClose);

	ALIGN NT_FUNC_LOCAL(NtQueryInformationProcess);

	ALIGN NT_FUNC_LOCAL(NtAllocateVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtProtectVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtFreeVirtualMemory);

		ALIGN NT_FUNC_LOCAL(memmove);
		ALIGN NT_FUNC_LOCAL(RtlZeroMemory);
		ALIGN NT_FUNC_LOCAL(RtlAllocateHeap);
		ALIGN NT_FUNC_LOCAL(RtlFreeHeap);

		ALIGN NT_FUNC_LOCAL(LdrpLoadDllInternal);
		ALIGN NT_FUNC_LOCAL(LdrGetProcedureAddress);

		ALIGN NT_FUNC_LOCAL(LdrUnloadDll);

		ALIGN NT_FUNC_LOCAL(RtlAnsiStringToUnicodeString);

		ALIGN NT_FUNC_LOCAL(LdrpPreprocessDllName);
		ALIGN NT_FUNC_LOCAL(RtlInsertInvertedFunctionTable);
		ALIGN NT_FUNC_LOCAL(RtlAddFunctionTable);
		ALIGN NT_FUNC_LOCAL(RtlLookupFunctionEntry);

		ALIGN NT_FUNC_LOCAL(RtlDeleteFunctionTable);
		ALIGN NT_FUNC_LOCAL(LdrpHandleTlsData);

		ALIGN NT_FUNC_LOCAL(LdrLockLoaderLock);
		ALIGN NT_FUNC_LOCAL(LdrUnlockLoaderLock);

		ALIGN NT_FUNC_LOCAL(LdrpDereferenceModule);

		ALIGN NT_FUNC_LOCAL(LdrProtectMrdata);

		ALIGN NT_FUNC_LOCAL(LdrpHeap);
		ALIGN NT_FUNC_LOCAL(LdrpInvertedFunctionTable);
		ALIGN NT_FUNC_LOCAL(LdrpTlsList);

		ALIGN f_MMI_FUNCTION MMP_Shell					= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_MapSections			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_RelocateImage			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_InitializeCookie		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadImports			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadDelayImports		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_SetPageProtections	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_EnableExceptions		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_HandleTLS				= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_RunTlsCallbacks		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_ExecuteDllMain		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanDataDirectories	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CloakHeader			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanUp				= nullptr;

		ALIGN decltype(MMIH_PreprocessModuleName)		* MMIHP_PreprocessModuleName		= nullptr;
		ALIGN decltype(MMIH_LoadModule)					* MMIHP_LoadModule					= nullptr;

		MANUAL_MAPPING_FUNCTION_TABLE();

		bool IsValid() const
		{
				return NtClose &&
		NtAllocateVirtualMemory && NtProtectVirtualMemory && NtFreeVirtualMemory &&
		memmove && RtlZeroMemory && RtlAllocateHeap && RtlFreeHeap &&
		LdrpLoadDllInternal && LdrGetProcedureAddress && LdrUnloadDll &&
		RtlAnsiStringToUnicodeString &&
		LdrpPreprocessDllName &&
		RtlAddFunctionTable && LdrpHandleTlsData &&
		LdrLockLoaderLock && LdrUnlockLoaderLock &&
		LdrpDereferenceModule &&
		LdrpHeap && LdrpTlsList;
		}
	};

 	ALIGN struct MANUAL_MAPPING_DATA
 	{
 		ALIGN HINSTANCE	hRet		= NULL;
 		ALIGN DWORD		Flags		= NULL;
 		ALIGN NTSTATUS	ntRet		= STATUS_SUCCESS;

 		ALIGN void				*	pFakeSEHDirectory	= nullptr;

 		ALIGN RUNTIME_FUNCTION	*	pDynamicFunctionTable	= nullptr;

 		ALIGN DWORD	InvertedTableInstalled = 0;

 		ALIGN BYTE *	pAllocationBase	= nullptr;
 		ALIGN BYTE *	pImageBase		= nullptr;
 		ALIGN BYTE *	pRawData		= nullptr;
 		ALIGN DWORD		RawSize			= 0;

 		ALIGN IMAGE_DOS_HEADER		* pDosHeader		= nullptr;
 		ALIGN IMAGE_NT_HEADERS		* pNtHeaders		= nullptr;
 		ALIGN IMAGE_OPTIONAL_HEADER	* pOptionalHeader	= nullptr;
 		ALIGN IMAGE_FILE_HEADER		* pFileHeader		= nullptr;

 		ALIGN MM_DEPENDENCY_RECORD * pImportsHead		= nullptr;
 		ALIGN MM_DEPENDENCY_RECORD * pDelayImportsHead	= nullptr;

 		ALIGN MAP_STATS MapStats{};

 		ALIGN MANUAL_MAPPING_FUNCTION_TABLE * FunctionTable = nullptr;

 		ALIGN DYNAMIC_NT_OFFSETS NtOffsets{};

		// Exec section protection bookkeeping. Three of the stages used to walk the section table and
		// issue NtProtectVirtualMemory independently, which turned one mapped image into six separate
		// RW->RX->RW->RX transitions on the same pages. Everything now routes through one flag so the
		// whole image is promoted exactly twice.
		ALIGN DWORD ExecProtectionState = MM_EXEC_STATE_MAPPABLE;

		// Payload obfuscation. The image bytes never cross the boundary in the clear: the host stores
		// a keystream transform and the remote side recovers the plaintext while copying it into place,
		// so neither the transfer nor the staging region ever holds a recognisable PE.
		ALIGN DWORD64	PayloadSeed0	= 0;
		ALIGN DWORD64	PayloadSeed1	= 0;
		ALIGN DWORD		PayloadEncoded	= 0;

		// Per-callback TLS diagnostics. When a TLS callback is rejected the remote side records which
		// entry failed and at what address, so the host can name the exact callback instead of only
		// reporting the aggregate range error.
		ALIGN DWORD		TlsCallbackIndex	= 0;
		ALIGN ULONG_PTR	TlsCallbackAddress	= 0;

		// Snapshot of the header values the stages that run *after* the erase still need.
		// The shell erases the headers before any payload code runs, so the module-load
		// finalisation steps (clean data directories, page protections) and the payload
		// drivers (TLS, entry point) can no longer read them from the image. The snapshot
		// is captured in MMI_MapSections while the raw headers are still intact, and the
		// MMI_* accessors below consult it only when INJ_ERASE_HEADER is set, so a run
		// without header erasure reads the live headers exactly as before.
		ALIGN DWORD					CachedSizeOfImage	= 0;
		ALIGN DWORD					CachedSizeOfHeaders	= 0;
		ALIGN DWORD					CachedEntryPoint	= 0;
		ALIGN DWORD					CachedSectionCount	= 0;
		ALIGN IMAGE_SECTION_HEADER	CachedSections[MM_MAX_CACHED_SECTIONS]{};
		ALIGN IMAGE_DATA_DIRECTORY	CachedDataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};

 		// Transient TLS state. MMI_HandleTLS registers the payload's TLS data (LdrpHandleTlsData
 		// reads the image's own headers to find the TLS directory, so the erase has to follow it),
 		// then the header erase runs, then MMI_RunTlsCallbacks drives the callbacks. These three
 		// pointers carry the setup across that boundary; they are heap objects and section data, not
 		// header bytes, so they survive the erase.
 		ALIGN void *	TlsDirectory	= nullptr;	// IMAGE_TLS_DIRECTORY * inside the mapped image
 		ALIGN void *	TlsDummyLdr		= nullptr;	// fake LDR_DATA_TABLE_ENTRY handed to LdrpHandleTlsData
 		ALIGN void *	TlsDdagNode		= nullptr;	// fake LDR_DDAG_NODE linked from the fake entry

 		// Verifiable execution telemetry. Written in-shell from explicit NTSTATUS,
 		// DllMain return, rdtsc deltas, and sliding-window scans — never inferred.
 		ALIGN VERIFIABLE_EXEC_TELEMETRY ExecTelemetry{};

 		// Per-section page-protection ground truth recorded in-shell.
 		ALIGN DWORD SectionProtCount = 0;
 		ALIGN SECTION_PROT_RECORD SectionProt[MM_MAX_PROT_RECORDS]{};
  	};
}

// Both sides of the transfer need the same rotation helper.
__forceinline DWORD64 MMI_RotateRight64(DWORD64 Value, unsigned Count)
{
	constexpr unsigned kBits = sizeof(DWORD64) * 8u;
	const unsigned Shift = Count & (kBits - 1u);

	if (!Shift)
	{
		return Value;
	}

	return (Value >> Shift) | (Value << (kBits - Shift));
}

#pragma region inlined helper functions

// Position indexed key stream. Both the host encoder and the remote decoder evaluate the same
// function for the same offset, so sections can be recovered in any order and in any granularity
// without carrying a running cipher state between passes.
__forceinline DWORD64 MMI_KeyBlock(DWORD64 Seed0, DWORD64 Seed1, DWORD64 Index)
{
	DWORD64 x = Seed0 ^ (Index * 0x9E3779B97F4A7C15ULL);
	x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
	x ^= x >> 27; x *= 0x94D049BB133111EBULL;
	x ^= x >> 31;
	x ^= Seed1 + (Index << 32) + Index;
	x ^= x >> 29; x *= 0xBF58476D1CE4E5B9ULL;
	x ^= x >> 32;
	x ^= x >> 25; x *= 0x2545F4914F6CDD1DULL;
	x ^= x >> 12;

	return x;
}

// Transforms a byte range in place. Applying the function twice is the identity, so the same routine
// encodes on the host and decodes in the target.
__forceinline void MMI_KeyTransformInPlace(BYTE * Data, size_t Size, DWORD64 Seed0, DWORD64 Seed1)
{
	if (!Data || !Size)
	{
		return;
	}

	size_t offset = 0;

	while (offset + sizeof(DWORD64) <= Size)
	{
		const DWORD64 Block = MMI_KeyBlock(Seed0, Seed1, offset / sizeof(DWORD64));
		*ReCa<DWORD64 *>(Data + offset) ^= Block;

		offset += sizeof(DWORD64);
	}

	if (offset < Size)
	{
		const DWORD64 Block = MMI_KeyBlock(Seed0, Seed1, offset / sizeof(DWORD64));
		const auto * Bytes = ReCa<const BYTE *>(&Block);

		for (size_t i = 0; offset + i < Size; ++i)
		{
			Data[offset + i] ^= Bytes[i];
		}
	}
}

// Streams a transformed copy without touching the source.
__forceinline void MMI_KeyTransformCopy(BYTE * Destination, const BYTE * Source, size_t Size, DWORD64 Seed0, DWORD64 Seed1)
{
	if (!Destination || !Source || !Size)
	{
		return;
	}

	size_t offset = 0;

	while (offset + sizeof(DWORD64) <= Size)
	{
		const DWORD64 Block = MMI_KeyBlock(Seed0, Seed1, offset / sizeof(DWORD64));
		*ReCa<DWORD64 *>(Destination + offset) = *ReCa<const DWORD64 *>(Source + offset) ^ Block;

		offset += sizeof(DWORD64);
	}

	if (offset < Size)
	{
		const DWORD64 Block = MMI_KeyBlock(Seed0, Seed1, offset / sizeof(DWORD64));
		const auto * Bytes = ReCa<const BYTE *>(&Block);

		for (size_t i = 0; offset + i < Size; ++i)
		{
			Destination[offset + i] = Source[offset + i] ^ Bytes[i];
		}
	}
}

__forceinline void * MMI_LdrpHeap(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f)
{
	if (!f || !f->LdrpHeap)
	{
		return nullptr;
	}

	return *f->LdrpHeap;
}

template <class T>
__forceinline T * NewObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, size_t Count = 1)
{
	void * heap = MMI_LdrpHeap(f);
	if (!f || !f->RtlAllocateHeap || !heap || !Count || sizeof(T) > (SIZE_MAX) / Count)
	{
		return nullptr;
	}

	return ReCa<T *>(f->RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, sizeof(T) * Count));
}

__forceinline void * NewBytes(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, SIZE_T Size)
{
	void * heap = MMI_LdrpHeap(f);
	if (!f || !f->RtlAllocateHeap || !heap || !Size || Size > 0x10000)
	{
		return nullptr;
	}

	return f->RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, Size);
}

__forceinline void WritePtrField(void * Base, DWORD Off, void * Value)
{
	*ReCa<void **>(ReCa<BYTE *>(Base) + Off) = Value;
}

__forceinline void * ReadPtrField(const void * Base, DWORD Off)
{
	return *ReCa<void * const *>(ReCa<const BYTE *>(Base) + Off);
}

// Header accessors. When the header region has been erased the live pointers address zeroed,
// no-access pages, so every post-erase read is served from the snapshot instead. When erasure is
// off the accessors are pass-throughs onto the mapped headers, keeping the unerased run identical.
__forceinline IMAGE_SECTION_HEADER * MMI_Sections(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return const_cast<IMAGE_SECTION_HEADER *>(pData->CachedSections);
	}

	return IMAGE_FIRST_SECTION(pData->pNtHeaders);
}

__forceinline DWORD MMI_SectionCount(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSectionCount;
	}

	return pData->pFileHeader->NumberOfSections;
}

__forceinline IMAGE_DATA_DIRECTORY * MMI_DataDirectory(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return const_cast<IMAGE_DATA_DIRECTORY *>(pData->CachedDataDirectory);
	}

	return pData->pOptionalHeader->DataDirectory;
}

__forceinline DWORD MMI_SizeOfImage(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSizeOfImage;
	}

	return pData->pOptionalHeader->SizeOfImage;
}

__forceinline DWORD MMI_SizeOfHeaders(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSizeOfHeaders;
	}

	return pData->pOptionalHeader->SizeOfHeaders;
}

__forceinline DWORD MMI_EntryPoint(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedEntryPoint;
	}

	return pData->pOptionalHeader->AddressOfEntryPoint;
}

__forceinline bool MMI_InImage(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const void * address, size_t size)
{
	if (!pData || !pData->pImageBase || !pData->pOptionalHeader || !address || !size)
	{
		return false;
	}

	const ULONG_PTR base = ReCa<ULONG_PTR>(pData->pImageBase);
	const ULONG_PTR target = ReCa<ULONG_PTR>(address);
	const ULONG_PTR image_size = MMI_SizeOfImage(pData);

	return target >= base && size <= image_size && target - base <= image_size - size;
}

__forceinline size_t MMI_BoundedStringLength(const char * text, size_t maximum)
{
	size_t length = 0;

	while (length < maximum && text[length])
	{
		++length;
	}

	return length;
}

__forceinline size_t MMI_ImageStringLength(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * text)
{
	if (!MMI_InImage(pData, text, sizeof(char)))
	{
		return 0;
	}

	const ULONG_PTR base = ReCa<ULONG_PTR>(pData->pImageBase);
	const size_t maximum = static_cast<size_t>(MMI_SizeOfImage(pData) - (ReCa<ULONG_PTR>(text) - base));

	const size_t length = MMI_BoundedStringLength(text, maximum);

	return length == maximum ? 0 : length;
}

__forceinline bool MMI_IsApisetName(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * text)
{
	static const char kApi[] = { 'a', 'p', 'i', '-', 'm', 's', '-' };
	static const char kExt[] = { 'e', 'x', 't', '-', 'm', 's', '-' };

	bool api = true;
	bool ext = true;

	for (size_t i = 0; i < 7; ++i)
	{
		if (!MMI_InImage(pData, text + i, sizeof(char)))
		{
			return false;
		}
		char c = text[i];
		if (c >= 'A' && c <= 'Z')
		{
			c = static_cast<char>(c + ('a' - 'A'));
		}
		api = api && (c == kApi[i]);
		ext = ext && (c == kExt[i]);
		if (!api && !ext)
		{
			return false;
		}
	}

	return api || ext;
}

template <class T>
__forceinline void DeleteObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, T * Object)
{

	void * heap = MMI_LdrpHeap(f);
	if (Object && f && f->RtlFreeHeap && heap)
	{
		f->RtlFreeHeap(heap, NULL, Object);
	}
}

__forceinline bool InitAnsiString(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, ANSI_STRING * String, const char * szString, size_t Length)
{

	if (!Length || Length > 0xFFFF || MMI_BoundedStringLength(szString, Length + 1) != Length)
	{
		return false;
	}

	String->szBuffer = NewObject<char>(f, Length + 1);
	if (!String->szBuffer)
	{
		return false;
	}

	String->Length = static_cast<WORD>(Length);
	String->MaxLength = static_cast<WORD>((Length + 1) * sizeof(char));
	f->memmove(String->szBuffer, szString, Length);

	return true;
}

#pragma endregion
