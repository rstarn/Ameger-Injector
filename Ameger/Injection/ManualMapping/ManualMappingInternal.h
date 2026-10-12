#pragma once

#include <cstdint>

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "Injection.h"
#include "Execution/Routine/StartRoutine.h"

// In-target manual-map shell contract.
// What: MANUAL_MAPPING_DATA is the shell's only argument (image bases,
//   headers, dependency lists, NtOffsets, stats); MANUAL_MAPPING_FUNCTION_TABLE
//   carries the resolved ntdll/local helpers plus per-stage entry points so the
//   shell never imports directly. Why page-split code_seg sections: each MMI_*
//   stage lands on its own RX page while data stays RW (W^X, never RWX).
//   Pipeline order in ManualMapping_Shell: MapSections -> Relocate -> Cookie ->
//   Imports -> DelayImports -> Exceptions -> TLS -> DllMain -> CleanDirs ->
//   Protections -> CloakHeader; any failure runs CleanUp and aborts.
// True when a relocation entry is a 64-bit VA fixup (type field == DIR64).
// Params: RelInfo (entry word). x64-only build supports DIR64 + ABSOLUTE skip.
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#define RELOC_FLAG RELOC_FLAG64

// Staging alignment for the raw-image slot (was VEHShell.h's BASE_ALIGNMENT;
// kept here since the VEH header is no longer included).
#define BASE_ALIGNMENT 0x10

namespace MMAP_NATIVE
{
	struct MANUAL_MAPPING_DATA;
	struct MANUAL_MAPPING_FUNCTION_TABLE;
}

// Payload DllMain signature invoked by MMI_ExecuteDllMain. Params: hDll
// (mapped image base), dwReason (ATTACH/DETACH), pReserved (null).
using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(HINSTANCE hDll, DWORD dwReason, void * pReserved);
// One shell-stage signature. Params: pData (in/out shell state). Returns:
// INJ_* code; any non-success aborts the pipeline into MMI_CleanUp.
using f_MMI_FUNCTION = DWORD(__stdcall *)(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

// Circular doubly-linked record of one loaded dependency (LDR ref held).
// Why circular: head->Prev is the tail, so append/unload are O(1) without a
// separate tail pointer. DllHandle is the LDR base used for LdrUnloadDll.
typedef struct _MM_DEPENDENCY_RECORD
{
	struct _MM_DEPENDENCY_RECORD * Next = nullptr;
	struct _MM_DEPENDENCY_RECORD * Prev = nullptr;

	HANDLE DllHandle = nullptr;
} MM_DEPENDENCY_RECORD;

// Pipeline stages (run in numeric code_seg order; $05 is intentionally
// unused). Each takes pData and returns INJ_*; see ManualMapping.cpp for the
// per-stage contract (inputs written, failures, W^X handling).
DWORD __declspec(code_seg(".mmap_sec$01")) __stdcall ManualMapping_Shell		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // orchestrator: runs stages in order, CleanUp on first failure
DWORD __declspec(code_seg(".mmap_sec$02")) __stdcall MMI_MapSections			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // validates + copies headers/sections to a RW image allocation
DWORD __declspec(code_seg(".mmap_sec$03")) __stdcall MMI_RelocateImage			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // applies DIR64 base relocs for the delta
DWORD __declspec(code_seg(".mmap_sec$04")) __stdcall MMI_InitializeCookie		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // seeds ___security_cookie from the image base
DWORD __declspec(code_seg(".mmap_sec$06")) __stdcall MMI_LoadImports			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // resolves the classic import table via LDR
DWORD __declspec(code_seg(".mmap_sec$07")) __stdcall MMI_LoadDelayImports		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // resolves the delay-import table via LDR
DWORD __declspec(code_seg(".mmap_sec$08")) __stdcall MMI_SetPageProtections		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // final RX/RW/RO split from section characteristics
DWORD __declspec(code_seg(".mmap_sec$09")) __stdcall MMI_EnableExceptions		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // SEH via inverted + function tables, zero VEH
DWORD __declspec(code_seg(".mmap_sec$0A")) __stdcall MMI_HandleTLS				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // allocates TLS slots and runs callbacks
DWORD __declspec(code_seg(".mmap_sec$0B")) __stdcall MMI_ExecuteDllMain			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // runs DllMain(ATTACH) under the loader lock
DWORD __declspec(code_seg(".mmap_sec$0C")) __stdcall MMI_CleanDataDirectories	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // zeroes import/export/debug/reloc/TLS metadata
DWORD __declspec(code_seg(".mmap_sec$0D")) __stdcall MMI_CloakHeader			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // zeroes the PE headers when INJ_ERASE_HEADER
DWORD __declspec(code_seg(".mmap_sec$0E")) __stdcall MMI_CleanUp				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData); // failure path: unloads deps, removes tables, frees image unless leaking

// Import helpers (share the shell calling convention, return NTSTATUS).
// MMIH_PreprocessModuleName: normalizes szModule to a UNICODE path + loader
// flags. MMIH_LoadModule: loads via LdrpLoadDllInternal and records the dep.
NTSTATUS __declspec(code_seg(".mmap_sec$12")) __stdcall MMIH_PreprocessModuleName(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * ModuleName, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags);
NTSTATUS __declspec(code_seg(".mmap_sec$13")) __stdcall MMIH_LoadModule(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head);

// End-of-shell sentinel (returns AMEGER_MMAP_SENTINEL). The host derives
// ShellSize from MMP_Shell..MMAP_SEC_END to know how many bytes to copy.
DWORD __declspec(code_seg(".mmap_sec$14")) MMAP_SEC_END();

namespace MMAP_NATIVE
{
	using namespace NATIVE;

	ALIGN struct MANUAL_MAPPING_FUNCTION_TABLE
	{
		ALIGN NT_FUNC_LOCAL(NtClose);

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
		// Optional: resolved but intentionally NOT part of IsValid(). A rename
		// or a build without the export must not fail the injection; the field
		// is simply null and MMI_CleanUp skips the delete.
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

		// Set by MMI_EnableExceptions only when RtlAddFunctionTable actually
		// registered the image's .pdata. MMI_CleanUp removes it before the
		// image is freed so the loader's table does not dangle. Null means no
		// entry was added (the loader already had one, or the stage failed).
		ALIGN RUNTIME_FUNCTION	*	pDynamicFunctionTable	= nullptr;

		// Set once MMI_EnableExceptions observes its inverted-table entry for
		// this image (even when the stage later fails). ntdll exposes no
		// removal routine, so MMI_CleanUp must leak the image (and the fake
		// SEH directory the entry may reference) instead of freeing them
		// under the dangling entry. DWORD (not bool) to keep the ALIGN layout
		// explicit; 0 = absent, 1 = installed.
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

		// Downloaded Windows layouts for the remote shell (no PDB/DbgHelp in
		// the target). Filled by the host from g_DynamicOffsets before the
		// WPM of pArg; every remote LDR/TLS/inverted/KUSER access uses these
		// instead of hardcoded struct offsets.
		ALIGN DYNAMIC_NT_OFFSETS NtOffsets{};
	};
}

#pragma region inlined helper functions

__forceinline UINT_PTR bit_rotate_r(UINT_PTR val, int count)
{
	// Rotate right by count. `-count` on a signed int is undefined, and shifting
	// by the full width is undefined too, so mask the count and derive the
	// complement explicitly instead of relying on x64's shift masking.
	constexpr unsigned kBits = sizeof(UINT_PTR) * 8u;
	const unsigned shift = static_cast<unsigned>(count) & (kBits - 1u);
	if (!shift)
	{
		return val;
	}

	return (val >> shift) | (val << (kBits - shift));
}

// Resolves the loader heap handle for one allocation without writing anywhere.
// f->LdrpHeap points into the target's ntdll .data (same system-wide base as
// the host's, so the pointer the host resolved stays valid in-target); the
// handle is read straight out of it on every call.
//
// Why no cache: the function table used to carry a writable pLdrpHeap slot
// that ManualMapping_Shell filled on entry. The host's TOCTOU guard freezes
// the table's page read-only before the shell runs (pRawData starts mid-page
// and VirtualProtectEx rounds down over the table tail), so that first write
// faulted with an access violation and killed the target deterministically -
// before any mapping, for every payload, on every flag set. A cache in
// MANUAL_MAPPING_DATA would work (pArg stays writable) but threading pData
// through every allocator is more invasive than one pointer chase per
// (infrequent) allocation, so the handle is simply re-read. Returns null when
// unresolved; callers fail closed.
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

// Download-dependent allocation: the byte count normally comes from the
// PDB-resolved NtOffsets (e.g. LdrEntrySize / LdrpPathSearchContextSize) and
// falls back to sizeof(static struct) only when the PDB lacked the type.
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

__forceinline bool MMI_InImage(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const void * address, size_t size)
{
	if (!pData || !pData->pImageBase || !pData->pOptionalHeader || !address || !size)
	{
		return false;
	}

	const ULONG_PTR base = ReCa<ULONG_PTR>(pData->pImageBase);
	const ULONG_PTR target = ReCa<ULONG_PTR>(address);
	const ULONG_PTR image_size = pData->pOptionalHeader->SizeOfImage;

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
	const size_t maximum = static_cast<size_t>(pData->pOptionalHeader->SizeOfImage - (ReCa<ULONG_PTR>(text) - base));

	const size_t length = MMI_BoundedStringLength(text, maximum);

	// MMI_BoundedStringLength returns `maximum` when it never met a NUL. That
	// is an unterminated string, not a valid length: a real terminator would
	// have to sit at text[maximum], one byte past SizeOfImage. Report 0 so
	// every caller's `!length` guard rejects it instead of walking - and
	// zeroing - past the end of the committed image. (maximum is always >= 1
	// here: MMI_InImage above proved text has one in-image byte.)
	return length == maximum ? 0 : length;
}

// True only for virtual apiset names ("api-ms-" / "ext-ms-", case-insensitive).
// STATUS_APISET_NOT_HOSTED is benign solely for these: the apiset schema has
// no host, so there is nothing to bind. A real dependency failing with this
// status must fail closed instead of leaving an unbound IAT under SUCCESS.
// Each byte is read only after proving it in-image; short/unterminated input
// returns false.
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
	// Same guards as NewObject: this used to dereference f->RtlFreeHeap and
	// the heap handle unconditionally, so a cleanup path reached before the
	// heap was resolved (or with no function table) faulted inside the shell.
	// The handle comes from MMI_LdrpHeap (read-only table, no cache write).
	void * heap = MMI_LdrpHeap(f);
	if (Object && f && f->RtlFreeHeap && heap)
	{
		f->RtlFreeHeap(heap, NULL, Object);
	}
}

__forceinline bool InitAnsiString(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, ANSI_STRING * String, const char * szString, size_t Length)
{
	// `Length` is the caller-measured in-image string length. A valid Length
	// proves the NUL at szString[Length] is in-image, because
	// MMI_ImageStringLength returns 0 for an unterminated string. The scan for
	// that NUL is bounded by Length + 1 instead of the old unbounded while(*c):
	// an unterminated module name used to walk past the end of the committed
	// image. Any NUL not exactly at index Length is rejected.
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