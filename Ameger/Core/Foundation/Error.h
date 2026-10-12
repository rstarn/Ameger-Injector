#pragma once

#include <Windows.h>
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// Central error-code registry for the runtime and the launcher.
// What: every DWORD return code the injector can produce, grouped by facility
//   (INJ_* core, INJ_MM_* manual-map shell, SR_* start-routine, FILE_* PE/file,
//   SYMBOL_* PDB/download). Why: a single header keeps host, shell, and
//   interface codes disjoint and comparable (see the range note on the
//   INJ_MM_* family in Interface/Source/Main.cpp). How: callers return a code
//   and fill ERROR_DATA with INIT_ERROR_DATA for the advanced/detail slot.
//   Values are stable ABI - never renumber, only append.
// These two deliberately share the value 0, but live in different namespaces:
// INJ_ERR_SUCCESS is the "no error" return code of the INJ_* API, while
// INJ_ERR_ADVANCED_NOT_DEFINED is the sentinel stored in ERROR_DATA.AdvErrorCode
// (via INIT_ERROR_DATA) to mean "this failure carries no advanced code". They
// are never interchangeable: a 0 AdvErrorCode is not a success return, and a
// success return is not an advanced code. Never compare one against the other.
#define INJ_ERR_SUCCESS					0x00000000
#define INJ_ERR_ADVANCED_NOT_DEFINED	0x00000000
// Core INJ_* facility below: generic host-side failures (bad path, bad PID,
// open/process errors, unsupported method). Codes are historical, not sorted.

// Manual-map shell facility (0x00400000 range). The launcher tests
// `result >= 0x00400000 && result < 0x00500000` to decide "the remote shell
// ran", so no SR_*/FILE_*/SYMBOL_* code may ever fall inside this window.

#define INJ_ERR_NO_DATA						0x00000001	
#define INJ_ERR_INVALID_FILEPATH			0x00000002	
#define INJ_ERR_FILE_DOESNT_EXIST			0x00000005	
#define INJ_ERR_INVALID_PID					0x00000006	
#define INJ_ERR_CANT_OPEN_PROCESS			0x00000007	
#define INJ_ERR_INVALID_PROC_HANDLE			0x00000008	
#define INJ_ERR_CANT_GET_EXE_FILENAME		0x00000009	
#define INJ_ERR_PLATFORM_MISMATCH			0x0000000A	
#define INJ_ERR_CANT_GET_TEMP_DIR			0x0000000B	
#define INJ_ERR_CANT_COPY_FILE				0x0000000C	
#define INJ_ERR_CANT_RENAME_FILE			0x0000000D	
#define INJ_ERR_INVALID_INJ_METHOD			0x0000000E	
#define INJ_ERR_WPM_FAIL					0x00000010	
#define INJ_ERR_GET_MODULE_HANDLE_FAIL		0x00000012	
#define INJ_ERR_OUT_OF_MEMORY_EXT			0x00000015	
#define INJ_ERR_OUT_OF_MEMORY_NEW			0x00000017	
#define INJ_ERR_GET_SYMBOL_ADDRESS_FAILED	0x00000019	
#define INJ_ERR_GET_PROC_ADDRESS_FAIL		0x0000001A	
#define INJ_ERR_VERIFY_RESULT_FAIL			0x0000001B	
#define INJ_ERR_SYMBOL_INIT_NOT_DONE		0x0000001C	
#define INJ_ERR_SYMBOL_LOAD_FAIL			0x0000001D	
#define INJ_ERR_CANT_GET_MODULE_PATH		0x0000001F	
#define INJ_ERR_FAILED_TO_LOAD_DLL			0x00000020	
#define INJ_ERR_UPDATE_PROTECTION_FAILED	0x0000002E	
#define INJ_ERR_NOT_IMPLEMENTED				0x00000033	
#define INJ_ERR_KERNEL32_MISSING			0x00000034	
#define INJ_ERR_IMPORT_HANDLER_NOT_DONE		0x00000037	
#define INJ_ERR_WINDOWS_VERSION				0x00000040	
#define INJ_ERR_ALREADY_RUNNING				0x00000042	
#define INJ_ERR_IMPORT_INTERRUPT			0x00000043	
#define INJ_ERR_INTERRUPT					0x00000045	
#define INJ_ERR_SYMBOL_PARSE_FAIL			0x00000046	
#define INJ_ERR_INVALID_EXE_PATH			0x00000048	
#define INJ_ERR_WINDOWS_BUILD_UNSUPPORTED	0x0000004E
#define INJ_ERR_HANDLE_HIJACK_FAILED		0x0000004F
#define INJ_ERR_STRING_TOO_LONG				0x00000049	

#define INJ_ERR_NO_RAW_DATA					0x0000004A	
#define INJ_ERR_FAILED_TO_RESOLVE_PATH		0x0000004C
#define INJ_ERR_UNHANDLED_EXCEPTION			0x0000004D


															

#define INJ_MM_ERR_NO_DATA						0x00400001	
#define INJ_MM_ERR_HEAP_ALLOC					0x00400003	
#define INJ_MM_ERR_UPDATE_PAGE_PROTECTION		0x00400006	
#define INJ_MM_ERR_MEMORY_ALLOCATION_FAILED		0x00400008	
#define INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED		0x00400009	
#define INJ_MM_ERR_IMPORT_FAIL					0x0040000A	
#define INJ_MM_ERR_DELAY_IMPORT_FAIL			0x0040000B	
#define INJ_MM_ERR_ENABLING_SEH_FAILED			0x0040000C	
#define INJ_MM_ERR_INVALID_HEAP_HANDLE			0x0040000E	
#define INJ_MM_ERR_INVALID_PE_IMAGE				0x00400011	
#define INJ_MM_ERR_LOADER_LOCK_FAILED			0x00400012
#define INJ_MM_ERR_DLLMAIN_FAILED				0x00400013
#define INJ_MM_ERR_TLS_CALLBACK_RANGE			0x00400014	// TLS callback pointer/array outside the mapped image: only a prefix ran, fail closed instead of reporting SUCCESS with callbacks skipped

#define SR_ERR_SUCCESS					0x00000000
// Start-routine facility (0x10000000 range): thread-launch outcomes.
// SR_HT_* (0x10200000) are hijack-thread specifics; TIMEOUT vs
// RECOVERY_REQUIRED drives whether the caller may free remote memory.

// PE/file validation facility (0x20000000 range): ReadFile/Validate rejections.

// Symbol/download facility (0x40000000 range): PDB resolve and import-handler
// readiness. Distinct from the 0x00400000 shell window above.

#define SR_ERR_INVALID_LAUNCH_METHOD	0x10000002	
#define SR_ERR_INTERRUPT				0x10000004	
#define SR_ERR_TARGET_EXITED			0x10000005

														

#define SR_HT_ERR_PROC_INFO_FAIL			0x10200001	
#define SR_HT_ERR_NO_THREADS				0x10200002	
#define SR_HT_ERR_OPEN_THREAD_FAIL			0x10200003	
#define SR_HT_ERR_SUSPEND_FAIL				0x10200004	
#define SR_HT_ERR_GET_CONTEXT_FAIL			0x10200005	
#define SR_HT_ERR_CANT_ALLOC_MEM			0x10200006	
#define SR_HT_ERR_WPM_FAIL					0x10200007	
#define SR_HT_ERR_SET_CONTEXT_FAIL			0x10200008	
#define SR_HT_ERR_RESUME_FAIL				0x10200009	
#define SR_HT_ERR_REMOTE_TIMEOUT			0x1020000A
#define SR_HT_ERR_REMOTE_PENDING_TIMEOUT	0x1020000B
#define SR_HT_ERR_RPM_FAIL					0x1020000C
#define SR_HT_ERR_RECOVERY_REQUIRED			0x1020000D	
#define SR_HT_ERR_OPEN_REFUSED				0x1020000E	// thread acquisition refused: handle hijacking found no donor and there is no direct OpenThread fallback
#define SR_HT_ERR_STUB_PATCH_FAIL			0x1020000F	// W^X stub opcode patch failed: copied asm did not match the expected lea/jmp/gs:[LastError] pattern, or the resolved TEB::LastErrorValue was unusable


												

#define FILE_ERR_SUCCESS					0x00000000

														
#define FILE_ERR_CANT_OPEN_FILE				0x20000001	
#define FILE_ERR_INVALID_FILE_SIZE			0x20000002	
#define FILE_ERR_INVALID_FILE				0x20000003	
#define FILE_ERR_MEMORY_ALLOCATION_FAILED	0x20000004	
#define FILE_ERR_INVALID_PE_LAYOUT			0x20000005	
#define FILE_ERR_RELOCATIONS_REQUIRED		0x20000006	


 
 
 
 

#define SYMBOL_ERR_SUCCESS						0x00000000

															
#define SYMBOL_ERR_CANT_OPEN_MODULE				0x40000001	
#define SYMBOL_ERR_FILE_SIZE_IS_NULL			0x40000002	
#define SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW		0x40000003	
#define SYMBOL_ERR_INVALID_FILE_ARCHITECTURE	0x40000004	
#define SYMBOL_ERR_CANT_ALLOC_MEMORY			0x40000005	
#define SYMBOL_ERR_NO_PDB_DEBUG_DATA			0x40000006	
#define SYMBOL_ERR_PATH_DOESNT_EXIST			0x40000007	
#define SYMBOL_ERR_CANT_CREATE_DIRECTORY		0x40000008	
#define SYMBOL_ERR_CANT_CONVERT_PDB_GUID		0x4000001A	
#define SYMBOL_ERR_DOWNLOAD_FAILED				0x4000000A	
#define SYMBOL_ERR_CANT_ACCESS_PDB_FILE			0x4000000B	
#define SYMBOL_ERR_CANT_OPEN_PDB_FILE			0x4000000C	
#define SYMBOL_ERR_CANT_OPEN_PROCESS			0x4000000D	
#define SYMBOL_ERR_SYM_INIT_FAIL				0x4000000E	
#define SYMBOL_ERR_SYM_LOAD_TABLE				0x4000000F	
#define SYMBOL_ERR_NOT_INITIALIZED				0x40000011	
#define SYMBOL_ERR_INVALID_SYMBOL_NAME			0x40000012	
#define SYMBOL_ERR_SYMBOL_SEARCH_FAILED			0x40000013	
#define SYMBOL_ERR_INTERRUPT					0x40000016	
#define SYMBOL_ERR_OBJECT_IS_NULL				0x40000018	
#define SYMBOL_ERR_OBJECT_NOT_READY				0x40000019	

 
 
 
 

// Per-call detail record. What: carries the advanced code plus the call-site
// line for diagnostics. szFileName/szFunctionName are intentionally zeroed by
// INIT_ERROR_DATA (kept for layout compat, never populated) - only
// AdvErrorCode and Line are meaningful.
struct ERROR_DATA
{
	DWORD		AdvErrorCode; // facility code (or INJ_ERR_ADVANCED_NOT_DEFINED = none)
	wchar_t		szFileName[MAX_PATH]; // reserved, always empty; see above
	wchar_t		szFunctionName[MAX_PATH]; // reserved, always empty; see above
	int			Line; // __LINE__ of the INIT_ERROR_DATA call site
};

// Stamps an ERROR_DATA with a code and the current line, clearing the two
// reserved name buffers. What: single statement, safe in any branch.
// Params: data (ERROR_DATA lvalue to fill), error (DWORD facility code).
#define INIT_ERROR_DATA(data, error) \
do { \
	(data).AdvErrorCode = (error); \
	(data).Line = __LINE__; \
	(data).szFileName[0] = L'\0'; \
	(data).szFunctionName[0] = L'\0'; \
} while (0)