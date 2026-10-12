#pragma once

#include <Windows.h>
#include "Core/Foundation/Primitives/InjectionTypes.h"

// Public injection ABI shared by the launcher and the runtime DLL.
// What: the in-memory payload descriptor (MEMORY_INJECTIONDATA), the
//   INJ_*/INJ_MM_* flag words, the exported function-pointer types, and the
//   telemetry getters/resets. Why one header: the launcher builds these structs
//   and the runtime reads them across the DLL boundary, so layout drift is a
//   silent reinterpretation bug - hence the offset static_asserts in
//   Interface/Source/Main.cpp. Mode/method enums live in InjectionTypes.h.
// There is exactly one payload path: the memory descriptor below. The on-disk
// file-path entries (CoreLoadA/CoreLoadW and their INJECTIONDATAA/W structs,
// with their temp-copy and name-scrambling toggles) were removed - a payload
// that never touches disk leaves nothing to enumerate.
// In-memory payload descriptor (the only path). Fields: RawData/RawSize
// (payload image bytes, owned by the caller for the call duration),
// ProcessID (target), Mode/Method (only IM_ManualMap/LM_HijackThread), Flags
// (INJ_*/INJ_MM_* word from BuildFlags), Timeout (ms for the remote shell),
// hHandleValue (sponsor process handle value, 0 = none), hDllOut (out remote
// image base), GenerateErrorLog (write ERROR_INFO on failure),
// TargetTid/hThreadHandleValue (pre-picked victim hint; 0/0 = runtime
// searches).
struct MEMORY_INJECTIONDATA
{
	BYTE * RawData;
	DWORD RawSize;
	DWORD ProcessID;
	INJECTION_MODE Mode;
	LAUNCH_METHOD Method;
	DWORD Flags;
	DWORD Timeout;
	ULONG_PTR hHandleValue;
	HINSTANCE hDllOut;
	bool GenerateErrorLog;
	DWORD TargetTid;				// pre-selected victim thread (0 = runtime picks)
	ULONG_PTR hThreadHandleValue;	// sponsor thread handle (0 = none)
};

#define INJ_ERASE_HEADER				0x0001	
// Bit 0x0002 is retired (was INJ_FAKE_HEADER). Do not reuse: a stale caller may
// still pass it and a silent meaning change would be a surprise.
#define INJ_NO_DONOR_SCAN				0x0004	// sponsor-only acquisition; skip the foreign-donor scan
// Bit 0x0008 is retired (was INJ_NO_DIRECT_FALLBACK). Do not reuse: with
// INJ_HANDLE_HIJACKING set, acquisition is now always stealth-only and fails
// closed when no donor qualifies, so there is no direct OpenProcess/OpenThread
// fallback left to disable.
// Bits 0x0010 and 0x0020 are retired (were INJ_SCRAMBLE_DLL_NAME and
// INJ_LOAD_DLL_COPY). Both existed only for the file-path injection entries
// (CoreLoadA/CoreLoadW, since removed): the payload now always arrives as
// caller-owned bytes, so there is no on-disk name to scramble and nothing to
// copy. Do not reuse either bit: a stale caller may still pass it and a silent
// meaning change would be a surprise.
#define INJ_SKIP_SPONSOR_ROUNDTRIP		0x0080	// skip the sponsor alloc/write/read/release proof
// INJ_HANDLE_HIJACKING lives in Core/Foundation/Primitives/InjectionTypes.h.

#define INJ_MM_CLEAN_DATA_DIR			0x00010000	
#define INJ_MM_RESOLVE_IMPORTS			0x00020000	
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00040000	
#define INJ_MM_EXECUTE_TLS				0x00080000	
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000	
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000	
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000	
#define INJ_MM_RUN_DLL_MAIN				0x00800000	
								
#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000	
// Bit 0x02000000 is retired (was INJ_MM_SHIFT_MODULE_BASE). Do not reuse.
#define INJ_MM_MAP_FROM_MEMORY		0x04000000
// Bit 0x08000000 is retired (was INJ_MM_ENABLE_VEH, C++ EH VEH shim). Do not
// reuse: VEH chain entries are the hottest Warden walk surface, so the shim
// was removed entirely. SEH (0x00100000) is inverted table +
// RtlAddFunctionTable + fake dir only, with zero VEH handlers.

// Last handle-acquisition outcome (HijackSource / HijackStats live in
// Core/Foundation/Primitives/InjectionTypes.h, included above).

using f_Memory_Inject = DWORD(__stdcall*)(MEMORY_INJECTIONDATA * pData);

using f_GetSymbolState = DWORD(__stdcall *)();
using f_GetImportState = DWORD(__stdcall *)();
using f_InitializeRuntime = DWORD(__stdcall *)();
using f_ShutdownRuntime = DWORD(__stdcall *)();

using f_StartDownload = void(__stdcall *)();
using f_GetLastHijackStats = void(__stdcall *)(HijackStats * ProcessOut, HijackStats * ThreadOut);
using f_GetLastMapStats = void(__stdcall *)(MAP_STATS * Out);
using f_GetLastStringStats = void(__stdcall *)(STRING_STATS * Out);
using f_GetLastThreadExecStats = void(__stdcall *)(THREAD_EXEC_STATS * Out);


using f_raw_print_callback = void(__stdcall *)(const char * szText);
using f_SetRawPrintCallback = DWORD(__stdcall *)(f_raw_print_callback callback);

// Flat, boundary-safe view of one failure record (exported as CoreLastError).
//
// Why this exists: the runtime appends a full ERROR_INFO to a 16-entry ring on
// every failed injection, and until now nothing read it. The ring's element
// type holds std::wstring members, so it cannot cross the DLL boundary by
// value, and the only trace of the advanced code was a LOG line - which
// compiles to ((void)0) unless AMEGER_KEEP_RUNTIME_LOGS is defined, and that
// macro is defined in no configuration. A shell-stage failure therefore
// reported only its bare INJ_MM_*/SR_HT_* code, with the AdvErrorCode and the
// call-site Line that actually identify the failing syscall unreachable.
//
// This POD is the transport. Deliberately fixed-size char arrays rather than
// strings: the launcher and the runtime must agree on layout, and a
// std::wstring member would not be memcpy-able. The two name fields are
// already basename-redacted by the runtime's error log (no absolute operator
// path), and TargetProcessId/HandleValue are excluded on purpose: they are
// identifying detail with no diagnostic value at the call site.
struct LAST_ERROR_INFO
{
	DWORD	ErrorCode;					// primary INJ_*/SR_*/FILE_* code
	DWORD	AdvErrorCode;				// facility code, GetLastError, or shell NTSTATUS
	int		Line;						// runtime __LINE__ of the failing INIT_ERROR_DATA
	DWORD	Flags;						// flag word the injection ran under
	int		InjectionMode;
	int		LaunchMethod;
	int		bNative;
	wchar_t	DllFileName[MAX_PATH];		// basename only, never a full path
	wchar_t	TargetProcessExeFileName[MAX_PATH];
};
static_assert(sizeof(LAST_ERROR_INFO) % 4 == 0, "LAST_ERROR_INFO must stay 4-byte aligned");

using f_GetLastErrorInfo = DWORD(__stdcall *)(LAST_ERROR_INFO * Out);
DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out);

DWORD __stdcall InitializeRuntime();
DWORD __stdcall ShutdownRuntime();
void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);
void __stdcall GetLastMapStats(MAP_STATS * Out);
void __stdcall GetLastStringStats(STRING_STATS * Out);
void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out);

// Zeroes the telemetry each getter above exposes. Call once at the start of an
// injection: the backing statics are process-wide and are only written on their
// success paths, so without this a run that fails early reports the previous
// run's outcome (e.g. a stale "thread context restored"). String stats are
// excluded - they are filled once at import-resolution time, not per injection.
void ResetHijackStats();
void ResetMapStats();
void ResetThreadExecStats();
