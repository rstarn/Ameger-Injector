#pragma once

#include <Windows.h>
#include "Core/Foundation/Primitives/InjectionTypes.h"

struct MEMORY_INJECTIONDATA
{
	BYTE * RawData;
	DWORD RawSize;
	DWORD ProcessID;
	DWORD Flags;
	DWORD Timeout;
	ULONG_PTR hHandleValue;
	HINSTANCE hDllOut;
	bool GenerateErrorLog;
	DWORD TargetTid;
	ULONG_PTR hThreadHandleValue;
	const wchar_t * DllPath;
};

#define INJ_ERASE_HEADER				0x0001

#define INJ_NO_DONOR_SCAN				0x0004

#define INJ_SKIP_SPONSOR_ROUNDTRIP		0x0080

#define INJ_MM_CLEAN_DATA_DIR			0x00010000
#define INJ_MM_RESOLVE_IMPORTS			0x00020000
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00040000
#define INJ_MM_EXECUTE_TLS				0x00080000
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000
#define INJ_MM_RUN_DLL_MAIN				0x00800000

#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000

#define INJ_MM_MAP_FROM_MEMORY		0x04000000

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

struct LAST_ERROR_INFO
{
	DWORD	ErrorCode;
	DWORD	AdvErrorCode;
	int		Line;
	DWORD	Flags;
	int		bNative;
	wchar_t	DllFileName[MAX_PATH];
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

void ResetHijackStats();
void ResetMapStats();
void ResetThreadExecStats();
