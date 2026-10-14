#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Core/Utility/Binary/PEImage.h"
#include "NT/NTDefinitions.h"

#include "NT/NTFunctions.h"
#include "../../../Injection.h"

#define ALIGN_UP(X, A) ((((ULONG_PTR)(X)) + ((ULONG_PTR)(A) - 1)) & (~(((ULONG_PTR)(A)) - 1)))

#define MAXPATH_IN_TCHAR	(MAX_PATH)

__forceinline PE_IMAGE::OPTIONS BuildPeValidationOptions(DWORD flags)
{
	PE_IMAGE::OPTIONS options;
	options.RequireDll = true;
	options.RequireRelocations = true;
	options.ResolveImports = (flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
	options.ResolveDelayImports = (flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
	options.EnableExceptions = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
	options.InitializeSecurityCookie = (flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
	options.ExecuteTls = (flags & INJ_MM_EXECUTE_TLS) != 0;
	return options;
}

inline HINSTANCE g_hInjMod = NULL;

struct ERROR_INFO

{
	std::wstring	DllFileName;
	std::wstring	TargetProcessExeFileName;
	DWORD			TargetProcessId;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	ULONG_PTR		HandleValue;
	int				bNative;
	int				Line;

	BYTE *	RawData;
	DWORD	RawSize;
};

struct INJECTION_SOURCE
{
	std::wstring DllPath;

	BYTE *	RawData		= nullptr;
	DWORD	RawSize		= 0;
	bool	FromMemory	= false;
};

inline std::wstring	g_RootPathW;

inline DWORD g_OSVersion = 0;
inline DWORD g_OSBuildNumber = 0;

#define g_Windows10_1607 14393
#define g_Windows11_21H2 22000
#define g_Windows11_22H2 22621
#define g_Windows11_23H2 22631
#define g_Windows11_24H2 26100
#define g_Windows11_25H2 26200
#define g_Windows11_26H2 26300

enum class WINDOWS_LAYOUT_FAMILY
{
	Windows11_21H2,
	Windows11_22H2,
	Windows11_24H2,
	Windows11_25H2,
	Windows11_26H2
};

DWORD GetOSVersion(DWORD * error_code = nullptr);

DWORD GetOSBuildVersion();

bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family);

bool FileExistsW(const std::wstring & FilePath);

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine, DWORD flags = 0);

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags = 0);

bool GetOwnModulePathW(std::wstring & out);

bool GetSymbolCacheRoot(std::wstring & out);

// Deletes a symbol cache root previously handed back by GetSymbolCacheRoot. This is a recursive
// delete, so the root is validated against an ownership allowlist first and the call fails closed
// rather than removing anything outside scratch storage. Never pass the injector's own install
// directory here.
bool DeleteSymbolCacheRoot(const std::wstring & root);

// True when "root" is a directory this library created for scratch use and therefore owns. Used by
// the cache teardown paths to make a destructive delete impossible to point at the install folder,
// the Windows directory, or a drive root.
bool IsOwnedScratchRoot(const std::wstring & root);

// Scratch directory name used when the per user cache location is unavailable. It is deliberately a
// subdirectory of the install folder, never the install folder itself, so that cleaning it up can
// never delete the runtime.
#define AMEGER_SCRATCH_LEAF_DIR L".symbols"

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code = nullptr);

// Explicit opt-in that re-enables the direct NtOpenProcess / NtOpenThread fallback when handle
// acquisition finds no donor. It is off by default so the fail-closed path is the shipped behaviour;
// set INJ_ALLOW_DIRECT_FALLBACK=1 to restore the legacy direct open.
bool AllowDirectHandleFallback();

// Opt-out of the only network operation the runtime performs. By default the symbol resolver is
// allowed to fetch the ntdll PDB from the symbol server and caches it, so the second and later runs
// work with no connectivity at all. Set AMEGER_SYMBOL_DOWNLOAD=0 to make an uncached PDB a hard
// error instead, which keeps the runtime from ever opening a socket on a machine that must not make
// outbound connections.
bool SymbolDownloadDisabled();

void ErrorLog(const ERROR_INFO & info);

struct ASYNC_WORKER_SLOT
{
	HANDLE Thread = nullptr;
	HANDLE Done = nullptr;
	DWORD Result = 0;
};

bool StartAsyncWorker(ASYNC_WORKER_SLOT & slot, LPTHREAD_START_ROUTINE entry, void * param);

bool PollAsyncWorker(ASYNC_WORKER_SLOT & slot);

void JoinAsyncWorker(ASYNC_WORKER_SLOT & slot);

// Blocks until the worker thread has actually exited, WITHOUT closing either handle. The Done event
// is signalled by the worker before it finishes unwinding and emitting its trailing telemetry, so a
// caller that only polls Done can observe "complete" while the thread is still logging. JoinAsyncWorker
// would also fix the ordering but consumes the handles, which breaks any later PollAsyncWorker call
// (WaitForSingleObject on a closed handle fails, reading as "not done"). This waits without consuming.
bool WaitAsyncWorkerThread(const ASYNC_WORKER_SLOT & slot);

std::wstring CharArrayToStdWstring(const char * szString);

void __stdcall StartDownload();
