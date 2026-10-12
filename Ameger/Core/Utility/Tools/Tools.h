#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Core/Utility/Binary/PEImage.h"
#include "NT/NTDefinitions.h"

#include "NT/NTFunctions.h"
#include "Injection.h"

// Shared host utilities: OS version/layout probes, PE validation entry
// points, path helpers, and the error-log record. What: the small functions
// every stage (init, validate, inject) needs. Why one header: BuildFlags and
// BuildPeValidationOptions must agree between launcher and shell, so the flag
// interpretation lives here, not duplicated per caller.
// Rounds X up to a multiple of A (A must be a power of two). Used for page
// staging layout. Params: X (value), A (alignment). Returns: aligned value.
#define ALIGN_UP(X, A) ((((ULONG_PTR)(X)) + ((ULONG_PTR)(A) - 1)) & (~(((ULONG_PTR)(A)) - 1)))

// TCHAR-path capacity alias; equals MAX_PATH. Kept so path buffers read
// uniformly regardless of UNICODE.
#define MAXPATH_IN_TCHAR	(MAX_PATH)

// Single source of truth for the PE-validation options implied by the INJ_MM_*
// flags. Both the host (ValidateDllFile*) and the in-target map shell
// (MMI_MapSections) derive their options from the same flags; sharing this
// keeps the two from drifting. Header-inline so it folds into the shell
// section, which cannot call host code.
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

// This runtime DLL's own module base, cached in DllMain on PROCESS_ATTACH.
// Used to resolve own path for the symbol-cache fallback.
inline HINSTANCE g_hInjMod = NULL;

// Failure snapshot written to the error log. What: one record per failed
// injection with the DLL/target identity, mode/method/flags, codes, and the
// source line. Consumed by ErrorLog(); never sent to the target.
struct ERROR_INFO
	
{
	std::wstring	DllFileName;
	std::wstring	TargetProcessExeFileName;
	DWORD			TargetProcessId;
	INJECTION_MODE	InjectionMode;
	LAUNCH_METHOD	LaunchMethod;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	ULONG_PTR		HandleValue;
	int				bNative;
	std::wstring	SourceFile;
	std::wstring	FunctionName;
	int				Line;

	
	BYTE *	RawData;
	DWORD	RawSize;
};

// Payload source: either a file path or an in-memory image. What: the host
// fills one side; ManualMap prefers the memory side (LoadFromMemory). Fields:
// DllPath (source file when !FromMemory), RawData/RawSize (image bytes when
// FromMemory), FromMemory (which side is valid).
struct INJECTION_SOURCE
{
	std::wstring DllPath;

	BYTE *	RawData		= nullptr;
	DWORD	RawSize		= 0;
	bool	FromMemory	= false;
};

// Own module directory (with trailing slash), resolved once at init. Used for
// cache-path fallbacks when the neutral %LOCALAPPDATA% root is unavailable.
inline std::wstring	g_RootPathW;

// Cached OS version and build number, filled once by GetOSVersion().
// g_OSVersion is packed as (major * 100 + minor): Windows 10/11 => 1000,
// Windows 8.1 => 602, Windows 7 => 601. Not an ordering key against the build
// numbers below - g_OSBuildNumber is that, and GetSupportedWindowsLayout uses
// it exclusively. Nothing compares g_OSVersion today; it exists so a caller
// can log or reject on a major/minor pair without re-probing the OS.
inline DWORD g_OSVersion = 0;
inline DWORD g_OSBuildNumber = 0;

// Build-number constants. They label a Windows build for logging/version
// display only; none of the Windows 10 (or earlier) values can be selected as
// a runtime layout - the entry gate rejects every build below 22000 (Win11
// 21H2), so GetSupportedWindowsLayout always resolves to a Win11 family.
#define g_Windows10_1607 14393
#define g_Windows11_21H2 22000
#define g_Windows11_22H2 22621
#define g_Windows11_23H2 22631
#define g_Windows11_24H2 26100
#define g_Windows11_25H2 26200

enum class WINDOWS_LAYOUT_FAMILY
{
	Windows11_21H2,
	Windows11_22H2,
	Windows11_24H2,
	Windows11_25H2
};

// Probes the OS version. Params: error_code (optional out detail). Returns:
// the packed major*100 + minor version (see the g_OSVersion note), or 0 on
// failure. Caches to g_OSVersion and g_OSBuildNumber; zero g_OSVersion is the
// "not probed / probe failed" sentinel, so do not treat it as a version.
DWORD GetOSVersion(DWORD * error_code = nullptr);

// Returns the cached build number (e.g. 26100). Must run after GetOSVersion.
DWORD GetOSBuildVersion();

// Maps a build number to a supported layout family. Params: build_number
// (in), layout_family (out family for PDB offsets). Returns: true when the
// build is Win11 21H2+ (else false, caller fails closed).
bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family);

// True when a file exists at FilePath (non-directory). Params: FilePath (in).
bool FileExistsW(const std::wstring & FilePath);

// Validates an on-disk DLL for mapping. Params: FilePath (in), target_machine
// (IMAGE_FILE_MACHINE_*), flags (INJ_MM_* driving BuildPeValidationOptions).
// Returns: FILE_ERR_* code (SUCCESS = loadable).
DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine, DWORD flags = 0);

// Validates an in-memory image. Params/returns mirror ValidateDllFile but over
// a byte range instead of a path.
DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags = 0);

// Resolves this module's directory into out (with trailing slash). Returns:
// true on success. Used once at init.
bool GetOwnModulePathW(std::wstring & out);

// Per-run cache root for the downloaded ntdll PDB. Deliberately NOT the
// module's own directory: a multi-megabyte ntdll.pdb appearing next to the
// injector is a loud, timestamped on-disk artifact. The leaf is drawn from the
// OS CSPRNG on every call, so a completed run leaves nothing an earlier run has
// already left behind and nothing an observer can look for by name. Call
// DeleteSymbolCacheRoot with the returned path to remove the tree again.
// Params: out (root, with trailing slash). Returns: true on success.
bool GetSymbolCacheRoot(std::wstring & out);

// Removes the tree GetSymbolCacheRoot created, including the PDB and the
// Symbols directory. Best effort: a failure leaves a random, uninteresting
// directory behind rather than failing the caller. Params: root (as returned).
void DeleteSymbolCacheRoot(const std::wstring & root);

// True when the target is a native 64-bit process (not WOW64). Params:
// hTargetProc (in handle), error_code (optional out). Used to refuse x86
// targets early in this x64-only build.
bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code = nullptr);

// Appends one ERROR_INFO record to the error log. Params: info (in snapshot).
// Only the exportable fields are retained (codes, mode/method/flags and the
// basename-redacted DLL/target names); PID, handle value, source names and the
// payload pointer are never stored, so neither the ring nor a crash dump of
// this process can surface them. Best-effort; never throws into the injection
// path.
void ErrorLog(const ERROR_INFO & info);

// Drains the newest error-ring record (exported as CoreLastError). What: this
// is the reader the ring above was written for - see LAST_ERROR_INFO in
// Injection.h for why it did not exist before and what the flat POD buys.
//
// Params: Out (out: receives the record; null is rejected). Returns:
// INJ_ERR_SUCCESS when a record was produced, INJ_ERR_NOT_IMPLEMENTED when the
// ring is empty (nothing has failed yet, or every failure so far ran with
// GenerateErrorLog set false), INJ_ERR_NO_DATA for a null Out.
DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out);

// Manual async-worker slot replacing std::shared_future<DWORD>.
//
// Why not std::async: instantiating std::async/std::future over our callables
// bakes tool-specific mangled names into plaintext RTTI (.?AV lambdas naming
// InitializeRuntime, adapters naming ERROR_DATA) plus the Concurrency PPL
// task type table - none of which the string-encryption gate covers (it gates
// ntdll symbol names, not STL internals). A raw thread + event carries no type
// names: the entry is a free function taking void*, the result is a DWORD.
// Same lifecycle as the future it replaces (start once, poll without blocking,
// join on shutdown). An exception escaping the worker is caught at the thread
// boundary and stored as a failure code instead of terminating the process
// (std::async would have captured it for a later .get() rethrow).
//
// Synchronization: Result is stored before Done is signaled (release), and
// Poll observes Done via WaitForSingleObject (acquire), so a ready poll
// implies a valid Result. Start stores Done before creating the thread, so a
// fast worker can never signal a null event.
struct ASYNC_WORKER_SLOT
{
	HANDLE Thread = nullptr;	// worker thread, null when never started
	HANDLE Done = nullptr;		// manual-reset, signaled once Result is final
	DWORD Result = 0;			// worker code, valid once Done is signaled
};

// Starts a worker thread running entry(param). Params: slot (out, reset
// first), entry (free function, must not be a template/member-pointer or the
// names return), param (owned per the entry's contract: on success the thread
// owns it, on failure the caller retains it). Returns false when the event or
// thread could not be created (slot left empty).
bool StartAsyncWorker(ASYNC_WORKER_SLOT & slot, LPTHREAD_START_ROUTINE entry, void * param);

// True when StartAsyncWorker succeeded (a thread exists to join).
bool AsyncWorkerStarted(const ASYNC_WORKER_SLOT & slot);

// True when the worker finished (Result valid). Never blocks.
bool PollAsyncWorker(ASYNC_WORKER_SLOT & slot);

// Blocks until the worker finishes, then releases its handles. Safe on a
// never-started slot (no-op).
void JoinAsyncWorker(ASYNC_WORKER_SLOT & slot);

// Converts a narrow null-terminated string to wstring. Params: szString (in,
// may be null -> empty). Returns: converted text.
std::wstring CharArrayToStdWstring(const char * szString);

// Kicks the async symbol/import workers (exported as CoreFetch). No params;
// pairs with InitializeRuntime's futures. Safe to call once workers exist.
void __stdcall StartDownload();

