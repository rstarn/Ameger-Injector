#pragma once

#include "NT/NTFunctions.h"
#include "System/Symbol/Parser/SymbolParser.h"
#include "Core/Utility/Tools/Tools.h"

// Lifecycle events (created by InitializeRuntime, signaled on shutdown):
// g_hRunningEvent (set once workers start), g_hInterruptEvent (abort hijack
// waits), g_hInterruptedEvent (hijack acknowledged the abort),
// g_hInterruptImport (abort the import resolve). g_InjectionGate is 0 when
// idle, 1 while Inject_Internal runs (second attempts refuse with
// ALREADY_RUNNING). import_handler_* carry the async ResolveImports outcome.
inline HANDLE g_hRunningEvent		= nullptr;
inline volatile LONG g_InjectionGate	= 0;
inline HANDLE g_hInterruptEvent		= nullptr;
inline HANDLE g_hInterruptedEvent	= nullptr;
inline HANDLE g_hInterruptImport	= nullptr;

inline ERROR_DATA					import_handler_error_data;
inline ASYNC_WORKER_SLOT			import_handler_ret;

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_FUNC_LOCAL(func) f_##func func
#define NT_FUNC_CONSTRUCTOR_INIT(func) this->func = NATIVE::func

#define WIN32_FUNC(func) inline decltype(func) * p##func = nullptr
// Loader names are compile-time XORed: ciphertext in .rdata, plaintext
// only on the stack for the duration of the call (see KcStrings/Core/XorString.h).
#define WIN32_FUNC_INIT(func, lib) NATIVE::p##func = ReCa<decltype(func) *>(GetProcAddress(lib, XOR_STR_A(#func).get()));

namespace NATIVE
{
	WIN32_FUNC(GetModuleHandleW);

	WIN32_FUNC(GetProcAddress);

	WIN32_FUNC(GetLastError);

	NT_FUNC(LdrUnloadDll);

	NT_FUNC(LdrpLoadDllInternal);

	NT_FUNC(LdrGetProcedureAddress);

	NT_FUNC(LdrpPreprocessDllName);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(RtlLookupFunctionEntry);
	NT_FUNC(LdrpHandleTlsData);

	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	NT_FUNC(LdrpDereferenceModule);

	NT_FUNC(memmove);
	NT_FUNC(RtlZeroMemory);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(RtlFreeHeap);

	NT_FUNC(RtlAnsiStringToUnicodeString);

	NT_FUNC(NtClose);

	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(NtProtectVirtualMemory);

	NT_FUNC(LdrProtectMrdata);

	NT_FUNC(NtDelayExecution);

	NT_FUNC(LdrpHeap);
	NT_FUNC(LdrpInvertedFunctionTable);
	NT_FUNC(LdrpTlsList);

	NT_FUNC(RtlAddFunctionTable);

	// Optional: only MMI_CleanUp consumes this. It must not be required, so
	// it is deliberately absent from MANUAL_MAPPING_FUNCTION_TABLE::IsValid().
	NT_FUNC(RtlDeleteFunctionTable);
}

// Resolves every encrypted NT import into NATIVE::* (async worker). What:
// decrypts each XOR/KC name on the stack, GetProcAddress-es it, and runs the
// tier self-test. Params: error_data (out detail on failure). Returns:
// INJ_ERR_SUCCESS, IMPORT_HANDLER_NOT_DONE while running, or the failure
// code. Aborts early when g_hInterruptImport is set. Fills STRING_STATS.
DWORD ResolveImports(ERROR_DATA & error_data);

// Copies the measured string-tier counters for the UI. Params: Out (out, may
// be null to skip). Exported for the interface, which reports the measured
// values rather than hardcoded ones (see STRING_STATS in InjectionTypes.h).
void __stdcall GetLastStringStats(STRING_STATS * Out);