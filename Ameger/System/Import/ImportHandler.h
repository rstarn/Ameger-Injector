#pragma once

#include "NT/NTFunctions.h"
#include "System/Symbol/Parser/SymbolParser.h"
#include "Core/Utility/Tools/Tools.h"

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

namespace NATIVE
{
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

	NT_FUNC(LdrpHeap);
	NT_FUNC(LdrpInvertedFunctionTable);
	NT_FUNC(LdrpTlsList);

	NT_FUNC(RtlAddFunctionTable);

	NT_FUNC(RtlDeleteFunctionTable);
}

DWORD ResolveImports(ERROR_DATA & error_data);

void __stdcall GetLastStringStats(STRING_STATS * Out);
