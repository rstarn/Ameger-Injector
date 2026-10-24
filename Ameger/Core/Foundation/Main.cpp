#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Core/Utility/Tools/Tools.h"
#include "Injection/Injection.h"
#include "System/Import/ImportHandler.h"

namespace
{
	// The runtime has exactly one owner at a time. The state below is the
	// arbiter: it moves from uninitialized through initializing to ready,
	// and a shutdown claims it through the shutting-down state so that two
	// concurrent callers can never both run the teardown.
	enum : LONG
	{
		RUNTIME_STATE_UNINITIALIZED = 0,
		RUNTIME_STATE_INITIALIZING = 1,
		RUNTIME_STATE_READY = 2,
		RUNTIME_STATE_FAILED = 3,
		RUNTIME_STATE_SHUT_DOWN = 4
	};

	volatile LONG g_RuntimeInitializationState = 0;

std::wstring g_SymbolCacheRoot;

	void CloseEventHandle(HANDLE & handle)
	{
		if (handle)
		{
			CloseHandle(handle);
			handle = nullptr;
		}
	}

	void CloseRuntimeEvents()
	{
		CloseEventHandle(g_hRunningEvent);
		CloseEventHandle(g_hInterruptEvent);
		CloseEventHandle(g_hInterruptedEvent);
		CloseEventHandle(g_hInterruptImport);
	}

	struct SymbolWorkerParams
	{
		ASYNC_WORKER_SLOT * Slot = nullptr;
		std::wstring ModulePath;
		std::wstring CacheRoot;
	};

	void StopRuntimeWorkers()
	{
		sym_ntdll_native.Interrupt();

		SetEvent(g_hInterruptEvent);
		SetEvent(g_hInterruptImport);

		JoinAsyncWorker(sym_ntdll_native_ret);
		JoinAsyncWorker(import_handler_ret);
	}

	void TeardownRuntime()
	{
		StopRuntimeWorkers();

		sym_ntdll_native.Cleanup();
		sym_parser.Cleanup();
		sym_ntdll_native.PurgePdb();

		DeleteSymbolCacheRoot(g_SymbolCacheRoot);
		g_SymbolCacheRoot.clear();

		CloseRuntimeEvents();

		InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_UNINITIALIZED);
	}

	DWORD WINAPI SymbolWorkerEntry(void * param)
	{
		SymbolWorkerParams * args = static_cast<SymbolWorkerParams *>(param);
		ASYNC_WORKER_SLOT * slot = args ? args->Slot : nullptr;
		if (!args || !slot)
		{
			delete args;
			return SYMBOL_ERR_OBJECT_IS_NULL;
		}

		DWORD result = SYMBOL_ERR_DOWNLOAD_FAILED;
		try
		{
			result = sym_ntdll_native.Initialize(args->ModulePath, args->CacheRoot, false, !SymbolDownloadDisabled());
		}
		catch (...)
		{
			LOG(0, "SymbolWorkerEntry: Unhandled Exception\n");
			result = SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		delete args;
		slot->Result = result;
		SetEvent(slot->Done);
		return result;
	}

	DWORD WINAPI ImportWorkerEntry(void * param)
	{
		ASYNC_WORKER_SLOT * slot = static_cast<ASYNC_WORKER_SLOT *>(param);
		if (!slot)
		{
			return INJ_ERR_NOT_IMPLEMENTED;
		}

		DWORD result = INJ_ERR_IMPORT_HANDLER_NOT_DONE;
		try
		{
			result = ResolveImports(import_handler_error_data);
		}
		catch (...)
		{
			LOG(0, "ImportWorkerEntry: Unhandled Exception\n");
			result = INJ_ERR_UNHANDLED_EXCEPTION;
		}

		slot->Result = result;
		SetEvent(slot->Done);
		return result;
	}

	DWORD RuntimeInitializationFailed(DWORD error_code)
	{
		StopRuntimeWorkers();
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_FAILED);
		return error_code;
	}
}

DWORD __stdcall InitializeRuntime()
{
	EXPORT_FUNCTION("CoreStart", __FUNCDNAME__)

	LONG previous_state = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_INITIALIZING, RUNTIME_STATE_UNINITIALIZED);
	if (previous_state == RUNTIME_STATE_READY)
	{
		return INJ_ERR_SUCCESS;
	}
	if (previous_state == RUNTIME_STATE_INITIALIZING)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}
	if (previous_state == RUNTIME_STATE_SHUT_DOWN)
	{
		// A teardown is still in flight; initializing underneath it would race with
		// the worker threads that teardown is about to join.
		return INJ_ERR_ALREADY_RUNNING;
	}

	// Only a failed runtime may be taken over again. UNINITIALIZED was already
	// claimed above, and every other state is either busy or owned by somebody else.
	bool owns_state = (previous_state == RUNTIME_STATE_UNINITIALIZED);
	if (!owns_state)
	{
		if (previous_state != RUNTIME_STATE_FAILED)
		{
			return INJ_ERR_ALREADY_RUNNING;
		}

		const LONG claimed = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_INITIALIZING, RUNTIME_STATE_FAILED);
		owns_state = (claimed == RUNTIME_STATE_FAILED);
	}

	if (!owns_state)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!GetOSVersion())
	{
		return RuntimeInitializationFailed(INJ_ERR_WINDOWS_VERSION);
	}

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		return RuntimeInitializationFailed(INJ_ERR_WINDOWS_BUILD_UNSUPPORTED);
	}

	if (!GetOwnModulePathW(g_RootPathW))
	{
		LOG(0, "Couldn't Resolve Own Module Path (Unicode)\n");

		return RuntimeInitializationFailed(INJ_ERR_CANT_GET_MODULE_PATH);
	}

	g_hRunningEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptImport = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!g_hRunningEvent || !g_hInterruptEvent || !g_hInterruptedEvent || !g_hInterruptImport)
	{
		LOG(0, "Failed To Create Synchronization Events = %08X\n", GetLastError());

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_EXT);
	}

	wchar_t * windows_directory = nullptr;
	if (_wdupenv_s(&windows_directory, nullptr, XOR_STR_W(L"WINDIR").get()) || !windows_directory)
	{
		LOG(0, "Couldn't Resolve %%WINDIR%%\n");
		return RuntimeInitializationFailed(INJ_ERR_CANT_GET_TEMP_DIR);
	}

	std::wstring native_ntdll_path = windows_directory;
	{
		auto suffix = KC_WSTR(L"\\System32\\ntdll.dll");
		native_ntdll_path += suffix.c_str();
	}
	free(windows_directory);

	std::wstring symbol_cache_root;
	if (!GetSymbolCacheRoot(symbol_cache_root))
	{
		symbol_cache_root = g_RootPathW + AMEGER_SCRATCH_LEAF_DIR + L"\\";

		if (!CreateDirectoryW(symbol_cache_root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(0, "Couldn't Create The Fallback Symbol Cache Directory = %08X\n", GetLastError());
			return RuntimeInitializationFailed(INJ_ERR_CANT_GET_TEMP_DIR);
		}
	}

	g_SymbolCacheRoot = symbol_cache_root;

	SymbolWorkerParams * sym_params = nullptr;
	try
	{
		sym_params = new SymbolWorkerParams{ &sym_ntdll_native_ret, native_ntdll_path, symbol_cache_root };
	}
	catch (...)
	{
		sym_params = nullptr;
	}

	const bool sym_started = sym_params && StartAsyncWorker(sym_ntdll_native_ret, SymbolWorkerEntry, sym_params);
	const bool imp_started = sym_started && StartAsyncWorker(import_handler_ret, ImportWorkerEntry, &import_handler_ret);
	if (!sym_started || !imp_started)
	{
		if (!sym_started)
			delete sym_params;

		LOG(0, "Runtime Initialization Failed While Launching Worker Threads\n");
		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_NEW);
	}

	InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_READY);
	LOG(0, "Runtime Initialization Started\n");

	return INJ_ERR_SUCCESS;
}
DWORD __stdcall ShutdownRuntime()
{
	EXPORT_FUNCTION("CoreStop", __FUNCDNAME__)

	for (int attempt = 0; attempt < 4; ++attempt)
	{
		// Read the state without changing it.
		const LONG state = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_UNINITIALIZED, RUNTIME_STATE_UNINITIALIZED);
		if (state == RUNTIME_STATE_UNINITIALIZED)
		{
			return INJ_ERR_SUCCESS;
		}
		if (state == RUNTIME_STATE_INITIALIZING || state == RUNTIME_STATE_SHUT_DOWN)
		{
			// Either an initialization is still running or another caller already
			// claimed the teardown.
			return INJ_ERR_ALREADY_RUNNING;
		}

		if (state == RUNTIME_STATE_READY && InterlockedCompareExchange(&g_InjectionGate, 0, 0) != 0)
		{
			// An injection is in flight; tearing the runtime down underneath it
			// would pull the symbol and import state out from under it.
			return INJ_ERR_ALREADY_RUNNING;
		}

		// Claim the teardown. SHUT_DOWN marks it as in progress and is only cleared
		// by TeardownRuntime once it has finished, so exactly one caller ever runs
		// the teardown.
		const LONG claimed = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_SHUT_DOWN, state);
		if (claimed != state)
		{
			// Lost the race; re-read and decide again.
			continue;
		}

		try
		{
			TeardownRuntime();
		}
		catch (...)
		{
			InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_FAILED);

			return INJ_ERR_INTERRUPT;
		}

		return INJ_ERR_SUCCESS;
	}

	return INJ_ERR_ALREADY_RUNNING;
}

DWORD __stdcall GetRuntimeAbiVersion()
{
	EXPORT_FUNCTION("CoreAbiVersion", __FUNCDNAME__)

	return AMEGER_RUNTIME_ABI_VERSION;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInjMod = hDll;
		DisableThreadLibraryCalls(hDll);
	}

	return TRUE;
}
