#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Injection/Injection.h"
#include "System/Import/ImportHandler.h"

namespace
{

	// The runtime state machine. Every transition goes through a compare exchange on this value, so a
	// re-entrant or concurrent caller observes one of five stable states rather than a half built one.
	//
	// RUNTIME_STATE_FAILED and RUNTIME_STATE_SHUT_DOWN are deliberately *retryable*: a symbol download
	// that timed out, or a launcher that shut the runtime down and then wants it back, must not leave
	// the host process permanently unable to inject. The previous behaviour latched the failure state
	// (and, worse, left the shut-down state behind after a no-op shutdown), which turned both into a
	// permanent INJ_ERR_NOT_IMPLEMENTED.
	enum : LONG
	{
		RUNTIME_STATE_UNINITIALIZED = 0,
		RUNTIME_STATE_INITIALIZING = 1,
		RUNTIME_STATE_READY = 2,
		RUNTIME_STATE_FAILED = 3,
		RUNTIME_STATE_SHUT_DOWN = 4
	};

	volatile LONG g_RuntimeInitializationState = 0;

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

	// Signals the workers and waits for them, then closes the events. The order matters: a worker that
	// is still running when its event handle is closed would be signing a destroyed object, so the
	// join always happens first. Both calls are idempotent, so this is safe at any construction depth.
	void StopRuntimeWorkers()
	{
		sym_ntdll_native.Interrupt();

		SetEvent(g_hInterruptEvent);
		SetEvent(g_hInterruptImport);

		JoinAsyncWorker(sym_ntdll_native_ret);
		JoinAsyncWorker(import_handler_ret);
	}

	// Full teardown back to the uninitialized state, for a clean shutdown or a retry after a failure.
	void TeardownRuntime()
	{
		StopRuntimeWorkers();

		sym_ntdll_native.Cleanup();
		sym_parser.Cleanup();
		sym_ntdll_native.PurgePdb();

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
			LOG(0, "SymbolWorkerEntry: unhandled exception\n");
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
			LOG(0, "ImportWorkerEntry: unhandled exception\n");
			result = INJ_ERR_UNHANDLED_EXCEPTION;
		}

		slot->Result = result;
		SetEvent(slot->Done);
		return result;
	}

	DWORD RuntimeInitializationFailed(DWORD error_code)
	{
		// A later step can fail after the workers are already running, so they are stopped here rather
		// than only at the launch-failure branch below.
		StopRuntimeWorkers();

		CloseRuntimeEvents();

		// The failure state is retryable: InitializeRuntime claims it again on the next attempt instead
		// of latching the failure for the rest of the host process's lifetime.
		InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_FAILED);

		return error_code;
	}
}

DWORD __stdcall InitializeRuntime()
{
#pragma EXPORT_FUNCTION("CoreStart", __FUNCDNAME__)

	// Claim the uninitialized state. READY and INITIALIZING are reported as they are; FAILED and
	// SHUT_DOWN fall through so a previous attempt can be retried instead of returning a permanent
	// failure.
	const LONG previous_state = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_INITIALIZING, RUNTIME_STATE_UNINITIALIZED);
	if (previous_state == RUNTIME_STATE_READY)
	{
		return INJ_ERR_SUCCESS;
	}
	if (previous_state == RUNTIME_STATE_INITIALIZING)
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
		LOG(0, "Couldn't resolve own module path (unicode)\n");

		return RuntimeInitializationFailed(INJ_ERR_CANT_GET_MODULE_PATH);
	}

	g_hRunningEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	g_hInterruptImport = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	if (!g_hRunningEvent || !g_hInterruptEvent || !g_hInterruptedEvent || !g_hInterruptImport)
	{
		LOG(0, "Failed to create synchronization events: %08X\n", GetLastError());

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_EXT);
	}

	wchar_t * windows_directory = nullptr;
	if (_wdupenv_s(&windows_directory, nullptr, XOR_STR_W(L"WINDIR").get()) || !windows_directory)
	{
		LOG(0, "Couldn't resolve %%WINDIR%%\n");

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
		// The per user cache location was unavailable, so scratch storage moves into a dedicated
		// subdirectory of the install folder. It must be a subdirectory: DeleteSymbolCacheRoot does a
		// recursive delete, and handing it the install folder itself would take the runtime, the
		// payload and the launcher with it.
		symbol_cache_root = g_RootPathW + AMEGER_SCRATCH_LEAF_DIR + L"\\";

		if (!CreateDirectoryW(symbol_cache_root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(0, "Couldn't create the fallback symbol cache directory: %08X\n", GetLastError());

			return RuntimeInitializationFailed(INJ_ERR_CANT_GET_TEMP_DIR);
		}
	}

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
		{
			delete sym_params;
		}

		LOG(0, "Runtime initialization failed while launching worker threads\n");

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_NEW);
	}

	InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_READY);
	LOG(0, "Runtime initialization started\n");

	return INJ_ERR_SUCCESS;
}

DWORD __stdcall ShutdownRuntime()
{
#pragma EXPORT_FUNCTION("CoreStop", __FUNCDNAME__)

	// Read the state without publishing anything. A state of UNINITIALIZED or SHUT_DOWN is already
	// idle, so a redundant shutdown is a no-op that leaves the state alone rather than overwriting it.
	const LONG state = InterlockedCompareExchange(&g_RuntimeInitializationState, RUNTIME_STATE_UNINITIALIZED, RUNTIME_STATE_UNINITIALIZED);
	if (state == RUNTIME_STATE_UNINITIALIZED || state == RUNTIME_STATE_SHUT_DOWN)
	{
		return INJ_ERR_SUCCESS;
	}

	if (state == RUNTIME_STATE_INITIALIZING)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}

	if (state == RUNTIME_STATE_READY && InterlockedCompareExchange(&g_InjectionGate, 0, 0) != 0)
	{
		// A load is in flight; leave the state to the gate owner.
		return INJ_ERR_ALREADY_RUNNING;
	}

	// RUNTIME_STATE_READY and RUNTIME_STATE_FAILED both tear down through the same path. A failed init
	// can leave a partially constructed worker set behind, so the teardown has to be unconditional.
	try
	{
		TeardownRuntime();
	}
	catch (...)
	{
		// The runtime is left in the retryable failure state rather than wedged, so the caller can
		// simply call InitializeRuntime again instead of the whole host being poisoned.
		InterlockedExchange(&g_RuntimeInitializationState, RUNTIME_STATE_FAILED);

		return INJ_ERR_INTERRUPT;
	}

	return INJ_ERR_SUCCESS;
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
