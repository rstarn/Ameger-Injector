#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Injection/Injection.h"
#include "System/Import/ImportHandler.h"

// Runtime DLL entry and lifecycle (CoreStart/CoreStop exports).
// What: owns the one-time process-wide init gate, the four control events,
//   and the async symbol/import workers. Why: every injection needs OS-layout
//   checks, a module path, and downloaded PDB/import state before touching a
//   target. How: InitializeRuntime moves g_RuntimeInitializationState
//   0->1->2 (failed runs land on 3, shut down on 4); ShutdownRuntime joins
//   the workers and closes the events. Depends on Injection.h (events/gates),
//   ImportHandler (ResolveImports), and the symbol loader.
namespace
{
	// Lifecycle state: 0 = never started, 1 = start in progress (re-entrancy
	// guard), 2 = running, 3 = a previous start failed, 4 = shut down.
	// Accessed only via Interlocked* so the export/UI thread and the workers
	// never race.
	volatile LONG g_RuntimeInitializationState = 0;

	// Closes one control event and nulls the caller's handle. Skips null so
	// repeated shutdown/failure paths stay idempotent. Params: handle (in/out
	// event to close). No return; never throws.
	void CloseEventHandle(HANDLE & handle)
	{
		if (handle)
		{
			CloseHandle(handle);
			handle = nullptr;
		}
	}

	// Closes all four lifecycle events. Called on init failure and on clean
	// shutdown; safe to call twice because CloseEventHandle nulls each slot.
	void CloseRuntimeEvents()
	{
		CloseEventHandle(g_hRunningEvent);
		CloseEventHandle(g_hInterruptEvent);
		CloseEventHandle(g_hInterruptedEvent);
		CloseEventHandle(g_hInterruptImport);
	}

	// Worker start parameters. Heap-owned: the thread takes ownership on a
	// successful start and deletes it; on a start failure the caller retains
	// it. Plain POD with wstrings - no templates, no member pointers, so no
	// mangled tool names reach .rdata (the whole reason std::async is gone).
	struct SymbolWorkerParams
	{
		ASYNC_WORKER_SLOT * Slot = nullptr;
		std::wstring ModulePath;
		std::wstring CacheRoot;
	};

	// Symbol-download worker entry. Free function taking void* (never a
	// template or member pointer) so its instantiation emits no tool-specific
	// RTTI. Reports through the slot and frees the params; an escaping
	// exception becomes a download failure rather than a terminate.
	DWORD WINAPI SymbolWorkerEntry(void * param)
	{
		SymbolWorkerParams * args = static_cast<SymbolWorkerParams *>(param);
		ASYNC_WORKER_SLOT * slot = args ? args->Slot : nullptr;
		if (!args || !slot)
		{
			delete args; // safe on null; slot-less start has nothing to report to
			return SYMBOL_ERR_OBJECT_IS_NULL;
		}

		DWORD result = SYMBOL_ERR_DOWNLOAD_FAILED;
		try
		{
			result = sym_ntdll_native.Initialize(args->ModulePath, args->CacheRoot, false, true);
		}
		catch (...)
		{
			result = SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		delete args;
		slot->Result = result;
		SetEvent(slot->Done);
		return result;
	}

	// Import-resolution worker entry. Same contract as above; the global error
	// record is passed by the callee itself, so the param is the slot alone.
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
			result = INJ_ERR_UNHANDLED_EXCEPTION;
		}

		slot->Result = result;
		SetEvent(slot->Done);
		return result;
	}

	// Shared failure exit for InitializeRuntime. What: tears down events and
	// parks the state on 3 (failed) so later calls return NOT_IMPLEMENTED
	// instead of retrying half-built state. Params: error_code (facility code
	// to propagate). Returns: the same code.
	DWORD RuntimeInitializationFailed(DWORD error_code)
	{
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, 3);

		return error_code;
	}
}

// One-time runtime startup (exported as CoreStart). What: validates the OS,
// resolves the module/symbol-cache paths, creates control events, and launches
// the async PDB + import workers. Side effects: sets state 0->1->2 (or 3 on
// failure), creates four manual-reset events. Returns: INJ_ERR_SUCCESS,
// ALREADY_RUNNING (start in progress), NOT_IMPLEMENTED (failed/shut down
// state), or the specific init failure code. Thread-safe via the state gate.
DWORD __stdcall InitializeRuntime()
{
#pragma EXPORT_FUNCTION("CoreStart", __FUNCDNAME__)

	const LONG previous_state = InterlockedCompareExchange(&g_RuntimeInitializationState, 1, 0);
	if (previous_state == 2)
	{
		return INJ_ERR_SUCCESS;
	}
	if (previous_state == 1)
	{
		return INJ_ERR_ALREADY_RUNNING;
	}
	if (previous_state != 0)
	{
		return INJ_ERR_NOT_IMPLEMENTED;
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
		// Raw L"\\System32\\ntdll.dll" here survived into .rdata as UTF-16 and
		// tripped the 'ntdll.dll' marker in the interface gate. KC_WSTR is the
		// block-scoped expression form, so it introduces no name to collide.
		auto suffix = KC_WSTR(L"\\System32\\ntdll.dll");
		native_ntdll_path += suffix.c_str();
	}
	free(windows_directory);

	// Symbol cache lives in a neutral per-user directory, never beside the
	// runtime DLL: a large ntdll.pdb next to the injector is a loud artifact.
	std::wstring symbol_cache_root;
	if (!GetSymbolCacheRoot(symbol_cache_root))
	{
		symbol_cache_root = g_RootPathW;   // fall back to the module directory
	}

	// Worker start parameters (see the file-scope SymbolWorkerParams above).
	// Heap-owned with thread-takes-ownership-on-success semantics.
	SymbolWorkerParams * sym_params = nullptr;
	try
	{
		sym_params = new SymbolWorkerParams{ &sym_ntdll_native_ret, native_ntdll_path, symbol_cache_root };
	}
	catch (...)
	{
		sym_params = nullptr;
	}

	// Start the symbol worker first: the import worker blocks on it, so a
	// half-started state (symbol running, import refused) must interrupt and
	// join the symbol worker rather than orphan it. JoinAsyncWorker is safe on
	// a never-started slot, so both joins run unconditionally below.
	const bool sym_started = sym_params && StartAsyncWorker(sym_ntdll_native_ret, SymbolWorkerEntry, sym_params);
	const bool imp_started = sym_started && StartAsyncWorker(import_handler_ret, ImportWorkerEntry, &import_handler_ret);
	if (!sym_started || !imp_started)
	{
		// Ownership rule: only a successful Start transfers sym_params to the
		// thread. If sym never started, free it here; if sym started (but imp
		// failed), the running thread owns and frees it - touching it here
		// would double-free.
		if (!sym_started)
		{
			delete sym_params;
		}

		LOG(0, "Runtime initialization failed while launching worker threads\n");

		sym_ntdll_native.Interrupt();
		SetEvent(g_hInterruptEvent);
		SetEvent(g_hInterruptImport);

		JoinAsyncWorker(sym_ntdll_native_ret);
		JoinAsyncWorker(import_handler_ret);

		return RuntimeInitializationFailed(INJ_ERR_OUT_OF_MEMORY_NEW);
	}

	InterlockedExchange(&g_RuntimeInitializationState, 2);
	LOG(0, "Runtime initialization started\n");

	return INJ_ERR_SUCCESS;
}

// Graceful teardown (exported as CoreStop). What: interrupts the workers,
// waits for them, releases symbol state, and closes events. Safe to call on
// a never-started (0), failed (3), or already-shut (4) runtime; refuses while
// an injection is gated. Returns: SUCCESS, ALREADY_RUNNING (busy), or
// INTERRUPT when a worker wait throws. Side effects: state ends on 4.
DWORD __stdcall ShutdownRuntime()
{
#pragma EXPORT_FUNCTION("CoreStop", __FUNCDNAME__)

	const LONG state = InterlockedCompareExchange(&g_RuntimeInitializationState, 1, 0);
	if (state == 0)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 4);

		return INJ_ERR_SUCCESS;
	}
	if (state == 1)
	{
		// A start is in progress. No write is needed here, and none should be
		// made: the CAS above only writes when the comparand matched (state was
		// 0), so reaching this branch means the exchange did NOT happen and the
		// state is still 1 - which is exactly what InitializeRuntime is about
		// to CAS forward to 2. Restoring 0 would let a ShutdownRuntime arriving
		// during the start window see a never-started runtime and park it at 4
		// while InitializeRuntime is still running.
		return INJ_ERR_ALREADY_RUNNING;
	}
	if (state == 4)
	{
		return INJ_ERR_SUCCESS;
	}
	if (state == 3)
	{
		// A previous start failed: still reclaim whatever artifacts it
		// produced (PDB bytes on disk in particular) before parking the
		// runtime at 4, otherwise a cancelled/failed init leaves the
		// timestamped ntdll.pdb behind. Cleanup() unmaps any partial map;
		// PurgePdb no-ops when nothing was downloaded.
		sym_ntdll_native.Cleanup();
		sym_parser.Cleanup();
		sym_ntdll_native.PurgePdb();
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, 4);

		return INJ_ERR_SUCCESS;
	}
	if (state != 2 || InterlockedCompareExchange(&g_InjectionGate, 0, 0) != 0)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 2);

		return INJ_ERR_ALREADY_RUNNING;
	}

	sym_ntdll_native.Interrupt();
	SetEvent(g_hInterruptEvent);
	SetEvent(g_hInterruptImport);

	try
	{
		// JoinAsyncWorker is safe on a never-started slot, so no validity
		// check is needed (and a validity check would itself race a
		// concurrent start, which the gate above already excludes).
		JoinAsyncWorker(sym_ntdll_native_ret);
		JoinAsyncWorker(import_handler_ret);
	}
	catch (...)
	{
		InterlockedExchange(&g_RuntimeInitializationState, 2);

		return INJ_ERR_INTERRUPT;
	}

	sym_ntdll_native.Cleanup();
	sym_parser.Cleanup();
	// Reclaim the cached PDB on every teardown, not only when ResolveImports
	// reached its purge site: a cancel/target-timeout fails earlier and used
	// to leave the multi-megabyte file behind as a timestamped artifact.
	// PurgePdb no-ops when nothing was downloaded.
	sym_ntdll_native.PurgePdb();
	CloseRuntimeEvents();

	InterlockedExchange(&g_RuntimeInitializationState, 4);

	return INJ_ERR_SUCCESS;
}

// Standard DLL entry. Params: hDll (module base, cached to g_hInjMod on
// attach), dwReason (only PROCESS_ATTACH is acted on), pReserved (unused).
// Disables thread notifications to keep Warden-visible loader traffic minimal.
// Returns TRUE always; see the note below on detach semantics.
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)
{
	UNREFERENCED_PARAMETER(pReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		g_hInjMod = hDll;
		DisableThreadLibraryCalls(hDll);
	}

	// Unloading this module cannot be blocked from DllMain: the loader ignores
	// the return value for DLL_PROCESS_DETACH (and DisableThreadLibraryCalls
	// above suppresses the DLL_THREAD_* notifications). The interface avoids
	// the situation rather than fighting it - it never calls FreeLibrary on the
	// runtime; it shuts the workers down and exits the process
	// (TerminateProcess), so the module is torn down with the address space.
	return TRUE;
}
