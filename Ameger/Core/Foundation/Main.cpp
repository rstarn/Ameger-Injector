#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Injection/Injection.h"
#include "System/Import/ImportHandler.h"

namespace
{

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

	DWORD RuntimeInitializationFailed(DWORD error_code)
	{
		CloseRuntimeEvents();
		InterlockedExchange(&g_RuntimeInitializationState, 3);

		return error_code;
	}
}

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

		auto suffix = KC_WSTR(L"\\System32\\ntdll.dll");
		native_ntdll_path += suffix.c_str();
	}
	free(windows_directory);

	std::wstring symbol_cache_root;
	if (!GetSymbolCacheRoot(symbol_cache_root))
	{
		symbol_cache_root = g_RootPathW;
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

		return INJ_ERR_ALREADY_RUNNING;
	}
	if (state == 4)
	{
		return INJ_ERR_SUCCESS;
	}
	if (state == 3)
	{

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

	sym_ntdll_native.PurgePdb();
	CloseRuntimeEvents();

	InterlockedExchange(&g_RuntimeInitializationState, 4);

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
