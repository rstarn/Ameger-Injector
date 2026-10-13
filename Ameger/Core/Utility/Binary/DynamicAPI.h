#pragma once

#include <Windows.h>
#include <wininet.h>
#include <DbgHelp.h>
#include <utility>
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"

#ifndef _WIN64
#error This build is x64-only.
#endif

namespace dyn
{

	struct VARIANT_INT
	{
		WORD	vt;
		WORD	wReserved1;
		WORD	wReserved2;
		WORD	wReserved3;
		union
		{
			LONGLONG	llVal;
			ULONGLONG	ullVal;
			LONG		lVal;
			ULONG		ulVal;
			BYTE		bVal;
			SHORT		iVal;
			USHORT		uiVal;
			INT			intVal;
			UINT		uintVal;
		};
	};

	using Fn_SymInitialize		= BOOL(__stdcall *)(HANDLE, PCSTR, BOOL);
	using Fn_SymCleanup			= BOOL(__stdcall *)(HANDLE);
	using Fn_SymSetOptions		= DWORD(__stdcall *)(DWORD);
	using Fn_SymLoadModuleEx	= DWORD64(__stdcall *)(HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD, PVOID, DWORD);
	using Fn_SymUnloadModule64	= BOOL(__stdcall *)(HANDLE, DWORD64);
	using Fn_SymFromName		= BOOL(__stdcall *)(HANDLE, PCSTR, PVOID);
	using Fn_SymGetTypeFromName	= BOOL(__stdcall *)(HANDLE, ULONG64, PCSTR, PVOID);
	using Fn_SymGetTypeInfo		= BOOL(__stdcall *)(HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID);

	struct DbgHelpTable
	{
		Fn_SymInitialize		SymInitialize		= nullptr;
		Fn_SymCleanup			SymCleanup			= nullptr;
		Fn_SymSetOptions		SymSetOptions		= nullptr;
		Fn_SymLoadModuleEx		SymLoadModuleEx		= nullptr;
		Fn_SymUnloadModule64	SymUnloadModule64	= nullptr;
		Fn_SymFromName			SymFromName			= nullptr;
		Fn_SymGetTypeFromName	SymGetTypeFromName	= nullptr;
		Fn_SymGetTypeInfo		SymGetTypeInfo		= nullptr;
	};

	inline bool LoadDbgHelp(DbgHelpTable & table, HMODULE & module)
	{

		static const char * const kExports[] = {
			"SymInitialize",
			"SymCleanup",
			"SymSetOptions",
			"SymLoadModuleEx",
			"SymUnloadModule64",
			"SymFromName",
			"SymGetTypeFromName",
			"SymGetTypeInfo",
		};

		FARPROC resolved[_countof(kExports)]{};

		auto module_name = XOR_STR_W(L"dbghelp.dll");
		HMODULE loaded = LoadLibraryW(module_name.get());
		if (!loaded)
		{
			return false;
		}

		for (size_t i = 0; i < _countof(kExports); ++i)
		{
			FARPROC proc = GetProcAddress(loaded, kExports[i]);
			if (!proc)
			{
				FreeLibrary(loaded);

				return false;
			}

			resolved[i] = proc;
		}

		table.SymInitialize		= reinterpret_cast<Fn_SymInitialize>(resolved[0]);
		table.SymCleanup			= reinterpret_cast<Fn_SymCleanup>(resolved[1]);
		table.SymSetOptions		= reinterpret_cast<Fn_SymSetOptions>(resolved[2]);
		table.SymLoadModuleEx		= reinterpret_cast<Fn_SymLoadModuleEx>(resolved[3]);
		table.SymUnloadModule64	= reinterpret_cast<Fn_SymUnloadModule64>(resolved[4]);
		table.SymFromName		= reinterpret_cast<Fn_SymFromName>(resolved[5]);
		table.SymGetTypeFromName	= reinterpret_cast<Fn_SymGetTypeFromName>(resolved[6]);
		table.SymGetTypeInfo		= reinterpret_cast<Fn_SymGetTypeInfo>(resolved[7]);

		module = loaded;

		return true;
	}

	using Fn_InternetOpenW			= HINTERNET(__stdcall *)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
	using Fn_InternetSetOptionW	= BOOL(__stdcall *)(HINTERNET, DWORD, LPVOID, DWORD);
	using Fn_InternetQueryOptionW	= BOOL(__stdcall *)(HINTERNET, DWORD, LPVOID, LPDWORD);
	using Fn_InternetOpenUrlW		= HINTERNET(__stdcall *)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
	using Fn_InternetReadFile		= BOOL(__stdcall *)(HINTERNET, LPVOID, DWORD, LPDWORD);
	using Fn_InternetCloseHandle	= BOOL(__stdcall *)(HINTERNET);

	struct WinInetTable
	{
		Fn_InternetOpenW			InternetOpenW		= nullptr;
		Fn_InternetSetOptionW	InternetSetOptionW	= nullptr;
		Fn_InternetQueryOptionW	InternetQueryOptionW	= nullptr;
		Fn_InternetOpenUrlW		InternetOpenUrlW	= nullptr;
		Fn_InternetReadFile		InternetReadFile	= nullptr;
		Fn_InternetCloseHandle	InternetCloseHandle	= nullptr;
	};

	inline bool LoadWinInet(WinInetTable & table, HMODULE & module)
	{
		static const char * const kExports[] = {
			"InternetOpenW",
			"InternetSetOptionW",
			"InternetQueryOptionW",
			"InternetOpenUrlW",
			"InternetReadFile",
			"InternetCloseHandle",
		};

		FARPROC resolved[_countof(kExports)]{};

		auto module_name = XOR_STR_W(L"wininet.dll");
		HMODULE loaded = LoadLibraryW(module_name.get());
		if (!loaded)
		{
			return false;
		}

		for (size_t i = 0; i < _countof(kExports); ++i)
		{
			FARPROC proc = GetProcAddress(loaded, kExports[i]);
			if (!proc)
			{
				FreeLibrary(loaded);

				return false;
			}

			resolved[i] = proc;
		}

		table.InternetOpenW		= reinterpret_cast<Fn_InternetOpenW>(resolved[0]);
		table.InternetSetOptionW	= reinterpret_cast<Fn_InternetSetOptionW>(resolved[1]);
		table.InternetQueryOptionW	= reinterpret_cast<Fn_InternetQueryOptionW>(resolved[2]);
		table.InternetOpenUrlW	= reinterpret_cast<Fn_InternetOpenUrlW>(resolved[3]);
		table.InternetReadFile	= reinterpret_cast<Fn_InternetReadFile>(resolved[4]);
		table.InternetCloseHandle	= reinterpret_cast<Fn_InternetCloseHandle>(resolved[5]);

		module = loaded;

		return true;
	}

	inline void ReleaseModule(HMODULE & handle)
	{
		if (handle)
		{
			HMODULE to_free = handle;

			handle = nullptr;

			FreeLibrary(to_free);
		}
	}
}
