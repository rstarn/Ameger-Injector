#pragma once

// Runtime-resolved third-party modules (dbghelp / wininet).
//
// Why this exists: the shipped PE must not statically import dbghelp.dll or
// wininet.dll. A manual-mapping carrier that imports either module is a
// textbook indicator: the import table is the first thing a module walk reads,
// it survives every string-encryption effort, and it is byte-identical in every
// build. Resolving the handful of functions below by name at the moment they
// are needed - and releasing the module as soon as they are not - keeps the
// import table limited to KERNEL32/ADVAPI32/USER32 and keeps both modules out
// of the process module list for the rest of the run.
//
// Rules followed by both subsystems:
//   - the module name and every export name are compile-time ciphertext
//     (XOR_STR_A/XOR_STR_W), so nothing in .rdata names either module or the
//     symbols used here;
//   - a symbol that cannot be resolved fails closed: the loader returns false
//     and frees whatever it loaded, and callers treat that as "symbols
//     unavailable" exactly as they already treat a failed SymInitialize;
//   - callers go through these tables ONLY. Naming a DbgHelp/WinINet function
//     directly (or taking its address) reintroduces the static import, so no
//     call site may do either. This includes the oleauto VARIANT helpers: the
//     local shape below is what the TI_GET_VALUE buffer actually needs.
//
// Usage is strictly pairing: Load() -> use -> Free(). Each load frees the
// module again, so the module list never carries dbghelp/wininet outside the
// window that genuinely needs them.

// Headers for the types only. Neither header creates an import: the import
// table is produced by *calling* a function (or taking its address), and every
// call below goes through a resolved pointer. Including them here keeps this
// header self-contained rather than relying on the PCH having pulled them in.
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
	// Hand-written VARIANT: only used as a 16-byte TI_GET_VALUE buffer for
	// integer enum constants. Declaring it locally is what removes the
	// oleaut32 VariantInit/VariantClear imports the parser previously carried.
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

	// ------------------------------------------------------------------
	// DbgHelp: used only while a PDB is being parsed for offsets.
	// ------------------------------------------------------------------

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

	// Resolves the DbgHelp entry points into table and returns a handle that
	// must be passed to FreeModule once the caller is done. Returns false (and
	// leaves module = nullptr) when the module or any symbol is unavailable.
	inline bool LoadDbgHelp(DbgHelpTable & table, HMODULE & module)
	{
		// Names deliberately unsuffixed: dbghelp.dll exports SymInitialize AND
		// SymInitializeW as two different functions, and only the unsuffixed
		// one is the entry point the SDK import library (and therefore the
		// previous static build) bound. Resolving the W variant silently
		// changes DbgHelp's behaviour - it skips the module-load bookkeeping
		// that later SymFromName calls depend on and they fail with
		// ERROR_MOD_NOT_FOUND. Same story for SymLoadModuleEx/SymLoadModuleExW.
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

	// ------------------------------------------------------------------
	// WinINet: used only while a PDB is being fetched.
	// ------------------------------------------------------------------

	using Fn_InternetOpenW			= HINTERNET(__stdcall *)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
	using Fn_InternetSetOptionW	= BOOL(__stdcall *)(HINTERNET, DWORD, LPVOID, DWORD);
	using Fn_InternetOpenUrlW		= HINTERNET(__stdcall *)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
	using Fn_InternetReadFile		= BOOL(__stdcall *)(HINTERNET, LPVOID, DWORD, LPDWORD);
	using Fn_InternetCloseHandle	= BOOL(__stdcall *)(HINTERNET);

	struct WinInetTable
	{
		Fn_InternetOpenW			InternetOpenW		= nullptr;
		Fn_InternetSetOptionW	InternetSetOptionW	= nullptr;
		Fn_InternetOpenUrlW		InternetOpenUrlW	= nullptr;
		Fn_InternetReadFile		InternetReadFile	= nullptr;
		Fn_InternetCloseHandle	InternetCloseHandle	= nullptr;
	};

	// Same contract as LoadDbgHelp: table out, handle out, fail-closed.
	inline bool LoadWinInet(WinInetTable & table, HMODULE & module)
	{
		static const char * const kExports[] = {
			"InternetOpenW",
			"InternetSetOptionW",
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
		table.InternetOpenUrlW	= reinterpret_cast<Fn_InternetOpenUrlW>(resolved[2]);
		table.InternetReadFile	= reinterpret_cast<Fn_InternetReadFile>(resolved[3]);
		table.InternetCloseHandle	= reinterpret_cast<Fn_InternetCloseHandle>(resolved[4]);

		module = loaded;

		return true;
	}

	// Releases a module loaded above. Safe on nullptr.
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
