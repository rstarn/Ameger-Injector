#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"

#include <utility>

using namespace NATIVE;

namespace
{

	class encrypted_symbol_name
	{
		const char * m_name;

	public:
		template <typename Holder, typename = decltype(std::declval<const Holder &>().c_str())>
		explicit encrypted_symbol_name(const Holder & holder) noexcept : m_name(holder.c_str()) {}

		const char * c_str() const noexcept { return m_name; }
	};
}

#define S_FUNC(f) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(#f))

#define S_FUNC_AS(f, sym) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(sym))

static STRING_STATS g_string_stats{};

template <typename T>
DWORD LoadSymbolNative(T & Function, const encrypted_symbol_name & name, bool CountDeclaration = true)
{
	if (CountDeclaration)
	{

		++g_string_stats.SymbolsDeclared;

		++g_string_stats.HookNamesBuilt;
	}

	DWORD RVA = 0;
	DWORD sym_ret = sym_parser.GetSymbolAddress(name.c_str(), RVA);

	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(1, "Failed to load native function: %s\n", name.c_str());

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	++g_string_stats.SymbolsResolved;

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	LOG(1, "ResolveImports called\n");

	// Counters describe one resolution pass, so a retry starts from a clean slate instead of reporting
	// the previous attempt's declarations alongside the current attempt's results.
	g_string_stats = STRING_STATS{};

	DWORD err = ERROR_SUCCESS;
	if (!GetOSVersion(&err))
	{
		INIT_ERROR_DATA(error_data, err);

		LOG(1, "Failed to determine Windows version\n");

		return INJ_ERR_WINDOWS_VERSION;
	}

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		LOG(1, "Unsupported Windows build: %u\n", GetOSBuildVersion());

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	auto ntdll_name = XOR_STR_W(L"ntdll.dll");
	g_hNTDLL	= GetModuleHandle(ntdll_name.get());
	if (!g_hNTDLL)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_MODULE_HANDLE_FAIL;
	}

	LOG(1, "native OS module    loaded at %p\n", g_hNTDLL);
	LOG(1, "OSVersion = %lu\nOSBuildVersion = %lu\n", GetOSVersion(), GetOSBuildVersion());

	auto k32_name = XOR_STR_W(L"kernel32.dll");
	HINSTANCE hK32 = GetModuleHandle(k32_name.get());
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle failed: %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}

	// kernel32 is pinned only so that its absence is reported as its own failure rather than surfacing
	// later as a null GetProcAddress result. Every native routine the runtime needs is resolved below
	// by RVA out of the ntdll symbols, never by name through a public export, so nothing here is looked
	// up through kernel32 and no kernel32 pointer is cached.
	(void)hK32;

	LOG(1, "Waiting for native symbol parser to finish initialization\n");

	while (!PollAsyncWorker(sym_ntdll_native_ret))
	{
		if (WaitForSingleObject(g_hInterruptImport, 10) == WAIT_OBJECT_0)
		{
			return INJ_ERR_IMPORT_INTERRUPT;
		}
	}

	DWORD sym_ret = sym_ntdll_native_ret.Result;
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol loading failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_LOAD_FAIL;
	}

	sym_ret = sym_parser.Initialize(&sym_ntdll_native);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native symbol parsing failed: %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_PARSE_FAIL;
	}

	auto pdb_guard = MakeScopeExit([&]() noexcept {
		sym_ntdll_native.Cleanup();
		sym_parser.Cleanup();
		sym_ntdll_native.PurgePdb();

		if (error_data.AdvErrorCode == INJ_ERR_ADVANCED_NOT_DEFINED)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_GET_SYMBOL_ADDRESS_FAILED);
		}
	});

	LOG(1, "Start loading native OS symbols\n");

	if (LoadSymbolNative(S_FUNC(LdrUnloadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(memmove)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlAllocateHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlFreeHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtClose)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(NtAllocateVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtFreeVirtualMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlInsertInvertedFunctionTable)))		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpHandleTlsData)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrLockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrUnlockLoaderLock)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrpHeap)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpTlsList)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	{
		const bool prefer_plural = GetOSBuildVersion() >= g_Windows11_22H2;
		DWORD table_ret = INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		if (prefer_plural)
		{
			table_ret = LoadSymbolNative(S_FUNC_AS(LdrpInvertedFunctionTable, "LdrpInvertedFunctionTables"));
			if (table_ret != INJ_ERR_SUCCESS)
			{
				LOG(1, "Plural entry missing, trying singular\n");

				table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable), false);
			}
		}
		else
		{
			table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable));
			if (table_ret != INJ_ERR_SUCCESS)
			{
				LOG(1, "Singular entry missing, trying plural\n");
				table_ret = LoadSymbolNative(S_FUNC_AS(LdrpInvertedFunctionTable, "LdrpInvertedFunctionTables"), false);
			}
		}
		if (table_ret != INJ_ERR_SUCCESS)
		{
			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		}
	}

	if (LoadSymbolNative(S_FUNC(LdrProtectMrdata)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpPreprocessDllName)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpLoadDllInternal)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(LdrpDereferenceModule)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAddFunctionTable)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlLookupFunctionEntry))) return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	LoadSymbolNative(S_FUNC(RtlDeleteFunctionTable));

	{
		const DWORD dyno_ret = ResolveDynamicOffsets();
		if (dyno_ret != SYMBOL_ERR_SUCCESS)
		{
			INIT_ERROR_DATA(error_data, dyno_ret);

			LOG(1, "Dynamic OS offsets failed: %08X\n", dyno_ret);

			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		}
	}

	pdb_guard.dismiss();

	sym_ntdll_native.Cleanup();

	LOG(1, "Native OS symbols loaded\n");

	sym_parser.Cleanup();

	sym_ntdll_native.PurgePdb();

	const unsigned kc_test = kc_strings::KcStringsSelfTest();
	LOG(1, "KcStrings self-test: %08X\n", kc_test);
	g_string_stats.TiersTotal = kc_strings::KcTierCount;
	g_string_stats.TiersPassed = kc_strings::KcTiersPassed(kc_test);
	if (kc_test != 0)
	{
		INIT_ERROR_DATA(error_data, kc_test);

		LOG(1, "KcStrings self-test failed: %08X\n", kc_test);

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	g_string_stats.Reported = 1;

	return INJ_ERR_SUCCESS;
}

void __stdcall GetLastStringStats(STRING_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreStrStats", __FUNCDNAME__)

	if (Out)
	{
		*Out = g_string_stats;
	}
}
