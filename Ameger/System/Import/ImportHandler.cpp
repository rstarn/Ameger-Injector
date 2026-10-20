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

#define S_FUNC(f) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(#f)), stats

#define S_FUNC_AS(f, sym) NATIVE::f, encrypted_symbol_name(KC_STR_LAYERED(sym)), stats

static STRING_STATS g_string_stats{};

// The stats block is written by the import worker thread and read by whichever
// thread asks for it, so it is published one LONG at a time. A plain struct copy
// would tear, and the counters would then report a mixture of two different runs.
static void StoreStringStats(const STRING_STATS & Src)
{
	static_assert(sizeof(STRING_STATS) % sizeof(LONG) == 0, "STRING_STATS must be a whole number of LONGs");

	volatile LONG * dst = ReCa<volatile LONG *>(&g_string_stats);
	const LONG * src = ReCa<const LONG *>(&Src);
	for (size_t i = 0; i < sizeof(STRING_STATS) / sizeof(LONG); ++i)
	{
		InterlockedExchange(&dst[i], src[i]);
	}
}

static void LoadStringStats(STRING_STATS & Dst)
{
	volatile LONG * src = ReCa<volatile LONG *>(&g_string_stats);
	LONG * dst = ReCa<LONG *>(&Dst);
	for (size_t i = 0; i < sizeof(STRING_STATS) / sizeof(LONG); ++i)
	{
		dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
	}
}

template <typename T>
DWORD LoadSymbolNative(T & Function, const encrypted_symbol_name & name, STRING_STATS & stats, bool CountDeclaration = true)
{
	if (CountDeclaration)
	{

		++stats.SymbolsDeclared;

		++stats.HookNamesBuilt;
	}

	DWORD RVA = 0;
	DWORD sym_ret = sym_parser.GetSymbolAddress(name.c_str(), RVA);

	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		LOG(1, "Failed To Load Native Function = %s\n", name.c_str());

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	Function = ReCa<T>(ReCa<UINT_PTR>(g_hNTDLL) + RVA);

	++stats.SymbolsResolved;

	// Publish the running totals so a concurrent reader sees progress rather than
	// a frozen snapshot.
	StoreStringStats(stats);

	return INJ_ERR_SUCCESS;
}

DWORD ResolveImports(ERROR_DATA & error_data)
{
	LOG(1, "ResolveImports Called\n");
	// The counters live in a local block and are published atomically, so a reader
	// on another thread never observes a half-written snapshot.
	STRING_STATS stats{ };
	StoreStringStats(stats);

	DWORD err = ERROR_SUCCESS;
	if (!GetOSVersion(&err))
	{
		INIT_ERROR_DATA(error_data, err);

		LOG(1, "Failed To Determine Windows Version\n");

		return INJ_ERR_WINDOWS_VERSION;
	}

	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(GetOSBuildVersion(), layout_family))
	{
		INIT_ERROR_DATA(error_data, static_cast<DWORD>(GetOSBuildVersion()));

		LOG(1, "Unsupported Windows Build = %u\n", GetOSBuildVersion());

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}

	auto ntdll_name = XOR_STR_W(L"ntdll.dll");
	g_hNTDLL	= GetModuleHandle(ntdll_name.get());
	if (!g_hNTDLL)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle Failed = %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_GET_MODULE_HANDLE_FAIL;
	}

	LOG(1, "Native OS Module Loaded At %p\n", g_hNTDLL);
	// The resolved build number selects which loader layout the shell may
	// assume. The launcher prints it because a mismatch here is the usual
	// cause of a mapping failure on an unexpected Windows build.
	LOG(1, "OSVersion = %lu\n", GetOSVersion());
	LOG(1, "OSBuildVersion = %lu\n", GetOSBuildVersion());

	auto k32_name = XOR_STR_W(L"kernel32.dll");
	HINSTANCE hK32 = GetModuleHandle(k32_name.get());
	if (!hK32)
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(1, "GetModuleHandle Failed = %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_KERNEL32_MISSING;
	}
	// kernel32 is only checked for presence. The loader internals that the
	// remote shell needs all live in ntdll, and the shell calls them
	// directly rather than going through kernel32.
	(void)hK32;

	LOG(1, "Waiting For Native Symbol Parser To Finish Initialization\n");

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

		LOG(1, "Native Symbol Loading Failed = %08X\n", sym_ret);

		return INJ_ERR_SYMBOL_LOAD_FAIL;
	}

	sym_ret = sym_parser.Initialize(&sym_ntdll_native);
	if (sym_ret != SYMBOL_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, sym_ret);

		LOG(1, "Native Symbol Parsing Failed = %08X\n", sym_ret);

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

	LOG(1, "Start Loading Native OS Symbols\n");

	if (LoadSymbolNative(S_FUNC(LdrUnloadDll)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(LdrGetProcedureAddress)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(memmove)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlZeroMemory)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlAllocateHeap)))						return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	if (LoadSymbolNative(S_FUNC(RtlFreeHeap)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

	if (LoadSymbolNative(S_FUNC(RtlAnsiStringToUnicodeString)))			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

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
				LOG(1, "Plural Entry Missing, Trying Singular\n");

				table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable), false);
			}
		}
		else
		{
			table_ret = LoadSymbolNative(S_FUNC(LdrpInvertedFunctionTable));
			if (table_ret != INJ_ERR_SUCCESS)
			{
				LOG(1, "Singular Entry Missing, Trying Plural\n");
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

			LOG(1, "Dynamic OS Offsets Failed = %08X\n", dyno_ret);

			return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
		}
	}

	pdb_guard.dismiss();

	sym_ntdll_native.Cleanup();

	LOG(1, "Native OS Symbols Loaded\n");

	sym_parser.Cleanup();

	sym_ntdll_native.PurgePdb();

	const unsigned kc_test = kc_strings::KcStringsSelfTest();
	LOG(1, "KcStrings Self-Test = %08X\n", kc_test);
	stats.TiersTotal = kc_strings::KcTierCount;
	stats.TiersPassed = kc_strings::KcTiersPassed(kc_test);
	if (kc_test != 0)
	{
		INIT_ERROR_DATA(error_data, kc_test);

		LOG(1, "KcStrings Self-Test Failed = %08X\n", kc_test);

		return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
	}

	stats.Reported = 1;

	StoreStringStats(stats);

	return INJ_ERR_SUCCESS;
}

void __stdcall GetLastStringStats(STRING_STATS * Out)
{
#pragma EXPORT_FUNCTION("CoreStrStats", __FUNCDNAME__)

	if (Out)
	{
		LoadStringStats(*Out);
	}
}
