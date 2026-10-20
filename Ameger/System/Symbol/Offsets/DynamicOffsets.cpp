#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "System/Symbol/Parser/SymbolParser.h"

static DWORD ResolveFieldEither(const char * const * types, size_t typeCount, const char * primary, const char * alternate, DWORD & out)
{
	DWORD off = 0;
	if (sym_parser.GetFieldOffsetAny(types, typeCount, primary, off) == SYMBOL_ERR_SUCCESS)
	{
		out = off;
		return SYMBOL_ERR_SUCCESS;
	}
	if (sym_parser.GetFieldOffsetAny(types, typeCount, alternate, off) == SYMBOL_ERR_SUCCESS)
	{
		out = off;
		return SYMBOL_ERR_SUCCESS;
	}
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

DWORD ResolveDynamicOffsets()
{
	if (g_DynamicOffsetsReady.load(std::memory_order_acquire))
	{
		return SYMBOL_ERR_SUCCESS;
	}

	DYNAMIC_NT_OFFSETS tmp{};

	auto t_teb_a = XOR_STR_A("TEB");
	auto t_teb_b = XOR_STR_A("_TEB");
	auto t_peb_a = XOR_STR_A("PEB");
	auto t_peb_b = XOR_STR_A("_PEB");
	auto t_kuser_a = XOR_STR_A("_KUSER_SHARED_DATA");
	auto t_kuser_b = XOR_STR_A("KUSER_SHARED_DATA");
	auto t_ldr_a = XOR_STR_A("_LDR_DATA_TABLE_ENTRY");
	auto t_ldr_b = XOR_STR_A("LDR_DATA_TABLE_ENTRY");
	auto t_ddag_a = XOR_STR_A("_LDR_DDAG_NODE");
	auto t_ddag_b = XOR_STR_A("LDR_DDAG_NODE");
	auto t_invt_a = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE");
	auto t_invt_b = XOR_STR_A("RTL_INVERTED_FUNCTION_TABLE");
	auto t_invt_c = XOR_STR_A("_INVERTED_FUNCTION_TABLE_USER_MODE");
	auto t_invt_d = XOR_STR_A("INVERTED_FUNCTION_TABLE_USER_MODE");
	auto t_inve_a = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_b = XOR_STR_A("RTL_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_c = XOR_STR_A("_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_d = XOR_STR_A("INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_tls_a = XOR_STR_A("_TLS_ENTRY");
	auto t_tls_b = XOR_STR_A("TLS_ENTRY");
	auto t_tls_c = XOR_STR_A("_LDRP_TLS_ENTRY");
	auto t_tls_d = XOR_STR_A("LDRP_TLS_ENTRY");
	auto t_path_a = XOR_STR_A("_LDRP_PATH_SEARCH_CONTEXT");
	auto t_path_b = XOR_STR_A("LDRP_PATH_SEARCH_CONTEXT");
	auto t_kstate_a = XOR_STR_A("_KTHREAD_STATE");
	auto t_kstate_b = XOR_STR_A("KTHREAD_STATE");

	auto f_same_teb_flags = XOR_STR_A("SameTebFlags");
	auto f_last_error = XOR_STR_A("LastErrorValue");
	auto f_ldr = XOR_STR_A("Ldr");
	auto f_cookie = XOR_STR_A("Cookie");
	auto f_dll_base = XOR_STR_A("DllBase");
	auto f_size_of_image = XOR_STR_A("SizeOfImage");
	auto f_full_dll_name = XOR_STR_A("FullDllName");
	auto f_base_dll_name = XOR_STR_A("BaseDllName");
	auto f_ddag_node = XOR_STR_A("DdagNode");
	auto f_state = XOR_STR_A("State");
	auto f_count = XOR_STR_A("Count");
	auto f_current_size = XOR_STR_A("CurrentSize");
	auto f_entries = XOR_STR_A("Entries");
	auto f_table_entry = XOR_STR_A("TableEntry");
	auto f_image_base = XOR_STR_A("ImageBase");
	auto f_exception_dir = XOR_STR_A("ExceptionDirectory");
	auto f_function_table = XOR_STR_A("FunctionTable");
	auto f_exception_dir_size = XOR_STR_A("ExceptionDirectorySize");
	auto f_size_of_table = XOR_STR_A("SizeOfTable");
	auto f_module_entry = XOR_STR_A("ModuleEntry");
	auto f_orig_full_dll = XOR_STR_A("OriginalFullDllName");
	auto f_running = XOR_STR_A("Running");

	const char * kTeb[] = { t_teb_a.get(), t_teb_b.get() };
	const char * kPeb[] = { t_peb_a.get(), t_peb_b.get() };
	const char * kKuser[] = { t_kuser_a.get(), t_kuser_b.get() };
	const char * kLdrEntry[] = { t_ldr_a.get(), t_ldr_b.get() };
	const char * kDdag[] = { t_ddag_a.get(), t_ddag_b.get() };

	const char * kInvTable[] = { t_invt_a.get(), t_invt_b.get(), t_invt_c.get(), t_invt_d.get() };
	const char * kInvEntry[] = { t_inve_a.get(), t_inve_b.get(), t_inve_c.get(), t_inve_d.get() };
	const char * kTls[] = { t_tls_a.get(), t_tls_b.get(), t_tls_c.get(), t_tls_d.get() };
	const char * kPathCtx[] = { t_path_a.get(), t_path_b.get() };
	const char * kThreadState[] = { t_kstate_a.get(), t_kstate_b.get() };

#define REQUIRE_FIELD(types, field, out) \
	do { \
		DWORD _off = 0; \
		DWORD _r = sym_parser.GetFieldOffsetAny(types, _countof(types), field, _off); \
		if (_r != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: Missing %s (Tried %s)\n", field, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = _off; \
	} while (0)

#define REQUIRE_FIELD_ALT(types, primary, alternate, out) \
	do { \
		if (ResolveFieldEither(types, _countof(types), primary, alternate, out) != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: Missing %s/%s (Tried %s)\n", primary, alternate, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
	} while (0)

#define REQUIRE_SIZE(types, out) \
	do { \
		ULONG64 _sz = 0; \
		if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
			LOG(1, "DynamicOffsets: Bad Size For %s\n", types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = static_cast<DWORD>(_sz); \
	} while (0)

#define OPTIONAL_FIELD(types, field, out) \
	do { \
		DWORD _off = 0; \
		DWORD _r = sym_parser.GetFieldOffsetAny(types, _countof(types), field, _off); \
		if (_r != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: Optional %s Absent (Tried %s); Leaving 0\n", field, types[0]); \
		} else { \
			(out) = _off; \
		} \
	} while (0)

#define OPTIONAL_SIZE(types, out) \
	do { \
		ULONG64 _sz = 0; \
		if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
			LOG(1, "DynamicOffsets: Optional Size For %s Unavailable; Leaving 0\n", types[0]); \
		} else { \
			(out) = static_cast<DWORD>(_sz); \
		} \
	} while (0)

#define OPTIONAL_FIELD_ALT(types, primary, alternate, out) \
	do { \
		if (ResolveFieldEither(types, _countof(types), primary, alternate, out) != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: Optional %s/%s Absent (Tried %s); Leaving 0\n", primary, alternate, types[0]); \
		} \
	} while (0)

	REQUIRE_FIELD(kTeb, f_same_teb_flags.get(), tmp.TebSameTebFlags);
	REQUIRE_FIELD(kTeb, f_last_error.get(), tmp.TebLastErrorValue);

	OPTIONAL_FIELD(kPeb, f_ldr.get(), tmp.PebLdr);

	REQUIRE_FIELD(kKuser, f_cookie.get(), tmp.KuserCookie);

	REQUIRE_FIELD(kLdrEntry, f_dll_base.get(), tmp.LdrEntryDllBase);
	REQUIRE_SIZE(kLdrEntry, tmp.LdrEntrySize);
	OPTIONAL_FIELD(kLdrEntry, f_size_of_image.get(), tmp.LdrEntrySizeOfImage);
	OPTIONAL_FIELD(kLdrEntry, f_full_dll_name.get(), tmp.LdrEntryFullDllName);
	OPTIONAL_FIELD(kLdrEntry, f_base_dll_name.get(), tmp.LdrEntryBaseDllName);
	OPTIONAL_FIELD(kLdrEntry, f_ddag_node.get(), tmp.LdrEntryDdagNode);
	OPTIONAL_FIELD(kDdag, f_state.get(), tmp.LdrDdagNodeState);
	OPTIONAL_SIZE(kDdag, tmp.LdrDdagNodeSize);

	REQUIRE_FIELD_ALT(kInvTable, f_count.get(), f_current_size.get(), tmp.InvertedTableCount);
	REQUIRE_FIELD_ALT(kInvTable, f_entries.get(), f_table_entry.get(), tmp.InvertedTableEntries);
	REQUIRE_FIELD(kInvEntry, f_image_base.get(), tmp.InvertedEntryImageBase);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir.get(), f_function_table.get(), tmp.InvertedEntryExceptionDirectory);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir_size.get(), f_size_of_table.get(), tmp.InvertedEntryExceptionDirectorySize);
	REQUIRE_SIZE(kInvEntry, tmp.InvertedEntrySize);

#undef REQUIRE_FIELD
#undef REQUIRE_FIELD_ALT
#undef REQUIRE_SIZE
#undef OPTIONAL_FIELD
#undef OPTIONAL_FIELD_ALT
#undef OPTIONAL_SIZE

	{
		DWORD off = 0;
		if (sym_parser.GetFieldOffsetAny(kTls, _countof(kTls), f_module_entry.get(), off) == SYMBOL_ERR_SUCCESS && off && off < 0x200)
		{
			tmp.TlsEntryModuleEntry = off;
		}
		else
		{
			tmp.TlsEntryModuleEntry = static_cast<DWORD>(offsetof(TLS_ENTRY, ModuleEntry));
			LOG(1, "DynamicOffsets: TLS Slot Via Documented Struct 0x%X (PDB Type Absent)\n", tmp.TlsEntryModuleEntry);
		}
		ULONG64 tls_sz = 0;
		if (sym_parser.GetTypeSizeAny(kTls, _countof(kTls), tls_sz) == SYMBOL_ERR_SUCCESS && tls_sz && tls_sz < 0x400)
		{
			tmp.TlsEntrySize = static_cast<DWORD>(tls_sz);
		}
		else
		{
			tmp.TlsEntrySize = static_cast<DWORD>(sizeof(TLS_ENTRY));
			LOG(1, "DynamicOffsets: TLS Size Via Documented Struct %lu\n", tmp.TlsEntrySize);
		}
	}

	{

		struct FALLBACK_CTX { wchar_t * a; void * b[3]; wchar_t * c; void * d[7]; ULONG64 e[4]; };

		ULONG64 ctx_sz = 0;
		if (sym_parser.GetTypeSizeAny(kPathCtx, _countof(kPathCtx), ctx_sz) == SYMBOL_ERR_SUCCESS && ctx_sz && ctx_sz < 0x1000)
		{
			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(ctx_sz);
		}
		else
		{

			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(sizeof(FALLBACK_CTX));
			LOG(1, "DynamicOffsets: Path Context Size Via Fallback %lu\n", tmp.LdrpPathSearchContextSize);
		}
		DWORD ctx_off = 0;
		if (sym_parser.GetFieldOffsetAny(kPathCtx, _countof(kPathCtx), f_orig_full_dll.get(), ctx_off) == SYMBOL_ERR_SUCCESS && ctx_off < 0x400)
		{
			tmp.LdrpPathSearchOriginalFullDllName = ctx_off;
		}
		else
		{
			tmp.LdrpPathSearchOriginalFullDllName = static_cast<DWORD>(offsetof(FALLBACK_CTX, c));
			LOG(1, "DynamicOffsets: Path Context Name Via Fallback 0x%X\n", tmp.LdrpPathSearchOriginalFullDllName);
		}
	}

	{
		DWORD v = 0;
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), f_running.get(), v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateRunning = v;
		}
		else
		{
			tmp.ThreadStateRunning = 2;
			LOG(2, "DynamicOffsets: Running Via Stable Fallback 2\n");
		}
	}

	g_DynamicOffsets = tmp;

	g_DynamicOffsetsReady.store(1, std::memory_order_release);
	LOG(1, "DynamicOffsets Ready: T0 = 0x%X | T1 = 0x%X | P0 = 0x%X | K0 = 0x%X | L0 = 0x%X | Size = %lu | I0 = 0x%X | I1 = 0x%X\n",
		tmp.TebSameTebFlags, tmp.TebLastErrorValue, tmp.PebLdr,
		tmp.KuserCookie, tmp.LdrEntryDllBase, tmp.LdrEntrySize,
		tmp.InvertedTableCount, tmp.InvertedTableEntries);

	return SYMBOL_ERR_SUCCESS;
}
