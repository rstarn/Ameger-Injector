#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "System/Symbol/Parser/SymbolParser.h"

// Offset-resolution implementation (see DynamicOffsets.h for the strict vs
// fallback policy). What: PDB type/enum queries, memcpy'd into
// MANUAL_MAPPING_DATA for the target shell.

// Same as REQUIRE_FIELD but accepts an older and a newer PDB spelling of the
// same field. Microsoft renames fields across builds without moving them; the
// field is still mandatory, so a type that carries neither name fails closed.
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

	// Every PDB type/field/enum name this resolver probes is held as
	// compile-time ciphertext and decrypted into stack buffers here; the
	// pointer arrays below only reference those buffers, which outlive every
	// read in this function. Nothing below is a plaintext .rdata literal.
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
	auto f_peb = XOR_STR_A("ProcessEnvironmentBlock");
	auto f_os_major = XOR_STR_A("OSMajorVersion");
	auto f_os_minor = XOR_STR_A("OSMinorVersion");
	auto f_os_build = XOR_STR_A("OSBuildNumber");
	auto f_ldr = XOR_STR_A("Ldr");
	auto f_process_heap = XOR_STR_A("ProcessHeap");
	auto f_loader_lock = XOR_STR_A("LoaderLock");
	auto f_cookie = XOR_STR_A("Cookie");
	auto f_dll_base = XOR_STR_A("DllBase");
	auto f_size_of_image = XOR_STR_A("SizeOfImage");
	auto f_full_dll_name = XOR_STR_A("FullDllName");
	auto f_ddag_node = XOR_STR_A("DdagNode");
	auto f_state = XOR_STR_A("State");
	auto f_count = XOR_STR_A("Count");
	auto f_current_size = XOR_STR_A("CurrentSize");
	auto f_entries = XOR_STR_A("Entries");
	auto f_table_entry = XOR_STR_A("TableEntry");
	auto f_image_base = XOR_STR_A("ImageBase");
	auto f_image_size = XOR_STR_A("ImageSize");
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
	// Inverted function table. 26xxx renamed the types and their fields while
	// keeping the exact same on-disk layout (see NTDefinitions.h): the table
	// became _INVERTED_FUNCTION_TABLE_USER_MODE {CurrentSize,MaximumSize,
	// Epoch,Overflow,TableEntry} and the entry became
	// _INVERTED_FUNCTION_TABLE_ENTRY {union{FunctionTable,DynamicTable},
	// ImageBase,SizeOfImage,SizeOfTable}. Both spellings are attempted below;
	// the layout is still required to be present, so this stays fail-closed.
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
			LOG(1, "DynamicOffsets: missing %s (tried %s)\n", field, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = _off; \
	} while (0)

// Same as REQUIRE_FIELD but accepts an older and a newer PDB spelling of the
// same field. Microsoft renames fields across builds without moving them; the
// field is still mandatory, so a type that carries neither name fails closed.
#define REQUIRE_FIELD_ALT(types, primary, alternate, out) \
	do { \
		if (ResolveFieldEither(types, _countof(types), primary, alternate, out) != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: missing %s/%s (tried %s)\n", primary, alternate, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
	} while (0)

#define REQUIRE_SIZE(types, out) \
	do { \
		ULONG64 _sz = 0; \
		if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
			LOG(1, "DynamicOffsets: bad size for %s\n", types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = static_cast<DWORD>(_sz); \
	} while (0)

// Best-effort variants. Same lookups, but a miss logs and leaves the field at
// zero instead of failing the whole resolution.
//
// Use these ONLY for fields nothing in the tree dereferences. A field that is
// actually consumed must stay STRICT: it has to be resolved or the consumer
// would compute from a zero offset, which is exactly the stale-guess class of
// bug the strict policy above exists to prevent. These exist because the
// strict subset had grown to cover several fields with no consumer at all, so
// a future ntdll PDB that renames or drops any one of them would block every
// injection over a value nothing reads. If a field below ever gains a
// consumer, promote it back to REQUIRE_FIELD in the same commit that adds the
// consumer - the zero fallback is only safe while the field is write-only.
#define OPTIONAL_FIELD(types, field, out) \
	do { \
		DWORD _off = 0; \
		DWORD _r = sym_parser.GetFieldOffsetAny(types, _countof(types), field, _off); \
		if (_r != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: optional %s absent (tried %s); leaving 0\n", field, types[0]); \
		} else { \
			(out) = _off; \
		} \
	} while (0)

#define OPTIONAL_SIZE(types, out) \
	do { \
		ULONG64 _sz = 0; \
		if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
			LOG(1, "DynamicOffsets: optional size for %s unavailable; leaving 0\n", types[0]); \
		} else { \
			(out) = static_cast<DWORD>(_sz); \
		} \
	} while (0)

// Best-effort counterpart of REQUIRE_FIELD_ALT for the same reason.
// OPTIONAL_FIELD_ALT is the mirror of REQUIRE_FIELD_ALT; a caller that needs
// one needs the other, so both live here and both are #undef'd below.
#define OPTIONAL_FIELD_ALT(types, primary, alternate, out) \
	do { \
		if (ResolveFieldEither(types, _countof(types), primary, alternate, out) != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: optional %s/%s absent (tried %s); leaving 0\n", primary, alternate, types[0]); \
		} \
	} while (0)

	// TEB: SameTebFlags (worker check) and LastErrorValue (stub gs:[] disp) are
	// consumed by the hijack path and stay STRICT. ProcessEnvironmentBlock has
	// no reader, so it is best-effort.
	REQUIRE_FIELD(kTeb, f_same_teb_flags.get(), tmp.TebSameTebFlags);
	REQUIRE_FIELD(kTeb, f_last_error.get(), tmp.TebLastErrorValue);
	OPTIONAL_FIELD(kTeb, f_peb.get(), tmp.TebProcessEnvironmentBlock);

	// PEB: the Windows version comes from RtlGetVersion and the loader lock is
	// only ever taken by the remote shell, which reads its own copy of these
	// values - no host-side consumer exists for any PEB field. Best-effort so a
	// PEB shape change cannot stall injection.
	OPTIONAL_FIELD(kPeb, f_os_major.get(), tmp.PebOsMajorVersion);
	OPTIONAL_FIELD(kPeb, f_os_minor.get(), tmp.PebOsMinorVersion);
	OPTIONAL_FIELD(kPeb, f_os_build.get(), tmp.PebOsBuildNumber);
	OPTIONAL_FIELD(kPeb, f_ldr.get(), tmp.PebLdr);
	OPTIONAL_FIELD(kPeb, f_process_heap.get(), tmp.PebProcessHeap);
	OPTIONAL_FIELD(kPeb, f_loader_lock.get(), tmp.PebLoaderLock);
	OPTIONAL_SIZE(kPeb, tmp.PebSize);

	// KUSER_SHARED_DATA.Cookie field (base 0x7FFE0000 is fixed mapping).
	// Consumed by MMI_EnableExceptions - STRICT.
	REQUIRE_FIELD(kKuser, f_cookie.get(), tmp.KuserCookie);

	// LDR entry: only DllBase and sizeof() are consumed (MMI_LoadModule's
	// name preprocessing and MMI_HandleTLS's dummy entry). The rest are
	// documentation of the shape and have no reader.
	REQUIRE_FIELD(kLdrEntry, f_dll_base.get(), tmp.LdrEntryDllBase);
	REQUIRE_SIZE(kLdrEntry, tmp.LdrEntrySize);
	OPTIONAL_FIELD(kLdrEntry, f_size_of_image.get(), tmp.LdrEntrySizeOfImage);
	OPTIONAL_FIELD(kLdrEntry, f_full_dll_name.get(), tmp.LdrEntryFullDllName);
	OPTIONAL_FIELD(kLdrEntry, f_ddag_node.get(), tmp.LdrEntryDdagNode);
	OPTIONAL_FIELD(kDdag, f_state.get(), tmp.LdrDdagNodeState);
	OPTIONAL_SIZE(kDdag, tmp.LdrDdagNodeSize);

	// Inverted tables. Field names differ by build (Count/CurrentSize,
	// Entries/TableEntry, ImageSize/SizeOfImage,
	// ExceptionDirectory/FunctionTable, ExceptionDirectorySize/SizeOfTable);
	// the offsets are identical. Everything read by MMI_EnableExceptions is
	// STRICT; ImageSize/SizeOfImage is not read there (the shell proves image
	// containment with MMI_InImage against SizeOfImage it already holds).
	REQUIRE_FIELD_ALT(kInvTable, f_count.get(), f_current_size.get(), tmp.InvertedTableCount);
	REQUIRE_FIELD_ALT(kInvTable, f_entries.get(), f_table_entry.get(), tmp.InvertedTableEntries);
	REQUIRE_FIELD(kInvEntry, f_image_base.get(), tmp.InvertedEntryImageBase);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir.get(), f_function_table.get(), tmp.InvertedEntryExceptionDirectory);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir_size.get(), f_size_of_table.get(), tmp.InvertedEntryExceptionDirectorySize);
	REQUIRE_SIZE(kInvEntry, tmp.InvertedEntrySize);
	OPTIONAL_FIELD_ALT(kInvEntry, f_image_size.get(), f_size_of_image.get(), tmp.InvertedEntryImageSize);

#undef REQUIRE_FIELD
#undef REQUIRE_FIELD_ALT
#undef REQUIRE_SIZE
#undef OPTIONAL_FIELD
#undef OPTIONAL_FIELD_ALT
#undef OPTIONAL_SIZE

	// TLS entry: PDB-first, with a fallback derived from the repo's own
	// documented _TLS_ENTRY (NTDefinitions.h, static_asserted to 72) instead of
	// a hand-summed field list that could silently drift from it. The only
	// consumer (MMI_HandleTLS) uses the size purely as an upper bound for
	// reading ModuleEntry, so an oversized guess is harmless while an
	// undersized one would disable the LdrpTlsList unlink and leak the dummy
	// entry - err on the large side by taking the documented struct size.
	{
		DWORD off = 0;
		if (sym_parser.GetFieldOffsetAny(kTls, _countof(kTls), f_module_entry.get(), off) == SYMBOL_ERR_SUCCESS && off && off < 0x200)
		{
			tmp.TlsEntryModuleEntry = off;
		}
		else
		{
			tmp.TlsEntryModuleEntry = static_cast<DWORD>(offsetof(TLS_ENTRY, ModuleEntry));
			LOG(1, "DynamicOffsets: TLS slot via documented struct 0x%X (PDB type absent)\n", tmp.TlsEntryModuleEntry);
		}
		ULONG64 tls_sz = 0;
		if (sym_parser.GetTypeSizeAny(kTls, _countof(kTls), tls_sz) == SYMBOL_ERR_SUCCESS && tls_sz && tls_sz < 0x400)
		{
			tmp.TlsEntrySize = static_cast<DWORD>(tls_sz);
		}
		else
		{
			tmp.TlsEntrySize = static_cast<DWORD>(sizeof(TLS_ENTRY));
			LOG(1, "DynamicOffsets: TLS size via documented struct %lu\n", tmp.TlsEntrySize);
		}
	}

	// LDRP_PATH_SEARCH_CONTEXT size + OriginalFullDllName offset: PDB-first,
	// static fallback (over-allocate is safe; under-allocate would corrupt).
	{
		// One definition shared by both fallbacks below. Layout is the
		// reverse-engineered context: it is only ever sized/offset, never
		// dereferenced.
		struct FALLBACK_CTX { wchar_t * a; void * b[3]; wchar_t * c; void * d[7]; ULONG64 e[4]; };

		ULONG64 ctx_sz = 0;
		if (sym_parser.GetTypeSizeAny(kPathCtx, _countof(kPathCtx), ctx_sz) == SYMBOL_ERR_SUCCESS && ctx_sz && ctx_sz < 0x1000)
		{
			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(ctx_sz);
		}
		else
		{
			// Fallback keeps the reverse-engineered size; it is only a heap
			// allocation length, never an in-target field offset.
			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(sizeof(FALLBACK_CTX));
			LOG(1, "DynamicOffsets: path context size via fallback %lu\n", tmp.LdrpPathSearchContextSize);
		}
		DWORD ctx_off = 0;
		if (sym_parser.GetFieldOffsetAny(kPathCtx, _countof(kPathCtx), f_orig_full_dll.get(), ctx_off) == SYMBOL_ERR_SUCCESS && ctx_off < 0x400)
		{
			tmp.LdrpPathSearchOriginalFullDllName = ctx_off;
		}
		else
		{
			tmp.LdrpPathSearchOriginalFullDllName = static_cast<DWORD>(offsetof(FALLBACK_CTX, c));
			LOG(1, "DynamicOffsets: path context name via fallback 0x%X\n", tmp.LdrpPathSearchOriginalFullDllName);
		}
	}

	// Thread Running state (PDB first, stable fallback 2): the only scheduler
	// value consumed anywhere (victim selection is Running-only). No wait
	// stubs are disassembled and no consensus is published: with waiting
	// threads never hijacked, return-address offsets have no consumer.
	{
		DWORD v = 0;
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), f_running.get(), v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateRunning = v;
		}
		else
		{
			tmp.ThreadStateRunning = 2;
			LOG(2, "DynamicOffsets: Running via stable fallback 2\n");
		}
	}

	tmp.Ready = 1;
	g_DynamicOffsets = tmp;
	// Publish only after every field is written: release-store the flag so a
	// consumer's acquire-load of g_DynamicOffsetsReady observes the full
	// struct. Ready is also set in tmp for the MANUAL_MAPPING_DATA copy, but
	// this atomic store is the synchronization primitive.
	g_DynamicOffsetsReady.store(1, std::memory_order_release);
	LOG(1, "DynamicOffsets ready: t0=0x%X t1=0x%X t2=0x%X p0=0x%X p1=0x%X k0=0x%X l0=0x%X sz=%lu i0=0x%X i1=0x%X\n",
		tmp.TebSameTebFlags, tmp.TebLastErrorValue, tmp.TebProcessEnvironmentBlock,
		tmp.PebOsBuildNumber, tmp.PebLdr, tmp.KuserCookie, tmp.LdrEntryDllBase, tmp.LdrEntrySize,
		tmp.InvertedTableCount, tmp.InvertedTableEntries);

	return SYMBOL_ERR_SUCCESS;
}
