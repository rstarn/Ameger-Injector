#pragma once

#include <Windows.h>

#include <algorithm>

#include "Core/Foundation/Error.h"

namespace PE_IMAGE
{
// Strict host+shell PE validator for manual-map payloads.
// What: proves a raw file image is safe to map (headers, sections, dirs,
//   thunks) before any byte is copied into the target. Why one header-inline
//   copy: both the host (ValidateDllFile*) and the in-target shell
//   (MMI_MapSections) must enforce identical rules, and the shell cannot call
//   host code - inlining folds the checks into its code_seg. How: Validate()
//   fills a VIEW then runs the staged checks; every helper below is
//   overflow-safe and fail-closed (false/invalid on any anomaly).
	// Upper bound for SizeOfImage and file size (1 GB). Larger images are
	// rejected outright to bound copy/scan work in both host and shell.
	constexpr DWORD MAX_IMAGE_SIZE = 0x40000000;
	// Upper bound for NumberOfSections. Keeps the O(n^2) overlap walk bounded.
	constexpr WORD MAX_SECTION_COUNT = 96;

	// Validation knobs, derived from INJ_MM_* flags via BuildPeValidationOptions.
	// Each true member enables one staged check in Validate().
	struct OPTIONS
	{
		bool RequireDll = false; // IMAGE_FILE_DLL characteristic required
		bool RequireExports = false; // export dir must validate
		bool RequireRelocations = false; // base-reloc dir must validate
		bool ResolveImports = false; // classic import dir must validate
		bool ResolveDelayImports = false; // delay-import dir must validate
		bool EnableExceptions = false; // exception dir must exist
		bool InitializeSecurityCookie = false; // load-config size sanity
		bool ExecuteTls = false; // TLS dir shape sanity when present
	};

	// Validated image cursor. What: raw bytes plus resolved header pointers
	// for the MapRva/FindSection helpers. Filled by Validate() on success;
	// meaningless on failure. Fields: Data/Size (file bytes), NtHeaders
	// (in-Data pointer), Sections (in-Data section table).
	struct VIEW
	{
		const BYTE * Data = nullptr;
		size_t Size = 0;
		const IMAGE_NT_HEADERS64 * NtHeaders = nullptr;
		const IMAGE_SECTION_HEADER * Sections = nullptr;
	};

	// Contiguous readable run for one RVA. What: Data points into VIEW bytes,
	// Available is the bytes left in that section (or headers). Empty
	// (null Data) means the RVA is unmapped. Produced by MapRva().
	struct MAPPING
	{
		const BYTE * Data = nullptr;
		size_t Available = 0;
	};

	// True when [offset, offset+count) lies fully inside [0, total) without
	// wrapping. Overflow-safe: the subtraction form never adds past SIZE_MAX.
	__forceinline bool RangeWithin(size_t offset, size_t count, size_t total)
	{
		return offset <= total && count <= total - offset;
	}

	// True for nonzero powers of two (alignment values). Params: value (in).
	__forceinline bool IsPowerOfTwo(DWORD value)
	{
		return value != 0 && (value & (value - 1)) == 0;
	}

	// True when value is a multiple of a power-of-two alignment. Params:
	// value/alignment (in). Non-power-of-two alignments always fail.
	__forceinline bool IsAligned(DWORD value, DWORD alignment)
	{
		return IsPowerOfTwo(alignment) && (value & (alignment - 1)) == 0;
	}

	// Locates the section owning an RVA (span = max(VirtualSize, RawData)).
	// Params: view (validated cursor), rva (in). Returns: owning section or
	// null when the RVA falls in no section (headers handled by MapRva).
	__forceinline const IMAGE_SECTION_HEADER * FindSection(const VIEW & view, DWORD rva)
	{
		const IMAGE_FILE_HEADER & file_header = view.NtHeaders->FileHeader;

		for (WORD index = 0; index < file_header.NumberOfSections; ++index)
		{
			const IMAGE_SECTION_HEADER & section = view.Sections[index];
			const DWORD span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
			if (rva >= section.VirtualAddress && rva - section.VirtualAddress < span)
			{
				return &section;
			}
		}

		return nullptr;
	}

	__forceinline MAPPING MapRva(const VIEW & view, DWORD rva)
	{
		if (rva < view.NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			if (!RangeWithin(rva, 1, view.Size))
			{
				return {};
			}

			return { view.Data + rva, view.NtHeaders->OptionalHeader.SizeOfHeaders - rva };
		}

		const IMAGE_SECTION_HEADER * section = FindSection(view, rva);
		if (!section || !section->SizeOfRawData)
		{
			return {};
		}

		const DWORD raw_offset = rva - section->VirtualAddress;
		if (raw_offset >= section->SizeOfRawData)
		{
			return {};
		}

		return { view.Data + section->PointerToRawData + raw_offset, section->SizeOfRawData - raw_offset };
	}

	__forceinline bool IsZeroTerminated(const BYTE * data, size_t available)
	{
		for (size_t index = 0; index < available; ++index)
		{
			if (data[index] == 0)
			{
				return true;
			}
		}

		return false;
	}

	__forceinline bool ValidateThunkTable(const VIEW & view, DWORD rva)
	{
		const MAPPING mapping = MapRva(view, rva);
		if (!mapping.Data || mapping.Available < sizeof(IMAGE_THUNK_DATA64))
		{
			return false;
		}

		const size_t maximum_entries = mapping.Available / sizeof(IMAGE_THUNK_DATA64);
		for (size_t index = 0; index < maximum_entries; ++index)
		{
			const IMAGE_THUNK_DATA64 & thunk = *reinterpret_cast<const IMAGE_THUNK_DATA64 *>(mapping.Data + index * sizeof(IMAGE_THUNK_DATA64));
			if (!thunk.u1.AddressOfData)
			{
				return true;
			}

			if (!IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
			{
				// MapRva takes a 32-bit RVA: a crafted 64-bit thunk with
				// high bits set would truncate here while the shell adds the
				// full width (validator/shell divergence). Reject high-bit
				// RVAs outright; legitimate x64 images never set them.
				if ((thunk.u1.AddressOfData >> 32) != 0)
				{
					return false;
				}
				const MAPPING name_mapping = MapRva(view, static_cast<DWORD>(thunk.u1.AddressOfData));
				if (!name_mapping.Data || name_mapping.Available < sizeof(WORD) || !IsZeroTerminated(name_mapping.Data + sizeof(WORD), name_mapping.Available - sizeof(WORD)))
				{
					return false;
				}
			}
		}

		return false;
	}

	// Counts the null-terminated thunk entries at rva (excluding the
	// terminator). Returns false when unterminated or when any name entry is
	// malformed - the same walk ValidateThunkTable performs, but with the
	// count exposed so callers can bound the parallel IAT.
	__forceinline bool MeasureThunkTable(const VIEW & view, DWORD rva, size_t & count_out)
	{
		count_out = 0;
		const MAPPING mapping = MapRva(view, rva);
		if (!mapping.Data || mapping.Available < sizeof(IMAGE_THUNK_DATA64))
		{
			return false;
		}

		const size_t maximum_entries = mapping.Available / sizeof(IMAGE_THUNK_DATA64);
		for (size_t index = 0; index < maximum_entries; ++index)
		{
			const IMAGE_THUNK_DATA64 & thunk = *reinterpret_cast<const IMAGE_THUNK_DATA64 *>(mapping.Data + index * sizeof(IMAGE_THUNK_DATA64));
			if (!thunk.u1.AddressOfData)
			{
				count_out = index;
				return true;
			}

			if (!IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
			{
				if ((thunk.u1.AddressOfData >> 32) != 0)
				{
					return false;
				}
				const MAPPING name_mapping = MapRva(view, static_cast<DWORD>(thunk.u1.AddressOfData));
				if (!name_mapping.Data || name_mapping.Available < sizeof(WORD) || !IsZeroTerminated(name_mapping.Data + sizeof(WORD), name_mapping.Available - sizeof(WORD)))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			const IMAGE_IMPORT_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.Name)
			{
				return true;
			}

			if (!MapRva(view, descriptor.Name).Data)
			{
				return false;
			}

			const DWORD thunk_rva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
			if (!thunk_rva || !ValidateThunkTable(view, thunk_rva))
			{
				return false;
			}

			// FirstThunk is the IAT the resolver writes resolved pointers into.
			// A descriptor with a valid OriginalFirstThunk but FirstThunk == 0
			// passes the ILT check above, yet the loader would write at
			// pImageBase + 0 - the DOS/NT headers. Require a non-zero, in-image
			// IAT as the PE spec mandates. OriginalFirstThunk == 0 descriptors
			// stay valid: FirstThunk is then the thunk_rva checked above, and a
			// bound IAT is never walked here as a name table.
			if (!descriptor.FirstThunk || !RangeWithin(descriptor.FirstThunk, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage))
			{
				return false;
			}

			// The ILT check above proves the name table is fully terminated,
			// but said nothing about the destination IAT beyond its first
			// entry: a truncated IAT (second entry outside the image) passes
			// that check, and the resolver loop then exits at the boundary
			// with a prefix bound while still reporting success. Measure the
			// ILT length and require the whole IAT (entries + terminator) to
			// be in-image for the same count. Bounds-only (no name walk), so
			// a bound IAT carrying addresses instead of thunks is not
			// misread. OriginalFirstThunk == 0 needs no second range: IAT and
			// ILT are the same bytes already validated above.
			if (descriptor.OriginalFirstThunk)
			{
				size_t ilt_count = 0;
				if (!MeasureThunkTable(view, descriptor.OriginalFirstThunk, ilt_count))
				{
					return false;
				}
				const size_t iat_bytes = (ilt_count + 1) * sizeof(IMAGE_THUNK_DATA64);
				if (ilt_count + 1 < ilt_count || !RangeWithin(descriptor.FirstThunk, iat_bytes, view.NtHeaders->OptionalHeader.SizeOfImage))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateDelayImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			const IMAGE_DELAYLOAD_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.DllNameRVA)
			{
				return true;
			}

			// ImportAddressTableRVA is the delay IAT the resolver writes into,
			// so it must be non-zero and in-image for the same reason as the
			// classic FirstThunk above. ImportNameTableRVA is the read-only
			// name table walked by ValidateThunkTable. The name-table check
			// alone leaves a truncated delay IAT (same prefix-success shape
			// as the classic case), so the full IAT range for the measured
			// name count is required bounds-only below.
			if (!MapRva(view, descriptor.DllNameRVA).Data ||
				!descriptor.ImportAddressTableRVA ||
				!RangeWithin(descriptor.ImportAddressTableRVA, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage) ||
				!descriptor.ImportNameTableRVA ||
				!ValidateThunkTable(view, descriptor.ImportNameTableRVA))
			{
				return false;
			}

			{
				size_t name_count = 0;
				if (!MeasureThunkTable(view, descriptor.ImportNameTableRVA, name_count))
				{
					return false;
				}
				const size_t iat_bytes = (name_count + 1) * sizeof(IMAGE_THUNK_DATA64);
				if (name_count + 1 < name_count || !RangeWithin(descriptor.ImportAddressTableRVA, iat_bytes, view.NtHeaders->OptionalHeader.SizeOfImage))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateExports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			return false;
		}

		const IMAGE_EXPORT_DIRECTORY & exports = *reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(mapping.Data);
		if (!exports.NumberOfFunctions || !exports.NumberOfNames || !exports.AddressOfFunctions || !exports.AddressOfNames || !exports.AddressOfNameOrdinals)
		{
			return false;
		}

		const MAPPING functions = MapRva(view, exports.AddressOfFunctions);
		const MAPPING names = MapRva(view, exports.AddressOfNames);
		const MAPPING ordinals = MapRva(view, exports.AddressOfNameOrdinals);
		const size_t function_bytes = static_cast<size_t>(exports.NumberOfFunctions) * sizeof(ULONG);
		const size_t name_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(ULONG);
		const size_t ordinal_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(USHORT);
		if (!functions.Data || !names.Data || !ordinals.Data || function_bytes > functions.Available || name_bytes > names.Available || ordinal_bytes > ordinals.Available)
		{
			return false;
		}

		for (DWORD index = 0; index < exports.NumberOfNames; ++index)
		{
			const DWORD name_rva = *reinterpret_cast<const DWORD *>(names.Data + index * sizeof(DWORD));
			const USHORT ordinal = *reinterpret_cast<const USHORT *>(ordinals.Data + index * sizeof(USHORT));
			if (!name_rva || ordinal >= exports.NumberOfFunctions || !MapRva(view, name_rva).Data)
			{
				return false;
			}
		}

		return true;
	}

	__forceinline bool ValidateRelocations(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size)
		{
			return false;
		}

		size_t offset = 0;
		while (offset < directory.Size)
		{
			if (directory.Size - offset < sizeof(IMAGE_BASE_RELOCATION))
			{
				return false;
			}

			const IMAGE_BASE_RELOCATION & block = *reinterpret_cast<const IMAGE_BASE_RELOCATION *>(mapping.Data + offset);
			if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block.SizeOfBlock > directory.Size - offset || (block.SizeOfBlock & 1))
			{
				return false;
			}

			const size_t entry_count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			const WORD * entries = reinterpret_cast<const WORD *>(mapping.Data + offset + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t index = 0; index < entry_count; ++index)
			{
				const WORD type = entries[index] >> 12;
				if (type == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}
				if (type != IMAGE_REL_BASED_DIR64)
				{
					return false;
				}

				// 64-bit add: the 32-bit form wraps (0xFFFFFF00+0xFFF -> 0xFF)
				// and a wrapped small value passes the bound check while the
				// shell (ULONGLONG math) rejects it - validator/shell
				// divergence. Widen first, then compare. No new import/syscall.
				const ULONGLONG patch_rva = static_cast<ULONGLONG>(block.VirtualAddress) + static_cast<ULONGLONG>(entries[index] & 0x0FFF);
				// Guard the subtraction: SizeOfImage < sizeof(ULONG_PTR) would
				// wrap to a huge bound and disable the check entirely.
				if (view.NtHeaders->OptionalHeader.SizeOfImage < sizeof(ULONG_PTR) ||
					patch_rva > static_cast<ULONGLONG>(view.NtHeaders->OptionalHeader.SizeOfImage - sizeof(ULONG_PTR)))
				{
					return false;
				}
			}

			offset += block.SizeOfBlock;
		}

		return offset == directory.Size;
	}

	__forceinline DWORD Validate(const BYTE * data, size_t size, DWORD target_machine, const OPTIONS & options, VIEW & view)
	{
		if (!data || size < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DOS_HEADER & dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER *>(data);
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t nt_offset = static_cast<size_t>(dos_header.e_lfanew);
		if (!RangeWithin(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64), size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_NT_HEADERS64 & nt_headers = *reinterpret_cast<const IMAGE_NT_HEADERS64 *>(data + nt_offset);
		if (nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.FileHeader.Machine != target_machine || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (nt_headers.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) || !RangeWithin(nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), nt_headers.FileHeader.SizeOfOptionalHeader, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const WORD section_count = nt_headers.FileHeader.NumberOfSections;
		if (!section_count || section_count > MAX_SECTION_COUNT)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t section_table_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader;
		const size_t section_table_size = static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER);
		const DWORD file_alignment = nt_headers.OptionalHeader.FileAlignment;
		const DWORD section_alignment = nt_headers.OptionalHeader.SectionAlignment;
		const DWORD size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders;
		const DWORD size_of_image = nt_headers.OptionalHeader.SizeOfImage;

		if (nt_headers.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
			!IsPowerOfTwo(file_alignment) || file_alignment < 0x200 || file_alignment > 0x10000 ||
			!IsPowerOfTwo(section_alignment) || section_alignment < file_alignment || section_alignment > 0x10000 ||
			!IsAligned(size_of_headers, file_alignment) || !IsAligned(size_of_image, section_alignment) ||
			!size_of_headers || size_of_headers > size || size_of_headers > size_of_image || size_of_headers > MAX_IMAGE_SIZE || size_of_image > MAX_IMAGE_SIZE ||
			!RangeWithin(nt_offset, section_table_offset - nt_offset + section_table_size, size_of_headers) ||
			!RangeWithin(section_table_offset, section_table_size, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireDll && !(nt_headers.FileHeader.Characteristics & IMAGE_FILE_DLL))
		{
			return FILE_ERR_INVALID_FILE;
		}

		if (nt_headers.OptionalHeader.AddressOfEntryPoint >= size_of_image ||
			nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_SECTION_HEADER * sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(data + section_table_offset);
		view.Data = data;
		view.Size = size;
		view.NtHeaders = &nt_headers;
		view.Sections = sections;

		for (WORD index = 0; index < section_count; ++index)
		{
			const IMAGE_SECTION_HEADER & section = sections[index];
			const ULONGLONG section_span = (std::max)(static_cast<ULONGLONG>(section.Misc.VirtualSize), static_cast<ULONGLONG>(section.SizeOfRawData));
			const ULONGLONG section_end = static_cast<ULONGLONG>(section.VirtualAddress) + section_span;
			if (!section.VirtualAddress || !IsAligned(section.VirtualAddress, section_alignment) || section_end > size_of_image)
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}

			// Headers occupy image [0, size_of_headers). A section mapped at
			// VirtualAddress < size_of_headers would be copied over the just
			// written headers by MMI_MapSections and subsequently trusted
			// (NT headers re-read from the overwritten copy). Reject any
			// virtual overlap with the headers outright. Pure integer check:
			// no syscall, import, or timing surface.
			if (static_cast<ULONGLONG>(section.VirtualAddress) < static_cast<ULONGLONG>(size_of_headers))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}

			if (section.SizeOfRawData)
			{
				if (!IsAligned(section.PointerToRawData, file_alignment) || section.PointerToRawData < size_of_headers || !RangeWithin(section.PointerToRawData, section.SizeOfRawData, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}

			// Pairwise overlap: virtual ranges [VirtualAddress, end) must be
			// disjoint (a later section would otherwise overwrite an earlier
			// one, including its import tables), and file ranges
			// [PointerToRawData, +SizeOfRawData) must be disjoint (shared
			// file bytes mapped to two RVAs break the header trust above).
			// section_count <= 96 so O(n^2) is bounded; ULONGLONG math cannot
			// wrap (both ends already proven <= size_of_image / size).
			for (WORD prior = 0; prior < index; ++prior)
			{
				const IMAGE_SECTION_HEADER & other = sections[prior];
				const ULONGLONG other_span = (std::max)(static_cast<ULONGLONG>(other.Misc.VirtualSize), static_cast<ULONGLONG>(other.SizeOfRawData));
				const ULONGLONG other_end = static_cast<ULONGLONG>(other.VirtualAddress) + other_span;
				if (static_cast<ULONGLONG>(section.VirtualAddress) < other_end &&
					static_cast<ULONGLONG>(other.VirtualAddress) < section_end)
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}

				if (section.SizeOfRawData && other.SizeOfRawData)
				{
					const ULONGLONG raw_end = static_cast<ULONGLONG>(section.PointerToRawData) + section.SizeOfRawData;
					const ULONGLONG other_raw_end = static_cast<ULONGLONG>(other.PointerToRawData) + other.SizeOfRawData;
					if (static_cast<ULONGLONG>(section.PointerToRawData) < other_raw_end &&
						static_cast<ULONGLONG>(other.PointerToRawData) < raw_end)
					{
						return FILE_ERR_INVALID_PE_LAYOUT;
					}
				}
			}
		}

		for (DWORD index = 0; index < nt_headers.OptionalHeader.NumberOfRvaAndSizes; ++index)
		{
			const IMAGE_DATA_DIRECTORY & directory = nt_headers.OptionalHeader.DataDirectory[index];
			if (!directory.Size)
			{
				continue;
			}

			if (index == IMAGE_DIRECTORY_ENTRY_SECURITY)
			{
				if (!RangeWithin(directory.VirtualAddress, directory.Size, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}
			else if (!RangeWithin(directory.VirtualAddress, directory.Size, size_of_image))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		const IMAGE_DATA_DIRECTORY & load_config = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		if (load_config.Size && load_config.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		const IMAGE_DATA_DIRECTORY & exceptions = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (exceptions.Size && exceptions.Size % sizeof(RUNTIME_FUNCTION))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		if (options.EnableExceptions && !exceptions.Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DATA_DIRECTORY & tls = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tls.Size)
		{
			const MAPPING tls_mapping = MapRva(view, tls.VirtualAddress);
			if (tls.Size < sizeof(IMAGE_TLS_DIRECTORY) || !tls_mapping.Data || tls_mapping.Available < sizeof(IMAGE_TLS_DIRECTORY))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		if (options.RequireExports && !ValidateExports(view))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireRelocations && !ValidateRelocations(view))
		{
			return FILE_ERR_RELOCATIONS_REQUIRED;
		}

		if ((options.ResolveImports && !ValidateImports(view)) || (options.ResolveDelayImports && !ValidateDelayImports(view)))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		return FILE_ERR_SUCCESS;
	}
}
