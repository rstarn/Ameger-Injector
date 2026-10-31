
#include "Core/Utility/Header/PrecompiledHeader.h"

#include <TlHelp32.h>
#include <intrin.h>
#include <cstdio>

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection/ManualMapping/ManualMappingCore.h"

using namespace NATIVE;
using namespace MMAP_NATIVE;

namespace
{

	MAP_STATS g_LastMapStats{};
	VERIFIABLE_EXEC_TELEMETRY g_LastExecTelemetry{};




	bool WriteRemoteExact(HANDLE hTargetProc, void * address, const void * buffer, SIZE_T size)
	{
		if (!hTargetProc || !address || !buffer || !size)
		{
			return false;
		}

		SIZE_T written = 0;
		if (!ScWriteProcessMemory(hTargetProc, address, buffer, size, &written))
		{
			return false;
		}
		return written == size;
	}

	void StoreMapStats(const MAP_STATS & Src)
	{
		static_assert(sizeof(MAP_STATS) % sizeof(LONG) == 0, "MAP_STATS must be a whole number of LONGs");





		MAP_STATS copy{};
		copy = Src;

		LONG * dst = ReCa<LONG *>(&g_LastMapStats);
		const LONG * src = ReCa<const LONG *>(&copy);
		for (size_t i = 0; i < sizeof(MAP_STATS) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadMapStats(MAP_STATS & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_LastMapStats);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(MAP_STATS) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	void StoreExecTelemetry(const VERIFIABLE_EXEC_TELEMETRY & Src)
	{
		static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0, "telemetry must be LONG-multiple");



		VERIFIABLE_EXEC_TELEMETRY copy{};
		copy = Src;

		LONG * dst = ReCa<LONG *>(&g_LastExecTelemetry);
		const LONG * src = ReCa<const LONG *>(&copy);
		for (size_t i = 0; i < sizeof(VERIFIABLE_EXEC_TELEMETRY) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadExecTelemetry(VERIFIABLE_EXEC_TELEMETRY & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&g_LastExecTelemetry);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(VERIFIABLE_EXEC_TELEMETRY) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
	}

	constexpr SIZE_T kScrubChunk = 0x100000;

















	bool ResolveRemoteNtdllBaseFromModuleList(DWORD target_pid, ULONG_PTR & base_out)
	{
		base_out = 0;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
		if (snapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		MODULEENTRY32W entry{};
		entry.dwSize = sizeof(entry);
		bool found = false;
		if (Module32FirstW(snapshot, &entry))
		{
			do
		 {
				if (_wcsicmp(entry.szModule, L"ntdll.dll") == 0)
				{
					base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
					found = base_out != 0;
					break;
				}
			} while (Module32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return found;
	}

	bool ResolveRemoteNtdllBase(HANDLE hTargetProc, ULONG_PTR & base_out)
	{
		base_out = 0;

		PROCESS_BASIC_INFORMATION basic{ };
		const NTSTATUS basic_status = ScNtQueryInformationProcess(hTargetProc,
			PROCESSINFOCLASS::ProcessBasicInformation, &basic, sizeof(basic), nullptr);
		if (NT_FAIL(basic_status) || !basic.pPEB)
		{
			LOG(1, "ResolveRemoteNtdllBase: The Process Basic Information Query Failed (Status = %08X | PEB = %p)\n",
				static_cast<unsigned>(basic_status), basic.pPEB);
			return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
		}

		const DYNAMIC_NT_OFFSETS & dyno = g_DynamicOffsets;

		const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
		const DWORD ldr_base_offset = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
		const DWORD ldr_name_offset = dyno.LdrEntryBaseDllName ? dyno.LdrEntryBaseDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, BaseDllName));

		if (peb_ldr_offset + sizeof(void *) > 0x800 ||
			ldr_base_offset + sizeof(void *) > 0x800 ||
			ldr_name_offset + sizeof(UNICODE_STRING) > 0x800)
		{
			return false;
		}

		PEB_LDR_DATA * ldr = nullptr;


		if (!ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(basic.pPEB) + peb_ldr_offset, &ldr, sizeof(void *), nullptr) || !ldr)
		{
			LOG(1, "ResolveRemoteNtdllBase: The Loader Pointer Could Not Be Read (PEB = %p | Offset = %08X)\n",
				basic.pPEB, peb_ldr_offset);
			return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
		}

		LIST_ENTRY head{ };
		if (!ScReadProcessMemory(hTargetProc, &ldr->InLoadOrderModuleListHead, &head, sizeof(head), nullptr))
		{
			LOG(1, "ResolveRemoteNtdllBase: The Loader List Head Could Not Be Read (Ldr = %p)\n", ldr);
			return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
		}



		const LIST_ENTRY * head_address = &ldr->InLoadOrderModuleListHead;
		LIST_ENTRY * current = head.Flink;
		ULONG depth = 0;

		for (; current && current != head_address && depth < 4096; ++depth)
		{
			LIST_ENTRY link{ };
			if (!ScReadProcessMemory(hTargetProc, current, &link, sizeof(link), nullptr))
			{
				LOG(1, "ResolveRemoteNtdllBase: A Loader List Link Could Not Be Read (Depth = %lu | Address = %p)\n",
					static_cast<unsigned long>(depth), current);
				return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
			}



			const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);

			UNICODE_STRING name{ };
			if (ScReadProcessMemory(hTargetProc, entry + ldr_name_offset, &name, sizeof(name), nullptr) &&
				name.Length == sizeof(L"ntdll.dll") - sizeof(wchar_t) && name.szBuffer)
			{
				wchar_t buffer[16]{ 0 };
				if (ScReadProcessMemory(hTargetProc, name.szBuffer, buffer, sizeof(L"ntdll.dll"), nullptr) &&
					_wcsicmp(buffer, L"ntdll.dll") == 0)
				{
					ULONG_PTR base = 0;
					if (!ScReadProcessMemory(hTargetProc, entry + ldr_base_offset, &base, sizeof(base), nullptr))
					{
						return false;
					}

					base_out = base;

					return base_out != 0;
				}
			}

			current = link.Flink;
		}

		LOG(1, "ResolveRemoteNtdllBase: The Loader List Was Walked Without Finding ntdll (Depth = %lu)\n",
			static_cast<unsigned long>(depth));
		return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
	}







	static void Hex16(const BYTE * b, char * out)
	{
		for (int i = 0; i < 16; ++i)
		{
			snprintf(out + i * 2, 3, "%02X", b[i]);
		}
		out[32] = 0;
	}

	DWORD HostMapRemoteImage(HANDLE hTargetProc, const INJECTION_SOURCE & source, const PE_IMAGE::VIEW & view,
		MANUAL_MAPPING_DATA & data, void *& base_out, ERROR_DATA & error_data)
	{
		base_out = nullptr;

		const IMAGE_NT_HEADERS * nt = view.NtHeaders;
		if (!nt || !source.RawData || !source.RawSize)
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		const DWORD size_of_image = nt->OptionalHeader.SizeOfImage;
		const DWORD size_of_headers = nt->OptionalHeader.SizeOfHeaders;
		const ULONG_PTR preferred_base = static_cast<ULONG_PTR>(nt->OptionalHeader.ImageBase);

		if (!size_of_image || size_of_image > PE_IMAGE::MAX_IMAGE_SIZE ||
			size_of_headers > size_of_image || size_of_headers > source.RawSize)
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		const unsigned __int64 map_t0 = __rdtsc();





		// Vector 1: page-file-backed section with dual RW/RX views (keep private-map as fallback)
		void * view_rw = nullptr;   // PAGE_READWRITE view: payload build/write surface (never executable)
		void * view_rx = nullptr;   // PAGE_EXECUTE_READ view: execution surface
		NTSTATUS alloc_status = STATUS_SUCCESS;
		bool section_mapped = false;

		{
			HANDLE section_handle = NULL;
			OBJECT_ATTRIBUTES section_attrs{};
			section_attrs.Length = sizeof(OBJECT_ATTRIBUTES);

			LARGE_INTEGER max_size{};
			max_size.QuadPart = static_cast<LONGLONG>(size_of_image);

			// Page-file section (SEC_COMMIT, NOT SEC_IMAGE / NOT a file), max protection RWX
			alloc_status = ScNtCreateSection(&section_handle, SECTION_ALL_ACCESS, &section_attrs,
				&max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

			if (NT_SUCCESS(alloc_status) && section_handle)
			{
				LOG(1, "Host Map: [+] NtCreateSection: status=0x%08X handle=0x%08X maxsize=0x%08X\n",
					static_cast<unsigned>(alloc_status),
					static_cast<unsigned>(reinterpret_cast<uintptr_t>(section_handle) & 0xFFFFFFFF),
					static_cast<unsigned>(max_size.QuadPart));

				// Single writable+executable view (PAGE_EXECUTE_READWRITE). The shell executes its
				// code and writes its internal .data/.bss globals through this one view, so it must
				// be RWX during setup; MMI_SetPageProtections flips it to PAGE_EXECUTE_READ at the
				// end of the shell (final VAD: MEM_MAPPED + PAGE_EXECUTE_READ = Vector 1).
				void * base_view = nullptr;
				SIZE_T view_size = size_of_image;
				// Single-view: AllocationType=0, InheritDisposition=2 (ViewUnmap).
				const NTSTATUS m1 = ScNtMapViewOfSection(section_handle, hTargetProc, &base_view, 0, view_size, nullptr, &view_size, 2, 0, PAGE_EXECUTE_READWRITE);

				// Track B step 7: query the section's actual attributes (SectionBasicInformation) —
				// answers whether the section is actually committed to its full size.
				{
					SECTION_BASIC_INFORMATION sec_info{};
					ULONG ret_len = 0;
					const NTSTATUS q_status = ScNtQuerySection(section_handle,
						SECTION_INFORMATION_CLASS::SectionBasicInformation, &sec_info, sizeof(sec_info), &ret_len);
					LOG(1, "Host Map: [i] NtQuerySection: status=0x%08X | Base=0x%llX | Attribute=0x%llX | MaximumSize=0x%llX | PageProtection=0x%08X | AllocAttributes=0x%08X\n",
						static_cast<unsigned>(q_status),
						static_cast<unsigned long long>(sec_info.BaseAddress.QuadPart),
						static_cast<unsigned long long>(sec_info.Attribute.QuadPart),
						static_cast<unsigned long long>(sec_info.MaximumSize.QuadPart),
						static_cast<unsigned>(sec_info.PageProtection),
						static_cast<unsigned>(sec_info.Attributes));
				}

				// Close the section handle immediately after both views are mapped
				ScNtClose(section_handle);

				// The section handle was closed right after mapping, so any residual handle
				// (Vector 1 verifier step 3) sees 0 section handles in the target.
				if (NT_SUCCESS(m1) && base_view)
				{
					view_rw = base_view;
					view_rx = base_view;
					section_mapped = true;

					LOG(1, "Host Map: [+] Section Mapped (Single RWX View = %p | Size = 0x%X)\n",
						base_view, size_of_image);
					// The view is RWX only during shell setup; the shell flips it to
					// PAGE_EXECUTE_READ at MMI_SetPageProtections (documented residual window).
					LOG(1, "[!] Section View RWX During Shell Setup — Flipped To RX At MMI_SetPageProtections; Window Is Milliseconds\n");
				}
				else
				{
					// Track B step 8 — the RWX max-protection pagefile section was rejected by the
					// kernel. Recreate with PAGE_READWRITE max protection + SEC_COMMIT and map a
					// single RW view (remap-to-RX deviation).
					LOG(1, "Host Map: [i] Section Map Failed (RWX=0x%08X) — PAGE_READWRITE Sanity Check (Step 8)\n",
						static_cast<unsigned>(m1));

					OBJECT_ATTRIBUTES section_attrs_rw{};
					section_attrs_rw.Length = sizeof(OBJECT_ATTRIBUTES);
					LARGE_INTEGER max_size_rw{};
					max_size_rw.QuadPart = static_cast<LONGLONG>(size_of_image);
					const NTSTATUS alloc_rw = ScNtCreateSection(&section_handle, SECTION_ALL_ACCESS, &section_attrs_rw,
						&max_size_rw, PAGE_READWRITE, SEC_COMMIT, nullptr);

					if (NT_SUCCESS(alloc_rw) && section_handle)
					{
						void * base_rw2 = nullptr;
						SIZE_T view_size_rw2 = size_of_image;
						// Single RW view of the PAGE_READWRITE section; AllocationType=0, InheritDisposition=2 (ViewUnmap).
						const NTSTATUS m_rw = ScNtMapViewOfSection(section_handle, hTargetProc, &base_rw2, 0, view_size_rw2, nullptr, &view_size_rw2, 2, 0, PAGE_READWRITE);

						{
							SECTION_BASIC_INFORMATION sec_info_rw{};
							ULONG ret_len = 0;
							const NTSTATUS q_rw = ScNtQuerySection(section_handle,
								SECTION_INFORMATION_CLASS::SectionBasicInformation, &sec_info_rw, sizeof(sec_info_rw), &ret_len);
							LOG(1, "Host Map: [i] NtQuerySection (RW retry): status=0x%08X | MaximumSize=0x%llX | PageProtection=0x%08X | AllocAttributes=0x%08X\n",
								static_cast<unsigned>(q_rw),
								static_cast<unsigned long long>(sec_info_rw.MaximumSize.QuadPart),
								static_cast<unsigned>(sec_info_rw.PageProtection),
								static_cast<unsigned>(sec_info_rw.Attributes));
						}

						ScNtClose(section_handle);
						section_handle = NULL;

						if (NT_SUCCESS(m_rw) && base_rw2)
						{
							// PAGE_READWRITE max protection accepted → SEC_COMMIT + PAGE_EXECUTE_READWRITE
							// is being rejected by the kernel. Remap-to-RX deviation: the single RW view
							// is promoted to RX on the remote side by MMI_SetExecProtections at execution.
							view_rw = base_rw2;
							view_rx = base_rw2;   // same base; RX promotion deferred to the execute step
							section_mapped = true;
							LOG(1, "Host Map: [+] PAGE_READWRITE Retry Succeeded — RWX Max Protection Rejected; Remap-to-RX Deviation\n");
						}
						else
						{
							LOG(1, "Host Map: [!] RW Retry Map Failed (map=0x%08X) — MEM_PRIVATE Fallback Engaged; Vector 1 Unverified\n",
								static_cast<unsigned>(m_rw));
						}
					}
					else
					{
						LOG(1, "Host Map: [!] RW Retry Section Create Failed (0x%08X) — MEM_PRIVATE Fallback Engaged; Vector 1 Unverified\n",
							static_cast<unsigned>(alloc_rw));
					}
					// If section_mapped stays false, flow continues to the private-map path below.
				}
			}
			else
			{
				// Vector 1: NtCreateSection failed — log the MEM_PRIVATE fallback and continue (not silent).
				LOG(1, "Host Map: [!] NtCreateSection Failed (0x%08X) — MEM_PRIVATE Fallback Engaged; Vector 1 Unverified\n",
					static_cast<unsigned>(alloc_status));
				// section_mapped stays false; flow continues to the private-map path below.
			}
		}

		void * remote_base;
		if (section_mapped)
		{
			remote_base = view_rx;   // shell executes from the RX view
		}
		else
		{
			// Fallback: existing private-map path (detectable MEM_PRIVATE)
			view_rw = view_rx = nullptr;
			remote_base = ReCa<void *>(preferred_base);
			SIZE_T remote_size = size_of_image;
			alloc_status = ScNtAllocateVirtualMemory(hTargetProc, &remote_base, 0, &remote_size,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (NT_FAIL(alloc_status) || !remote_base)
			{
				remote_base = nullptr;
				remote_size = size_of_image;
				alloc_status = ScNtAllocateVirtualMemory(hTargetProc, &remote_base, 0, &remote_size,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}

			if (NT_FAIL(alloc_status) || !remote_base)
			{
				INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

				LOG(1, "Host Map: Image Allocation Failed = %08X\n", static_cast<unsigned>(alloc_status));

				return INJ_MM_ERR_MEMORY_ALLOCATION_FAILED;
			}

			LOG(1, "Host Map: [!] Section Mapping Unavailable; Private-Mem Fallback Engaged (MEM_PRIVATE, Detectable)\n");
		}

		// Guard only the RW view (section path); on the private path guard the allocated base.
		void * guarded_base = section_mapped ? view_rw : remote_base;
		RemoteAllocation image_guard(hTargetProc, guarded_base);

		std::vector<BYTE> image;
		try
		{
			image.assign(size_of_image, 0);
		}
		catch (const std::bad_alloc &)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			return INJ_ERR_OUT_OF_MEMORY_NEW;
		}

		auto wipe_guard = MakeScopeExit([&]() noexcept {
			if (!image.empty())
			{
				SecureZeroMemory(image.data(), image.size());
			}
		});

		memcpy(image.data(), source.RawData, size_of_headers);

		auto * mapped_dos = ReCa<IMAGE_DOS_HEADER *>(image.data());
		if (mapped_dos->e_magic != IMAGE_DOS_SIGNATURE ||
			mapped_dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
			static_cast<size_t>(mapped_dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size_of_headers)
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * mapped_nt = ReCa<IMAGE_NT_HEADERS *>(image.data() + mapped_dos->e_lfanew);
		const WORD section_count = mapped_nt->FileHeader.NumberOfSections;
		auto * mapped_sections = IMAGE_FIRST_SECTION(mapped_nt);

		for (WORD i = 0; i < section_count; ++i)
		{
			IMAGE_SECTION_HEADER & section = mapped_sections[i];

			if (section.SizeOfRawData)
			{
				if (section.PointerToRawData > source.RawSize ||
					section.SizeOfRawData > source.RawSize - section.PointerToRawData ||
					section.VirtualAddress > size_of_image ||
					section.SizeOfRawData > size_of_image - section.VirtualAddress)
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				memcpy(image.data() + section.VirtualAddress,
					source.RawData + section.PointerToRawData, section.SizeOfRawData);
			}



		}

		const ULONG_PTR remote_address = ReCa<ULONG_PTR>(remote_base);
		const ULONG_PTR delta = remote_address - preferred_base;
		DWORD reloc_applied = 0;

		if (delta)
		{
			const IMAGE_DATA_DIRECTORY & reloc =
				mapped_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			if (reloc.Size < sizeof(IMAGE_BASE_RELOCATION) ||
				reloc.VirtualAddress > size_of_image ||
				reloc.Size > size_of_image - reloc.VirtualAddress)
			{
				return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
			}

			BYTE * cursor = image.data() + reloc.VirtualAddress;
			const BYTE * reloc_end = cursor + reloc.Size;

			while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end)
			{
				auto * block = ReCa<IMAGE_BASE_RELOCATION *>(cursor);

				if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
					block->SizeOfBlock > static_cast<DWORD>(reloc_end - cursor) ||
					((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0)
				{
					return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
				}

				const UINT entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto * entries = ReCa<WORD *>(block + 1);

				for (UINT i = 0; i < entry_count; ++i)
				{
					if ((entries[i] >> 12) != IMAGE_REL_BASED_DIR64)
					{
						continue;
					}

					const ULONGLONG patch_rva =
						static_cast<ULONGLONG>(block->VirtualAddress) + (entries[i] & 0x0FFF);

					if (patch_rva + sizeof(ULONG_PTR) > size_of_image)
					{
						return INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED;
					}

					ULONG_PTR value = 0;
					memcpy(&value, image.data() + patch_rva, sizeof(value));
					value += delta;
					memcpy(image.data() + patch_rva, &value, sizeof(value));
					++reloc_applied;
				}

				cursor += block->SizeOfBlock;
			}
		}

		mapped_nt->OptionalHeader.ImageBase = remote_address;

		if ((data.Flags & INJ_MM_INIT_SECURITY_COOKIE) &&
			mapped_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size)
		{
			const IMAGE_DATA_DIRECTORY & load_config =
				mapped_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];






			const SIZE_T cookie_span = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR);
			if (load_config.Size < cookie_span ||
				load_config.VirtualAddress > size_of_image ||
				cookie_span > size_of_image - load_config.VirtualAddress)
			{
				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			auto * pLoadConfig = ReCa<IMAGE_LOAD_CONFIG_DIRECTORY *>(image.data() + load_config.VirtualAddress);

			if (pLoadConfig->SecurityCookie)
			{
				ULONGLONG new_cookie = remote_address & 0x0000FFFFFFFFFFFFULL;
				if (new_cookie == 0x2B992DDFA232ULL)
				{
					++new_cookie;
				}
				else if (!(new_cookie & 0x0000FFFF00000000ULL))
				{
					new_cookie |= (new_cookie | 0x4711ULL) << 0x10;
				}

				const ULONG_PTR cookie_va = static_cast<ULONG_PTR>(pLoadConfig->SecurityCookie);
				const ULONG_PTR image_end = remote_address + size_of_image;

				if (cookie_va < remote_address || cookie_va >= image_end ||
					image_end - cookie_va < sizeof(ULONG_PTR))
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				memcpy(image.data() + (cookie_va - remote_address), &new_cookie, sizeof(new_cookie));
			}
		}

		data.CachedSizeOfImage = size_of_image;
		data.CachedSizeOfHeaders = size_of_headers;
		data.CachedEntryPoint = mapped_nt->OptionalHeader.AddressOfEntryPoint;

		const DWORD cached_sections = section_count > MM_MAX_CACHED_SECTIONS ? MM_MAX_CACHED_SECTIONS : section_count;
		data.CachedSectionCount = cached_sections;
		memcpy(data.CachedSections, mapped_sections, cached_sections * sizeof(IMAGE_SECTION_HEADER));
		memcpy(data.CachedDataDirectory, mapped_nt->OptionalHeader.DataDirectory, sizeof(data.CachedDataDirectory));

		// Write the payload into the RW view (never executable). On the private fallback, write into the allocated base.
		void * write_target = section_mapped ? view_rw : remote_base;
		// [DIAG] image write step: which base the payload is written to vs where the shell reads.
		LOG(1, "[DIAG] WriteRemoteExact target = 0x%p, size = 0x%08X, source = 0x%p | RW view = 0x%p, RX view (shell pImageBase) = 0x%p\n",
			write_target, static_cast<unsigned>(size_of_image), (void *)image.data(), view_rw, remote_base);
		if (!WriteRemoteExact(hTargetProc, write_target, image.data(), size_of_image))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Host Map: The Finished Image Could Not Be Written\n");

			return INJ_ERR_WPM_FAIL;
		}

		// CHECK 1: [RELOC] evidence for relocation + entry points, logged before the shell runs.
		{
			const DWORD reloc_dir_size = mapped_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			LOG(1, "[RELOC] PreferredBase=0x%llX ActualBase=0x%llX Delta=0x%llX RelocationsApplied=%u RelocationSectionPresent=%c\n",
				(unsigned long long)preferred_base, (unsigned long long)remote_address, (unsigned long long)delta,
				reloc_applied, reloc_dir_size ? 'Y' : 'N');
			LOG(1, "[RELOC] OriginalEntryPoint=0x%llX ResolvedEntryPoint=0x%llX\n",
				(unsigned long long)mapped_nt->OptionalHeader.AddressOfEntryPoint,
				(unsigned long long)(remote_address + mapped_nt->OptionalHeader.AddressOfEntryPoint));
		}

		data.pAllocationBase = ReCa<BYTE *>(remote_base);
		data.pImageBase = ReCa<BYTE *>(remote_base);
		data.pDosHeader = ReCa<IMAGE_DOS_HEADER *>(remote_base);
		data.pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(remote_address + mapped_dos->e_lfanew);
		data.pOptionalHeader = &data.pNtHeaders->OptionalHeader;
		data.pFileHeader = &data.pNtHeaders->FileHeader;
		data.pSectionRwView = section_mapped ? ReCa<BYTE *>(view_rw) : nullptr;
		data.ExecProtectionState = MM_EXEC_STATE_MAPPABLE;

		const unsigned __int64 map_t1 = __rdtsc();
		data.ExecTelemetry.HostMapCycles = map_t1 >= map_t0 ? (map_t1 - map_t0) : 0;

		base_out = remote_base;
		image_guard.release();

		LOG(1, "Host Map: Image Mapped At %p | Size = %08X | Relocation Delta = 0x%llX\n",
			remote_base, size_of_image, static_cast<unsigned long long>(delta));

		return INJ_ERR_SUCCESS;
	}
}

DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)
{
	LOG(1, "Begin In-Memory Load\n");

	const DWORD os_build = GetOSBuildVersion();
	WINDOWS_LAYOUT_FAMILY layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
	if (!GetSupportedWindowsLayout(os_build, layout_family))
	{
		INIT_ERROR_DATA(error_data, os_build);

		return INJ_ERR_WINDOWS_BUILD_UNSUPPORTED;
	}



	const DWORD remote_flags = Flags;
	INJECTION_SOURCE source = Source;
	PE_IMAGE::VIEW source_view;
	DWORD validation_result = FILE_ERR_SUCCESS;

	try
	{
		validation_result = PE_IMAGE::Validate(source.RawData, source.RawSize, IMAGE_FILE_MACHINE_AMD64, BuildPeValidationOptions(remote_flags), source_view);
	}
	catch (const std::bad_alloc &)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		return INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	if (validation_result != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, validation_result);

		LOG(1, "Strict PE Validation Failed = %08X\n", validation_result);

		return validation_result;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.Flags = remote_flags;
	data.OSBuildNumber = os_build;

	if (!g_DynamicOffsetsReady.load(std::memory_order_acquire))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Dynamic OS Offsets Not Ready, Refusing In-Memory Load\n");

		return INJ_ERR_SYMBOL_INIT_NOT_DONE;
	}
	data.NtOffsets = g_DynamicOffsets;





	void * image_base = nullptr;
	const DWORD map_result = HostMapRemoteImage(hTargetProc, source, source_view, data, image_base, error_data);
	if (map_result != INJ_ERR_SUCCESS)
	{
		return map_result;
	}

	const SIZE_T image_span = static_cast<SIZE_T>(source_view.NtHeaders->OptionalHeader.SizeOfImage);
	RemoteAllocation image_guard(hTargetProc, image_base);
	auto image_cleanup_guard = MakeScopeExit([&]() noexcept {
		if (image_guard.get())
		{
			ScrubRemoteRegion(hTargetProc, image_base, image_span, kScrubChunk);
			image_guard.reset();
		}
	});







	UniqueHandle completion_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
	HANDLE completion_event_remote = nullptr;
	if (completion_event)
	{
		HANDLE duplicated_event = nullptr;
		if (DuplicateHandle(GetCurrentProcess(), completion_event.get(), hTargetProc, &duplicated_event,
			0, FALSE, DUPLICATE_SAME_ACCESS) && duplicated_event)
		{
			completion_event_remote = duplicated_event;
		}
		else
		{
			LOG(1, "[ManualMap] [*] Completion Event Could Not Be Duplicated; Falling Back To State Polling\n");
		}
	}

	data.CompletionEvent = completion_event_remote;



	bool remote_event_owned = completion_event_remote != nullptr;
	auto remote_event_guard = MakeScopeExit([&]() noexcept {
		if (remote_event_owned && completion_event_remote)
		{
			ScNtDuplicateObject(hTargetProc, completion_event_remote, nullptr, nullptr,
				0, 0, DUPLICATE_CLOSE_SOURCE);
		}
	});








	// Tier 2: function scope so the resolved target ntdll base reaches BuildSyscallStubs
	// (it rebases the fake-stack ret gadgets into the target's address space).
	ULONG_PTR remote_ntdll = 0;

	{
		const ULONG_PTR local_ntdll = reinterpret_cast<ULONG_PTR>(g_hNTDLL);
		if (!local_ntdll)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Local ntdll Base Is Unknown; Refusing In-Memory Load\n");

			return INJ_ERR_GET_MODULE_HANDLE_FAIL;
		}

		if (!ResolveRemoteNtdllBase(hTargetProc, remote_ntdll))
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Could Not Resolve The Target's ntdll Base; Refusing In-Memory Load\n");

			return INJ_ERR_GET_MODULE_HANDLE_FAIL;
		}

		if (remote_ntdll != local_ntdll)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Target ntdll Base Mismatch (Local = %p | Target = %p); Refusing In-Memory Load\n",
				ReCa<void *>(local_ntdll), ReCa<void *>(remote_ntdll));

			return INJ_ERR_NTDLL_LAYOUT_MISMATCH;
		}

		LOG(1, "Target ntdll Base Matches The Local Image (%p)\n", ReCa<void *>(local_ntdll));
	}

	LOG(1, "Shell Data Initialized\n");

	ULONG_PTR ShellSize		= ReCa<ULONG_PTR>(MMAP_SEC_END) - ReCa<ULONG_PTR>(ManualMapping_Shell);

	constexpr SIZE_T kStagePage = 0x1000;

	const DWORD remote_stub_hashes[SC_REMOTE_STUB_COUNT] =
	{
		SC_NtAllocateVirtualMemory,
		SC_NtProtectVirtualMemory,
		SC_NtFreeVirtualMemory,
		SC_NtQueryInformationProcess,
	};





	const SIZE_T stub_table_size	= static_cast<SIZE_T>(SC_REMOTE_STUB_COUNT) * SC_STUB_SIZE_SAMPLED;
	const SIZE_T stub_area_size		= stub_table_size + sizeof(void *);
	const SIZE_T exec_area_size		= static_cast<SIZE_T>(ShellSize) + stub_area_size;

	SIZE_T AllocationSize = 0;
	const SIZE_T allocation_parts[] =
	{
		sizeof(MANUAL_MAPPING_DATA),
		exec_area_size + (kStagePage * 2),
		sizeof(MANUAL_MAPPING_FUNCTION_TABLE) + (kStagePage * 2)
	};

	for (SIZE_T part : allocation_parts)
	{
		if (part > static_cast<SIZE_T>(-1) - AllocationSize)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

			LOG(1, "Allocation Size Overflow\n");

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
	table_local->MMIP_EnableExceptions		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_EnableExceptions)		- mmap_sec_base));
	table_local->MMIP_HandleTLS				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_HandleTLS)				- mmap_sec_base));
	table_local->MMIP_RunTlsCallbacks		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_RunTlsCallbacks)			- mmap_sec_base));
	table_local->MMIP_ExecuteDllMain		= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_ExecuteDllMain)			- mmap_sec_base));
	table_local->MMIP_CleanDataDirectories	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanDataDirectories)	- mmap_sec_base));
	table_local->MMIP_CloakHeader			= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CloakHeader)				- mmap_sec_base));
	table_local->MMIP_CleanUp				= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_CleanUp)					- mmap_sec_base));

	table_local->MMIHP_PreprocessModuleName		= ReCa<decltype(MMIH_PreprocessModuleName)		*>(pShells + (ReCa<BYTE *>(MMIH_PreprocessModuleName)		- mmap_sec_base));
	table_local->MMIHP_LoadModule				= ReCa<decltype(MMIH_LoadModule)				*>(pShells + (ReCa<BYTE *>(MMIH_LoadModule)					- mmap_sec_base));



	{




		// Vector 7: target addresses of the sampler ring + index inside MANUAL_MAPPING_DATA.
		// Both live in pArg (the PAGE_READWRITE MANUAL_MAPPING_DATA region), so the emitted
		// stubs can write them RIP-relatively while pArg is still writable during mapping stages.
		const ULONG_PTR ring_base = reinterpret_cast<ULONG_PTR>(pArg)
			+ offsetof(MANUAL_MAPPING_DATA, ExecTelemetry)
			+ offsetof(VERIFIABLE_EXEC_TELEMETRY, SyscallSamples);
		const ULONG_PTR sysidx_addr = reinterpret_cast<ULONG_PTR>(pArg)
			+ offsetof(MANUAL_MAPPING_DATA, ExecTelemetry)
			+ offsetof(VERIFIABLE_EXEC_TELEMETRY, SyscallSampleIndex);

		BYTE stub_slab[SC_REMOTE_STUB_COUNT * SC_STUB_SIZE_SAMPLED + sizeof(void *)]
		{
			0
		};

		const DWORD Built = BuildSyscallStubs(stub_slab, sizeof(stub_slab), remote_stub_hashes, SC_REMOTE_STUB_COUNT,
			reinterpret_cast<ULONG_PTR>(pStubArea), ring_base, sysidx_addr, &data.ExecTelemetry, remote_ntdll);

		if (Built != SC_REMOTE_STUB_COUNT)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_SYSCALL_RESOLVE_FAILED);

			LOG(1, "Remote Syscall Stubs Only Partially Built = %u/%u\n", Built, SC_REMOTE_STUB_COUNT);

			return INJ_ERR_SYSCALL_STUB_BUILD_FAILED;
		}

		for (DWORD i = 0; i < SC_REMOTE_STUB_COUNT; ++i)
		{
			if (SyscallServiceOfStub(stub_slab + (i * SC_STUB_SIZE_SAMPLED)) == 0)
			{
				continue;
			}

			switch (i)
			{
				case 0: table_local->NtAllocateVirtualMemory	= ReCa<f_NtAllocateVirtualMemory>(pStubArea + i * SC_STUB_SIZE_SAMPLED); break;
				case 1: table_local->NtProtectVirtualMemory	= ReCa<f_NtProtectVirtualMemory>	(pStubArea + i * SC_STUB_SIZE_SAMPLED); break;
				case 2: table_local->NtFreeVirtualMemory		= ReCa<f_NtFreeVirtualMemory>	(pStubArea + i * SC_STUB_SIZE_SAMPLED); break;
				case 3: table_local->NtQueryInformationProcess = ReCa<f_NtQueryInformationProcess>(pStubArea + i * SC_STUB_SIZE_SAMPLED); break;
				default: break;
			}
		}



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

	// CHECK 2: read-back of the shell entry's first 16 bytes vs the on-disk shell function.
	{
		BYTE expected[16];
		memcpy(expected, ReCa<BYTE *>(ManualMapping_Shell), sizeof(expected));

		BYTE actual[16] = { 0 };
		SIZE_T read_back = 0;
		const NTSTATUS rb_status = ScNtReadVirtualMemory(hTargetProc, ReCa<BYTE *>(pShells), actual, sizeof(actual), &read_back);
		const bool rb_match = NT_SUCCESS(rb_status) && read_back == sizeof(actual) &&
			memcmp(expected, actual, sizeof(actual)) == 0;

		char expected_hex[33] = { 0 };
		char actual_hex[33] = { 0 };
		Hex16(expected, expected_hex);
		Hex16(actual, actual_hex);

		LOG(1, "[READBACK] ShellEntry=0x%llX First16=%s\n",
			(unsigned long long)ReCa<ULONG_PTR>(pShells), actual_hex);
		LOG(1, "[READBACK] Expected=%s Match=%c\n", expected_hex, rb_match ? 'Y' : 'N');
	}

	if (!WriteRemoteExact(hTargetProc, pFunctionTable, table_local.get(), sizeof(MANUAL_MAPPING_FUNCTION_TABLE)))

	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "WriteProcessMemory Failed\n");

		return INJ_ERR_WPM_FAIL;
	}

	LOG(1, "Staging Dispatch Written To Memory\n");

	{




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
	// CHECK 1 (line 3): is the shell entry inside the section view?
	{
		const ULONG_PTR shell_entry = ReCa<ULONG_PTR>(pShells);
		const ULONG_PTR section_start = ReCa<ULONG_PTR>(image_base);
		const ULONG_PTR section_end = section_start + static_cast<ULONG_PTR>(image_span);
		const bool shell_in_section = (shell_entry >= section_start && shell_entry < section_end);
		LOG(1, "[RELOC] ShellEntry=0x%llX ShellEntryInSection=%c\n",
			(unsigned long long)shell_entry, shell_in_section ? 'Y' : 'N');
	}

	DWORD dwRet = StartRoutine(hTargetProc, ReCa<f_Routine>(pShells), pArg, remote_flags, remote_ret, Timeout, SponsorThread, SponsorTid, completion_event.get(), error_data);

	LOG(1, "Return From StartRoutine\n");

	if (dwRet != SR_ERR_SUCCESS)
	{
		LOG(1, "StartRoutine Failed = %08X\n", dwRet);

		if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED)
		{






			leak_staging = true;
			image_guard.release();
			allocation_guard.release();
			remote_event_owned = false;







			{
				MAP_STATS Retained{ };
				Retained.RetainedAllocBase = ReCa<ULONG_PTR>(image_base);
				Retained.RetainedAllocSize = static_cast<DWORD>(image_span);
				StoreMapStats(Retained);
			}
		}
		else
		{







			ScrubRemoteRegion(hTargetProc, image_base, image_span, kScrubChunk);
			image_guard.reset();
		}

		return dwRet;

	}




	image_guard.release();
	remote_event_owned = false;

	LOG(1, "Fetching Routine Data\n");

	if (!ScReadProcessMemory(hTargetProc, pAllocBase, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "ReadProcessMemory Failed\n");

		return INJ_ERR_VERIFY_RESULT_FAIL;
	}

	StoreMapStats(data.MapStats);
	StoreExecTelemetry(data.ExecTelemetry);




	{
		const bool event_signaled = completion_event &&
			WaitForSingleObject(completion_event.get(), 0) == WAIT_OBJECT_0;

		if (!completion_event)
		{
			LOG(1, "[ManualMap] [*] Completion Event: Unavailable | State Polling Only\n");
		}
		else if (event_signaled && data.ExecTelemetry.CompletionEventSignaled)
		{
			LOG(1, "[ManualMap] [+] Completion Event: Signaled | NtSetEvent = 0x%08X | Shell Handle Closed\n",
				(unsigned)data.ExecTelemetry.CompletionEventStatus);
		}
		else
		{
			LOG(1, "[ManualMap] [x] Completion Event: Not Signaled | Status = 0x%08X | Shell Exit Path Was Not Reached\n",
				(unsigned)data.ExecTelemetry.CompletionEventStatus);
		}




		if (data.CompletionEvent)
		{
			ScNtDuplicateObject(hTargetProc, data.CompletionEvent, nullptr, nullptr,
				0, 0, DUPLICATE_CLOSE_SOURCE);
		}
	}

	if (data.ExecTelemetry.HostMapCycles)
	{
		LOG(1, "[ManualMap] [+] Host Map: Cycles = %llu | Import Stage = %llu | Delay Stage = %llu | TLS Stage = %llu\n",
			(unsigned long long)data.ExecTelemetry.HostMapCycles,
			(unsigned long long)data.ExecTelemetry.ImportStageCycles,
			(unsigned long long)data.ExecTelemetry.DelayImportStageCycles,
			(unsigned long long)data.ExecTelemetry.TlsStageCycles);
		LOG(1, "[ManualMap] [+] Shell Stages: Exceptions = %llu | TLS Callbacks = %llu | Header Cloak = %llu | Directories = %llu | Protections = %llu\n",
			(unsigned long long)data.ExecTelemetry.ExceptionStageCycles,
			(unsigned long long)data.ExecTelemetry.TlsCallbackStageCycles,
			(unsigned long long)data.ExecTelemetry.HeaderStageCycles,
			(unsigned long long)data.ExecTelemetry.DirectoryStageCycles,
			(unsigned long long)data.ExecTelemetry.ProtectStageCycles);
	}
	else
	{
		LOG(1, "[ManualMap] [x] Host Map Cycles Missing; The Host-Mapped Image Was Not Reported\n");
	}



	if (data.pImageBase && data.CachedSectionCount)
	{
		LOG(1, "[ManualMap] [+] Image Relocation: Base = %p | Sections = %u\n", ReCa<void *>(data.pImageBase), data.CachedSectionCount);
	}
	else
	{
		LOG(1, "[ManualMap] [x] Image Relocation Produced Nothing (Base = %p | Sections = %u)\n",
			ReCa<void *>(data.pImageBase), data.CachedSectionCount);
	}


	if (data.ExecTelemetry.DllMainCyclesDelta == 0)
	{
		LOG(1, "[ManualMap] [*] DllMain: Not Entered (No Entry Point In Image, Or An Earlier Stage Aborted)\n");
	}
	else if (data.ExecTelemetry.DllMainResult == 0)
	{
		LOG(1, "[ManualMap] [x] DllMain: Result = 0 (False) | Win32 = 0x%08X | Cycles = %llu -- Payload Refused To Initialize\n",
			data.ExecTelemetry.DllMainLastWin32Error,
			(unsigned long long)data.ExecTelemetry.DllMainCyclesDelta);
	}
	else
	{
		LOG(1, "[ManualMap] [+] DllMain: Result = 1 | Win32 = 0x%08X | Cycles = %llu\n",
			data.ExecTelemetry.DllMainLastWin32Error,
			(unsigned long long)data.ExecTelemetry.DllMainCyclesDelta);
	}

	if (data.ExecTelemetry.LdrLockStatus == 0 && data.ExecTelemetry.LdrUnlockStatus == 0)
	{
		LOG(1, "[ManualMap] [+] LoaderLock: Lock = 0x%08X | State = %u | Cookie = 0x%llX | Unlock = 0x%08X\n",
			(unsigned)data.ExecTelemetry.LdrLockStatus, data.ExecTelemetry.LoaderLockState,
			(unsigned long long)data.ExecTelemetry.LoaderLockCookie,
			(unsigned)data.ExecTelemetry.LdrUnlockStatus);
	}
	else
	{
		LOG(1, "[ManualMap] [x] LoaderLock NTSTATUS Non-Zero: Lock = 0x%08X | Unlock = 0x%08X | State = %u\n",
			(unsigned)data.ExecTelemetry.LdrLockStatus,
			(unsigned)data.ExecTelemetry.LdrUnlockStatus,
			data.ExecTelemetry.LoaderLockState);
	}

	const bool tls_ok = data.ExecTelemetry.TlsCallbacksConfigured == data.ExecTelemetry.TlsCallbacksExecuted &&
		data.ExecTelemetry.TlsCallbacksFailed == 0;
	LOG(1, "[ManualMap] [%s] TLS: Configured = %u | Executed = %u | Failed = %u | Last = %p\n",
		tls_ok ? "+" : "x",
		data.ExecTelemetry.TlsCallbacksConfigured, data.ExecTelemetry.TlsCallbacksExecuted,
		data.ExecTelemetry.TlsCallbacksFailed, data.ExecTelemetry.TlsLastExecutedAddress);


	const bool seh_ok = data.ExecTelemetry.DynamicTableInstalled || data.ExecTelemetry.InvertedTableInstalled;
	LOG(1, "[ManualMap] [%s] SEH: Dynamic = %d | Inverted = %d | Entry = %p%s\n",
		seh_ok ? "+" : "*",
		(int)data.ExecTelemetry.DynamicTableInstalled, (int)data.ExecTelemetry.InvertedTableInstalled,
		data.ExecTelemetry.InvertedTableEntryBase,
		seh_ok ? "" : " (None Installed - Payload Exceptions Not Covered)");

	if (data.ExecTelemetry.PreSectionSpanWiped == 0)
	{
		LOG(1, "[HeaderCloak] [*] Wipe: Not Executed (Shell Aborted Before Cloak)\n");
	}
	else
	{
		LOG(1, "[HeaderCloak] [+] Wipe: Span = %llu | MZ = %u | PE = %u | Prot = 0x%08X\n", (unsigned long long)data.ExecTelemetry.PreSectionSpanWiped, data.ExecTelemetry.MZRemnantsFound, data.ExecTelemetry.PERemnantsFound, data.ExecTelemetry.PostWipeProtection);
	}

	if (data.SectionProtCount == 0)
	{
		LOG(1, "[ManualMap] [*] PageProtections: Not Applied (Shell Aborted Before Protections)\n");
	}
	else
	{
		LOG(1, "[ManualMap] [+] PageProtections: %u Section Records\n", data.SectionProtCount);
	}

	if (remote_ret != INJ_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, (DWORD)data.ntRet);

		if (remote_ret == INJ_MM_ERR_TLS_CALLBACK_RANGE)
		{
			LOG(1, "TLS Callback #%u Rejected (Address %p)\n",
				data.TlsCallbackIndex, ReCa<void *>(data.TlsCallbackAddress));
		}

		LOG(1, "Shell Failed = %08X\n", remote_ret);

		return remote_ret;
	}

	if (!data.hRet)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(1, "Shell Failed\n");

		return INJ_ERR_FAILED_TO_LOAD_DLL;
	}

	LOG(1, "Shell Returned Successfully\n");

	hOut = data.hRet;

	LOG(1, "ImageBase = %p\n", ReCa<void *>(hOut));

	return INJ_ERR_SUCCESS;
}

#pragma region inlined dependency record functions

__forceinline MM_DEPENDENCY_RECORD * BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle)
{
	if (!head)
	{
		return nullptr;
	}

	if (!(*head))
	{
		*head = NewObject<MM_DEPENDENCY_RECORD>(f);

		if (!(*head))
		{
			return nullptr;
		}

		(*head)->Next = *head;
		(*head)->Prev = *head;
		(*head)->DllHandle = DllHandle;

		return (*head);
	}

	auto next = NewObject<MM_DEPENDENCY_RECORD>(f);
	if (next)
	{
		next->Next			= (*head);
		next->Prev			= (*head)->Prev;

		(*head)->Prev->Next	= next;
		(*head)->Prev		= next;

		next->DllHandle = DllHandle;
	}

	return next;
}

__forceinline MM_DEPENDENCY_RECORD * SearchDependencyRecordByHandle(MM_DEPENDENCY_RECORD * head, HANDLE hDll)
{
	if (!head)
	{
		return nullptr;
	}

	auto cur = head;

	do
	{
		if (cur->DllHandle == hDll)
		{
			return cur;
		}

		cur = cur->Next;
	} while (cur != head);

	return nullptr;
}

__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)
{
	if (!head)
	{
		return;
	}

	while (head->Prev != head)
	{
		auto cur = head->Prev;
		auto prev = cur->Prev;
		auto next = cur->Next;

		prev->Next = next;
		next->Prev = prev;

		f->LdrUnloadDll(cur->DllHandle);
		ScrubFreeObject(f, cur, sizeof(MM_DEPENDENCY_RECORD));
	}

	f->LdrUnloadDll(head->DllHandle);
	ScrubFreeObject(f, head, sizeof(MM_DEPENDENCY_RECORD));
}

__forceinline void FreeDependencyNodeList(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * & head)
{
	if (!head)
	{
		return;
	}

	while (head->Prev != head)
	{
		auto cur = head->Prev;
		cur->Prev->Next = cur->Next;
		cur->Next->Prev = cur->Prev;
		ScrubFreeObject(f, cur, sizeof(MM_DEPENDENCY_RECORD));
	}

	ScrubFreeObject(f, head, sizeof(MM_DEPENDENCY_RECORD));
	head = nullptr;
}

#pragma endregion

#pragma region manual mapping internal helper functions

DWORD __declspec(code_seg(".code$05")) __stdcall MMI_SetExecProtections(MANUAL_MAPPING_DATA * pData, DWORD NewState)
{
	if (!pData || !pData->FunctionTable || !pData->pNtHeaders || !pData->pFileHeader)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	if (pData->ExecProtectionState == NewState)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	const ULONG NewProtect = NewState == MM_EXEC_STATE_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READWRITE;

	auto * pSec = MMI_Sections(pData);
	for (UINT i = 0; i != MMI_SectionCount(pData); ++i, ++pSec)
	{
		if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{
			continue;
		}

		void * base = pData->pImageBase + pSec->VirtualAddress;
		SIZE_T sec_size = pSec->Misc.VirtualSize > pSec->SizeOfRawData ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;

		if (!sec_size)
		{
			continue;
		}

		ULONG old_prot = 0;
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, NewProtect, &old_prot);
		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}

	pData->ExecProtectionState = NewState;

	return INJ_ERR_SUCCESS;
}

bool __declspec(code_seg(".code$11")) __stdcall MMI_FindLoadedModule(MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule)
{
	*hModule = nullptr;

	if (!pData || !pData->FunctionTable || !FullName || !FullName->szBuffer || !FullName->Length)
	{
		return false;
	}

	if (!pData->FunctionTable->NtQueryInformationProcess)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return false;
	}

	if (!Basic.pPEB)
	{
		return false;
	}

	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	const DWORD ldr_name_off = dyno.LdrEntryFullDllName ? dyno.LdrEntryFullDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, FullDllName));
	const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));

	if (ldr_name_off + sizeof(UNICODE_STRING) > 0x800 || ldr_base_off + sizeof(void *) > 0x800)
	{
		return false;
	}

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
	auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

	if (!pLdr)
	{
		return false;
	}

	const LIST_ENTRY * head = &pLdr->InLoadOrderModuleListHead;
	LIST_ENTRY * current = head->Flink;

	for (ULONG depth = 0; current && current != head && depth < 4096; ++depth)
	{
		const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
		const auto * EntryName = ReCa<const UNICODE_STRING *>(entry + ldr_name_off);

		if (EntryName->Length == FullName->Length && EntryName->szBuffer)
		{
			bool equal = true;

			const DWORD chars = FullName->Length / sizeof(wchar_t);
			for (DWORD i = 0; i < chars; ++i)
			{
				wchar_t a = EntryName->szBuffer[i];
				wchar_t b = FullName->szBuffer[i];

				if (a >= L'A' && a <= L'Z')
				{
					a = static_cast<wchar_t>(a - L'A' + L'a');
				}

				if (b >= L'A' && b <= L'Z')
				{
					b = static_cast<wchar_t>(b - L'A' + L'a');
				}

				if (a != b)
				{
					equal = false;
					break;
				}
			}

			if (equal)
			{
				*hModule = ReCa<HINSTANCE>(*ReCa<void * const *>(entry + ldr_base_off));

				return *hModule != nullptr;
			}
		}

		current = current->Flink;
	}

	return false;
}

bool __declspec(code_seg(".code$11")) __stdcall MMI_AddressInLoadedImage(MANUAL_MAPPING_DATA * pData, const void * Address)
{
	if (!pData || !pData->FunctionTable || !pData->FunctionTable->NtQueryInformationProcess || !Address)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)) || !Basic.pPEB)
	{
		return false;
	}

	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
	const DWORD ldr_image_off = dyno.LdrEntrySizeOfImage ? dyno.LdrEntrySizeOfImage : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage));

	if (ldr_base_off + sizeof(void *) > 0x800 || ldr_image_off + sizeof(ULONG) > 0x800)
	{
		return false;
	}

	const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
	auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);

	if (!pLdr)
	{
		return false;
	}

	const ULONG_PTR Target = ReCa<ULONG_PTR>(Address);
	const LIST_ENTRY * head = &pLdr->InLoadOrderModuleListHead;
	LIST_ENTRY * current = head->Flink;

	for (ULONG depth = 0; current && current != head && depth < 4096; ++depth)
	{
		const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
		const ULONG_PTR Base = ReCa<ULONG_PTR>(*ReCa<void * const *>(entry + ldr_base_off));
		const ULONG Size = *ReCa<const ULONG *>(entry + ldr_image_off);

		if (Base && Size && Target >= Base && Target - Base < Size)
		{
			return true;
		}

		current = current->Flink;
	}

	return false;
}

#pragma endregion

#pragma region manual mapping internal helper functions

NTSTATUS __declspec(code_seg(".code$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
{
	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	auto * ModNameA = NewObject<ANSI_STRING>(f);
	if (!ModNameA)
	{
		return STATUS_NO_MEMORY;
	}

	const size_t module_name_length = MMI_ImageStringLength(pData, szModule);
	if (!module_name_length || !InitAnsiString(f, ModNameA, szModule, module_name_length))
	{
		ScrubFreeObject(f, ModNameA, sizeof(ANSI_STRING));

		return STATUS_NO_MEMORY;
	}

	auto * ModNameW = NewObject<UNICODE_STRING>(f);
	if (!ModNameW)
	{
		ScrubFreeObject(f, ModNameA->szBuffer, ModNameA->MaxLength);
		ScrubFreeObject(f, ModNameA, sizeof(ANSI_STRING));

		return STATUS_NO_MEMORY;
	}

	ModNameW->szBuffer	= NewObject<wchar_t>(f, MAX_PATH);
	ModNameW->MaxLength = sizeof(wchar_t[MAX_PATH]);

	if (!ModNameW->szBuffer)
	{
		ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));
		ScrubFreeObject(f, ModNameA->szBuffer, ModNameA->MaxLength);
		ScrubFreeObject(f, ModNameA, sizeof(ANSI_STRING));

		return STATUS_NO_MEMORY;
	}

	ntRet = f->RtlAnsiStringToUnicodeString(ModNameW, ModNameA, FALSE);
	if (NT_FAIL(ntRet))
	{
		ScrubFreeObject(f, ModNameW->szBuffer, sizeof(wchar_t[MAX_PATH]));
		ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));

		ScrubFreeObject(f, ModNameA->szBuffer, ModNameA->MaxLength);
		ScrubFreeObject(f, ModNameA, sizeof(ANSI_STRING));

		return ntRet;
	}

	ScrubFreeObject(f, ModNameA->szBuffer, ModNameA->MaxLength);
	ScrubFreeObject(f, ModNameA, sizeof(ANSI_STRING));

	LDRP_UNICODE_STRING_BUNDLE * pModPathW = NewObject<LDRP_UNICODE_STRING_BUNDLE>(f);
	if (!pModPathW)
	{
		ScrubFreeObject(f, ModNameW->szBuffer, sizeof(wchar_t[MAX_PATH]));
		ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));

		return STATUS_NO_MEMORY;
	}

	pModPathW->String.MaxLength = sizeof(pModPathW->StaticBuffer);
	pModPathW->String.szBuffer	= pModPathW->StaticBuffer;

	ntRet = f->LdrpPreprocessDllName(ModNameW, pModPathW, nullptr, CtxFlags);

	if (NT_SUCCESS(ntRet))
	{

		Module->Length		= pModPathW->String.Length;
		Module->MaxLength	= pModPathW->String.MaxLength;
		Module->szBuffer	= NewObject<wchar_t>(f, Module->MaxLength / sizeof(wchar_t));

		if (!Module->szBuffer)
		{
			ScrubFreeObject(f, pModPathW, sizeof(LDRP_UNICODE_STRING_BUNDLE));
			ScrubFreeObject(f, ModNameW->szBuffer, sizeof(wchar_t[MAX_PATH]));
			ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));

			return STATUS_NO_MEMORY;
		}
		else
		{
			f->memmove(Module->szBuffer, pModPathW->StaticBuffer, Module->Length);
		}
	}
	else
	{
		ScrubFreeObject(f, pModPathW, sizeof(LDRP_UNICODE_STRING_BUNDLE));
		ScrubFreeObject(f, ModNameW->szBuffer, sizeof(wchar_t[MAX_PATH]));
		ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));

		return ntRet;
	}

	ScrubFreeObject(f, pModPathW, sizeof(LDRP_UNICODE_STRING_BUNDLE));
	ScrubFreeObject(f, ModNameW->szBuffer, sizeof(wchar_t[MAX_PATH]));
	ScrubFreeObject(f, ModNameW, sizeof(UNICODE_STRING));

	return STATUS_SUCCESS;
}

NTSTATUS __declspec(code_seg(".code$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
{
	auto f = pData->FunctionTable;
	const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;

	NTSTATUS ntRet = STATUS_SUCCESS;

	void * entry_out = nullptr;

	const DWORD ctx_size = dyno.LdrpPathSearchContextSize ? dyno.LdrpPathSearchContextSize : sizeof(LDRP_PATH_SEARCH_CONTEXT);
	const DWORD ctx_name_off = dyno.LdrpPathSearchOriginalFullDllName;
	void * ctx = NewBytes(f, ctx_size);
	if (!ctx)
	{
		return STATUS_NO_MEMORY;
	}

	if (ctx_name_off + sizeof(void *) <= ctx_size)
	{
		WritePtrField(ctx, ctx_name_off, Module->szBuffer);
	}
	else
	{

		ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx)->OriginalFullDllName = Module->szBuffer;
	}





	f->LdrpLoadDllInternal(Module, ReCa<LDRP_PATH_SEARCH_CONTEXT *>(ctx), CtxFlag, nullptr,
		nullptr, nullptr, ReCa<LDR_DATA_TABLE_ENTRY_WIN11 **>(&entry_out), &ntRet, nullptr);

	ScrubFreeObject(f, ctx, ctx_size);

	if (NT_SUCCESS(ntRet))
	{
		if (entry_out)
		{
			void * dll_base = ReadPtrField(entry_out, dyno.LdrEntryDllBase);
			*hModule = ReCa<HINSTANCE>(dll_base);

			MM_DEPENDENCY_RECORD * entry = nullptr;

			if (head)
			{
				entry = SearchDependencyRecordByHandle(*head, ReCa<HANDLE>(dll_base));
			}

			if (!entry)
			{
				entry = BuildDependencyRecord(f, head, ReCa<HANDLE>(*hModule));

				if (!entry)
				{
					f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));

					return STATUS_NO_MEMORY;
				}
			}

			f->LdrpDereferenceModule(ReCa<LDR_DATA_TABLE_ENTRY *>(entry_out));
		}
		else
		{
			ntRet = STATUS_DLL_NOT_FOUND;
		}
	}

	return ntRet;
}

#pragma endregion














LONG __declspec(code_seg(".code$10")) __stdcall MMI_DebugPrintVeh(PEXCEPTION_POINTERS ExceptionInfo)
{
	EXCEPTION_RECORD * record = ExceptionInfo ? ExceptionInfo->ExceptionRecord : nullptr;

	if (!record || (record->ExceptionFlags & EXCEPTION_NONCONTINUABLE))
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	const DWORD code = record->ExceptionCode;
	if (code == DBG_PRINTEXCEPTION_C || code == DBG_PRINTEXCEPTION_WIDE_C)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}
#define MM_SHELL_EXIT(Result) \
	do { \
		if (pData->DebugPrintVehHandle) \
		{ \
			bool mm_veh_removed = true; \
			if (f->RtlRemoveVectoredExceptionHandler) \
			{ \
				mm_veh_removed = f->RtlRemoveVectoredExceptionHandler(pData->DebugPrintVehHandle) != 0; \
			} \
			if (!mm_veh_removed && pData->pAllocationBase) \
			{ \
				pData->MapStats.RetainedAllocBase = ReCa<ULONG_PTR>(pData->pAllocationBase); \
			} \
			pData->DebugPrintVehHandle = nullptr; \
		} \
		if (pData->CompletionEvent) \
		{ \
			if (f->NtSetEvent) \
			{ \
				LONG mm_event_previous = 0; \
				pData->ExecTelemetry.CompletionEventStatus = f->NtSetEvent(pData->CompletionEvent, &mm_event_previous); \
				pData->ExecTelemetry.CompletionEventSignaled = NT_SUCCESS(pData->ExecTelemetry.CompletionEventStatus) ? 1 : 0; \
			} \
			if (f->NtClose) \
			{ \
				f->NtClose(pData->CompletionEvent); \
			} \
			pData->CompletionEvent = nullptr; \
		} \
		return (Result); \
	} while (0)

#define MM_SHELL_STAGE(Name, Field, Call) \
	do { \
		const unsigned __int64 mm_stage_start = __rdtsc(); \
		const DWORD mm_stage_ret = (Call); \
		const unsigned __int64 mm_stage_end = __rdtsc(); \
		pData->ExecTelemetry.Field = mm_stage_end >= mm_stage_start ? (mm_stage_end - mm_stage_start) : 0; \
		if (mm_stage_ret != INJ_ERR_SUCCESS) \
		{ \
			f->MMIP_CleanUp(pData); \
			MM_SHELL_EXIT(mm_stage_ret); \
		} \
	} while (0)

DWORD __declspec(code_seg(".code$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	auto * f = pData->FunctionTable;

	if (!f->LdrpHeap || !*f->LdrpHeap)
	{
		return INJ_MM_ERR_INVALID_HEAP_HANDLE;
	}




	if (!pData->pAllocationBase || !pData->pImageBase ||
		!pData->CachedSizeOfImage || !pData->CachedSizeOfHeaders ||
		!pData->CachedSectionCount ||
		ReCa<IMAGE_DOS_HEADER *>(pData->pImageBase)->e_magic != IMAGE_DOS_SIGNATURE)
	{
		f->MMIP_CleanUp(pData);

		MM_SHELL_EXIT(INJ_MM_ERR_INVALID_PE_IMAGE);
	}

	pData->pDosHeader		= ReCa<IMAGE_DOS_HEADER *>(pData->pImageBase);
	pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pImageBase + pData->pDosHeader->e_lfanew);
	pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
	pData->pFileHeader		= &pData->pNtHeaders->FileHeader;

	if (f->RtlAddVectoredExceptionHandler && f->RtlRemoveVectoredExceptionHandler)
	{
		pData->DebugPrintVehHandle = f->RtlAddVectoredExceptionHandler(1, MMI_DebugPrintVeh);
		if (pData->DebugPrintVehHandle)
		{
			pData->ExecTelemetry.DebugPrintVehInstalled |= 0x10u;
		}
	}

	MM_SHELL_STAGE("MMI_LoadImports", ImportStageCycles, f->MMIP_LoadImports(pData));
	MM_SHELL_STAGE("MMI_LoadDelayImports", DelayImportStageCycles, f->MMIP_LoadDelayImports(pData));
	MM_SHELL_STAGE("MMI_EnableExceptions", ExceptionStageCycles, f->MMIP_EnableExceptions(pData));
	MM_SHELL_STAGE("MMI_HandleTLS", TlsStageCycles, f->MMIP_HandleTLS(pData));
	MM_SHELL_STAGE("MMI_RunTlsCallbacks", TlsCallbackStageCycles, f->MMIP_RunTlsCallbacks(pData));
	{



		const DWORD dll_main_ret = f->MMIP_ExecuteDllMain(pData);
		if (dll_main_ret != INJ_ERR_SUCCESS)
		{
			f->MMIP_CleanUp(pData);

			MM_SHELL_EXIT(dll_main_ret);
		}
	}



	MM_SHELL_STAGE("MMI_CloakHeader", HeaderStageCycles, f->MMIP_CloakHeader(pData));
	MM_SHELL_STAGE("MMI_CleanDataDirectories", DirectoryStageCycles, f->MMIP_CleanDataDirectories(pData));
	MM_SHELL_STAGE("MMI_SetPageProtections", ProtectStageCycles, f->MMIP_SetPageProtections(pData));

	FreeDependencyNodeList(f, pData->pImportsHead);
	FreeDependencyNodeList(f, pData->pDelayImportsHead);

	pData->hRet = ReCa<HINSTANCE>(pData->pImageBase);

	MM_SHELL_EXIT(INJ_ERR_SUCCESS);
}

#undef MM_SHELL_STAGE
#undef MM_SHELL_EXIT

DWORD __declspec(code_seg(".code$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY	* pImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;







	const bool imports_requested = (pData->Flags & INJ_MM_RESOLVE_IMPORTS) != 0;

	if (!pImportDir->VirtualAddress || pImportDir->Size == 0)
	{
		if (imports_requested)
		{
			pData->ntRet = STATUS_INVALID_IMAGE_FORMAT;

			return INJ_MM_ERR_IMPORT_FAIL;
		}

		return INJ_ERR_SUCCESS;
	}

	IMAGE_IMPORT_DESCRIPTOR * const pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size);

	pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress);

	if (!MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) ||
		!MMI_InImage(pData, pImportDescr, pImportDir->Size))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	bool ErrorBreak = false;

	while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
	{

		auto * szModule = ReCa<const char *>(pData->pImageBase + pImportDescr->Name);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

			if (ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;



		if (!MMI_FindLoadedModule(pData, &ModNameW, &hDll) || !hDll)
		{
			pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pImportsHead);
		}
		else
		{
			pData->ntRet = STATUS_SUCCESS;
		}

		if (NT_FAIL(pData->ntRet))
		{
			ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pImportDescr;

				if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

		if (!pImportDescr->FirstThunk)
		{
			ErrorBreak = true;
			break;
		}

		// Vector 1: derive thunk and IAT pointers from the RW (write) view when active. The shell
		// writes resolved addresses into the IAT, which lives in the never-executable RW view.
		BYTE * iat_base = pData->pSectionRwView ? pData->pSectionRwView : pData->pImageBase;

		IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(iat_base + pImportDescr->OriginalFirstThunk);
		IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(iat_base + pImportDescr->FirstThunk);

		if (!pImportDescr->OriginalFirstThunk)
		{
			pThunk = pIAT;
		}

		{
			const SIZE_T image_size_iat = MMI_SizeOfImage(pData);
			const ULONG_PTR ib = ReCa<ULONG_PTR>(iat_base);
			if (ReCa<ULONG_PTR>(pIAT) < ib || ReCa<ULONG_PTR>(pIAT) - ib + sizeof(*pIAT) > image_size_iat ||
				ReCa<ULONG_PTR>(pThunk) < ib || ReCa<ULONG_PTR>(pThunk) - ib + sizeof(*pThunk) > image_size_iat)
			{
				ErrorBreak = true;
				break;
			}
		}

		// Vector 1: the IAT and thunk pointers live in the RW (write) view, so bound-check them
		// against the RW view base (not pImageBase) to stay correct even if the two views differ.
		const SIZE_T iat_span = MMI_SizeOfImage(pData);
		const ULONG_PTR iat_ib = ReCa<ULONG_PTR>(iat_base);
		for (; pThunk && pThunk->u1.AddressOfData &&
			ReCa<ULONG_PTR>(pThunk) >= iat_ib && ReCa<ULONG_PTR>(pThunk) - iat_ib + sizeof(*pThunk) <= iat_span &&
			ReCa<ULONG_PTR>(pIAT) >= iat_ib && ReCa<ULONG_PTR>(pIAT) - iat_ib + sizeof(*pIAT) <= iat_span; ++pThunk, ++pIAT)
		{
			UINT_PTR * pFuncRef = ReCa<UINT_PTR *>(pIAT);

			IMAGE_IMPORT_BY_NAME * pImport = nullptr;
			if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
			{

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pThunk->u1.Ordinal), ReCa<void **>(pFuncRef));
			}
			else
			{

			if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
			{
				ErrorBreak = true;
				break;
			}

			pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));

			const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);






			if (pData->OdsReturnStub && MMI_IsDebugPrintImport(pImport->Name, import_name_length))
			{
				*pFuncRef = ReCa<UINT_PTR>(pData->OdsReturnStub);
				++pData->ExecTelemetry.DebugPrintVehInstalled;
				pData->ntRet = STATUS_SUCCESS;
			}
			else
			{
				auto * ansi_import = NewObject<ANSI_STRING>(f);
				if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
				{
					ScrubFreeObject(f, ansi_import, sizeof(ANSI_STRING));
					ErrorBreak = true;
					break;
				}

				ansi_import->szBuffer	= pImport->Name;
				ansi_import->Length		= static_cast<WORD>(import_name_length);
				ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pFuncRef));

				ScrubFreeObject(f, ansi_import, sizeof(ANSI_STRING));
			}
			}

			if (NT_FAIL(pData->ntRet))
			{
				ErrorBreak = true;
				break;
			}
		}

		if (!ErrorBreak)
		{
			if (!pThunk || !MMI_InImage(pData, pThunk, sizeof(*pThunk)) || !MMI_InImage(pData, pIAT, sizeof(*pIAT)) || pThunk->u1.AddressOfData)
			{
				ErrorBreak = true;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pImportDescr;

		if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RESOLVE_DELAY_IMPORTS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	NTSTATUS ntRet = STATUS_SUCCESS;

	IMAGE_DATA_DIRECTORY		* pDelayImportDir	= ReCa<IMAGE_DATA_DIRECTORY *>(&MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	IMAGE_DELAYLOAD_DESCRIPTOR	* pDelayImportDescr = nullptr;





	if (pDelayImportDir->VirtualAddress && pDelayImportDir->Size == 0)
	{
		pData->ntRet = STATUS_INVALID_IMAGE_FORMAT;

		return INJ_MM_ERR_DELAY_IMPORT_FAIL;
	}

	if (!pDelayImportDir->VirtualAddress)
	{
		return INJ_ERR_SUCCESS;
	}

	IMAGE_DELAYLOAD_DESCRIPTOR * const pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size);

	pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress);

	if (!MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) ||
		!MMI_InImage(pData, pDelayImportDescr, pDelayImportDir->Size))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	bool ErrorBreak = false;

	while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
	{
		auto * szModule = ReCa<const char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA);

		if (!MMI_ImageStringLength(pData, szModule))
		{
			ErrorBreak = true;
			break;
		}

		UNICODE_STRING ModNameW{ 0 };

		ModNameW.MaxLength	= MAX_PATH * sizeof(wchar_t);
		ModNameW.szBuffer	= nullptr;

		LDRP_LOAD_CONTEXT_FLAGS ctx_flags{ 0 };
		ntRet = f->MMIHP_PreprocessModuleName(pData, szModule, &ModNameW, &ctx_flags);
		if (NT_FAIL(ntRet))
		{
			ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

			if (ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		HINSTANCE hDll = NULL;


		if (!MMI_FindLoadedModule(pData, &ModNameW, &hDll) || !hDll)
		{
			pData->ntRet = f->MMIHP_LoadModule(pData, &ModNameW, ctx_flags, &hDll, &pData->pDelayImportsHead);
		}
		else
		{
			pData->ntRet = STATUS_SUCCESS;
		}

		if (NT_FAIL(pData->ntRet))
		{
			ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

			if (pData->ntRet == STATUS_APISET_NOT_HOSTED && MMI_IsApisetName(pData, szModule))
			{
				++pDelayImportDescr;

				if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
				{
					break;
				}

				continue;
			}

			ErrorBreak = true;
			break;
		}

		ScrubFreeObject(f, ModNameW.szBuffer, ModNameW.MaxLength);

		// Vector 1: the module-handle slot and the IAT are written in-target, so route them
		// through the never-executable RW view when the section path is active.
		BYTE * iat_base = pData->pSectionRwView ? pData->pSectionRwView : pData->pImageBase;

		if (pDelayImportDescr->ModuleHandleRVA)
		{
			{
				const SIZE_T sz = MMI_SizeOfImage(pData);
				const ULONG_PTR ib = ReCa<ULONG_PTR>(iat_base);
				const ULONG_PTR mh = ib + pDelayImportDescr->ModuleHandleRVA;
				if (mh < ib || mh - ib + sizeof(HINSTANCE) > sz)
				{
					ErrorBreak = true;
					break;
				}
			}

			HINSTANCE * pModule = ReCa<HINSTANCE *>(iat_base + pDelayImportDescr->ModuleHandleRVA);
			*pModule = hDll;
		}

		if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
		{
			ErrorBreak = true;
			break;
		}

		IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(iat_base + pDelayImportDescr->ImportAddressTableRVA);
		IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

		{
			const SIZE_T sz = MMI_SizeOfImage(pData);
			const ULONG_PTR ib = ReCa<ULONG_PTR>(iat_base);
			const ULONG_PTR ib2 = ReCa<ULONG_PTR>(pData->pImageBase);
			const ULONG_PTR iat = ib + pDelayImportDescr->ImportAddressTableRVA;
			const ULONG_PTR name_t = ib2 + pDelayImportDescr->ImportNameTableRVA;
			if (iat < ib || iat - ib + sizeof(*pIAT) > sz || name_t < ib2 || name_t - ib2 + sizeof(*pNameTable) > sz)
			{
				ErrorBreak = true;
				break;
			}
		}

		{
			const SIZE_T sz = MMI_SizeOfImage(pData);
			const ULONG_PTR ib = ReCa<ULONG_PTR>(iat_base);
			const ULONG_PTR ib2 = ReCa<ULONG_PTR>(pData->pImageBase);
			for (; pIAT && pIAT->u1.Function &&
				ReCa<ULONG_PTR>(pIAT) >= ib && ReCa<ULONG_PTR>(pIAT) - ib + sizeof(*pIAT) <= sz &&
				ReCa<ULONG_PTR>(pNameTable) >= ib2 && ReCa<ULONG_PTR>(pNameTable) - ib2 + sizeof(*pNameTable) <= sz; ++pIAT, ++pNameTable)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
			{
				pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), nullptr, IMAGE_ORDINAL(pNameTable->u1.Ordinal), ReCa<void **>(pIAT));
			}
			else
			{
				if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					ErrorBreak = true;
					break;
				}

				auto pImport = ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));

				const size_t import_name_length = MMI_ImageStringLength(pData, pImport->Name);



				if (pData->OdsReturnStub && MMI_IsDebugPrintImport(pImport->Name, import_name_length))
				{
					pIAT->u1.Function = ReCa<UINT_PTR>(pData->OdsReturnStub);
					++pData->ExecTelemetry.DebugPrintVehInstalled;
					pData->ntRet = STATUS_SUCCESS;
				}
				else
				{
					auto * ansi_import= NewObject<ANSI_STRING>(f);
					if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
					{
						ScrubFreeObject(f, ansi_import, sizeof(ANSI_STRING));
						ErrorBreak = true;
						break;
					}

					ansi_import->szBuffer	= pImport->Name;
					ansi_import->Length		= static_cast<WORD>(import_name_length);
					ansi_import->MaxLength	= static_cast<WORD>((ansi_import->Length + 1) * sizeof(char));

					pData->ntRet = f->LdrGetProcedureAddress(ReCa<void *>(hDll), ansi_import, 0, ReCa<void **>(pIAT));

					ScrubFreeObject(f, ansi_import, sizeof(ANSI_STRING));
				}
				}

			if (NT_FAIL(pData->ntRet))
			{
				ErrorBreak = true;
				break;
			}
		}
	}

		if (!ErrorBreak)
		{
			if (!pIAT || !MMI_InImage(pData, pIAT, sizeof(*pIAT)) || !MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) || pIAT->u1.Function)
			{
				ErrorBreak = true;
			}
		}

		if (ErrorBreak)
		{
			break;
		}

		++pDelayImportDescr;

		if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
		{
			break;
		}
	}

	if (ErrorBreak)
	{
		return INJ_MM_ERR_DELAY_IMPORT_FAIL;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_SET_PAGE_PROTECTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	// Vector 1 (single-RWX-view section mapping): the per-section demotion below MUST run.
	// NtProtectVirtualMemory works on this page-file section view (MMI_SetExecProtections
	// and MMI_CloakHeader already flip it successfully); skipping it left the non-executable
	// sections at the view's PAGE_EXECUTE_READWRITE, a W^X violation. This loop drops
	// .rdata/.pdata/.reloc to PAGE_READONLY and .data/.tls to PAGE_READWRITE at end-of-shell.
	auto f = pData->FunctionTable;

	ULONG OldProtection = 0;



	if (!(pData->Flags & INJ_ERASE_HEADER))
	{



		void * HeaderBase = pData->pImageBase;
		SIZE_T SizeOut = MMI_SizeOfHeaders(pData);
		pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &HeaderBase, &SizeOut, PAGE_READONLY, &OldProtection);

		if (NT_FAIL(pData->ntRet))
		{
			return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
		}
	}



	bool section_failure = false;

	auto pCurrentSectionHeader = MMI_Sections(pData);
	const DWORD section_count = MMI_SectionCount(pData);

	pData->SectionProtCount = 0;

	for (UINT i = 0; i != section_count; ++i, ++pCurrentSectionHeader)
	{
		void * pSectionBase		= pData->pImageBase + pCurrentSectionHeader->VirtualAddress;
		DWORD characteristics	= pCurrentSectionHeader->Characteristics;
		SIZE_T SectionSize		= (std::max)(static_cast<SIZE_T>(pCurrentSectionHeader->Misc.VirtualSize), static_cast<SIZE_T>(pCurrentSectionHeader->SizeOfRawData));

		ULONG NewProtection = PAGE_NOACCESS;
		NTSTATUS prot_status = STATUS_SUCCESS;

		if (SectionSize)
		{

			if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_EXECUTE_READ;
				}
				else
				{
					NewProtection = PAGE_EXECUTE;
				}
			}
			else
			{
				if (characteristics & IMAGE_SCN_MEM_WRITE)
				{
					NewProtection = PAGE_READWRITE;
				}
				else if (characteristics & IMAGE_SCN_MEM_READ)
				{
					NewProtection = PAGE_READONLY;
				}
			}

			pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &pSectionBase, &SectionSize, NewProtection, &OldProtection);
			prot_status = pData->ntRet;
			if (NT_FAIL(pData->ntRet))
			{
				section_failure = true;
			}
		}

		pData->SectionProtCount = i + 1;

		if (NT_FAIL(prot_status))
		{
			section_failure = true;
			break;
		}
	}

	if (section_failure)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
{

	if (!(pData->Flags & INJ_MM_ENABLE_EXCEPTIONS))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

#ifdef _WIN64
	const IMAGE_DATA_DIRECTORY & exc_dir = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (exc_dir.Size)
	{
		if (exc_dir.Size % sizeof(RUNTIME_FUNCTION) != 0)
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}

		auto * pExceptionHandlers = ReCa<RUNTIME_FUNCTION *>(pData->pImageBase + exc_dir.VirtualAddress);
		const DWORD EntryCount = exc_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));

		if (!MMI_InImage(pData, pExceptionHandlers, exc_dir.Size))
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}

		if (!f->RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), ReCa<DWORD64>(pData->pImageBase)))
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}
		pData->pDynamicFunctionTable = pExceptionHandlers;
		pData->ExecTelemetry.DynamicTableInstalled = TRUE;

		bool dynamic_ok = true;
		if (f->RtlLookupFunctionEntry && EntryCount)
		{
			const RUNTIME_FUNCTION & first = pExceptionHandlers[0];
			const ULONGLONG probe = ReCa<ULONGLONG>(pData->pImageBase) + first.BeginAddress;
			ULONGLONG lookup_base = 0;
			BYTE history[312];
			f->RtlZeroMemory(history, sizeof(history));
			RUNTIME_FUNCTION * found = f->RtlLookupFunctionEntry(probe, &lookup_base, history);
			dynamic_ok = (found != nullptr && lookup_base == ReCa<ULONGLONG>(pData->pImageBase));
		}
		if (!dynamic_ok)
		{
			pData->ExecTelemetry.DynamicTableInstalled = FALSE;
		}








		if (!dynamic_ok)
		{
			pData->ntRet = STATUS_UNSUCCESSFUL;
			return INJ_MM_ERR_ENABLING_SEH_FAILED;
		}
	}
#endif

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_EXECUTE_TLS))
	{
		return INJ_ERR_SUCCESS;
	}

	if (!MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
	{
		return INJ_MM_ERR_INVALID_PE_IMAGE;
	}

	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);






	{
		bool has_callbacks = false;
		if (pTLS->AddressOfCallBacks &&
			MMI_InImage(pData, ReCa<void *>(pTLS->AddressOfCallBacks), sizeof(void *)))
		{
			has_callbacks = *ReCa<void * const *>(pTLS->AddressOfCallBacks) != nullptr;
		}

		const bool has_data = pTLS->StartAddressOfRawData != 0 || pTLS->SizeOfZeroFill != 0;

		if (!has_callbacks && !has_data)
		{
			pData->ExecTelemetry.TlsLoaderEntryAbsent = 1;
			return INJ_ERR_SUCCESS;
		}
	}

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	const DWORD ldr_size = pData->NtOffsets.LdrEntrySize ? pData->NtOffsets.LdrEntrySize : sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
	const DWORD ldr_base_off = pData->NtOffsets.LdrEntryDllBase ? pData->NtOffsets.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
	const DWORD ldr_image_off = pData->NtOffsets.LdrEntrySizeOfImage ? pData->NtOffsets.LdrEntrySizeOfImage : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage));
	const DWORD ddag_off = pData->NtOffsets.LdrEntryDdagNode ? pData->NtOffsets.LdrEntryDdagNode : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DdagNode));
	const DWORD ddag_state_off = pData->NtOffsets.LdrDdagNodeState ? pData->NtOffsets.LdrDdagNodeState : static_cast<DWORD>(offsetof(LDR_DDAG_NODE_WIN11, State));
	const DWORD ddag_size = pData->NtOffsets.LdrDdagNodeSize ? pData->NtOffsets.LdrDdagNodeSize : sizeof(LDR_DDAG_NODE_WIN11);

	if (!ldr_size || ldr_size > 0x1000 || ldr_base_off + sizeof(void *) > ldr_size)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	void * pDummyLdrRaw = NewBytes(f, ldr_size);
	if (!pDummyLdrRaw)
	{
		return INJ_MM_ERR_HEAP_ALLOC;
	}
	WritePtrField(pDummyLdrRaw, ldr_base_off, pData->pImageBase);
	if (ldr_image_off + sizeof(ULONG) <= ldr_size)
	{
		*ReCa<ULONG *>(ReCa<BYTE *>(pDummyLdrRaw) + ldr_image_off) = MMI_SizeOfImage(pData);
	}


	void * pDdagRaw = nullptr;
	if (ddag_off + sizeof(void *) <= ldr_size && ddag_state_off + sizeof(int) <= ddag_size && ddag_size <= 0x800)
	{
		pDdagRaw = NewBytes(f, ddag_size);
		if (!pDdagRaw)
		{
			DeleteObject(f, pDummyLdrRaw);

			return INJ_MM_ERR_HEAP_ALLOC;
		}

		*ReCa<int *>(ReCa<BYTE *>(pDdagRaw) + ddag_state_off) = static_cast<int>(LdrModulesReadyToInit);




		WritePtrField(pDdagRaw, offsetof(LDR_DDAG_NODE_WIN11, Modules), pDdagRaw);
		WritePtrField(pDdagRaw, offsetof(LDR_DDAG_NODE_WIN11, Modules) + sizeof(void *), pDdagRaw);

		WritePtrField(pDummyLdrRaw, ddag_off, pDdagRaw);
	}

	auto * pDummyLdr = ReCa<LDR_DATA_TABLE_ENTRY *>(pDummyLdrRaw);






	pData->TlsDirectory	= pTLS;
	pData->TlsDummyLdr	= pDummyLdrRaw;
	pData->TlsDdagNode	= pDdagRaw;
	pData->TlsDummyLdrSize = ldr_size;
	pData->TlsDdagNodeSize = pDdagRaw ? ddag_size : 0;




	const bool tls_has_data = pTLS->EndAddressOfRawData > pTLS->StartAddressOfRawData ||
		pTLS->SizeOfZeroFill != 0;
	pData->TlsDataLive = tls_has_data ? 1 : 0;
	pData->ExecTelemetry.TlsHasData = tls_has_data ? 1u : 0u;

	DWORD * const pTlsIndex = (pTLS->AddressOfIndex &&
		MMI_InImage(pData, ReCa<void *>(pTLS->AddressOfIndex), sizeof(DWORD)))
		? ReCa<DWORD *>(pTLS->AddressOfIndex) : nullptr;

	const ULONG_PTR teb = static_cast<ULONG_PTR>(__readgsqword(0x30));
	const ULONG_PTR peb = teb ? *ReCa<ULONG_PTR *>(teb + 0x60) : 0;
	DWORD * tls_bitmap = nullptr;
	ULONG_PTR * tls_slots = nullptr;
	if (peb && pData->NtOffsets.PebTlsBitmapBits &&
		pData->NtOffsets.PebTlsBitmapBits + 2 * sizeof(ULONG) <= 0x400)
	{
		tls_bitmap = ReCa<DWORD *>(peb + pData->NtOffsets.PebTlsBitmapBits);
	}
	if (teb && pData->NtOffsets.TebTlsSlots &&
		pData->NtOffsets.TebTlsSlots + 64 * sizeof(void *) <= 0x2000)
	{
		tls_slots = ReCa<ULONG_PTR *>(teb + pData->NtOffsets.TebTlsSlots);
	}

	ULONG lock_state = 0;
	ULONG_PTR lock_cookie = 0;
	pData->ExecTelemetry.TlsLockStatus = f->LdrLockLoaderLock(NULL, &lock_state, &lock_cookie);
	if (NT_FAIL(pData->ExecTelemetry.TlsLockStatus))
	{
		ScrubFreeObject(f, pDdagRaw, ddag_size);
		ScrubFreeObject(f, pDummyLdrRaw, ldr_size);

		pData->TlsDirectory	= nullptr;
		pData->TlsDummyLdr	= nullptr;
		pData->TlsDdagNode	= nullptr;
		pData->TlsDummyLdrSize = 0;
		pData->TlsDdagNodeSize = 0;

		return INJ_MM_ERR_LOADER_LOCK_FAILED;
	}

	pData->TlsIndexPrior = pTlsIndex ? *pTlsIndex : 0;
	pData->TlsBitmapBefore = tls_bitmap
		? (static_cast<DWORD64>(tls_bitmap[0]) | (static_cast<DWORD64>(tls_bitmap[1]) << 32))
		: 0;
	pData->TlsExpectedIndex = 0xFFFFFFFF;
	pData->TlsSlotBefore = 0;
	pData->TlsSlotAfter = 0;
	if (!tls_has_data && tls_bitmap)
	{



		for (DWORD bit = 0; bit < 64; ++bit)
		{
			if (!(tls_bitmap[bit >> 5] & (1u << (bit & 31))))
			{
				pData->TlsExpectedIndex = bit;
				if (tls_slots)
				{
					pData->TlsSlotBefore = tls_slots[bit];
				}
				break;
			}
		}
	}

	pData->ntRet = f->LdrpHandleTlsData(pDummyLdr);

	if (NT_SUCCESS(pData->ntRet))
	{
		pData->TlsIndex = pTlsIndex ? *pTlsIndex : 0;
		pData->ExecTelemetry.TlsIndex = pData->TlsIndex;
		pData->TlsBitmapAfter = tls_bitmap
			? (static_cast<DWORD64>(tls_bitmap[0]) | (static_cast<DWORD64>(tls_bitmap[1]) << 32))
			: 0;
		if (tls_slots && pData->TlsIndex < 64)
		{
			pData->TlsSlotAfter = tls_slots[pData->TlsIndex];
		}

		const DWORD assigned = pData->TlsIndex;
		const DWORD assigned_bit = assigned < 64 ? (1u << (assigned & 31)) : 0;
		const bool bit_now_set = assigned_bit && tls_bitmap &&
			(tls_bitmap[assigned >> 5] & assigned_bit) != 0;








		if (!tls_has_data && bit_now_set &&
			assigned == pData->TlsExpectedIndex &&
			pTlsIndex && tls_bitmap && tls_slots && f->LdrpTlsList &&
			pData->NtOffsets.TlsEntrySize >= sizeof(LIST_ENTRY) + sizeof(void *) &&
			pData->NtOffsets.TlsEntrySize < 0x1000 &&
			pData->NtOffsets.TlsEntryModuleEntry + sizeof(void *) <= pData->NtOffsets.TlsEntrySize)
		{
			BYTE * tls_entry = nullptr;
			bool entry_found = false;
			bool entry_unlinked = false;

			auto node = f->LdrpTlsList->Flink;
			ULONG guard = 0;
			while (node && node != f->LdrpTlsList && guard++ < 0x4000)
			{
				auto entry_bytes = ReCa<BYTE *>(node);
				node = node->Flink;
				if (ReadPtrField(entry_bytes, pData->NtOffsets.TlsEntryModuleEntry) == pDummyLdr)
				{
					entry_found = true;
					auto links = ReCa<LIST_ENTRY *>(entry_bytes);
					if (links->Blink && links->Flink)
					{
						links->Blink->Flink = links->Flink;
						links->Flink->Blink = links->Blink;
						entry_unlinked = true;
						tls_entry = entry_bytes;
					}
					break;
				}
			}





			const bool list_clear = entry_unlinked || (!entry_found && node == f->LdrpTlsList);
			if (list_clear)
			{
				if (!entry_found)
				{
					pData->ExecTelemetry.TlsLoaderEntryAbsent = 1;
				}

				if (entry_unlinked)
				{
					ScrubFreeObject(f, tls_entry, pData->NtOffsets.TlsEntrySize);
					pData->ExecTelemetry.TlsLoaderEntryUnlinked = 1;
				}

				*pTlsIndex = pData->TlsIndexPrior;
				pData->ExecTelemetry.TlsIndexRestored = 1;

				tls_bitmap[assigned >> 5] &= ~assigned_bit;
				pData->ExecTelemetry.TlsBitmapBitCleared = 1;

				tls_slots[assigned] = pData->TlsSlotBefore;
				pData->ExecTelemetry.TlsSlotCleared = 1;

				ScrubFreeObject(f, pDdagRaw, ddag_size);
				ScrubFreeObject(f, pDummyLdrRaw, ldr_size);
				pDdagRaw = nullptr;
				pDummyLdrRaw = nullptr;
				pDummyLdr = nullptr;

				pData->TlsDummyLdr = nullptr;
				pData->TlsDdagNode = nullptr;
				pData->TlsDummyLdrSize = 0;
				pData->TlsDdagNodeSize = 0;
			}
		}
	}

	pData->ExecTelemetry.TlsUnlockStatus = f->LdrUnlockLoaderLock(NULL, lock_cookie);

	if (NT_FAIL(pData->ExecTelemetry.TlsUnlockStatus))
	{
		return INJ_MM_ERR_LOADER_LOCK_FAILED;
	}

	if (NT_FAIL(pData->ntRet))
	{
		ScrubFreeObject(f, pDdagRaw, ddag_size);
		ScrubFreeObject(f, pDummyLdrRaw, ldr_size);

		pData->TlsDirectory	= nullptr;
		pData->TlsDummyLdr	= nullptr;
		pData->TlsDdagNode	= nullptr;
		pData->TlsDummyLdrSize = 0;
		pData->TlsDdagNodeSize = 0;

		return static_cast<DWORD>(pData->ntRet);
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0F")) __stdcall MMI_RunTlsCallbacks(MANUAL_MAPPING_DATA * pData)
{
	auto * pTLS = ReCa<IMAGE_TLS_DIRECTORY *>(pData->TlsDirectory);




	if (!pTLS)
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG callback_count = 0;
	ULONG configured_count = 0;
	DWORD tls_result = INJ_ERR_SUCCESS;
	auto * pScan = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pScan)
	{
		if (!MMI_InImage(pData, pScan, sizeof(*pScan)))
		{
			break;
		}
		if (!(*pScan))
		{
			break;
		}
		++configured_count;
		++pScan;
		if (configured_count >= 1025)
		{
			break;
		}
	}
	pData->ExecTelemetry.TlsCallbacksConfigured = configured_count;

	auto * pCallback = ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
	while (pCallback)
	{

		if (!MMI_InImage(pData, pCallback, sizeof(*pCallback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(pCallback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		auto Callback = *pCallback;
		if (!Callback)
		{

			break;
		}

		if (callback_count >= 1024)
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(Callback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}



		const bool callback_in_image = MMI_InImage(pData, ReCa<void *>(Callback), sizeof(BYTE));
		if (!callback_in_image && !MMI_AddressInLoadedImage(pData, ReCa<void *>(Callback)))
		{
			pData->TlsCallbackIndex = callback_count;
			pData->TlsCallbackAddress = ReCa<ULONG_PTR>(Callback);
			pData->ExecTelemetry.TlsCallbacksFailed = (configured_count > callback_count) ? (configured_count - callback_count) : 1;
			pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
			tls_result = INJ_MM_ERR_TLS_CALLBACK_RANGE;
			break;
		}

		Callback(pData->pImageBase, DLL_PROCESS_ATTACH, nullptr);
		pData->ExecTelemetry.TlsLastExecutedAddress = ReCa<PVOID>(Callback);
		++callback_count;
		++pCallback;
	}
	if (tls_result == INJ_ERR_SUCCESS)
	{
		pData->ExecTelemetry.TlsCallbacksExecuted = callback_count;
		pData->ExecTelemetry.TlsCallbacksFailed = 0;
	}







	pData->TlsDirectory = nullptr;
	return tls_result;
}

DWORD __declspec(code_seg(".code$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_RUN_DLL_MAIN))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	if (!MMI_EntryPoint(pData))
	{
		return INJ_ERR_SUCCESS;
	}

	ULONG		State	= 0;
	ULONG_PTR	Cookie	= 0;
	bool		locked	= false;

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	if (pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK)
	{
		pData->ntRet = f->LdrLockLoaderLock(NULL, &State, &Cookie);
		pData->ExecTelemetry.LdrLockStatus = pData->ntRet;
		pData->ExecTelemetry.LoaderLockState = State;
		pData->ExecTelemetry.LoaderLockCookie = Cookie;

		locked = NT_SUCCESS(pData->ntRet);
		if (!locked)
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + MMI_EntryPoint(pData));
	const unsigned __int64 dll_t0 = __rdtsc();
	const BOOL dll_result = DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_ATTACH, nullptr);
	const unsigned __int64 dll_t1 = __rdtsc();




	DWORD dll_win32 = 0;
	{
		const DWORD teb_last_error = pData->NtOffsets.TebLastErrorValue;
		if (teb_last_error && teb_last_error + sizeof(DWORD) <= 0x2000)
		{
			const ULONG_PTR teb = static_cast<ULONG_PTR>(__readgsqword(0x30));
			if (teb)
			{
				dll_win32 = *ReCa<DWORD *>(ReCa<BYTE *>(teb) + teb_last_error);
			}
		}
	}
	pData->ExecTelemetry.DllMainResult = dll_result;
	pData->ExecTelemetry.DllMainLastWin32Error = dll_win32;
	pData->ExecTelemetry.DllMainCyclesDelta = (dll_t1 >= dll_t0) ? (dll_t1 - dll_t0) : 0;
	if (!dll_result)
	{

		DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_DETACH, nullptr);

		if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
		{
			const NTSTATUS unlock_st = f->LdrUnlockLoaderLock(NULL, Cookie);
			pData->ExecTelemetry.LdrUnlockStatus = unlock_st;
			if (!NT_SUCCESS(unlock_st))
			{
				return INJ_MM_ERR_LOADER_LOCK_FAILED;
			}
		}

		return INJ_MM_ERR_DLLMAIN_FAILED;
	}

	if ((pData->Flags & INJ_MM_RUN_UNDER_LDR_LOCK) && locked)
	{
		const NTSTATUS unlock_st = f->LdrUnlockLoaderLock(NULL, Cookie);
		pData->ExecTelemetry.LdrUnlockStatus = unlock_st;
		if (!NT_SUCCESS(unlock_st))
		{
			return INJ_MM_ERR_LOADER_LOCK_FAILED;
		}
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_MM_CLEAN_DATA_DIR))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;

	pData->MapStats.ImportSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	pData->MapStats.DelayImportSize	= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	pData->MapStats.DebugSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	pData->MapStats.RelocSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	pData->MapStats.TlsSize			= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	pData->MapStats.ExportSize		= MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pData->MapStats.CleanedMask		=
		((pData->MapStats.ImportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_IMPORT) |
		((pData->MapStats.DelayImportSize	? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) |
		((pData->MapStats.DebugSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_DEBUG) |
		((pData->MapStats.RelocSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_BASERELOC) |
		((pData->MapStats.TlsSize			? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_TLS) |
		((pData->MapStats.ExportSize		? 1u : 0u) << IMAGE_DIRECTORY_ENTRY_EXPORT);

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_WRITABLE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	DWORD Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto * pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + Size);
		auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr && pImportDescr < pImportEnd && MMI_InImage(pData, pImportDescr, sizeof(*pImportDescr)) && pImportDescr->Name)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pImportDescr->Name));

			if (mod_length && MMI_InImage(pData, pData->pImageBase + pImportDescr->Name, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pImportDescr->Name, mod_length + 1);
			}
			pImportDescr->Name = 0;

			if (!pImportDescr->OriginalFirstThunk && !pImportDescr->FirstThunk)
			{
				break;
			}

			IMAGE_THUNK_DATA * pThunk	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->OriginalFirstThunk);
			IMAGE_THUNK_DATA * pIAT		= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
			{
				pThunk = pIAT;
			}

			for (; pThunk && MMI_InImage(pData, pThunk, sizeof(*pThunk)) && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && pThunk->u1.AddressOfData; ++pThunk, ++pIAT)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
				{
					pThunk->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pThunk->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pThunk->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);

					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pImportDescr->OriginalFirstThunk = 0;
			pImportDescr->FirstThunk = 0;

			++pImportDescr;
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	if (Size)
	{
		auto * pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + Size);
		auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		while (pDelayImportDescr && pDelayImportDescr < pDelayImportEnd && MMI_InImage(pData, pDelayImportDescr, sizeof(*pDelayImportDescr)) && pDelayImportDescr->DllNameRVA)
		{
			const size_t mod_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pDelayImportDescr->DllNameRVA));

			if (mod_length && MMI_InImage(pData, pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pDelayImportDescr->DllNameRVA, mod_length + 1);
			}
			pDelayImportDescr->DllNameRVA = 0;

			pDelayImportDescr->ModuleHandleRVA = 0;

			if (!pDelayImportDescr->ImportAddressTableRVA || !pDelayImportDescr->ImportNameTableRVA)
			{
				break;
			}

			IMAGE_THUNK_DATA * pIAT			= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportAddressTableRVA);
			IMAGE_THUNK_DATA * pNameTable	= ReCa<IMAGE_THUNK_DATA *>(pData->pImageBase + pDelayImportDescr->ImportNameTableRVA);

			for (; pIAT && MMI_InImage(pData, pIAT, sizeof(*pIAT)) && MMI_InImage(pData, pNameTable, sizeof(*pNameTable)) && pIAT->u1.Function; ++pIAT, ++pNameTable)
			{

				if (IMAGE_SNAP_BY_ORDINAL(pNameTable->u1.Ordinal))
				{
					pNameTable->u1.Ordinal = 0;
				}
				else if (MMI_InImage(pData, ReCa<void *>(pData->pImageBase + pNameTable->u1.AddressOfData), sizeof(IMAGE_IMPORT_BY_NAME)))
				{
					auto * pImport	= ReCa<IMAGE_IMPORT_BY_NAME *>(pData->pImageBase + (pNameTable->u1.AddressOfData));
					const size_t func_length = MMI_ImageStringLength(pData, pImport->Name);

					if (func_length && MMI_InImage(pData, pImport->Name, func_length + 1))
					{
						f->RtlZeroMemory(pImport->Name, func_length + 1);
					}
				}
			}

			pDelayImportDescr->ImportAddressTableRVA = 0;
			pDelayImportDescr->ImportNameTableRVA = 0;

			++pDelayImportDescr;
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (Size)
	{
		auto * pExportDir = ReCa<IMAGE_EXPORT_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (!MMI_InImage(pData, pExportDir, sizeof(*pExportDir)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		if (pExportDir->Name)
		{
			const size_t dll_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pExportDir->Name));
			if (dll_length && MMI_InImage(pData, pData->pImageBase + pExportDir->Name, dll_length + 1))
			{
				f->RtlZeroMemory(pData->pImageBase + pExportDir->Name, dll_length + 1);
			}
			pExportDir->Name = 0;
		}

		const DWORD name_count = pExportDir->NumberOfNames;
		const DWORD func_count = pExportDir->NumberOfFunctions;

		if (name_count || func_count)
		{

			if (name_count >= 4096 || func_count >= 4096)
			{
				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			if ((name_count && (!pExportDir->AddressOfNames || !pExportDir->AddressOfNameOrdinals)) ||
				(func_count && !pExportDir->AddressOfFunctions))
			{
				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			if (name_count)
			{
				auto * pNameRVAs = ReCa<DWORD *>(pData->pImageBase + pExportDir->AddressOfNames);
				auto * pOrdinals = ReCa<WORD *>(pData->pImageBase + pExportDir->AddressOfNameOrdinals);
				if (!MMI_InImage(pData, pNameRVAs, name_count * sizeof(DWORD)) ||
					!MMI_InImage(pData, pOrdinals, name_count * sizeof(WORD)))
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				for (DWORD i = 0; i < name_count; ++i)
				{
					if (!pNameRVAs[i])
					{
						continue;
					}
					const size_t func_length = MMI_ImageStringLength(pData, ReCa<char *>(pData->pImageBase + pNameRVAs[i]));
					if (func_length && MMI_InImage(pData, pData->pImageBase + pNameRVAs[i], func_length + 1))
					{
						f->RtlZeroMemory(pData->pImageBase + pNameRVAs[i], func_length + 1);
					}
					pNameRVAs[i] = 0;
				}

				f->RtlZeroMemory(pOrdinals, name_count * sizeof(WORD));
			}

			if (func_count)
			{
				auto * pFuncRVAs = ReCa<DWORD *>(pData->pImageBase + pExportDir->AddressOfFunctions);
				if (!MMI_InImage(pData, pFuncRVAs, func_count * sizeof(DWORD)))
				{
					return INJ_MM_ERR_INVALID_PE_IMAGE;
				}

				f->RtlZeroMemory(pFuncRVAs, func_count * sizeof(DWORD));
			}
		}

		f->RtlZeroMemory(pExportDir, sizeof(*pExportDir));

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		if (!MMI_InImage(pData, pDebugDir, sizeof(*pDebugDir)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		BYTE * pDebugData = pData->pImageBase + pDebugDir->AddressOfRawData;
		if (pDebugDir->SizeOfData && !MMI_InImage(pData, pDebugData, pDebugDir->SizeOfData))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		f->RtlZeroMemory(pDebugData, pDebugDir->SizeOfData);

		pDebugDir->SizeOfData = 0;
		pDebugDir->AddressOfRawData = 0;
		pDebugDir->PointerToRawData = 0;

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto * pRelocEnd = ReCa<BYTE *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + Size);
		auto * pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (ReCa<BYTE *>(pRelocData) + sizeof(IMAGE_BASE_RELOCATION) <= pRelocEnd && pRelocData->VirtualAddress)
		{
			if (pRelocData->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
				pRelocData->SizeOfBlock > static_cast<DWORD>(pRelocEnd - ReCa<BYTE *>(pRelocData)))
			{

				return INJ_MM_ERR_INVALID_PE_IMAGE;
			}

			WORD * pRelativeInfo = ReCa<WORD *>(pRelocData + 1);
			UINT RelocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			f->RtlZeroMemory(pRelativeInfo, RelocCount * sizeof(WORD));

			pRelocData = ReCa<IMAGE_BASE_RELOCATION *>(ReCa<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		if (!MMI_InImage(pData, ReCa<void *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), sizeof(IMAGE_TLS_DIRECTORY)))
		{
			return INJ_MM_ERR_INVALID_PE_IMAGE;
		}

		auto * pTLS			= ReCa<IMAGE_TLS_DIRECTORY *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto * pCallback	= ReCa<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		ULONG callback_count = 0;
		for (; pCallback && MMI_InImage(pData, pCallback, sizeof(*pCallback)) && (*pCallback) && callback_count < 1024; ++pCallback, ++callback_count)
		{
			*pCallback = nullptr;
		}

		pTLS->AddressOfCallBacks	= 0;
		pTLS->AddressOfIndex		= 0;
		pTLS->EndAddressOfRawData	= 0;
		pTLS->SizeOfZeroFill		= 0;
		pTLS->StartAddressOfRawData = 0;

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress	= 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_TLS].Size			= 0;
	}


	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
	if (Size)
	{
		auto * pBound = ReCa<IMAGE_BOUND_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
		if (MMI_InImage(pData, pBound, Size))
		{
			f->RtlZeroMemory(pBound, Size);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	}


	Size = MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	if (Size)
	{
		BYTE * pResRoot = pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

		if (MMI_InImage(pData, pResRoot, Size))
		{



			constexpr int kMaxResourceDepth = 16;
			constexpr DWORD kMaxResourceDirs = 0x2000;
			DWORD visited_dirs = 0;

			auto walk_resource_dir = [&](auto&& self, const BYTE * table, int depth) -> void
			{
				if (depth > kMaxResourceDepth || visited_dirs >= kMaxResourceDirs ||
					!table || table < pResRoot || table >= pResRoot + Size ||
					!MMI_InImage(pData, table, sizeof(IMAGE_RESOURCE_DIRECTORY)))
				{
					return;
				}

				++visited_dirs;

				const auto * pTable = ReCa<const IMAGE_RESOURCE_DIRECTORY *>(table);
				const UINT entries = pTable->NumberOfNamedEntries + pTable->NumberOfIdEntries;

				if (!entries || entries > 0x800)
				{
					return;
				}

				const auto * pEntry = ReCa<const IMAGE_RESOURCE_DIRECTORY_ENTRY *>(table + sizeof(IMAGE_RESOURCE_DIRECTORY));

				for (UINT e = 0; e < entries; ++e)
				{
					if (!MMI_InImage(pData, pEntry + e, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
					{
						break;
					}

					if ((pEntry[e].Name & 0x80000000) != 0)
					{
						const DWORD name_offset = pEntry[e].Name & 0x7FFFFFFF;

						if (MMI_InImage(pData, pResRoot + name_offset, sizeof(IMAGE_RESOURCE_DIRECTORY_STRING)))
						{
							auto * pStr = ReCa<IMAGE_RESOURCE_DIRECTORY_STRING *>(pResRoot + name_offset);

							if (pStr->Length)
							{
								const SIZE_T bytes = static_cast<SIZE_T>(pStr->Length) * sizeof(wchar_t);
								if (MMI_InImage(pData, pStr->NameString, bytes))
								{
									f->RtlZeroMemory(pStr->NameString, bytes);
								}

								pStr->Length = 0;
							}
						}
					}

					const DWORD target = pEntry[e].OffsetToData & 0x7FFFFFFF;

					if (pEntry[e].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
					{
						if (target < Size)
						{
							self(self, pResRoot + target, depth + 1);
						}

						continue;
					}

					if (target + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > Size)
					{
						continue;
					}

					auto * pDataEntry = ReCa<IMAGE_RESOURCE_DATA_ENTRY *>(pResRoot + target);

					if (pEntry[e].Id == 16 && pDataEntry->Size && MMI_InImage(pData, pResRoot + pDataEntry->OffsetToData, pDataEntry->Size))
					{
						f->RtlZeroMemory(pResRoot + pDataEntry->OffsetToData, pDataEntry->Size);

						pDataEntry->Size = 0;
						pDataEntry->OffsetToData = 0;
					}
				}
			};

			walk_resource_dir(walk_resource_dir, pResRoot, 0);
		}

		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
	}

	if (MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size ||
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].Size)
	{
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
		MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	}

	{
		const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		if (ProtRet != INJ_ERR_SUCCESS)
		{
			return ProtRet;
		}
	}

	{
		constexpr DWORD kCleanedDirectories[] = {
			IMAGE_DIRECTORY_ENTRY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_BASERELOC,
			IMAGE_DIRECTORY_ENTRY_TLS,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			IMAGE_DIRECTORY_ENTRY_RESOURCE,
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
			IMAGE_DIRECTORY_ENTRY_IAT,
		};

		auto * dirs = MMI_DataDirectory(pData);
		DWORD residual = 0;
		for (const DWORD entry : kCleanedDirectories)
		{
			if (dirs[entry].VirtualAddress || dirs[entry].Size)
			{
				residual |= 1u << entry;
			}
		}

		pData->MapStats.ResidualMask	= residual;
		pData->MapStats.Verified		= residual ? 0u : 1u;




		pData->MapStats.VerifiedCachedCopy = (pData->Flags & INJ_ERASE_HEADER) ? 1u : 0u;
	}

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
{
	if (!(pData->Flags & INJ_ERASE_HEADER))
	{
		return INJ_ERR_SUCCESS;
	}

	auto f = pData->FunctionTable;
	if (!f || !f->NtProtectVirtualMemory || !f->RtlZeroMemory)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}

	auto * pDos = pData->pDosHeader;
	auto * pNt = pData->pNtHeaders;
	if (!pDos || !pNt || !pData->pImageBase)
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}



	const DWORD e_lfanew		= pDos->e_lfanew;
	const DWORD nt_size			= static_cast<DWORD>(sizeof(IMAGE_NT_HEADERS64));
	const DWORD section_size	= static_cast<DWORD>(sizeof(IMAGE_SECTION_HEADER));
	const DWORD opt_hdr_off		= static_cast<DWORD>(FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader));
	const DWORD size_optional	= pNt->FileHeader.SizeOfOptionalHeader;
	DWORD		num_sections	= pNt->FileHeader.NumberOfSections;
	const DWORD size_of_image	= pNt->OptionalHeader.SizeOfImage;



	DWORD limit = size_of_image;
	DWORD pre_section = 0;
	if (num_sections)
	{
		const DWORD first_section = IMAGE_FIRST_SECTION(pNt)->VirtualAddress;
		if (first_section && first_section < limit)
		{
			limit = first_section;
		}




		if (first_section && first_section < size_of_image)
		{
			pre_section = first_section;
		}
	}

	if (!limit)
	{
		return INJ_ERR_SUCCESS;
	}

	DWORD dos_bytes = 0x40;
	if (dos_bytes > limit)
	{
		dos_bytes = limit;
	}

	DWORD nt_bytes = 0;
	if (e_lfanew < limit)
	{
		const DWORD room = limit - e_lfanew;
		nt_bytes = room < nt_size ? room : nt_size;
	}


	DWORD sec_bytes = 0;
	const DWORD sec_off = e_lfanew + opt_hdr_off + size_optional;
	if (sec_off < limit)
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






	DWORD scan_mz_before = 0;
	DWORD scan_pe_before = 0;
	DWORD scan_mz_after = 0;
	DWORD scan_pe_after = 0;

	{
		const BYTE * pScan = ReCa<const BYTE *>(pData->pImageBase);
		for (DWORD i = 0; i + 2 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x4D && pScan[i + 1] == 0x5A)
			{
				++scan_mz_before;
			}
		}
		for (DWORD i = 0; i + 4 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x50 && pScan[i + 1] == 0x45 && pScan[i + 2] == 0x00 && pScan[i + 3] == 0x00)
			{
				++scan_pe_before;
			}
		}
	}




	f->RtlZeroMemory(pData->pImageBase, wipe_size);

	{
		const BYTE * pScan = ReCa<const BYTE *>(pData->pImageBase);
		for (DWORD i = 0; i + 2 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x4D && pScan[i + 1] == 0x5A)
			{
				++scan_mz_after;
			}
		}
		for (DWORD i = 0; i + 4 <= wipe_size; ++i)
		{
			if (pScan[i] == 0x50 && pScan[i + 1] == 0x45 && pScan[i + 2] == 0x00 && pScan[i + 3] == 0x00)
			{
				++scan_pe_after;
			}
		}
	}


	const ULONG final_access = PAGE_NOACCESS;
	pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, final_access, &old_access);
	if (NT_FAIL(pData->ntRet))
	{
		return INJ_MM_ERR_UPDATE_PAGE_PROTECTION;
	}





	pData->MapStats.HeaderStructuralSize	= structural_size;
	pData->MapStats.HeaderWipeSize			= wipe_size;
	pData->MapStats.HeaderWipeProtect		= final_access;
	pData->MapStats.HeaderScanBytes			= wipe_size;
	pData->MapStats.HeaderScanMZ			= scan_mz_before;
	pData->MapStats.HeaderScanPE			= scan_pe_before;
	pData->ExecTelemetry.PreSectionSpanWiped = static_cast<SIZE_T>(wipe_size);
	pData->ExecTelemetry.MZRemnantsFound = scan_mz_after;
	pData->ExecTelemetry.PERemnantsFound = scan_pe_after;
	pData->ExecTelemetry.PostWipeProtection = final_access;

	return INJ_ERR_SUCCESS;
}

DWORD __declspec(code_seg(".code$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
{
	if (!pData || !pData->FunctionTable)
	{
		return INJ_MM_ERR_NO_DATA;
	}

	auto f = pData->FunctionTable;



	if (pData->ExecTelemetry.DllMainResult && pData->ExecTelemetry.DllMainCyclesDelta != 0 &&
		MMI_EntryPoint(pData))
	{
		MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
		f_DLL_ENTRY_POINT DllMain = ReCa<f_DLL_ENTRY_POINT>(pData->pImageBase + MMI_EntryPoint(pData));
		DllMain(ReCa<HINSTANCE>(pData->pImageBase), DLL_PROCESS_DETACH, nullptr);
	}

	const bool leak_image_for_inverted = (pData->InvertedTableInstalled != 0);
	if (pData->pFakeSEHDirectory && !leak_image_for_inverted)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pFakeSEHDirectory), &Size, MEM_RELEASE);
	}

	if (pData->pDelayImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pDelayImportsHead);
	}

	if (pData->pImportsHead)
	{
		UnloadAndDeleteDependencyRecord(f, pData->pImportsHead);
	}

	bool retain_staging = pData->pAllocationBase &&
		pData->MapStats.RetainedAllocBase == ReCa<ULONG_PTR>(pData->pAllocationBase);

	if (pData->DebugPrintVehHandle && f->RtlRemoveVectoredExceptionHandler)
	{
		const ULONG removed = f->RtlRemoveVectoredExceptionHandler(pData->DebugPrintVehHandle);
		if (!removed)
		{
			retain_staging = true;
		}
		pData->DebugPrintVehHandle = nullptr;
	}

	if (pData->pDynamicFunctionTable && f->RtlDeleteFunctionTable)
	{
		const BOOLEAN deleted = f->RtlDeleteFunctionTable(pData->pDynamicFunctionTable);
		if (!deleted)
		{

			pData->MapStats.RetainedAllocBase = ReCa<ULONG_PTR>(pData->pImageBase);
		}
	}

	if (pData->pAllocationBase && !leak_image_for_inverted && !retain_staging)
	{
		SIZE_T Size = 0;
		f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &Size, MEM_RELEASE);
	}
	else if (retain_staging && pData->pAllocationBase)
	{
		pData->MapStats.RetainedAllocBase = ReCa<ULONG_PTR>(pData->pAllocationBase);
		pData->MapStats.RetainedAllocSize = 0;
	}

	// Vector 1: once the payload no longer needs to write, unmap the RW view of the page-file section.
	if (pData->pSectionRwView && f->NtUnmapViewOfSection)
	{
		const NTSTATUS unmap_ret = f->NtUnmapViewOfSection(NtCurrentProcess(), ReCa<void *>(pData->pSectionRwView));
		if (NT_FAIL(unmap_ret))
		{
			// Retain the address on failure so it is not silently lost.
			pData->MapStats.RetainedAllocBase = ReCa<ULONG_PTR>(pData->pSectionRwView);
		}
		else
		{
			pData->pSectionRwView = nullptr;
		}
	}

	return 0;
}

#ifndef AMEGER_MMAP_SENTINEL
#define AMEGER_MMAP_SENTINEL (__LINE__ * 37u + 101u)
#endif

DWORD __declspec(code_seg(".code$14")) MMAP_SEC_END()
{
	return AMEGER_MMAP_SENTINEL;
}

MANUAL_MAPPING_FUNCTION_TABLE::MANUAL_MAPPING_FUNCTION_TABLE()
{
	NT_FUNC_CONSTRUCTOR_INIT(NtAllocateVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtProtectVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtFreeVirtualMemory);
	NT_FUNC_CONSTRUCTOR_INIT(NtSetEvent);
	NT_FUNC_CONSTRUCTOR_INIT(NtClose);
	NT_FUNC_CONSTRUCTOR_INIT(NtCreateSection);
	NT_FUNC_CONSTRUCTOR_INIT(NtMapViewOfSection);
	NT_FUNC_CONSTRUCTOR_INIT(NtUnmapViewOfSection);

	NT_FUNC_CONSTRUCTOR_INIT(memmove);
	NT_FUNC_CONSTRUCTOR_INIT(RtlZeroMemory);
	NT_FUNC_CONSTRUCTOR_INIT(RtlAllocateHeap);
	NT_FUNC_CONSTRUCTOR_INIT(RtlFreeHeap);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpLoadDllInternal);
	NT_FUNC_CONSTRUCTOR_INIT(LdrGetProcedureAddress);

	NT_FUNC_CONSTRUCTOR_INIT(LdrUnloadDll);

	NT_FUNC_CONSTRUCTOR_INIT(RtlAnsiStringToUnicodeString);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpPreprocessDllName);
	NT_FUNC_CONSTRUCTOR_INIT(RtlInsertInvertedFunctionTable);
#ifdef _WIN64
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(RtlLookupFunctionEntry);

	NT_FUNC_CONSTRUCTOR_INIT(RtlDeleteFunctionTable);
#endif
	NT_FUNC_CONSTRUCTOR_INIT(RtlAddVectoredExceptionHandler);
	NT_FUNC_CONSTRUCTOR_INIT(RtlRemoveVectoredExceptionHandler);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpHandleTlsData);

	NT_FUNC_CONSTRUCTOR_INIT(LdrLockLoaderLock);
	NT_FUNC_CONSTRUCTOR_INIT(LdrUnlockLoaderLock);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpDereferenceModule);

	NT_FUNC_CONSTRUCTOR_INIT(LdrProtectMrdata);

	NT_FUNC_CONSTRUCTOR_INIT(LdrpHeap);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpInvertedFunctionTable);
	NT_FUNC_CONSTRUCTOR_INIT(LdrpTlsList);
}

void ResetMapStats()
{
	const MAP_STATS Empty{};
	StoreMapStats(Empty);
}

void __stdcall GetLastMapStats(MAP_STATS * Out)
{
	EXPORT_FUNCTION("CoreLoadStats", __FUNCDNAME__)

	if (Out)
	{
		LoadMapStats(*Out);
	}
}

void ResetExecTelemetry()
{
	const VERIFIABLE_EXEC_TELEMETRY Empty{};
	StoreExecTelemetry(Empty);
}

void __stdcall GetLastExecTelemetry(VERIFIABLE_EXEC_TELEMETRY * Out)
{
	EXPORT_FUNCTION("CoreExecTelemetry", __FUNCDNAME__)

	if (Out)
	{
		LoadExecTelemetry(*Out);
	}
}
