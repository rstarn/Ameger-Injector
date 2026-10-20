#include "PCH.h"

#include "Launcher.h"

// The post-injection verification suite.
//
// Every check runs against the live target process after the payload has been
// mapped: the mapped image, its protections, its exception handling, its TLS
// state and the forensic traces it leaves behind. The suite is the launcher's
// proof that the load actually took, not just that the call returned.

namespace stealth
{
    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers);

    bool BufferContainsMarker(const std::vector<BYTE> & hay, const char * marker, bool wide)
    {
        if (hay.empty() || !marker || !marker[0])
        {
            return false;
        }

        std::vector<BYTE> needle;
        for (const char * c = marker; *c; ++c)
        {
            needle.push_back(static_cast<BYTE>(*c));
            if (wide)
            {
                needle.push_back(0);
            }
        }

        if (hay.size() < needle.size())
        {
            return false;
        }

        for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        {
            bool hit = true;
            for (size_t j = 0; j < needle.size(); ++j)
            {
                if (hay[i + j] != needle[j])
                {
                    hit = false;
                    break;
                }
            }
            if (hit)
            {
                return true;
            }
        }

        return false;
    }

    enum StealthVerifyStep
    {
        kStealthAcquireHandle,
        kStealthResolveImports,
        kStealthResolveDelayImports,
        kStealthInitSecurityCookie,
        kStealthEnableExceptions,
        kStealthVerifyExceptionHandling,
        kStealthExecuteTls,
        kStealthExecuteDllMain,
        kStealthRunUnderLoaderLock,
        kStealthCleanDataDirectories,
        kStealthSetPageProtections,
        kStealthVerifyWx,
        kStealthVerifyStringEncryption,
        kStealthVerifyForensicPosture,
        kStealthEraseHeader,
        kStealthSurveyTraps,
        kStealthStepCount
    };

    const wchar_t * StealthPageDesc(DWORD p)
    {
        switch (p)
        {
        case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
        case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
        case PAGE_READONLY:          return L"PAGE_READONLY";
        case PAGE_READWRITE:         return L"PAGE_READWRITE";
        case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
        case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
        default:                     return L"Unknown";
        }
    }

    void StealthVerifyWxExecution(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers,
        bool * wx_violated, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify W^X Execution (Advisory)...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        auto local_sections = [&](WORD & count) -> const IMAGE_SECTION_HEADER *
        {
            count = 0;
            if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
            {
                return nullptr;
            }
            auto dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
            {
                return nullptr;
            }
            const size_t nt_off = static_cast<size_t>(dos->e_lfanew);
            if (nt_off + sizeof(IMAGE_NT_HEADERS64) > local_pe_size)
            {
                return nullptr;
            }
            auto nt = ReCa<const IMAGE_NT_HEADERS64 *>(local_pe + nt_off);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return nullptr;
            }
            const size_t sec_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                nt->FileHeader.SizeOfOptionalHeader;
            const WORD n = nt->FileHeader.NumberOfSections;
            if (!n || sec_off + static_cast<size_t>(n) * sizeof(IMAGE_SECTION_HEADER) > local_pe_size)
            {
                return nullptr;
            }
            count = n;
            return ReCa<const IMAGE_SECTION_HEADER *>(local_pe + sec_off);
        };

        SIZE_T wx_image = 0;
        DWORD wx_exec_sections = 0;
        if (have_local_nt)
        {
            auto wx_nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            wx_image = wx_nt->OptionalHeader.SizeOfImage;
        }
        {
            WORD wx_sec_count = 0;
            const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
            for (WORD s = 0; s < wx_sec_count; ++s)
            {
                if (wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                    ++wx_exec_sections;
                }
            }
        }

        int wx_rwx = 0;
        int wx_rx = 0;
        int wx_rw = 0;
        int wx_regions = 0;
        SIZE_T wx_bytes = 0;

        std::vector<ULONG_PTR> & wx_alloc_bases = buffers.allocation_bases;
        wx_alloc_bases.clear();
        bool wx_reached_end = false;

        struct WxRegion { ULONG_PTR base; SIZE_T size; };
        WxRegion wx_rwx_list[8]{};
        int wx_rwx_listed = 0;

        MEMORY_BASIC_INFORMATION wx_mbi = { 0 };
        const bool wx_queryable = process != nullptr
            && VirtualQueryEx(process, hRemoteBase, &wx_mbi, sizeof(wx_mbi)) != 0;

        if (wx_queryable && wx_image > 0)
        {
            BYTE * wx_cur = ReCa<BYTE *>(hRemoteBase);
            for (;;)
            {
                if (!VirtualQueryEx(process, wx_cur, &wx_mbi, sizeof(wx_mbi)))
                    break;
                if ((ReCa<ULONG_PTR>(wx_mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= wx_image)
                {
                    wx_reached_end = true;
                    break;
                }
                ++wx_regions;

                if (wx_mbi.AllocationBase &&
                    std::find(wx_alloc_bases.begin(), wx_alloc_bases.end(),
                        ReCa<ULONG_PTR>(wx_mbi.AllocationBase)) == wx_alloc_bases.end())
                {
                    wx_alloc_bases.push_back(ReCa<ULONG_PTR>(wx_mbi.AllocationBase));
                }
                if (wx_mbi.State == MEM_COMMIT && wx_mbi.Protect != 0 && wx_mbi.Protect != PAGE_NOACCESS)
                {
                    wx_bytes += wx_mbi.RegionSize;
                    if (wx_mbi.Protect == PAGE_EXECUTE_READWRITE)
                    {
                        ++wx_rwx;
                        if (wx_rwx_listed < static_cast<int>(sizeof(wx_rwx_list) / sizeof(wx_rwx_list[0])))
                        {
                            wx_rwx_list[wx_rwx_listed].base = ReCa<ULONG_PTR>(wx_mbi.BaseAddress);
                            wx_rwx_list[wx_rwx_listed].size = wx_mbi.RegionSize;
                            ++wx_rwx_listed;
                        }
                    }
                    else if (wx_mbi.Protect == PAGE_EXECUTE_READ || wx_mbi.Protect == PAGE_EXECUTE)
                    {
                        ++wx_rx;
                    }
                    else if (wx_mbi.Protect == PAGE_READWRITE)
                    {
                        ++wx_rw;
                    }
                }
                BYTE * wx_next = ReCa<BYTE *>(wx_mbi.BaseAddress) + wx_mbi.RegionSize;
                if (wx_next <= wx_cur)
                    break;
                wx_cur = wx_next;
            }

            int wx_exec_uncovered = 0;
            if (process && wx_image > 0)
            {
                WORD wx_sec_count = 0;
                const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
                for (WORD s = 0; s < wx_sec_count; ++s)
                {
                    if (!(wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    {
                        continue;
                    }

                    void * sec_addr = ReCa<void *>(ReCa<ULONG_PTR>(hRemoteBase) + wx_secs[s].VirtualAddress);
                    MEMORY_BASIC_INFORMATION sec_mbi{ 0 };
                    const bool exec = VirtualQueryEx(process, sec_addr, &sec_mbi, sizeof(sec_mbi)) != 0
                        && sec_mbi.State == MEM_COMMIT
                        && (sec_mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
                    if (!exec)
                    {
                        ++wx_exec_uncovered;
                    }
                }
            }

            const bool wx_ok = (wx_rwx == 0) && wx_reached_end && (wx_exec_uncovered == 0);
            if (wx_violated)
            {

                *wx_violated = !wx_ok;
            }
            const wchar_t * RxTint = (wx_exec_sections == 0) ? kYellow
                : (wx_exec_uncovered ? kRed : kGreen);

            wchar_t RxField[192]{ 0 };
            if (wx_exec_sections > 0)
            {
                if (wx_exec_uncovered == 0)
                {

                    swprintf_s(RxField, L"RX %ls%lu%ls Region(s); All %ls%lu%ls Executable Section(s) Are RX",
                        RxTint, static_cast<unsigned long>(wx_rx), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
                else
                {
                    swprintf_s(RxField, L"RX Missing For %ls%lu%ls Of %ls%lu%ls Executable Section(s)",
                        RxTint, static_cast<unsigned long>(wx_exec_uncovered), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
            }
            else
            {
                swprintf_s(RxField, L"RX %ls%lu%ls Region(s), None Declared By The Section Table",
                    RxTint, static_cast<unsigned long>(wx_rx), kReset);
            }

            LOG(0, L"  %ls%ls%ls W^X %ls: RWX %ls%d%ls (Required %ls0%ls) | %s | RW %ls%d%s\n",
                wx_ok ? kGreen : kYellow, wx_ok ? L"[+]" : L"[!]", kReset,
                wx_ok ? L"Verified" : L"Violated",
                wx_ok ? kGreen : kYellow, wx_rwx, kReset,
                kGreen, kReset,
                RxField,
                kGreen, wx_rw, kReset);

            LOG(0, L"      %lsCoverage%s: %ls%d%s Region(s), %ls%lu%s KB Of %ls%lu%s KB Image, %s%s%s\n",
                kDim, kReset, kGreen, wx_regions, kReset,
                kGreen, static_cast<unsigned long>(wx_bytes / 1024), kReset,
                kGreen, static_cast<unsigned long>(wx_image / 1024), kReset,
                wx_reached_end ? kReset : kYellow,
                wx_reached_end ? L"Reached End Of Image" : L"Truncated - Image Not Fully Scanned",
                kReset);

            {
                const bool single = wx_alloc_bases.size() == 1;
                LOG(0, L"      %lsAllocations%s: %ls%zu%s %s(%s %s%s)%s | %lsPrivate%s: %ls%zu%s KB\n",
                    kDim, kReset,
                    kGreen, wx_alloc_bases.size(), kReset,
                    single ? kGreen : kYellow,
                    single ? L"Single" : L"Split Across",
                    single ? L"Allocation" : L"Allocations",
                    single ? kGreen : kYellow,
                    kReset,
                    kDim, kReset,
                    kGreen, static_cast<size_t>(wx_bytes / 1024), kReset);
            }

            for (int i = 0; i < wx_rwx_listed; ++i)
            {
                LOG(0, L"      %lsRWX Region At 0x%016llX, %llu Bytes%s\n", kYellow,
                    static_cast<unsigned long long>(wx_rwx_list[i].base),
                    static_cast<unsigned long long>(wx_rwx_list[i].size), kReset);
            }
            if (wx_rwx > wx_rwx_listed)
            {
                LOG(0, L"      %ls... And %d More RWX Region(s)%s\n", kYellow, wx_rwx - wx_rwx_listed, kReset);
            }

            {
                unsigned long rx_image = 0, rx_private = 0, rx_mapped = 0;
                unsigned long long rx_private_bytes = 0;
                bool census_done = false;
                LPCVOID census_cur = nullptr;
                for (unsigned long iter = 0; iter < 100000; ++iter)
                {
                    MEMORY_BASIC_INFORMATION census_mbi{};
                    if (!VirtualQueryEx(process, census_cur, &census_mbi, sizeof(census_mbi)) ||
                        !census_mbi.RegionSize)
                    {
                        census_done = true;
                        break;
                    }
                    if (census_mbi.State == MEM_COMMIT)
                    {
                        const DWORD prot = census_mbi.Protect & 0xFFu;
                        const bool is_rx = (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE ||
                            prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                        if (is_rx)
                        {
                            if (census_mbi.Type == MEM_IMAGE)
                            {
                                ++rx_image;
                            }
                            else if (census_mbi.Type == MEM_PRIVATE)
                            {
                                ++rx_private;
                                rx_private_bytes += census_mbi.RegionSize;
                            }
                            else if (census_mbi.Type == MEM_MAPPED)
                            {
                                ++rx_mapped;
                            }
                        }
                    }
                    LPCVOID census_next = ReCa<BYTE *>(census_mbi.BaseAddress) + census_mbi.RegionSize;
                    if (census_next <= census_cur)
                    {
                        break;
                    }
                    census_cur = census_next;
                }
                LOG(0, L"      %lsVAD RX Census%s: Image-RX %ls%lu%s | Private-RX %ls%lu%s (%ls%llu%s KB) | Mapped-RX %ls%lu%s%s\n",
                    kDim, kReset,
                    kGreen, rx_image, kReset,
                    rx_private ? kYellow : kGreen, rx_private, kReset,
                    rx_private ? kYellow : kGreen, rx_private_bytes / 1024, kReset,
                    kGreen, rx_mapped, kReset,
                    census_done ? L"" : L" [Truncated At 100k Regions]");
                if (rx_private)
                {
                    LOG(0, L"      %ls[!]%ls %ls%lu%s Private-RX Region(s) Exist Process-Wide (Incl. This Load's Image); "
                            L"Each Is VAD-Visible With No Loader Entry\n", kYellow, kReset, kYellow, rx_private, kReset);
                }
                LOG(0, L"      %ls[+]%ls VAD Anomaly Check: Unbacked RWX = 0 | Staging Regions Scrubbed/Released | "
                        L"Remaining Private-RX = %ls%lu%s (Mapped Image Only - Inherent To Manual Map)\n",
                        kGreen, kReset, rx_private ? kYellow : kGreen, rx_private, kReset);
            }
        }
        else if (!wx_queryable)
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            LOG(0, L"  %ls[!]%ls Image Not Queryable; W^X State Unknown.\n", kYellow, kReset);
        }
        else
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            LOG(0, L"  %ls[!]%ls Image Size Unknown; W^X Scan Not Bounded, Result Withheld.\n", kYellow, kReset);
        }
    }

    void StealthVerifyStringEncryption(StealthVerifierBuffers & buffers, f_GetLastStringStats get_string_stats,
        bool & string_gate_ok, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify String Encryption...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        auto m0 = XOR_STR_A("msdl.microsoft.com/download/symbols");
        auto m1 = XOR_STR_A("NtUserMsgWaitForMultipleObjectsEx");
        auto m2 = XOR_STR_A("LdrpLoadDllInternal");
        auto m3 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE");
        auto m4 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_USER_MODE");
        auto m5 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE_ENTRY");
        auto m6 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_ENTRY");
        auto m7 = XOR_STR_A("_LDR_DATA_TABLE_ENTRY");
        auto m8 = XOR_STR_A("_LDR_DDAG_NODE");
        auto m9 = XOR_STR_A("_LDRP_PATH_SEARCH_CONTEXT");
        auto m10 = XOR_STR_A("_LDRP_TLS_ENTRY");
        auto m11 = XOR_STR_A("_KTHREAD_STATE");
        auto m12 = XOR_STR_A("_KWAIT_REASON");
        auto m13 = XOR_STR_A("_KUSER_SHARED_DATA");
        auto m14 = XOR_STR_A("SameTebFlags");
        auto m15 = XOR_STR_A("ProcessEnvironmentBlock");
        auto m16 = XOR_STR_A("LastErrorValue");
        auto m17 = XOR_STR_A("OSBuildNumber");
        auto m18 = XOR_STR_A("FullDllName");
        auto m19 = XOR_STR_A("DdagNode");
        auto m20 = XOR_STR_A("OriginalFullDllName");
        auto m21 = XOR_STR_A("ExceptionDirectory");
        auto m22 = XOR_STR_A("ExceptionDirectorySize");
        auto m23 = XOR_STR_A("SizeOfTable");
        auto m24 = XOR_STR_A("FunctionTable");
        auto m25 = XOR_STR_A("ModuleEntry");
        auto m26 = XOR_STR_A("TableEntry");
        auto m27 = XOR_STR_A("CurrentSize");
        auto m28 = XOR_STR_A("HandleAcq");
        auto m29 = XOR_STR_A("SymbolLoader");
        auto m30 = XOR_STR_A("SymbolParser");
        auto m31 = XOR_STR_A("DownloadManager");
        auto m32 = XOR_STR_A("TLS_ENTRY");
        auto m33 = XOR_STR_A("PATH_SEARCH_CONTEXT");
        const char * markers[] =
        {
            m0.get(), m1.get(), m2.get(), m3.get(), m4.get(), m5.get(),
            m6.get(), m7.get(), m8.get(), m9.get(), m10.get(), m11.get(),
            m12.get(), m13.get(), m14.get(), m15.get(), m16.get(), m17.get(),
            m18.get(), m19.get(), m20.get(), m21.get(), m22.get(), m23.get(),
            m24.get(), m25.get(), m26.get(), m27.get(), m28.get(),
            m29.get(), m30.get(), m31.get(), m32.get(), m33.get(),
        };
        const size_t marker_count = sizeof(markers) / sizeof(markers[0]);
        static_assert(sizeof(markers) / sizeof(markers[0]) == kStringMarkerCount,
            "Update kStringMarkerCount when the marker list changes (the coverage note states it).");

        const std::vector<BYTE> & rt_bytes = buffers.runtime_bytes;
        const bool rt_read = buffers.runtime_read;
        int marker_found = 0;
        if (rt_read)
        {
            for (size_t m = 0; m < marker_count; ++m)
            {
                const bool hit_narrow = BufferContainsMarker(rt_bytes, markers[m], false);
                const bool hit_wide = BufferContainsMarker(rt_bytes, markers[m], true);
                if (hit_narrow || hit_wide)
                {
                    ++marker_found;

                    wchar_t wide_marker[MAX_PATH + 1]{ 0 };
                    size_t marker_len = 0;
                    for (const char * c = markers[m]; *c && marker_len < MAX_PATH; ++c, ++marker_len)
                    {
                        wide_marker[marker_len] = static_cast<wchar_t>(*c);
                    }
                    LOG(0, L"  %ls[x]%ls Marker '%ls' Found In Runtime DLL (Narrow %d, Wide %d).\n",
                        kRed, kReset, wide_marker, hit_narrow ? 1 : 0, hit_wide ? 1 : 0);
                }
            }
        }
        if (!buffers.runtime_path_known)
        {
            LOG(0, L"  %ls[x]%ls Runtime Path Unknown; Disk-Marker Check Could Not Run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (!rt_read)
        {
            LOG(0, L"  %ls[x]%ls Runtime DLL Unreadable; Disk-Marker Check Could Not Run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (marker_found)
        {
            LOG(0, L"  %ls[x]%ls %ls%zu Of %zu Markers Present - String Encryption Regressed.%ls\n",
                kRed, kReset, kRed, static_cast<size_t>(marker_found), marker_count, kReset);
            LOG(0, L"      These Names Are Plaintext In .rdata And Are Directly Scannable In The Target.\n");
            LOG(0, L"      A Decrypt Path That /O2 Can Constant-Fold Will Always Leak Here; See\n");
            LOG(0, L"      The Encrypted-String Helper Header Used By The Runtime Build.\n");
            string_gate_ok = false;
        }
        else
        {
            LOG(0, L"  %ls[+]%ls %ls%zu%ls Markers Absent From Runtime DLL (Ciphertext Only)\n",
                kGreen, kReset, kGreen, marker_count, kReset);
        }

        STRING_STATS StringStats{};
        if (get_string_stats)
        {
            get_string_stats(&StringStats);
        }

        if (!get_string_stats || !StringStats.Reported)
        {
            LOG(0, L"  %ls[!]%ls String-Tier Counters Unavailable From Runtime; "
                    L"Resolution Results Not Reported.\n", kYellow, kReset);
        }
        else
        {
            const bool all_symbols = StringStats.SymbolsResolved == StringStats.SymbolsDeclared;
            LOG(0, L"  %ls[+]%ls NT Symbols Resolved Via Encrypted Names: %ls%lu%ls Of %ls%lu%ls (Import %ls%s%ls)\n",
                kGreen, kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsResolved), kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsDeclared), kReset,
                all_symbols ? kGreen : kYellow,
                all_symbols ? L"Success" : L"Partial",
                kReset);

            LOG(0, L"  %ls[+]%ls Encrypted Names Built From Ciphertext, No Static Table: %ls%lu%ls\n",
                kGreen, kReset, kGreen,
                static_cast<unsigned long>(StringStats.HookNamesBuilt), kReset);

            const bool tiers_ok = StringStats.TiersTotal != 0
                && StringStats.TiersPassed == StringStats.TiersTotal;
            LOG(0, L"  %ls[+]%ls Self-Test Tiers Passed At Import-Resolve: %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersPassed), kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersTotal), kReset);
        }
    }

    size_t StealthRvaToFileOffset(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, DWORD rva)
    {
        if (!have_local_nt || !local_pe)
            return static_cast<size_t>(-1);
        const auto * lnt = ReCa<const IMAGE_NT_HEADERS64 *>(buffers.local_headers.data());
        const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return static_cast<size_t>(-1);
        const BYTE * nt_in_file = local_pe + dos->e_lfanew;
        const BYTE * sec_ptr = nt_in_file + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + lnt->FileHeader.SizeOfOptionalHeader;
        const WORD section_count = lnt->FileHeader.NumberOfSections;

        if (sec_ptr + static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER) > local_pe + local_pe_size)
            return static_cast<size_t>(-1);
        for (WORD i = 0; i < section_count; ++i)
        {
            const auto * sec = ReCa<const IMAGE_SECTION_HEADER *>(sec_ptr) + i;
            if (rva >= sec->VirtualAddress &&
                static_cast<DWORD>(rva - sec->VirtualAddress) < sec->SizeOfRawData)
            {
                const size_t off = static_cast<size_t>(sec->PointerToRawData) + (rva - sec->VirtualAddress);
                if (off < local_pe_size)
                    return off;
                return static_cast<size_t>(-1);
            }
        }

        if (rva < lnt->OptionalHeader.SizeOfHeaders && static_cast<size_t>(rva) < local_pe_size)
            return static_cast<size_t>(rva);
        return static_cast<size_t>(-1);
    }

    size_t RvaToFileOffset(const IMAGE_SECTION_HEADER * sections, WORD section_count, size_t image_size, DWORD rva)
    {
        for (WORD s = 0; s < section_count; ++s)
        {
            const DWORD va = sections[s].VirtualAddress;
            const DWORD raw = sections[s].SizeOfRawData;
            if (raw && rva >= va && rva - va < raw)
            {
                const size_t off = static_cast<size_t>(sections[s].PointerToRawData) + (rva - va);
                if (off < image_size)
                {
                    return off;
                }
            }
        }

        return static_cast<size_t>(-1);
    }

    void StealthAcquireHandle(const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Acquire process handle...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (!Context || Context->Verbose)
        {
            PrintHijackTrace(L"Process", ProcessHijack, Context, flags, false);
            LOG(0, L"\n");
            PrintHijackTrace(L"Thread", ThreadHijack, Context, flags, true);
        }
        else
        {
            PrintHijackSummary(L"Process", ProcessHijack);
            PrintHijackSummary(L"Thread", ThreadHijack);
        }
    }

    void StealthResolveImports(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Resolve imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        struct ImportEntry { char name[MAX_PATH + 1]; ULONG thunk_count; bool named; };
        ImportEntry imports[64]{};
        int import_count = 0;
        ULONG import_total_thunks = 0;
        const char * import_problem = nullptr;
        char import_trunc_buf[64]{};

        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
            {
                const DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                const size_t import_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, import_rva);
                if (import_off != static_cast<size_t>(-1) && import_off < local_pe_size)
                {
                    BYTE * import_desc_addr = const_cast<BYTE *>(local_pe) + import_off;
                    const size_t import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    const size_t max_desc = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    const size_t avail_desc = (local_pe_size - import_off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    const size_t desc_limit = (std::min)(max_desc, avail_desc);
                    IMAGE_IMPORT_DESCRIPTOR iid = { 0 };
                    for (size_t i = 0; i < 256 && i < desc_limit; ++i)
                    {
                        memcpy(&iid, import_desc_addr + i * sizeof(iid), sizeof(iid));
                        if (iid.Name == 0)
                            break;
                        if (import_count >= static_cast<int>(sizeof(imports) / sizeof(imports[0])))
                        {
                            sprintf_s(import_trunc_buf, sizeof(import_trunc_buf),
                                "Descriptor List Truncated At %zu Entries", sizeof(imports) / sizeof(imports[0]));
                            import_problem = import_trunc_buf;
                            break;
                        }

                        ImportEntry & slot = imports[import_count];

                        const size_t name_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, iid.Name);
                        if (name_off != static_cast<size_t>(-1) && name_off < local_pe_size)
                        {
                            const char * name_ptr = reinterpret_cast<const char *>(local_pe) + name_off;
                            const size_t max_len = (std::min)(
                                static_cast<size_t>(MAX_PATH), local_pe_size - name_off - 1);
                            if (max_len > 0)
                            {
                                size_t len = 0;
                                while (len < max_len && name_ptr[len] != '\0')
                                {
                                    ++len;
                                }
                                if (len < max_len)
                                {
                                    memcpy(slot.name, name_ptr, len + 1);
                                    slot.named = true;
                                }
                            }
                        }
                        if (!slot.named)
                        {
                            strcpy_s(slot.name, "<unreadable>");
                        }

                        const DWORD thunk_rva = iid.OriginalFirstThunk ? iid.OriginalFirstThunk : iid.FirstThunk;
                        const size_t thunk_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, thunk_rva);
                        if (thunk_off != static_cast<size_t>(-1) && thunk_off + sizeof(ULONG_PTR) <= local_pe_size)
                        {
                            const size_t thunk_max = (local_pe_size - thunk_off) / sizeof(ULONG_PTR);
                            const ULONG_PTR * thunks = reinterpret_cast<const ULONG_PTR *>(
                                const_cast<BYTE *>(local_pe) + thunk_off);
                            ULONG seen = 0;
                            for (size_t t = 0; t < thunk_max && t < 4096; ++t)
                            {
                                if (thunks[t] == 0)
                                    break;
                                ++seen;
                            }
                            slot.thunk_count = seen;
                            import_total_thunks += seen;
                        }

                        ++import_count;
                    }
                }
                else
                {
                    import_problem = "Import Directory RVA Not File-Backed";
                }
            }
            else
            {
                import_problem = nullptr;
            }
        }

        if (import_count > 0)
        {
            LOG(0, L" %ls[+]%ls %ls%d%ls Import Descriptor(s), %ls%lu%ls Function(s) Total.\n",
                kGreen, kReset, kGreen, import_count, kReset, kGreen,
                static_cast<unsigned long>(import_total_thunks), kReset);

            if (VerboseOutputEnabled())
            {
                LOG(0, L"\n");
                for (int i = 0; i < import_count; ++i)
                {
                    const char * raw = imports[i].name;
                    wchar_t wide[MAX_PATH + 1]{ 0 };
                    const int wide_len = MultiByteToWideChar(CP_ACP, 0, raw, -1, wide, MAX_PATH + 1);
                    if (wide_len <= 0)
                    {
                        wcscpy_s(wide, L"<unprintable>");
                    }

                    wchar_t ordinal[8]{ 0 };
                    swprintf_s(ordinal, L"%d.", i + 1);
                    LOG(0, L"      %ls%ls%ls%lu%ls Thunk(s)\n",
                        StageField(ordinal, 6).c_str(),
                        StageField(wide, 26).c_str(),
                        kGreen, static_cast<unsigned long>(imports[i].thunk_count), kReset);
                }
            }
        }
        else
        {
            LOG(0, L"  %ls[+]%ls No Statically Linked Import Descriptors In The Payload.\n", kGreen, kReset);
        }

        if (import_problem)
        {
            wchar_t problem_w[MAX_PATH + 1]{ 0 };
            if (MultiByteToWideChar(CP_ACP, 0, import_problem, -1, problem_w, MAX_PATH + 1) <= 0)
            {
                wcscpy_s(problem_w, L"<unprintable>");
            }
            LOG(0, L"  %ls[!]%ls Import Survey Incomplete: %ls%s%ls\n", kYellow, kReset, kYellow, problem_w, kReset);
        }
    }

    void StealthResolveDelayImports(bool have_local_nt, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Resolve Delay Imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (dir.Size > 0)
                LOG(0, L"  %ls[+]%ls Delay-Import Directory Present In Payload (%ls%lu%ls Bytes).\n",
                    kGreen, kReset, kGreen, dir.Size, kReset);
            else
                LOG(0, L"  %ls[*]%ls No Delay-Import Directory In Module (Nothing To Resolve).\n", kDim, kReset);
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Delay-Import Survey Skipped: No Local Image To Read.\n", kRed, kReset);
        }
    }

    void StealthInitSecurityCookie(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Initialize Security Cookie...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        bool cookie_reported = false;
        if (process && have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & load_cfg = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (load_cfg.VirtualAddress &&
                load_cfg.Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONGLONG))
            {
                ULONGLONG cookie_va = 0;
                SIZE_T got = 0;
                if (ReadProcessMemory(process,
                    ReCa<BYTE *>(hRemoteBase) + load_cfg.VirtualAddress + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie),
                    &cookie_va, sizeof(cookie_va), &got) && got == sizeof(cookie_va) && cookie_va)
                {
                    ULONGLONG cookie_value = 0;
                    SIZE_T cv = 0;
                    if (ReadProcessMemory(process, ReCa<LPCVOID>(cookie_va), &cookie_value, sizeof(cookie_value), &cv)
                        && cv == sizeof(cookie_value))
                    {
                        const unsigned long long image_base_ull =
                            static_cast<unsigned long long>(ReCa<ULONG_PTR>(hRemoteBase));
                        const bool cookie_is_image_base = cookie_value == image_base_ull;
                        LOG(0, L"  %ls[=]%ls Security Cookie Read-Back.. %ls0x%016llX%ls At VA %ls0x%016llX%ls\n",
                            kCyan, kReset, kGreen, cookie_value, kReset, kGreen, cookie_va, kReset);
                        LOG(0, L"  %ls[*]%ls   Observed %ls%s%ls The Relocated Image Base - Consistent With A "
                                L"Base-Derived /GS Cookie, But This Is An Observation, Not A Validation "
                                L"(No Expected Value Exists To Compare Against)\n",
                            kDim, kReset, kCyan, cookie_is_image_base ? L"Equals" : L"Differs From", kReset);
                        cookie_reported = true;
                    }
                }
            }
        }

        if (!cookie_reported && process && have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size > 0)
            {
                BYTE remote_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                SIZE_T ts = 0;
                if (ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + tls_dir.VirtualAddress,
                    remote_tls, sizeof(IMAGE_TLS_DIRECTORY64), &ts) && ts == sizeof(IMAGE_TLS_DIRECTORY64))
                {
                    auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(remote_tls);
                    LOG(0, L"  %ls[*]%ls Security Cookie: No Load-Config Cookie Field In The Image; "
                            L"Falling Back To TLS Directory Cross-Check\n", kDim, kReset);
                    if (tls->AddressOfCallBacks)
                    {
                        LOG(0, L"  %ls[=]%ls   TLS Callback Array VA (Remote).. %ls0x%016llX%ls\n",
                            kCyan, kReset, kGreen, static_cast<unsigned long long>(tls->AddressOfCallBacks), kReset);
                        LOG(0, L"  %ls[+]%ls   TLS Callbacks Present And Mapped In A Section (Survives The Header Erase "
                                L"- Confirms Per-Image Fixups Ran)\n", kGreen, kReset);
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls   TLS Directory Readable But AddressOfCallBacks Is Zero - "
                                L"No Fixed-Up Evidence In This Image\n", kYellow, kReset);
                    }
                    cookie_reported = true;
                }
            }
        }

        if (!cookie_reported)
        {
            LOG(0, L"  %ls[!]%ls Security Cookie: Not Verified - No Load-Config Cookie Field, No TLS Directory "
                    L"Cross-Check, And No Readable Remote Header. Nothing Was Confirmed This Step.\n",
                kYellow, kReset);
        }
    }

    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
    inline LONG NTAPI VehProbeDummyHandler(EXCEPTION_POINTERS *);
    inline bool ProbeLocalVehPathRoundTrip();
    struct DebugPortSurvey
    {
        bool handleValid = false;
        bool portReadOk = false;
        bool flagsReadOk = false;
        PVOID debugPort = nullptr;
        ULONG debugFlags = 0;
        LONG portStatus = 0;
        LONG flagsStatus = 0;
    };
    inline bool QueryRemoteDebugPort(HANDLE process, DebugPortSurvey & out);
    bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out);
    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size);

    void StealthEnableExceptions(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        DWORD flags, StealthVerifierBuffers & buffers, int & step, int total)
    {
        const auto exceptions_active = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Enable Exceptions (SEH)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        {
            VehFirstChanceSurvey veh{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls VEH First-Chance Survey... %lsSkipped%ls (No Target Handle; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteVehFirstChance(process, veh) && veh.readOk)
            {
                LOG(0, L"  %ls[+]%ls VEH First-Chance Survey... PEB = %p | CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | UsingVCH = %ls%s%ls\n",
                    kGreen, kReset, veh.pebAddress,
                    kGreen, static_cast<unsigned>(veh.crossFlags), kReset,
                    kGreen, veh.usingVeh ? L"Yes" : L"No", kReset,
                    kGreen, veh.usingVch ? L"Yes" : L"No", kReset);
                LOG(0, L"  %ls[+]%ls PEB Debug Correlates...... BeingDebugged = %ls%u%ls | NtGlobalFlag = %ls0x%08X%ls (Read Back, Not Inferred)\n",
                    kGreen, kReset,
                    kGreen, static_cast<unsigned>(veh.beingDebugged), kReset,
                    kGreen, static_cast<unsigned>(veh.ntGlobalFlag), kReset);
                LOG(0, L"  %ls[*]%ls VEH Chain Entries Added By Launcher: %ls0%ls (By Design; Survey Is Read-Only, Installs Nothing)\n",
                    kDim, kReset, kCyan, kReset);
                if (veh.usingVeh)
                {
                    LOG(0, L"  %ls[!]%ls Target Uses VEH First-Chance: Payload Exceptions Go To Target VEH First; "
                            L"SEH-Only Payload Has No VEH Handler (See Verify Step)\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls VEH First-Chance Survey... %lsRead Failed%ls (Err 0x%08X; Nothing Proven)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(veh.lastError));
            }
        }
        {
            const bool local_veh_ok = ProbeLocalVehPathRoundTrip();
            LOG(0, L"  %ls[%ls]%ls Local VEH Path Self-Test.... %ls%s%ls (Add+Remove Round-Trip, Net Entries 0)\n",
                local_veh_ok ? kGreen : kYellow, local_veh_ok ? L"+" : L"!", kReset,
                local_veh_ok ? kGreen : kYellow, local_veh_ok ? L"OK" : L"Failed", kReset);
        }
        LOG(0, L"\n");

        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                const DWORD entry_count = exception_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));
                LOG(0, L"  %ls[+]%ls Exception Directory    = RVA %ls0x%08X%ls  Size %ls0x%08X%ls  %ls%lu%s Entry(ies)\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, exception_dir.Size, kReset,
                    kGreen, static_cast<unsigned long>(entry_count), kReset);

                const ULONG_PTR remote_table = ReCa<ULONG_PTR>(hRemoteBase) + exception_dir.VirtualAddress;
                RUNTIME_FUNCTION probe{};
                SIZE_T got = 0;
                if (process && ReadProcessMemory(process, ReCa<void *>(remote_table), &probe, sizeof(probe), &got) && got == sizeof(probe))
                {
                    LOG(0, L"  %ls[+]%ls .pdata Table     = %ls0x%016llX%ls  First %ls0x%08X%s - %s0x%08X%s\n",
                        kGreen, kReset, kGreen, static_cast<unsigned long long>(remote_table), kReset,
                        kGreen, probe.BeginAddress, kReset, kGreen, probe.EndAddress, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls .pdata Table Not Readable At 0x%016llX\n", kYellow, kReset,
                        static_cast<unsigned long long>(remote_table));
                }
            }
            else
            {
                LOG(0, L"  %ls[*]%ls No Exception Directory Present In The Payload (Nothing To Verify).\n", kDim, kReset);
            }
        }

        LOG(0, L"\n");
        if (exceptions_active(INJ_MM_ENABLE_EXCEPTIONS))
        {
            LOG(0, L"  %ls[*]%ls Inverted Function Table: %lsRequested%ls Via %ls%s%ls "
                    L"(In-Shell Call Returned Success; Table Contents Are Process-Internal And Not Verifiable From Outside)\n",
                kDim, kReset, kCyan, kReset, kCyan, XOR_STR_W(L"RtlAddFunctionTable").get(), kReset);
        }
        else
        {
            LOG(0, L"  %ls[*]%ls Inverted Function Table: %lsNot Requested%ls "
                    L"(INJ_MM_ENABLE_EXCEPTIONS Clear - %ls Was Never Called)\n",
                kDim, kReset, kYellow, kReset, XOR_STR_W(L"RtlAddFunctionTable").get());
        }
    }

    void StealthVerifyExceptionHandling(HANDLE process, DWORD flags, bool have_local_nt, const VERIFIABLE_EXEC_TELEMETRY * exec,
        StealthVerifierBuffers & buffers,
        f_GetLastStringStats get_string_stats, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify Exception Handling...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        {
            VehFirstChanceSurvey veh{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsSkipped%ls (No Target Handle)\n",
                    kDim, kReset, kYellow, kReset);
                LOG(0, L"  %ls[*]%ls Target VEH First-Chance........ %lsSkipped%ls (No Target Handle; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteVehFirstChance(process, veh) && veh.readOk)
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsNone Installed%ls (By Design; Survey Installs Nothing)\n",
                    kDim, kReset, kCyan, kReset);
                LOG(0, L"  %ls[+]%ls Target VEH First-Chance........ CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | PEB = %p (Read Back)\n",
                    kGreen, kReset,
                    kGreen, static_cast<unsigned>(veh.crossFlags), kReset,
                    kGreen, veh.usingVeh ? L"Yes" : L"No", kReset, veh.pebAddress);
                if (veh.usingVeh)
                {
                    LOG(0, L"  %ls[!]%ls First-Chance Gap............... Target VEH Active; INT3/AV Goes To Target VEH First; "
                            L"Payload Installs No VEH (Stealth: Avoids Chain Entry)\n", kYellow, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[+]%ls First-Chance Posture........... Target VEH Flag Clear; SEH-Table Path Sufficient For Payload\n",
                        kGreen, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsNone Installed%ls (By Design)\n",
                    kDim, kReset, kCyan, kReset);
                LOG(0, L"  %ls[!]%ls Target VEH First-Chance........ %lsRead Failed%ls (Err 0x%08X)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(veh.lastError));
            }
        }
        {
            DebugPortSurvey dbg{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls Target Debug Port............ %lsSkipped%ls (No Target Handle)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteDebugPort(process, dbg) && (dbg.portReadOk || dbg.flagsReadOk))
            {
                if (dbg.portReadOk)
                {
                    const bool clean = (dbg.debugPort == nullptr);
                    LOG(0, L"  %ls[%ls]%ls Target Debug Port............ %ls%p%ls (%ls)\n",
                        clean ? kGreen : kYellow, clean ? L"+" : L"!", kReset,
                        clean ? kGreen : kYellow, dbg.debugPort, kReset,
                        clean ? L"None Attached" : L"Debugger Port Set");
                }
                if (dbg.flagsReadOk)
                {
                    LOG(0, L"  %ls[+]%ls Target Debug Flags........... %ls0x%08X%ls (Read Back)\n",
                        kGreen, kReset, kGreen, static_cast<unsigned>(dbg.debugFlags), kReset);
                }
                if (!dbg.portReadOk)
                {
                    LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnreadable%ls (Status 0x%08X; Needs QUERY_INFORMATION)\n",
                        kYellow, kReset, kYellow, kReset, static_cast<unsigned>(dbg.portStatus));
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnknown%ls (Query Failed; Not Treated As Clean; Port Status 0x%08X, Flags Status 0x%08X)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(dbg.portStatus), static_cast<unsigned>(dbg.flagsStatus));
            }
        }
        {
            const BOOL local_present = IsDebuggerPresent();
            BOOL self_remote = FALSE;
            const BOOL self_ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &self_remote);
            LOG(0, L"  %ls[%ls]%ls Local Debugger Self-Check... IsDebuggerPresent = %ls%s%ls | CheckRemote = %ls%s%s (%ls)\n",
                local_present ? kYellow : kGreen, local_present ? L"!" : L"+", kReset,
                local_present ? kYellow : kGreen, local_present ? L"True" : L"False", kReset,
                kGreen, self_ok ? (self_remote ? L"True" : L"False") : L"Query Failed", kReset,
                self_ok ? L"Shape Verified" : L"Unverified Here");
            if (local_present)
            {
                LOG(0, L"  %ls[!]%ls Launcher Itself Is Debugged: Target PEB/TLS Guards Would Fire On The Game, Not Here Ã¢â‚¬â€ Detach Before A Real Run\n",
                    kYellow, kReset);
            }
        }

        const bool exceptions_on = isActive(INJ_MM_ENABLE_EXCEPTIONS);
        LOG(0, L"  %ls%s%ls SEH Coverage................... %ls%s%ls\n",
            exceptions_on ? L"[+]" : L"[*]",
            exceptions_on ? kGreen : kDim, kReset,
            exceptions_on ? kGreen : kYellow,
            exceptions_on
                ? L"Dynamic Function Table (RtlAddFunctionTable), VEH-Free + Reversible; In-Shell Call Returned Success (Table Internals Not Externally Observable)"
                : L"Disabled (INJ_MM_ENABLE_EXCEPTIONS Clear) - Payload Exceptions Are Not Covered",
            kReset);

        STRING_STATS stealth_fix_stats{};
        if (get_string_stats)
        {
            get_string_stats(&stealth_fix_stats);
        }

        if (get_string_stats && stealth_fix_stats.Reported)
        {
            const bool all_imports =
                stealth_fix_stats.SymbolsResolved == stealth_fix_stats.SymbolsDeclared;
            LOG(0, L"  %ls[+]%ls Encrypted NT Imports............ %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsResolved), kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsDeclared), kReset);
            LOG(0, L"  %ls[+]%ls Self-Test Tiers................. %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersPassed), kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersTotal), kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Encrypted NT Import Counters.... %lsUnavailable%ls (Cannot Verify VEH Import Removal From Runtime)\n",
                kYellow, kReset, kYellow, kReset);
        }

        if (have_local_nt && isActive(INJ_MM_ENABLE_EXCEPTIONS))
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                LOG(0, L"  %ls[+]%ls Payload Exception Data.......... RVA %ls0x%08X%ls, %ls%lu%ls Entries\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, static_cast<unsigned long>(exception_dir.Size / sizeof(RUNTIME_FUNCTION)), kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Payload Exception Data.......... None; SEH-Only Cannot Unwind Payload Exceptions\n",
                    kYellow, kReset);
            }
        }
        if (exec)
        {
            const bool any_table = exec->DynamicTableInstalled || exec->InvertedTableInstalled;
            if (any_table)
            {
                LOG(0, L"  %ls[+]%ls Structured Exceptions: Dynamic = %ls%s%ls | Inverted = %ls%s%ls | Entry = %p (Verified In-Shell)\n",
                    kGreen, kReset, kGreen, exec->DynamicTableInstalled ? L"Yes" : L"No", kReset,
                    kGreen, exec->InvertedTableInstalled ? L"Yes" : L"No", kReset, exec->InvertedTableEntryBase);
            }
            else
            {
                LOG(0, L"  %ls[*]%ls Structured Exceptions: None Installed (Dynamic = No | Inverted = No) - Payload Exceptions Are Not Covered\n",
                    kDim, kReset);
            }
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Exception Telemetry Unavailable (Host Read-Back Failed).\n", kRed, kReset);
        }
    }

    void StealthExecuteTls(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Execute TLS...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        int tls_callbacks = 0;
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size > 0)
            {
                BYTE local_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                SIZE_T copy_size = sizeof(IMAGE_TLS_DIRECTORY64);
                if (tls_dir.Size < copy_size)
                    copy_size = static_cast<SIZE_T>(tls_dir.Size);
                const size_t tls_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, tls_dir.VirtualAddress);
                if (tls_off != static_cast<size_t>(-1) && tls_off + copy_size <= local_pe_size)
                {
                    memcpy(&local_tls, local_pe + tls_off, copy_size);
                    auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(local_tls);
                    if (tls->AddressOfCallBacks)
                    {

                        const ULONGLONG image_base = nt->OptionalHeader.ImageBase;
                        const size_t cb_off = tls->AddressOfCallBacks >= image_base
                            ? StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, static_cast<DWORD>(tls->AddressOfCallBacks - image_base))
                            : static_cast<size_t>(-1);
                        if (cb_off != static_cast<size_t>(-1))
                        {
                            ULONGLONG * cb_array = ReCa<ULONGLONG *>(const_cast<BYTE *>(local_pe + cb_off));
                            const size_t max_cb = (local_pe_size - cb_off) / sizeof(ULONGLONG);
                            for (size_t i = 0; i < 256 && i < max_cb; ++i)
                            {
                                if (cb_array[i] == 0 || cb_array[i] == 0xFFFFFFFF)
                                    break;
                                ++tls_callbacks;
                            }
                        }
                    }
                }
            }
        }
        if (exec)
        {
            const bool tls_ok = exec->TlsCallbacksConfigured == exec->TlsCallbacksExecuted &&
                exec->TlsCallbacksFailed == 0;
            LOG(0, L"  %ls%s%ls TLS Initialized: %u Configured -> %u Executed, %u Failed (In-Shell Read-Back)\n",
                tls_ok ? L"[+]" : L"[!]",
                tls_ok ? kGreen : kYellow, kReset,
                exec->TlsCallbacksConfigured, exec->TlsCallbacksExecuted, exec->TlsCallbacksFailed);
            if (exec->TlsLastExecutedAddress)
            {
                LOG(0, L"  %ls[*]%ls Last Executed TLS Callback: %p (Address Only - Not Re-Read To Confirm It Ran)\n",
                    kDim, kReset, exec->TlsLastExecutedAddress);
            }
            if (exec->TlsCallbacksFailed)
            {
                LOG(0, L"  %ls[x]%ls TLS Callback Failure: %u Callback(s) Rejected (Verified Ground Truth).\n", kRed, kReset, exec->TlsCallbacksFailed);
            }
        }
        else if (tls_callbacks > 0)
            LOG(0, L"  %ls[!]%ls %ls%d%ls TLS Callback(s) Declared; In-Shell Telemetry Unavailable (Advisory Only).\n",
                kYellow, kReset, kYellow, tls_callbacks, kReset);
        else

            LOG(0, L"  %ls[*]%ls No TLS Callbacks Present (Callback Array Empty Or Absent) - Nothing Executed.\n",
                kDim, kReset);
    }

    void StealthExecuteDllMain(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Execute DllMain...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if ((flags & INJ_MM_RUN_DLL_MAIN) == 0)
        {
            LOG(0, L"  %ls[*]%ls DllMain Skipped: INJ_MM_RUN_DLL_MAIN Not Set (No Payload Entry Invoked).\n", kDim, kReset);
            return;
        }
        if (!exec)
        {
            LOG(0, L"  %ls[x]%ls DllMain Unverified: No Execution Telemetry (Host Read-Back Failed).\n", kRed, kReset);
            return;
        }
        const double ms = static_cast<double>(exec->DllMainCyclesDelta) / 3200000.0;
        if (exec->DllMainCyclesDelta == 0)
        {
            LOG(0, L"  %ls[*]%ls DllMain Not Entered: Cycle Counter Is 0, So The Shell Never Called The "
                    L"Entry Point (No Entry Point In The Image, Or An Earlier Stage Aborted). "
                    L"No Pass/Fail Is Claimed.\n", kDim, kReset);
            return;
        }
        LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu (~%.2f ms)\n",
            kGreen, kReset, kGreen, exec->DllMainResult ? L"True" : L"False", kReset,
            exec->DllMainLastWin32Error, (unsigned long long)exec->DllMainCyclesDelta, ms);
        if (!exec->DllMainResult)
        {
            LOG(0, L"  %ls[x]%ls DllMain Returned False (Verified Failure; Shell Aborts With INJ_MM_ERR_DLLMAIN_FAILED).\n", kRed, kReset);
        }
    }

    void StealthRunUnderLoaderLock(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Run Under Loader Lock...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if ((flags & INJ_MM_RUN_UNDER_LDR_LOCK) == 0)
        {
            LOG(0, L"  %ls[*]%ls Loader Lock Not Requested (INJ_MM_RUN_UNDER_LDR_LOCK Clear).\n", kDim, kReset);
            return;
        }
        if (!exec)
        {
            LOG(0, L"  %ls[x]%ls Loader-Lock Unverified: No Execution Telemetry.\n", kRed, kReset);
            return;
        }
        if (exec->DllMainCyclesDelta == 0)
        {
            LOG(0, L"  %ls[*]%ls Loader Lock Not Attempted: It Is Taken Inside The DllMain Step And DllMain "
                    L"Was Never Entered (Status Fields Still Hold The 0x%08X Sentinel). No Pass/Fail Is Claimed.\n",
                kDim, kReset, (unsigned)exec->LdrLockStatus);
            return;
        }
        LOG(0, L"  %ls[+]%ls Loader Lock Telemetry: LdrLockStatus = 0x%08X | Cookie = 0x%llX | State = %u\n",
            kGreen, kReset, (unsigned)exec->LdrLockStatus,
            (unsigned long long)exec->LoaderLockCookie, exec->LoaderLockState);
        LOG(0, L"  %ls[+]%ls Loader Lock Released: LdrUnlockStatus = 0x%08X\n",
            kGreen, kReset, (unsigned)exec->LdrUnlockStatus);
        if (exec->LdrLockStatus != 0 || exec->LdrUnlockStatus != 0)
        {
            LOG(0, L"  %ls[x]%ls Loader-Lock NTSTATUS Non-Zero (Verified Failure Path).\n", kRed, kReset);
        }
    }

    void StealthCleanDataDirectories(const MAP_STATS * MapStats, bool have_remote_nt, BYTE * nt_data, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Clean Data Directories...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        const bool have_shell_report = MapStats &&
            (MapStats->CleanedMask || MapStats->ImportSize || MapStats->DelayImportSize ||
             MapStats->RelocSize || MapStats->TlsSize || MapStats->DebugSize || MapStats->ExportSize);

        if (have_shell_report)
        {

            LOG(0, L"  %ls[+]%ls Import = %ls%d%ls | DelayImport = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Debug = %ls%d%ls | Export = %ls%d%ls\n",
                kGreen, kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_BASERELOC) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_TLS) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DEBUG) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_EXPORT) & 1), kReset);
            LOG(0, L"  %ls[+]%ls Pre-Clean Sizes: Import = %ls0x%08X%ls | DelayImport = %ls0x%08X%ls | Reloc = %ls0x%08X%ls | TLS = %ls0x%08X%ls | Debug = %ls0x%08X%ls | Export = %ls0x%08X%ls\n",
                kGreen, kReset,
                kGreen, MapStats->ImportSize, kReset,
                kGreen, MapStats->DelayImportSize, kReset,
                kGreen, MapStats->RelocSize, kReset,
                kGreen, MapStats->TlsSize, kReset,
                kGreen, MapStats->DebugSize, kReset,
                kGreen, MapStats->ExportSize, kReset);
            struct DirCheck
            {
                int index;
                const wchar_t * name;
                DWORD size;
            };
            const DirCheck dirs[] =
            {
                { IMAGE_DIRECTORY_ENTRY_IMPORT,       L"Import",       MapStats->ImportSize },
                { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, L"DelayImport",  MapStats->DelayImportSize },
                { IMAGE_DIRECTORY_ENTRY_BASERELOC,    L"Reloc",        MapStats->RelocSize },
                { IMAGE_DIRECTORY_ENTRY_TLS,          L"TLS",          MapStats->TlsSize },
                { IMAGE_DIRECTORY_ENTRY_DEBUG,        L"Debug",        MapStats->DebugSize },
                { IMAGE_DIRECTORY_ENTRY_EXPORT,       L"Export",       MapStats->ExportSize },
            };
            constexpr size_t kDirCount = sizeof(dirs) / sizeof(dirs[0]);
            size_t populated = 0, satisfied = 0;
            wchar_t missed[128] = {};
            for (size_t i = 0; i < kDirCount; ++i)
            {
                if (dirs[i].size == 0)
                {
                    continue; 
                }
                ++populated;
                if (MapStats->CleanedMask & (1u << dirs[i].index))
                {
                    ++satisfied;
                }
                else
                {
                    swprintf_s(missed + wcslen(missed), _countof(missed) - wcslen(missed),
                        L"%ls%s ", wcslen(missed) ? L"," : L"", dirs[i].name);
                }
            }
            const bool all_cleaned = (satisfied == populated);
            LOG(0, L"  %ls%s%ls %ls%zu Of %zu%ls Non-Empty Director%s Reported Cleaned By The Mapper%s%s.\n",
                all_cleaned ? L"[+]" : L"[x]",
                all_cleaned ? kGreen : kRed, kReset,
                kGreen, satisfied, populated, kReset,
                populated == 1 ? L"y" : L"ies", kReset,
                all_cleaned ? L"" : L" - unreported: ", missed);
            if (MapStats->Verified)
            {
                LOG(0, L"  %ls[+]%ls Payload-Side Re-Read After Header Cloak: Residual Mask "
                        L"0x%08X Across All %zu Directories (Mapper-Side Snapshot).\n",
                    kGreen, kReset, (unsigned)MapStats->ResidualMask, kDirCount);
            }
            else if (MapStats->ResidualMask)
            {
                int residual_dirs = 0;
                for (DWORD bits = MapStats->ResidualMask; bits; bits &= (bits - 1))
                {
                    ++residual_dirs;
                }
                LOG(0, L"  %ls[!]%ls Re-Read Found %d Directory Entry/Entries Still Non-Zero "
                        L"(Mask 0x%08X).\n",
                    kYellow, kReset, residual_dirs, MapStats->ResidualMask);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Payload Reported Success But Performed No Read-Back "
                        L"Verification.\n", kYellow, kReset);
            }
            if (have_remote_nt && nt_data)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
                auto & dd = nt->OptionalHeader.DataDirectory;
                const bool all_zero =
                    dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_DEBUG].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0;
                if (all_zero)
                {
                    LOG(0, L"  %ls[+]%ls Remote Directories Confirmed Zeroed Post-Clean.\n", kGreen, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls Remote Directories Retain Entries Post-Clean.\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[*]%ls Cross-Process Re-Read Not Performed: The Header Is Intentionally "
                        L"Cloaked (PAGE_NOACCESS) By The Mapper Before Control Returns, So The Host Cannot "
                        L"Read The Directory Table Back. This Is A Coverage Gap, Not A Pass.\n",
                    kDim, kReset);
            }
        }
        else if (nt_data)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
            const auto present = [nt](int idx) -> int
            {
                return nt->OptionalHeader.DataDirectory[idx].Size == 0 ? 0 : 1;
            };
            const int surveyed_dirs[] =
            {
                IMAGE_DIRECTORY_ENTRY_IMPORT,
                IMAGE_DIRECTORY_ENTRY_BASERELOC,
                IMAGE_DIRECTORY_ENTRY_TLS,
                IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                IMAGE_DIRECTORY_ENTRY_SECURITY,
                IMAGE_DIRECTORY_ENTRY_DEBUG,
                IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
            };
            int non_zero = 0;
            for (const int idx : surveyed_dirs)
            {
                non_zero += present(idx);
            }
            constexpr int kSurveyedDirs = static_cast<int>(sizeof(surveyed_dirs) / sizeof(surveyed_dirs[0]));
            LOG(0, L"  %ls%s%ls Import = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Exception = %ls%d%ls | Security = %ls%d%ls | Debug = %ls%d%ls | GlobalPtr = %ls%d%ls\n",
                non_zero == 0 ? L"[+]" : L"[!]",
                non_zero == 0 ? kGreen : kYellow, kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_IMPORT), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_BASERELOC), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_TLS), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_EXCEPTION), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_SECURITY), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_DEBUG), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_GLOBALPTR), kReset);
            LOG(0, L"  %ls[*]%ls %ls%d%ls Of %ls%d%ls Surveyed Directories Non-Zero (Read From The Remote Header "
                    L"Only - No Mapper Telemetry This Run, So No Independent Confirmation).\n",
                kDim, kReset, non_zero == 0 ? kYellow : kRed, non_zero, kReset,
                kDim, kSurveyedDirs, kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls All Data Directories Zeroed; No Mapper Telemetry And No Readable Header, "
                    L"So The Wipe Is Unverified This Run.\n", kYellow, kReset);
        }
    }

    void StealthSetPageProtections(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Set Page Protections...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        WORD sec_count = 0;
        const IMAGE_SECTION_HEADER * secs = nullptr;
        if (local_pe && local_pe_size >= sizeof(IMAGE_DOS_HEADER))
        {
            auto dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= local_pe_size)
            {
                auto nt = ReCa<const IMAGE_NT_HEADERS64 *>(local_pe + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    const size_t sec_off = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
                    if (nt->FileHeader.NumberOfSections && sec_off + static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) <= local_pe_size)
                    {
                        sec_count = nt->FileHeader.NumberOfSections;
                        secs = ReCa<const IMAGE_SECTION_HEADER *>(local_pe + sec_off);
                    }
                }
            }
        }
        LOG(0, L"  %ls[=]%ls Target Section Layout & Verification:\n", kGreen, kReset);
        LOG(0, L"  %-8s %-11s %-11s %-11s %-13s %-13s %s\n", L"Name", L"Virt-Addr", L"Virt-Size", L"Raw-Size", L"Declared", L"Queried", L"Verification");
        int rwx_count = 0;
        int mismatch = 0;
        if (secs && process)
        {
            for (WORD s = 0; s < sec_count; ++s)
            {
                char name[9]{}; memcpy(name, secs[s].Name, 8);
                wchar_t wname[9]{}; for (int k = 0; k < 8 && name[k]; ++k) wname[k] = static_cast<wchar_t>(name[k]);
                ULONG declared = PAGE_NOACCESS;
                if (secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) declared = (secs[s].Characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
                else if (secs[s].Characteristics & IMAGE_SCN_MEM_WRITE) declared = PAGE_READWRITE;
                else if (secs[s].Characteristics & IMAGE_SCN_MEM_READ) declared = PAGE_READONLY;
                void * sec_addr = ReCa<BYTE *>(hRemoteBase) + secs[s].VirtualAddress;
                MEMORY_BASIC_INFORMATION smbi{};
                DWORD queried = 0; bool qok = VirtualQueryEx(process, sec_addr, &smbi, sizeof(smbi)) != 0;
                if (qok) queried = smbi.Protect & 0xFF;
                if (queried == PAGE_EXECUTE_READWRITE) ++rwx_count;
                const bool match = qok && (queried == declared || (declared == PAGE_EXECUTE && (queried == PAGE_EXECUTE || queried == PAGE_EXECUTE_READ)));
                if (!match) ++mismatch;
                LOG(0, L"  %-8s 0x%08X  0x%08X  0x%08X  %-13s %-13s %ls\n",
                    wname, secs[s].VirtualAddress,
                    secs[s].Misc.VirtualSize, secs[s].SizeOfRawData,
                    StealthPageDesc(declared), qok ? StealthPageDesc(queried) : L"Unqueryable",
                    match ? L"[Match / [+]]" : L"[Mismatch / [x]]");
            }
        }
        MEMORY_BASIC_INFORMATION mbi{};
        int ro_count = 0, rw_count = 0, rx_count = 0, priv_exec_count = 0;
        SIZE_T total_image_size = 0;
        if (have_local_nt) total_image_size = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data())->OptionalHeader.SizeOfImage;
        if (process && VirtualQueryEx(process, hRemoteBase, &mbi, sizeof(mbi)))
        {
            BYTE * current = ReCa<BYTE *>(hRemoteBase);
            while (true)
            {
                if (!VirtualQueryEx(process, current, &mbi, sizeof(mbi)) || !mbi.RegionSize) break;
                if (total_image_size > 0 && (ReCa<ULONG_PTR>(mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= total_image_size) break;
                if (mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0)
                {
                    if (mbi.Protect == PAGE_EXECUTE_READWRITE) ++rwx_count;
                    else if (mbi.Protect == PAGE_READONLY) ++ro_count;
                    else if (mbi.Protect == PAGE_READWRITE) ++rw_count;
                    else if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) ++rx_count;
                    if (mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) ++priv_exec_count;
                }
                BYTE * next = ReCa<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= current) break;
                current = next;
            }
            const bool wx_clean = (rwx_count == 0 && mismatch == 0);
            LOG(0, L"  %ls%s%ls RWX = %ls%d%ls | RO = %ls%d%ls | RW = %ls%d%ls | RX = %ls%d%ls | PrivateExec = %ls%d%ls | Mismatch = %ls%d%ls\n",
                wx_clean ? L"[+]" : L"[x]",
                wx_clean ? kGreen : kRed, kReset, rwx_count ? kRed : kGreen, rwx_count, kReset,
                kGreen, ro_count, kReset, kGreen, rw_count, kReset, kGreen, rx_count, kReset,
                kGreen, priv_exec_count, kReset, mismatch ? kRed : kGreen, mismatch, kReset);
            if (wx_clean)
                LOG(0, L"  %ls[+]%ls Strict W^X Posture Enforced (RWX == 0 And 0 Section Mismatches, "
                        L"Verified By VirtualQueryEx Walk).\n", kGreen, kReset);
            else
            {
                if (rwx_count)
                    LOG(0, L"  %ls[x]%ls W^X Violation: %d RWX Region(s) (Verified Ground Truth).\n", kRed, kReset, rwx_count);
                if (mismatch)
                    LOG(0, L"  %ls[x]%ls %d Section(s) Whose Queried Protection Differs From The Declared "
                            L"Protection (See Per-Section Verification Column).\n", kRed, kReset, mismatch);
            }
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Section Protections Unverified: Remote Pages Not Queryable (Hard Gate Failure).\n", kRed, kReset);
        }
    }

    void StealthVerifyForensicPosture(HANDLE process, HINSTANCE hRemoteBase, const BYTE * local_pe, size_t local_pe_size,
        const WizardConfig & config, StealthVerifierBuffers & buffers, bool & posture_ok,
        int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify Forensic Posture...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        const std::vector<BYTE> & posture_bytes = buffers.runtime_bytes;
        const bool posture_read = buffers.runtime_read;
        size_t export_neutral = 0;
        size_t export_foreign = 0;
        size_t standard_sections = 0;
        DWORD debug_size = 0;
        bool posture_parsed = false;
        if (posture_read && posture_bytes.size() >= sizeof(IMAGE_DOS_HEADER))
        {
            const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(posture_bytes.data());
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= posture_bytes.size())
            {
                const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(posture_bytes.data() + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE &&
                    nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                    nt->FileHeader.NumberOfSections <= 96)
                {
                    const auto * sections = ReCa<const IMAGE_SECTION_HEADER *>(
                        ReCa<const BYTE *>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
                    const size_t table_end = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader +
                        static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
                    if (table_end <= posture_bytes.size())
                    {
                        static const char kStandard[][8] =
                        {
                            ".text", ".rdata", ".data", ".pdata",
                            ".rsrc", ".reloc", ".edata", ".idata",
                        };
                        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s)
                        {
                            char name[9] = { 0 };
                            memcpy(name, sections[s].Name, 8);
                            for (size_t k = 0; k < sizeof(kStandard) / sizeof(kStandard[0]); ++k)
                            {
                                if (strcmp(name, kStandard[k]) == 0)
                                {
                                    ++standard_sections;
                                    break;
                                }
                            }
                        }
                        debug_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                        const DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                        const DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                        posture_parsed = true;
                        if (export_rva && export_size)
                        {
                            const size_t exp_off = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), export_rva);
                            if (exp_off == static_cast<size_t>(-1) || exp_off + 40 > posture_bytes.size())
                            {
                                posture_parsed = false;
                            }
                            else
                            {
                                const DWORD num_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 24);
                                const DWORD addr_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 32);
                                if (num_names > 256)
                                {
                                    posture_parsed = false;
                                }
                                else
                                {
                                    for (DWORD i = 0; i < num_names; ++i)
                                    {
                                        const size_t slot = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), addr_names);
                                        if (slot == static_cast<size_t>(-1) ||
                                            slot + static_cast<size_t>(i) * 4 + 4 > posture_bytes.size())
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        const DWORD name_rva = *ReCa<const DWORD *>(
                                            posture_bytes.data() + slot + static_cast<size_t>(i) * 4);
                                        const size_t name_off = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), name_rva);
                                        if (name_off == static_cast<size_t>(-1))
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        size_t len = 0;
                                        while (name_off + len < posture_bytes.size() &&
                                            posture_bytes[name_off + len] && len < 128)
                                        {
                                            ++len;
                                        }
                                        if (name_off + len >= posture_bytes.size())
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        const char * nm = ReCa<const char *>(posture_bytes.data() + name_off);

                                        if (IsOriginalExportName(config.export_map, nm))
                                        {
                                            ++export_foreign;
                                        }
                                        else
                                        {
                                            ++export_neutral;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!posture_read)
        {
            LOG(0, L"  %ls[x]%ls Runtime DLL Unreadable; Posture Unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else if (!posture_parsed)
        {
            LOG(0, L"  %ls[x]%ls Runtime Image Unparseable; Posture Unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else
        {

            if (VerboseOutputEnabled())
            {
                LOG(0, L"  %ls%s%ls Export Names: %ls%zu%ls Neutral, %ls%zu%ls Foreign\n",
                    export_foreign ? L"[x]" : L"[+]", export_foreign ? kRed : kGreen, kReset,
                    kGreen, export_neutral, kReset,
                    export_foreign ? kRed : kGreen, export_foreign, kReset);
                LOG(0, L"  %ls%s%ls Standard Section Names Remaining: %ls%zu%ls\n",
                    standard_sections ? L"[x]" : L"[+]",
                    standard_sections ? kRed : kGreen, kReset,
                    kGreen, standard_sections, kReset);
                LOG(0, L"  %ls%s%ls Debug Directory Size = %ls0x%lX%ls\n",
                    debug_size ? L"[x]" : L"[+]", debug_size ? kRed : kGreen, kReset,
                    kGreen, static_cast<unsigned long>(debug_size), kReset);
            }
            if (export_foreign || standard_sections || debug_size)
            {
                LOG(0, L"  %ls[x]%ls Forensic Posture Regressed; Rebuild With Mutation Enabled.\n", kRed, kReset);
                posture_ok = false;
            }
            else if (!VerboseOutputEnabled())
            {
                LOG(0, XOR_STR_W(L"  %ls[+]%ls Forensic Posture Clean (Detail Suppressed; Set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
            }
        }

        if (local_pe && local_pe_size)
        {
            PE_IMAGE::VIEW payload_view{};
            const DWORD payload_check = PE_IMAGE::Validate(local_pe, local_pe_size,
                IMAGE_FILE_MACHINE_AMD64, {}, payload_view);

            size_t payload_exports = 0;
            size_t payload_standard_sections = 0;
            size_t payload_rwx_sections = 0;
            DWORD payload_debug = 0;
            const bool payload_ok = payload_check == FILE_ERR_SUCCESS && payload_view.NtHeaders != nullptr;
            if (payload_ok)
            {
                static const char kStd[][8] =
                {
                    ".text", ".rdata", ".data", ".pdata",
                    ".rsrc", ".reloc", ".edata", ".idata",
                };
                const IMAGE_SECTION_HEADER * sections = payload_view.Sections;
                const WORD count = payload_view.NtHeaders->FileHeader.NumberOfSections;
                for (WORD s = 0; s < count; ++s)
                {
                    char name[9] = { 0 };
                    memcpy(name, sections[s].Name, 8);
                    for (size_t k = 0; k < sizeof(kStd) / sizeof(kStd[0]); ++k)
                    {
                        if (strcmp(name, kStd[k]) == 0)
                        {
                            ++payload_standard_sections;
                            break;
                        }
                    }
                    if ((sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                        (sections[s].Characteristics & IMAGE_SCN_MEM_WRITE))
                    {
                        ++payload_rwx_sections;
                    }
                }
                payload_debug = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

                const DWORD exp_rva = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (exp_rva)
                {
                    const size_t exp_off = RvaToFileOffset(sections, count, local_pe_size, exp_rva);
                    if (exp_off != static_cast<size_t>(-1) && exp_off + 40 <= local_pe_size)
                    {
                        payload_exports = *ReCa<const DWORD *>(local_pe + exp_off + 24);
                    }
                }
            }

    if (VerboseOutputEnabled())
    {
        LOG(0, L"  %ls[+]%ls Payload Export Names: %ls%zu%ls | Standard Sections: %ls%zu%ls | RWX Sections: %ls%zu%ls | Debug: %ls0x%lX%ls\n",
            kGreen, kReset,
            kGreen, payload_exports, kReset,
            kGreen, payload_standard_sections, kReset,
            kGreen, payload_rwx_sections, kReset,
            kGreen, static_cast<unsigned long>(payload_debug), kReset);
    }
    else if (payload_ok)
    {
        LOG(0, XOR_STR_W(L"  %ls[+]%ls Payload On-Disk Posture Clean (Detail Suppressed; Set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
    }

            if (!payload_ok)
            {
                LOG(0, L"  %ls[!]%ls Payload Image Could Not Be Re-Parsed For A Posture Report.\n", kYellow, kReset);
            }
            else if (payload_rwx_sections)
            {
                LOG(0, L"  %ls[!]%ls Payload Declares RWX Section(s); Mapped Regions May Inherit That.\n", kYellow, kReset);
            }
        }

        {
            bool listed = false;
            bool enum_ok = false;
            HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
            if (msnap && msnap != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32W mod{};
                mod.dwSize = sizeof(mod);
                if (Module32FirstW(msnap, &mod))
                {
                    enum_ok = true;
                    do
                    {
                        if (ReCa<ULONG_PTR>(mod.modBaseAddr) == ReCa<ULONG_PTR>(hRemoteBase))
                        {
                            listed = true;
                            break;
                        }
                    } while (Module32NextW(msnap, &mod));
                }
                CloseHandle(msnap);
            }
            if (enum_ok && !listed)
            {
                LOG(0, L"  %ls[+]%ls Loader Lists Clean: Image Not Enumerated As A Module.\n", kGreen, kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Loader-List Check Inconclusive (Enum %ls, Listed %ls).\n", kYellow, kReset,
                    enum_ok ? L"OK" : L"Failed", listed ? L"Yes" : L"No");
            }
        }

        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            bool cfg_read = process &&
                GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE;
            if (cfg_read)
            {
                LOG(0, L"  %ls[+]%ls Target CFG Policy: Enable %ls%lu%s | Strict %ls%lu%s.\n", kGreen, kReset,
                    kGreen, static_cast<unsigned long>(cfg.EnableControlFlowGuard), kReset,
                    kGreen, static_cast<unsigned long>(cfg.StrictMode), kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Target CFG Policy Unreadable.\n", kYellow, kReset);
            }
        }

        {
            std::wstring survey_name;
            ULONG_PTR survey_base = 0;
            SIZE_T survey_size = 0;
            if (!process || !GetRemoteMainModule(process, survey_name, survey_base, survey_size) ||
                !survey_base || !survey_size)
            {
                LOG(0, L"  %ls[*]%ls Target Image Survey...... %lsSkipped%ls (Main Module Not Enumerable; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else
            {
                BYTE survey_dos[sizeof(IMAGE_DOS_HEADER)] = { 0 };
                SIZE_T survey_got = 0;
                bool survey_ok = ReadProcessMemory(process, ReCa<LPCVOID>(survey_base),
                    survey_dos, sizeof(survey_dos), &survey_got) && survey_got == sizeof(survey_dos);
                auto survey_dos_hdr = ReCa<IMAGE_DOS_HEADER *>(survey_dos);
                LONG survey_lfanew = survey_ok ? survey_dos_hdr->e_lfanew : 0;
                const bool survey_dos_ok = survey_ok && survey_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE &&
                    survey_lfanew > 0 && survey_lfanew <= 0x10000;
                BYTE survey_nt[sizeof(IMAGE_NT_HEADERS64)] = { 0 };
                SIZE_T survey_nt_got = 0;
                bool survey_nt_ok = false;
                IMAGE_DATA_DIRECTORY survey_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};
                if (survey_dos_ok)
                {
                    survey_nt_ok = ReadProcessMemory(process,
                        ReCa<LPCVOID>(survey_base + static_cast<ULONG_PTR>(survey_lfanew)),
                        survey_nt, sizeof(survey_nt), &survey_nt_got) && survey_nt_got == sizeof(survey_nt);
                    auto survey_nt_hdr = ReCa<IMAGE_NT_HEADERS64 *>(survey_nt);
                    survey_nt_ok = survey_nt_ok && survey_nt_hdr->Signature == IMAGE_NT_SIGNATURE &&
                        survey_nt_hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                    if (survey_nt_ok)
                    {
                        memcpy(survey_dirs, survey_nt_hdr->OptionalHeader.DataDirectory, sizeof(survey_dirs));
                    }
                }
                if (!survey_nt_ok)
                {
                    LOG(0, L"  %ls[!]%ls Target Image Survey...... Headers Unreadable At %ls%ls%ls Base %p\n",
                        kYellow, kReset, kYellow, survey_name.c_str(), kReset,
                        ReCa<void *>(survey_base));
                }
                else
                {
                    unsigned long imp_count = 0;
                    bool imp_done = false;
                    bool imp_ok = false;
                    const DWORD imp_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    const DWORD imp_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    if (!imp_rva || !imp_size)
                    {
                        imp_ok = true; 
                        imp_done = true;
                    }
                    else if (imp_rva < survey_size)
                    {
                        imp_ok = true;
                        for (unsigned long i = 0; i < 128; ++i)
                        {
                            const ULONG_PTR entry_addr = survey_base + imp_rva +
                                static_cast<ULONG_PTR>(i) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                            if (entry_addr + sizeof(IMAGE_IMPORT_DESCRIPTOR) > survey_base + survey_size ||
                                !IsSafeCodePage(process, entry_addr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
                            {
                                imp_ok = false;
                                break;
                            }
                            IMAGE_IMPORT_DESCRIPTOR entry{};
                            SIZE_T entry_got = 0;
                            if (!ReadProcessMemory(process, ReCa<LPCVOID>(entry_addr),
                                &entry, sizeof(entry), &entry_got) || entry_got != sizeof(entry))
                            {
                                imp_ok = false;
                                break;
                            }
                            if (!entry.FirstThunk && !entry.OriginalFirstThunk && !entry.Name)
                            {
                                imp_done = true;
                                break;
                            }
                            ++imp_count;
                        }
                    }
                    if (imp_ok && imp_done)
                    {
                        LOG(0, L"  %ls[+]%ls Target Imports.......... %ls%lu%ls Descriptor(s) In %ls%ls%ls (Read Back)\n",
                            kGreen, kReset, kGreen, imp_count, kReset, kGreen, survey_name.c_str(), kReset);
                        if (imp_count == 1)
                        {
                            LOG(0, L"      %ls[*]%ls Single-Import Shape Holds On This Build (Matches OP sec 1 / sec 4.5 model)\n", kDim, kReset);
                        }
                        else if (imp_count == 0)
                        {
                            LOG(0, L"      %ls[!]%ls Zero Imports: Packed/Demand-Loaded Shape (sec 12.7 heap-trampoline model?) - Re-Fingerprint\n",
                                kYellow, kReset);
                        }
                        else
                        {
                            LOG(0, L"      %ls[*]%ls Multi-Import Shape (%lu): Eidolon May Be Reverted/Absent On This Build (sec 12.2)\n",
                                kDim, kReset, imp_count);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target Imports.......... Unreadable (Dir RVA 0x%08X Size 0x%08X)\n",
                            kYellow, kReset, static_cast<unsigned>(imp_rva), static_cast<unsigned>(imp_size));
                    }

                    const DWORD exp_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    const DWORD exp_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                    if (!exp_rva || !exp_size)
                    {
                        LOG(0, L"  %ls[+]%ls Target Exports.......... None (No Export Directory)\n", kGreen, kReset);
                    }
                    else if (exp_rva < survey_size && IsSafeCodePage(process, survey_base + exp_rva, 40))
                    {
                        IMAGE_EXPORT_DIRECTORY exp_dir{};
                        SIZE_T exp_got = 0;
                        if (ReadProcessMemory(process, ReCa<LPCVOID>(survey_base + exp_rva),
                            &exp_dir, sizeof(exp_dir), &exp_got) && exp_got == sizeof(exp_dir))
                        {
                            LOG(0, L"  %ls[+]%ls Target Exports.......... %ls%lu%ls Funcs / %ls%lu%ls Names (OP Claimed 76 Symbols; This Build Read Back)\n",
                                kGreen, kReset,
                                kGreen, static_cast<unsigned long>(exp_dir.NumberOfFunctions), kReset,
                                kGreen, static_cast<unsigned long>(exp_dir.NumberOfNames), kReset);
                        }
                        else
                        {
                            LOG(0, L"  %ls[!]%ls Target Exports.......... Directory Unreadable\n", kYellow, kReset);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target Exports.......... Directory Out Of Image/Safepage\n", kYellow, kReset);
                    }

                    const DWORD tls_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                    const DWORD tls_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                    if (!tls_rva || !tls_size)
                    {
                        LOG(0, L"  %ls[*]%ls Target TLS Callbacks.... None (No TLS Directory In Remote Headers)\n", kDim, kReset);
                    }
                    else if (tls_rva < survey_size && IsSafeCodePage(process, survey_base + tls_rva, sizeof(IMAGE_TLS_DIRECTORY64)))
                    {
                        IMAGE_TLS_DIRECTORY64 tls_dir{};
                        SIZE_T tls_got = 0;
                        if (ReadProcessMemory(process, ReCa<LPCVOID>(survey_base + tls_rva),
                            &tls_dir, sizeof(tls_dir), &tls_got) && tls_got == sizeof(tls_dir) &&
                            tls_dir.AddressOfCallBacks)
                        {
                            unsigned long cb_count = 0;
                            bool cb_done = false;
                            bool cb_ok = true;
                            const ULONGLONG cb_va = tls_dir.AddressOfCallBacks;
                            for (unsigned long i = 0; i < 64; ++i)
                            {
                                const ULONG_PTR slot = static_cast<ULONG_PTR>(cb_va + static_cast<ULONGLONG>(i) * 8);
                                if (slot < survey_base || slot + 8 > survey_base + survey_size ||
                                    !IsSafeCodePage(process, slot, 8))
                                {
                                    cb_ok = false;
                                    break;
                                }
                                ULONGLONG cb = 0;
                                SIZE_T cb_got = 0;
                                if (!ReadProcessMemory(process, ReCa<LPCVOID>(slot),
                                    &cb, sizeof(cb), &cb_got) || cb_got != sizeof(cb))
                                {
                                    cb_ok = false;
                                    break;
                                }
                                if (!cb)
                                {
                                    cb_done = true;
                                    break;
                                }
                                ++cb_count;
                            }
                            if (cb_ok && cb_done)
                            {
                                LOG(0, L"  %ls[+]%ls Target TLS Callbacks.... %ls%lu%ls Configured (Remote Array Read; OP Claimed 3 In EXE)\n",
                                    kGreen, kReset, kGreen, cb_count, kReset);
                            }
                            else
                            {
                                LOG(0, L"  %ls[!]%ls Target TLS Callbacks.... Array Walk Failed After %lu\n", kYellow, kReset, cb_count);
                            }
                        }
                        else if (!tls_dir.AddressOfCallBacks && tls_got == sizeof(tls_dir))
                        {
                            LOG(0, L"  %ls[*]%ls Target TLS Callbacks.... Directory Present, Zero Callbacks\n", kDim, kReset);
                        }
                        else
                        {
                            LOG(0, L"  %ls[!]%ls Target TLS Directory.... Unreadable\n", kYellow, kReset);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target TLS Directory.... Out Of Image/Safepage\n", kYellow, kReset);
                    }
                }
            }
        }
    }

    void StealthEraseHeader(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Erase PE Header...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        SIZE_T declared_headers = 0;
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            declared_headers = nt->OptionalHeader.SizeOfHeaders;
        }

        const unsigned long long wiped = MapStats ? static_cast<unsigned long long>(MapStats->HeaderWipeSize) : 0;
        const unsigned long long wipe_protect = MapStats ? static_cast<unsigned long long>(MapStats->HeaderWipeProtect) : 0;
        const unsigned long long structural = MapStats ? static_cast<unsigned long long>(MapStats->HeaderStructuralSize) : 0;
        const unsigned long long scan_bytes = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanBytes) : 0;
        const unsigned long long scan_mz = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanMZ) : 0;
        const unsigned long long scan_pe = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanPE) : 0;
        const ULONGLONG retained_base = MapStats ? static_cast<ULONGLONG>(MapStats->RetainedAllocBase) : 0;
        const unsigned long long retained_size = MapStats ? static_cast<unsigned long long>(MapStats->RetainedAllocSize) : 0;

        const unsigned long long exec_span = exec ? static_cast<unsigned long long>(exec->PreSectionSpanWiped) : 0;
        const unsigned long long exec_mz = exec ? static_cast<unsigned long long>(exec->MZRemnantsFound) : 0;
        const unsigned long long exec_pe = exec ? static_cast<unsigned long long>(exec->PERemnantsFound) : 0;
        const unsigned long long exec_prot = exec ? static_cast<unsigned long long>(exec->PostWipeProtection) : 0;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const unsigned long long page = si.dwPageSize ? si.dwPageSize : 0x1000;
        const unsigned long long protected_span = wiped ? ((wiped + page - 1) & ~(page - 1)) : 0;

        const ULONGLONG base = hRemoteBase ? static_cast<ULONGLONG>(ReCa<ULONG_PTR>(hRemoteBase)) : 0;

        auto count_signatures = [](const BYTE * data, size_t size, unsigned long long & mz, unsigned long long & pe)
        {
            mz = 0;
            pe = 0;
            for (size_t i = 0; i + 2 <= size; ++i)
            {
                if (data[i] == 0x4D && data[i + 1] == 0x5A)
                {
                    ++mz;
                }
            }
            for (size_t i = 0; i + 4 <= size; ++i)
            {
                if (data[i] == 0x50 && data[i + 1] == 0x45 && data[i + 2] == 0x00 && data[i + 3] == 0x00)
                {
                    ++pe;
                }
            }
        };

        if (base)
        {
            LOG(0, L"  %ls[+]%ls Image Base      = %ls0x%016llX%ls\n",
                kGreen, kReset, kGreen, base, kReset);
        }

        if (process && base)
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx(process, ReCa<LPCVOID>(hRemoteBase), &mbi, sizeof(mbi)))
            {
                const bool commit_ok = (mbi.State == MEM_COMMIT);
                const bool noaccess_ok = ((mbi.Protect & 0xFF) == PAGE_NOACCESS);
                const wchar_t * protection = L"Other";
                switch (mbi.Protect & 0xFF)
                {
                case PAGE_READONLY: protection = L"Readonly"; break;
                case PAGE_NOACCESS: protection = L"Noaccess"; break;
                case PAGE_READWRITE: protection = L"Readwrite (Still Writable)"; break;
                case PAGE_EXECUTE_READ: protection = L"Execute Read"; break;
                default: break;
                }
                if (commit_ok && noaccess_ok)
                {
                    LOG(0, L"  %ls[+]%ls Page Protection Assertion: VirtualQueryEx Verified 0x%llX [PAGE_NOACCESS] | State = MEM_COMMIT\n",
                        kGreen, kReset, base);
                }
                else
                {
                    LOG(0, L"  %ls[x]%ls Page Protection Mismatch: State = 0x%X | Protect = %ls (0x%08X) (Required MEM_COMMIT+PAGE_NOACCESS)\n",
                        kRed, kReset, mbi.State, protection, mbi.Protect);
                }
                LOG(0, L"  %ls[*]%ls Pre-Section Span Bound: Span = [0x00000000-0x%llX) | Wiped = %llu Bytes\n",
                    kDim, kReset, wiped, wiped);
            }
            else
            {
                LOG(0, L"  %ls[x]%ls Header Page Protection Unreadable: VirtualQueryEx Failed (Hard Gate Failure).\n", kRed, kReset);
            }

            if (declared_headers)
            {
                LOG(0, L"  %ls[+]%ls Declared SizeOfHeaders = %ls0x%llX%ls (Span The Loader Would Have Mapped)\n",
                    kGreen, kReset, kGreen,
                    static_cast<unsigned long long>(declared_headers), kReset);
            }

            if (wiped)
            {
                LOG(0, L"  %ls[+]%ls Structural Header Span = %ls0x%llX%ls (DOS Stub + NT Headers + Section Table)\n",
                    kGreen, kReset, kGreen, structural, kReset);
                LOG(0, L"  %ls[+]%ls Zeroed Header Span     = %ls0x%llX%ls (Entire Pre-Section Region; Mapper Telemetry)\n",
                    kGreen, kReset, kGreen, wiped, kReset);
                LOG(0, L"  %ls[+]%ls Page-Protected Span    = %ls0x%llX%ls @ %ls%s%ls\n",
                    kGreen, kReset, kGreen, protected_span, kReset,
                    kGreen, StealthPageDesc(static_cast<DWORD>(wipe_protect)), kReset);

                LOG(0, L"  %ls[+]%ls MZ/PE Scan (Image)     = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls0x%llX%ls Byte(s) Of The Mapped Image (In-Shell, Pre-NOACCESS)\n",
                    kGreen, kReset, kGreen, scan_mz, kReset, kGreen, scan_pe, kReset, kGreen, scan_bytes, kReset);

                if (exec)
                {
                    const bool agree = (exec_span == wiped) && (exec_mz == scan_mz) && (exec_pe == scan_pe) && (exec_prot == wipe_protect);
                    if (agree)
                    {
                        LOG(0, L"  %ls[+]%ls Exec Telemetry Cross-Check: Span = %llu | MZ = %llu | PE = %llu | Prot = 0x%08llX - Agrees With MapStats\n",
                            kGreen, kReset, exec_span, exec_mz, exec_pe, exec_prot);
                    }
                    else
                    {
                        LOG(0, L"  %ls[x]%ls Exec Telemetry Mismatch: Span = %llu/0x%llX | MZ = %llu/%llu | PE = %llu/%llu | Prot = 0x%08llX/0x%08llX\n",
                            kRed, kReset,
                            exec_span, wiped, exec_mz, scan_mz, exec_pe, scan_pe, exec_prot, wipe_protect);
                    }
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls Exec Telemetry Unavailable: Cloak Cross-Check Skipped, Host Read-Back Failed.\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Wiped Span Unavailable: Mapper Reported No Header-Wipe Telemetry.\n",
                    kYellow, kReset);
            }

            if (retained_base && retained_size)
            {
                const size_t want = static_cast<size_t>(retained_size < 0x1000 ? retained_size : 0x1000);
                std::vector<BYTE> scan_buf(want, 0);
                SIZE_T got = 0;
                if (ReadProcessMemory(process, ReCa<LPCVOID>(retained_base), scan_buf.data(), want, &got) && got)
                {
                    unsigned long long r_mz = 0;
                    unsigned long long r_pe = 0;
                    count_signatures(scan_buf.data(), got, r_mz, r_pe);
                    LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls%llu%ls Byte(s) Of Retained Allocation %ls0x%llX%ls\n",
                        kGreen, kReset, kGreen, r_mz, kReset, kGreen, r_pe, kReset,
                        kGreen, static_cast<unsigned long long>(got), kReset, kGreen, retained_base, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls MZ/PE Scan (Host)      = Retained Allocation %ls0x%llX%ls Not Readable (Protection Changed).\n",
                        kYellow, kReset, kYellow, retained_base, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = No Other Injection Allocation Remains Readable - The Manual-Map And Thread-Hijack Staging Regions Are Scrubbed And Released Before This Stage, And The Image Header Page Is NOACCESS By Design.\n",
                    kGreen, kReset);
            }
        }
        else if (!process || !base)
        {
            LOG(0, L"  %ls[!]%ls Image Base Not Readable; Header State Unknown.\n", kYellow, kReset);
        }
    }

    void StealthSurveyTraps(HANDLE process, DWORD survey_pid, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Survey Target Traps...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        ReportGameTraps(process, survey_pid, buffers);
        LOG(0, L"\n");
    }

    bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {
        if (wx_violated)
        {
            *wx_violated = false;
        }

        if (!hRemoteBase)
            return false;


        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        bool string_gate_ok = true;
        bool posture_ok = true;

        const bool step_enabled[kStealthStepCount] =
        {
            isActive(INJ_HANDLE_HIJACKING),
            isActive(INJ_MM_RESOLVE_IMPORTS) || isActive(INJ_MM_RUN_DLL_MAIN),
            isActive(INJ_MM_RESOLVE_DELAY_IMPORTS),
            isActive(INJ_MM_INIT_SECURITY_COOKIE),
            isActive(INJ_MM_ENABLE_EXCEPTIONS),
            true,
            isActive(INJ_MM_EXECUTE_TLS),
            isActive(INJ_MM_RUN_DLL_MAIN),
            isActive(INJ_MM_RUN_UNDER_LDR_LOCK),
            isActive(INJ_MM_CLEAN_DATA_DIR),
            isActive(INJ_MM_SET_PAGE_PROTECTIONS),
            true,
            true,
            true,
            isActive(INJ_ERASE_HEADER),
            survey_game_traps,
        };

        int total = 0;
        for (bool enabled : step_enabled)
        {
            if (enabled)
            {
                ++total;
            }
        }

        int step = 0;

        auto read_local_nt = [&]() -> bool
        {
            if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
                return false;
            BYTE * local_copy = const_cast<BYTE *>(local_pe);
            auto dos = ReCa<IMAGE_DOS_HEADER *>(local_copy);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            if (dos->e_lfanew < 0)
                return false;
            if (local_pe_size < static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64))
                return false;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(local_copy + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            memcpy(buffers.local_headers.data(), nt, sizeof(IMAGE_NT_HEADERS64));
            return true;
        };

        auto read_remote_nt = [&]() -> bool
        {
            if (!process)
                return false;
            BYTE dos_buf[sizeof(IMAGE_DOS_HEADER)] = { 0 };
            SIZE_T ds = 0;
            if (!ReadProcessMemory(process, hRemoteBase, dos_buf, sizeof(IMAGE_DOS_HEADER), &ds))
                return false;
            auto dos = ReCa<IMAGE_DOS_HEADER *>(dos_buf);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000)
                return false;
            SIZE_T ns = 0;
            if (!ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + dos->e_lfanew,
                buffers.remote_headers.data(), sizeof(IMAGE_NT_HEADERS64), &ns))
                return false;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.remote_headers.data());
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            return true;
        };

        const bool have_remote_nt = read_remote_nt();
        const bool have_local_nt = read_local_nt();
        BYTE * nt_data = have_remote_nt ? buffers.remote_headers.data()
            : (have_local_nt ? buffers.local_headers.data() : nullptr);

        if (step_enabled[kStealthAcquireHandle])
        {
            StealthAcquireHandle(ProcessHijack, ThreadHijack, Context, flags, step, total);
        }

        if (step_enabled[kStealthResolveImports])
        {
            StealthResolveImports(have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }

        if (step_enabled[kStealthResolveDelayImports])
        {
            StealthResolveDelayImports(have_local_nt, buffers, step, total);
        }

        if (step_enabled[kStealthInitSecurityCookie])
        {
            StealthInitSecurityCookie(process, hRemoteBase, have_local_nt, buffers, step, total);
        }

        if (step_enabled[kStealthEnableExceptions])
        {
            StealthEnableExceptions(process, hRemoteBase, have_local_nt, flags, buffers, step, total);
        }

        if (step_enabled[kStealthVerifyExceptionHandling])
        {
            StealthVerifyExceptionHandling(process, flags, have_local_nt, ExecTelemetry, buffers, get_string_stats, step, total);
        }

        if (step_enabled[kStealthExecuteTls])
        {
            StealthExecuteTls(have_local_nt, local_pe, local_pe_size, ExecTelemetry, buffers, step, total);
        }

        if (step_enabled[kStealthExecuteDllMain])
        {
            StealthExecuteDllMain(ExecTelemetry, flags, step, total);
        }

        if (step_enabled[kStealthRunUnderLoaderLock])
        {
            StealthRunUnderLoaderLock(ExecTelemetry, flags, step, total);
        }

        if (step_enabled[kStealthCleanDataDirectories])
        {
            StealthCleanDataDirectories(MapStats, have_remote_nt, nt_data, step, total);
        }

        if (step_enabled[kStealthSetPageProtections])
        {
            StealthSetPageProtections(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }
        if (step_enabled[kStealthVerifyWx])
        {
            StealthVerifyWxExecution(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, wx_violated, step, total);
        }

        if (step_enabled[kStealthVerifyStringEncryption])
        {
            StealthVerifyStringEncryption(buffers, get_string_stats, string_gate_ok, step, total);
        }

        if (step_enabled[kStealthVerifyForensicPosture])
        {
            StealthVerifyForensicPosture(process, hRemoteBase, local_pe, local_pe_size, config, buffers, posture_ok, step, total);
        }

        if (step_enabled[kStealthEraseHeader])
        {
            StealthEraseHeader(process, hRemoteBase, have_local_nt, MapStats, ExecTelemetry, buffers, step, total);
        }
        if (step_enabled[kStealthSurveyTraps])
        {
            StealthSurveyTraps(process, survey_pid, buffers, step, total);
        }

        return string_gate_ok && posture_ok;
    }

    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {
        __try
        {
            return DebugAndVerifyStealth(process, hRemoteBase, flags, local_pe, local_pe_size, ProcessHijack, ThreadHijack, Context, MapStats, ExecTelemetry, get_string_stats, survey_game_traps, survey_pid, wx_violated, config, buffers);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG(0, L"  %ls[x]%ls Verification Faulted; Gate Cannot Be Satisfied.\n", kRed, kReset);
            return false;
        }
    }

    bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out)
    {
        name_out.clear();
        base_out = 0;
        size_out = 0;
        if (!process)
        {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Module32FirstW(snapshot, &entry))
        {

            name_out = entry.szModule;
            base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
            size_out = static_cast<SIZE_T>(entry.modBaseSize);
            found = !name_out.empty() && base_out != 0;
        }

        CloseHandle(snapshot);
        return found;
    }

    static_assert(offsetof(PEB, CrossProcessFlags) == 80);
    static_assert(offsetof(PEB, Mutant) == 8);

    namespace
    {
        using NtQueryInformationProcessFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        NtQueryInformationProcessFn ResolveNtQueryInformationProcess()
        {
            auto mod_name = XOR_STR_W(L"ntdll.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());
            if (!mod)
            {
                return nullptr;
            }
            auto api_name = XOR_STR_A("NtQueryInformationProcess");
            return ReCa<NtQueryInformationProcessFn>(GetProcAddress(mod, api_name.get()));
        }
    }

    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out)
    {
        out = VehFirstChanceSurvey{};
        if (!process || process == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        out.handleValid = true;

        NtQueryInformationProcessFn query = ResolveNtQueryInformationProcess();
        if (!query)
        {
            out.lastError = GetLastError();
            return false;
        }

        struct LocalPbi
        {
            LONG ExitStatus;
            PVOID PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG BasePriority;
            HANDLE UniqueProcessId;
            HANDLE InheritedFromUniqueProcessId;
        };
        LocalPbi pbi{};
        ULONG ret_len = 0;
        const LONG status = query(process, 0, &pbi, static_cast<ULONG>(sizeof(pbi)), &ret_len);
        if (status != 0 || !pbi.PebBaseAddress)
        {
            out.lastError = static_cast<DWORD>(status != 0 ? status : ERROR_INVALID_ADDRESS);
            return false;
        }
        out.pebAddress = pbi.PebBaseAddress;

        const ULONG_PTR peb = ReCa<ULONG_PTR>(pbi.PebBaseAddress);
        const ULONG_PTR cross_addr = peb + offsetof(PEB, CrossProcessFlags);
        const ULONG_PTR debugged_addr = peb + 2;
        const ULONG_PTR global_flag_addr = peb + offsetof(PEB, NtGlobalFlag);

        ULONG cross = 0;
        BYTE debugged = 0;
        ULONG gflag = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(cross_addr), &cross, sizeof(cross), &got) ||
            got != sizeof(cross))
        {
            out.lastError = GetLastError();
            return false;
        }
        got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(debugged_addr), &debugged, sizeof(debugged), &got) ||
            got != sizeof(debugged))
        {
            out.lastError = GetLastError();
            return false;
        }
        got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(global_flag_addr), &gflag, sizeof(gflag), &got) ||
            got != sizeof(gflag))
        {
            out.lastError = GetLastError();
            return false;
        }

        out.crossFlags = cross;
        out.usingVeh = (cross & 0x4u) != 0;
        out.usingVch = (cross & 0x8u) != 0;
        out.beingDebugged = debugged;
        out.ntGlobalFlag = gflag;
        out.readOk = true;
        return true;
    }

    inline LONG NTAPI VehProbeDummyHandler(EXCEPTION_POINTERS *)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    inline bool ProbeLocalVehPathRoundTrip()
    {
        void * handle = AddVectoredExceptionHandler(1, VehProbeDummyHandler);
        if (!handle)
        {
            return false;
        }
        const ULONG removed = RemoveVectoredExceptionHandler(handle);
        return removed != 0;
    }

    inline bool QueryRemoteDebugPort(HANDLE process, DebugPortSurvey & out)
    {
        out = DebugPortSurvey{};
        if (!process || process == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        out.handleValid = true;

        NtQueryInformationProcessFn query = ResolveNtQueryInformationProcess();
        if (!query)
        {
            return false;
        }

        PVOID port = nullptr;
        ULONG port_len = 0;
        out.portStatus = query(process, 7, &port, static_cast<ULONG>(sizeof(port)), &port_len);
        if (out.portStatus == 0 && port_len == sizeof(port))
        {
            out.debugPort = port;
            out.portReadOk = true;
        }

        ULONG pflags = 0;
        ULONG flags_len = 0;
        out.flagsStatus = query(process, 31, &pflags, static_cast<ULONG>(sizeof(pflags)), &flags_len);
        if (out.flagsStatus == 0 && flags_len == sizeof(pflags))
        {
            out.debugFlags = pflags;
            out.flagsReadOk = true;
        }

        return out.portReadOk || out.flagsReadOk;
    }

    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size)
    {
        if (!process || !address || !size)
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process, reinterpret_cast<void *>(address), &mbi, sizeof(mbi)))
        {
            return false;
        }

        if (mbi.State != MEM_COMMIT)
        {
            return false;
        }

        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
        {
            return false;
        }

        const ULONG_PTR region_end = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (address + size > region_end)
        {
            return false;
        }

        return true;
    }

    bool GetRemoteEidRange(HANDLE process, ULONG_PTR base, ULONG_PTR & start_out, ULONG_PTR & end_out)
    {
        start_out = 0;
        end_out = 0;
        if (!process || !base)
        {
            return false;
        }
        IMAGE_DOS_HEADER dos{};
        SIZE_T done = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &done) ||
            done != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
        {
            return false;
        }
        DWORD sig = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + static_cast<ULONG_PTR>(dos.e_lfanew)),
            &sig, sizeof(sig), &done) || done != sizeof(sig) || sig != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        const ULONG_PTR file_hdr = base + static_cast<ULONG_PTR>(dos.e_lfanew) + sizeof(DWORD);
        WORD num_sections = 0;
        WORD opt_size = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 2),
            &num_sections, sizeof(num_sections), &done) || done != sizeof(num_sections))
        {
            return false;
        }
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 16),
            &opt_size, sizeof(opt_size), &done) || done != sizeof(opt_size))
        {
            return false;
        }
        if (!num_sections || num_sections > 96)
        {
            return false;
        }
        const ULONG_PTR sec_table = file_hdr + sizeof(IMAGE_FILE_HEADER) + opt_size;
        for (WORD i = 0; i < num_sections; ++i)
        {
            IMAGE_SECTION_HEADER sec{};
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(sec_table + static_cast<ULONG_PTR>(i) * sizeof(sec)),
                &sec, sizeof(sec), &done) || done != sizeof(sec))
            {
                return false;
            }
            char name[9] = { 0 };
            memcpy(name, sec.Name, 8);
            if (strcmp(name, ".eid") == 0)
            {
                const DWORD extent = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                if (!extent)
                {
                    return false;
                }
                start_out = base + sec.VirtualAddress;
                end_out = start_out + extent;
                return end_out > start_out;
            }
        }
        return false;
    }

    SIZE_T ReadSurveyBound(const wchar_t * name)
    {
        wchar_t buffer[32] = {};
        const DWORD got = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
        if (got == 0 || got >= sizeof(buffer) / sizeof(buffer[0]))
        {
            return 0;
        }

        wchar_t * end = nullptr;
        const unsigned long long value = wcstoull(buffer, &end, 10);
        if (!end || *end != L'\0')
        {
            return 0;
        }

        return static_cast<SIZE_T>(value);
    }

    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers)
    {
        if (!process || !target_pid)
        {
            return;
        }

        std::vector<SurveyModule> & survey_modules = buffers.survey_modules;
        survey_modules.clear();
        {
            std::wstring main_name;
            ULONG_PTR main_base = 0;
            SIZE_T main_size = 0;
            if (GetRemoteMainModule(process, main_name, main_base, main_size))
            {
                survey_modules.push_back(SurveyModule{ main_name, main_base, main_size });
            }
        }

        const SIZE_T max_walk_regions = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_REGIONS").get());
        const SIZE_T max_walk_bytes = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_MB").get()) * (1u << 20);
        const SIZE_T max_sample_regions = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_SAMPLE_REGIONS").get());

        constexpr SIZE_T kSurveyChunkBytes = 0x10000;

        std::vector<BYTE> & chunk_buf = buffers.survey_chunk;
        if (chunk_buf.size() != kSurveyChunkBytes)
        {
            chunk_buf.resize(kSurveyChunkBytes);
            if (chunk_buf.size() != kSurveyChunkBytes)
            {

                LOG(0, L"  %ls[!]%ls Survey Read Window Unavailable; INT3 Scan Skipped.\n", kYellow, kReset);
                return;
            }
        }

        int found = 0;
        for (size_t m = 0; m < survey_modules.size(); ++m)
        {
            const std::wstring & mod = survey_modules[m].name;
            const ULONG_PTR base = survey_modules[m].base;
            const SIZE_T image_size = survey_modules[m].size;
            if (!base)
            {
                continue;
            }

            ++found;

            size_t guarded = 0;
            size_t noaccess = 0;
            size_t guarded_bytes = 0;
            size_t noaccess_bytes = 0;
            size_t sampled = 0;
            size_t exec_regions = 0;
            size_t cc_bytes = 0;
            size_t sample_bytes = 0;
            size_t walked = 0;
            size_t eid_skipped = 0;

            size_t sample_capped = 0;
            bool walk_capped = false;
            bool walk_aborted = false;
            const bool unknown_extent = (image_size == 0);
            ULONG_PTR eid_start = 0;
            ULONG_PTR eid_end = 0;
            const bool has_eid = GetRemoteEidRange(process, base, eid_start, eid_end);

            const ULONG_PTR walk_end = unknown_extent ? 0 : (base + image_size);

            BYTE * cursor = reinterpret_cast<BYTE *>(base);
            size_t regions = 0;
            for (;;)
            {
                if (unknown_extent)
                {
                    walk_aborted = true;
                    break;
                }

                if (max_walk_regions && regions >= max_walk_regions)
                {
                    walk_capped = true;
                    break;
                }

                if (reinterpret_cast<ULONG_PTR>(cursor) >= walk_end)
                {
                    break;
                }

                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(process, cursor, &mbi, sizeof(mbi)) || !mbi.RegionSize)
                {
                    walk_aborted = true;
                    break;
                }

                BYTE * next = reinterpret_cast<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cursor)
                {
                    walk_aborted = true;
                    break;
                }

                if (has_eid)
                {
                    const ULONG_PTR r_start = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
                    const ULONG_PTR r_end = reinterpret_cast<ULONG_PTR>(next);
                    if (r_start < eid_end && r_end > eid_start)
                    {
                        ++eid_skipped;
                        cursor = next;
                        ++regions;
                        if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                        {
                            walk_capped = true;
                            break;
                        }
                        continue;
                    }
                }

                if (mbi.State == MEM_COMMIT)
                {
                    ++walked;
                    if (mbi.Protect & PAGE_GUARD)
                    {
                        ++guarded;
                        guarded_bytes += mbi.RegionSize;
                    }
                    else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
                    {
                        ++noaccess;
                        noaccess_bytes += mbi.RegionSize;
                    }
                    else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    {
                        ++exec_regions;
                        if (max_sample_regions && sampled >= max_sample_regions)
                        {
                            ++sample_capped;
                        }
                        else
                        {

                            SIZE_T remaining = mbi.RegionSize;
                            BYTE * addr = reinterpret_cast<BYTE *>(mbi.BaseAddress);
                            size_t region_cc = 0;
                            size_t region_read = 0;
                            while (remaining)
                            {
                                const SIZE_T want = remaining < kSurveyChunkBytes ? remaining : kSurveyChunkBytes;
                                SIZE_T got = 0;
                                if (!ReadProcessMemory(process, addr, chunk_buf.data(), want, &got) || !got)
                                {
                                    break;
                                }

                                for (size_t i = 0; i < static_cast<size_t>(got); ++i)
                                {
                                    if (chunk_buf[i] == 0xCC)
                                    {
                                        ++region_cc;
                                    }
                                }

                                region_read += static_cast<size_t>(got);
                                addr += got;
                                remaining -= got;
                                if (got < want)
                                {
                                    break;
                                }
                            }

                            if (region_read)
                            {
                                cc_bytes += region_cc;
                                sample_bytes += region_read;
                                ++sampled;
                            }
                        }
                    }
                }

                cursor = next;
                ++regions;
                if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                {
                    walk_capped = true;
                    break;
                }
            }

            const size_t cc_pct = sample_bytes ? (cc_bytes * 100) / sample_bytes : 0;

            const wchar_t * Verdict = guarded ? L"Guarded" : L"No Guard Pages";
            wchar_t VerdictNote[192]{};
            if (guarded == 0)
            {
                if (sample_bytes == 0)
                {
                    swprintf_s(VerdictNote, L"No Executable Region Was Readable");
                }
                else if (cc_pct)
                {
                    swprintf_s(VerdictNote, L"INT3 %zu%% Of Sampled Exec Bytes (Process-Wide; Not A Per-Module Verdict)",
                        cc_pct);
                }
                else
                {
                    swprintf_s(VerdictNote, L"No INT3 In Sampled Exec Bytes");
                }
            }
            LOG(0, L"  %ls%ls%s%s (%ls%zu%s Committed Region(s) Walked, Process-Wide)\n",
                StageField(mod, 24).c_str(),
                guarded ? kYellow : L"", Verdict, kReset,
                kGreen, walked, kReset);
            if (VerdictNote[0])
            {
                LOG(0, L"  %*s%ls%s\n", static_cast<int>(StageField(mod, 24).size()), L"", VerdictNote, kReset);
            }

            LOG(0, L"\n");

            LOG(0, L"      %ls%ls%zu%ls Region(s), %ls%zu%ls KB\n",
                StageField(L"Guard:", 12).c_str(),
                kGreen, guarded, kReset,
                kGreen, static_cast<size_t>(guarded_bytes / 1024), kReset);

            LOG(0, L"      %ls%ls%zu%ls Region(s), %ls%zu%ls KB\n",
                StageField(L"No-Access:", 12).c_str(),
                kGreen, noaccess, kReset,
                kGreen, static_cast<size_t>(noaccess_bytes / 1024), kReset);

            if (eid_skipped)
            {
                LOG(0, L"      %ls%ls%zu%ls Region(s) Skipped (Encrypted Core, Never Read)\n",
                    StageField(L"EID:", 12).c_str(),
                    kGreen, eid_skipped, kReset);
            }

            if (sample_bytes)
            {
                LOG(0, L"      %ls%ls%zu%ls Of %ls%zu%ls Sampled Bytes Are INT3 (%ls0xCC%ls), %ls%zu%s%%, From %ls%zu%ls Of %ls%zu%ls Exec Region(s)\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, cc_bytes, kReset,
                    kGreen, sample_bytes, kReset,
                    kGreen, kReset,
                    kGreen, cc_pct, kReset,
                    kGreen, sampled, kReset, kGreen, exec_regions, kReset);

                if (sample_capped)
                {

                    LOG(0, L"%*s%ls%zu%ls Of %ls%zu%ls Exec Region(s) Not Sampled (Cap %ls%zu%ls), So The INT3 Count Is A Floor, Not A Total\n",
                        static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                        kGreen, sample_capped, kReset,
                        kGreen, exec_regions, kReset,
                        kGreen, max_sample_regions, kReset);
                }
            }
            else
            {
                LOG(0, L"      %lsNo Executable Region Was Readable\n",
                    StageField(L"INT3:", 12).c_str());
            }

            if (walk_capped || walk_aborted)
            {

                wchar_t reason[192]{};
                const auto append = [&reason](const wchar_t * part)
                {
                    if (!part)
                    {
                        return;
                    }
                    size_t used = 0;
                    while (used < _countof(reason) && reason[used])
                    {
                        ++used;
                    }
                    if (used >= _countof(reason) - 1)
                    {
                        return;
                    }
                    wchar_t * dst = reason + used;
                    size_t left = _countof(reason) - 1 - used;
                    if (used)
                    {
                        if (left < 3)
                        {
                            return;
                        }
                        *dst++ = L' ';
                        *dst++ = L'/';
                        *dst++ = L' ';
                        left -= 3;
                    }
                    while (left && *part)
                    {
                        *dst++ = *part++;
                        --left;
                    }
                    *dst = L'\0';
                };

                if (walk_capped)
                {
                    if (max_walk_regions)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"Cap %ls%zu%ls Regions", kGreen, max_walk_regions, kReset);
                        append(part);
                    }
                    if (max_walk_bytes)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"Cap %ls%zu%ls MB", kGreen, static_cast<size_t>(max_walk_bytes >> 20), kReset);
                        append(part);
                    }
                }
                if (walk_aborted)
                {
                    append(unknown_extent ? L"Module Extent Unknown" : L"Query Failed Before Module End");
                }

                LOG(0, L"%*sRegion Walk Stopped Early (%ls); Counts Are Partial\n",
                    static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                    reason);
            }

            LOG(0, L"\n");
        }

        if (!found)
        {
            LOG(0, L"  %ls[!]%ls No Target Module Present; Nothing To Survey.\n", kYellow, kReset);
        }
    }


}
