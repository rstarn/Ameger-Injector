#include "PCH.h"

#include "Launcher.h"

#include <intrin.h>

// Vector 7: the launcher (interface exe) does not link the Ameger Native module's
// static gadget-pool accessors (they run inside the target process), so verify the
// mechanism on the host side: scan this process's ntdll for 0F 05 syscall gadgets,
// and demonstrate randomization with a seeded xorshift32 PRNG.
namespace
{
    constexpr uint8_t kOpSyscall0 = 0x0F;
    constexpr uint8_t kOpSyscall1 = 0x05;
    constexpr size_t kMaxGadgetPool = 32;

    uint32_t g_GadgetPrng = 0;

    static void SeedGadgetPrng()
    {
        LARGE_INTEGER perf{};
        QueryPerformanceCounter(&perf);
        g_GadgetPrng = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_GadgetPrng) ^
            static_cast<uint32_t>(perf.QuadPart) ^ 0x9E3779B9u);
        if (!g_GadgetPrng)
        {
            g_GadgetPrng = 0x9E3779B9u;
        }
    }

    static uint32_t GadgetPrngNext()
    {
        uint32_t x = g_GadgetPrng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_GadgetPrng = x;
        return x;
    }

    // Scan ntdll's executable sections for 0F 05 (syscall) gadget candidates.
    static size_t ScanSyscallGadgetPool(void **pool, size_t max)
    {
        size_t count = 0;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
        {
            return 0;
        }

        const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(ntdll);
        const auto * pe = ReCa<const IMAGE_NT_HEADERS *>(reinterpret_cast<uintptr_t>(ntdll) + dos->e_lfanew);
        if (!pe)
        {
            return 0;
        }

        const WORD section_count = pe->FileHeader.NumberOfSections;
        const IMAGE_SECTION_HEADER * sections = IMAGE_FIRST_SECTION(pe);
        for (WORD s = 0; s < section_count; ++s)
        {
            const IMAGE_SECTION_HEADER & sec = sections[s];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            {
                continue;
            }
            const BYTE * start = reinterpret_cast<const BYTE *>(ntdll) + sec.VirtualAddress;
            const size_t span = sec.Misc.VirtualSize;
            for (size_t off = 0; off + 2 <= span && count < max; ++off)
            {
                if (start[off] == kOpSyscall0 && start[off + 1] == kOpSyscall1)
                {
                    pool[count++] = const_cast<BYTE *>(start + off);
                }
            }
        }
        return count;
    }

    static void * GadgetPick(const void * const *pool, size_t count)
    {
        if (!count)
        {
            return nullptr;
        }
        return const_cast<void *>(pool[GadgetPrngNext() % count]);
    }
}








namespace stealth
{
    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers);





    namespace LoadConfig64
    {
        constexpr SIZE_T kSecurityCookie = 0x58;
        constexpr SIZE_T kGuardFlags = 0x90;
        constexpr SIZE_T kMinimumSizeForGuardFlags = kGuardFlags + sizeof(DWORD);

        constexpr DWORD kGuardCfInstrumented = 0x00000100;
        constexpr DWORD kGuardCfFunctionTablePresent = 0x00000400;
        constexpr DWORD kGuardSecurityCookieUnused = 0x00000800;
        constexpr DWORD kGuardCfInstrumentedAndImportsInstrumented = 0x00001000;
    }






    double MeasureTscHz()
    {
        static const double hz = []()
        {
            LARGE_INTEGER freq{};
            LARGE_INTEGER start{};
            LARGE_INTEGER end{};
            if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0)
            {
                return 0.0;
            }



            ULONGLONG tsc_warm = __rdtsc();
            QueryPerformanceCounter(&start);
            Sleep(60);
            ULONGLONG tsc_end = __rdtsc();
            QueryPerformanceCounter(&end);

            const LONGLONG ticks = end.QuadPart - start.QuadPart;
            if (ticks <= 0 || tsc_end <= tsc_warm)
            {
                return 0.0;
            }

            const double seconds = static_cast<double>(ticks) / static_cast<double>(freq.QuadPart);
            if (seconds <= 0.0)
            {
                return 0.0;
            }

            const double measured = static_cast<double>(tsc_end - tsc_warm) / seconds;




            if (measured < 1.0e8 || measured > 1.0e10)
            {
                return 0.0;
            }
            return measured;
        }();
        return hz;
    }




    bool CyclesToMilliseconds(ULONGLONG cycles, double & milliseconds)
    {
        const double hz = MeasureTscHz();
        if (hz <= 0.0 || cycles == 0)
        {
            return false;
        }
        milliseconds = (static_cast<double>(cycles) / hz) * 1000.0;
        return true;
    }

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
        kStealthVerifyUsermodeVectors,
        kStealthEraseHeader,
        kStealthSurveyHostSurface,
        kStealthSurveyTraps,

        // Vector 1 — page-file section / dual-view verification
        kStealthVerifyMappingType,
        kStealthVerifyNoLoaderArtifact,
        kStealthVerifySectionHandleClosed,
        kStealthReportKernelResiduals,
        // Vector 7 — hardened stack spoof verification
        kStealthVerifyStackSpoofGeometry,
        kStealthVerifyGadgetValidity,
        kStealthVerifySpoofRandomization,

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
                unsigned long rx_image = 0, rx_private = 0, rx_mapped = 0, rx_this_load = 0;
                unsigned long long rx_private_bytes = 0;
                const ULONG_PTR this_load_base = ReCa<ULONG_PTR>(hRemoteBase);
                const ULONG_PTR this_load_end = this_load_base + (wx_image ? wx_image : 0);
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
                            const ULONG_PTR region_start = ReCa<ULONG_PTR>(census_mbi.BaseAddress);
                            if (this_load_base && region_start >= this_load_base && region_start < this_load_end)
                            {
                                ++rx_this_load;
                            }
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





                    const unsigned long pre_existing = rx_private > rx_this_load ? rx_private - rx_this_load : 0;
                    LOG(0, L"      %ls[!]%ls %ls%lu%s Private-RX Region(s) Process-Wide: %ls%lu%s Belong To This Load's Image @ %p | %ls%lu%s Pre-Existing In The Target; Each Is VAD-Visible With No Loader Entry\n",
                        kYellow, kReset, kYellow, rx_private, kReset,
                        kYellow, rx_this_load, kReset, hRemoteBase,
                        kYellow, pre_existing, kReset);
                }





                LOG(0, L"      %ls[+]%ls In-Image RWX = %ls%d%s (Required 0) | This Load's Image = %ls%lu%s Of %ls%lu%s RX Region(s) (Inherent To Manual Map)\n",
                    kGreen, kReset, wx_rwx ? kYellow : kGreen, wx_rwx, kReset,
                    kGreen, rx_this_load, kReset,
                    rx_private ? kYellow : kGreen, rx_private, kReset);
                LOG(0, L"      %ls[*]%ls Staging Regions Scrubbed/Released Is A Mapper Property, Not Re-Checked Here.\n",
                        kDim, kReset);
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
        auto m32 = XOR_STR_A("TLS_ENTRY");
        auto m33 = XOR_STR_A("PATH_SEARCH_CONTEXT");
        const char * markers[] =
        {
            m0.get(), m2.get(), m3.get(), m4.get(), m5.get(),
            m6.get(), m7.get(), m8.get(), m9.get(), m10.get(), m11.get(),
            m12.get(), m13.get(), m14.get(), m16.get(), m17.get(),
            m18.get(), m19.get(), m20.get(), m21.get(), m22.get(), m23.get(),
            m24.get(), m25.get(), m26.get(), m27.get(), m28.get(),
            m29.get(), m30.get(), m32.get(), m33.get(),
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
    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size);



    bool ReadRemoteImageString(HANDLE process, ULONG_PTR image_base, SIZE_T image_size, DWORD rva,
        char * out, size_t out_size)
    {
        if (!out || out_size == 0)
        {
            return false;
        }
        out[0] = '\0';
        if (!rva || rva >= image_size)
        {
            return false;
        }

        const ULONG_PTR address = image_base + rva;
        if (address < image_base || address >= image_base + image_size)
        {
            return false;
        }

        const SIZE_T available = image_size - rva;
        const SIZE_T want = available < (out_size - 1) ? available : (out_size - 1);

        SIZE_T got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(address), out, want, &got) || got == 0)
        {
            out[0] = '\0';
            return false;
        }




        SIZE_T length = 0;
        while (length < got && out[length] != '\0')
        {
            ++length;
        }
        out[length] = '\0';

        if (length == 0)
        {
            return false;
        }



        for (SIZE_T i = 0; i < length; ++i)
        {
            const unsigned char c = static_cast<unsigned char>(out[i]);
            if (c < 0x20 || c > 0x7E)
            {
                out[0] = '\0';
                return false;
            }
        }
        return true;
    }





    void ReadRemoteImportNames(HANDLE process, ULONG_PTR image_base, SIZE_T image_size,
        const IMAGE_IMPORT_DESCRIPTOR & entry, std::wstring & dll_out, std::wstring & function_out)
    {
        dll_out.clear();
        function_out.clear();

        char dll_name[256] = { 0 };
        if (ReadRemoteImageString(process, image_base, image_size, entry.Name, dll_name, sizeof(dll_name)))
        {
            dll_out.clear();
            for (const char * c = dll_name; *c; ++c)
            {
                dll_out.push_back(static_cast<wchar_t>(*c));
            }
        }




        const DWORD thunk_rva = entry.OriginalFirstThunk ? entry.OriginalFirstThunk : entry.FirstThunk;
        if (!thunk_rva || thunk_rva >= image_size)
        {
            return;
        }

        for (unsigned long i = 0; i < 4096; ++i)
        {
            const ULONG_PTR slot = image_base + thunk_rva + static_cast<ULONG_PTR>(i) * sizeof(ULONG_PTR);
            if (slot + sizeof(ULONG_PTR) > image_base + image_size ||
                !IsSafeCodePage(process, slot, sizeof(ULONG_PTR)))
            {
                return;
            }

            ULONG_PTR thunk = 0;
            SIZE_T got = 0;
            if (!ReadProcessMemory(process, ReCa<LPCVOID>(slot), &thunk, sizeof(thunk), &got) ||
                got != sizeof(thunk))
            {
                return;
            }
            if (!thunk)
            {
                return;
            }

            if (thunk & (static_cast<ULONG_PTR>(1) << 63))
            {
                function_out = L"Ordinal " + std::to_wstring(thunk & 0xFFFF);
                return;
            }

            const DWORD name_rva = static_cast<DWORD>(thunk & 0x7FFFFFFFULL);
            if (!name_rva || name_rva + sizeof(WORD) >= image_size)
            {
                return;
            }


            char function_name[256] = { 0 };
            if (ReadRemoteImageString(process, image_base, image_size, name_rva + sizeof(WORD),
                function_name, sizeof(function_name)))
            {
                function_out.clear();
                for (const char * c = function_name; *c; ++c)
                {
                    function_out.push_back(static_cast<wchar_t>(*c));
                }
            }
            return;
        }
    }

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




                const bool denied_by_rights =
                    dbg.portStatus == static_cast<NTSTATUS>(0xC0000022u) &&
                    dbg.flagsStatus == static_cast<NTSTATUS>(0xC0000022u);
                LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnknown%ls (%ls; Port Status 0x%08X, Flags Status 0x%08X)\n",
                    kYellow, kReset, kYellow, kReset,
                    denied_by_rights
                        ? L"Refused By Handle Rights - QUERY_LIMITED Posture By Decision; Not Queryable, Not Reported Clean"
                        : L"Query Failed; Not Treated As Clean",
                    static_cast<unsigned>(dbg.portStatus), static_cast<unsigned>(dbg.flagsStatus));
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
                LOG(0, L"  %ls[!]%ls Launcher Itself Is Debugged: Target PEB/TLS Guards Would Fire On The Game, Not Here; Detach Before A Real Run\n",
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
            if (exec->TlsHasData)
            {
                LOG(0, L"  %ls[+]%ls TLS Registration Retained: The Image Carries TLS Data, So Index %u, The PEB Bit, "
                        L"The TEB Slot, And The LdrpTlsList Entry Must Stay Live.\n",
                    kGreen, kReset, exec->TlsIndex);
            }
            else if (exec->TlsCallbacksConfigured == 0 && exec->TlsLoaderEntryAbsent != 0)
            {




                LOG(0, L"  %ls[+]%ls Loader Mutation Skipped: The TLS Directory Declares No Callbacks And No Data; "
                        L"No LDR Entry, PEB Bit, Or Loader Heap Was Ever Touched.\n",
                    kGreen, kReset);
            }
            else if (exec->TlsCallbacksConfigured)
            {
                const bool nothing_to_rewind = exec->TlsLoaderEntryAbsent != 0;
                const bool rewound = nothing_to_rewind || (exec->TlsIndexRestored && exec->TlsBitmapBitCleared &&
                    exec->TlsSlotCleared && exec->TlsLoaderEntryUnlinked);
                LOG(0, L"  %ls[%ls]%ls Loader TLS Registration: Index Restored = %ls | PEB Bit Cleared = %ls | "
                        L"TEB Slot Restored = %ls | Loader Entry Unlinked = %ls | Nothing To Rewind = %ls\n",
                    rewound ? L"+" : L"!", rewound ? kGreen : kYellow, kReset,
                    exec->TlsIndexRestored ? L"True" : L"False",
                    exec->TlsBitmapBitCleared ? L"True" : L"False",
                    exec->TlsSlotCleared ? L"True" : L"False",
                    exec->TlsLoaderEntryUnlinked ? L"True" : L"False",
                    nothing_to_rewind ? L"True" : L"False");
                if (!rewound)
                {
                    LOG(0, L"  %ls[!]%ls The Loader Registration Could Not Be Fully Rewound; Loader Bookkeeping May Remain.\n",
                        kYellow, kReset);
                }
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
        double ms = 0.0;
        const bool have_ms = CyclesToMilliseconds(exec->DllMainCyclesDelta, ms);
        if (exec->DllMainCyclesDelta == 0)
        {
            LOG(0, L"  %ls[*]%ls DllMain Not Entered: Cycle Counter Is 0, So The Shell Never Called The "
                    L"Entry Point (No Entry Point In The Image, Or An Earlier Stage Aborted). "
                    L"No Pass/Fail Is Claimed.\n", kDim, kReset);
            return;
        }
        if (have_ms)
        {
            LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu (%.2f ms At A Measured %.2f GHz)\n",
                kGreen, kReset, kGreen, exec->DllMainResult ? L"True" : L"False", kReset,
                exec->DllMainLastWin32Error, (unsigned long long)exec->DllMainCyclesDelta, ms, MeasureTscHz() / 1.0e9);
        }
        else
        {
            LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu "
                    L"(No Counter Frequency Calibration Available; No Duration Is Claimed)\n",
                kGreen, kReset, kGreen, exec->DllMainResult ? L"True" : L"False", kReset,
                exec->DllMainLastWin32Error, (unsigned long long)exec->DllMainCyclesDelta);
        }
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
            if (MapStats->Verified && MapStats->VerifiedCachedCopy)
            {
                LOG(0, L"  %ls[*]%ls Residual Mask 0x%08X Across All %zu Directories Was Checked "
                        L"Against The Mapper's Cached Copy: The In-Image Header Was Already Wiped "
                        L"(INJ_ERASE_HEADER), So This Is Cache Consistency, Not An Independent Re-Read.\n",
                    kDim, kReset, (unsigned)MapStats->ResidualMask, kDirCount);
            }
            else if (MapStats->Verified)
            {
                LOG(0, L"  %ls[+]%ls Mapper-Side Re-Read Of The In-Image Directory Table: Residual Mask "
                        L"0x%08X Across All %zu Directories.\n",
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

        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
        const bool cfg_read = process &&
            GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE;
        DWORD load_config_guard_flags = 0;
        DWORD load_config_size = 0;
        bool guard_flags_read = false;

        {
            std::wstring survey_name;
            ULONG_PTR survey_base = 0;
            SIZE_T survey_size = 0;
            if (!process || !GetRemoteMainModule(process, survey_name, survey_base, survey_size) ||
                !survey_base || !survey_size)
            {
                LOG(0, L"  %ls[*]%ls Target Image Survey...... %lsSkipped%ls (Main Module Not Enumerable; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
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





                    if (survey_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress &&
                        survey_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size >= LoadConfig64::kMinimumSizeForGuardFlags)
                    {
                        DWORD guard_flags = 0;
                        SIZE_T gf_got = 0;
                        const ULONG_PTR lc_va = survey_base + survey_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                        if (ReadProcessMemory(process, ReCa<LPCVOID>(lc_va + LoadConfig64::kGuardFlags),
                            &guard_flags, sizeof(guard_flags), &gf_got) && gf_got == sizeof(guard_flags))
                        {
                            load_config_guard_flags = guard_flags;
                            load_config_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                            guard_flags_read = true;
                        }
                    }

                    unsigned long imp_count = 0;
                    bool imp_done = false;
                    bool imp_ok = false;
                    std::wstring imp_first_dll;
                    std::wstring imp_first_function;
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
                            if (imp_count == 0)
                            {
                                ReadRemoteImportNames(process, survey_base, survey_size, entry,
                                    imp_first_dll, imp_first_function);
                            }
                            ++imp_count;
                        }
                    }
                    if (imp_ok && imp_done)
                    {
                        LOG(0, L"  %ls[+]%ls Target Imports.......... %ls%lu%ls Descriptor(s) In %ls%ls%ls (Read Back)\n",
                            kGreen, kReset, kGreen, imp_count, kReset, kGreen, survey_name.c_str(), kReset);
                        if (!imp_first_dll.empty())
                        {
                            LOG(0, L"      %ls%ls%ls!%ls%ls%ls\n", kDim, imp_first_dll.c_str(), kReset,
                                kGreen, imp_first_function.empty() ? L"<no named import>" : imp_first_function.c_str(), kReset);
                        }
                        if (imp_count == 1)
                        {
                            LOG(0, L"      %ls[*]%ls Single-Import Shape: Every Call This Image Makes Leaves Through One Imported Module.\n", kDim, kReset);
                        }
                        else if (imp_count == 0)
                        {
                            LOG(0, L"      %ls[!]%ls Zero Import Descriptors: Nothing Is Resolved Statically; "
                                    L"The Image Is Packed Or Demand-Loaded.\n", kYellow, kReset);
                        }
                        else
                        {
                            LOG(0, L"      %ls[*]%ls Multi-Import Shape: %lu Descriptor(s).\n", kDim, kReset, imp_count);
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
                            LOG(0, L"  %ls[+]%ls Target Exports.......... %ls%lu%ls Funcs / %ls%lu%ls Names (Read Back From The Export Directory)\n",
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
                                LOG(0, L"  %ls[+]%ls Target TLS Callbacks.... %ls%lu%ls Configured (Remote Array Read)\n",
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
                    if (guard_flags_read)
                    {
                        const bool instrumented = (load_config_guard_flags & LoadConfig64::kGuardCfInstrumented) != 0;
                        LOG(0, L"  %ls[=]%ls Target Load Config: GuardFlags = %ls0x%08X%ls | CFG Instrumented = %ls%s%ls | Load Config Size = %lu\n",
                            kCyan, kReset,
                            kGreen, load_config_guard_flags, kReset,
                            instrumented ? kGreen : kYellow, instrumented ? L"Yes" : L"No", kReset,
                            load_config_size);
                    }
                    else
                    {
                        LOG(0, L"  %ls[*]%ls Target Load Config: No Guard Flags Field Read (No Load Config Directory, "
                                L"Or It Is Shorter Than The Field).\n", kDim, kReset);
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

                LOG(0, L"  %ls[+]%ls MZ/PE Scan (Pre-Wipe)  = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls0x%llX%ls Byte(s) Of The Mapped Image (In-Shell, Before The Wipe)\n",
                    kGreen, kReset, kGreen, scan_mz, kReset, kGreen, scan_pe, kReset, kGreen, scan_bytes, kReset);

                if (exec)
                {




                    const bool agree = (exec_span == wiped) &&
                        (exec_mz == 0) && (exec_pe == 0) &&
                        (exec_mz <= scan_mz) && (exec_pe <= scan_pe) &&
                        (exec_prot == wipe_protect);
                    if (agree)
                    {
                        LOG(0, L"  %ls[+]%ls Exec Telemetry Cross-Check: Span = %llu | MZ = %llu | PE = %llu | Prot = 0x%08llX - Post-Wipe Region Holds Nothing\n",
                            kGreen, kReset, exec_span, exec_mz, exec_pe, exec_prot);
                    }
                    else
                    {
                        LOG(0, L"  %ls[x]%ls Exec Telemetry Mismatch: Span = %llu/0x%llX | MZ = %llu (Post) / %llu (Pre) | PE = %llu (Post) / %llu (Pre) | Prot = 0x%08llX/0x%08llX\n",
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

    bool CapturePreLoadBaseline(DWORD pid, StealthVerifierBuffers & buffers)
    {
        buffers.pre_load_modules.clear();
        buffers.pre_target_windows = 0;
        buffers.pre_target_layered = 0;
        if (!pid)
        {
            return false;
        }





        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W mod{};
            mod.dwSize = sizeof(mod);
            if (Module32FirstW(snap, &mod))
            {
                do
                {
                    buffers.pre_load_modules.emplace_back(mod.szModule);
                } while (Module32NextW(snap, &mod));
            }
            CloseHandle(snap);
        }




        struct WindowTally
        {
            DWORD pid;
            size_t windows;
            size_t layered;
        } tally{ pid, 0, 0 };
        EnumWindows([](HWND hwnd, LPARAM param) -> BOOL {
            WindowTally * t = reinterpret_cast<WindowTally *>(param);
            DWORD owner = 0;
            GetWindowThreadProcessId(hwnd, &owner);
            if (owner != t->pid)
            {
                return TRUE;
            }
            ++t->windows;
            if (GetWindowLongW(hwnd, GWL_EXSTYLE) & (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW))
            {
                ++t->layered;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&tally));
        buffers.pre_target_windows = tally.windows;
        buffers.pre_target_layered = tally.layered;

        return !buffers.pre_load_modules.empty();
    }





    void StealthSurveyHostSurface(const StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Survey Host Surface...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)buffers;

        {
            MEMORYSTATUSEX memory{};
            memory.dwLength = sizeof(memory);
            if (GlobalMemoryStatusEx(&memory))
            {



                const bool commit_equals_physical = memory.ullTotalPageFile <= memory.ullTotalPhys;
                LOG(0, L"  %ls[%ls]%ls Memory Surface............ Physical %ls%llu MB%ls | Commit Limit %ls%llu MB%ls | In Use %ls%llu MB%ls %ls\n",
                    commit_equals_physical ? kYellow : kGreen, commit_equals_physical ? L"!" : L"+", kReset,
                    kGreen, memory.ullTotalPhys >> 20, kReset,
                    commit_equals_physical ? kYellow : kGreen, memory.ullTotalPageFile >> 20, kReset,
                    kGreen, memory.ullAvailPageFile >> 20, kReset,
                    commit_equals_physical
                        ? L"(Commit Limit Does Not Exceed Physical Memory - The No-Pagefile VM Tell)"
                        : L"(Commit Limit Exceeds Physical Memory - Pagefile Present)");
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Memory Surface............ GlobalMemoryStatusEx Failed (0x%08X)\n",
                    kYellow, kReset, static_cast<unsigned>(GetLastError()));
            }
        }

        {
            int regs[4]{};
            __cpuid(regs, 0);
            char vendor[13]{};
            memcpy(vendor + 0, &regs[1], 4);
            memcpy(vendor + 4, &regs[3], 4);
            memcpy(vendor + 8, &regs[2], 4);
            __cpuid(regs, 1);
            const bool hypervisor = (regs[2] & (1 << 31)) != 0;
            LOG(0, L"  %ls[%ls]%ls CPU Surface.............. Vendor '%hs' | Hypervisor Present Bit %ls%s%ls %ls\n",
                hypervisor ? kYellow : kGreen, hypervisor ? L"!" : L"+", kReset,
                vendor,
                hypervisor ? kYellow : kGreen, hypervisor ? L"Set" : L"Clear", kReset,
                hypervisor
                    ? L"(CPUID Leaf 1 ECX Bit 31 - C3's Spoofing Checklist Item)"
                    : L"(No Hypervisor Bit)");
        }

        {
            using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
            using NtQueryObjectFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            auto query_system = ntdll ? ReCa<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
            auto query_object = ntdll ? ReCa<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject")) : nullptr;

            size_t events = 0, sections = 0, mutants = 0;
            size_t named_events = 0, named_sections = 0, named_mutants = 0;
            size_t named_other = 0;
            bool census_ok = false;
            if (query_system && query_object)
            {
                std::vector<BYTE> buffer(1 << 20);
                ULONG size = static_cast<ULONG>(buffer.size());
                LONG status = query_system(64, buffer.data(), size, &size);
                while (static_cast<DWORD>(status) == 0xC0000004u && buffer.size() < (32u << 20))
                {
                    buffer.resize(size > buffer.size() ? size : buffer.size() * 2);
                    size = static_cast<ULONG>(buffer.size());
                    status = query_system(64, buffer.data(), size, &size);
                }

                if (status == 0)
                {



                    struct HandleEntryEx
                    {
                        void * Object;
                        ULONG_PTR ProcessId;
                        void * Handle;
                        ULONG GrantedAccess;
                        USHORT CreatorBackTraceIndex;
                        USHORT ObjectTypeIndex;
                        ULONG HandleAttributes;
                        ULONG Reserved;
                    };

                    census_ok = true;
                    const ULONG_PTR count = *ReCa<const ULONG_PTR *>(buffer.data());
                    const HandleEntryEx * entries = ReCa<const HandleEntryEx *>(buffer.data() + sizeof(ULONG_PTR) * 2);
                    const size_t capacity = (buffer.size() - sizeof(ULONG_PTR) * 2) / sizeof(HandleEntryEx);
                    const size_t total_entries = count < capacity ? static_cast<size_t>(count) : capacity;
                    const DWORD self = GetCurrentProcessId();
                    size_t checked = 0;

                    for (size_t i = 0; i < total_entries && checked < 1024; ++i)
                    {
                        const HandleEntryEx & entry = entries[i];
                        if (entry.ProcessId != self || !entry.Handle)
                        {
                            continue;
                        }
                        ++checked;






                        HANDLE duplicate = nullptr;
                        if (!DuplicateHandle(GetCurrentProcess(), entry.Handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
                        {
                            continue;
                        }

                        BYTE type_buf[128]{};
                        ULONG returned = 0;
                        if (query_object(duplicate, 2, type_buf, sizeof(type_buf), &returned) == 0)
                        {
                            const auto * type_name = ReCa<const UNICODE_STRING *>(type_buf);
                            const wchar_t * name = type_name && type_name->szBuffer ? type_name->szBuffer : L"";
                            const size_t name_len = type_name ? type_name->Length / sizeof(wchar_t) : 0;

                            const bool is_event = name_len == 5 && wcsncmp(name, L"Event", 5) == 0;
                            const bool is_section = name_len == 7 && wcsncmp(name, L"Section", 7) == 0;
                            const bool is_mutant = name_len == 6 && wcsncmp(name, L"Mutant", 6) == 0;
                            if (is_event || is_section || is_mutant)
                            {
                                bool named = false;
                                BYTE name_buf[128]{};
                                if (query_object(duplicate, 1, name_buf, sizeof(name_buf), &returned) == 0)
                                {
                                    const auto * object_name = ReCa<const UNICODE_STRING *>(name_buf);
                                    named = object_name && object_name->Length != 0 && object_name->szBuffer;
                                }

                                if (is_event)
                                {
                                    ++events;
                                    named_events += named ? 1 : 0;
                                }
                                else if (is_section)
                                {
                                    ++sections;
                                    named_sections += named ? 1 : 0;
                                }
                                else
                                {
                                    ++mutants;
                                    named_mutants += named ? 1 : 0;
                                }
                            }
                        }
                        CloseHandle(duplicate);
                    }
                }
            }

            const size_t named_total = named_events + named_sections + named_mutants + named_other;
            if (census_ok)
            {
                LOG(0, L"  %ls[%ls]%ls Kernel Objects (This Run).. Events %ls%zu%ls (Named %ls%zu%ls) | Sections %ls%zu%ls (Named %ls%zu%ls) | Mutants %ls%zu%ls (Named %ls%zu%ls) %ls\n",
                    named_total ? kYellow : kGreen, named_total ? L"!" : L"+", kReset,
                    kGreen, events, kReset, named_events ? kYellow : kGreen, named_events, kReset,
                    kGreen, sections, kReset, named_sections ? kYellow : kGreen, named_sections, kReset,
                    kGreen, mutants, kReset, named_mutants ? kYellow : kGreen, named_mutants, kReset,
                    named_total
                        ? L"(Named Objects Exist - A \\BaseNamedObjects Scan Surface; Note The Loader Holds System-Named \\KnownDlls Sections)"
                        : L"(All Unnamed - No \\BaseNamedObjects Surface)");
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Kernel Objects (This Run).. Enumeration Failed; Not Reported As Clean\n",
                    kYellow, kReset);
            }
        }

        {
            wchar_t root[MAX_PATH]{};
            const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", root, MAX_PATH);
            if (len && len < MAX_PATH)
            {



                const std::wstring dir = std::wstring(root) + L"\\Symbols";
                size_t files = 0;
                size_t folders = 0;
                unsigned long long bytes = 0;
                WIN32_FIND_DATAW found{};
                HANDLE search = FindFirstFileW((dir + L"\\*").c_str(), &found);
                if (search != INVALID_HANDLE_VALUE)
                {
                    do
                    {
                        if (!(found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcscmp(found.cFileName, L".") == 0 || wcscmp(found.cFileName, L"..") == 0)
                        {
                            continue;
                        }
                        ++folders;
                        const std::wstring first = dir + L"\\" + found.cFileName;
                        WIN32_FIND_DATAW inner{};
                        HANDLE sub = FindFirstFileW((first + L"\\*").c_str(), &inner);
                        if (sub != INVALID_HANDLE_VALUE)
                        {
                            do
                            {
                                if (!(inner.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcscmp(inner.cFileName, L".") == 0 || wcscmp(inner.cFileName, L"..") == 0)
                                {
                                    continue;
                                }
                                const std::wstring second = first + L"\\" + inner.cFileName;
                                WIN32_FIND_DATAW leaf{};
                                HANDLE deep = FindFirstFileW((second + L"\\*").c_str(), &leaf);
                                if (deep != INVALID_HANDLE_VALUE)
                                {
                                    do
                                    {
                                        if (leaf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                                        {
                                            continue;
                                        }
                                        ++files;
                                        bytes += (static_cast<unsigned long long>(leaf.nFileSizeHigh) << 32) | leaf.nFileSizeLow;
                                    } while (FindNextFileW(deep, &leaf));
                                    FindClose(deep);
                                }
                            } while (FindNextFileW(sub, &inner));
                            FindClose(sub);
                        }
                    } while (FindNextFileW(search, &found));
                    FindClose(search);
                }
                LOG(0, L"  %ls[*]%ls Symbol Store............. %ls%ls%ls | %zu Folder(s), %zu File(s), %llu KB - Persistent By Design (One Download Per Machine; The Per-Run Scratch Is Deleted On Shutdown)\n",
                    kDim, kReset,
                    kGreen, dir.c_str(), kReset,
                    folders, files, bytes / 1024);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Symbol Store............. LOCALAPPDATA Unresolvable\n", kYellow, kReset);
            }
        }

        LOG(0, L"\n");
    }

    void StealthSurveyTraps(HANDLE process, DWORD survey_pid, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Survey Target Traps...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        ReportGameTraps(process, survey_pid, buffers);
        LOG(0, L"\n");
    }

    void StealthVerifyUsermodeVectors(HANDLE process, const HijackStats * process_hijack,
        DWORD survey_pid, const StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify Usermode Detection Vectors...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        DWORD own_pid = GetCurrentProcessId();
        int visible_windows = 0;




        struct OverlayTally
        {
            DWORD pid;
            int count;
        } overlay{ own_pid, 0 };
        EnumWindows([](HWND hwnd, LPARAM param) -> BOOL {
            OverlayTally * tally = reinterpret_cast<OverlayTally *>(param);
            if (!IsWindowVisible(hwnd))
            {
                return TRUE;
            }
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == tally->pid)
            {
                ++tally->count;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&overlay));
        visible_windows = overlay.count;






        size_t after_windows = 0;
        size_t after_layered = 0;
        if (survey_pid)
        {
            struct TargetWindowTally
            {
                DWORD pid;
                size_t windows;
                size_t layered;
            } target_tally{ survey_pid, 0, 0 };
            EnumWindows([](HWND hwnd, LPARAM param) -> BOOL {
                TargetWindowTally * tally = reinterpret_cast<TargetWindowTally *>(param);
                DWORD owner = 0;
                GetWindowThreadProcessId(hwnd, &owner);
                if (owner != tally->pid)
                {
                    return TRUE;
                }
                ++tally->windows;
                if (GetWindowLongW(hwnd, GWL_EXSTYLE) & (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW))
                {
                    ++tally->layered;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&target_tally));
            after_windows = target_tally.windows;
            after_layered = target_tally.layered;
        }

        const bool veh_ok = ProbeLocalVehPathRoundTrip();

        LOG(0, L"  %ls[%ls]%ls Overlay Surface............ Visible Windows Owned By This Process: %ls%d%ls %ls\n",
            visible_windows == 0 ? kGreen : kRed, visible_windows == 0 ? L"+" : L"x", kReset,
            visible_windows == 0 ? kGreen : kRed, visible_windows, kReset,
            visible_windows == 0 ? L"(None - Hidden Scratch Target, No UI Created)" : L"(DETECTED - Visible Window Present)");
        if (survey_pid)
        {
            const long window_delta = static_cast<long>(after_windows) - static_cast<long>(buffers.pre_target_windows);
            const long layered_delta = static_cast<long>(after_layered) - static_cast<long>(buffers.pre_target_layered);
            const bool surface_clean = window_delta == 0 && layered_delta == 0;
            LOG(0, L"  %ls[%ls]%ls Payload Window Surface.... Target-Owned Windows: %ls%zu -> %zu%ls (%ls%+ld%ls) | Layered/Transparent: %ls%zu -> %zu%ls (%ls%+ld%ls) %ls\n",
                surface_clean ? kGreen : kYellow, surface_clean ? L"+" : L"!", kReset,
                surface_clean ? kGreen : kYellow, buffers.pre_target_windows, after_windows, kReset,
                window_delta == 0 ? kGreen : kYellow, window_delta, kReset,
                surface_clean ? kGreen : kYellow, buffers.pre_target_layered, after_layered, kReset,
                layered_delta == 0 ? kGreen : kYellow, layered_delta, kReset,
                surface_clean ? L"(No Surface The Target Can Enumerate Was Added)" : L"(Payload Created Window Surface - EnumWindows/DWM Visible)");
        }





        int design_assertions = 6;
        LOG(0, L"  %ls[*]%ls Input Polling.............. Not Measured (Design Assertion): GetAsyncKeyState (HOME/END), No Target Hook\n", kDim, kReset);
        LOG(0, L"  %ls[*]%ls Shared Memory.............. Not Measured (Design Assertion): Unnamed Events Only, No Named Objects\n", kDim, kReset);
        if (process_hijack)
        {
            LOG(0, L"  %ls[*]%ls Handle Donor.............. Observed Telemetry: Owners Opened: %lu | Dup Denied: %lu | Verify Rejected: %lu | Total Handles: %lu\n",
                kDim, kReset,
                static_cast<unsigned long>(process_hijack->OwnersOpened),
                static_cast<unsigned long>(process_hijack->DupDenied),
                static_cast<unsigned long>(process_hijack->VerifyRejected),
                static_cast<unsigned long>(process_hijack->TotalHandles));
        }
        else
        {
            LOG(0, L"  %ls[*]%ls Handle Donor.............. Not Measured (Design Assertion): Owner Screened By Name Before Open\n", kDim, kReset);
            ++design_assertions;
        }
        LOG(0, L"  %ls[%ls]%ls VEH Chain.................. Local Add+Remove Round-Trip: %ls%s%ls | Installed In Target: 0 (By Design)\n",
            veh_ok ? kGreen : kRed, veh_ok ? L"+" : L"x", kReset,
            veh_ok ? kGreen : kRed, veh_ok ? L"OK" : L"Failed", kReset);
        LOG(0, L"  %ls[*]%ls TLS Callbacks............. Not Measured Here (Design Assertion): Payload Installs 0; Actual Count Is In-Shell Telemetry\n", kDim, kReset);
        LOG(0, L"  %ls[*]%ls Timing..................... Not Measured (Design Assertion): Coarse GetTickCount64 Window Only\n", kDim, kReset);
        LOG(0, L"  %ls[*]%ls HWID/Identity.............. Not Measured (Design Assertion): No Probe APIs Called By The Launcher\n", kDim, kReset);
        LOG(0, L"  %ls[*]%ls Integrity Hashing......... Not Measured (Design Assertion): Query-Only And Scan-Only, No Writes To Game Pages\n", kDim, kReset);
        const bool measured_ok = (visible_windows == 0 && veh_ok);
        if (measured_ok)
        {
            LOG(0, L"  %ls[*]%ls Usermode Vectors........... 2 Vectors Measured And OK (Overlay, VEH); "
                    L"%d Design Assertions Not Exercised - Not A Pass\n",
                kDim, kReset, design_assertions);
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Usermode Vectors........... Measured Vector Failure: Overlay Or VEH Check Failed\n",
                kRed, kReset);
        }
        (void)process;
    }

    // Forward declarations for the Vector 1 / Vector 7 verifier steps (defined further down).
    void StealthVerifyMappingType(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers, int & step, int total);
    void StealthVerifyNoLoaderArtifact(HANDLE process, HINSTANCE hRemoteBase, DWORD survey_pid,
        StealthVerifierBuffers & buffers, int & step, int total);
    void StealthVerifySectionHandleClosed(HANDLE process, HINSTANCE hRemoteBase, int & step, int total);
    void StealthReportKernelResiduals(int & step, int total);
    void StealthVerifyStackSpoofGeometry(HANDLE process, HINSTANCE hRemoteBase,
        StealthVerifierBuffers & buffers, int & step, int total, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry);
    void StealthVerifyGadgetValidity(StealthVerifierBuffers & buffers, int & step, int total);
    void StealthVerifySpoofRandomization(HANDLE process, HINSTANCE hRemoteBase, int & step, int total);

    bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {



        if (wx_violated)
        {
            *wx_violated = true;
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
            true,
            isActive(INJ_ERASE_HEADER),
            true,
            survey_game_traps,
            // Vector 1 + Vector 7 verification steps (always run)
            true,
            true,
            true,
            true,
            true,
            true,
            true,
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

        if (step_enabled[kStealthVerifyUsermodeVectors])
        {
            StealthVerifyUsermodeVectors(process, ProcessHijack, survey_pid, buffers, step, total);
        }

        if (step_enabled[kStealthEraseHeader])
        {
            StealthEraseHeader(process, hRemoteBase, have_local_nt, MapStats, ExecTelemetry, buffers, step, total);
        }
        if (step_enabled[kStealthSurveyHostSurface])
        {
            StealthSurveyHostSurface(buffers, step, total);
        }
        if (step_enabled[kStealthSurveyTraps])
        {
            StealthSurveyTraps(process, survey_pid, buffers, step, total);
        }

        // Vector 1: page-file section verification
        if (step_enabled[kStealthVerifyMappingType])
        {
            StealthVerifyMappingType(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }
        if (step_enabled[kStealthVerifyNoLoaderArtifact])
        {
            StealthVerifyNoLoaderArtifact(process, hRemoteBase, survey_pid, buffers, step, total);
        }
        if (step_enabled[kStealthVerifySectionHandleClosed])
        {
            StealthVerifySectionHandleClosed(process, hRemoteBase, step, total);
        }
        if (step_enabled[kStealthReportKernelResiduals])
        {
            StealthReportKernelResiduals(step, total);
        }

        // Vector 7: hardened stack spoof verification (telemetry-driven: samples the payload's
        // own emitted-stub syscall rings instead of snapshotting an idle target thread)
        if (step_enabled[kStealthVerifyStackSpoofGeometry])
        {
            StealthVerifyStackSpoofGeometry(process, hRemoteBase, buffers, step, total, ExecTelemetry);
        }
        if (step_enabled[kStealthVerifyGadgetValidity])
        {
            StealthVerifyGadgetValidity(buffers, step, total);
        }
        if (step_enabled[kStealthVerifySpoofRandomization])
        {
            StealthVerifySpoofRandomization(process, hRemoteBase, step, total);
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




    bool EnumerateRemoteModules(HANDLE process, std::vector<SurveyModule> & out)
    {
        out.clear();
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
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                if (!entry.modBaseAddr || !entry.modBaseSize)
                {
                    continue;
                }
                SurveyModule module{};
                module.name = entry.szModule;
                module.base = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
                module.size = static_cast<SIZE_T>(entry.modBaseSize);
                out.push_back(module);
            } while (Module32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        std::sort(out.begin(), out.end(), [](const SurveyModule & a, const SurveyModule & b)
        {
            return a.base < b.base;
        });

        return !out.empty();
    }



    bool FindModuleByBase(const std::vector<SurveyModule> & modules, ULONG_PTR base, SurveyModule & out)
    {
        for (const SurveyModule & module : modules)
        {
            if (module.base == base)
            {
                out = module;
                return true;
            }
        }
        return false;
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

        std::vector<SurveyModule> modules;
        if (!EnumerateRemoteModules(process, modules))
        {
            return false;
        }

        VehFirstChanceSurvey survey{};
        if (QueryRemoteVehFirstChance(process, survey) && survey.readOk && survey.imageBase)
        {
            SurveyModule main{};
            if (FindModuleByBase(modules, survey.imageBase, main))
            {
                name_out = main.name;
                base_out = main.base;
                size_out = main.size;
                return true;
            }
        }

        const SurveyModule & first = modules.front();
        name_out = first.name;
        base_out = first.base;
        size_out = first.size;
        return true;
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
        const ULONG_PTR image_base_addr = peb + offsetof(PEB, ImageBaseAddress);

        ULONG cross = 0;
        BYTE debugged = 0;
        ULONG gflag = 0;
        ULONG_PTR image_base = 0;
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
        got = 0;


        if (ReadProcessMemory(process, ReCa<LPCVOID>(image_base_addr), &image_base, sizeof(image_base), &got) &&
            got == sizeof(image_base))
        {
            out.imageBase = image_base;
        }

        out.crossFlags = cross;
        out.usingVeh = (cross & 0x4u) != 0;
        out.usingVch = (cross & 0x8u) != 0;
        out.beingDebugged = debugged;
        out.ntGlobalFlag = gflag;
        out.readOk = true;
        return true;
    }

    // ===== Vector 1 + Vector 7 verification steps =====

    void StealthVerifyMappingType(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 1: Verify Mapping Type (VAD)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)have_local_nt; (void)local_pe; (void)buffers;

        if (!process || process == INVALID_HANDLE_VALUE || !hRemoteBase)
        {
            LOG(0, L"  %ls[!]%ls Mapping Type Unverifiable: Process Handle Or Remote Base Unavailable\n", kYellow, kReset);
            return;
        }

        const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(hRemoteBase);

        // BUG 3: query the VAD at the image base. If that returns a bare 4 KB region, also
        // query base+0x1000 to rule out a page-boundary / erased-header-page artifact.
        MEMORY_BASIC_INFORMATION mbi{};
        const bool q_base = VirtualQueryEx(process, ReCa<LPCVOID>(base), &mbi, sizeof(mbi));

        MEMORY_BASIC_INFORMATION mbi_next{};
        bool q_next = false;
        if (q_base && mbi.RegionSize == 0x1000)
        {
            q_next = VirtualQueryEx(process, ReCa<LPCVOID>(base + 0x1000), &mbi_next, sizeof(mbi_next));
        }

        if (!q_base)
        {
            LOG(0, L"  %ls[!]%ls VAD Query Failed At Base 0x%llX\n", kYellow, kReset, static_cast<unsigned long long>(base));
            return;
        }

        auto dump_mbi = [](const wchar_t * label, ULONG_PTR queried, const MEMORY_BASIC_INFORMATION & m) -> void
        {
            LOG(0, L"    %ls%s @ 0x%016llX%ls BaseAddress = 0x%016llX | AllocationBase = 0x%016llX | AllocationProtect = 0x%04X | RegionSize = 0x%016llX | State = 0x%08X | Protect = 0x%04X | Type = 0x%08X\n",
                kYellow, label, static_cast<unsigned long long>(queried), kReset,
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(m.BaseAddress)),
                static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(m.AllocationBase)),
                static_cast<unsigned long long>(m.AllocationProtect),
                static_cast<unsigned long long>(m.RegionSize),
                static_cast<unsigned long long>(m.State),
                static_cast<unsigned long long>(m.Protect),
                static_cast<unsigned long long>(m.Type));
        };

        LOG(0, L"  %ls[VAD] Seven-Field MEMORY_BASIC_INFORMATION Dump (Base-Of-Image Query)%ls\n", kYellow, kReset);
        dump_mbi(L"MBI", base, mbi);
        if (q_next)
        {
            LOG(0, L"  %ls[VAD] Seven-Field MEMORY_BASIC_INFORMATION Dump (ImageBase + 0x1000)%ls\n", kYellow, kReset);
            dump_mbi(L"MBI", base + 0x1000, mbi_next);
        }

        // BUG 1: MEM_MAPPED is the correct type for a page-file section view (the section path),
        // and MEM_IMAGE is the correct type for an image-mapped load. Only MEM_PRIVATE indicates
        // the detectable private-map fallback.
        const wchar_t * type_str =
            mbi.Type == MEM_IMAGE ? L"MEM_IMAGE" :
            mbi.Type == MEM_MAPPED ? L"MEM_MAPPED" :
            mbi.Type == MEM_PRIVATE ? L"MEM_PRIVATE" : L"UNKNOWN";

        const SIZE_T size_of_image = static_cast<SIZE_T>(local_pe_size);

        if (mbi.Type == MEM_MAPPED)
        {
            LOG(0, L"  %ls[+]%ls VAD Mapping Type = MEM_MAPPED (Page-File Section; Not Private-Map Fallback) | Base = 0x%llX | SizeOfImage = 0x%llX\n",
                kGreen, kReset,
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(size_of_image));
        }
        else if (mbi.Type == MEM_IMAGE)
        {
            LOG(0, L"  %ls[+]%ls VAD Mapping Type = MEM_IMAGE (Image-Mapped Page-Backed Section; Not Private-Map Fallback) | Base = 0x%llX | SizeOfImage = 0x%llX\n",
                kGreen, kReset,
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(size_of_image));
        }
        else if (mbi.Type == MEM_PRIVATE)
        {
            LOG(0, L"  %ls[x]%ls VAD Mapping Type = MEM_PRIVATE (Private-Map Fallback; Detectable) | Base = 0x%llX | SizeOfImage = 0x%llX\n",
                kRed, kReset,
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(size_of_image));
        }
        else
        {
            LOG(0, L"  %ls[!]%ls VAD Mapping Type = %ls (Unrecognized) | Base = 0x%llX | SizeOfImage = 0x%llX\n",
                kYellow, kReset, type_str,
                static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(size_of_image));
        }

        // BUG 3: the image base is the erased header page (PAGE_NOACCESS by design), so judge the
        // RX flip on the first page past the header (base+0x1000, the .text body).
        const MEMORY_BASIC_INFORMATION & body_mbi = (q_next ? mbi_next : mbi);
        const ULONG_PTR body_address = (q_next ? (base + 0x1000) : base);
        const bool rx_flip_ok = (body_mbi.Protect == PAGE_EXECUTE_READ);

        LOG(0, L"  %ls[VAD] Expected After RX Flip = PAGE_EXECUTE_READ (0x%04llX) | Observed At 0x%016llX = %ls (0x%04llX)%ls%ls\n",
            rx_flip_ok ? kGreen : kYellow,
            static_cast<unsigned long long>(PAGE_EXECUTE_READ),
            static_cast<unsigned long long>(body_address),
            StealthPageDesc(body_mbi.Protect),
            static_cast<unsigned long long>(body_mbi.Protect),
            rx_flip_ok ? L" [RX Flip Effective]" : L" [RX Flip Skipped Or Wrong Address; Diagnostic, Not A Fix]",
            kReset);
    }

    void StealthVerifyNoLoaderArtifact(HANDLE process, HINSTANCE hRemoteBase, DWORD survey_pid,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 1: Verify No Loader Artifact (Ldr Walk)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)survey_pid; (void)buffers;

        VehFirstChanceSurvey veh{};
        if (!QueryRemoteVehFirstChance(process, veh) || !veh.pebAddress)
        {
            LOG(0, L"  %ls[!]%ls PEB Address Unreadable; Cannot Walk Ldr\n", kYellow, kReset);
            return;
        }

        const ULONG_PTR peb = ReCa<ULONG_PTR>(veh.pebAddress);
        ULONG_PTR ldr = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(peb + 24), &ldr, sizeof(ldr), &got) || got != sizeof(ldr) || !ldr)
        {
            LOG(0, L"  %ls[!]%ls Ldr Pointer Unreadable At PEB+24 (PEB = %p)\n", kYellow, kReset, veh.pebAddress);
            return;
        }

        struct LDR_ENTRY
        {
            LIST_ENTRY InLoadOrder;
            LIST_ENTRY LoadOrder;
            LIST_ENTRY BaseAddressOrder;
            ULONG_PTR DllBase;
        };
        static_assert(sizeof(LDR_ENTRY) >= 0x18, "LDR_ENTRY must expose DllBase at offset 24");

        const SIZE_T head_offsets[] = { 0x28, 0x30, 0x38 };
        ULONG_PTR matching = 0;
        ULONG_PTR scanned = 0;

        for (size_t h = 0; h < sizeof(head_offsets) / sizeof(head_offsets[0]); ++h)
        {
            const ULONG_PTR head_addr = ldr + head_offsets[h];
            LIST_ENTRY head{};
            got = 0;
            if (!ReadProcessMemory(process, ReCa<LPCVOID>(head_addr), &head, sizeof(head), &got) || got != sizeof(head))
            {
                continue;
            }

            ULONG_PTR cur = ReCa<ULONG_PTR>(head.Flink);
            while (cur && cur != head_addr && scanned < 4096)
            {
                LDR_ENTRY entry{};
                got = 0;
                if (ReadProcessMemory(process, ReCa<LPCVOID>(cur), &entry, sizeof(entry), &got) && got == sizeof(entry))
                {
                    ++scanned;
                    if (ReCa<ULONG_PTR>(hRemoteBase) == entry.DllBase)
                    {
                        ++matching;
                    }
                }

                LIST_ENTRY next{};
                got = 0;
                if (!ReadProcessMemory(process, ReCa<LPCVOID>(cur), &next, sizeof(next), &got) || got != sizeof(next))
                {
                    break;
                }
                cur = ReCa<ULONG_PTR>(next.Flink);
                if (cur == head_addr)
                {
                    break;
                }
            }
        }

        if (matching == 0)
        {
            LOG(0, L"  %ls[+]%ls Ldr Walk Clean: 0 Of %llu Scanned Entries Match Remote Base %p\n",
                kGreen, kReset, static_cast<unsigned long long>(scanned), hRemoteBase);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Loader Artifact Present: %llu Ldr Entries Point At Remote Base %p\n",
                kYellow, kReset, static_cast<unsigned long long>(matching), hRemoteBase);
        }
    }

    void StealthVerifySectionHandleClosed(HANDLE process, HINSTANCE hRemoteBase, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 1: Verify Section Handle Closed...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)hRemoteBase;

        if (!process || process == INVALID_HANDLE_VALUE)
        {
            LOG(0, L"  %ls[!]%ls Section Handle Check Skipped: Process Handle Unavailable\n", kYellow, kReset);
            return;
        }

        const DWORD target_pid = GetProcessId(process);

        using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryObjectFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query_system = ntdll ? ReCa<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
        auto query_object = ntdll ? ReCa<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject")) : nullptr;

        if (!query_system || !query_object)
        {
            LOG(0, L"  %ls[!]%ls NtQuerySystemInformation Or NtQueryObject Unavailable\n", kYellow, kReset);
            return;
        }

        std::vector<BYTE> buffer(1 << 20);
        ULONG size = static_cast<ULONG>(buffer.size());
        LONG status = query_system(64, buffer.data(), size, &size);
        while (static_cast<DWORD>(status) == 0xC0000004u && buffer.size() < (32u << 20))
        {
            buffer.resize(size > buffer.size() ? size : buffer.size() * 2);
            size = static_cast<ULONG>(buffer.size());
            status = query_system(64, buffer.data(), size, &size);
        }

        if (status != 0)
        {
            LOG(0, L"  %ls[!]%ls System Handle Table Unreadable (Status = 0x%08X)\n", kYellow, kReset, static_cast<unsigned>(status));
            return;
        }

        struct HandleEntryEx
        {
            void * Object;
            ULONG_PTR ProcessId;
            void * Handle;
            ULONG GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };

        const ULONG_PTR count = *ReCa<const ULONG_PTR *>(buffer.data());
        const HandleEntryEx * entries = ReCa<const HandleEntryEx *>(buffer.data() + sizeof(ULONG_PTR) * 2);
        const size_t capacity = (buffer.size() - sizeof(ULONG_PTR) * 2) / sizeof(HandleEntryEx);
        const size_t total_entries = count < capacity ? static_cast<size_t>(count) : capacity;

        size_t target_sections = 0;
        size_t checked = 0;
        for (size_t i = 0; i < total_entries; ++i)
        {
            const HandleEntryEx & entry = entries[i];
            if (entry.ProcessId != target_pid || !entry.Handle)
            {
                continue;
            }
            ++checked;

            HANDLE duplicate = nullptr;
            if (!DuplicateHandle(GetCurrentProcess(), entry.Handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
            {
                continue;
            }

            BYTE type_buf[128]{};
            ULONG returned = 0;
            if (query_object(duplicate, 2, type_buf, sizeof(type_buf), &returned) == 0)
            {
                const auto * type_name = ReCa<const UNICODE_STRING *>(type_buf);
                const wchar_t * name = (type_name && type_name->szBuffer) ? type_name->szBuffer : L"";
                const size_t name_len = type_name ? type_name->Length / sizeof(wchar_t) : 0;
                if (name_len == 7 && wcsncmp(name, L"Section", 7) == 0)
                {
                    ++target_sections;
                }
            }
            CloseHandle(duplicate);
        }

        if (target_sections == 0)
        {
            LOG(0, L"  %ls[+]%ls Section Handle Closed: 0 Section Handles Held By Target PID %u (%llu Handles Checked)\n",
                kGreen, kReset, target_pid, static_cast<unsigned long long>(checked));
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Section Handle Still Open: %llu Section Handles Held By Target PID %u\n",
                kYellow, kReset, static_cast<unsigned long long>(target_sections), target_pid);
        }
    }

    void StealthReportKernelResiduals(int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Kernel Residuals (Not User-Mode Fixable)...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        LOG(0, L"  %ls[!]%ls ETW-TI: Kernel Residual (Not User-Mode Fixable)\n", kYellow, kReset);
        LOG(0, L"  %ls[!]%ls KernelVAD: Kernel Residual (Not User-Mode Fixable)\n", kYellow, kReset);
        LOG(0, L"  %ls[!]%ls HWStackIntegrity: Kernel Residual (Not User-Mode Fixable)\n", kYellow, kReset);
        LOG(0, L"  %ls[!]%ls ObCallbacks: Kernel Residual (Not User-Mode Fixable)\n", kYellow, kReset);
    }

    void StealthVerifyStackSpoofGeometry(HANDLE process, HINSTANCE hRemoteBase,
        StealthVerifierBuffers & buffers, int & step, int total, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 7: Verify Stack Spoof Geometry...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)buffers; (void)hRemoteBase;

        if (!process || process == INVALID_HANDLE_VALUE)
        {
            LOG(0, L"  %ls[!]%ls VerifyStackSpoofGeometry: Skipped — Process Handle Unavailable\n", kYellow, kReset);
            return;
        }

        const DWORD target_pid = GetProcessId(process);

        // Vector 7 (this pass): frame resolution is driven by the telemetry ring the payload's
        // own emitted syscall stubs write — one SYSCALL_SAMPLE per syscall issued through a
        // sampled stub, recording TID, RSP, TSC and which remote stub fired. Each captured stack
        // qword is classified with kernel32 VirtualQueryEx (MEMORY_BASIC_INFORMATION) plus a
        // one-time module range map (EnumProcessModulesEx + GetModuleInformation). NtQueryVirtualMemory
        // is NOT used: on this build its name-returning classes fail uniformly (class 3 is
        // MemoryRegionInformation, not a name class; class 2 returned STATUS_IO_PENDING), and
        // VirtualQueryEx is the proven-working path for the resolve handle.
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

        // (1a) Enumerate the target process's threads via a Toolhelp32 Thread32 walk.
        // BUG 2: the snapshot must be created for the TARGET pid (0 snapshots only the
        // current process, which is why the census previously returned 0 threads).
        DWORD thread_count = 0;
        DWORD sample_tid = 0;
        DWORD entries_seen = 0;
        bool first_ok = false;
        bool snap_ok = false;

        // BUG 2 diagnostic (item 1): confirm the handle we census with is a valid
        // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ handle to the target PID.
        {
            HANDLE probe = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
            LOG(0, L"  [Census] OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, %u) = 0x%p (%s) | GetLastError = 0x%08X | Passed-In Process Handle = 0x%p\n",
                target_pid, probe, probe ? L"OK" : L"FAILED", static_cast<unsigned>(GetLastError()), process);
            if (probe)
            {
                CloseHandle(probe);
            }
        }
        {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, target_pid);
            snap_ok = (snap != INVALID_HANDLE_VALUE);
            LOG(0, L"  [Census] PID In Use = %u | Process Handle = 0x%p | CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %u) = 0x%p (%s) | GetLastError = 0x%08X\n",
                target_pid, process, target_pid, snap, snap_ok ? L"OK" : L"FAILED (INVALID_HANDLE_VALUE)",
                static_cast<unsigned>(GetLastError()));

            if (snap_ok)
            {
                THREADENTRY32 te{};
                te.dwSize = sizeof(te);
                first_ok = Thread32First(snap, &te) != FALSE;
                LOG(0, L"  [Census] Thread32First = %s | Filter Applied: th32OwnerProcessID == %u (no state/exit-code filter; THREADENTRY32 carries no state)\n",
                    first_ok ? L"TRUE" : L"FALSE", target_pid);

                if (first_ok)
                {
                    do
                    {
                        ++entries_seen;
                        if (te.th32OwnerProcessID == target_pid)
                        {
                            ++thread_count;
                            if (sample_tid == 0)
                            {
                                sample_tid = te.th32ThreadID;
                            }
                        }
                    } while (Thread32Next(snap, &te));
                }
                CloseHandle(snap);
            }
        }
        LOG(0, L"  [Census] Entries Seen = %u | Entries Matched Target PID = %u | Sample TID = %u\n",
            entries_seen, thread_count, sample_tid);
        LOG(0, L"  Target Threads (PID %u): %u Found (Sample TID %u)\n", target_pid, thread_count, sample_tid);

        if (thread_count == 0)
        {
            LOG(0, L"  %ls[!]%ls VerifyStackSpoofGeometry: No Target Threads In Census (PID %u)\n", kYellow, kReset, target_pid);
            return;
        }

        // (2) Vector 7 (this pass): the frames come from the telemetry ring the payload's own
        // emitted syscall stubs wrote — NOT from snapshotting an idle target thread, and NOT by
        // re-reading the (already scrubbed+released) shell stack at the recorded RSP. Each
        // SYSCALL_SAMPLE carries its own Frames[8] (the [rsp+0..56] qwords captured AT SYSCALL
        // TIME inside the sampler, while the shell stack was still mapped). Read the most recent
        // <= 8 samples and resolve each captured qword against the target's mapped modules (class 3).
        LOG(0, L"  [Telemetry] sizeof(VERIFIABLE_EXEC_TELEMETRY) = %u | sample ring = %u x %u = %u bytes\n",
            static_cast<unsigned>(sizeof(VERIFIABLE_EXEC_TELEMETRY)),
            static_cast<unsigned>(SYSCALL_SAMPLE_COUNT),
            static_cast<unsigned>(sizeof(SYSCALL_SAMPLE)),
            static_cast<unsigned>(SYSCALL_SAMPLE_COUNT * sizeof(SYSCALL_SAMPLE)));

        const LONG sample_index = ExecTelemetry ? ExecTelemetry->SyscallSampleIndex : 0;
        if (sample_index == 0)
        {
            LOG(0, L"  %ls[!]%ls No syscall samples recorded\n", kYellow, kReset);
            return; // INCONCLUSIVE: the emitted stubs never fired a syscall before verification.
        }

        const int samples_available = static_cast<int>(sample_index < SYSCALL_SAMPLE_COUNT
            ? sample_index : SYSCALL_SAMPLE_COUNT);
        const int samples_taken = samples_available < 8 ? samples_available : 8; // most recent <= 8

        // SyscallSampleIndex is the NEXT slot to write (incremented mod SYSCALL_SAMPLE_COUNT per
        // sample), so the most recently written slot is (SyscallSampleIndex - 1) mod COUNT.
        int slot = (static_cast<int>(sample_index) - 1) % SYSCALL_SAMPLE_COUNT;
        if (slot < 0) slot += SYSCALL_SAMPLE_COUNT;

        // (3a) Vector 7 (this pass): a dedicated full-rights handle for frame resolution. The
        // passed-in `process` handle is a forensic Query-Limited handle whose granted mask may
        // lack PROCESS_VM_READ (class-3 NtQueryVirtualMemory then returns STATUS_ACCESS_VIOLATION
        // uniformly). This handle exists only for resolution and is closed at scope exit; the
        // passed-in handle is left exactly as-is for every other path.
        HANDLE resolve_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
        if (!resolve_handle)
        {
            // Retry under SeDebugPrivilege (mirrors SeDebugPrivilegeScope in
            // Ameger/System/Handle/HandleHijack.cpp, which is file-local there, so a local
            // equivalent is used here).
            struct SeDebugPrivilegeScope
            {
                HANDLE Token = nullptr;
                SeDebugPrivilegeScope()
                {
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
                    {
                        Token = nullptr;
                        return;
                    }
                    LUID Luid{};
                    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &Luid))
                    {
                        TOKEN_PRIVILEGES Privileges{};
                        Privileges.PrivilegeCount = 1;
                        Privileges.Privileges[0].Luid = Luid;
                        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        AdjustTokenPrivileges(Token, FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr);
                    }
                }
                ~SeDebugPrivilegeScope()
                {
                    if (Token)
                    {
                        LUID Luid{};
                        if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &Luid))
                        {
                            TOKEN_PRIVILEGES Privileges{};
                            Privileges.PrivilegeCount = 1;
                            Privileges.Privileges[0].Luid = Luid;
                            Privileges.Privileges[0].Attributes = 0; // disable again on scope exit
                            AdjustTokenPrivileges(Token, FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr);
                        }
                        CloseHandle(Token);
                    }
                }
            };
            {
                SeDebugPrivilegeScope debug_privilege_scope;
                resolve_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
            }
        }
        if (!resolve_handle)
        {
            LOG(0, L"  %ls[x]%ls Resolve Handle Could Not Be Opened (0x%08X) — Frame Resolution Skipped\n",
                kRed, kReset, static_cast<unsigned>(GetLastError()));
            return;
        }
        struct ResolveHandleGuard
        {
            HANDLE h;
            explicit ResolveHandleGuard(HANDLE handle) : h(handle) {}
            ~ResolveHandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        };
        ResolveHandleGuard resolve_guard(resolve_handle);

        // Verify the granted access: NtQueryObject(ObjectBasicInformation) readback first; if the
        // readback itself fails, prove VM_READ functionally with a VirtualQueryEx probe (success is
        // impossible without PROCESS_VM_READ).
        ULONG granted = 0;
        bool granted_known = false;
        {
            using NtQueryObjectFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto qobj = ntdll ? ReCa<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject")) : nullptr;
            if (qobj)
            {
                ULONG basic[32]{};
                ULONG returned = 0;
                if (qobj(resolve_handle, 0, basic, sizeof(basic), &returned) == 0 && returned >= sizeof(ULONG) * 2)
                {
                    granted = basic[1]; // GrantedAccess
                    granted_known = true;
                }
            }
        }
        bool vm_read_ok = granted_known ? ((granted & PROCESS_VM_READ) != 0) : false;
        if (!granted_known)
        {
            MEMORY_BASIC_INFORMATION probe{};
            vm_read_ok = VirtualQueryEx(resolve_handle, nullptr, &probe, sizeof(probe)) != 0;
            LOG(0, L"  [RESOLVE] Granted Readback Failed; VirtualQueryEx Probe = %s (functional VM_READ proof)\n",
                vm_read_ok ? L"OK" : L"FAILED");
        }
        LOG(0, L"  [RESOLVE] Handle opened = 0x%p | Requested = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | Granted = 0x%08X | VM_READ Bit = %s\n",
            resolve_handle, static_cast<unsigned>(granted), vm_read_ok ? L"YES" : L"NO");

        if (!vm_read_ok)
        {
            LOG(0, L"  %ls[x]%ls Resolve Handle Opened But PROCESS_VM_READ Not Granted — Target May Be Protected\n",
                kRed, kReset);
            return;
        }

        // (3b) Vector 7 (this pass): build the target's module range map ONCE before the frame
        // loop (psapi: EnumProcessModulesEx + GetModuleInformation + GetModuleBaseNameW), on the
        // dedicated full-rights resolve handle.
        struct ModuleRange
        {
            ULONGLONG Base;
            ULONGLONG End;
            std::wstring Name;
        };
        std::vector<ModuleRange> module_map;
        {
            HMODULE modules[1024]{};
            DWORD needed = 0;
            if (EnumProcessModulesEx(resolve_handle, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
            {
                const DWORD count = needed / sizeof(HMODULE);
                for (DWORD i = 0; i < count; ++i)
                {
                    MODULEINFO mi{};
                    if (GetModuleInformation(resolve_handle, modules[i], &mi, sizeof(mi)))
                    {
                        WCHAR name[MAX_PATH]{};
                        if (GetModuleBaseNameW(resolve_handle, modules[i], name, _countof(name)))
                        {
                            const ULONGLONG base = (ULONGLONG)mi.lpBaseOfDll;
                            module_map.push_back({ base, base + mi.SizeOfImage, name });
                        }
                    }
                }
            }
        }
        LOG(0, L"  [MODMAP] Enumerated %u modules from target PID.\n",
            static_cast<unsigned>(module_map.size()));

        // Classify one stack qword with VirtualQueryEx + the module map, on the dedicated
        // full-rights resolve handle — NOT the forensic limited-open `process`.
        auto ResolveFrame = [&](ULONG_PTR addr, std::wstring & res, bool & in_module,
            DWORD & state_out, DWORD & type_out)
        {
            in_module = false;

            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T vq = VirtualQueryEx(resolve_handle, (LPCVOID)addr, &mbi, sizeof(mbi));
            state_out = mbi.State;
            type_out = mbi.Type;

            if (vq == 0)
            {
                wchar_t qfail[64]{};
                swprintf(qfail, 64, L"vq failed (err=0x%08X)", static_cast<unsigned>(GetLastError()));
                res = qfail;
                return;
            }

            if (mbi.State == MEM_FREE)
            {
                // Memory unmapped since the sample was captured (shell/stack scrubbed+released).
                res = L"freed";
                return;
            }

            if (mbi.Type == MEM_IMAGE)
            {
                for (const auto & r : module_map)
                {
                    if (addr >= r.Base && addr < r.End)
                    {
                        res = L"module:" + r.Name;
                        in_module = true;
                        return;
                    }
                }
                res = L"MEM_IMAGE (not in module map)";
                return;
            }

            if (mbi.Type == MEM_MAPPED) { res = L"MEM_MAPPED"; return; }
            if (mbi.Type == MEM_PRIVATE) { res = L"MEM_PRIVATE"; return; }

            wchar_t unknown[32]{};
            swprintf(unknown, 32, L"unknown type 0x%08X", mbi.Type);
            res = unknown;
        };

        // Only qwords that look like canonical user-mode pointers are return-address candidates.
        // Small integers are saved register values or arguments, not return addresses.
        auto looks_like_pointer = [](ULONGLONG v) -> bool
        {
            return v >= 0x10000ULL && v <= 0x00007FFFFFFFFFFFULL;
        };

        int total_frames = 0;     // P = pointer-like qwords across all recorded samples
        int resolved = 0;         // M = pointer-like qwords resolving into a target module
        int frames_mapped = 0;    // X = pointer-like qwords in MEM_MAPPED regions
        int frames_private = 0;   // Y = pointer-like qwords in MEM_PRIVATE regions
        int frames_freed = 0;     // Z = pointer-like qwords in MEM_FREE regions (scrubbed)
        int frames_other = 0;     // W = vq failed / MEM_IMAGE not in module map / unknown type
        int frames_skipped = 0;   // S = non-pointer qwords, excluded from P
        std::vector<std::wstring> module_tags;
        std::vector<std::wstring> frame_res;
        std::vector<ULONG_PTR> frame_addrs;
        std::vector<bool> frame_in_module;

        for (int s = 0; s < samples_taken; ++s)
        {
            const SYSCALL_SAMPLE & samp = ExecTelemetry->SyscallSamples[slot];
            slot = (slot + SYSCALL_SAMPLE_COUNT - 1) % SYSCALL_SAMPLE_COUNT; // walk backwards (older)

            // The 8 stack qwords were captured AT SYSCALL TIME into samp.Frames[8] by the emitted
            // sampler. They live in the payload's persistent data section (survives to verify time),
            // so no ReadProcessMemory is needed -- the shell stack is already released by now.
            for (int i = 0; i < 8; ++i)
            {
                std::wstring res;
                bool in_module = false;

                if (!looks_like_pointer(samp.Frames[i]))
                {
                    // Small integer / non-canonical value: a saved register or argument, not a
                    // return address. Report it, but keep it out of the denominator.
                    LOG(0, L"  [FRAME] sample=%d tid=%u cycle=0x%016llX i=%d addr=0x%016llX resolution=not-a-pointer\n",
                        s, static_cast<unsigned>(samp.ThreadId), static_cast<unsigned long long>(samp.CycleCount),
                        i, static_cast<unsigned long long>(samp.Frames[i]));
                    LOG(0, L"         record: rsp=0x%016llX funcId=%u (remote stub %u of 4)\n",
                        static_cast<unsigned long long>(samp.Rsp), static_cast<unsigned>(samp.FunctionId),
                        static_cast<unsigned>(samp.FunctionId));
                    ++frames_skipped;
                    continue;
                }

                DWORD frame_state = 0;
                DWORD frame_type = 0;
                ResolveFrame(samp.Frames[i], res, in_module, frame_state, frame_type);

                LOG(0, L"  [FRAME] sample=%d tid=0x%08X cycle=0x%016llX i=%d addr=0x%016llX state=0x%08X type=0x%08X resolution=%ls\n",
                    s, static_cast<unsigned>(samp.ThreadId), static_cast<unsigned long long>(samp.CycleCount),
                    i, static_cast<unsigned long long>(samp.Frames[i]), frame_state, frame_type, res.c_str());

                if (in_module)
                {
                    ++resolved;
                    const std::size_t colon = res.find(L':');
                    module_tags.push_back(res.substr(colon != std::wstring::npos ? colon + 1 : 0));
                }
                else if (res == L"MEM_MAPPED")
                {
                    ++frames_mapped;
                }
                else if (res == L"MEM_PRIVATE")
                {
                    ++frames_private;
                }
                else if (res == L"freed")
                {
                    ++frames_freed;
                }
                else
                {
                    ++frames_other; // vq failed / MEM_IMAGE not in module map / unknown type
                }

                ++total_frames;
                frame_addrs.push_back(samp.Frames[i]);
                frame_res.push_back(res);
                frame_in_module.push_back(in_module);
            }
        }

        LOG(0, L"  [GEOM] Pointer Frames: %d | In Module: %d | MEM_MAPPED: %d | MEM_PRIVATE: %d | Freed: %d | Other: %d | Samples: %d\n",
            total_frames, resolved, frames_mapped, frames_private, frames_freed, frames_other, samples_taken);

        // (3) Print the geometry verdict in the required format (P = total pointer-like qwords).
        if (total_frames == 0)
        {
            LOG(0, L"  %ls[!]%ls VerifyStackSpoofGeometry: No Pointer-Like Frames Captured — Sample May Not Be From A Syscall Return Point\n",
                kYellow, kReset);
        }
        else if (resolved == total_frames)
        {
            std::vector<std::wstring> unique_mods;
            for (const auto & m : module_tags)
            {
                if (std::find(unique_mods.begin(), unique_mods.end(), m) == unique_mods.end())
                {
                    unique_mods.push_back(m);
                }
            }
            std::wstring list;
            for (size_t i = 0; i < unique_mods.size(); ++i)
            {
                if (i) list += L", ";
                list += unique_mods[i];
            }
            LOG(0, L"  %ls[+]%ls VerifyStackSpoofGeometry: %d/%d Frames In Module — %ls\n",
                kGreen, kReset, resolved, total_frames, list.c_str());
        }
        else if (resolved > 0)
        {
            std::wstring fail_desc;
            for (size_t i = 0; i < frame_in_module.size(); ++i)
            {
                if (!frame_in_module[i])
                {
                    if (!fail_desc.empty()) fail_desc += L"; ";
                    fail_desc += std::to_wstring(i);
                    fail_desc += L" At 0x";
                    wchar_t hex[24]{};
                    swprintf(hex, 24, L"%016llX", static_cast<unsigned long long>(frame_addrs[i]));
                    fail_desc += hex;
                    fail_desc += L" Resolved To ";
                    fail_desc += frame_res[i];
                }
            }
            LOG(0, L"  %ls[!]%ls VerifyStackSpoofGeometry: %d/%d Frames In Module — Frames %ls\n",
                kYellow, kReset, resolved, total_frames, fail_desc.c_str());
        }
        else
        {
            LOG(0, L"  %ls[x]%ls VerifyStackSpoofGeometry: 0/%d Frames In Module — Spoof Broken (all pointer frames outside modules)\n",
                kRed, kReset, total_frames);
        }

        // Note: each sample captured RSP at the instant the payload's own emitted stub fired a
        // syscall, so these are genuine payload syscall stacks, not an idle target thread.
        LOG(0, L"  Note: Samples captured RSP at payload-syscall time; geometry is resolved against the target's own mapped modules.\n");
    }

    void StealthVerifyGadgetValidity(StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 7: Verify Gadget Validity (HallWatch)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)buffers;

        void * pool[kMaxGadgetPool];
        const size_t pool_count = ScanSyscallGadgetPool(pool, kMaxGadgetPool);
        if (pool_count == 0)
        {
            LOG(0, L"  %ls[!]%ls Gadget Pool Empty: No 0F 05 Gadgets Found In ntdll (HallWatch Direct Stubs Will Engage)\n", kYellow, kReset);
            return;
        }

        size_t healthy = 0;
        size_t bad = 0;
        for (size_t i = 0; i < pool_count; ++i)
        {
            const BYTE * bytes = ReCa<const BYTE *>(pool[i]);
            if (bytes && bytes[0] == 0x0F && bytes[1] == 0x05)
            {
                ++healthy;
            }
            else
            {
                ++bad;
            }
        }

        if (bad == 0)
        {
            LOG(0, L"  %ls[+]%ls Gadget Pool Valid: %llu/%llu Gadgets Start With 0F 05 (Syscall)\n",
                kGreen, kReset,
                static_cast<unsigned long long>(healthy), static_cast<unsigned long long>(pool_count));
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Gadget Pool: %llu Healthy / %llu Corrupt (First Bytes Not 0F 05)\n",
                kYellow, kReset,
                static_cast<unsigned long long>(healthy), static_cast<unsigned long long>(bad));
        }
    }

    void StealthVerifySpoofRandomization(HANDLE process, HINSTANCE hRemoteBase, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Vector 7: Verify Spoof Randomization...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        (void)process; (void)hRemoteBase;

        void * pool[kMaxGadgetPool];
        const size_t pool_count = ScanSyscallGadgetPool(pool, kMaxGadgetPool);
        if (pool_count <= 1)
        {
            LOG(0, L"  %ls[!]%ls Spoof Randomization Not Demonstrable: Gadget Pool Too Small (Size %llu; Need >= 2)\n",
                kYellow, kReset, static_cast<unsigned long long>(pool_count));
            return;
        }

        SeedGadgetPrng();
        void * pick1 = GadgetPick(pool, pool_count);
        void * pick2 = GadgetPick(pool, pool_count);

        if (pick1 && pick2 && pick1 != pick2)
        {
            LOG(0, L"  %ls[+]%ls Spoof Randomization Active: Two Consecutive Picks Differ (%p -> %p) | Pool Size = %llu\n",
                kGreen, kReset, pick1, pick2, static_cast<unsigned long long>(pool_count));
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Spoof Randomization Inactive: Consecutive Picks Identical (%p) | Pool Size = %llu\n",
                kYellow, kReset, pick1, static_cast<unsigned long long>(pool_count));
        }
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







    struct EncryptedCoreRange
    {
        ULONG_PTR start = 0;
        ULONG_PTR end = 0;
        std::wstring module_name;
        std::wstring section_name;
    };



    bool IsEncryptedCoreSectionName(const char * name)
    {
        if (!name)
        {
            return false;
        }
        char trimmed[9] = { 0 };
        size_t length = 0;
        while (length < 8 && name[length] && name[length] != ' ')
        {
            ++length;
        }
        if (!length)
        {
            return false;
        }
        memcpy(trimmed, name, length);
        return _stricmp(trimmed, ".eid") == 0;
    }




    bool FindEncryptedCoreRange(HANDLE process, const SurveyModule & module, EncryptedCoreRange & out)
    {
        out = EncryptedCoreRange{};
        if (!process || !module.base)
        {
            return false;
        }
        IMAGE_DOS_HEADER dos{};
        SIZE_T done = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(module.base), &dos, sizeof(dos), &done) ||
            done != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
        {
            return false;
        }
        DWORD sig = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(module.base + static_cast<ULONG_PTR>(dos.e_lfanew)),
            &sig, sizeof(sig), &done) || done != sizeof(sig) || sig != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        const ULONG_PTR file_hdr = module.base + static_cast<ULONG_PTR>(dos.e_lfanew) + sizeof(DWORD);
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
            if (!IsEncryptedCoreSectionName(name))
            {
                continue;
            }
            const DWORD extent = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
            if (!extent)
            {
                return false;
            }
            out.start = module.base + sec.VirtualAddress;
            out.end = out.start + extent;
            out.module_name = module.name;
            out.section_name.clear();
            for (const char * c = name; *c; ++c)
            {
                out.section_name.push_back(static_cast<wchar_t>(*c));
            }
            return out.end > out.start;
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



    struct ModuleCensus
    {
        const SurveyModule * module = nullptr;
        bool is_main = false;
        bool has_encrypted_core = false;
        bool sampled = false;

        size_t committed_regions = 0;
        size_t exec_regions = 0;
        size_t noaccess_regions = 0;
        size_t guard_regions = 0;
        size_t core_regions = 0;

        size_t cc_bytes = 0;
        size_t gadget_hits = 0;
        size_t sample_bytes = 0;
        size_t exec_regions_sampled = 0;
        size_t exec_regions_not_sampled = 0;
    };







    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers)
    {
        if (!process || !target_pid)
        {
            return;
        }

        std::vector<SurveyModule> & survey_modules = buffers.survey_modules;
        survey_modules.clear();
        if (!EnumerateRemoteModules(process, survey_modules))
        {
            LOG(0, L"  %ls[!]%ls Target Module List Not Enumerable; Nothing To Survey.\n", kYellow, kReset);
            return;
        }



        ULONG_PTR main_base = 0;
        SIZE_T main_size = 0;
        std::wstring main_name;
        if (!GetRemoteMainModule(process, main_name, main_base, main_size))
        {
            LOG(0, L"  %ls[!]%ls Target Main Module Not Identifiable; Nothing To Survey.\n", kYellow, kReset);
            return;
        }





        constexpr size_t kMaxCoreProbes = 96;
        std::vector<EncryptedCoreRange> cores;
        {
            std::vector<size_t> order(survey_modules.size());
            for (size_t i = 0; i < order.size(); ++i)
            {
                order[i] = i;
            }
            std::sort(order.begin(), order.end(), [&](size_t a, size_t b)
            {
                return survey_modules[a].size > survey_modules[b].size;
            });

            for (size_t probed = 0; probed < order.size() && probed < kMaxCoreProbes; ++probed)
            {
                EncryptedCoreRange core{};
                if (FindEncryptedCoreRange(process, survey_modules[order[probed]], core))
                {
                    cores.push_back(core);
                }
            }
        }

        const SIZE_T max_walk_regions = buffers.survey_max_regions
            ? buffers.survey_max_regions
            : ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_REGIONS").get());
        const SIZE_T max_walk_bytes = (buffers.survey_max_mb
            ? buffers.survey_max_mb
            : ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_MB").get())) * (1u << 20);
        const SIZE_T max_sample_regions = buffers.survey_max_sample_regions
            ? buffers.survey_max_sample_regions
            : ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_SAMPLE_REGIONS").get());

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





        std::vector<ModuleCensus> census(survey_modules.size());
        for (size_t i = 0; i < survey_modules.size(); ++i)
        {
            census[i].module = &survey_modules[i];
            census[i].is_main = (survey_modules[i].base == main_base);
        }
        for (const EncryptedCoreRange & core : cores)
        {
            for (ModuleCensus & entry : census)
            {
                if (entry.module && entry.module->base + entry.module->size > core.start &&
                    core.end > entry.module->base)
                {
                    entry.has_encrypted_core = true;
                    break;
                }
            }
        }


        size_t space_committed = 0;
        size_t space_exec = 0;
        size_t space_noaccess = 0;
        size_t space_guard = 0;
        size_t image_committed = 0;
        size_t image_exec = 0;
        size_t image_noaccess = 0;
        size_t image_guard = 0;
        size_t free_committed = 0;
        size_t free_exec = 0;
        size_t free_noaccess = 0;
        size_t free_guard = 0;
        size_t core_regions = 0;
        size_t core_bytes = 0;
        size_t regions_walked = 0;
        ULONG_PTR walked_bytes = 0;
        size_t regions_total = 0;
        bool walk_capped = false;
        bool walk_aborted = false;
        std::wstring walk_reason;



        ULONG_PTR max_application_address = 0;
        {
            SYSTEM_INFO system_info{};
            GetSystemInfo(&system_info);
            max_application_address = reinterpret_cast<ULONG_PTR>(system_info.lpMaximumApplicationAddress);
            if (!max_application_address)
            {
                max_application_address = 0x00007FFFFFFF0000ULL;
            }
        }





        const auto module_of = [&](ULONG_PTR address) -> ModuleCensus *
        {
            size_t lo = 0;
            size_t hi = census.size();
            while (lo < hi)
            {
                const size_t mid = lo + (hi - lo) / 2;
                ModuleCensus & entry = census[mid];
                if (!entry.module || address < entry.module->base)
                {
                    hi = mid;
                }
                else if (address - entry.module->base >= entry.module->size)
                {
                    lo = mid + 1;
                }
                else
                {
                    return &entry;
                }
            }
            return nullptr;
        };

        const auto in_encrypted_core = [&](ULONG_PTR start, ULONG_PTR end) -> bool
        {
            for (const EncryptedCoreRange & core : cores)
            {
                if (start < core.end && end > core.start)
                {
                    return true;
                }
            }
            return false;
        };

        ULONG_PTR cursor = 0;
        for (;;)
        {
            if (max_walk_regions && regions_total >= max_walk_regions)
            {
                walk_capped = true;
                walk_reason = L"Region Cap";
                break;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) || !mbi.RegionSize)
            {



                if (cursor < max_application_address)
                {
                    walk_aborted = true;
                    walk_reason = L"Query Failed";
                }
                break;
            }

            const ULONG_PTR region_start = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
            const ULONG_PTR region_end = region_start + mbi.RegionSize;
            if (region_end <= cursor)
            {
                walk_aborted = true;
                walk_reason = L"Query Did Not Advance";
                break;
            }

            ++regions_total;

            if (mbi.State == MEM_COMMIT)
            {
                ++space_committed;
                ++regions_walked;
                walked_bytes += mbi.RegionSize;

                ModuleCensus * owner = module_of(region_start);
                const bool in_image = (owner != nullptr);
                const bool in_core = in_encrypted_core(region_start, region_end);

                if (in_core)
                {
                    ++core_regions;
                    core_bytes += mbi.RegionSize;
                    if (owner)
                    {
                        ++owner->core_regions;
                    }
                    cursor = region_end;
                    continue;
                }

                size_t * exec_counter = in_image ? &image_exec : &free_exec;
                size_t * noaccess_counter = in_image ? &image_noaccess : &free_noaccess;
                size_t * guard_counter = in_image ? &image_guard : &free_guard;

                if (mbi.Protect & PAGE_GUARD)
                {
                    ++space_guard;
                    ++(*guard_counter);
                    if (owner)
                    {
                        ++owner->guard_regions;
                    }
                }
                else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
                {
                    ++space_noaccess;
                    ++(*noaccess_counter);
                    if (owner)
                    {
                        ++owner->noaccess_regions;
                    }
                }
                else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                {
                    ++space_exec;
                    ++(*exec_counter);
                    if (owner)
                    {
                        ++owner->exec_regions;
                    }



                    const bool worth_reading = owner && (owner->is_main || owner->has_encrypted_core);
                    if (worth_reading && max_sample_regions &&
                        owner->exec_regions_sampled >= max_sample_regions)
                    {
                        ++owner->exec_regions_not_sampled;
                    }
                    else if (worth_reading)
                    {
                        SIZE_T remaining = mbi.RegionSize;
                        BYTE * addr = reinterpret_cast<BYTE *>(mbi.BaseAddress);
                        size_t region_cc = 0;
                        size_t region_gadgets = 0;
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




                                if (i + 3 < got &&
                                    chunk_buf[i] == 0x48 && chunk_buf[i + 1] == 0x8B &&
                                    chunk_buf[i + 2] == 0x01 && chunk_buf[i + 3] == 0xC3)
                                {
                                    ++region_gadgets;
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
                            owner->cc_bytes += region_cc;
                            owner->gadget_hits += region_gadgets;
                            owner->sample_bytes += region_read;
                            ++owner->exec_regions_sampled;
                            owner->sampled = true;
                        }
                    }
                }

                if (owner)
                {
                    ++owner->committed_regions;
                    ++image_committed;
                }
                else
                {
                    ++free_committed;
                }
            }

            cursor = region_end;




            if (max_walk_bytes && walked_bytes > max_walk_bytes)
            {
                walk_capped = true;
                walk_reason = L"Walk Cap";
                break;
            }
        }






        if (!buffers.pre_load_modules.empty())
        {
            std::vector<std::wstring> appeared;
            for (const SurveyModule & module : survey_modules)
            {
                bool known = false;
                for (const std::wstring & before : buffers.pre_load_modules)
                {
                    if (_wcsicmp(before.c_str(), module.name.c_str()) == 0)
                    {
                        known = true;
                        break;
                    }
                }
                if (!known)
                {
                    appeared.push_back(module.name);
                }
            }

            if (appeared.empty())
            {
                LOG(0, L"  %ls[+]%ls Loader-List Delta.......... +0 Module(s) Since Selection (All Dependencies Were Preloaded; The Loader List Is Unchanged)\n",
                    kGreen, kReset);
            }
            else
            {
                std::wstring joined;
                for (size_t i = 0; i < appeared.size() && i < 8; ++i)
                {
                    if (i)
                    {
                        joined += L", ";
                    }
                    joined += appeared[i];
                }
                if (appeared.size() > 8)
                {
                    joined += L", ...";
                }
                LOG(0, L"  %ls[!]%ls Loader-List Delta.......... +%zu Module(s) Since Selection (Loaded By The Shell; Visible To A Module-List Diff): %ls\n",
                    kYellow, kReset, appeared.size(), joined.c_str());
            }
        }
        else
        {
            LOG(0, L"  %ls[*]%ls Loader-List Delta.......... No Pre-Load Baseline (Delta Not Computable This Run)\n",
                kDim, kReset);
        }



        LOG(0, L"  %lsScope%ls  %ls%zu%ls Module(s) Loaded | Main Image = %ls%ls%ls @ %p | %ls%zu%ls KB\n",
            kDim, kReset,
            kGreen, survey_modules.size(), kReset,
            kGreen, main_name.c_str(), kReset, reinterpret_cast<void *>(main_base),
            kGreen, static_cast<size_t>(main_size / 1024), kReset);

        LOG(0, L"  %lsWalk%ls    %ls%zu%ls Committed Region(s) Walked (%ls%zu%ls MB) | %ls%zu%ls Guard | %ls%zu%ls No-Access | %ls%zu%ls Executable\n",
            kDim, kReset,
            kGreen, regions_walked, kReset,
            kGreen, static_cast<size_t>(walked_bytes / (1024 * 1024)), kReset,
            kGreen, space_guard, kReset,
            kGreen, space_noaccess, kReset,
            kGreen, space_exec, kReset);

        LOG(0, L"  %lsBy Range%ls  Inside Module Images.. Guard %ls%zu%ls | No-Access %ls%zu%ls | Executable %ls%zu%ls | Committed %ls%zu%ls\n",
            kDim, kReset,
            kGreen, image_guard, kReset,
            kGreen, image_noaccess, kReset,
            kGreen, image_exec, kReset,
            kGreen, image_committed, kReset);

        LOG(0, L"  %lsBy Range%ls  Free Address Space.... Guard %ls%zu%ls | No-Access %ls%zu%ls | Executable %ls%zu%ls | Committed %ls%zu%ls\n",
            kDim, kReset,
            kGreen, free_guard, kReset,
            kGreen, free_noaccess, kReset,
            kGreen, free_exec, kReset,
            kGreen, free_committed, kReset);

        if (core_regions)
        {
            LOG(0, L"  %lsEncrypted%ls %ls%zu%ls Region(s) / %ls%zu%ls KB Inside A Loader's Encrypted Core - Never Read\n",
                kDim, kReset,
                kGreen, core_regions, kReset,
                kGreen, static_cast<size_t>(core_bytes / 1024), kReset);
            for (const EncryptedCoreRange & core : cores)
            {
                LOG(0, L"           %ls%ls%ls -> %ls%ls%ls @ %p..%p\n",
                    kDim, core.module_name.c_str(), kReset,
                    kGreen, core.section_name.c_str(), kReset,
                    reinterpret_cast<void *>(core.start), reinterpret_cast<void *>(core.end));
            }
        }

        LOG(0, L"\n");

        for (const ModuleCensus & entry : census)
        {
            if (!entry.module)
            {
                continue;
            }

            const bool interesting = entry.is_main || entry.has_encrypted_core;
            if (!interesting)
            {
                continue;
            }

            const wchar_t * role = entry.is_main ? L"Main Image" : L"Encrypted-Core Carrier";

            LOG(0, L"  %ls%ls%ls  (%ls)\n", StageField(entry.module->name, 24).c_str(), kGreen, kReset, role);
            LOG(0, L"      %ls%ls%zu%ls Committed | %ls%zu%ls Executable | %ls%zu%ls No-Access | %ls%zu%ls Guard | %ls%zu%ls Encrypted-Core\n",
                StageField(L"Regions:", 12).c_str(),
                kGreen, entry.committed_regions, kReset,
                kGreen, entry.exec_regions, kReset,
                kGreen, entry.noaccess_regions, kReset,
                kGreen, entry.guard_regions, kReset,
                kGreen, entry.core_regions, kReset);

            if (entry.sample_bytes)
            {
                const size_t cc_pct = (entry.cc_bytes * 100) / entry.sample_bytes;
                LOG(0, L"      %ls%ls%zu%ls Of %ls%zu%ls Sampled Bytes Are INT3 (%ls0xCC%ls), %ls%zu%s%%, From %ls%zu%ls Of %ls%zu%ls Executable Region(s)\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, entry.cc_bytes, kReset,
                    kGreen, entry.sample_bytes, kReset,
                    kGreen, kReset,
                    kGreen, cc_pct, kReset,
                    kGreen, entry.exec_regions_sampled, kReset, kGreen, entry.exec_regions, kReset);
                LOG(0, L"      %ls%ls%zu%ls Hit(s) In The Sampled Executable Region(s) (The Demand-Paging Touch Gadget; A Non-Zero Count Is The Lead For Watching A No-Access Page Turn Readable)\n",
                    StageField(L"Gadget:", 12).c_str(),
                    entry.gadget_hits ? kYellow : kGreen, entry.gadget_hits, kReset);
                LOG(0, L"      %ls%lsThis Module's Image Range Only%ls\n",
                    StageField(L"Scope:", 12).c_str(), kDim, kReset);
            }
            else
            {
                LOG(0, L"      %lsNo Executable Region Of This Module Was Readable\n",
                    StageField(L"INT3:", 12).c_str());
            }





            if (entry.has_encrypted_core && !entry.is_main && process)
            {
                BYTE loader_dos[sizeof(IMAGE_DOS_HEADER)]{};
                SIZE_T got = 0;
                if (ReadProcessMemory(process, ReCa<LPCVOID>(entry.module->base), loader_dos, sizeof(loader_dos), &got) && got == sizeof(loader_dos))
                {
                    const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(loader_dos);
                    if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x10000)
                    {
                        BYTE loader_nt_buf[sizeof(IMAGE_NT_HEADERS64)]{};
                        if (ReadProcessMemory(process, ReCa<BYTE *>(entry.module->base) + dos->e_lfanew, loader_nt_buf, sizeof(loader_nt_buf), &got) && got == sizeof(loader_nt_buf))
                        {
                            const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(loader_nt_buf);
                            if (nt->Signature == IMAGE_NT_SIGNATURE)
                            {
                                const ULONGLONG base = entry.module->base;
                                const ULONGLONG image_end = base + nt->OptionalHeader.SizeOfImage;

                                {
                                    const IMAGE_DATA_DIRECTORY & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                                    size_t descriptors = 0;
                                    wchar_t first_name[64]{};
                                    bool name_read = false;
                                    if (dir.VirtualAddress && dir.VirtualAddress < nt->OptionalHeader.SizeOfImage)
                                    {
                                        IMAGE_IMPORT_DESCRIPTOR desc{};
                                        for (DWORD walk = 0; walk < 128; ++walk)
                                        {
                                            const ULONGLONG at = base + dir.VirtualAddress + static_cast<ULONGLONG>(walk) * sizeof(desc);
                                            if (!ReadProcessMemory(process, ReCa<LPCVOID>(at), &desc, sizeof(desc), &got) || got != sizeof(desc) || !desc.Name)
                                            {
                                                break;
                                            }
                                            ++descriptors;
                                            if (descriptors == 1 && desc.Name < nt->OptionalHeader.SizeOfImage)
                                            {
                                                char narrow[64]{};
                                                if (ReadProcessMemory(process, ReCa<LPCVOID>(base + desc.Name), narrow, sizeof(narrow) - 1, &got) && got)
                                                {
                                                    narrow[got < sizeof(narrow) - 1 ? got : sizeof(narrow) - 1] = '\0';
                                                    MultiByteToWideChar(CP_UTF8, 0, narrow, -1, first_name, 64);
                                                    name_read = first_name[0] != L'\0';
                                                }
                                            }
                                            if (desc.Characteristics == 0 && desc.FirstThunk == 0 && desc.ForwarderChain == 0 && desc.TimeDateStamp == 0)
                                            {
                                                break;
                                            }
                                        }
                                    }
                                    LOG(0, L"      %ls%ls%zu%ls Descriptor(s)%ls%ls\n",
                                        StageField(L"Imports:", 12).c_str(),
                                        kGreen, descriptors, kReset,
                                        name_read ? L" | First: " : L"",
                                        name_read ? first_name : L"");
                                }

                                {
                                    const IMAGE_DATA_DIRECTORY & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                                    size_t callbacks = 0;
                                    bool counted = false;
                                    if (dir.VirtualAddress && dir.Size >= sizeof(IMAGE_TLS_DIRECTORY64) &&
                                        dir.VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY64) <= nt->OptionalHeader.SizeOfImage)
                                    {
                                        IMAGE_TLS_DIRECTORY64 tls{};
                                        if (ReadProcessMemory(process, ReCa<LPCVOID>(base + dir.VirtualAddress), &tls, sizeof(tls), &got) && got == sizeof(tls) && tls.AddressOfCallBacks)
                                        {
                                            counted = true;
                                            if (tls.AddressOfCallBacks >= base && tls.AddressOfCallBacks < image_end)
                                            {
                                                ULONGLONG array_buf[64]{};
                                                const SIZE_T span = static_cast<SIZE_T>(image_end - tls.AddressOfCallBacks);
                                                const SIZE_T want = (sizeof(array_buf) < span) ? sizeof(array_buf) : span;
                                                if (ReadProcessMemory(process, ReCa<LPCVOID>(tls.AddressOfCallBacks), array_buf, want, &got) && got)
                                                {
                                                    for (size_t i = 0; i < got / sizeof(ULONGLONG); ++i)
                                                    {
                                                        if (array_buf[i] == 0 || array_buf[i] == 0xFFFFFFFF)
                                                        {
                                                            break;
                                                        }
                                                        ++callbacks;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    LOG(0, L"      %ls%ls%ls%ls\n",
                                        StageField(L"TLS:", 12).c_str(),
                                        kGreen,
                                        counted ? (callbacks ? std::to_wstring(callbacks).c_str() : L"Directory Present, Zero Callbacks") : L"None (No TLS Directory In Remote Headers)",
                                        kReset);
                                }
                            }
                        }
                    }
                }
            }

            if (entry.exec_regions_not_sampled)
            {
                LOG(0, L"      %ls%ls%zu%ls Of %ls%zu%ls Executable Region(s) Not Sampled (Cap %ls%zu%ls), So The INT3 Count Is A Floor, Not A Total\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, entry.exec_regions_not_sampled, kReset,
                    kGreen, entry.exec_regions, kReset,
                    kGreen, max_sample_regions, kReset);
            }

            LOG(0, L"\n");
        }

        if (walk_capped || walk_aborted)
        {
            wchar_t reason[192]{};
            if (walk_capped && !walk_reason.empty())
            {
                swprintf_s(reason, L"%ls", walk_reason.c_str());
            }
            if (walk_aborted)
            {
                if (reason[0])
                {
                    wcscat_s(reason, L" / ");
                }
                wcscat_s(reason, L"Query Failed Before The End Of The Address Space");
            }
            LOG(0, L"  %ls[!]%ls Region Walk Stopped Early (%ls); Counts Are Partial\n",
                kYellow, kReset, reason[0] ? reason : L"Unknown Reason");
        }
    }


}
