#include "PCH.h"

#include "Launcher.h"

// Process inspection and the reporting that sits on top of it.
//
// The launcher needs to identify processes, and the launch transcript needs to
// name the donor processes behind an acquired handle. Both live here so the two
// halves of the tool agree on how a process is identified.

namespace
{
    // Reads the target's architecture through IsWow64Process2 when it is
    // available, falling back to IsWow64Process on builds that predate it.
    Architecture ProcessArchitecture(HANDLE process)
    {
        using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
        auto k32_name = XOR_STR_W(L"kernel32.dll");
        HMODULE k32_mod = GetModuleHandleW(k32_name.get());
        IsWow64Process2Fn is_wow64_process2 = nullptr;
        if (k32_mod)
        {
            auto wow_name = XOR_STR_A("IsWow64Process2");
            is_wow64_process2 = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(k32_mod, wow_name.get()));
        }
        if (is_wow64_process2)
        {
            USHORT process_machine = 0;
            USHORT native_machine = 0;
            if (is_wow64_process2(process, &process_machine, &native_machine))
            {
                if (process_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
                if (native_machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    return Architecture::X64;
                }
                if (native_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
            }
        }

        BOOL is_wow64 = FALSE;
        if (IsWow64Process(process, &is_wow64) && is_wow64)
        {
            return Architecture::X86;
        }

        SYSTEM_INFO system_info{};
        GetNativeSystemInfo(&system_info);
        return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? Architecture::X64 : Architecture::X86;
    }
}  // namespace

// Opens the process read-only and takes both its image name and its
// architecture from the same handle, so the two cannot disagree.
bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
    {
        return false;
    }

    wchar_t path[MAX_PATH * 2]{};
    DWORD length = static_cast<DWORD>(std::size(path));
    const BOOL queried = QueryFullProcessImageNameW(process, 0, path, &length);
    architecture = ProcessArchitecture(process);
    CloseHandle(process);
    if (!queried)
    {
        return false;
    }

    const std::wstring full_path(path, length);
    const size_t slash = full_path.find_last_of(L"\\/");
    name = slash == std::wstring::npos ? full_path : full_path.substr(slash + 1);
    return !name.empty();
}

// The fixed-buffer form used where a std::wstring would be wasted work, such as
// naming a donor process while walking a handle table.
bool QueryProcessFixed(DWORD pid, wchar_t * name_out, size_t name_count, Architecture & architecture)
{
    if (!name_out || name_count == 0)
    {
        return false;
    }

    name_out[0] = L'\0';
    std::wstring name;
    if (!QueryProcess(pid, name, architecture) || name.empty())
    {
        return false;
    }
    if (name.size() >= name_count)
    {
        return false;
    }
    name.copy(name_out, name.size());
    name_out[name.size()] = L'\0';
    return true;
}

// The reported name of the process that owned the handle before it was
// duplicated. An unreadable name leaves the buffer empty, which the callers
// render as a bare PID.
void DescribeDonor(DWORD Pid, wchar_t * NameOut, size_t NameCount)
{
    if (!NameOut || NameCount == 0)
    {
        return;
    }

    NameOut[0] = L'\0';
    if (!Pid)
    {
        return;
    }
    Architecture Arch = Architecture::Unknown;
    QueryProcessFixed(Pid, NameOut, NameCount, Arch);
}

// The stage-by-stage account of how a process or thread handle was acquired.
// It is only worth printing when the acquisition was configured and the runtime
// reported telemetry, so both of those are checked first.
void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread)
{
    if (!Stats || !Stats->Attempted)
    {
        LOG(0, L"  %ls[!]%ls %ls Handle: No Telemetry (Older Runtime?).\n", kYellow, kReset, Kind);
        return;
    }

    const bool SponsorUsed = Stats->Success && Stats->Source == static_cast<DWORD>(HijackSource::Sponsor);

    wchar_t Text[256]{ 0 };

    LOG(0, L"  %ls Acquisition Trace:\n\n", Kind);

    int Stage = 0;
    const bool target_known = Context && !Context->TargetName.empty();
    LOG(0, L"    %ls %ls %ls%ls%ls | PID = %ls%lu%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Target").c_str(),
        target_known ? kGreen : kYellow,
        target_known ? Context->TargetName.c_str() : L"unknown", kReset,
        kGreen, Context ? Context->TargetPid : 0, kReset);

    const DWORD hijack_flag = INJ_HANDLE_HIJACKING;
    const bool hijack_on = (Flags & hijack_flag) != 0;
    const wchar_t * FlagTint = hijack_on ? kGreen : kYellow;
    LOG(0, L"    %ls %ls %ls%s%ls (%ls0x%04X%s In Flags %ls0x%08X%s)\n", StageTag(++Stage).c_str(),
        StageLabel(L"Config Flag").c_str(),
        FlagTint, hijack_on ? L"Y" : L"N", kReset,
        FlagTint, hijack_flag, kReset,
        FlagTint, Flags, kReset);

    // SeDebugPrivilege is only a lever for the launcher when it is the one
    // opening the handle; for a thread hijack the runtime does the work from
    // inside the target, so the launcher's token is irrelevant.
    if (!IsThread)
    {
        LOG(0, XOR_STR_W(L"    %ls %ls SeDebugPrivilege %ls%s%ls\n").get(), StageTag(++Stage).c_str(), StageLabel(L"Privilege").c_str(),
            kDim, L"Not Required (Runtime-Side Acquisition)", kReset);
    }

    if (IsThread && Context && Context->SponsorThreadOpened)
    {
        LOG(0, L"    %ls %ls %ls0x%08X%ls Pre-Opened, TID %ls0x%04X%ls\n", StageTag(++Stage).c_str(),
            StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorThreadValue), kReset,
            kGreen, Context->SponsorTid, kReset);
    }
    else if (IsThread && Context && Context->SponsorThreadAttempted)
    {
        LOG(0, L"    %ls %ls %lsFailed%ls (No Valid TID)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Sponsor").c_str(), kRed, kReset);
    }
    else if (IsThread)
    {
        LOG(0, L"    %ls %ls %lsNot Attempted%ls\n", StageTag(++Stage).c_str(),
            StageLabel(L"Sponsor").c_str(), kYellow, kReset);
    }
    else
    {
        LOG(0, L"    %ls %ls %lsNone%ls (Donor Scan Only)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Sponsor").c_str(), kYellow, kReset);
    }

    if (SponsorUsed)
    {
        LOG(0, L"    %ls %ls %lsNot Required%ls (Sponsor Satisfied Acquisition)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Scan").c_str(), kYellow, kReset);
    }
    else
    {
        LOG(0, L"    %ls %ls Status %ls0x%08X%ls, %ls%lu%ls Handles\n", StageTag(++Stage).c_str(),
            StageLabel(L"Enumeration").c_str(),
            Stats->SnapStatus == 0 ? kGreen : kYellow, Stats->SnapStatus, kReset,
            kGreen, Stats->TotalHandles, kReset);

        LOG(0, L"    %ls %ls %ls%s%ls (%ls)\n", StageTag(++Stage).c_str(), StageLabel(L"Calibration").c_str(),
            Stats->Calibrated ? kGreen : kYellow,
            Stats->Calibrated ? L"Self-Calibrated" : L"Uncalibrated", kReset,
            Stats->Calibrated ? L"Filtered Scan" : L"Unfiltered Scan");

        LOG(0, L"    %ls %ls Examined %ls%lu%ls Of %ls%lu%ls, Owners %ls%lu%ls, Dup-Denied %ls%lu%ls, Verify-Rejected %ls%lu%ls, Budget-Skipped %ls%lu%ls\n",
            StageTag(++Stage).c_str(), StageLabel(L"Scan").c_str(),
            kGreen, Stats->Examined, kReset, kGreen, Stats->TotalHandles, kReset,
            kGreen, Stats->OwnersOpened, kReset, kGreen, Stats->DupDenied, kReset,
            kGreen, Stats->VerifyRejected, kReset, kGreen, Stats->BudgetSkipped, kReset);
        LOG(0, L"    %ls %ls Snapshot %ls%u%ls Bytes | Probe Method %ls%u%ls (0 = None, 1 = Reserve, 2 = Protect, 3 = Roundtrip)\n",
            StageTag(++Stage).c_str(), StageLabel(L"Snapshot").c_str(),
            kGreen, Stats->SnapshotBytes, kReset, kGreen, Stats->ProbeMethod, kReset);
    }

    // The donor is named when it can be read; a PID with no name is still
    // enough to correlate against a process list afterwards.
    if (Stats->Success && Stats->DonorPid)
    {
        wchar_t Donor[MAX_PATH * 2]{ 0 };
        DescribeDonor(Stats->DonorPid, Donor, _countof(Donor));
        if (Donor[0])
        {
            LOG(0, L"    %ls %ls %ls%s%ls (PID %ls%lu%ls), Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Donor Owner").c_str(), kGreen, Donor, kReset,
                kGreen, Stats->DonorPid, kReset,
                kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
        }
        else
        {
            LOG(0, L"    %ls %ls PID %ls%lu%ls, Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Donor Owner").c_str(),
                kGreen, Stats->DonorPid, kReset,
                kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
        }
    }
    else
    {
        LOG(0, L"    %ls %ls %lsNone%ls Qualifying\n", StageTag(++Stage).c_str(),
            StageLabel(L"Donor owner").c_str(), kYellow, kReset);
    }

    if (Stats->Success)
    {
        if (Stats->Source == static_cast<DWORD>(HijackSource::Sponsor))
        {
            swprintf_s(Text, L"Sponsor");
        }
        else
        {
            swprintf_s(Text, L"Donor Scan");
        }
        LOG(0, L"    %ls %ls %ls%s%ls, Granted %ls0x%08X%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Result").c_str(),
            kGreen, Text, kReset, kGreen, Stats->GrantedAccess, kReset);
    }
    else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
    {
        LOG(0, L"    %ls %ls %lsDirect Open%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Result").c_str(), kYellow, kReset, kYellow, Stats->FailCode, kReset);
    }
    else
    {
        LOG(0, L"    %ls %ls %lsFailed%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Result").c_str(), kRed, kReset, kRed, Stats->FailCode, kReset);
    }

    // An unused sponsor TID is worth calling out: it explains why a scan
    // fallback ran even though the sponsor path was configured.
    if (IsThread && Context && Context->SponsorTid && Context->UsedTid
        && Context->UsedTid != Context->SponsorTid && Stats->Success
        && Stats->Source != static_cast<DWORD>(HijackSource::Sponsor))
    {
        LOG(0, L"    %ls %ls Sponsor TID %ls0x%04lX%ls %lsNot Usable%ls; Hijacked TID %ls0x%04lX%ls\n",
            StageTag(++Stage).c_str(), StageLabel(L"Fallback").c_str(),
            kGreen, static_cast<unsigned long>(Context->SponsorTid), kReset,
            kYellow, kReset,
            kGreen, static_cast<unsigned long>(Context->UsedTid), kReset);
    }
}

// The one-line form of the same result, used where the full trace would drown
// the rest of the report.
void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats)
{
    if (!Stats || !Stats->Attempted)
    {
        LOG(0, L"  %ls[!]%ls %ls Handle: No Telemetry (Older Runtime?).\n", kYellow, kReset, Kind);
        return;
    }

    if (Stats->Success)
    {
        const wchar_t * SourceText = Stats->Source == static_cast<DWORD>(HijackSource::Sponsor) ? L"Sponsor"
            : Stats->Source == static_cast<DWORD>(HijackSource::Scan) ? L"Scan" : L"Direct";
        LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %ls%s%ls (%ls0x%08X%ls)\n", kGreen, kReset, Kind,
            kGreen, SourceText, kReset, kGreen, Stats->NewHandle, kReset);
    }
    else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
    {
        LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %lsDirect%s (Code %ls0x%08X%ls)\n", kGreen, kReset, Kind,
            kYellow, kReset, kYellow, Stats->FailCode, kReset);
    }
    else
    {
        LOG(0, L"  %ls[!]%ls %ls Handle Failed (Code %ls0x%08X%ls)\n", kYellow, kReset, Kind,
            kYellow, Stats->FailCode, kReset);
    }
}
