#pragma once

// Shared declarations for the launcher.
//
// The launcher is split across several translation units. Everything that more
// than one of them needs lives here; everything else stays local to the unit
// that owns it.

#include "PCH.h"

#include <cstdarg>
#include <cstdio>

#include "../../Ameger/Injection.h"
#include "../../Ameger/Core/Foundation/Error.h"
#include "../../Ameger/Core/Foundation/Primitives/ResourceGuard.h"
#include "../../Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "../../Ameger/Core/Utility/Binary/PEImage.h"
#include "../../Ameger/NT/NTDefinitions.h"

// The launcher decrypts the deployed configuration with DPAPI and hashes the
// runtime image with CNG, so both import libraries are linked from here.
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

#pragma region console colours

// The console tints are real ANSI sequences. They are only ever written to a
// real console (UiLog checks the console mode before it prints), and the
// on-disk transcript is written with the escapes stripped. When the host
// console cannot render VT sequences, UiLog strips them from the stream too,
// so a redirected or legacy console never shows escape bytes.
inline constexpr wchar_t kReset[] = L"\x1b[0m";
inline constexpr wchar_t kGreen[] = L"\x1b[92m";
inline constexpr wchar_t kRed[] = L"\x1b[91m";
inline constexpr wchar_t kYellow[] = L"\x1b[93m";
inline constexpr wchar_t kDim[] = L"\x1b[90m";
inline constexpr wchar_t kCyan[] = L"\x1b[96m";

#pragma endregion

#pragma region console output

int UiLog(int indent, const wchar_t * format, ...);

#undef LOG
#define LOG UiLog

// The result log keeps a rolling transcript of everything the launcher printed,
// so a run that ended badly can still be inspected afterwards. The transcript
// is written as the run goes rather than assembled at the end, so the record
// exists even when the process does not reach its own exit path.
namespace ameger_ui_log
{
    void AppendStripped(const wchar_t * text);
    void AppendClean(const wchar_t * text);
    std::wstring ResultLogPath();
    void ResetResultLog();
    bool BeginResultLog(const wchar_t * header);
    void FlushResultLog();
    void WriteResultLog();
    void DiscardResultLog();
    void Clear();
}

// The name of the transcript file next to the launcher. It is derived from the
// launcher name so a renamed build does not overwrite an older transcript.
inline std::wstring g_ResultLogName;

#pragma endregion

#pragma region shared types

enum class Architecture
{
    Unknown,
    X86,
    X64
};

struct MemoryInjectionData
{
    BYTE * RawData;
    DWORD RawSize;
    DWORD ProcessID;
    DWORD Flags;
    DWORD Timeout;
    ULONG_PTR hHandleValue;
    HINSTANCE hDllOut;
    bool GenerateErrorLog;
    DWORD TargetTid;
    ULONG_PTR hThreadHandleValue;
    const wchar_t * DllPath;
};

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

struct Runtime
{
    HMODULE module = nullptr;
    f_Memory_Inject memory_inject = nullptr;
    f_GetSymbolState get_symbol_state = nullptr;
    f_GetImportState get_import_state = nullptr;
    f_InitializeRuntime initialize_runtime = nullptr;
    f_ShutdownRuntime shutdown_runtime = nullptr;
    f_StartDownload start_download = nullptr;
    f_SetRawPrintCallback set_raw_print_callback = nullptr;
    f_GetLastHijackStats get_last_hijack_stats = nullptr;
    f_GetLastMapStats get_last_map_stats = nullptr;
    f_GetLastStringStats get_last_string_stats = nullptr;
    f_GetLastThreadExecStats get_last_thread_exec_stats = nullptr;
    f_GetLastExecTelemetry get_last_exec_telemetry = nullptr;
    f_GetRuntimeAbiVersion get_runtime_abi_version = nullptr;
    f_GetLastErrorInfo get_last_error_info = nullptr;
    f_ClearLastErrorInfo clear_last_error_info = nullptr;
};

struct FileInformation
{
    Architecture architecture = Architecture::Unknown;
    bool dotnet = false;
};

// Everything that pins one running process down to one specific instance.
// A name is not an identity: a game can exit and be relaunched between the
// moment the operator confirms it and the moment the payload is written.
//
// The loader list is a three-way answer. A process that has one can be
// mapped into; a process whose PEB reports no list at all has not been set
// up by the loader and cannot; and a process whose PEB cannot be read might
// be either, so it is left for the direct write probe to decide rather than
// being written off.
enum class LoaderListState
{
    Unknown,
    Published,
    NotPublished
};

struct ProcessIdentity
{
    DWORD pid = 0;
    std::wstring name;        // leaf name
    std::wstring full_path;   // full image path
    ULONGLONG creation_time = 0;  // FILETIME, as a 64-bit value
    Architecture architecture = Architecture::Unknown;
    LoaderListState loader_list_state = LoaderListState::Unknown;

    // A process is only ruled out when the loader list is known to be absent.
    bool LoaderListAvailable() const
    {
        return loader_list_state != LoaderListState::NotPublished;
    }

    bool Matches(const ProcessIdentity & other) const
    {
        if (!pid || !other.pid || pid != other.pid)
        {
            return false;
        }
        if (creation_time && other.creation_time && creation_time != other.creation_time)
        {
            return false;
        }
        if (!full_path.empty() && !other.full_path.empty() &&
            _wcsicmp(full_path.c_str(), other.full_path.c_str()) != 0)
        {
            return false;
        }
        return true;
    }
};

struct TargetSelection
{
    DWORD pid = 0;
    std::wstring requested_name;
    std::wstring name;
    Architecture architecture = Architecture::Unknown;
    bool by_name = false;
    // The identity of the process the operator actually confirmed. The
    // launcher re-resolves a name-based target before the load, and without
    // this the confirmation would apply to a different process than the one
    // that ends up being written to.
    ProcessIdentity identity;
};

struct ExportNameMap
{
    std::string old_name;
    std::string new_name;
};

struct WizardConfig
{
    int schema_version = 0;
    bool handle_hijacking = true;
    bool hijack_scan = true;
    bool sponsor_roundtrip = true;
    bool verbose_trace = true;

    bool quiet = false;

    bool detach_console = false;
    bool test_mode = false;
    bool run_dllmain = true;
    bool page_protections = true;
    bool loader_lock = true;
    bool exceptions = true;
    bool resolve_imports = true;
    bool security_cookie = true;
    bool delay_imports = true;
    bool clean_data = true;
    bool execute_tls = true;
    int timeout = 60000;

    // The launcher always runs elevated, and an elevated process is started
    // with a fresh environment rather than the one its parent had. Every
    // tuning knob therefore lives in the configuration file, which is read
    // after the elevation, and not in an environment variable.
    //
    // The transcript of a run is always written. Removing it is something
    // that has to be asked for, and it is only ever asked for after a
    // successful run.
    // The transcript of a run is always written while the run is going, so a
    // crash still leaves its record. Whether a *successful* run's transcript
    // is kept afterwards is the operator's call, and the standing choice is
    // to keep it: the record of a successful load is the one worth having.
    // Removing it has to be asked for explicitly in the configuration; a
    // failed or cancelled run always keeps its transcript regardless.
    bool discard_result_log_on_success = false;
    // Whether the "begin load?" confirmation is answered for the operator.
    // It lives here rather than in an environment variable because the
    // launcher runs elevated, and an elevated process does not inherit its
    // parent's environment.
    bool auto_confirm = false;
    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;
    std::wstring donor_owner_blocklist;
    // The image the test run points at. It defaults to notepad, which is
    // harmless and always present.
    std::wstring test_target = L"notepad.exe";

    std::wstring target_name;
    std::wstring expected_payload_sha256;

    std::wstring payload_name;
    std::wstring runtime_name;
    std::vector<ExportNameMap> export_map;

    std::wstring dll_dir = L"DLLs";
};

// Everything the launcher learned about the donor handles of the last attempt.
struct HijackContext
{
    DWORD TargetPid = 0;
    std::wstring TargetName;
    bool SponsorThreadAttempted = false;
    bool SponsorThreadOpened = false;
    ULONG_PTR SponsorThreadValue = 0;
    DWORD SponsorTid = 0;

    DWORD UsedTid = 0;
    bool Verbose = true;
};

#pragma endregion

#pragma region stage formatting

inline std::wstring StageLabel(const wchar_t * label, size_t width = 20)
{
    std::wstring text(label ? label : L"");
    while (text.size() < width)
    {
        text += L'.';
    }
    return text;
}

inline std::wstring StageField(const wchar_t * label, size_t width = 20)
{
    return StageLabel(label, width) + L" ";
}

inline std::wstring StageField(const std::wstring & label, size_t width = 20)
{
    return StageLabel(label.c_str(), width) + L" ";
}

inline std::wstring StageTag(int stage)
{
    wchar_t num[16]{ 0 };
    swprintf_s(num, L"%d", stage);
    return std::wstring(L"[") + kGreen + num + kReset + L"]";
}

#pragma endregion

// The number of encrypted-string markers the build plants in the runtime DLL.
// The verification suite counts how many of them survived into the mapped image
// and asserts the count against this value, so the two must move together.
constexpr size_t kStringMarkerCount = 31;
#pragma region shared helpers

// Whether the launcher should print the runtime's own trace output. The runtime
// asks for it through a callback, so the decision is made in one place.
inline bool VerboseOutputEnabled()
{
    static const bool verbose = []()
    {
        wchar_t buffer[8] = {};

        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_VERBOSE").get(), buffer, 4);
        return !(got == 1 && buffer[0] == L'0');
    }();
    return verbose;
}

// Whether the full thread census should be printed. It is expensive and only
// useful while diagnosing a donor selection problem.
inline bool FullThreadCensusEnabled()
{
    static const bool full = []()
    {
        wchar_t buffer[8] = {};

        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_FULL_CENSUS").get(), buffer, 4);
        return got == 1 && buffer[0] == L'1';
    }();
    return full;
}

// Whether an export name is one of the runtime's original names rather than one
// of the permuted names the build assigned to it.
inline bool IsOriginalExportName(const std::vector<ExportNameMap> & map, const char * name)
{
    if (!name)
    {
        return false;
    }
    for (const ExportNameMap & entry : map)
    {
        if (entry.old_name == name)
        {
            return true;
        }
    }
    return false;
}

#pragma endregion

#pragma region process inspection

// Queries the name and the architecture of a running process.
bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture);

// Reads the full identity of a running process: its name, its image path, its
// creation time and its architecture, all from the same handle.
bool QueryProcessIdentity(DWORD pid, ProcessIdentity & out);

// The fixed-buffer form of QueryProcess.
bool QueryProcessFixed(DWORD pid, wchar_t * name_out, size_t name_count, Architecture & architecture);

// Writes the name of a donor process into a caller supplied buffer.
void DescribeDonor(DWORD pid, wchar_t * name_out, size_t name_count);

// The per-handle acquisition trace and summary shown after an injection.
void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread);
void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats);

#pragma endregion

#pragma region stealth verification

struct SurveyModule
{
    std::wstring name;
    ULONG_PTR base = 0;
    SIZE_T size = 0;
};

struct StealthVerifierBuffers
{
    bool runtime_path_known = false;
    std::vector<BYTE> runtime_bytes;
    bool runtime_read = false;

    std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> remote_headers{};
    std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> local_headers{};

    std::vector<ULONG_PTR> allocation_bases;

    std::vector<SurveyModule> survey_modules;
    std::vector<BYTE> survey_chunk;

    // The bounds on the region census. They come from the configuration
    // file, because the launcher runs elevated and an elevated process does
    // not inherit the environment variables its parent had.
    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;

    // B3/A2: the pre-load baseline of the target's loader list and window
    // surface, taken before anything is mapped, so the verification suite
    // reports the delta the load actually left rather than an assertion.
    std::vector<std::wstring> pre_load_modules;
    size_t pre_target_windows = 0;
    size_t pre_target_layered = 0;
};

namespace stealth
{
    // B2: the measured TSC frequency, calibrated against the performance
    // counter; 0.0 when the calibration is unavailable.
    double MeasureTscHz();

    // B3/A2: captures the target's module list and window surface before the
    // load. One transient module snapshot (closed immediately) and one window
    // walk; the suite takes the same measurements again afterwards and the
    // report shows the delta.
    bool CapturePreLoadBaseline(DWORD pid, StealthVerifierBuffers & buffers);

    // Runs the post-injection verification suite. Returns true only when every
    // enabled check passed; a fault inside the verifier is caught and reported as
    // a failure rather than being allowed to escape.
    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers);

    // The protection constant behind an image page, as a printable name.
    const wchar_t * StealthPageDesc(DWORD p);

    // What the target's vectored exception handling looks like from the outside:
    // whether the chains cross the process boundary and whether the PEB flags
    // that feed anti-debug checks are still at their defaults.
    struct VehFirstChanceSurvey
    {
        bool handleValid = false;
        bool readOk = false;
        ULONG crossFlags = 0;
        bool usingVeh = false;
        bool usingVch = false;
        BYTE beingDebugged = 0;
        ULONG ntGlobalFlag = 0;
        PVOID pebAddress = nullptr;
        // The image base the target itself is running from. The module list is
        // walked in load order, so the PEB is the only reliable way to say
        // which entry is the main image and which is a dependency.
        ULONG_PTR imageBase = 0;
        DWORD lastError = 0;
    };

    // Reads the target's exception-chain state through its PEB.
    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
}

#pragma endregion
