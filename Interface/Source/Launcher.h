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

inline constexpr wchar_t kReset[] = L"";
inline constexpr wchar_t kGreen[] = L"";
inline constexpr wchar_t kRed[] = L"";
inline constexpr wchar_t kYellow[] = L"";
inline constexpr wchar_t kDim[] = L"";
inline constexpr wchar_t kCyan[] = L"";

#pragma endregion

#pragma region console output

int UiLog(int indent, const wchar_t * format, ...);

#undef LOG
#define LOG UiLog

// The result log keeps a rolling transcript of everything the launcher printed,
// so a run that ended badly can still be inspected afterwards.
namespace ameger_ui_log
{
    void AppendStripped(const wchar_t * text);
    std::wstring Snapshot();
    std::wstring ResultLogPath();
    void ResetResultLog();
    void WriteResultLog();
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
    f_GetLastErrorInfo get_last_error_info = nullptr;
    f_ClearLastErrorInfo clear_last_error_info = nullptr;
};

struct FileInformation
{
    Architecture architecture = Architecture::Unknown;
    bool dotnet = false;
};

struct TargetSelection
{
    DWORD pid = 0;
    std::wstring requested_name;
    std::wstring name;
    Architecture architecture = Architecture::Unknown;
    bool by_name = false;
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
constexpr size_t kStringMarkerCount = 34;
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
};

namespace stealth
{
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
        DWORD lastError = 0;
    };

    // Reads the target's exception-chain state through its PEB.
    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
}

#pragma endregion
