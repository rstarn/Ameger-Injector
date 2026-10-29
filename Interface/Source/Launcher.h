#pragma once







#include "PCH.h"

#include <cstdarg>
#include <cstdio>

#include "../../Ameger/Injection.h"
#include "../../Ameger/Core/Foundation/Error.h"
#include "../../Ameger/Core/Foundation/Primitives/ResourceGuard.h"
#include "../../Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "../../Ameger/Core/Utility/Binary/PEImage.h"
#include "../../Ameger/NT/NTDefinitions.h"



#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

#pragma region console colours






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










enum class LoaderListState
{
    Unknown,
    Published,
    NotPublished
};

struct ProcessIdentity
{
    DWORD pid = 0;
    std::wstring name;
    std::wstring full_path;
    ULONGLONG creation_time = 0;
    Architecture architecture = Architecture::Unknown;
    LoaderListState loader_list_state = LoaderListState::Unknown;


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









    bool discard_result_log_on_success = false;




    bool auto_confirm = false;
    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;
    std::wstring donor_owner_blocklist;


    std::wstring test_target = L"notepad.exe";

    std::wstring target_name;
    std::wstring expected_payload_sha256;

    std::wstring payload_name;
    std::wstring runtime_name;
    std::vector<ExportNameMap> export_map;

    std::wstring dll_dir = L"DLLs";
};


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




constexpr size_t kStringMarkerCount = 31;
#pragma region shared helpers



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


bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture);



bool QueryProcessIdentity(DWORD pid, ProcessIdentity & out);


bool QueryProcessFixed(DWORD pid, wchar_t * name_out, size_t name_count, Architecture & architecture);


void DescribeDonor(DWORD pid, wchar_t * name_out, size_t name_count);


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




    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;




    std::vector<std::wstring> pre_load_modules;
    size_t pre_target_windows = 0;
    size_t pre_target_layered = 0;
};

namespace stealth
{


    double MeasureTscHz();





    bool CapturePreLoadBaseline(DWORD pid, StealthVerifierBuffers & buffers);




    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers);


    const wchar_t * StealthPageDesc(DWORD p);




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



        ULONG_PTR imageBase = 0;
        DWORD lastError = 0;
    };


    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
}

#pragma endregion
