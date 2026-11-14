#pragma once

#ifndef _WIN64
#error This build is x64-only: 32-bit / WOW64 support has been eradicated (ManualMap + HijackThread only).
#endif

#include <Windows.h>
#include "../../../Injection.h"
#include "Core/Foundation/Primitives/InjectionTypes.h"
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "Core/Foundation/Primitives/KcStrings/Core/KcStrSuite.h"

#include <atomic>

#if defined(NTDDI_VERSION) && (NTDDI_VERSION < NTDDI_WIN11)
#error The mininum requirement for this library is Windows 11.
#endif

#if __has_include(<format>)
#include <format>
#endif
#include <iomanip>
#include <sstream>
#include <string>
#include <tchar.h>

#include <fstream>
#include <shlwapi.h>

#include <ctime>
#include <chrono>
#include <map>
#include <memory>
#include <random>

#include <algorithm>
#include <vector>

#include <DbgHelp.h>

#include <thread>

#include <WinInet.h>
#include <Urlmon.h>

#pragma warning(disable: 4201)
#pragma warning(disable: 4324)
#pragma warning(disable: 6001)
#pragma warning(disable: 6258)
#pragma warning(disable: 28159)

#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)




#define EXPORT_FUNCTION(export_name, link_name) __pragma(comment(linker, "/EXPORT:" export_name "=" link_name))

#define ALIGN_8 __declspec(align(8))
#define ALIGN ALIGN_8

inline std::atomic<f_raw_print_callback> g_print_raw_callback{nullptr};

void custom_print(int indention_offset, const char * format, ...);

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

void custom_diag_print(int indention_offset, const char * format, ...);

#ifdef AMEGER_KEEP_RUNTIME_LOGS
#define LOG custom_print
#define DIAG custom_diag_print
#else
#define LOG(...) ((void)0)
#define DIAG(...) ((void)0)
#endif

// Diagnostics gate for the "[*] ... Diag" / "[*] Stub ... Check" trace lines. The launcher sets
// AMEGER_DIAG=1 when Configuration.ini's Diagnostics switch is on; an elevated launcher cannot be
// handed an environment variable from the shell, so the switch travels through the config and
// the child target inherits the variable from the launcher. Off (the default) means silent.
inline bool AmegerDiagEnabled()
{
    static const bool enabled = []() -> bool
    {
        wchar_t buffer[8] = {};
        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_DIAG").get(), buffer, 4);
        return got == 1 && buffer[0] == L'1';
    }();
    return enabled;
}

inline bool AmegerDiagStreamEnabled()
{
    static const bool enabled = []() -> bool
    {
        wchar_t buffer[8] = {};
        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_DIAG_STREAM").get(), buffer, 4);
        return got == 1 && buffer[0] == L'1';
    }();
    return enabled;
}
