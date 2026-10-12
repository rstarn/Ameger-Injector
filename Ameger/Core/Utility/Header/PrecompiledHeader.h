#pragma once

// Precompiled header: shared includes, shorthands, and the LOG gate.
// What: pulls in Windows/STL/DbgHelp/WinInet once for every runtime TU so the
//   shell, hijack, and symbol code share one build baseline. Why PCH: the
//   manual-map shell is size-sensitive (page-split W^X staging), so common
//   headers must not be re-parsed per TU. How: every runtime .cpp includes
//   this first; shell code_seg sections still get their own placement via
//   ManualMappingInternal.h. x64-only by design (see the guard below).
#ifndef _WIN64
#error This build is x64-only: 32-bit / WOW64 support has been eradicated (ManualMap + HijackThread only).
#endif

#include <Windows.h>
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

#include <vector>

#include <DbgHelp.h>
// <thread> for std::this_thread::sleep_for only. Deliberately NOT <future>:
// std::async/std::future instantiate Concurrency PPL task machinery over the
// caller's types and bake their mangled names into .rdata (see ASYNC_WORKER_SLOT
// in Tools.h); the workers use raw threads instead.
#include <thread>

#include <WinInet.h>
#include <Urlmon.h>

#pragma warning(disable: 4201) 
#pragma warning(disable: 4324) 
#pragma warning(disable: 6001) 
#pragma warning(disable: 6258) 
#pragma warning(disable: 28159) 

// Short alias for reinterpret_cast. Used pervasively for RVA/VA arithmetic;
// the terse name keeps pointer-math lines readable. No semantics beyond the cast.
#define ReCa reinterpret_cast

// Truncates a pointer to its low 32 bits for %08X logging. Params: p (any
// pointer). Returns: the low DWORD. Never dereferences.
#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

// Emits a /EXPORT linker directive renaming an export. Params: export_name
// (renamed per-build name from ShuffleExports), link_name (__FUNCDNAME__ of
// the function). Keeps shipped export names unstable across builds.
#define EXPORT_FUNCTION(export_name, link_name) comment(linker, "/EXPORT:" export_name "=" link_name)

// 8-byte alignment for cross-boundary structs (MANUAL_MAPPING_DATA, telemetry).
// Every ALIGN field pads to 8 so host, shell, and launcher agree on offsets.
#define ALIGN_8 __declspec(align(8))
#define ALIGN ALIGN_8

// Raw-text trace callback type. Params: szText (null-terminated ANSI line).
using f_raw_print_callback = void(__stdcall *)(const char * szText);
// Current trace sink; QuietPrint in production, custom_print in debug logs.
inline std::atomic<f_raw_print_callback> g_print_raw_callback{nullptr};

// Debug trace printer. Params: indention_offset (nesting depth), format +
// varargs (printf-style). No-op unless AMEGER_KEEP_RUNTIME_LOGS (see LOG).
void custom_print(int indention_offset, const char * format, ...);

// Installs the trace sink. Params: print (callback, or null to mute).
// Returns: INJ_ERR_SUCCESS. Called once by the launcher after LoadLibrary.
DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

// Stealth: runtime LOG format strings would otherwise persist as plaintext
// in .rdata (muted at runtime via QuietPrint, but on disk regardless).
// Shipped builds compile logs out entirely; define AMEGER_KEEP_RUNTIME_LOGS
// for a debug build that needs the print-callback trace.
#ifdef AMEGER_KEEP_RUNTIME_LOGS
#define LOG custom_print
#else
#define LOG(...) ((void)0)
#endif