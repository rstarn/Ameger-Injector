  #pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Foundation/Error.h"
#include "Core/Utility/Tools/Tools.h"
#include "Injection/ManualMapping/ManualMappingInternal.h"

// Host-side manual-map entry (runs in the injector, stages the remote shell).
// See ManualMappingInternal.h for the in-target shell stages.
namespace MMAP_NATIVE
{
// Validates the payload, stages code+data+raw image into the target (RW,
// promoted RX before execution), runs it via StartRoutine, and reads back the
// result. Params: DllPath (payload source), hTargetProc (target), Method
// (only LM_HijackThread), Flags (INJ_MM_* pipeline selection), hOut (out
// remote image base), Timeout (ms for the shell), SponsorThread/SponsorTid
// (victim hint), error_data (out detail). Returns: INJ_*/SR_* code.
	DWORD ManualMap(const INJECTION_SOURCE & DllPath, HANDLE hTargetProc, LAUNCH_METHOD Method, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
}