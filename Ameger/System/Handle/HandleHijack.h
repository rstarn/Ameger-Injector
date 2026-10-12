#pragma once

#include <Windows.h>

#include "Core/Foundation/Error.h"
#include "Core/Foundation/Primitives/InjectionTypes.h"

DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess);

bool ProbeMemoryRoundtrip(HANDLE Candidate);

void RecordHijackOutcome(const HijackStats & Stats, bool IsThread);

void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);
