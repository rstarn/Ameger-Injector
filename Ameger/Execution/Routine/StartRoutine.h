#pragma once

#include "System/Information/ProcessInformation.h"
#include "Core/Utility/Tools/Tools.h"

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished	= 2,
	// The stub publishes the exit sentinel after the routine has returned and
	// while the state page is still addressed, so the host can tell a routine
	// that finished from one that is still unwinding.
	SR_RS_Exited			= 3
};

__forceinline bool RemoteRoutineSettled(SR_REMOTE_STATE state)
{
	return state >= SR_REMOTE_STATE::SR_RS_ExecutionFinished;
}

using f_Routine			= DWORD(__fastcall *)(void * pArg);

#define SR_FP_FLAG_XSAVE 0x00000001
#define SR_FP_AREA 128
#define SR_FP_AREA_SIZE 864
#define SR_SAVED_RSP 96
#define SR_CYCLES_DELTA 80
#define SR_SCRUB_BYTES 88

// XCR0 components the hijack stub is allowed to request. Mirrors the SR_FP_* constants
// in Execution/Stub/RemoteShell.inc; the stub narrows this further against the
// victim's own XCR0 with XGETBV before it issues XSAVE.
#define SR_FP_XCR0_X87 0x00000001
#define SR_FP_XCR0_SSE 0x00000002
#define SR_FP_XCR0_AVX 0x00000004
#define SR_FP_XCR0_MASK 0x00000007

// XSAVE image geometry: 64-byte XSAVE header + 512-byte legacy region, plus the
// 256-byte YMM region when AVX is part of the requested mask.
#define SR_FP_XSAVE_LEGACY_BYTES 576
#define SR_FP_AVX_BYTES 256

ALIGN struct SR_REMOTE_DATA
{
	ALIGN SR_REMOTE_STATE	State				= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	ALIGN DWORD				Ret					= 0;
	ALIGN DWORD				LastWin32Error		= 0;
	ALIGN void *			pArg				= nullptr;
	ALIGN f_Routine			pRoutine			= nullptr;
	ALIGN UINT_PTR			Buffer				= 0;
	ALIGN DWORD				FpFlags				= 0;
	ALIGN DWORD				FpMask				= 0;
	ALIGN WORD				ShellCw				= 0x037F;
	ALIGN DWORD				ShellMxcsr			= 0x01F80;
	// The stub installs a known control word and MXCSR before the routine
	// runs, and restores the originals afterwards.
	ALIGN unsigned __int64	RoutineCyclesDelta	= 0;
	ALIGN SIZE_T			StackScrubbedBytes	= 0;
};

static_assert(sizeof(SR_REMOTE_DATA) == 96);
static_assert(offsetof(SR_REMOTE_DATA, Ret) == 8);
static_assert(offsetof(SR_REMOTE_DATA, LastWin32Error) == 16);
static_assert(offsetof(SR_REMOTE_DATA, pArg) == 24);
static_assert(offsetof(SR_REMOTE_DATA, pRoutine) == 32);
static_assert(offsetof(SR_REMOTE_DATA, Buffer) == 40);
static_assert(offsetof(SR_REMOTE_DATA, FpFlags) == 48);
static_assert(offsetof(SR_REMOTE_DATA, FpMask) == 56);
static_assert(offsetof(SR_REMOTE_DATA, ShellCw) == 64);
static_assert(offsetof(SR_REMOTE_DATA, ShellMxcsr) == 72);
static_assert(offsetof(SR_REMOTE_DATA, RoutineCyclesDelta) == 80);
static_assert(offsetof(SR_REMOTE_DATA, StackScrubbedBytes) == 88);

extern "C" BYTE RemoteThreadHijackBegin[];
extern "C" BYTE RemoteThreadHijackEnd[];
extern "C" BYTE RemoteThreadReturnTarget[];
extern "C" BYTE RemoteThreadState[];

extern "C" BYTE RemoteThreadLeaStateIn[];
extern "C" BYTE RemoteThreadLeaStateOut[];
extern "C" BYTE RemoteThreadJmpReturn[];
extern "C" BYTE RemoteThreadTebReadIn[];
extern "C" BYTE RemoteThreadTebReadOut[];
extern "C" BYTE RemoteThreadTebWrite[];

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);

DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg,							DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
