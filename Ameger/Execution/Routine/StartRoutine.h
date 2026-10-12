#pragma once

#include "System/Information/ProcessInformation.h"
#include "Core/Utility/Tools/Tools.h"

// Remote-execution contract between the hijack host and the asm stub.
// What: SR_REMOTE_STATE tracks one stub run, SR_REMOTE_DATA is the shared
//   control block (host writes pArg/pRoutine + ReturnTarget, stub writes
//   State/Ret/LastWin32Error), f_Routine is the shell signature the stub
//   calls. Why: the host polls State across the process boundary, so the
//   values must be a terminal progression (Pending->Executing->Finished) and
//   the struct layout must match RemoteThreadHijack.asm field-for-field
//   (see the static_asserts below and RemoteShell.inc offsets).
// Remote stub lifecycle: Pending (staged, thread not yet running it) ->
// Executing (stub set at call time) -> Finished (stub set after Ret captured).
enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0, // staged; hijack thread still on its own RIP
	SR_RS_Executing			= 1, // stub running (includes the mapping-shell call)
	SR_RS_ExecutionFinished	= 2 // stub returned; Ret/LastWin32Error valid, RIP home
};

// Shell entry signature invoked by the stub: takes the caller's argument
// block, returns an INJ_* code. Must be __fastcall to match the `call rax`
// with RCX=pArg in the asm stub.
using f_Routine			= DWORD(__fastcall *)(void * pArg);

// Host settle delay (ms) after ResumeThread before the first state poll.
// Lets the victim get scheduled without a tight immediate spin.
#define SR_REMOTE_DELAY 50

// Complete FP/SIMD/XSTATE preservation control block, mirrored by
// RemoteShell.inc (SR_FP_*). Everything the victim had in the FP/SIMD domain -
// x87 control word and st0-st7, MXCSR, xmm0-xmm15 and the ymm upper halves on
// the XSAVE path - is saved into the state page by one instruction, because a
// stack copy there is destroyed by the shell's home space (see RemoteShell.inc
// for the measured failure). Flags bit SR_FP_FLAG_XSAVE selects XSAVE over
// FXSAVE and is written by the host's CPUID/XGETBV probe; Mask is the
// XCR0-derived feature word handed to XSAVE/XRSTOR. The two shell words are the
// exception-masked modes installed for the duration of the shell call so the
// victim's own FP exception state cannot fault the shell.
#define SR_FP_FLAG_XSAVE 0x00000001
#define SR_FP_AREA 128
#define SR_FP_AREA_SIZE 864

// Shared control block (80 bytes, 8-aligned fields). Fields: State (polled
// terminal lifecycle above), Ret (shell INJ_* result, valid when Finished),
// LastWin32Error (TEB LastError captured by the stub), pArg/pRoutine (host
// inputs: argument block and shell entry in the target), Buffer (stub scratch:
// the victim's pre-hijack TEB LastError, saved on entry and restored on exit
// so the shell's residue never leaks into the victim - see RemoteShell.inc),
// then the FP/XSTATE block described above. The host patches ReturnTarget
// separately (see RemoteThreadReturnTarget).
ALIGN struct SR_REMOTE_DATA
{
	ALIGN SR_REMOTE_STATE	State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	ALIGN DWORD				Ret				= 0;
	ALIGN DWORD				LastWin32Error	= 0;
	ALIGN void *			pArg			= nullptr;
	ALIGN f_Routine			pRoutine		= nullptr;
	ALIGN UINT_PTR			Buffer			= 0;
	ALIGN DWORD				FpFlags			= 0;
	ALIGN DWORD				FpMask			= 0;
	ALIGN WORD				ShellCw			= 0x037F;	// FNINIT default: all x87 exceptions masked
	ALIGN DWORD				ShellMxcsr		= 0x01F80;	// SSE default: all exceptions masked, RC nearest
};


static_assert(sizeof(SR_REMOTE_DATA) == 80);
static_assert(offsetof(SR_REMOTE_DATA, Ret) == 8);
static_assert(offsetof(SR_REMOTE_DATA, LastWin32Error) == 16);
static_assert(offsetof(SR_REMOTE_DATA, pArg) == 24);
static_assert(offsetof(SR_REMOTE_DATA, pRoutine) == 32);
static_assert(offsetof(SR_REMOTE_DATA, Buffer) == 40);
static_assert(offsetof(SR_REMOTE_DATA, FpFlags) == 48);
static_assert(offsetof(SR_REMOTE_DATA, FpMask) == 56);
static_assert(offsetof(SR_REMOTE_DATA, ShellCw) == 64);
static_assert(offsetof(SR_REMOTE_DATA, ShellMxcsr) == 72);


// ASM stub markers (RemoteThreadHijack.asm): Begin/End delimit the bytes
// copied to the target, ReturnTarget is the saved-RIP slot patched with the
// captured RIP, State is the SR_REMOTE_DATA base inside the copied image.
extern "C" BYTE RemoteThreadHijackBegin[];
extern "C" BYTE RemoteThreadHijackEnd[];
extern "C" BYTE RemoteThreadReturnTarget[];
extern "C" BYTE RemoteThreadState[];

// Runs a shell routine in the target via the selected method. Params:
// hTargetProc (in target handle), pRoutine/pArg (shell entry + arg block, in
// target addresses), Method (only LM_HijackThread), Flags (INJ_* steering
// sponsor/scan behavior), Out (out shell Ret when Finished), Timeout (ms to
// wait for Finished), SponsorThread/SponsorTid (optional pre-opened victim
// fast path), error_data (out detail). Returns: SR_* code.
DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);

// Hijack-thread implementation behind StartRoutine. Same params/returns;
// see ThreadHijacking.cpp for the suspend/stub/recovery pipeline.
DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg,							DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
