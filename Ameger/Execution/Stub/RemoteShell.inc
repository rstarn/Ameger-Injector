; Field offsets into the in-target SR_REMOTE_DATA control block, mirroring
; StartRoutine.h byte-for-byte (see the static_asserts there). What: lets the
; asm stub address State/Ret/LastError/Arg/Routine without a struct layout.
; Keep in sync with SR_REMOTE_DATA; a drift corrupts the host poll.
SR_STATE EQU 0
SR_RET EQU 8
SR_LAST_ERROR EQU 16
SR_ARG EQU 24
SR_ROUTINE EQU 32
; Scratch for the victim's saved TEB LastError (low DWORD; high stays 0).
; Written on stub entry, read back to restore on exit. See StartRoutine.h.
SR_BUFFER EQU 40
; Complete FP/SIMD/XSTATE preservation. Everything - x87 control word and data
; registers, MXCSR, xmm0-15, and (when the CPU/OS allow it) the ymm upper
; halves - is saved into the stub-private state page with one instruction
; instead of being copied to the stub's stack frame.
;
; Why not the stack frame: at the shell's entry its rsp is one slot below this
; stub's frame, so its 32-byte home space covers [frame-8, frame+0x18) and
; anything saved in the first 24 bytes of a stack frame is destroyed the moment
; the shell spills a register (an instrumented run measured a saved CW of 0x077F
; reading back as 0x051F). The state page is private to the stub - the shell is
; never handed this pointer - so these slots cannot be clobbered.
SR_FP_FLAGS EQU 48
SR_FP_MASK EQU 56
; Exception-masked control words the stub installs for the duration of the
; shell call, so the victim's own (possibly unmasked) FP exception state cannot
; #MF/#XF the shell or the payload's DllMain. The save above holds the victim's
; real values, so these are purely a shield for the shell's own code.
SR_SHELL_CW EQU 64
SR_SHELL_MXCSR EQU 72
; The FXSAVE/XSAVE image itself. Offset 128 keeps the area 64-byte aligned
; relative to the (page-aligned) state page base, which XSAVE requires - an
; unaligned operand is #GP. Size covers the worst case this build saves:
; 512-byte legacy area + 64-byte XSAVE header + 256-byte YMM_Hi128 = 832.
SR_FP_FLAG_XSAVE EQU 1
SR_FP_AREA EQU 128
SR_FP_AREA_SIZE EQU 864

; Assemble-time placeholder only: MASM needs a constant for the gs:[disp32]
; encoding, and 68H is the legacy TEB::LastErrorValue. The host OVERWRITES
; this disp32 in its staged copy with g_DynamicOffsets.TebLastErrorValue
; (PDB TEB::LastErrorValue) before the stub runs, and fails closed
; (SR_HT_ERR_STUB_PATCH_FAIL) unless it patches every read site
; (65 44 8B 1C 25, two occurrences: entry save + exit report) and the single
; write site (65 44 89 1C 25, exit restore), or the resolved value is 0. 68H
; is therefore never executed; never rely on it.
TEB_LAST_ERROR EQU 68H
