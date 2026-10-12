INCLUDE RemoteShell.inc

REMOTE_THREAD SEGMENT ALIGN(16) 'CODE'

PUBLIC RemoteThreadHijackBegin
PUBLIC RemoteThreadHijackEnd
PUBLIC RemoteThreadReturnTarget
PUBLIC RemoteThreadState

; ---------------------------------------------------------------------------
; Per-build stub byte variance. AMEGER_STUB_SEED is supplied by this project's
; MASM PreprocessorDefinitions (AMEGER_STUB_SEED=$(AmegerStubSeed)); Create.bat
; draws a fresh value every build. Each bit below independently selects between
; two byte-encodings of the SAME instruction:
;   bit 0 - FP area addressing : 0 = lea r10,[rbx+off], 1 = mov r10,rbx ; add r10,off
;   bit 1 - FP area width     : 0 = xsave/fxsave (32-bit mask), 1 = xsave64/fxsave64
;   bit 2 - RSP capture       : 0 = mov r12,rsp, 1 = lea r12,[rsp]
; Every pair is a pure encoding substitution: no flag, register, stack, memory
; or control-flow effect differs, so register/stack discipline, the exit state,
; the TEB LastError write and the jmp [ReturnTarget] return are unchanged. The
; FP slots live in the stub-private state page and are addressed off rbx (never
; off rsp), so no variant shifts any offset; the RSP capture runs before the
; alignment, so the aligned frame is identical in every variant. The width pair
; only changes how wide the FPU instruction/data pointer fields are stored
; inside the image, and each save is consumed by the matching restore in the
; same staged copy, so both forms are self-consistent. STUB_SEED is 0 when no
; per-build seed reached this project, and 0 selects every legacy encoding, so
; the stub assembles byte-for-byte to the pre-variance bytes.
; ---------------------------------------------------------------------------
IFDEF AMEGER_STUB_SEED
STUB_SEED EQU AMEGER_STUB_SEED
ELSE
STUB_SEED EQU 0
ENDIF
STUB_FP_ADDR     EQU (STUB_SEED AND 1)
STUB_FP_WIDTH    EQU (STUB_SEED AND 2)
STUB_RSP_CAPTURE EQU (STUB_SEED AND 4)

RemoteThreadHijackBegin:
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    lea rbx, [RemoteThreadState]
IF STUB_RSP_CAPTURE
    lea r12, [rsp]
ELSE
    mov r12, rsp
ENDIF
    ; 16-byte align for the shell call. The 64 bytes of scratch below the
    ; aligned frame exist for a specific reason and must not be removed: at the
    ; shell's entry rsp is one slot below this frame, so the callee's 32-byte
    ; home space spans [entry-8, entry+0x18) - i.e. ABOVE its own rsp, exactly
    ; where the registers pushed by this stub live. Without the scratch the
    ; shell's (ABI-legal) home-space spills overwrite the stub's saved
    ; r13/r14/r15 and the victim resumes with them corrupted (an instrumented
    ; run measured a victim local living in r15 coming back as a pointer to
    ; this stub's own staging block). The scratch guarantees the home space
    ; lands in dead space instead.
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 40h

    ; ---- save the victim's complete FP/SIMD/XSTATE into the state page ----
    ; One instruction covers the x87 control word, the x87 data registers
    ; (st0-st7), MXCSR, xmm0-xmm15 and - on the XSAVE path - the ymm upper
    ; halves. xmm6-xmm15 are non-volatile under Win64 and the x87/MXCSR modes
    ; are process-wide, so a victim holding live values there across the shell
    ; (and the payload's whole DllMain, which freely uses SIMD) would resume
    ; silently corrupted rather than crashing. The path is chosen by the host,
    ; which probes CPUID/XGETBV before staging: XSAVE when the OS saves the
    ; extended state, FXSAVE otherwise (both cover the legacy x87/SSE area).
IF STUB_FP_ADDR
    mov r10, rbx
    add r10, SR_FP_AREA
ELSE
    lea r10, [rbx+SR_FP_AREA]
ENDIF
    cmp dword ptr [rbx+SR_FP_FLAGS], SR_FP_FLAG_XSAVE
    jne StubFpSaveFallback
    mov eax, [rbx+SR_FP_MASK]
    xor edx, edx
IF STUB_FP_WIDTH
    xsave64 [r10]
ELSE
    xsave [r10]
ENDIF
    jmp StubFpSaveDone
StubFpSaveFallback:
IF STUB_FP_WIDTH
    fxsave64 [r10]
ELSE
    fxsave [r10]
ENDIF
StubFpSaveDone:

    ; Shield the shell from whatever FP exception state the victim left behind.
    ; Both words are exception-masked and the image above holds the victim's
    ; real values, so this only prevents an #MF/#XF inside the shell.
    fldcw word ptr [rbx+SR_SHELL_CW]
    ldmxcsr dword ptr [rbx+SR_SHELL_MXCSR]

    mov rax, [rbx+SR_ROUTINE]
    mov rcx, [rbx+SR_ARG]
    ; Preserve the victim's TEB LastError across the shell call. The mapping
    ; shell (LDR imports, TLS, DllMain) sets LastError as a side effect, and
    ; without this the victim resumes with the shell's residue instead of its
    ; own value - observable to any code that reads GetLastError after we
    ; return, including an anti-cheat context check. Stashed in the reserved
    ; SR_BUFFER slot (zero-initialized, 8 bytes; only the low DWORD is used).
    ; The gs:[] disp32 is patched by the host like TEB_LAST_ERROR below; the
    ; read pattern is byte-identical so the host patches every occurrence.
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_BUFFER], r11d
    mov qword ptr [rbx+SR_STATE], 1
    call rax
    mov [rbx+SR_RET], eax
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_LAST_ERROR], r11d
    ; Restore the victim's original LastError before returning. The write
    ; encoding (65 44 89 1C 25) differs from the read above, so the host
    ; patches it as a separate site and fails closed if it is absent.
    mov r11d, [rbx+SR_BUFFER]
    mov gs:[TEB_LAST_ERROR], r11d
    mov qword ptr [rbx+SR_STATE], 2

    ; ---- restore the victim's complete FP/SIMD/XSTATE from the state page ----
    ; Same instruction pair as the save, so the image format always matches.
    ; Runs after the shell returns, so anything the payload did to the FP state
    ; is discarded, exactly like a register restore.
IF STUB_FP_ADDR
    mov r10, rbx
    add r10, SR_FP_AREA
ELSE
    lea r10, [rbx+SR_FP_AREA]
ENDIF
    cmp dword ptr [rbx+SR_FP_FLAGS], SR_FP_FLAG_XSAVE
    jne StubFpRestoreFallback
    mov eax, [rbx+SR_FP_MASK]
    xor edx, edx
IF STUB_FP_WIDTH
    xrstor64 [r10]
ELSE
    xrstor [r10]
ENDIF
    jmp StubFpRestoreDone
StubFpRestoreFallback:
IF STUB_FP_WIDTH
    fxrstor64 [r10]
ELSE
    fxrstor [r10]
ENDIF
    StubFpRestoreDone:
    mov rsp, r12

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq

    ; ---- scrub this thread's stack window before returning home ----
    ; The stub, the mapping shell and the payload's DllMain all ran on the
    ; victim's own stack, so everything below the hijack rsp is now stale
    ; garbage: our frames, the shell's frames, resolved addresses, decrypted
    ; strings and pointers. That window survives in the target's stack pages
    ; indefinitely, which is the single most valuable residue we can leave.
    ;
    ; The victim's live frames are ABOVE its rsp, so everything below is dead
    ; by definition - zeroing it cannot change a single observable value. The
    ; window is bounded below by the thread's current stack limit
    ; (TEB::StackLimit, gs:[0x10]) so the walk never reaches an uncommitted
    ; page and never triggers stack growth.
    ;
    ; The floor must be recomputed here rather than taken from a saved register:
    ; the pops above have already restored r12 (and every other callee-saved
    ; register) to the victim's values, so what r12 holds now has nothing to do
    ; with this frame. The stub's own frame is a fixed function of the victim's
    ; original rsp, which is what rsp is right now: 16 pushed registers (80h)
    ; below it, aligned down, then the 40h scratch. The shell ran deeper than
    ; that, and StackLimit below bounds how far down the walk goes.
    lea rdi, [rsp]
    mov rax, rdi
    sub rax, 80h
    and rax, 0FFFFFFFFFFFFFFF0h
    sub rax, 40h
    ; rax = the lowest address this stub's own frames occupied. Never above rsp
    ; (the arithmetic only subtracts), so the window is always well-formed.
    mov r10, gs:[10h]
    cmp r10, rdi
    jae StubStackScrubDone      ; degenerate: limit already above rsp
    cmp r10, rax
    jae StubStackScrubSkipLow   ; limit sits above our floor: clamp to it
    cmp rax, rdi
    jae StubStackScrubDone      ; degenerate: window already empty
    mov rdx, rdi
    sub rdx, rax
    shr rdx, 3
    xor r8d, r8d
StubStackScrubLoop:
    test rdx, rdx
    jz StubStackScrubTail
    mov qword ptr [rdi-8], r8
    sub rdi, 8
    dec rdx
    jmp StubStackScrubLoop
StubStackScrubTail:
    jmp StubStackScrubDone
StubStackScrubSkipLow:
    ; StackLimit is above our window's floor: only zero down to it.
    mov rdx, rdi
    sub rdx, r10
    shr rdx, 3
    xor r8d, r8d
StubStackScrubLoopLow:
    test rdx, rdx
    jz StubStackScrubDone
    mov qword ptr [rdi-8], r8
    sub rdi, 8
    dec rdx
    jmp StubStackScrubLoopLow
StubStackScrubDone:
    jmp qword ptr [RemoteThreadReturnTarget]

ALIGN 16
RemoteThreadState:
RemoteThreadStateFlag    DQ 0
RemoteThreadRet          DD 0
RemoteThreadPad1         DD 0
RemoteThreadLastError    DD 0
RemoteThreadPad2         DD 0
RemoteThreadArg          DQ 0
RemoteThreadRoutine      DQ 0
RemoteThreadBuffer       DQ 0
; FP/XSTATE control block (mirrors SR_REMOTE_DATA; ALIGN8 on the host side, so
; every field below is padded to 8 bytes). The struct's own tail pad after
; ShellMxcsr is declared explicitly so sizeof(SR_REMOTE_DATA) == 80 stays
; visible here rather than implied by the host's alignment rule. Flags bit
; SR_FP_FLAG_XSAVE selects the XSAVE path; Mask is the XCR0-derived feature word
; the stub passes to XSAVE/XRSTOR. The two shell words default to the FNINIT
; values so a stub that somehow ran with a zeroed control block still runs the
; shell with every FP exception masked rather than unmasked.
RemoteThreadFpFlags      DQ 0
RemoteThreadFpMask       DQ 0
RemoteThreadShellCw      DW 037Fh
RemoteThreadShellCwPad   DW 0
RemoteThreadShellMxcsr   DD 01F80h
RemoteThreadShellMxPad   DD 0
RemoteThreadShellTailPad DD 0
; Reserved to hold any future ALIGN8 fields; keeps SR_FP_AREA at offset 128,
; which is what makes the area 64-byte aligned (XSAVE #GPs otherwise).
RemoteThreadFpReserved   BYTE 48 DUP (0)
; The victim's saved FP/SIMD/XSTATE image. Never referenced off rsp: see the
; home-space note in RemoteShell.inc.
RemoteThreadFpArea       BYTE SR_FP_AREA_SIZE DUP (0)
RemoteThreadReturnTarget DQ 0

RemoteThreadHijackEnd:

REMOTE_THREAD ENDS

END
