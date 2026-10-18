SR_STATE EQU 0
SR_RET EQU 8
SR_LAST_ERROR EQU 16
SR_ARG EQU 24
SR_ROUTINE EQU 32
SR_BUFFER EQU 40
SR_FP_FLAGS EQU 48
SR_FP_MASK EQU 56
SR_SHELL_CW EQU 64
SR_SHELL_MXCSR EQU 72
SR_CYCLES_DELTA EQU 80
SR_SCRUB_BYTES EQU 88
SR_FP_FLAG_XSAVE EQU 1
SR_FP_AREA EQU 128
SR_FP_AREA_SIZE EQU 864
SR_SAVED_RSP EQU 96

;; SR_STATE values. Kept in lockstep with SR_REMOTE_STATE in Execution/Routine/StartRoutine.h.
SR_STATE_PENDING  EQU 0
SR_STATE_RUNNING  EQU 1
SR_STATE_FINISHED EQU 2
;; Published after the routine result is stored and while the state page is still addressed:
;; the trailing pops would otherwise restore the victim RBX, so the store must precede them.
;; Reclamation stays gated on the thread's RIP being observed outside the RX code page,
;; because the return jump itself still reads the target out of the state page.
SR_STATE_EXITED   EQU 3

;; XSAVE/XRSTOR take a 64-bit feature mask in EDX:EAX. Every component this stub can
;; request lives in EAX (x87/SSE/AVX, and AVX-512 when enabled); EDX must be zero because
;; a non-zero EDX names an XCR0 bit that does not exist and raises #GP.

TEB_LAST_ERROR EQU 68H
