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
;; The RSP the stub actually pivoted to. The host compares it against the
;; allocation window, so a stub that failed to pivot cannot pass silently.
SR_SHELL_RSP EQU 88
SR_FP_FLAG_XSAVE EQU 1
SR_FP_AREA EQU 128
SR_FP_AREA_SIZE EQU 864
SR_SAVED_RSP EQU 96

;; Dedicated shell stack, laid out after the state page in the same allocation.
;; The first 128 bytes of victim stack are still used for the register spill
;; (they hold the victim's own register values and hold no shell data), but the
;; routine and everything it calls run here.
;; Guard page sits between the state page and the shell stack, so an overflow
;; faults on PAGE_NOACCESS instead of overwriting the state page.
SR_SHELL_STACK_BASE EQU 8192
SR_SHELL_STACK_SIZE EQU 1048576
;; 16-byte aligned top, minus a 64-byte slot for the caller's shadow space.
SR_SHELL_STACK_TOP EQU 1056704

;; XCR0 components this stub is allowed to request. Bit 0 = x87, bit 1 = SSE,
;; bit 2 = AVX (YMM). AVX-512 (bits 5-7) is deliberately excluded: its XSAVE image
;; does not fit SR_FP_AREA_SIZE, and - more importantly - XRSTOR with a mask that omits
;; a component leaves that component's registers untouched, so the victim's ZMM state
;; survives simply by never being written.
SR_FP_XCR0_X87  EQU 1
SR_FP_XCR0_SSE  EQU 2
SR_FP_XCR0_AVX  EQU 4
SR_FP_XCR0_MASK EQU 7

;; XSAVE image geometry for the components above: the 64-byte XSAVE header plus the
;; 512-byte legacy region, followed by the 256-byte YMM region when AVX is requested.
SR_FP_XSAVE_LEGACY_BYTES EQU 576
SR_FP_AVX_BYTES         EQU 256

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
;; request lives in EAX (x87/SSE/AVX only; the mask is capped at XCR0 bits 0-2 and
;; never enables AVX-512 state); EDX must be zero because a non-zero EDX names an XCR0
;; bit that does not exist and raises #GP.
;;
;; The mask is computed *inside* the stub with XGETBV, which reads the XCR0 of the
;; thread that executes it - the victim's own XCR0, not the injector's. XCR0 is a
;; per-thread register, so reading the injector's value and replaying it would be
;; wrong whenever the two differ, and a mask that is not a subset of the victim's XCR0
;; raises #GP and kills the thread being hijacked.
;;
;; Only the REX.W forms (xsave64/xrstor64, fxsave64/fxrstor64) are emitted. Without
;; REX.W the 64-bit forms save only the low 128 bits of the XMM registers, which would
;; silently drop the victim's YMM state whenever AVX is enabled.

TEB_LAST_ERROR EQU 68H
