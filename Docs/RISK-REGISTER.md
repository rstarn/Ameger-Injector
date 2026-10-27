# Ameger Risk Register (post TASK-003)

Corrected against the verified code excerpts and a direct read of the
on-disk source. R2/R3/R5 are re-classified from the original census;
R1 remediation is split into TASK-004 (Mapper repo) and noted here as
PENDING.

| ID | Severity | Status | File | Note |
|----|----------|--------|------|------|
| R1 | P0 | MITIGATED (client-side) | `Mapper/Provider/Provider.hpp`, `Mapper/Provider/Driver.cpp` | Client-side bounds committed to Ameger-Mapper as 35878968 (baseline-004-post): `kMaxCopySize = 0x10000000` plus overflow checks on `destination + size` and `source + size`. The kernel handler inside the embedded `PdFwKrnl` binary is unbounded by design (that is the CVE the provider exposes); it is not a code defect in this repository and it is not fixable from source. |
| R2 | P3 | CLOSED (not a defect) | `Ameger/Execution/ThreadHijacking.cpp` `FindHijackThread` | Bounded by `kMaxHandleProbes` on both running and waiting paths; prefers event-driven over delay waits; excludes worker threads. Census overstated as P1. |
| R3 | P2 | DOCUMENTED (deliberate trade) | `Ameger/Injection/ManualMapping/ManualMapping.cpp` | `leak_staging = true` on `SR_HT_ERR_RECOVERY_REQUIRED` is intentional; the remote shell may still own its allocation. `MAP_STATS` records only the image base. Comment corrected in TASK-003. |
| R4 | P1 | CLOSED (already fail-closed) | `Ameger/NT/Windows11.h`, `Ameger/Injection/ManualMapping/ManualMapping.cpp` | `static_assert`s in `Windows11.h` remain the compile-time ABI guard. `MMAP_NATIVE::ManualMap` already returns `INJ_ERR_ADVANCED_NOT_DEFINED` when `g_DynamicOffsetsReady == 0`; the earlier "silent fallback" characterization in RISK-DESIGN-PROPOSALS.md was a misreading of the code. |
| R5 | CLOSED | CLOSED (already correct) | `Interface/Source/Main.cpp:3428-3436` | Pin refuses empty, missing, or mismatching `PayloadSha256`. Design proposal was a misreading. |
| R6 | P2 | DOCUMENTED | `Build/Executors/Create.bat` | Build-order invariant documented inline. Not a code change. |
| R7 | P2 | GUARDED | `Ameger/Core/Utility/Tools/Tools.cpp:241` | `static_assert(kAlphabetChars == 62, ...)` guards the invariant. |
| R8 | P2 | DOCUMENTED | `Build/Scripts/CreateSeeds.ps1` | Per-build seeds recorded in `BuildNames.state` for reuse. |
| R9 | P2 | MITIGATED (already fails closed) | `Ameger/Native/Syscall.cpp:571-951` | Resolver logs a warning when `Ready < kSyscallTableCount` and refuses to mark the layer complete. |
| R10 | P2 | MITIGATED (already screened) | `Interface/Source/Main.cpp` `SelectTarget` | Screens by loader-list presence and prefers the largest working set, per `.analysis` F4e. |

## Residual exposure not closed by this register

- **R1 kernel side — architectural, not a pending fix.** The
  PdFwKrnl driver's IOCTL handler performs an unchecked memcpy by
  design (CVE-2023-20598). Client-side bounds catch caller bugs;
  they cannot constrain a caller that constructs a plausible
  in-bounds address pair. Closing this requires either replacing
  the .sys with a validating build (out of scope; the driver
  binary is embedded in Resource.hpp and would need re-signing) or
  a pre-IOCTL wrapper that remaps every target through a checked
  table (a rewrite of the provider abstraction, not a fix).
  Recorded here so the exposure is visible; not scheduled.

