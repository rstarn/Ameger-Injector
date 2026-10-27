> **Superseded for R2, R3, and R5.** The R2, R3, and R5 sections
> below were written before the code was re-read for TASK-003 and
> are factually wrong on three points:
>
>   - R2: `FindHijackThread` is already bounded by `kMaxHandleProbes`
>     on both the running and waiting paths and prefers event-driven
>     over delay waits. It is not a P1.
>   - R3: the staging leak on `SR_HT_ERR_RECOVERY_REQUIRED` is a
>     documented, intentional trade-off, not an oversight.
>   - R5: the pin check already refuses a missing, empty, or
>     mismatching `PayloadSha256` at `Main.cpp:3428-3436`.
>
> The authoritative post-remediation register is
> `Docs/RISK-REGISTER.md`. This file is kept unmodified as the
> historical record of what TASK-002 believed.

# TASK-002 Risk Design Proposals

This document proposes designs for risks R1 through R5 in `Docs/RISK-CODE-EXCERPTS.md`. It is prose-only and does not change any source file.

## DISCREPANCIES

- `D:\Ameger\Mapper\Mapper\Provider\Service.cpp` was specified by the task but was not found on disk. The proposal for R1 is therefore limited to the provider ABI, driver client code, and the embedded driver resource.

## R1 — Mapper Provider Unbounded MemCopy

ROOT CAUSE: `Provider.hpp` exposes `CopyRequest` without an upper bound on offset or size, and `Driver.cpp` performs a `memcpy` using that caller-supplied size.

FAILURE MODE: An out-of-bounds copy can corrupt process memory, crash the target, or be observable through anomalous IOCTL payloads.

PROPOSED CHANGE: Enforce offset and size limits in both the client-side provider and the kernel driver before copying. Add a bounded copy helper that rejects requests whose end offset exceeds the target image, and return a provider error rather than attempting the copy.

RISK OF CHANGE: The change spans the kernel driver, the client provider, and any existing caller that sends large copy requests. The `kCopyIoctl` ABI can remain stable while validation is added on both ends.

TEST: Add unit tests that attempt an in-bounds copy and then an out-of-bounds copy, asserting that the in-bounds path succeeds and the out-of-bounds path returns a safe provider error.

DEPENDENCIES: Kernel driver handler, `Provider.hpp`, `Driver.cpp`, and Mapper callers of the provider copy primitive.

## R2 — ThreadHijacking Handle Probe

ROOT CAUSE: `ThreadHijacking.cpp` probes the handle table to find a usable thread handle, which both increases observability and creates a window where the handle can be invalid or closed after being found.

FAILURE MODE: The hijack can fail or behave unreliably, and the handle-table enumeration itself can be observed by an onlooker scanning the process handle table.

PROPOSED CHANGE: Avoid handle-table probing by opening the target process with the required access rights and obtaining the target thread handle through the selected target flow. Keep `THREAD_EXEC_STATS` and the shell-stack layout invariants, but reduce observable side effects and stale-handle races.

RISK OF CHANGE: Existing callers may rely on the current probe behavior, and the telemetry fields must keep their offsets intact. The change should preserve the published stats layout.

TEST: Run the hijack against a scratch target and confirm that `THREAD_EXEC_STATS` is populated correctly, the handle-table scan is absent, and the shell-stack geometry invariants still compile and pass.

DEPENDENCIES: `ThreadHijacking.cpp`, `THREAD_EXEC_STATS`, `StartRoutine.h`, target selection in `Main.cpp`.

## R3 — ManualMapping Memory Leak

ROOT CAUSE: The manual mapping routine in `ManualMapping.cpp` allocates buffers for mapping and frees them only on selected paths, leaving allocations unreleased when errors occur.

FAILURE MODE: Repeated injections can leak memory in the target process, leading to gradual exhaustion or crash over multiple runs.

PROPOSED CHANGE: Make ownership of every allocated buffer explicit so that all error paths release memory before returning. Keep `MAP_STATS` unchanged so the stats layout remains compatible with existing consumers.

RISK OF CHANGE: Editing allocation paths in a complex manual-mapping routine risks introducing a double-free or skipping a release. A careful audit of every return path is required before changing ownership.

TEST: Run an ASAN or leak-checker build of the manual mapping routine, then verify that `MAP_STATS` still has size 80 and the offset assertions still compile.

DEPENDENCIES: `ManualMapping.cpp`, `Injection.h` (`MAP_STATS`), and the target-process memory layout code.

## R4 — Windows11 LDR Offsets

ROOT CAUSE: `Windows11.h` uses fixed `LDR` offsets that are guarded by `static_assert`, but Windows updates can change the `PEB_LDR_DATA` layout or module list offsets.

FAILURE MODE: Stale offsets cause incorrect module table reads, failed import resolution, or crashes when running on a newer or patched Windows build.

PROPOSED CHANGE: Derive the `LDR` address at runtime from the `PEB`, validate the module list before traversal, and keep the existing static assertions as the in-repo ABI guard. Add Windows 11 detection so the correct offset set is selected per OS build.

RISK OF CHANGE: Runtime resolution adds new failure modes and needs testing across Windows 10 and Windows 11. Excessive runtime probing can itself be observable.

TEST: Build with all `static_assert` checks enabled, run import resolution on Windows 10 and Windows 11, and verify that the resolved module names and export addresses match expectations.

DEPENDENCIES: `PEB` access, `LDR` module lists, `NTDefinitions.h`, and the syscall layer.

## R5 — Payload Pin Enforcement

ROOT CAUSE: The payload loader in `Main.cpp` requires a `PayloadSha256` pin, but the validation path can allow execution to proceed if the pin is missing, or block valid configurations when the pin has not been migrated.

FAILURE MODE: A tampered payload can be executed if the pin check is bypassed, or legitimate operators can be blocked when their configuration does not carry the pin.

PROPOSED CHANGE: Make the payload SHA-256 pin mandatory before injection, reject a missing or empty pin early, and keep the existing verify functions while ensuring the non-empty pin requirement is enforced on every injection path.

RISK OF CHANGE: Stricter pin enforcement may block existing configurations that do not yet have a payload pin. Those configurations need a migration step.

TEST: Add negative tests with a missing pin and positive tests with a valid SHA-256, asserting that missing pins are refused and valid pins are accepted.

DEPENDENCIES: `Main.cpp` payload inspection, configuration parser, deployed configuration keys, and the DLL inspection helpers.

## RECOMMENDED-ORDER

1. Fix R1 first because the provider copy primitive can corrupt memory directly and touches both the Mapper provider ABI and the kernel driver.
2. Fix R5 second so payload integrity is enforced before any execution path.
3. Fix R3 third to remove the manual mapping leak, which is lower severity but still a correctness issue.
4. Fix R2 fourth to reduce observability and stale-handle races in thread hijacking.
5. Fix R4 last because Windows 11 offset validation requires OS-level testing and the greatest change surface.
