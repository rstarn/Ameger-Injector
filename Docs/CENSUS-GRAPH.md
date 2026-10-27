# TASK-001 Census: Architecture and Graphs

## MODULE MAP

- **Core** — foundational runtime, precompiled header, error/telemetry, string primitives, and dynamic API helpers. Public headers: `Ameger/Core/Foundation/Error.h`, `Ameger/Core/Utility/Header/PrecompiledHeader.h`, `Ameger/Core/Utility/Tools/Tools.h`, `Ameger/Injection.h`, `Ameger/Core/Utility/Binary/DynamicAPI.h`. Entry points: `InitializeRuntime`, `ShutdownRuntime`, `GetRuntimeAbiVersion`, `DllMain` in `Ameger/Core/Foundation/Main.cpp:143`, `:266`, `:318`, `:325`. Dependencies: `Tools`, `ImportHandler`, `DynamicAPI`, `Syscall`, `ManualMapping`.

- **NT** — Windows kernel structure definitions and helpers. Public headers: `Ameger/NT/NTDefinitions.h`, `Ameger/NT/NTFunctions.h`, `Ameger/NT/Windows11.h`. Responsibilities: typed access to PEB/LDR, process/thread information, and Windows 11 layout constants.

- **Native** — ntdll syscall layer. Public header: `Ameger/Native/Syscall.h`. Entry points: `BuildPool` (`Ameger/Native/Syscall.cpp:466`), `SyscallResolveAll` (`:572`). Dependency: ntdll exports and exported syscall gadget discovery.

- **System** — process metadata, symbol loading/parsing, handle hijacking, download manager, import resolution, and dynamic offsets. Public headers: `Ameger/System/Information/ProcessInformation.h`, `Ameger/System/Import/ImportHandler.h`, `Ameger/System/Handle/HandleHijack.h`, `Ameger/System/Symbol/Loader/SymbolLoader.h`, `Ameger/System/Symbol/Parser/SymbolParser.h`, `Ameger/System/Symbol/Offsets/DynamicOffsets.h`.

- **Execution** — thread hijacking and remote shell execution. Public header: `Ameger/Execution/Routine/StartRoutine.h`. Entry points: `StartRoutine` (`Ameger/Execution/Routine/StartRoutine.cpp:5`), `SR_HijackThread` (`Ameger/Execution/ThreadHijacking.cpp:2052`). Assembly/support: `Ameger/Execution/Stub/RemoteThreadHijack.asm`, `Ameger/Execution/Stub/RemoteShell.inc`.

- **Injection** — memory injection and manual mapping. Entry points: `Memory_InjectBody` (`Ameger/Injection/Injection.cpp:169`), `ManualMapping_Shell` (`Ameger/Injection/ManualMapping/ManualMapping.cpp:1715`). Public ABI: `Ameger/Injection.h`, `Ameger/Injection/ManualMapping/ManualMappingInternal.h`.

- **Interface** — launcher executable, wizard UI, config parsing, injection orchestration, and result logging. Entry point: `wWinMain` (`Interface/Source/Main.cpp:5297`). Public support: `Interface/Source/Launcher.h`, `Interface/Source/Interface/Interface.cpp`, `Process.cpp`, `Stealth.cpp`.

- **Build** — build and protection pipeline. Entry scripts: `Build/Executors/Create.bat`, `Build/Executors/Protect.bat`, `Build/Executors/Protection/ProtectDLL.bat`, `Build/Executors/Protection/ProtectEXE.bat`. Outputs: `Build/Release` binaries, `Build/Release/Cache` state, encrypted deployed config, VMP-protected payload/launcher.

- **Mapper** — out-of-tree kernel mapping/provider tool at `D:\Ameger\Mapper`. Public/support files: `Mapper/PE`, `Mapper/Mapper`, `Mapper/Provider`, `Mapper/Service`, `Mapper/Symbols`, `Mapper/App`, `Mapper/Utilities`. Responsibilities: parse PE, relocate/map driver images, resolve symbols/PDBs, and drive kernel memory access through a provider driver.

## BUILD GRAPH

### `Build/Executors/Create.bat` end-to-end

1. Locate MSBuild via vswhere (`Build/Executors/Create.bat:57`).
2. Verify both Visual Studio projects exist (`Build/Executors/Create.bat:72`).
3. Clean `Build/Release` and `Build/obj`, prepare cache directories (`Build/Executors/Create.bat:80`–`85`).
4. Generate per-build names and write `Build/Release/Cache/BuildNames.state` (`Build/Executors/Create.bat:89`, `:162`).
5. Adopt or deploy the payload into a randomized DLL folder (`Build/Executors/Create.bat:107`).
6. Build the runtime project with per-build seeds from `Build/Scripts/CreateSeeds.ps1` and mutation arguments (`Build/Executors/Create.bat:111`–`138`).
7. Verify the merged manual-mapping section in the stock runtime DLL (`Build/Executors/Create.bat:140`–`147`).
8. Run `Build/Scripts/BuildPE.ps1` to mutate the runtime binary (`Build/Executors/Create.bat:151`).
9. Rename exports and persist names state (`Build/Executors/Create.bat:160`–`163`).
10. Compute runtime SHA-256 in chunks (`Build/Executors/Create.bat:166`–`191`).
11. Build the launcher project with runtime hash arguments (`Build/Executors/Create.bat:199`).
12. Deploy payload and protect config (`Build/Executors/Create.bat:207`–`210`).
13. Verify one launcher EXE, verify launcher PE, embedded magic, config magic, payload pin, config keys, runtime PE, syscall stubs, syscall payload, syscall stealth, and export names (`Build/Executors/Create.bat:216`–`245`).
14. Remove import artifacts and sweep intermediates into cache (`Build/Executors/Create.bat:251`–`255`).

Scripts that mutate build output:
- `CreateSeeds.ps1`: creates per-build sentinel/string/stub seeds.
- `BuildPE.ps1`: randomizes section names and mutates the runtime DLL.
- `ShuffleNaming.ps1` / `ShuffleExports.ps1`: renames build outputs and exports.
- `ProtectConfig.ps1`: encrypts/protects the deployed config.
- `BuildVMP.ps1`: drives VMProtect virtualization during protection stages.
- `RepinPayload.ps1`: repins payload SHA-256 in config/state.

Load-bearing ordering:
- `:verify_mmap_sections` must run before `BuildPE.ps1` because BuildPE randomizes section names; if reordered, the `.code` section check could fail (`Build/Executors/Create.bat:140`–`147`).
- Runtime SHA-256 must be computed before building the launcher, because the launcher embeds `AmegerRuntimeHash0` through `AmegerRuntimeHash7` (`Build/Executors/Create.bat:191`, `:199`).
- Export names must be written to `BuildNames.state` before protection stages resolve deployed names (`Build/Executors/Create.bat:162`, `Build/Executors/Protect.bat:90`–`95`).

### `Build/Executors/Protect.bat` end-to-end

1. Validate stage argument: `dll` or `exe` (`Build/Executors/Protect.bat:30`–`37`).
2. Require `Build/Release` and both protection stage scripts (`Build/Executors/Protect.bat:42`–`54`).
3. Run `Build/Executors/Protection/ProtectDLL.bat` unless stage is `exe` (`Build/Executors/Protect.bat:71`).
4. Run `Build/Executors/Protection/ProtectEXE.bat` unless stage is `dll` (`Build/Executors/Protect.bat:82`).
5. Read `Build/Release/Cache/BuildNames.state` to locate deployed payload/launcher names (`Build/Executors/Protect.bat:90`–`95`).
6. Summarize success/failure and delete names state when both stages completed unconditionally (`Build/Executors/Protect.bat:100`–`120`).

## RUNTIME CALL GRAPH

1. `wWinMain` starts the launcher UI and CLI flow (`Interface/Source/Main.cpp:5297`).
2. `BuildFlags` converts `WizardConfig` into injection flags (`Interface/Source/Main.cpp:3561`; used at `:4177`, `:4531`).
3. Target process start/select: `CreateProcessW` for a scratch target (`Interface/Source/Main.cpp:562`, `:4083`). Privilege boundary crossed: **N** (user-mode process creation).
4. Runtime DLL load: `LoadLibraryExW` loads the protected runtime (`Interface/Source/Main.cpp:2682`).
5. Export resolution binds `runtime.memory_inject` from the runtime DLL (`Interface/Source/Main.cpp:2726`).
6. Injection call: `runtime.memory_inject(reinterpret_cast<MEMORY_INJECTIONDATA *>(&data))` (`Interface/Source/Main.cpp:4578`).
7. Runtime memory injection body: `Memory_InjectBody` validates and prepares mapping (`Ameger/Injection/Injection.cpp:169`).
8. Manual mapping shell entry: `ManualMapping_Shell` (`Ameger/Injection/ManualMapping/ManualMapping.cpp:1715`).
9. Thread execution: `SR_HijackThread` (`Ameger/Execution/ThreadHijacking.cpp:2052`), delegating to `SR_HijackThreadOnce` (`Ameger/Execution/ThreadHijacking.cpp:829`).
10. Final thread path: remote shell stack executes the injected routine and the hijacked thread resumes with the new routine result.

Alternate paths and selection:
- TLS callbacks: `MMI_RunTlsCallbacks` (`Ameger/Injection/ManualMapping/ManualMapping.cpp:2579`), gated by `ExecuteTLS` / `LockLoaderLock` config (`Interface/Source/Main.cpp:2416`, `:2424`).
- Exception handlers: `MMI_EnableExceptions` (`Ameger/Injection/ManualMapping/ManualMapping.cpp:2350`), gated by `EnableExceptions` (`Interface/Source/Main.cpp:2432`).
- Mapping-only path: `MMI_CleanUp` and data-directory cleanup (`Ameger/Injection/ManualMapping/ManualMapping.cpp:3432`, `:2773`).
- APC is not used as an execution vector; execution uses thread hijack (`Ameger/Execution/ThreadHijacking.cpp:2052`).

## MAPPER BOUNDARY

Classification: **IOCTL** — the Mapper communicates with a vulnerable kernel driver through `DeviceIoControl`, not named pipes or shared memory.

Evidence:
- Device name: `Provider::kDeviceName = L"\\.\PdFwKrnl"` (`D:\Ameger\Mapper\Mapper\Provider\Provider.hpp:31`).
- IOCTL code: `Provider::kCopyIoctl = 0x80002014` (`D:\Ameger\Mapper\Mapper\Provider\Provider.hpp:37`).
- Request ABI: packed `Provider::CopyRequest` with `Reserved[16]`, `Destination`, `Source`, `Reserved2`, `Size`, `Reserved3` (`D:\Ameger\Mapper\Mapper\Provider\Provider.hpp:50`–`58`).
- Request fill helper: `Provider::FillCopyRequest` (`D:\Ameger\Mapper\Mapper\Provider\Provider.hpp:64`).
- Invocation: `DeviceIoControl(hDevice, Provider::kCopyIoctl, &request, sizeof(request), nullptr, 0, &bytes_returned, nullptr)` (`D:\Ameger\Mapper\Mapper\Provider\Driver.cpp:1336`).
- Kernel read/write built on `Driver::MemCopy` (`D:\Ameger\Mapper\Mapper\Provider\Driver.cpp:1328`).

## CONFIGURATION SURFACE

Source: `Build/Configuration.ini`; reader: `Interface/Source/Main.cpp`.

| key | section | type | default/recorded value | reader | effect |
|---|---|---|---|---|---|
| `TestMode` | `[General]` | bool Y/N | `N` | `Interface/Source/Main.cpp:2367` | Forces target selection to a scratch target and closes it on run end. |
| `Timeout` | `[General]` | integer ms | `30000` | `Interface/Source/Main.cpp:2375` | Timeout budget for hijack/symbol/import polling; larger values widen donor probing. |
| `SchemaVersion` | `[General]` | integer | `1` | `Interface/Source/Main.cpp:2298` | Schema gate for config parsing. |
| `ProcessName` | `[General]` | quoted string | `"Overwatch.exe"` | `Interface/Source/Main.cpp:2306` | Target process image name; required for non-test mode. |
| `PayloadSha256` | `[General]` | 64-hex string | `551F...279DB` | `Interface/Source/Main.cpp:2310` | Pins the payload digest; missing pin refuses load. |
| `Quiet` | `[General]` | bool | `N` | `Interface/Source/Main.cpp:2363` | Suppresses console chatter while preserving result logging. |
| `HijackScan` | `[General]` | bool | `Y` | `Interface/Source/Main.cpp:2351` | Enables donor/thread scan and handle acquisition trace. |
| `VerboseTrace` | `[General]` | bool | `Y` | `Interface/Source/Main.cpp:2359` | Prints runtime trace and census output. |
| `DetachConsole` | `[General]` | bool | `N` | `Interface/Source/Main.cpp:2371` | Detaches console output from the interactive window. |
| `HandleHijacking` | `[General]` | bool | `Y` | `Interface/Source/Main.cpp:2347` | Allows direct handle hijacking path. |
| `SponsorRoundtrip` | `[General]` | bool | `N` | `Interface/Source/Main.cpp:2355` | Enables sponsor thread roundtrip behavior. |
| `DiscardResultLogOnSuccess` | `[General]` | bool | `N` | `Interface/Source/Main.cpp:2384` | Deletes transcript on successful run when enabled. |
| `AutoConfirm` | `[General]` | bool | `N` | `Interface/Source/Main.cpp:2388` | Skips operator confirmation prompt. |
| `TestTarget` | `[General]` | string | `notepad.exe` | `Interface/Source/Main.cpp:2408` | Target used when `TestMode=Y`. |
| `SurveyMaxMb` | `[General]` | integer MB | `0` | `Interface/Source/Main.cpp:2396` | Limits survey memory in megabytes; 0 means unlimited/default. |
| `SurveyMaxRegions` | `[General]` | integer | `0` | `Interface/Source/Main.cpp:2392` | Limits census region count. |
| `SurveyMaxSampleRegions` | `[General]` | integer | `0` | `Interface/Source/Main.cpp:2400` | Limits sampled census regions. |
| `DonorOwnerBlocklist` | `[General]` | string list | empty | `Interface/Source/Main.cpp:2404` | Blocks donor owner PIDs/image names from sponsor/hijack selection. |
| `ExecuteTLS` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2416` | Runs TLS callbacks after mapping. |
| `RunDLLMain` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2420` | Calls mapped-image `DllMain`. |
| `LockLoaderLock` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2424` | Uses loader lock during mapping. |
| `ResolveImports` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2428` | Resolves imports for the mapped image. |
| `EnableExceptions` | `[ManualMap]` | bool | `N` | `Interface/Source/Main.cpp:2432` | Enables exception-directory setup. |
| `SetPageProtections` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2440` | Applies section page protections. |
| `InitSecurityCookie` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2436` | Initializes security cookie for the mapped image. |
| `ResolveDelayImports` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2444` | Resolves delayed imports. |
| `CleanDataDirectories` | `[ManualMap]` | bool | `Y` | `Interface/Source/Main.cpp:2448` | Erases/cleans data directories during load. |

Security-relevant keys: `PayloadSha256`, `TestMode`, `Quiet`, `HijackScan`, `HandleHijacking`, `DonorOwnerBlocklist`, `AutoConfirm`, and all `[ManualMap]` toggles.

## INVARIANTS

### static_assert invariants

- `LAST_ERROR_INFO` 4-byte alignment — `Ameger/Injection.h:69`: violating breaks error-struct layout consumers.
- `THREAD_EXEC_STATS` alignment to `LONG` — `Ameger/Execution/ThreadHijacking.cpp:24`: violates aligned memory copy/telemetry semantics.
- Hijack shell stack layout — `Ameger/Execution/ThreadHijacking.cpp:67`–`73`: violates remote shell stack base/top/alignment assumptions.
- `SR_REMOTE_DATA` size and offsets — `Ameger/Execution/Routine/StartRoutine.h:80`–`91`: violates remote data layout passed to hijacked thread.
- `MemoryInjectionData` mirrors `MEMORY_INJECTIONDATA` — `Interface/Source/Launcher.h:100`–`123` and `Interface/Source/Main.cpp:776`–`799`: mismatch corrupts injection data passed to the runtime.
- `HijackStats` size/offset — `Ameger/Core/Foundation/Primitives/InjectionTypes.h:45`–`46`.
- `THREAD_EXEC_STATS` size/offsets — `Ameger/Core/Foundation/Primitives/InjectionTypes.h:82`–`94`.
- `MAP_STATS`, `STRING_STATS`, telemetry sizes — `Ameger/Core/Foundation/Primitives/InjectionTypes.h:126`, `:138`, `:218`–`220`.
- Windows 11 LDR offsets — `Ameger/NT/Windows11.h:104`–`113`: violates Windows 11 LDR layout assumptions.
- PEB/LDR_DATA/UNICODE_STRING layout — `Ameger/NT/NTDefinitions.h:313`–`322`, `:429`–`431`.
- Config magic size — `Interface/Source/Main.cpp:2127`: encrypted config magic must remain 8 chars plus null.

### Struct/const offsets, sizes, magic, version

- `MEMORY_INJECTIONDATA` ABI: launcher and runtime must agree on size/offsets (`Interface/Source/Main.cpp:776`–`799`, `Ameger/Injection.h`).
- `SR_REMOTE_DATA`: size 96 and fixed offsets (`Ameger/Execution/Routine/StartRoutine.h:80`–`91`).
- `UNICODE_STRING`, `CLIENT_ID`, `ANSI_STRING`, `PEB_LDR_DATA` fixed offsets (`Ameger/NT/NTDefinitions.h:313`–`322`).
- `LDR_DDAG_NODE_WIN11` and `LDR_DATA_TABLE_ENTRY_WIN11` offsets (`Ameger/NT/Windows11.h:104`–`113`).
- Runtime ABI version: `AMEGER_RUNTIME_ABI_VERSION = 20261024u` (`Ameger/Injection.h:5`); if violated, launcher/runtime version mismatch causes load refusal.

### Constants mirrored between C++ and build/asm/ini

- `AMEGER_RUNTIME_ABI_VERSION` (`Ameger/Injection.h:5`) is mirrored to `Interface/Source/Launcher.h` through `f_GetRuntimeAbiVersion` (`Interface/Source/Launcher.h:141`) and consumed by launcher verification.
- `SR_SHELL_STACK_*` and hijack page constants appear in C++ and assembly stub support (`Ameger/Execution/ThreadHijacking.cpp:67`–`73`; `Ameger/Execution/Stub/RemoteThreadHijack.asm`).
- `SC_Nt*` FNV-1a syscall name hashes are defined in `Ameger/Native/Syscall.h:22`–`39` and consumed by `Ameger/Native/Syscall.cpp:88`–`103`.
- Build config magic and payload pin are mirrored between `Build/Configuration.ini`, encrypted deployed config, and launcher verification (`Build/Configuration.ini:6`, `Interface/Source/Main.cpp:2310`).

### Build-order dependencies

- `Build/Executors/Create.bat:146`: verify merged `.code` sections before `BuildPE.ps1` mutates section names.
- `Build/Executors/Create.bat:191`/`:199`: runtime hash must be available before building the launcher.
- `Build/Executors/Create.bat:162`/`Build/Executors/Protect.bat:90`: names state must be written before protection stages resolve deployed names.
- `Build/Executors/Create.bat:118`/`:124`: seed generation must precede MSBuild mutation args.

## .analysis SUMMARY

Part A — Thread 761091 OP (`.analysis:109`): verbatim preservation of the original question and claims about Warden/Eidolon; constraints: keep claims tagged `[SRC]` verbatim.

Part B — Reply thread pp. 1–3 (`.analysis:533`): dispute where Warden lives; central technical claim `[SRC]`; streamed argument is `[MY synthesis]`; fabrication allegation `[UNV]`. Constraints: Warden placement and stream-based defense require source attribution.

Part C — Three additional threads (`.analysis:604`): tutorial `[SRC]`, source-level Eidolon internal call `[SRC]`, `Overwatch_Loader.dll` Warden module analysis `[SRC]`, obfuscator info, independent AutoDump tooling, and Blizzard statement `[SRC]`.

Part D — Verification (`.analysis:893`): marks prior claims as WRONG, UNSUPPORTED, or RESOLVED (`.analysis:898`–`1136`); D13 records live read-back confirmation and D14 marks build-pinned values stale.

Part E — Retracted (`.analysis:1249`): Part E was withdrawn after live measurement (`E0`); correction E1a fixes census labeling; E2 records what the live run settled.

Part F — Implications (`.analysis:1388`): F1 closes open questions from live measurements; F2 records a live defect found and fixed; F3 updates priorities; F4 standing decisions plus new decisions F4a–F4h covering elevated launcher environment, CFG declaration readability, screened donor owner, missing loader list, brokered same-named processes, excluded thread handles, test mode purpose, and shipped release verification.

Part F2 — Real census of `Overwatch.exe` (`.analysis:1887`): single import named, encrypted core located structurally, in-image/free-space split, second-process reproduction, and re-confirmed facts.

Part F6 — Mitigation ledger (`.analysis:2004`): mitigation tracking added on 2026-10-25.

Part G — Open questions (`.analysis:2073`): unresolved kernel/hypervisor mapping, zero-residue re-map, and Ob callback attribution.

Part H — Sources and access log (`.analysis:2112`): source/provenance tracking.

Part K — Kernel phase K0 census baseline (`.analysis:2219`): `--census=flt` bugcheck 0x1E, FltEnumerateFilters ABI, defect fixes, post-fix baseline, and verification status (`.analysis:2227`–`2347`).
