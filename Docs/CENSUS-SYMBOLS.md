# TASK-001 Census: Symbol Map

D:\Ameger\Injector\Ameger\Core\Foundation\Main.cpp — 337 lines — sha12:CD66D40B2D29
INCLUDES:
- "Core/Foundation/Error.h" [project] (Main.cpp:2)
- "Core/Utility/Tools/Tools.h" [project] (Main.cpp:4)
- "Injection/Injection.h" [project] (Main.cpp:5)
- "System/Import/ImportHandler.h" [project] (Main.cpp:6)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct SymbolWorkerParams (Main.cpp:44) fields/constants: `Slot`, `ModulePath`, `CacheRoot`
FUNCTIONS:
- `void CloseEventHandle(HANDLE & handle)` — Main.cpp:26–34
  Summary: Closes an event handle when it is open and clears the local pointer.
- `void CloseRuntimeEvents()` — Main.cpp:35–42
  Summary: Closes running, interrupted, interrupt, and interrupt-import event handles.
- `void StopRuntimeWorkers()` — Main.cpp:50–66
  Summary: Signals interrupt events and joins the symbol/import worker threads.
- `void TeardownRuntime()` — Main.cpp:67–82
  Summary: Releases worker threads, events, and runtime state during shutdown.
- `DWORD WINAPI SymbolWorkerEntry(void * param)` — Main.cpp:83–109
  Summary: Thread entry for the symbol-resolution worker; validates arguments and fills the async worker slot.
- `DWORD WINAPI ImportWorkerEntry(void * param)` — Main.cpp:110–133
  Summary: Thread entry for the import-resolution worker; validates arguments and fills the async worker slot.
- `DWORD RuntimeInitializationFailed(DWORD error_code)` — Main.cpp:134–141
  Summary: Records an initialization failure and returns the error code.
- `DWORD __stdcall InitializeRuntime()` — Main.cpp:143–265
  Summary: Runs the runtime initialization state machine: OS build, module path, symbol/import workers, events, and syscall layer setup.
- `DWORD __stdcall ShutdownRuntime()` — Main.cpp:266–317
  Summary: Claims the shutting-down state, checks the injection gate, and tears down runtime state.
- `DWORD __stdcall GetRuntimeAbiVersion()` — Main.cpp:318–324
  Summary: Returns the runtime ABI version constant.
- `BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, void * pReserved)` — Main.cpp:325–337
  Summary: Handles DLL_PROCESS_ATTACH by starting runtime initialization and registering shutdown handling.

KEYWORD_LINES:
- keyword lines in `InitializeRuntime` (Main.cpp:143–265):
  symbol_cache_root = g_RootPathW + AMEGER_SCRATCH_LEAF_DIR + L"\\";

D:\Ameger\Injector\Ameger\Core\Utility\Header\PrecompiledHeader.cpp — 130 lines — sha12:D28F8BD58CC4
INCLUDES:
- "Core/Foundation/Error.h" [project] (PrecompiledHeader.cpp:2)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)` — PrecompiledHeader.cpp:6–23
  Summary: Publishes a raw print callback used by custom_print.
- `void ImTheTrashMan(const wchar_t * expression, const wchar_t * function, const wchar_t * file, unsigned int line, uintptr_t pReserved)` — PrecompiledHeader.cpp:24–32
  Summary: Assertion failure handler that prints expression, function, file, and line.
- `void custom_print(int indention_offset, const char * format, ...)` — PrecompiledHeader.cpp:33–130
  Summary: Formats an indented message, allocates a buffer, calls vsprintf_s, and dispatches through the raw print callback under a lock.

KEYWORD_LINES:
- keyword lines in `custom_print` (PrecompiledHeader.cpp:33–130):
  void custom_print(int indention_offset, const char * format, ...)
  if (indention_offset < 0)
  indention_offset = 0;
  char * buffer = new(std::nothrow) char[size + static_cast<size_t>(indention_offset)]();
  memset(buffer, '\x20', indention_offset);
  result = vsprintf_s(buffer + indention_offset, size, format, args);
  buffer = new(std::nothrow) char[size + indention_offset]();
  memset(buffer, '\x20', indention_offset);
  AcquireSRWLockExclusive(&g_print_lock);
  ReleaseSRWLockExclusive(&g_print_lock);

D:\Ameger\Injector\Ameger\Core\Utility\Tools\Tools.cpp — 940 lines — sha12:36F69D54FFE4
INCLUDES:
- "Core/Utility/Tools/Tools.h" [project] (Tools.cpp:2)
- "../../../Injection.h" [project] (Tools.cpp:4)
- "System/Import/ImportHandler.h" [project] (Tools.cpp:5)
- <bcrypt.h> [system] (Tools.cpp:6)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct ScratchTreeEntry (Tools.cpp:330) fields/constants: `Path`, `Depth`
- struct ERROR_RING_RECORD (Tools.cpp:726) fields/constants: `ErrorCode`, `AdvErrorCode`, `Line`, `Flags`, `bNative`
FUNCTIONS:
- `BOOL CALLBACK InitOSVersionOnce(PINIT_ONCE, PVOID parameter, PVOID *)` — Tools.cpp:20–69
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD GetOSVersion(DWORD * error_code)` — Tools.cpp:71–81
  Summary: Initializes and returns the Windows version via an InitOnce helper.
- `DWORD GetOSBuildVersion()` — Tools.cpp:82–91
  Summary: Returns the cached Windows build number.
- `bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family)` — Tools.cpp:92–162
  Summary: Maps Windows build numbers to supported layout-family constants.
- `DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags)` — Tools.cpp:163–188
  Summary: Validates an in-memory PE against target machine, size, and layout rules.
- `bool GetOwnModulePathW(std::wstring & out)` — Tools.cpp:189–209
  Summary: Resolves the current module path into a wide string.
- `bool GetSymbolCacheRoot(std::wstring & out)` — Tools.cpp:210–274
  Summary: Creates or returns the root directory for symbol cache storage.
- `bool BuildStablePdbCachePath(const std::wstring & pdb_name, const std::wstring & guid_and_age, std::wstring & out)` — Tools.cpp:275–321
  Summary: Builds a stable cache path for a PDB name plus GUID/age.
- `bool DeleteScratchTree(const std::wstring & root)` — Tools.cpp:338–443
  Summary: Recursively deletes a scratch directory tree and reparse points.
- `bool DeleteSymbolCacheRoot(const std::wstring & root)` — Tools.cpp:445–473
  Summary: Deletes an owned symbol cache root.
- `bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code)` — Tools.cpp:474–534
  Summary: Uses IsWow64Process2 to verify target process architecture.
- `bool AllowDirectHandleFallback()` — Tools.cpp:535–547
  Summary: Returns a config-driven toggle for direct handle fallback.
- `bool SymbolDownloadDisabled()` — Tools.cpp:548–560
  Summary: Returns a config-driven toggle that disables symbol downloads.
- `bool IsScratchLeafName(const std::wstring & leaf)` — Tools.cpp:568–596
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsOwnedScratchRoot(const std::wstring & root)` — Tools.cpp:608–720
  Summary: Validates that a scratch root is owned by this process.
- `void ErrorLog(const ERROR_INFO & info)` — Tools.cpp:748–773
  Summary: Appends an error record to the error log under an SRW lock.
- `DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out)` — Tools.cpp:774–817
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __stdcall ClearLastErrorInfo()` — Tools.cpp:818–834
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool StartAsyncWorker(ASYNC_WORKER_SLOT & slot, LPTHREAD_START_ROUTINE entry, void * param)` — Tools.cpp:835–864
  Summary: Starts a worker thread and stores its handle and state in the async worker slot.
- `bool PollAsyncWorker(ASYNC_WORKER_SLOT & slot)` — Tools.cpp:865–874
  Summary: Checks whether an async worker has completed and captures its result.
- `void JoinAsyncWorker(ASYNC_WORKER_SLOT & slot)` — Tools.cpp:875–889
  Summary: Joins the worker thread.
- `bool WaitAsyncWorkerThread(const ASYNC_WORKER_SLOT & slot)` — Tools.cpp:890–899
  Summary: Waits on the worker completion event and returns success.
- `void __stdcall StartDownload()` — Tools.cpp:924–940
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `InitOSVersionOnce` (Tools.cpp:20–69):
  HMODULE hNtdll = GetModuleHandleW(ntdll_name.get());
  if (!hNtdll)
  auto pRtlGetVersion = ReCa<f_RtlGetVersion>(GetProcAddress(hNtdll, rtlver_name.get()));
- keyword lines in `GetSymbolCacheRoot` (Tools.cpp:210–274):
  static_assert(kAlphabetChars == 62, "the scratch alphabet must stay 62 characters");
- keyword lines in `DeleteScratchTree` (Tools.cpp:338–443):
  LOG(1, "Failed To Delete A File In Scratch Storage = 0x%08X (%ls)\n", GetLastError(), child.c_str());
  LOG(1, "Failed To Remove A Reparse Point In Scratch Storage = 0x%08X (%ls)\n", GetLastError(), child.c_str());
  LOG(1, "Failed To Remove A Directory In Scratch Storage = 0x%08X (%ls)\n", remove_error, directories[i - 1].c_str());
- keyword lines in `IsScratchLeafName` (Tools.cpp:568–596):
  if (leaf == AMEGER_SCRATCH_LEAF_DIR)
- keyword lines in `ErrorLog` (Tools.cpp:748–773):
  AcquireSRWLockExclusive(&g_ErrorLogLock);
  ReleaseSRWLockExclusive(&g_ErrorLogLock);
- keyword lines in `GetLastErrorInfo` (Tools.cpp:774–817):
  AcquireSRWLockShared(&g_ErrorLogLock);
  ReleaseSRWLockShared(&g_ErrorLogLock);
- keyword lines in `ClearLastErrorInfo` (Tools.cpp:818–834):
  AcquireSRWLockExclusive(&g_ErrorLogLock);
  ReleaseSRWLockExclusive(&g_ErrorLogLock);

D:\Ameger\Injector\Ameger\Execution\Routine\StartRoutine.cpp — 15 lines — sha12:796DB400E91C
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (StartRoutine.cpp:1)
- "Execution/Routine/StartRoutine.h" [project] (StartRoutine.cpp:2)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD Flags, DWORD & Out, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data)` — StartRoutine.cpp:4–15
  Summary: Validates routine arguments and delegates to the thread-hijack routine execution path.

KEYWORD_LINES:
- keyword lines in `StartRoutine` (StartRoutine.cpp:4–15):
  return SR_ERR_INVALID_LAUNCH_METHOD;
  return SR_HijackThread(hTargetProc, pRoutine, pArg, Out, Timeout, Flags, SponsorThread, SponsorTid, CompletionEvent, error_data);

D:\Ameger\Injector\Ameger\Execution\ThreadHijacking.cpp — 2137 lines — sha12:92BA584D1A15
INCLUDES:
- <intrin.h> [system] (ThreadHijacking.cpp:2)
- <TlHelp32.h> [system] (ThreadHijacking.cpp:4)
- "Core/Foundation/Primitives/ResourceGuard.h" [project] (ThreadHijacking.cpp:5)
- "Execution/Routine/StartRoutine.h" [project] (ThreadHijacking.cpp:7)
- "System/Handle/HandleHijack.h" [project] (ThreadHijacking.cpp:8)
- "Injection/Injection.h" [project] (ThreadHijacking.cpp:9)
- "Native/Syscall.h" [project] (ThreadHijacking.cpp:10)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct DeferredTrampoline (ThreadHijacking.cpp:449) fields/constants: `Process`, `Thread`, `Base`
FUNCTIONS:
- `void StoreThreadExecStat(DWORD & Field, DWORD Value)` — ThreadHijacking.cpp:16–20
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StoreThreadExecStats(const THREAD_EXEC_STATS & Src)` — ThreadHijacking.cpp:21–38
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LoadThreadExecStats(THREAD_EXEC_STATS & Dst)` — ThreadHijacking.cpp:39–48
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsSafeWaitReason(KWAIT_REASON reason)` — ThreadHijacking.cpp:83–87
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResumeThreadWithRetry(HANDLE hThread)` — ThreadHijacking.cpp:88–116
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsWorkerTid(HANDLE hTargetProc, DWORD tid)` — ThreadHijacking.cpp:117–144
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsExcluded(const std::vector<DWORD> & excluded, DWORD tid)` — ThreadHijacking.cpp:145–154
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ThreadCensusEnabled()` — ThreadHijacking.cpp:160–169
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LogThreadCensus(HANDLE hTargetProc, ProcessInformation & pi, const std::vector<DWORD> & excluded, DWORD selected_tid)` — ThreadHijacking.cpp:170–240
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD FindHijackThreadToolhelp(HANDLE hTargetProc, const std::vector<DWORD> & excluded)` — ThreadHijacking.cpp:247–358
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD FindHijackThread(ProcessInformation & processInformation, const std::vector<DWORD> & excluded, bool * out_was_running = nullptr, bool allow_waiting = true)` — ThreadHijacking.cpp:359–447
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void CloseDeferredTrampoline(DeferredTrampoline & Entry)` — ThreadHijacking.cpp:461–477
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool EnqueueDeferredTrampoline(HANDLE Process, HANDLE Thread, void * Base)` — ThreadHijacking.cpp:478–555
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool DeferredProcessGone(HANDLE Process)` — ThreadHijacking.cpp:556–572
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ReapDeferredTrampolines()` — ThreadHijacking.cpp:573–770
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ProbeFpCaps(DWORD & OutFlags, DWORD & OutMask, const BYTE * pStatePage)` — ThreadHijacking.cpp:772–827
  Summary: Probes floating-point/SSE/AVX state page capabilities from saved thread state.
- `DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)` — ThreadHijacking.cpp:828–2027
  Summary: Suspends the target thread, saves FP state, allocates a shell stack, writes shell code and state, restores context, and resumes the thread.
- `bool IsRetryableHijackFailure(DWORD code)` — ThreadHijacking.cpp:2028–2050
  Summary: Classifies hijack failure codes as retryable.
- `DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data)` — ThreadHijacking.cpp:2051–2121
  Summary: Retry wrapper around the single-attempt thread hijack path.
- `void ResetThreadExecStats()` — ThreadHijacking.cpp:2122–2127
  Summary: Resets thread execution telemetry counters.
- `void __stdcall GetLastThreadExecStats(THREAD_EXEC_STATS * Out)` — ThreadHijacking.cpp:2128–2137
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `StoreThreadExecStats` (ThreadHijacking.cpp:21–38):
  static_assert(sizeof(THREAD_EXEC_STATS) % sizeof(LONG) == 0, "THREAD_EXEC_STATS must be a whole number of LONGs");
- keyword lines in `ResumeThreadWithRetry` (ThreadHijacking.cpp:88–116):
  const NTSTATUS status = ScNtResumeThread(hThread, nullptr);
- keyword lines in `IsWorkerTid` (ThreadHijacking.cpp:117–144):
  if (NT_FAIL(ScNtQueryInformationThread(hThread.get(), THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)) || !tbi.TebBaseAddress)
- keyword lines in `LogThreadCensus` (ThreadHijacking.cpp:170–240):
  if (ht && NT_SUCCESS(ScNtQueryInformationThread(ht.get(), THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)))
  LOG(1, "  0x%04X   %-8s %-11d %p   %s (0x%04X)  %s\n",
- keyword lines in `FindHijackThreadToolhelp` (ThreadHijacking.cpp:247–358):
  if (!NT_FAIL(ScNtQueryInformationThread(ht.get(), static_cast<THREADINFOCLASS>(9), &start, sizeof(start), nullptr)) && start)
- keyword lines in `EnqueueDeferredTrampoline` (ThreadHijacking.cpp:478–555):
  AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
  ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
- keyword lines in `ReapDeferredTrampolines` (ThreadHijacking.cpp:573–770):
  AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
  ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
  SR_REMOTE_STATE state = SR_REMOTE_STATE::SR_RS_ExecutionPending;
  if (!ScReadProcessMemory(Entry.Process, ReCa<BYTE *>(Entry.Base) + kDeferredCodePage, &state, sizeof(state), nullptr))
  if (state == SR_REMOTE_STATE::SR_RS_ExecutionPending)
  const NTSTATUS rewind_suspend = ScNtSuspendThread(Entry.Thread, &rewind_previous);
  if (NT_SUCCESS(ScNtGetContextThread(Entry.Thread, &rewind)))
  const BYTE * state_page = ReCa<const BYTE *>(Entry.Base) + kDeferredCodePage;
  ScReadProcessMemory(Entry.Process, state_page + SR_SAVED_RSP, &saved_rsp, sizeof(saved_rsp), nullptr) &&
  if (NT_SUCCESS(ScNtSetContextThread(Entry.Thread, &rewind)))
  if (NT_FAIL(ScNtSuspendThread(Entry.Thread, &previous)))
  const bool have_context = NT_SUCCESS(ScNtGetContextThread(Entry.Thread, &ctx)) != FALSE;
  if (!have_context || (ctx.Rip >= base && ctx.Rip < base + kDeferredCodePage))
  AcquireSRWLockExclusive(&g_DeferredTrampolineLock);
  ReleaseSRWLockExclusive(&g_DeferredTrampolineLock);
- keyword lines in `ProbeFpCaps` (ThreadHijacking.cpp:772–827):
  static void ProbeFpCaps(DWORD & OutFlags, DWORD & OutMask, const BYTE * pStatePage)
  __cpuidex(regs, 0xD, 0);
  const DWORD supported = static_cast<DWORD>(regs[0]) & SR_FP_XCR0_MASK;
  const DWORD needed = (supported & SR_FP_XCR0_AVX)
  ? (SR_FP_XSAVE_LEGACY_BYTES + SR_FP_AVX_BYTES)
  : SR_FP_XSAVE_LEGACY_BYTES;
  if (needed > SR_FP_AREA_SIZE)
  const ULONG_PTR area = reinterpret_cast<ULONG_PTR>(pStatePage) + SR_FP_AREA;
  OutFlags = SR_FP_FLAG_XSAVE;
- keyword lines in `SR_HijackThreadOnce` (ThreadHijacking.cpp:828–2027):
  static DWORD SR_HijackThreadOnce(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, const std::vector<DWORD> & excluded, ERROR_DATA & error_data)
  LOG(2, "Begin SR_AcquireThread\n");
  return SR_HT_ERR_PROC_INFO_FAIL;
  && NT_SUCCESS(ScNtDuplicateObject(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
  return SR_HT_ERR_NO_THREADS;
  if (!(Flags & INJ_NO_DONOR_SCAN))
  return SR_HT_ERR_OPEN_REFUSED;
  return SR_HT_ERR_OPEN_THREAD_FAIL;
  static_assert(SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR) <= kHijackStatePage,
  return SR_HT_ERR_STUB_PATCH_FAIL;
  const size_t state_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadState) - shellcode_begin);
  const size_t return_target_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(RemoteThreadReturnTarget) - shellcode_begin);
  if (return_target_offset < state_offset ||
  return_target_offset + sizeof(ULONG_PTR) > shellcode_size ||
  state_area_size < SR_FP_AREA + SR_FP_AREA_SIZE + sizeof(ULONG_PTR))
  static_cast<unsigned long long>(state_offset),
  static_cast<unsigned long long>(return_target_offset),
  return SR_HT_ERR_STUB_PATCH_FAIL;
  const size_t code_size = state_offset;
  const size_t data_size = shellcode_size - state_offset;
  const size_t pad = kHijackCodePage - code_size;
  if (code_size >= kHijackCodePage || data_size > kHijackCodePage)
  return SR_HT_ERR_STUB_PATCH_FAIL;
  std::vector<BYTE> staged(kHijackCodePage + data_size, 0x00);
  return SR_HT_ERR_CANT_ALLOC_MEM;
  memcpy(staged.data() + kHijackCodePage, shellcode.data() + state_offset, data_size);
  const BYTE lea_prefix[3] = { 0x48, 0x8D, 0x1D };
  const BYTE jmp_prefix[2] = { 0xFF, 0x25 };
  const size_t site_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(label) - shellcode_begin);
  if (site_offset + prefix_len + sizeof(int) > code_size)
  if (memcmp(staged.data() + site_offset, prefix, prefix_len) != 0)
  memcpy(&disp, staged.data() + site_offset + prefix_len, sizeof(disp));
  memcpy(staged.data() + site_offset + prefix_len, &disp, sizeof(disp));
  return SR_HT_ERR_STUB_PATCH_FAIL;
  const BYTE teb_read_prefix[5] = { 0x65, 0x44, 0x8B, 0x1C, 0x25 };
  const BYTE teb_write_prefix[5] = { 0x65, 0x44, 0x89, 0x1C, 0x25 };
  const size_t site_offset = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(label) - shellcode_begin);
  if (site_offset + sizeof(teb_read_prefix) + sizeof(DWORD) > code_size)
  if (memcmp(staged.data() + site_offset, prefix, sizeof(teb_read_prefix)) != 0)
  memcpy(staged.data() + site_offset + sizeof(teb_read_prefix), &teb_last_error, sizeof(teb_last_error));
  return SR_HT_ERR_STUB_PATCH_FAIL;
  if (NT_FAIL(ScNtSuspendThread(hThread, &sr_suspend)))
  return SR_HT_ERR_SUSPEND_FAIL;
  return SR_HT_ERR_SUSPEND_FAIL;
  if (NT_FAIL(ScNtGetContextThread(hThread, &OldContext)))
  return SR_HT_ERR_GET_CONTEXT_FAIL;
  const size_t staged_return_offset = kHijackCodePage + (return_target_offset - state_offset);
  const size_t staged_state_offset = kHijackCodePage;
  *reinterpret_cast<ULONG_PTR *>(staged.data() + staged_return_offset) = OldRIP;
  auto * remote_data = reinterpret_cast<SR_REMOTE_DATA *>(staged.data() + staged_state_offset);
  BYTE * pState = ReCa<BYTE *>(pMem) + kHijackCodePage;
  remote_data->ShellCw = 0x037F;
  remote_data->ShellMxcsr = 0x01F80;
  const ULONG_PTR shell_stack_base = ReCa<ULONG_PTR>(pState) + SR_SHELL_STACK_BASE;
  LOG(1, "[ThreadHijack] [*] Context Captured: Target RIP = 0x%llX | RSP = 0x%llX\n", (unsigned long long)OldRIP, (unsigned long long)OldContext.Rsp);
  LOG(1, "[ThreadHijack] [*] Floating-Point State: Mode = %s | Ceiling Mask = 0x%X | Area = %u Bytes\n", remote_data->FpFlags ? "XSAVE" : "FXSAVE", remote_data->FpMask, SR_FP_AREA_SIZE);
  LOG(1, "[ThreadHijack] [*] Staging: VA = %p | Code RX = 0x1000 | State RW = 0x1000 | Shell Stack RW = %llu Bytes\n",
  LOG(1, "[ThreadHijack] [*] RIP Redirection: 0x%llX -> %p\n", (unsigned long long)OldRIP, pRemoteFunc);
  LOG(2, "Remote Thread Shell Prepared (W^X Split: Code RX 0x1000, State RW)\n");
  return SR_HT_ERR_WPM_FAIL;
  const BOOL guard_page_ok = ScProtectMemory(hTargetProc, ReCa<BYTE *>(pMem) + kHijackCodePage + kHijackStatePage, kHijackGuardPage, PAGE_NOACCESS);
  LOG(2, "Guard Page Protect(NOACCESS) Failed\n");
  LOG(2, "Guard Page Established (NOACCESS) Between State Page And Shell Stack\n");
  if (!ScProtectMemory(hTargetProc, pCode, kHijackCodePage, PAGE_EXECUTE_READ))
  LOG(2, "Protect(RX) Failed\n");
  return SR_HT_ERR_WPM_FAIL;
  if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
  return SR_HT_ERR_SET_CONTEXT_FAIL;
  if (NT_FAIL(ScNtResumeThread(hThread, &sr_resume)))
  if (NT_FAIL(ScNtSetContextThread(hThread, &OldContext)))
  return SR_HT_ERR_RECOVERY_REQUIRED;
  return SR_HT_ERR_RESUME_FAIL;
  SR_REMOTE_DATA data{ };
  data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
  constexpr ULONG_PTR kStubFrameWindow = 0x100;
  const ULONG_PTR code_end = code_base + kHijackCodePage;
  if (NT_FAIL(ScNtSuspendThread(hThread, nullptr)))
  if (NT_SUCCESS(ScNtGetContextThread(hThread, &ctx)))
  SR_REMOTE_DATA fresh{ };
  fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
  const bool finished = fresh_ok && fresh.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished;
  restored = NT_SUCCESS(ScNtSetContextThread(hThread, &ctx)) != FALSE;
  if (!NT_SUCCESS(ScNtGetContextThread(hThread, &probe)))
  return probe.Rip < code_base || probe.Rip >= code_base + kHijackCodePage;
  auto ReclaimOrRetainTrampoline = [&](bool context_restored, SR_REMOTE_STATE State) -> void
  // the shell stack begins SR_SHELL_STACK_BASE bytes into it. These values
  const ULONG_PTR shell_base = ReCa<ULONG_PTR>(pState) + SR_SHELL_STACK_BASE;
  const ULONG_PTR shell_end = shell_base + SR_SHELL_STACK_SIZE;
  LOG(2, "Completion Event Signaled; Polling The State Page At Full Speed\n");
  if (data.State == SR_REMOTE_STATE::SR_RS_Executing &&
  // The stub rewrote SR_FP_MASK with the mask it actually used, which
  LOG(1, "[ThreadHijack] [*] Polling Execution: State = Finished | Iterations = %u | Elapsed = %u ms | Return Value = 0x%08X\n", poll_iterations, exec_ms, data.Ret);
  completion_seen ? "Signaled Before The State Page Settled" : "Not Observed Before Settlement",
  LOG(1, "[ThreadHijack] [+] Shell Stack Pivot: RSP = 0x%llX Inside 0x%llX..0x%llX | Victim Stack Spill = %u Bytes (Register Values Only) | Cycles = %llu\n",
  StoreThreadExecStat(g_ThreadExecStats.FailCode, SR_HT_ERR_SHELL_PIVOT_INVALID);
  LOG(1, "[ThreadHijack] [x] Shell Stack Pivot Not Verified: RSP = 0x%llX Outside 0x%llX..0x%llX; The Victim Stack May Have Been Used\n",
  if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= kStartupProbeMs)
  if (!nudge_sent && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending && waited >= nudge_after_ms)
  if (bRet && data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
  StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? error_data.AdvErrorCode : SR_HT_ERR_RECOVERY_REQUIRED);
  return context_restored ? SR_ERR_INTERRUPT : SR_HT_ERR_RECOVERY_REQUIRED;
  return SR_ERR_TARGET_EXITED;
  if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
  StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED);
  return context_restored ? SR_HT_ERR_RPM_FAIL : SR_HT_ERR_RECOVERY_REQUIRED;
  if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionPending)
  SR_REMOTE_DATA fresh{ };
  fresh.State = SR_REMOTE_STATE::SR_RS_ExecutionPending;
  StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? SR_HT_ERR_REMOTE_PENDING_TIMEOUT : SR_HT_ERR_RECOVERY_REQUIRED);
  return SR_HT_ERR_REMOTE_PENDING_TIMEOUT;
  return SR_HT_ERR_RECOVERY_REQUIRED;
  if (NT_FAIL(ScNtSuspendThread(hThread, nullptr)))
  if (NT_SUCCESS(ScNtGetContextThread(hThread, &check_context)))
  const ULONG_PTR code_end = code_base + kHijackCodePage;
  context_restored = NT_SUCCESS(ScNtSetContextThread(hThread, &check_context)) != FALSE;
  LOG(1, "[ThreadHijack] [+] Context Verification: Restored RIP = 0x%llX | Thread Resumed\n", (unsigned long long)OldRIP);
  LOG(1, "[ThreadHijack] [x] Context Verification Failed: RIP = 0x%llX | Not Restored\n", (unsigned long long)OldRIP);
  StoreThreadExecStat(g_ThreadExecStats.FailCode, context_restored ? ERROR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED);
  return context_restored ? SR_ERR_SUCCESS : SR_HT_ERR_RECOVERY_REQUIRED;
- keyword lines in `IsRetryableHijackFailure` (ThreadHijacking.cpp:2028–2050):
  // SR_HT_ERR_RECOVERY_REQUIRED stays non-retryable: that donor may still
  case SR_HT_ERR_NO_THREADS:
  case SR_HT_ERR_SUSPEND_FAIL:
  case SR_HT_ERR_OPEN_THREAD_FAIL:
  case SR_HT_ERR_OPEN_REFUSED:
  case SR_HT_ERR_REMOTE_PENDING_TIMEOUT:
- keyword lines in `SR_HijackThread` (ThreadHijacking.cpp:2051–2121):
  DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & Out, DWORD Timeout, DWORD Flags, ULONG_PTR SponsorThread, DWORD SponsorTid, HANDLE CompletionEvent, ERROR_DATA & error_data)
  DWORD last_code = SR_HT_ERR_NO_THREADS;
  last_code = SR_HijackThreadOnce(hTargetProc, pRoutine, pArg, round_out, remaining, Flags,
  if (last_code == SR_ERR_SUCCESS)
  return SR_ERR_SUCCESS;
  if (last_code != SR_HT_ERR_NO_THREADS)

D:\Ameger\Injector\Ameger\Injection\Injection.cpp — 482 lines — sha12:0CD8011A2F06
INCLUDES:
- "Core/Foundation/Primitives/ResourceGuard.h" [project] (Injection.cpp:2)
- "Injection.h" [project] (Injection.cpp:4)
- "Injection/ManualMapping/ManualMappingCore.h" [project] (Injection.cpp:5)
- "System/Handle/HandleHijack.h" [project] (Injection.cpp:6)
- "Native/Syscall.h" [project] (Injection.cpp:7)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- class InjectionGateGuard (Injection.cpp:113) fields/constants: `m_Acquired`, `m_Acquired`
FUNCTIONS:
- `DWORD OpenTargetProcess(DWORD pid, DWORD access_mask, DWORD flags, ULONG_PTR sponsor_value, UniqueHandle & out, ERROR_DATA & error_data)` — Injection.cpp:12–111
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `public: InjectionGateGuard()` — Injection.cpp:116–127
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `operator bool()` — Injection.cpp:137–141
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data)` — Injection.cpp:144–167
  Summary: Initializes error-data structure fields used by the injection layer.
- `DWORD Memory_InjectBody(MEMORY_INJECTIONDATA * pData)` — Injection.cpp:168–382
  Summary: Executes the memory-injection body: payload write, mapping shell invocation, and result return.
- `DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData)` — Injection.cpp:383–389
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __stdcall GetSymbolState()` — Injection.cpp:390–429
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __stdcall GetImportState()` — Injection.cpp:430–468
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `OpenTargetProcess` (Injection.cpp:12–111):
  bool duplicate_ok = NT_SUCCESS(ScNtDuplicateObject(GetCurrentProcess(), sponsor, GetCurrentProcess(),
  if (!(flags & INJ_NO_DONOR_SCAN))

D:\Ameger\Injector\Ameger\Injection\ManualMapping\ManualMapping.cpp — 3622 lines — sha12:F291521ABB59
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (ManualMapping.cpp:1)
- <TlHelp32.h> [system] (ManualMapping.cpp:3)
- <intrin.h> [system] (ManualMapping.cpp:5)
- "Core/Foundation/Primitives/ResourceGuard.h" [project] (ManualMapping.cpp:6)
- "Injection/ManualMapping/ManualMappingCore.h" [project] (ManualMapping.cpp:8)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `bool WriteRemoteExact(HANDLE hTargetProc, void * address, const void * buffer, SIZE_T size)` — ManualMapping.cpp:22–35
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StoreMapStats(const MAP_STATS & Src)` — ManualMapping.cpp:36–54
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LoadMapStats(MAP_STATS & Dst)` — ManualMapping.cpp:55–64
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StoreExecTelemetry(const VERIFIABLE_EXEC_TELEMETRY & Src)` — ManualMapping.cpp:65–81
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LoadExecTelemetry(VERIFIABLE_EXEC_TELEMETRY & Dst)` — ManualMapping.cpp:82–91
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveRemoteNtdllBaseFromModuleList(DWORD target_pid, ULONG_PTR & base_out)` — ManualMapping.cpp:111–139
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveRemoteNtdllBase(HANDLE hTargetProc, ULONG_PTR & base_out)` — ManualMapping.cpp:140–231
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD HostMapRemoteImage(HANDLE hTargetProc, const INJECTION_SOURCE & source, const PE_IMAGE::VIEW & view,
		MANUAL_MAPPING_DATA & data, void *& base_out, ERROR_DATA & error_data)` — ManualMapping.cpp:239–486
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD MMAP_NATIVE::ManualMap(const INJECTION_SOURCE & Source, HANDLE hTargetProc, DWORD Flags, HINSTANCE & hOut, DWORD Timeout, ULONG_PTR SponsorThread, DWORD SponsorTid, ERROR_DATA & error_data)` — ManualMapping.cpp:488–1155
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `__forceinline MM_DEPENDENCY_RECORD * BuildDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD ** head, HANDLE DllHandle)` — ManualMapping.cpp:1158–1195
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `__forceinline MM_DEPENDENCY_RECORD * SearchDependencyRecordByHandle(MM_DEPENDENCY_RECORD * head, HANDLE hDll)` — ManualMapping.cpp:1196–1217
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `__forceinline void UnloadAndDeleteDependencyRecord(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * head)` — ManualMapping.cpp:1218–1241
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `__forceinline void FreeDependencyNodeList(MANUAL_MAPPING_FUNCTION_TABLE * f, MM_DEPENDENCY_RECORD * & head)` — ManualMapping.cpp:1242–1260
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$05")) __stdcall MMI_SetExecProtections(MANUAL_MAPPING_DATA * pData, DWORD NewState)` — ManualMapping.cpp:1265–1309
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool __declspec(code_seg(".code$11")) __stdcall MMI_FindLoadedModule(MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule)` — ManualMapping.cpp:1310–1401
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool __declspec(code_seg(".code$11")) __stdcall MMI_AddressInLoadedImage(MANUAL_MAPPING_DATA * pData, const void * Address)` — ManualMapping.cpp:1402–1453
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NTSTATUS __declspec(code_seg(".code$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)` — ManualMapping.cpp:1458–1563
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NTSTATUS __declspec(code_seg(".code$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)` — ManualMapping.cpp:1564–1636
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `LONG __declspec(code_seg(".code$10")) __stdcall MMI_DebugPrintVeh(PEXCEPTION_POINTERS ExceptionInfo)` — ManualMapping.cpp:1653–1669
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:1714–1796
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:1800–2029
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2030–2251
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2252–2348
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2349–2427
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2428–2577
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0F")) __stdcall MMI_RunTlsCallbacks(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2578–2677
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2678–2771
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:2772–3238
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:3239–3430
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)` — ManualMapping.cpp:3431–3534
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD __declspec(code_seg(".code$14")) MMAP_SEC_END()` — ManualMapping.cpp:3539–3543
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ResetMapStats()` — ManualMapping.cpp:3591–3596
  Summary: Resets manual-mapping statistics.
- `void __stdcall GetLastMapStats(MAP_STATS * Out)` — ManualMapping.cpp:3597–3606
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ResetExecTelemetry()` — ManualMapping.cpp:3607–3612
  Summary: Resets execution telemetry counters.
- `void __stdcall GetLastExecTelemetry(VERIFIABLE_EXEC_TELEMETRY * Out)` — ManualMapping.cpp:3613–3622
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `StoreMapStats` (ManualMapping.cpp:36–54):
  static_assert(sizeof(MAP_STATS) % sizeof(LONG) == 0, "MAP_STATS must be a whole number of LONGs");
- keyword lines in `StoreExecTelemetry` (ManualMapping.cpp:65–81):
  static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0, "telemetry must be LONG-multiple");
- keyword lines in `ResolveRemoteNtdllBaseFromModuleList` (ManualMapping.cpp:111–139):
  bool ResolveRemoteNtdllBaseFromModuleList(DWORD target_pid, ULONG_PTR & base_out)
- keyword lines in `ResolveRemoteNtdllBase` (ManualMapping.cpp:140–231):
  bool ResolveRemoteNtdllBase(HANDLE hTargetProc, ULONG_PTR & base_out)
  const NTSTATUS basic_status = ScNtQueryInformationProcess(hTargetProc,
  LOG(1, "ResolveRemoteNtdllBase: The Process Basic Information Query Failed (Status = %08X | PEB = %p)\n",
  return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
  const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
  const DWORD ldr_base_offset = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
  const DWORD ldr_name_offset = dyno.LdrEntryBaseDllName ? dyno.LdrEntryBaseDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, BaseDllName));
  if (peb_ldr_offset + sizeof(void *) > 0x800 ||
  ldr_base_offset + sizeof(void *) > 0x800 ||
  ldr_name_offset + sizeof(UNICODE_STRING) > 0x800)
  if (!ScReadProcessMemory(hTargetProc, ReCa<BYTE *>(basic.pPEB) + peb_ldr_offset, &ldr, sizeof(void *), nullptr) || !ldr)
  LOG(1, "ResolveRemoteNtdllBase: The Loader Pointer Could Not Be Read (PEB = %p | Offset = %08X)\n",
  basic.pPEB, peb_ldr_offset);
  return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
  LOG(1, "ResolveRemoteNtdllBase: The Loader List Head Could Not Be Read (Ldr = %p)\n", ldr);
  return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
  LOG(1, "ResolveRemoteNtdllBase: A Loader List Link Could Not Be Read (Depth = %lu | Address = %p)\n",
  return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
  const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
  if (ScReadProcessMemory(hTargetProc, entry + ldr_name_offset, &name, sizeof(name), nullptr) &&
  if (!ScReadProcessMemory(hTargetProc, entry + ldr_base_offset, &base, sizeof(base), nullptr))
  LOG(1, "ResolveRemoteNtdllBase: The Loader List Was Walked Without Finding ntdll (Depth = %lu)\n",
  return ResolveRemoteNtdllBaseFromModuleList(ScGetProcessId(hTargetProc), base_out);
- keyword lines in `HostMapRemoteImage` (ManualMapping.cpp:239–486):
  const IMAGE_NT_HEADERS * nt = view.NtHeaders;
  NTSTATUS alloc_status = ScNtAllocateVirtualMemory(hTargetProc, &remote_base, 0, &remote_size,
  alloc_status = ScNtAllocateVirtualMemory(hTargetProc, &remote_base, 0, &remote_size,
  static_cast<ULONGLONG>(block->VirtualAddress) + (entries[i] & 0x0FFF);
  const SIZE_T cookie_span = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR);
  ULONGLONG new_cookie = remote_address & 0x0000FFFFFFFFFFFFULL;
  if (new_cookie == 0x2B992DDFA232ULL)
  else if (!(new_cookie & 0x0000FFFF00000000ULL))
  new_cookie |= (new_cookie | 0x4711ULL) << 0x10;
  data.pNtHeaders = ReCa<IMAGE_NT_HEADERS *>(remote_address + mapped_dos->e_lfanew);
  data.pOptionalHeader = &data.pNtHeaders->OptionalHeader;
  data.pFileHeader = &data.pNtHeaders->FileHeader;
  data.ExecProtectionState = MM_EXEC_STATE_MAPPABLE;
  LOG(1, "Host Map: Image Mapped At %p | Size = %08X | Relocation Delta = 0x%llX\n",
- keyword lines in `MMAP_NATIVE::ManualMap` (ManualMapping.cpp:488–1155):
  data.NtOffsets = g_DynamicOffsets;
  const SIZE_T image_span = static_cast<SIZE_T>(source_view.NtHeaders->OptionalHeader.SizeOfImage);
  ScNtDuplicateObject(hTargetProc, completion_event_remote, nullptr, nullptr,
  if (!ResolveRemoteNtdllBase(hTargetProc, remote_ntdll))
  constexpr SIZE_T kStagePage = 0x1000;
  const DWORD remote_stub_hashes[SC_REMOTE_STUB_COUNT] =
  SC_NtAllocateVirtualMemory,
  SC_NtProtectVirtualMemory,
  SC_NtFreeVirtualMemory,
  SC_NtQueryInformationProcess,
  // embedding a `syscall` instruction, so the target never holds a `0F 05`
  const SIZE_T stub_table_size	= static_cast<SIZE_T>(SC_REMOTE_STUB_COUNT) * SC_STUB_SIZE;
  exec_area_size + (kStagePage * 2),
  sizeof(MANUAL_MAPPING_FUNCTION_TABLE) + (kStagePage * 2)
  BYTE * pShells			= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pArg)			+ sizeof(MANUAL_MAPPING_DATA),				kStagePage));
  BYTE * pStubArea		= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pShells)		+ ShellSize,								SC_STUB_AREA_ALIGN));
  BYTE * pFunctionTable	= ReCa<BYTE *>(ALIGN_UP(ReCa<ULONG_PTR>(pStubArea)		+ stub_area_size,							kStagePage));
  table_local->MMIP_SetPageProtections	= ReCa<f_MMI_FUNCTION>(pShells + (ReCa<BYTE *>(MMI_SetPageProtections)		- mmap_sec_base));
  // offset relative to the start of the shell, rebased onto the copy that
  BYTE stub_slab[SC_REMOTE_STUB_COUNT * SC_STUB_SIZE + sizeof(void *)]
  const DWORD Built = BuildSyscallStubs(stub_slab, sizeof(stub_slab), remote_stub_hashes, SC_REMOTE_STUB_COUNT,
  if (Built != SC_REMOTE_STUB_COUNT)
  INIT_ERROR_DATA(error_data, INJ_ERR_SYSCALL_RESOLVE_FAILED);
  LOG(1, "Remote Syscall Stubs Only Partially Built = %u/%u\n", Built, SC_REMOTE_STUB_COUNT);
  return INJ_ERR_SYSCALL_STUB_BUILD_FAILED;
  for (DWORD i = 0; i < SC_REMOTE_STUB_COUNT; ++i)
  if (SyscallServiceOfStub(stub_slab + (i * SC_STUB_SIZE)) == 0)
  case 0: table_local->NtAllocateVirtualMemory	= ReCa<f_NtAllocateVirtualMemory>(pStubArea + i * SC_STUB_SIZE); break;
  case 1: table_local->NtProtectVirtualMemory	= ReCa<f_NtProtectVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
  case 2: table_local->NtFreeVirtualMemory		= ReCa<f_NtFreeVirtualMemory>	(pStubArea + i * SC_STUB_SIZE); break;
  case 3: table_local->NtQueryInformationProcess = ReCa<f_NtQueryInformationProcess>(pStubArea + i * SC_STUB_SIZE); break;
  // The gadget slot travels with the stubs: it holds the ntdll `syscall ; ret`
  // debug-print exception is never raised; landing on a 0xC3 byte executes a
  if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x400)
  if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
  if (start[j] == 0xC3)
  // 16-byte aligned offset that can sit past the end of a page-rounded size.
  const SIZE_T rx_span = ALIGN_UP(code_bytes, kStagePage);
  const NTSTATUS protect_status = ScProtectMemoryStatus(hTargetProc, pShells, rx_span, PAGE_EXECUTE_READ, nullptr, &protected_code);
  LOG(1, "Protect(RX) Failed = %08X | Span = %llx | Base = %p\n",
  if (dwRet != SR_ERR_SUCCESS)
  if (dwRet == SR_HT_ERR_RECOVERY_REQUIRED)
  // Every other failure - including SR_HT_ERR_REMOTE_PENDING_TIMEOUT,
  LOG(1, "[ManualMap] [+] Completion Event: Signaled | NtSetEvent = 0x%08X | Shell Handle Closed\n",
  LOG(1, "[ManualMap] [x] Completion Event: Not Signaled | Status = 0x%08X | Shell Exit Path Was Not Reached\n",
  ScNtDuplicateObject(hTargetProc, data.CompletionEvent, nullptr, nullptr,
  LOG(1, "[ManualMap] [+] Shell Stages: Exceptions = %llu | TLS Callbacks = %llu | Header Cloak = %llu | Directories = %llu | Protections = %llu\n",
  (unsigned long long)data.ExecTelemetry.ProtectStageCycles);
  LOG(1, "[ManualMap] [x] DllMain: Result = 0 (False) | Win32 = 0x%08X | Cycles = %llu -- Payload Refused To Initialize\n",
  LOG(1, "[ManualMap] [+] DllMain: Result = 1 | Win32 = 0x%08X | Cycles = %llu\n",
  LOG(1, "[ManualMap] [+] LoaderLock: Lock = 0x%08X | State = %u | Cookie = 0x%llX | Unlock = 0x%08X\n",
  LOG(1, "[ManualMap] [x] LoaderLock NTSTATUS Non-Zero: Lock = 0x%08X | Unlock = 0x%08X | State = %u\n",
  LOG(1, "[HeaderCloak] [+] Wipe: Span = %llu | MZ = %u | PE = %u | Prot = 0x%08X\n", (unsigned long long)data.ExecTelemetry.PreSectionSpanWiped, data.ExecTelemetry.MZRemnantsFound, data.ExecTelemetry.PERemnantsFound, data.ExecTelemetry.PostWipeProtection);
  LOG(1, "[ManualMap] [*] PageProtections: Not Applied (Shell Aborted Before Protections)\n");
  LOG(1, "[ManualMap] [+] PageProtections: %u Section Records\n", data.SectionProtCount);
- keyword lines in `__declspec` (ManualMapping.cpp:1265–1309):
  DWORD __declspec(code_seg(".code$05")) __stdcall MMI_SetExecProtections(MANUAL_MAPPING_DATA * pData, DWORD NewState)
  if (!pData || !pData->FunctionTable || !pData->pNtHeaders || !pData->pFileHeader)
  if (pData->ExecProtectionState == NewState)
  const ULONG NewProtect = NewState == MM_EXEC_STATE_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READWRITE;
  if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
  pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &sec_size, NewProtect, &old_prot);
  pData->ExecProtectionState = NewState;
- keyword lines in `__declspec` (ManualMapping.cpp:1310–1401):
  bool __declspec(code_seg(".code$11")) __stdcall MMI_FindLoadedModule(MANUAL_MAPPING_DATA * pData, const UNICODE_STRING * FullName, HINSTANCE * hModule)
  if (!pData->FunctionTable->NtQueryInformationProcess)
  if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)))
  const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;
  const DWORD ldr_name_off = dyno.LdrEntryFullDllName ? dyno.LdrEntryFullDllName : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, FullDllName));
  const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
  if (ldr_name_off + sizeof(UNICODE_STRING) > 0x800 || ldr_base_off + sizeof(void *) > 0x800)
  const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
  auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);
  const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
- keyword lines in `__declspec` (ManualMapping.cpp:1402–1453):
  bool __declspec(code_seg(".code$11")) __stdcall MMI_AddressInLoadedImage(MANUAL_MAPPING_DATA * pData, const void * Address)
  if (!pData || !pData->FunctionTable || !pData->FunctionTable->NtQueryInformationProcess || !Address)
  if (NT_FAIL(pData->FunctionTable->NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &Basic, sizeof(Basic), nullptr)) || !Basic.pPEB)
  const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;
  const DWORD ldr_base_off = dyno.LdrEntryDllBase ? dyno.LdrEntryDllBase : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, DllBase));
  const DWORD ldr_image_off = dyno.LdrEntrySizeOfImage ? dyno.LdrEntrySizeOfImage : static_cast<DWORD>(offsetof(LDR_DATA_TABLE_ENTRY_WIN11, SizeOfImage));
  if (ldr_base_off + sizeof(void *) > 0x800 || ldr_image_off + sizeof(ULONG) > 0x800)
  const DWORD peb_ldr_offset = dyno.PebLdr ? dyno.PebLdr : static_cast<DWORD>(offsetof(PEB, Ldr));
  auto * pLdr = *ReCa<PEB_LDR_DATA * const *>(ReCa<const BYTE *>(Basic.pPEB) + peb_ldr_offset);
  const BYTE * entry = ReCa<const BYTE *>(current) - offsetof(LDR_DATA_TABLE_ENTRY_WIN11, InLoadOrderLinks);
- keyword lines in `__declspec` (ManualMapping.cpp:1458–1563):
  NTSTATUS __declspec(code_seg(".code$12")) __stdcall MMIH_PreprocessModuleName(MANUAL_MAPPING_DATA * pData, const char * szModule, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS * CtxFlags)
- keyword lines in `__declspec` (ManualMapping.cpp:1564–1636):
  NTSTATUS __declspec(code_seg(".code$13")) __stdcall MMIH_LoadModule(MANUAL_MAPPING_DATA * pData, UNICODE_STRING * Module, LDRP_LOAD_CONTEXT_FLAGS CtxFlag, HINSTANCE * hModule, MM_DEPENDENCY_RECORD ** head)
  const DYNAMIC_NT_OFFSETS & dyno = pData->NtOffsets;
- keyword lines in `__declspec` (ManualMapping.cpp:1653–1669):
  LONG __declspec(code_seg(".code$10")) __stdcall MMI_DebugPrintVeh(PEXCEPTION_POINTERS ExceptionInfo)
- keyword lines in `__declspec` (ManualMapping.cpp:1714–1796):
  DWORD __declspec(code_seg(".code$01")) __stdcall ManualMapping_Shell(MANUAL_MAPPING_DATA * pData)
  pData->pNtHeaders		= ReCa<IMAGE_NT_HEADERS *>(pData->pImageBase + pData->pDosHeader->e_lfanew);
  pData->pOptionalHeader	= &pData->pNtHeaders->OptionalHeader;
  pData->pFileHeader		= &pData->pNtHeaders->FileHeader;
  pData->ExecTelemetry.DebugPrintVehInstalled |= 0x10u;
  MM_SHELL_STAGE(ProtectStageCycles, f->MMIP_SetPageProtections(pData));
- keyword lines in `__declspec` (ManualMapping.cpp:1800–2029):
  DWORD __declspec(code_seg(".code$06")) __stdcall MMI_LoadImports(MANUAL_MAPPING_DATA * pData)
  IMAGE_IMPORT_DESCRIPTOR * pImportDescr	= nullptr;
  IMAGE_IMPORT_DESCRIPTOR * const pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size);
  pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress);
  if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
  if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
  if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
  if (pImportDescr >= ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + pImportDir->VirtualAddress + pImportDir->Size))
- keyword lines in `__declspec` (ManualMapping.cpp:2030–2251):
  DWORD __declspec(code_seg(".code$07")) __stdcall MMI_LoadDelayImports(MANUAL_MAPPING_DATA * pData)
  IMAGE_DELAYLOAD_DESCRIPTOR	* pDelayImportDescr = nullptr;
  IMAGE_DELAYLOAD_DESCRIPTOR * const pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size);
  pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress);
  if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
  if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
  if (!ansi_import || !import_name_length || import_name_length > 0xFFFF)
  if (pDelayImportDescr >= ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + pDelayImportDir->VirtualAddress + pDelayImportDir->Size))
- keyword lines in `__declspec` (ManualMapping.cpp:2252–2348):
  DWORD __declspec(code_seg(".code$08")) __stdcall MMI_SetPageProtections(MANUAL_MAPPING_DATA * pData)
  ULONG OldProtection = 0;
  // NtProtectVirtualMemory writes the page-rounded base back through the
  pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &HeaderBase, &SizeOut, PAGE_READONLY, &OldProtection);
  ULONG NewProtection = PAGE_NOACCESS;
  if (characteristics & IMAGE_SCN_MEM_EXECUTE)
  if (characteristics & IMAGE_SCN_MEM_READ)
  NewProtection = PAGE_EXECUTE_READ;
  NewProtection = PAGE_EXECUTE;
  if (characteristics & IMAGE_SCN_MEM_WRITE)
  NewProtection = PAGE_READWRITE;
  else if (characteristics & IMAGE_SCN_MEM_READ)
  NewProtection = PAGE_READONLY;
  pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &pSectionBase, &SectionSize, NewProtection, &OldProtection);
- keyword lines in `__declspec` (ManualMapping.cpp:2349–2427):
  DWORD __declspec(code_seg(".code$09")) __stdcall MMI_EnableExceptions(MANUAL_MAPPING_DATA * pData)
  const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
  // table by writing ntdll's .mrdata under LdrProtectMrdata(FALSE) - a
- keyword lines in `__declspec` (ManualMapping.cpp:2428–2577):
  DWORD __declspec(code_seg(".code$0A")) __stdcall MMI_HandleTLS(MANUAL_MAPPING_DATA * pData)
  const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
  block_size = (block_size + 0xF) & ~static_cast<SIZE_T>(0xF);
  block_size = 0x10;
  if (block_size > 0x400000)
- keyword lines in `__declspec` (ManualMapping.cpp:2578–2677):
  DWORD __declspec(code_seg(".code$0F")) __stdcall MMI_RunTlsCallbacks(MANUAL_MAPPING_DATA * pData)
- keyword lines in `__declspec` (ManualMapping.cpp:2678–2771):
  DWORD __declspec(code_seg(".code$0B")) __stdcall MMI_ExecuteDllMain(MANUAL_MAPPING_DATA * pData)
  const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
  const DWORD teb_last_error = pData->NtOffsets.TebLastErrorValue;
  if (teb_last_error && teb_last_error + sizeof(DWORD) <= 0x2000)
  const ULONG_PTR teb = static_cast<ULONG_PTR>(__readgsqword(0x30));
- keyword lines in `__declspec` (ManualMapping.cpp:2772–3238):
  DWORD __declspec(code_seg(".code$0C")) __stdcall MMI_CleanDataDirectories(MANUAL_MAPPING_DATA * pData)
  const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_WRITABLE);
  auto * pImportEnd = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + Size);
  auto * pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  auto * pDelayImportEnd = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + Size);
  auto * pDelayImportDescr = ReCa<IMAGE_DELAYLOAD_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
  auto * pBound = ReCa<IMAGE_BOUND_IMPORT_DESCRIPTOR *>(pData->pImageBase + MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
  // data entry. Both offsets are relative to the resource root.
  constexpr DWORD kMaxResourceDirs = 0x2000;
  if (!entries || entries > 0x800)
  if ((pEntry[e].Name & 0x80000000) != 0)
  const DWORD name_offset = pEntry[e].Name & 0x7FFFFFFF;
  if (MMI_InImage(pData, pResRoot + name_offset, sizeof(IMAGE_RESOURCE_DIRECTORY_STRING)))
  auto * pStr = ReCa<IMAGE_RESOURCE_DIRECTORY_STRING *>(pResRoot + name_offset);
  const DWORD target = pEntry[e].OffsetToData & 0x7FFFFFFF;
  if (MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size ||
  MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = 0;
  MMI_DataDirectory(pData)[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = 0;
  const DWORD ProtRet = MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
- keyword lines in `__declspec` (ManualMapping.cpp:3239–3430):
  DWORD __declspec(code_seg(".code$0D")) __stdcall MMI_CloakHeader(MANUAL_MAPPING_DATA * pData)
  if (!f || !f->NtProtectVirtualMemory || !f->RtlZeroMemory)
  auto * pNt = pData->pNtHeaders;
  if (!pDos || !pNt || !pData->pImageBase)
  const DWORD size_optional	= pNt->FileHeader.SizeOfOptionalHeader;
  DWORD		num_sections	= pNt->FileHeader.NumberOfSections;
  const DWORD size_of_image	= pNt->OptionalHeader.SizeOfImage;
  const DWORD first_section = IMAGE_FIRST_SECTION(pNt)->VirtualAddress;
  DWORD dos_bytes = 0x40;
  pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, PAGE_READWRITE, &old_access);
  if (pScan[i] == 0x4D && pScan[i + 1] == 0x5A)
  if (pScan[i] == 0x50 && pScan[i + 1] == 0x45 && pScan[i + 2] == 0x00 && pScan[i + 3] == 0x00)
  if (pScan[i] == 0x4D && pScan[i + 1] == 0x5A)
  if (pScan[i] == 0x50 && pScan[i + 1] == 0x45 && pScan[i + 2] == 0x00 && pScan[i + 3] == 0x00)
  pData->ntRet = f->NtProtectVirtualMemory(NtCurrentProcess(), &base, &region, final_access, &old_access);
  pData->MapStats.HeaderWipeProtect		= final_access;
  pData->ExecTelemetry.PostWipeProtection = final_access;
- keyword lines in `__declspec` (ManualMapping.cpp:3431–3534):
  DWORD __declspec(code_seg(".code$0E")) __stdcall MMI_CleanUp(MANUAL_MAPPING_DATA * pData)
  MMI_SetExecProtections(pData, MM_EXEC_STATE_EXECUTE);
  f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pFakeSEHDirectory), &Size, MEM_RELEASE);
  f->NtFreeVirtualMemory(NtCurrentProcess(), ReCa<void **>(&pData->pAllocationBase), &Size, MEM_RELEASE);
- keyword lines in `__declspec` (ManualMapping.cpp:3539–3543):
  DWORD __declspec(code_seg(".code$14")) MMAP_SEC_END()

D:\Ameger\Injector\Ameger\Native\Syscall.cpp — 1178 lines — sha12:3E1FDCA71E8F
INCLUDES:
- <new> [system] (Syscall.cpp:2)
- "Native/Syscall.h" [project] (Syscall.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct SYSCALL_ENTRY (Syscall.cpp:73) fields/constants: `NameHash`, `Service`, `Stub`
- struct HARVESTED_ENTRY (Syscall.cpp:80) fields/constants: `Rva`, `Service`
- struct RESOLUTION_INFO (Syscall.cpp:127) fields/constants: `Reconstructed`, `Hooked`, `Rva`
- struct SyscallLockGuard (Syscall.cpp:154) fields/constants: none detected
- struct NOP_PATTERN (Syscall.cpp:326) fields/constants: `Length`
FUNCTIONS:
- `bool SyscallVerbose()` — Syscall.cpp:6–16
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SilencedInvalidParameter(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)` — Syscall.cpp:20–22
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SyscallLog(int level, const char * fmt, ...)` — Syscall.cpp:24–59
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `public: SyscallLockGuard()` — Syscall.cpp:156–157
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `BOOL CALLBACK InitializeLockOnce(PINIT_ONCE, PVOID, PVOID *)` — Syscall.cpp:160–164
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void EnsureLock()` — Syscall.cpp:165–169
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `SYSCALL_ENTRY * FindEntry(DWORD NameHash)` — Syscall.cpp:170–182
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool StubLooksHealthy(const BYTE * Code, DWORD Available, DWORD & ServiceOut)` — Syscall.cpp:189–232
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool BoundedRead(const BYTE * Base, DWORD Rva, SIZE_T Size, DWORD ImageSize)` — Syscall.cpp:233–247
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const IMAGE_EXPORT_DIRECTORY * LocateExportDirectory(const BYTE * Ntdll, DWORD & ImageSizeOut)` — Syscall.cpp:248–311
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void FillNoOpTail(BYTE * Destination, SIZE_T Size, DWORD Key)` — Syscall.cpp:338–374
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void * FindSyscallGadget()` — Syscall.cpp:375–407
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool WriteStub(BYTE * Destination, DWORD Service, void * Gadget, ULONG_PTR GadgetSlotAddress, ULONG_PTR StubAddress)` — Syscall.cpp:429–464
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool BuildPool()` — Syscall.cpp:465–559
  Summary: Builds and publishes the local syscall stub pool with RX protection and W^X verification.
- `void * SyscallGadgetAddress()` — Syscall.cpp:561–570
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SyscallResolveAll()` — Syscall.cpp:571–951
  Summary: Resolves ntdll syscall service numbers, rebuilds missing service numbers, and builds remote-capable stubs.
- `void * SyscallStub(DWORD NameHash)` — Syscall.cpp:952–975
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SyscallServiceOfStub(const void * Stub)` — Syscall.cpp:976–1019
  Summary: Identifies the service number stored in a syscall stub.
- `DWORD ScGetProcessImageName(HANDLE ProcessHandle, wchar_t * Buffer, DWORD Characters)` — Syscall.cpp:1020–1093
  Summary: Reads the target process image name through a resolved syscall stub.
- `DWORD BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count, ULONG_PTR RemoteBase)` — Syscall.cpp:1094–1178
  Summary: Emits remote syscall stubs that jump through ntdll syscall gadgets.

KEYWORD_LINES:
- keyword lines in `SyscallVerbose` (Syscall.cpp:6–16):
  const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_SYSCALL_VERBOSE").get(), buffer, 4);
- keyword lines in `SyscallLockGuard` (Syscall.cpp:156–157):
  SyscallLockGuard()	{ AcquireSRWLockExclusive(&g_SyscallLock); }
- keyword lines in `FindEntry` (Syscall.cpp:170–182):
  SYSCALL_ENTRY * FindEntry(DWORD NameHash)
- keyword lines in `StubLooksHealthy` (Syscall.cpp:189–232):
  if (Candidate > 0xFFFF)
  // The syscall instruction has to follow the service load within a short
  // window; a ret or a jump before it means this is not a plain syscall stub
  for (DWORD i = sizeof(kPrologueHealthyA) + sizeof(DWORD); i + 1 < Available && i <= 0x20; ++i)
  if (Code[i] == 0x0F && Code[i + 1] == 0x05)
  if (Code[i] == 0xC3 || Code[i] == 0xE9)
- keyword lines in `LocateExportDirectory` (Syscall.cpp:248–311):
  const IMAGE_EXPORT_DIRECTORY * LocateExportDirectory(const BYTE * Ntdll, DWORD & ImageSizeOut)
  if (!Ntdll)
  const auto * Dos = ReCa<const IMAGE_DOS_HEADER *>(Ntdll);
  if (Dos->e_lfanew <= 0 || static_cast<DWORD>(Dos->e_lfanew) > 0x400)
  const auto * Nt = ReCa<const IMAGE_NT_HEADERS64 *>(Ntdll + Dos->e_lfanew);
  if (Nt->Signature != IMAGE_NT_SIGNATURE)
  if (Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  ImageSizeOut = Nt->OptionalHeader.SizeOfImage;
  if (!ImageSizeOut || ImageSizeOut > 0x8000000)
  const IMAGE_DATA_DIRECTORY & Dir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!BoundedRead(Ntdll, Dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), ImageSizeOut))
  const auto * Export = ReCa<const IMAGE_EXPORT_DIRECTORY *>(Ntdll + Dir.VirtualAddress);
  if (!Export->NumberOfNames || Export->NumberOfNames > 0x8000 ||
  !Export->NumberOfFunctions || Export->NumberOfFunctions > 0x8000)
  if (!BoundedRead(Ntdll, Export->AddressOfNames, sizeof(DWORD) * Export->NumberOfNames, ImageSizeOut) ||
  !BoundedRead(Ntdll, Export->AddressOfNameOrdinals, sizeof(WORD) * Export->NumberOfNames, ImageSizeOut) ||
  !BoundedRead(Ntdll, Export->AddressOfFunctions, sizeof(DWORD) * Export->NumberOfFunctions, ImageSizeOut))
- keyword lines in `FillNoOpTail` (Syscall.cpp:338–374):
  Destination[i] = 0x90;
- keyword lines in `FindSyscallGadget` (Syscall.cpp:375–407):
  if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
- keyword lines in `WriteStub` (Syscall.cpp:429–464):
  *ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;
  // instruction, i.e. to SC_STUB_TAIL_INDIRECT.
  - static_cast<LONGLONG>(StubAddress + SC_STUB_TAIL_INDIRECT);
  Destination[SC_STUB_OFFSET_SYSCALL] = kOpJmpRip0;
  Destination[SC_STUB_OFFSET_SYSCALL + 1] = kOpJmpRip1;
  *ReCa<LONG *>(Destination + SC_STUB_OFFSET_SYSCALL + 2) = static_cast<LONG>(delta);
  FillNoOpTail(Destination + SC_STUB_TAIL_INDIRECT, SC_STUB_SIZE - SC_STUB_TAIL_INDIRECT, Service);
- keyword lines in `BuildPool` (Syscall.cpp:465–559):
  SC_LOG_INFO("Building Syscall Stub Pool (%zu Entries, %u Bytes Each)...", kSyscallTableCount, SC_STUB_SIZE);
  SC_LOG_ERR("VirtualAlloc Failed For Stub Pool");
  // through it, so the `syscall` instruction itself only ever exists inside a
  SC_LOG_ERR("Stub Pool Layout Invalid Or ntdll Syscall Gadget Unavailable");
  SYSCALL_ENTRY & Entry = g_SyscallTable[i];
  BYTE * slot = Pool + (i * SC_STUB_SIZE);
  SC_LOG_ERR("Syscall Stub Displacement Out Of Range For Entry %zu", i);
  SC_LOG_ERR("No Valid Syscall Entries To Write");
  DWORD OldProtect = 0;
  if (!VirtualProtect(Pool, kStubAreaSize + 16, PAGE_EXECUTE_READ, &OldProtect))
  SC_LOG_ERR("VirtualProtect RX Failed");
  SC_LOG_OK("Stub Pool Built: %u/%zu Stubs At %p (RX)", Written, kSyscallTableCount, Pool);
- keyword lines in `SyscallResolveAll` (Syscall.cpp:571–951):
  SC_LOG_OK("Syscall Pool Already Ready (%u/%zu Stubs)", Ready, kSyscallTableCount);
  SC_LOG_INFO("Resolving Syscall Service Numbers From ntdll...");
  const BYTE * Ntdll = ReCa<const BYTE *>(GetModuleHandleW(ntdll_name.get()));
  if (!Ntdll)
  SC_LOG_ERR("ntdll.dll Not Loaded");
  const IMAGE_EXPORT_DIRECTORY * Export = LocateExportDirectory(Ntdll, ImageSize);
  SC_LOG_ERR("Failed To Locate ntdll Export Directory");
  SC_LOG_INFO("ntdll Base: %p | ImageSize: 0x%X | Exports: %u", Ntdll, ImageSize, Export->NumberOfNames);
  SC_LOG_ERR("Failed To Reserve Harvest Buffer");
  constexpr DWORD kHarvestedCap = 0x4000;
  const auto * Names		= ReCa<const DWORD *>(Ntdll + Export->AddressOfNames);
  const auto * Ordinals	= ReCa<const WORD *>(Ntdll + Export->AddressOfNameOrdinals);
  const auto * Functions	= ReCa<const DWORD *>(Ntdll + Export->AddressOfFunctions);
  if (!NameRva || !BoundedRead(Ntdll, NameRva, 2, ImageSize))
  const char * Name = ReCa<const char *>(Ntdll + NameRva);
  DWORD h = 0x811C9DC5u;
  h *= 0x01000193u;
  SYSCALL_ENTRY * Entry = FindEntry(Hash);
  if (!Rva || !BoundedRead(Ntdll, Rva, kStubProbeSize, ImageSize))
  if (StubLooksHealthy(Ntdll + Rva, ImageSize - Rva, Service))
  memcpy(g_Resolution[idx].Prologue, Ntdll + Rva, 4);
  if (BoundedRead(Ntdll, Rva, 4, ImageSize))
  memcpy(g_Resolution[idx].Prologue, Ntdll + Rva, 4);
  SC_LOG_INFO("Pass 1: Scanned %u Exports | Matched %u | Healthy %u | Rerouted %u | Unreadable %u",
  if (!NameRva || !BoundedRead(Ntdll, NameRva, 2, ImageSize))
  const char * Name = ReCa<const char *>(Ntdll + NameRva);
  DWORD h = 0x811C9DC5u;
  h *= 0x01000193u;
  // offset from the lower neighbour in service slots.
  const DWORD offset_calls = (Rva - Lower->Rva) / stride_bytes;
  const int Reconstructed = static_cast<int>(Lower->Service) + static_cast<int>(offset_calls);
  if (Reconstructed > 0 && Reconstructed <= 0xFFFF)
  SC_LOG_INFO("Recovered %s Via SSN 0x%04X + %u | Distance: 0x%X Bytes | Stride %u Bytes/SSN", kSyscallNames[i], Lower->Service, offset_calls, span_rva, stride_bytes);
  SC_LOG_INFO("Pass 2: Reconstructed %u/%zu Services", reconstructed, kSyscallTableCount);
  SC_LOG_ERR("Failed To Build Syscall Stub Pool");
  SC_LOG_INFO("[Syscall] [*] Local ntdll.dll Base: %p (Size: 0x%X)\n", Ntdll, ImageSize);
  SC_LOG_INFO("[Syscall] [*] Export Census: %u Total Exports Harvested (%u Healthy)\n", Export->NumberOfNames, healthy);
  SC_LOG_INFO("[Syscall] [=] System Service Resolution Table:\n");
  SC_LOG_INFO("  Idx  Service Name              SSN      Status        Prologue      Address               Method\n");
  const void * addr = valid ? ReCa<const void *>(Ntdll + g_Resolution[ti].Rva) : nullptr;
  SC_LOG_INFO("  [%02zu] %-24s 0x%04X   %-8s    %02X %02X %02X %02X  %p  %s\n",
  const bool is_rx = (mbi.Protect == PAGE_EXECUTE_READ);
  if (!is_rx && mbi.Protect == PAGE_EXECUTE_READWRITE)
  SC_LOG_OK("[Syscall] [+] Stub Pool Staging: VA = %p | Size = 0x%X Bytes\n", pool, kStubAreaSize);
  SC_LOG_OK("[Syscall] [+] Memory Protection Query: Protect = 0x%08X (%s) | RWX Count = %u\n",
  mbi.Protect, "PAGE_EXECUTE_READ", rwx_count);
  SC_LOG_ERR("[Syscall] [x] Stub Pool Protection Mismatch = 0x%08X (RWX = %u)\n", mbi.Protect, rwx_count);
  SC_LOG_ERR("[Syscall] [x] Stub Pool Not Queryable; Protection Unverified\n");
  // all, leaves the whole syscall layer unavailable rather than being used.
  SC_LOG_ERR("[Syscall] [x] Stub Pool W^X Verification Failed; Marking Layer Unavailable\n");
  SC_LOG_OK("Syscall Layer Ready: %u/%zu Stubs Built\n", Ready, kSyscallTableCount);
  SC_LOG_WARN("Syscall Layer Incomplete: %u/%zu Stubs Built - %zu Unresolved\n",
- keyword lines in `SyscallServiceOfStub` (Syscall.cpp:976–1019):
  const bool prologue_a = memcmp(Bytes + SC_STUB_OFFSET_PROLOGUE, kPrologueA, sizeof(kPrologueA)) == 0;
  const bool prologue_b = memcmp(Bytes + SC_STUB_OFFSET_PROLOGUE, kPrologueB, sizeof(kPrologueB)) == 0;
  if (Bytes[SC_STUB_OFFSET_OPCODE] != kOpMovEaxImm32)
  const BYTE op0 = Bytes[SC_STUB_OFFSET_SYSCALL];
  const BYTE op1 = Bytes[SC_STUB_OFFSET_SYSCALL + 1];
  // "syscall ; ret" body would mean either an older build or memory the
  const DWORD Service = *ReCa<const DWORD *>(Bytes + SC_STUB_OFFSET_SERVICE);
  if (!Service || Service > 0xFFFF)
- keyword lines in `ScGetProcessImageName` (Syscall.cpp:1020–1093):
  ULONG Size = 0x400;
  const NTSTATUS Status = ScNtQueryInformationProcess(ProcessHandle, PROCESSINFOCLASS::ProcessImageFileNameWin32, Scratch.data(), Size + sizeof(wchar_t) * 2, &Size);
  if (Status == static_cast<NTSTATUS>(0xC0000004))
  const ULONG Required = Size > 0x10000 ? 0x10000 : Size;
  const ULONGLONG Grown = Attempted ? static_cast<ULONGLONG>(Attempted) * 2 : 0x800;
  const ULONGLONG Next = Grown > 0x10000 ? 0x10000 : Grown;
- keyword lines in `BuildSyscallStubs` (Syscall.cpp:1094–1178):
  const SIZE_T stub_bytes = static_cast<SIZE_T>(Count) * SC_STUB_SIZE;
  // Remote stubs never carry an inline `syscall`; they jump through the ntdll
  // `syscall ; ret` gadget so the target process holds no `0F 05` pattern of its
  SC_LOG_ERR("Remote Syscall Stubs Require The ntdll Syscall Gadget");
  BYTE * slot = Destination + (i * SC_STUB_SIZE);
  ? (RemoteBase + static_cast<ULONG_PTR>(i) * SC_STUB_SIZE)
  SC_LOG_ERR("Remote Syscall Stub %u Displacement Out Of Range", i);
SYSCALLS (hashed names):
NtOpenProcess -> 0x5EA49A38
NtOpenThread -> 0x6C58330B
NtDuplicateObject -> 0x859D7997
NtQuerySystemInformation -> 0x7A43974A
NtQueryInformationProcess -> 0xEA2DDA8A
NtQueryInformationThread -> 0x0C06E4E1
NtAllocateVirtualMemory -> 0xCA67B978
NtFreeVirtualMemory -> 0xB51CC567
NtProtectVirtualMemory -> 0xBD799926
NtWriteVirtualMemory -> 0x43E32F32
NtReadVirtualMemory -> 0x6E2A0391
NtSuspendThread -> 0x7D8DDCB1
NtResumeThread -> 0xE06437FC
NtGetContextThread -> 0x65ECAF30
NtSetContextThread -> 0xEA61D9E4

D:\Ameger\Injector\Ameger\System\Download\Manager.cpp — 159 lines — sha12:EC2A4EF7789C
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (Manager.cpp:1)
- "System/Download/Manager.h" [project] (Manager.cpp:2)
- <process.h> [system] (Manager.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `bool Manager::StartWatchdog()` — Manager.cpp:28–60
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Manager::StopWatchdog()` — Manager.cpp:61–79
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Manager::WatchdogProc()` — Manager.cpp:80–107
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Manager::SetTimeout(DWORD milliseconds)` — Manager.cpp:108–139
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Manager::StopTimeout()` — Manager.cpp:140–145
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Manager::TimedOut()` — Manager.cpp:146–150
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Manager::TouchDeadline()` — Manager.cpp:151–159
  Summary: UNVERIFIED: signature recorded; body not fully read.

D:\Ameger\Injector\Ameger\System\Handle\HandleHijack.cpp — 1278 lines — sha12:B0F12A23083C
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (HandleHijack.cpp:1)
- <TlHelp32.h> [system] (HandleHijack.cpp:2)
- <unordered_map> [system] (HandleHijack.cpp:4)
- <unordered_set> [system] (HandleHijack.cpp:6)
- <string> [system] (HandleHijack.cpp:7)
- <vector> [system] (HandleHijack.cpp:8)
- "Core/Foundation/Primitives/ResourceGuard.h" [project] (HandleHijack.cpp:9)
- "Core/Foundation/Primitives/KcStrings/Core/XorString.h" [project] (HandleHijack.cpp:10)
- "Core/Utility/Tools/Tools.h" [project] (HandleHijack.cpp:11)
- "System/Handle/HandleHijack.h" [project] (HandleHijack.cpp:12)
- "Native/Syscall.h" [project] (HandleHijack.cpp:13)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL (HandleHijack.cpp:31) fields/constants: `Object`, `UniqueProcessId`, `HandleValue`, `GrantedAccess`, `CreatorBackTraceIndex`, `ObjectTypeIndex`, `HandleAttributes`, `Reserved`
- struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL (HandleHijack.cpp:43) fields/constants: `NumberOfHandles`, `Reserved`
- struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY (HandleHijack.cpp:50) fields/constants: `UniqueProcessId`, `CreatorBackTraceIndex`, `ObjectTypeIndex`, `HandleAttributes`, `HandleValue`, `Object`, `GrantedAccess`
- struct SYSTEM_HANDLE_INFORMATION_LEGACY (HandleHijack.cpp:61) fields/constants: `NumberOfHandles`
- struct NtdllHandles (HandleHijack.cpp:70) fields/constants: `NtQuerySystemInformation`, `NtDuplicateObject`
- class SeDebugPrivilegeScope (HandleHijack.cpp:171) fields/constants: none detected
- struct EnumSnapshot (HandleHijack.cpp:192) fields/constants: `Buffer`, `Extended`
- class VM_PROBE_POLICY (HandleHijack.cpp:344) fields/constants: `Reserve`, `Protect`, `None`
- class DonorOwnerBlocklist (HandleHijack.cpp:492) fields/constants: `m_Names`
- class ProcessImageIndex (HandleHijack.cpp:567) fields/constants: `m_Names`, `snapshot`, `return`
- struct Candidate (HandleHijack.cpp:867) fields/constants: `OwnerPid`, `HandleValue`, `Object`, `GrantedAccess`
FUNCTIONS:
- `__forceinline bool NtOk(NTSTATUS Status)` — HandleHijack.cpp:75–79
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveNtdll(NtdllHandles & Out)` — HandleHijack.cpp:80–90
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool EnableSeDebugPrivilege()` — HandleHijack.cpp:91–120
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void EnsureSeDebugPrivilege()` — HandleHijack.cpp:134–141
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void DisableSeDebugPrivilege()` — HandleHijack.cpp:142–169
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `public: SeDebugPrivilegeScope()` — HandleHijack.cpp:173–177
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD QueryHandleSnapshot(const NtdllHandles & Ntdll, ULONG InfoClass, bool Extended, EnumSnapshot & Out, NTSTATUS & LastStatus)` — HandleHijack.cpp:197–248
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD QueryAnySnapshot(const NtdllHandles & Ntdll, EnumSnapshot & Out, NTSTATUS & LastStatus)` — HandleHijack.cpp:249–264
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool FindOwnEntryType(const EnumSnapshot & Snapshot, DWORD SelfPid, ULONG_PTR HandleValue, USHORT & TypeIndexOut)` — HandleHijack.cpp:265–333
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `VM_PROBE_POLICY GetVmProbePolicy()` — HandleHijack.cpp:350–385
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProbeQueryUsable(HANDLE Candidate, DWORD TargetPid)` — HandleHijack.cpp:386–396
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProbeVmOperation(HANDLE Candidate)` — HandleHijack.cpp:397–461
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool VerifyProcessDonor(HANDLE Candidate, DWORD TargetPid)` — HandleHijack.cpp:462–471
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool VerifyThreadDonor(HANDLE Candidate, DWORD TargetPid, DWORD TargetTid)` — HandleHijack.cpp:472–481
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Excludes(const wchar_t * image_name)` — HandleHijack.cpp:546–561
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Build()` — HandleHijack.cpp:572–596
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const wchar_t * Find(DWORD pid)` — HandleHijack.cpp:597–606
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `HANDLE OpenOwnerCached(std::vector<std::pair<DWORD, UniqueHandle>> & Owners, DWORD OwnerPid)` — HandleHijack.cpp:608–646
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD ScanSnapshot(const NtdllHandles & Ntdll, const EnumSnapshot & Snapshot, DWORD SelfPid,
		DWORD TargetPid, DWORD TargetTid, bool ThreadScan, USHORT WantedType, bool HaveType, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats & Detail)` — HandleHijack.cpp:647–1004
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD HijackImpl(DWORD TargetPid, DWORD TargetTid, bool ThreadScan, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats * Detail)` — HandleHijack.cpp:1005–1107
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StoreHijackStats(HijackStats & Dst, const HijackStats & Src)` — HandleHijack.cpp:1120–1126
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LoadHijackStats(HijackStats & Src, HijackStats & Dst)` — HandleHijack.cpp:1127–1133
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess)` — HandleHijack.cpp:1135–1163
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProbeMemoryRoundtrip(HANDLE Candidate)` — HandleHijack.cpp:1164–1210
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ResetHijackStats()` — HandleHijack.cpp:1211–1216
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void RecordHijackOutcome(const HijackStats & Stats, bool IsThread)` — HandleHijack.cpp:1217–1221
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut)` — HandleHijack.cpp:1222–1236
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)` — HandleHijack.cpp:1237–1257
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)` — HandleHijack.cpp:1258–1278
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `NtOk` (HandleHijack.cpp:75–79):
  __forceinline bool NtOk(NTSTATUS Status)
- keyword lines in `ResolveNtdll` (HandleHijack.cpp:80–90):
  bool ResolveNtdll(NtdllHandles & Out)
  // The handle enumeration and the duplication both go through the syscall
  Out.NtQuerySystemInformation = ReCa<f_NtQuerySystemInformationLocal>(SyscallStub(SC_NtQuerySystemInformation));
  Out.NtDuplicateObject = ReCa<f_NtDuplicateObjectLocal>(SyscallStub(SC_NtDuplicateObject));
  return Out.NtQuerySystemInformation && Out.NtDuplicateObject;
- keyword lines in `QueryHandleSnapshot` (HandleHijack.cpp:197–248):
  DWORD QueryHandleSnapshot(const NtdllHandles & Ntdll, ULONG InfoClass, bool Extended, EnumSnapshot & Out, NTSTATUS & LastStatus)
  const NTSTATUS Status = Ntdll.NtQuerySystemInformation(InfoClass, Out.Buffer.data(),
  size_t Next = Returned > 0 ? (static_cast<size_t>(Returned) + 0x10000) : (Size * 2);
  if (!NtOk(Status))
- keyword lines in `QueryAnySnapshot` (HandleHijack.cpp:249–264):
  DWORD QueryAnySnapshot(const NtdllHandles & Ntdll, EnumSnapshot & Out, NTSTATUS & LastStatus)
  DWORD Result = QueryHandleSnapshot(Ntdll, kSystemExtendedHandleInformation, true, Out, LastStatus);
  return QueryHandleSnapshot(Ntdll, kSystemHandleInformation, false, Out, LastStatus);
- keyword lines in `FindOwnEntryType` (HandleHijack.cpp:265–333):
  const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
  const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
- keyword lines in `GetVmProbePolicy` (HandleHijack.cpp:350–385):
  return VM_PROBE_POLICY::Protect;
- keyword lines in `ProbeVmOperation` (HandleHijack.cpp:397–461):
  case VM_PROBE_POLICY::Protect:
  if (!(info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
  return ScProtectMemory(Candidate, info.BaseAddress, info.RegionSize, info.Protect, &old_protect);
  void * Page = ScAllocateMemory(Candidate, 0x1000, PAGE_NOACCESS);
  if (!Page)
  if (ScFreeMemory(Candidate, Page))
  LOG(1, "ProbeVmOperation: Release Failed Three Times; Page Retained In Target\n");
- keyword lines in `ScanSnapshot` (HandleHijack.cpp:647–1004):
  DWORD ScanSnapshot(const NtdllHandles & Ntdll, const EnumSnapshot & Snapshot, DWORD SelfPid,
  // 2 = Protect, 3 = Roundtrip). A thread scan only verifies query rights,
  case VM_PROBE_POLICY::Protect:
  if (!NtOk(Ntdll.NtDuplicateObject(GetCurrentProcess(), SourceValue, GetCurrentProcess(),
  if (!NtOk(Ntdll.NtDuplicateObject(Owner, SourceValue, GetCurrentProcess(),
  const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
  const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
  Detail.SnapshotBytes = static_cast<DWORD>(Snapshot.Buffer.size() > 0xFFFFFFFF ? 0xFFFFFFFF : Snapshot.Buffer.size());
  LOG(1, "[Handle] [+] Donor Handle Acquired: Donor PID = %u | Donor Handle = 0x%08X\n", FoundDonorPid, FoundDonorHandle);
  LOG(1, "[Handle] [+] Duplicated Handle: Local = 0x%08X | Granted = 0x%08X\n", FoundNewHandle, FoundGranted);
- keyword lines in `HijackImpl` (HandleHijack.cpp:1005–1107):
  NtdllHandles Ntdll{ };
  if (!ResolveNtdll(Ntdll))
  const DWORD SnapshotRet = QueryAnySnapshot(Ntdll, Snap, SnapStatus);
  Local.SnapshotBytes = static_cast<DWORD>(Snap.Buffer.size() > 0xFFFFFFFF ? 0xFFFFFFFF : Snap.Buffer.size());
  const DWORD ScanRet = ScanSnapshot(Ntdll, Snap, SelfPid, TargetPid, TargetTid, ThreadScan, WantedType, HaveType, DesiredAccess, TargetOwnerHandle, Out, Local);
- keyword lines in `StoreHijackStats` (HandleHijack.cpp:1120–1126):
  AcquireSRWLockExclusive(&g_HijackStatsLock);
  ReleaseSRWLockExclusive(&g_HijackStatsLock);
- keyword lines in `LoadHijackStats` (HandleHijack.cpp:1127–1133):
  AcquireSRWLockShared(&g_HijackStatsLock);
  ReleaseSRWLockShared(&g_HijackStatsLock);
- keyword lines in `ProbeMemoryRoundtrip` (HandleHijack.cpp:1164–1210):
  void * Page = ScAllocateMemory(Candidate, 0x1000, PAGE_READWRITE);
  if (!Page)
  BYTE Written = 0xA5;
  const bool Ok = ScWriteProcessMemory(Candidate, Page, &Written, sizeof(Written), &Done) && Done == sizeof(Written)
  && ScReadProcessMemory(Candidate, Page, &Readout, sizeof(Readout), &Done) && Done == sizeof(Readout)
  if (ScFreeMemory(Candidate, Page))

D:\Ameger\Injector\Ameger\System\Import\ImportHandler.cpp — 341 lines — sha12:E56458893DB7
INCLUDES:
- "Core/Foundation/Primitives/ResourceGuard.h" [project] (ImportHandler.cpp:2)
- "System/Import/ImportHandler.h" [project] (ImportHandler.cpp:4)
- "System/Symbol/Offsets/DynamicOffsets.h" [project] (ImportHandler.cpp:5)
- <utility> [system] (ImportHandler.cpp:6)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- class encrypted_symbol_name (ImportHandler.cpp:14) fields/constants: `m_name`, `Holder`
- struct ExportEntry (ImportHandler.cpp:152) fields/constants: `name`, `target`
FUNCTIONS:
- `void StoreStringStats(const STRING_STATS & Src)` — ImportHandler.cpp:35–45
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void LoadStringStats(STRING_STATS & Dst)` — ImportHandler.cpp:46–55
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD LoadSymbolNative(T & Function, const encrypted_symbol_name & name, STRING_STATS & stats, bool CountDeclaration = true)` — ImportHandler.cpp:58–87
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD ResolveImports(ERROR_DATA & error_data)` — ImportHandler.cpp:88–331
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void __stdcall GetLastStringStats(STRING_STATS * Out)` — ImportHandler.cpp:332–341
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `StoreStringStats` (ImportHandler.cpp:35–45):
  static_assert(sizeof(STRING_STATS) % sizeof(LONG) == 0, "STRING_STATS must be a whole number of LONGs");
- keyword lines in `ResolveImports` (ImportHandler.cpp:88–331):
  if (LoadSymbolNative(S_FUNC(NtAllocateVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
  if (LoadSymbolNative(S_FUNC(NtFreeVirtualMemory)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
  if (LoadSymbolNative(S_FUNC(NtProtectVirtualMemory)))				return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
  if (LoadSymbolNative(S_FUNC(NtSetEvent)))							return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
  if (LoadSymbolNative(S_FUNC(NtClose)))								return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;
  if (LoadSymbolNative(S_FUNC(LdrProtectMrdata)))					return INJ_ERR_GET_SYMBOL_ADDRESS_FAILED;

D:\Ameger\Injector\Ameger\System\Information\ProcessInformation.cpp — 340 lines — sha12:57297FA3A5D7
INCLUDES:
- "System/Information/ProcessInformation.h" [project] (ProcessInformation.cpp:2)
- "Native/Syscall.h" [project] (ProcessInformation.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `SYSTEM_PROCESS_INFORMATION * LocateProcessEntry(SYSTEM_PROCESS_INFORMATION * first, ULONG_PTR buffer_size, ULONG_PTR pid)` — ProcessInformation.cpp:13–43
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProcessInformation::SetProcess(HANDLE hTargetProc)` — ProcessInformation.cpp:71–141
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProcessInformation::NextThread()` — ProcessInformation.cpp:142–166
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProcessInformation::RefreshInformation()` — ProcessInformation.cpp:167–237
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD ProcessInformation::GetThreadId()` — ProcessInformation.cpp:238–247
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProcessInformation::GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason)` — ProcessInformation.cpp:248–262
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `HANDLE ProcessInformation::BorrowCurrentThreadHandle(DWORD tid)` — ProcessInformation.cpp:263–272
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ProcessInformation::SetCurrentThreadHandle(HANDLE thread, DWORD tid)` — ProcessInformation.cpp:273–278
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void * ProcessInformation::GetTEB()` — ProcessInformation.cpp:279–309
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProcessInformation::IsThreadWorkerThread()` — ProcessInformation.cpp:310–340
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `ProcessInformation::SetProcess` (ProcessInformation.cpp:71–141):
  if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
- keyword lines in `ProcessInformation::RefreshInformation` (ProcessInformation.cpp:167–237):
  NTSTATUS ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
  ULONG next_size = size_out + 0x1000;
  ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
- keyword lines in `ProcessInformation::GetThreadId` (ProcessInformation.cpp:238–247):
  return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
- keyword lines in `ProcessInformation::GetTEB` (ProcessInformation.cpp:279–309):
  if (!m_pCurrentThread || !m_pNtQueryInformationThread)
  auto ntRet = m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

D:\Ameger\Injector\Ameger\System\Symbol\Loader\SymbolLoader.cpp — 1099 lines — sha12:AE0D4A085B95
INCLUDES:
- "Core/Utility/Binary/DynamicAPI.h" [project] (SymbolLoader.cpp:2)
- "Core/Foundation/Error.h" [project] (SymbolLoader.cpp:3)
- "System/Symbol/Loader/SymbolLoader.h" [project] (SymbolLoader.cpp:5)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `void EnsureDirectoryTree(const std::wstring & dir)` — SymbolLoader.cpp:42–55
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SYMBOL_LOADER::VerifyExistingPdb(const GUID & guid, DWORD age)` — SymbolLoader.cpp:204–501
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_LOADER::Initialize(const std::wstring & szModulePath, const std::wstring & path, bool Redownload, bool AutoDownload)` — SymbolLoader.cpp:502–1006
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SYMBOL_LOADER::Cleanup()` — SymbolLoader.cpp:1007–1018
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SYMBOL_LOADER::PurgePdb()` — SymbolLoader.cpp:1019–1061
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SYMBOL_LOADER::SetDownload(bool bDownload)` — SymbolLoader.cpp:1062–1066
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SYMBOL_LOADER::Interrupt()` — SymbolLoader.cpp:1067–1084
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const std::wstring & SYMBOL_LOADER::GetFilepath()` — SymbolLoader.cpp:1085–1089
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_LOADER::GetFilesize()` — SymbolLoader.cpp:1090–1094
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SYMBOL_LOADER::IsReady()` — SymbolLoader.cpp:1095–1099
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `SYMBOL_LOADER::VerifyExistingPdb` (SymbolLoader.cpp:204–501):
  LOG(2, XOR_STR_A("SymbolLoader: Invalid PDB Page Metadata\n").get());
  const size_t root_page_list_offset = static_cast<size_t>(pPDBHeader->root_stream_page_number_list_number) * page_size;
  if (root_page_list_offset > size_on_disk - sizeof(int))
  LOG(2, XOR_STR_A("SymbolLoader: Invalid Root Page List\n").get());
  int root_page_number = *ReCa<int *>(pdb_raw + root_page_list_offset);
  LOG(2, XOR_STR_A("SymbolLoader: Invalid Root Page Number\n").get());
  const size_t root_stream_offset = static_cast<size_t>(root_page_number) * page_size;
  if (root_stream_offset > size_on_disk - sizeof(RootStream7))
  auto	* pRootStream		= ReCa<RootStream7 *>(pdb_raw + root_stream_offset);
  if (stream_header_bytes > size_on_disk - root_stream_offset)
  const size_t available_page_numbers = (size_on_disk - root_stream_offset - stream_header_bytes) / sizeof(int);
  const int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
  LOG(2, XOR_STR_A("SymbolLoader: Invalid Root Stream Page List\n").get());
  int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
  LOG(2, XOR_STR_A("SymbolLoader: Invalid Stream Page\n").get());
  LOG(2, XOR_STR_A("SymbolLoader: Invalid PDB Information Page\n").get());
  const size_t stream_data_offset = static_cast<size_t>(pdbInformation_page_index) * page_size;
  if (stream_data_offset > size_on_disk - sizeof(GUID_StreamData))
  auto * stream_data = ReCa<GUID_StreamData *>(pdb_raw + stream_data_offset);
  const size_t dbi_offset = static_cast<size_t>(dbi_page_index) * page_size;
  if (dbi_offset <= size_on_disk - sizeof(DBIStreamHeader))
  dbi_age = ReCa<DBIStreamHeader *>(pdb_raw + dbi_offset)->age;
- keyword lines in `SYMBOL_LOADER::Initialize` (SymbolLoader.cpp:502–1006):
  LOG(1, XOR_STR_A("SymbolLoader: Can't Allocate Memory = 0x%08X\n").get(), GetLastError());
  const DWORD codeview_offset = pDebugDir->AddressOfRawData;
  constexpr DWORD kCodeViewFixedSize = static_cast<DWORD>(offsetof(PdbInformation, PdbFileName));
  codeview_offset <= pOpt64->SizeOfImage &&
  codeview_size <= pOpt64->SizeOfImage - codeview_offset;
  if (pdbInformation->Signature != 0x53445352)
  LOG(1, XOR_STR_A("SymbolLoader: Can't Create/Open Download Path = 0x%08X\n").get(), GetLastError());
  LOG(1, XOR_STR_A("SymbolLoader: Can't Create/Open Download Path = 0x%08X\n").get(), GetLastError());
  const size_t pdb_name_offset = offsetof(PdbInformation, PdbFileName);
  const bool record_bounded = pDebugDir->SizeOfData > pdb_name_offset
  && pdb_name_offset <= pOpt64->SizeOfImage - pDebugDir->AddressOfRawData;
  pdb_name_capacity = pDebugDir->SizeOfData - pdb_name_offset;
  const size_t image_remaining = pOpt64->SizeOfImage - pDebugDir->AddressOfRawData - pdb_name_offset;
  LOG(1, XOR_STR_A("SymbolLoader: Download Attempt %d/3 Failed = 0x%08X\n").get(), attempt, dl_hr);
  LOG(1, XOR_STR_A("SymbolLoader: Failed To Download File = 0x%08X\n").get(), dl_hr);
  LOG(2, XOR_STR_A("SymbolLoader: Machine Symbol Store Copy Failed = 0x%08X\n").get(), GetLastError());
  LOG(1, XOR_STR_A("SymbolLoader: Can't Access PDB File = 0x%08X\n").get(), GetLastError());
  LOG(1, XOR_STR_A("SymbolLoader: Can't Open PDB File = 0x%08X\n").get(), GetLastError());
- keyword lines in `SYMBOL_LOADER::PurgePdb` (SymbolLoader.cpp:1019–1061):
  LOG(1, XOR_STR_A("SymbolLoader: Failed To Purge Cached PDB = 0x%08X\n").get(), GetLastError());

D:\Ameger\Injector\Ameger\System\Symbol\Offsets\DynamicOffsets.cpp — 280 lines — sha12:9B87191051A4
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (DynamicOffsets.cpp:1)
- "System/Symbol/Offsets/DynamicOffsets.h" [project] (DynamicOffsets.cpp:2)
- "System/Symbol/Parser/SymbolParser.h" [project] (DynamicOffsets.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct FALLBACK_CTX (DynamicOffsets.cpp:233) fields/constants: none detected
FUNCTIONS:
- `DWORD ResolveFieldEither(const char * const * types, size_t typeCount, const char * primary, const char * alternate, DWORD & out)` — DynamicOffsets.cpp:5–20
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD ResolveDynamicOffsets()` — DynamicOffsets.cpp:21–280
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `ResolveDynamicOffsets` (DynamicOffsets.cpp:21–280):
  if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
  if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
  off && off + 64 * sizeof(void *) <= 0x2000)
  off && off + 2 * sizeof(ULONG) <= 0x400)
  if (sym_parser.GetFieldOffsetAny(kTls, _countof(kTls), f_module_entry.get(), off) == SYMBOL_ERR_SUCCESS && off && off < 0x200)
  tmp.TlsEntryModuleEntry = static_cast<DWORD>(offsetof(TLS_ENTRY, ModuleEntry));
  LOG(1, "DynamicOffsets: TLS Slot Via Documented Struct 0x%X (PDB Type Absent)\n", tmp.TlsEntryModuleEntry);
  if (sym_parser.GetTypeSizeAny(kTls, _countof(kTls), tls_sz) == SYMBOL_ERR_SUCCESS && tls_sz && tls_sz < 0x400)
  if (sym_parser.GetTypeSizeAny(kPathCtx, _countof(kPathCtx), ctx_sz) == SYMBOL_ERR_SUCCESS && ctx_sz && ctx_sz < 0x1000)
  if (sym_parser.GetFieldOffsetAny(kPathCtx, _countof(kPathCtx), f_orig_full_dll.get(), ctx_off) == SYMBOL_ERR_SUCCESS && ctx_off < 0x400)
  tmp.LdrpPathSearchOriginalFullDllName = static_cast<DWORD>(offsetof(FALLBACK_CTX, c));
  LOG(1, "DynamicOffsets: Path Context Name Via Fallback 0x%X\n", tmp.LdrpPathSearchOriginalFullDllName);
  LOG(1, "DynamicOffsets Ready: T0 = 0x%X | T1 = 0x%X | P0 = 0x%X | K0 = 0x%X | L0 = 0x%X | Size = %lu | I0 = 0x%X | I1 = 0x%X\n",

D:\Ameger\Injector\Ameger\System\Symbol\Parser\SymbolParser.cpp — 481 lines — sha12:74C9D074A46F
INCLUDES:
- "Core/Utility/Header/PrecompiledHeader.h" [project] (SymbolParser.cpp:1)
- "Core/Utility/Binary/DynamicAPI.h" [project] (SymbolParser.cpp:2)
- "System/Symbol/Parser/SymbolParser.h" [project] (SymbolParser.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `DWORD SYMBOL_PARSER::Initialize(const SYMBOL_LOADER * pSymbolObject)` — SymbolParser.cpp:16–125
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut)` — SymbolParser.cpp:126–166
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut)` — SymbolParser.cpp:167–195
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetTypeSize(const char * szTypeName, ULONG64 & SizeOut)` — SymbolParser.cpp:196–220
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut)` — SymbolParser.cpp:221–311
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut)` — SymbolParser.cpp:312–336
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut)` — SymbolParser.cpp:337–359
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD SYMBOL_PARSER::GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut)` — SymbolParser.cpp:360–448
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void SYMBOL_PARSER::Cleanup()` — SymbolParser.cpp:449–481
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `SYMBOL_PARSER::Initialize` (SymbolParser.cpp:16–125):
  LOG(1, XOR_STR_A("SymbolParser: Can't Open Current Process = 0x%08X\n").get(), GetLastError());
  LOG(1, XOR_STR_A("SymbolParser: SymInitializeW Failed = 0x%08X\n").get(), GetLastError());
  m_SymbolTable = m_Api.SymLoadModuleEx(m_hProcess, nullptr, pdb_path.c_str(), nullptr, 0x10000000, pSymbolObject->GetFilesize(), nullptr, NULL);
  LOG(1, XOR_STR_A("SymbolParser: SymLoadModuleExW Failed = 0x%08X\n").get(), GetLastError());
- keyword lines in `SYMBOL_PARSER::GetSymbolAddress` (SymbolParser.cpp:126–166):
  if (si->Address < si->ModBase || si->Address - si->ModBase > 0xFFFFFFFFull)
- keyword lines in `SYMBOL_PARSER::GetTypeSize` (SymbolParser.cpp:196–220):
  if (!length || length > 0x10000)
- keyword lines in `SYMBOL_PARSER::GetFieldOffset` (SymbolParser.cpp:221–311):
  DWORD field_offset = 0;
  if (!m_Api.SymGetTypeInfo(m_hProcess, m_SymbolTable, children->ChildId[i], TI_GET_OFFSET, &field_offset))
  if (field_offset > 0x2000)
  OffsetOut = field_offset;
  LOG(2, XOR_STR_A("SymbolParser: %s::%s = 0x%X\n").get(), szTypeName, szFieldName, field_offset);

D:\Ameger\Injector\Interface\Source\Interface\Interface.cpp — 366 lines — sha12:76A0AA6AD5FC
INCLUDES:
- "Launcher.h" [project] (Interface.cpp:2)
- <cstdarg> [system] (Interface.cpp:4)
- <cstdio> [system] (Interface.cpp:6)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `SRWLOCK & Lock()` — Interface.cpp:68–73
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `HANDLE & File()` — Interface.cpp:87–91
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `size_t & Written()` — Interface.cpp:92–97
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool WriteUtf8(HANDLE file, const wchar_t * text, size_t chars)` — Interface.cpp:98–131
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void CloseFile()` — Interface.cpp:132–143
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void AppendClean(const wchar_t * text)` — Interface.cpp:144–173
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void AppendStripped(const wchar_t * text)` — Interface.cpp:174–183
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ResetResultLog()` — Interface.cpp:205–214
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool BeginResultLog(const wchar_t * header)` — Interface.cpp:215–248
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void DiscardResultLog()` — Interface.cpp:252–260
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void FlushResultLog()` — Interface.cpp:265–276
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void WriteResultLog()` — Interface.cpp:281–285
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Clear()` — Interface.cpp:286–293
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ConsoleSupportsColor()` — Interface.cpp:302–319
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int UiLog(int indent, const wchar_t * format, ...)` — Interface.cpp:320–364
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `Lock` (Interface.cpp:68–73):
  static SRWLOCK & Lock()
  static SRWLOCK lock = SRWLOCK_INIT;
- keyword lines in `WriteUtf8` (Interface.cpp:98–131):
  size_t offset = 0;
  while (offset < utf8.size())
  const DWORD chunk = static_cast<DWORD>(utf8.size() - offset > 0x100000 ? 0x100000 : utf8.size() - offset);
  if (!WriteFile(file, utf8.data() + offset, chunk, &written, nullptr) || !written)
  offset += written;
- keyword lines in `AppendClean` (Interface.cpp:144–173):
  AcquireSRWLockExclusive(&Lock());
  ReleaseSRWLockExclusive(&Lock());
- keyword lines in `BeginResultLog` (Interface.cpp:215–248):
  AcquireSRWLockExclusive(&Lock());
  ReleaseSRWLockExclusive(&Lock());
- keyword lines in `FlushResultLog` (Interface.cpp:265–276):
  AcquireSRWLockExclusive(&Lock());
  ReleaseSRWLockExclusive(&Lock());
- keyword lines in `Clear` (Interface.cpp:286–293):
  AcquireSRWLockExclusive(&Lock());
  ReleaseSRWLockExclusive(&Lock());

D:\Ameger\Injector\Interface\Source\Interface\Process.cpp — 412 lines — sha12:D8CDEE4A64B7
INCLUDES:
- "PCH.h" [project] (Process.cpp:1)
- "Launcher.h" [project] (Process.cpp:2)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct LocalPbi (Process.cpp:43) fields/constants: `ExitStatus`, `PebBaseAddress`, `AffinityMask`, `BasePriority`, `UniqueProcessId`, `InheritedFromUniqueProcessId`
FUNCTIONS:
- `LoaderListState ReadLoaderListState(HANDLE process)` — Process.cpp:28–70
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `Architecture ProcessArchitecture(HANDLE process)` — Process.cpp:74–115
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture)` — Process.cpp:120–131
  Summary: Queries process identity and architecture for a PID.
- `bool QueryProcessIdentity(DWORD pid, ProcessIdentity & out)` — Process.cpp:136–184
  Summary: Returns process identity metadata.
- `bool QueryProcessFixed(DWORD pid, wchar_t * name_out, size_t name_count, Architecture & architecture)` — Process.cpp:188–208
  Summary: Queries process name into a fixed buffer.
- `void DescribeDonor(DWORD Pid, wchar_t * NameOut, size_t NameCount)` — Process.cpp:213–227
  Summary: Describes a donor process by PID into a fixed buffer.
- `void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread)` — Process.cpp:232–383
  Summary: Prints trace data for process or thread hijack attempts.
- `void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats)` — Process.cpp:387–412
  Summary: Prints summary statistics for hijack attempts.

KEYWORD_LINES:
- keyword lines in `ReadLoaderListState` (Process.cpp:28–70):
  using NtQueryInformationProcessFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  auto query = reinterpret_cast<NtQueryInformationProcessFn>(
  GetProcAddress(ntdll, "NtQueryInformationProcess"));
- keyword lines in `PrintHijackTrace` (Process.cpp:232–383):
  LOG(0, L"    %ls %ls %ls%s%ls (%ls0x%04X%s In Flags %ls0x%08X%s)\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls %ls0x%08X%ls Pre-Opened, TID %ls0x%04X%ls\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls Status %ls0x%08X%ls, %ls%lu%ls Handles\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls Snapshot %ls%u%ls Bytes | Probe Method %ls%u%ls (0 = None, 1 = Reserve, 2 = Protect, 3 = Roundtrip)\n",
  LOG(0, L"    %ls %ls %ls%s%ls (PID %ls%lu%ls), Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls PID %ls%lu%ls, Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls %ls%s%ls, Granted %ls0x%08X%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Result").c_str(),
  LOG(0, L"    %ls %ls %lsDirect Open%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls %lsFailed%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
  LOG(0, L"    %ls %ls Sponsor TID %ls0x%04lX%ls %lsNot Usable%ls; Hijacked TID %ls0x%04lX%ls\n",
- keyword lines in `PrintHijackSummary` (Process.cpp:387–412):
  LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %ls%s%ls (%ls0x%08X%ls)\n", kGreen, kReset, Kind,
  LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %lsDirect%s (Code %ls0x%08X%ls)\n", kGreen, kReset, Kind,
  LOG(0, L"  %ls[!]%ls %ls Handle Failed (Code %ls0x%08X%ls)\n", kYellow, kReset, Kind,

D:\Ameger\Injector\Interface\Source\Interface\Stealth.cpp — 4315 lines — sha12:EDD923E79F8C
INCLUDES:
- "PCH.h" [project] (Stealth.cpp:1)
- "Launcher.h" [project] (Stealth.cpp:2)
- <intrin.h> [system] (Stealth.cpp:4)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- enum StealthVerifyStep (Stealth.cpp:141) fields/constants: `kStealthAcquireHandle`, `kStealthResolveImports`, `kStealthResolveDelayImports`, `kStealthInitSecurityCookie`, `kStealthEnableExceptions`, `kStealthVerifyExceptionHandling`, `kStealthExecuteTls`, `kStealthExecuteDllMain`, `kStealthRunUnderLoaderLock`, `kStealthCleanDataDirectories`, `kStealthSetPageProtections`, `kStealthVerifyWx`, `kStealthVerifyStringEncryption`, `kStealthVerifyForensicPosture`, `kStealthVerifyUsermodeVectors`, `kStealthEraseHeader`, `kStealthSurveyHostSurface`, `kStealthSurveyTraps`
- struct WxRegion (Stealth.cpp:249) fields/constants: `base`, `size`
- struct ImportEntry (Stealth.cpp:720) fields/constants: `thunk_count`, `named`
- struct DebugPortSurvey (Stealth.cpp:960) fields/constants: `handleValid`, `portReadOk`, `flagsReadOk`, `debugPort`, `debugFlags`, `portStatus`, `flagsStatus`
- struct DirCheck (Stealth.cpp:1604) fields/constants: `index`, `name`, `size`
- struct WindowTally (Stealth.cpp:2605) fields/constants: `pid`, `windows`, `layered`
- struct HandleEntryEx (Stealth.cpp:2713) fields/constants: `Object`, `ProcessId`, `Handle`, `GrantedAccess`, `CreatorBackTraceIndex`, `ObjectTypeIndex`, `HandleAttributes`, `Reserved`
- struct OverlayTally (Stealth.cpp:2905) fields/constants: `pid`, `count`
- struct TargetWindowTally (Stealth.cpp:2935) fields/constants: `pid`, `windows`, `layered`
- struct LocalPbi (Stealth.cpp:3371) fields/constants: `ExitStatus`, `PebBaseAddress`, `AffinityMask`, `BasePriority`, `UniqueProcessId`, `InheritedFromUniqueProcessId`
- struct EncryptedCoreRange (Stealth.cpp:3529) fields/constants: `start`, `end`, `module_name`, `section_name`
- struct ModuleCensus (Stealth.cpp:3657) fields/constants: `module`, `is_main`, `has_encrypted_core`, `sampled`, `committed_regions`, `exec_regions`, `noaccess_regions`, `guard_regions`, `core_regions`, `cc_bytes`, `gadget_hits`, `sample_bytes`, `exec_regions_sampled`, `exec_regions_not_sampled`
FUNCTIONS:
- `double MeasureTscHz()` — Stealth.cpp:39–83
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool CyclesToMilliseconds(ULONGLONG cycles, double & milliseconds)` — Stealth.cpp:88–97
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool BufferContainsMarker(const std::vector<BYTE> & hay, const char * marker, bool wide)` — Stealth.cpp:98–139
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const wchar_t * StealthPageDesc(DWORD p)` — Stealth.cpp:163–178
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthVerifyWxExecution(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers,
        bool * wx_violated, int & step, int total)` — Stealth.cpp:179–503
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthVerifyStringEncryption(StealthVerifierBuffers & buffers, f_GetLastStringStats get_string_stats,
        bool & string_gate_ok, int & step, int total)` — Stealth.cpp:504–641
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `size_t StealthRvaToFileOffset(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, DWORD rva)` — Stealth.cpp:642–675
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `size_t RvaToFileOffset(const IMAGE_SECTION_HEADER * sections, WORD section_count, size_t image_size, DWORD rva)` — Stealth.cpp:676–694
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthAcquireHandle(const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, DWORD flags, int & step, int total)` — Stealth.cpp:695–712
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthResolveImports(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:713–856
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthResolveDelayImports(bool have_local_nt, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:857–876
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthInitSecurityCookie(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:877–955
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadRemoteImageString(HANDLE process, ULONG_PTR image_base, SIZE_T image_size, DWORD rva,
        char * out, size_t out_size)` — Stealth.cpp:975–1031
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ReadRemoteImportNames(HANDLE process, ULONG_PTR image_base, SIZE_T image_size,
        const IMAGE_IMPORT_DESCRIPTOR & entry, std::wstring & dll_out, std::wstring & function_out)` — Stealth.cpp:1037–1108
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthEnableExceptions(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        DWORD flags, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:1112–1206
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthVerifyExceptionHandling(HANDLE process, DWORD flags, bool have_local_nt, const VERIFIABLE_EXEC_TELEMETRY * exec,
        StealthVerifierBuffers & buffers,
        f_GetLastStringStats get_string_stats, int & step, int total)` — Stealth.cpp:1207–1388
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthExecuteTls(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:1389–1501
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthExecuteDllMain(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)` — Stealth.cpp:1502–1543
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthRunUnderLoaderLock(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)` — Stealth.cpp:1544–1575
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthCleanDataDirectories(const MAP_STATS * MapStats, bool have_remote_nt, BYTE * nt_data, int & step, int total)` — Stealth.cpp:1576–1746
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthSetPageProtections(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:1747–1846
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthVerifyForensicPosture(HANDLE process, HINSTANCE hRemoteBase, const BYTE * local_pe, size_t local_pe_size,
        const WizardConfig & config, StealthVerifierBuffers & buffers, bool & posture_ok,
        int & step, int total)` — Stealth.cpp:1847–2392
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthEraseHeader(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:2393–2571
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool CapturePreLoadBaseline(DWORD pid, StealthVerifierBuffers & buffers)` — Stealth.cpp:2572–2630
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthSurveyHostSurface(const StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:2636–2883
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthSurveyTraps(HANDLE process, DWORD survey_pid, StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:2884–2891
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthVerifyUsermodeVectors(HANDLE process, const HijackStats * process_hijack,
        DWORD survey_pid, const StealthVerifierBuffers & buffers, int & step, int total)` — Stealth.cpp:2892–3021
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)` — Stealth.cpp:3022–3216
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)` — Stealth.cpp:3217–3234
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool EnumerateRemoteModules(HANDLE process, std::vector<SurveyModule> & out)` — Stealth.cpp:3239–3279
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool FindModuleByBase(const std::vector<SurveyModule> & modules, ULONG_PTR base, SurveyModule & out)` — Stealth.cpp:3283–3294
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out)` — Stealth.cpp:3299–3333
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NtQueryInformationProcessFn ResolveNtQueryInformationProcess()` — Stealth.cpp:3341–3352
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out)` — Stealth.cpp:3354–3437
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `LONG NTAPI VehProbeDummyHandler(EXCEPTION_POINTERS *)` — Stealth.cpp:3438–3442
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ProbeLocalVehPathRoundTrip()` — Stealth.cpp:3443–3453
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool QueryRemoteDebugPort(HANDLE process, DebugPortSurvey & out)` — Stealth.cpp:3454–3489
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size)` — Stealth.cpp:3490–3521
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsEncryptedCoreSectionName(const char * name)` — Stealth.cpp:3539–3557
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool FindEncryptedCoreRange(HANDLE process, const SurveyModule & module, EncryptedCoreRange & out)` — Stealth.cpp:3562–3634
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `SIZE_T ReadSurveyBound(const wchar_t * name)` — Stealth.cpp:3635–3653
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers)` — Stealth.cpp:3683–4312
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `MeasureTscHz` (Stealth.cpp:39–83):
  // A plausible TSC runs somewhere between 100 MHz and 10 GHz. A
- keyword lines in `StealthPageDesc` (Stealth.cpp:163–178):
  const wchar_t * StealthPageDesc(DWORD p)
- keyword lines in `StealthVerifyWxExecution` (Stealth.cpp:179–503):
  if (wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
  if (wx_mbi.State == MEM_COMMIT && wx_mbi.Protect != 0 && wx_mbi.Protect != PAGE_NOACCESS)
  if (wx_mbi.Protect == PAGE_EXECUTE_READWRITE)
  else if (wx_mbi.Protect == PAGE_EXECUTE_READ || wx_mbi.Protect == PAGE_EXECUTE)
  else if (wx_mbi.Protect == PAGE_READWRITE)
  if (!(wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
  && (sec_mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
  LOG(0, L"      %lsRWX Region At 0x%016llX, %llu Bytes%s\n", kYellow,
  const DWORD prot = census_mbi.Protect & 0xFFu;
- keyword lines in `StealthVerifyStringEncryption` (Stealth.cpp:504–641):
  static_assert(sizeof(markers) / sizeof(markers[0]) == kStringMarkerCount,
- keyword lines in `StealthResolveImports` (Stealth.cpp:713–856):
  const size_t max_desc = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
  const size_t avail_desc = (local_pe_size - import_off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
  IMAGE_IMPORT_DESCRIPTOR iid = { 0 };
- keyword lines in `StealthInitSecurityCookie` (Stealth.cpp:877–955):
  load_cfg.Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONGLONG))
  ReCa<BYTE *>(hRemoteBase) + load_cfg.VirtualAddress + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie),
  LOG(0, L"  %ls[=]%ls Security Cookie Read-Back.. %ls0x%016llX%ls At VA %ls0x%016llX%ls\n",
  LOG(0, L"  %ls[=]%ls   TLS Callback Array VA (Remote).. %ls0x%016llX%ls\n",
- keyword lines in `ReadRemoteImageString` (Stealth.cpp:975–1031):
  if (c < 0x20 || c > 0x7E)
- keyword lines in `ReadRemoteImportNames` (Stealth.cpp:1037–1108):
  const IMAGE_IMPORT_DESCRIPTOR & entry, std::wstring & dll_out, std::wstring & function_out)
  !IsSafeCodePage(process, slot, sizeof(ULONG_PTR)))
  function_out = L"Ordinal " + std::to_wstring(thunk & 0xFFFF);
  const DWORD name_rva = static_cast<DWORD>(thunk & 0x7FFFFFFFULL);
- keyword lines in `StealthEnableExceptions` (Stealth.cpp:1112–1206):
  LOG(0, L"  %ls[+]%ls VEH First-Chance Survey... PEB = %p | CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | UsingVCH = %ls%s%ls\n",
  LOG(0, L"  %ls[+]%ls PEB Debug Correlates...... BeingDebugged = %ls%u%ls | NtGlobalFlag = %ls0x%08X%ls (Read Back, Not Inferred)\n",
  LOG(0, L"  %ls[!]%ls VEH First-Chance Survey... %lsRead Failed%ls (Err 0x%08X; Nothing Proven)\n",
  LOG(0, L"  %ls[+]%ls Exception Directory    = RVA %ls0x%08X%ls  Size %ls0x%08X%ls  %ls%lu%s Entry(ies)\n",
  LOG(0, L"  %ls[+]%ls .pdata Table     = %ls0x%016llX%ls  First %ls0x%08X%s - %s0x%08X%s\n",
  LOG(0, L"  %ls[!]%ls .pdata Table Not Readable At 0x%016llX\n", kYellow, kReset,
- keyword lines in `StealthVerifyExceptionHandling` (Stealth.cpp:1207–1388):
  LOG(0, L"  %ls[+]%ls Target VEH First-Chance........ CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | PEB = %p (Read Back)\n",
  LOG(0, L"  %ls[!]%ls Target VEH First-Chance........ %lsRead Failed%ls (Err 0x%08X)\n",
  LOG(0, L"  %ls[+]%ls Target Debug Flags........... %ls0x%08X%ls (Read Back)\n",
  LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnreadable%ls (Status 0x%08X; Needs QUERY_INFORMATION)\n",
  dbg.portStatus == static_cast<NTSTATUS>(0xC0000022u) &&
  dbg.flagsStatus == static_cast<NTSTATUS>(0xC0000022u);
  LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnknown%ls (%ls; Port Status 0x%08X, Flags Status 0x%08X)\n",
  LOG(0, L"  %ls[+]%ls Payload Exception Data.......... RVA %ls0x%08X%ls, %ls%lu%ls Entries\n",
- keyword lines in `StealthExecuteTls` (Stealth.cpp:1389–1501):
  if (cb_array[i] == 0 || cb_array[i] == 0xFFFFFFFF)
- keyword lines in `StealthExecuteDllMain` (Stealth.cpp:1502–1543):
  LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu (%.2f ms At A Measured %.2f GHz)\n",
  LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu "
- keyword lines in `StealthRunUnderLoaderLock` (Stealth.cpp:1544–1575):
  L"Was Never Entered (Status Fields Still Hold The 0x%08X Sentinel). No Pass/Fail Is Claimed.\n",
  LOG(0, L"  %ls[+]%ls Loader Lock Telemetry: LdrLockStatus = 0x%08X | Cookie = 0x%llX | State = %u\n",
  LOG(0, L"  %ls[+]%ls Loader Lock Released: LdrUnlockStatus = 0x%08X\n",
- keyword lines in `StealthCleanDataDirectories` (Stealth.cpp:1576–1746):
  LOG(0, L"  %ls[+]%ls Pre-Clean Sizes: Import = %ls0x%08X%ls | DelayImport = %ls0x%08X%ls | Reloc = %ls0x%08X%ls | TLS = %ls0x%08X%ls | Debug = %ls0x%08X%ls | Export = %ls0x%08X%ls\n",
  LOG(0, L"  %ls[*]%ls Residual Mask 0x%08X Across All %zu Directories Was Checked "
  L"0x%08X Across All %zu Directories.\n",
  L"(Mask 0x%08X).\n",
- keyword lines in `StealthSetPageProtections` (Stealth.cpp:1747–1846):
  void StealthSetPageProtections(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
  LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Set Page Protections...\n\n", kGreen, step, kReset, kGreen, total, kReset);
  if (secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) declared = (secs[s].Characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
  else if (secs[s].Characteristics & IMAGE_SCN_MEM_WRITE) declared = PAGE_READWRITE;
  else if (secs[s].Characteristics & IMAGE_SCN_MEM_READ) declared = PAGE_READONLY;
  if (qok) queried = smbi.Protect & 0xFF;
  LOG(0, L"  %-8s 0x%08X  0x%08X  0x%08X  %-13s %-13s %ls\n",
  StealthPageDesc(declared), qok ? StealthPageDesc(queried) : L"Unqueryable",
  if (mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0)
  if (mbi.Protect == PAGE_EXECUTE_READWRITE) ++rwx_count;
  else if (mbi.Protect == PAGE_READONLY) ++ro_count;
  else if (mbi.Protect == PAGE_READWRITE) ++rw_count;
  else if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) ++rx_count;
  if (mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) ++priv_exec_count;
  LOG(0, L"  %ls[x]%ls %d Section(s) Whose Queried Protection Differs From The Declared "
  L"Protection (See Per-Section Verification Column).\n", kRed, kReset, mismatch);
  LOG(0, L"  %ls[x]%ls Section Protections Unverified: Remote Pages Not Queryable (Hard Gate Failure).\n", kRed, kReset);
- keyword lines in `StealthVerifyForensicPosture` (Stealth.cpp:1847–2392):
  LOG(0, L"  %ls%s%ls Debug Directory Size = %ls0x%lX%ls\n",
  const bool payload_ok = payload_check == FILE_ERR_SUCCESS && payload_view.NtHeaders != nullptr;
  const WORD count = payload_view.NtHeaders->FileHeader.NumberOfSections;
  if ((sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
  (sections[s].Characteristics & IMAGE_SCN_MEM_WRITE))
  payload_debug = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
  const DWORD exp_rva = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  LOG(0, L"  %ls[+]%ls Payload Export Names: %ls%zu%ls | Standard Sections: %ls%zu%ls | RWX Sections: %ls%zu%ls | Debug: %ls0x%lX%ls\n",
  survey_lfanew > 0 && survey_lfanew <= 0x10000;
  static_cast<ULONG_PTR>(i) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
  if (entry_addr + sizeof(IMAGE_IMPORT_DESCRIPTOR) > survey_base + survey_size ||
  !IsSafeCodePage(process, entry_addr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
  IMAGE_IMPORT_DESCRIPTOR entry{};
  LOG(0, L"  %ls[!]%ls Target Imports.......... Unreadable (Dir RVA 0x%08X Size 0x%08X)\n",
  else if (exp_rva < survey_size && IsSafeCodePage(process, survey_base + exp_rva, 40))
  else if (tls_rva < survey_size && IsSafeCodePage(process, survey_base + tls_rva, sizeof(IMAGE_TLS_DIRECTORY64)))
  !IsSafeCodePage(process, slot, 8))
  LOG(0, L"  %ls[=]%ls Target Load Config: GuardFlags = %ls0x%08X%ls | CFG Instrumented = %ls%s%ls | Load Config Size = %lu\n",
- keyword lines in `StealthEraseHeader` (Stealth.cpp:2393–2571):
  const unsigned long long wipe_protect = MapStats ? static_cast<unsigned long long>(MapStats->HeaderWipeProtect) : 0;
  const unsigned long long exec_prot = exec ? static_cast<unsigned long long>(exec->PostWipeProtection) : 0;
  const unsigned long long page = si.dwPageSize ? si.dwPageSize : 0x1000;
  if (data[i] == 0x4D && data[i + 1] == 0x5A)
  if (data[i] == 0x50 && data[i + 1] == 0x45 && data[i + 2] == 0x00 && data[i + 3] == 0x00)
  LOG(0, L"  %ls[+]%ls Image Base      = %ls0x%016llX%ls\n",
  const bool noaccess_ok = ((mbi.Protect & 0xFF) == PAGE_NOACCESS);
  switch (mbi.Protect & 0xFF)
  LOG(0, L"  %ls[+]%ls Page Protection Assertion: VirtualQueryEx Verified 0x%llX [PAGE_NOACCESS] | State = MEM_COMMIT\n",
  LOG(0, L"  %ls[x]%ls Page Protection Mismatch: State = 0x%X | Protect = %ls (0x%08X) (Required MEM_COMMIT+PAGE_NOACCESS)\n",
  kRed, kReset, mbi.State, protection, mbi.Protect);
  LOG(0, L"  %ls[*]%ls Pre-Section Span Bound: Span = [0x00000000-0x%llX) | Wiped = %llu Bytes\n",
  LOG(0, L"  %ls[x]%ls Header Page Protection Unreadable: VirtualQueryEx Failed (Hard Gate Failure).\n", kRed, kReset);
  LOG(0, L"  %ls[+]%ls Declared SizeOfHeaders = %ls0x%llX%ls (Span The Loader Would Have Mapped)\n",
  LOG(0, L"  %ls[+]%ls Structural Header Span = %ls0x%llX%ls (DOS Stub + NT Headers + Section Table)\n",
  LOG(0, L"  %ls[+]%ls Zeroed Header Span     = %ls0x%llX%ls (Entire Pre-Section Region; Mapper Telemetry)\n",
  LOG(0, L"  %ls[+]%ls Page-Protected Span    = %ls0x%llX%ls @ %ls%s%ls\n",
  kGreen, StealthPageDesc(static_cast<DWORD>(wipe_protect)), kReset);
  LOG(0, L"  %ls[+]%ls MZ/PE Scan (Pre-Wipe)  = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls0x%llX%ls Byte(s) Of The Mapped Image (In-Shell, Before The Wipe)\n",
  LOG(0, L"  %ls[+]%ls Exec Telemetry Cross-Check: Span = %llu | MZ = %llu | PE = %llu | Prot = 0x%08llX - Post-Wipe Region Holds Nothing\n",
  LOG(0, L"  %ls[x]%ls Exec Telemetry Mismatch: Span = %llu/0x%llX | MZ = %llu (Post) / %llu (Pre) | PE = %llu (Post) / %llu (Pre) | Prot = 0x%08llX/0x%08llX\n",
  const size_t want = static_cast<size_t>(retained_size < 0x1000 ? retained_size : 0x1000);
  LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls%llu%ls Byte(s) Of Retained Allocation %ls0x%llX%ls\n",
  LOG(0, L"  %ls[!]%ls MZ/PE Scan (Host)      = Retained Allocation %ls0x%llX%ls Not Readable (Protection Changed).\n",
  LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = No Other Injection Allocation Remains Readable - The Manual-Map And Thread-Hijack Staging Regions Are Scrubbed And Released Before This Stage, And The Image Header Page Is NOACCESS By Design.\n",
- keyword lines in `StealthSurveyHostSurface` (Stealth.cpp:2636–2883):
  // C3's pagefile signal: ullTotalPageFile is the same commit
  const bool commit_equals_physical = memory.ullTotalPageFile <= memory.ullTotalPhys;
  commit_equals_physical ? kYellow : kGreen, memory.ullTotalPageFile >> 20, kReset,
  kGreen, memory.ullAvailPageFile >> 20, kReset,
  ? L"(Commit Limit Does Not Exceed Physical Memory - The No-Pagefile VM Tell)"
  : L"(Commit Limit Exceeds Physical Memory - Pagefile Present)");
  LOG(0, L"  %ls[!]%ls Memory Surface............ GlobalMemoryStatusEx Failed (0x%08X)\n",
  using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
  using NtQueryObjectFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  auto query_system = ntdll ? ReCa<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
  auto query_object = ntdll ? ReCa<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject")) : nullptr;
  while (static_cast<DWORD>(status) == 0xC0000004u && buffer.size() < (32u << 20))
- keyword lines in `StealthVerifyUsermodeVectors` (Stealth.cpp:2892–3021):
  LOG(0, L"  %ls[*]%ls Integrity Hashing......... Not Measured (Design Assertion): Query-Only And Scan-Only, No Writes To Game Pages\n", kDim, kReset);
- keyword lines in `DebugAndVerifyStealth` (Stealth.cpp:3022–3216):
  if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000)
  if (step_enabled[kStealthSetPageProtections])
  StealthSetPageProtections(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, step, total);
- keyword lines in `ResolveNtQueryInformationProcess` (Stealth.cpp:3341–3352):
  NtQueryInformationProcessFn ResolveNtQueryInformationProcess()
  auto api_name = XOR_STR_A("NtQueryInformationProcess");
  return ReCa<NtQueryInformationProcessFn>(GetProcAddress(mod, api_name.get()));
- keyword lines in `QueryRemoteVehFirstChance` (Stealth.cpp:3354–3437):
  NtQueryInformationProcessFn query = ResolveNtQueryInformationProcess();
  const ULONG_PTR cross_addr = peb + offsetof(PEB, CrossProcessFlags);
  const ULONG_PTR global_flag_addr = peb + offsetof(PEB, NtGlobalFlag);
  const ULONG_PTR image_base_addr = peb + offsetof(PEB, ImageBaseAddress);
  out.usingVeh = (cross & 0x4u) != 0;
  out.usingVch = (cross & 0x8u) != 0;
- keyword lines in `QueryRemoteDebugPort` (Stealth.cpp:3454–3489):
  NtQueryInformationProcessFn query = ResolveNtQueryInformationProcess();
- keyword lines in `IsSafeCodePage` (Stealth.cpp:3490–3521):
  bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size)
  if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
- keyword lines in `FindEncryptedCoreRange` (Stealth.cpp:3562–3634):
  if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
- keyword lines in `ReportGameTraps` (Stealth.cpp:3683–4312):
  constexpr SIZE_T kSurveyChunkBytes = 0x10000;
  max_application_address = 0x00007FFFFFFF0000ULL;
  if (mbi.Protect & PAGE_GUARD)
  else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
  else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
  if (chunk_buf[i] == 0xCC)
  chunk_buf[i] == 0x48 && chunk_buf[i + 1] == 0x8B &&
  chunk_buf[i + 2] == 0x01 && chunk_buf[i + 3] == 0xC3)
  LOG(0, L"      %ls%ls%zu%ls Of %ls%zu%ls Sampled Bytes Are INT3 (%ls0xCC%ls), %ls%zu%s%%, From %ls%zu%ls Of %ls%zu%ls Executable Region(s)\n",
  LOG(0, L"      %ls%ls%zu%ls Hit(s) In The Sampled Executable Region(s) (The Demand-Paging Touch Gadget; A Non-Zero Count Is The Lead For Watching A No-Access Page Turn Readable)\n",
  if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x10000)
  IMAGE_IMPORT_DESCRIPTOR desc{};
  if (array_buf[i] == 0 || array_buf[i] == 0xFFFFFFFF)

D:\Ameger\Injector\Interface\Source\Main.cpp — 5552 lines — sha12:12F00221FBD6
INCLUDES:
- "PCH.h" [project] (Main.cpp:1)
- "Launcher.h" [project] (Main.cpp:2)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- class StdoutParkGuard (Main.cpp:24) fields/constants: `saved_stdout_fd_`, `saved_stderr_fd_`, `saved_stdout_handle_`, `saved_stderr_handle_`, `stdout_nul_`, `stderr_nul_`, `saved_stdout_fd_`, `saved_stderr_fd_`, `nul`, `nul_fd`, `nul_fd`
- class FileHandleGuard (Main.cpp:127) fields/constants: `handle_`
- struct Category (Main.cpp:981) fields/constants: `probe`, `title`
- struct CensusBlock (Main.cpp:987) fields/constants: `start`, `rows`, `open`
- class ConfirmationResult (Main.cpp:1315) fields/constants: `Proceed`, `Cancelled`, `Unavailable`
- struct PhaseRecord (Main.cpp:1496) fields/constants: none detected
- struct Cache (Main.cpp:1994) fields/constants: `path`, `resolved`
- struct FlagBit (Main.cpp:3523) fields/constants: `bit`, `name`
- struct RtlOsVersionInfo (Main.cpp:3840) fields/constants: `dwOSVersionInfoSize`, `dwMajorVersion`, `dwMinorVersion`, `dwBuildNumber`, `dwPlatformId`
- struct HideWindowContext (Main.cpp:3934) fields/constants: `pid`
- class ScratchTargetGuard (Main.cpp:3978) fields/constants: `m_Preexisting`, `m_Process`, `m_ImageName`, `m_Owns`, `return`
- struct ReleasedHandles (Main.cpp:4772) fields/constants: none detected
- struct Coverage (Main.cpp:4944) fields/constants: `label`, `checked`, `note`
FUNCTIONS:
- `public: StdoutParkGuard()` — Main.cpp:32–92
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void reset(HANDLE handle = INVALID_HANDLE_VALUE)` — Main.cpp:161–169
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `HANDLE release()` — Main.cpp:175–181
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool DiscardResultLogOnSuccess()` — Main.cpp:210–223
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool GetOwnExePath(std::wstring & out)` — Main.cpp:224–236
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool MakeRandomExeFileName(std::wstring & out)` — Main.cpp:237–280
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool HasMarker(const std::wstring & commandLine, const wchar_t * marker)` — Main.cpp:281–285
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int GetRetryIndex()` — Main.cpp:286–303
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD FindTrustedBroker(DWORD excludePid)` — Main.cpp:413–498
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SpawnWithSpoofedParent(const std::wstring & exePath, const std::wstring & args, DWORD brokerPid)` — Main.cpp:499–573
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsDeletableSelfCopy(const std::wstring & own_path, const std::wstring & candidate)` — Main.cpp:580–625
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void DeleteOwnSelfCopyIfChild()` — Main.cpp:630–653
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool PolymorphicSelfRename(const std::wstring & parentHint)` — Main.cpp:654–707
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SpawnFreshRetryProcess(int nextRetry)` — Main.cpp:708–774
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void EnableAnsi()` — Main.cpp:803–812
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PrintError(const wchar_t * message)` — Main.cpp:813–833
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PrintWarning(const wchar_t * message)` — Main.cpp:834–854
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void StealthBeep(DWORD frequency, DWORD duration)` — Main.cpp:855–876
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void __stdcall QuietPrint(const char *)` — Main.cpp:888–891
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void __stdcall VerbosePrint(const char * text)` — Main.cpp:894–1173
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ResetRuntimeCategory()` — Main.cpp:1174–1178
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void DetachInterfaceConsole()` — Main.cpp:1179–1193
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool InterfaceConsolePresent()` — Main.cpp:1194–1202
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadLine(const wchar_t * prompt, std::wstring & value)` — Main.cpp:1220–1231
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ParseUnsigned(const std::wstring & text, unsigned long long & value)` — Main.cpp:1232–1250
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `size_t ParseConfigSize(const std::wstring & text, size_t current)` — Main.cpp:1255–1263
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ParseDword(const std::wstring & text, DWORD & value)` — Main.cpp:1264–1275
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadYesNo(const wchar_t * prompt, bool default_value, bool & value)` — Main.cpp:1276–1313
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `ConfirmationResult ConfirmBeforeDetection()` — Main.cpp:1321–1441
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool FileExists(const std::wstring & path)` — Main.cpp:1466–1471
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `size_t & PhaseCount()` — Main.cpp:1510–1515
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `ULONGLONG & T0()` — Main.cpp:1516–1521
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `ULONGLONG NowMs()` — Main.cpp:1522–1526
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void BeginSession()` — Main.cpp:1527–1539
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `PhaseRecord & Begin(const wchar_t * name)` — Main.cpp:1540–1557
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void End(bool ok = true)` — Main.cpp:1558–1578
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Note(const wchar_t * fmt, ...)` — Main.cpp:1579–1595
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void Summary(const wchar_t * outcome)` — Main.cpp:1596–1619
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD PickHijackThreadTid(DWORD target_pid, DWORD exclude_tid)` — Main.cpp:1637–1890
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool EqualsNoCase(const std::wstring & value, const wchar_t * expected)` — Main.cpp:1902–1906
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const std::wstring & ConfigurationPath()` — Main.cpp:1991–2009
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ParseConfigBool(const std::wstring & value, bool default_value)` — Main.cpp:2010–2022
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsValidDeployedFileName(const std::wstring & name)` — Main.cpp:2023–2043
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ParseExportMap(const std::wstring & value, std::vector<ExportNameMap> & map)` — Main.cpp:2044–2109
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const std::string * FindMappedExportName(const std::vector<ExportNameMap> & map, const char * old_name)` — Main.cpp:2110–2125
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool HasConfigBlobMagic(const std::string & raw)` — Main.cpp:2128–2146
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool DecryptConfigBlob(const std::string & raw, std::string & out)` — Main.cpp:2147–2170
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool LoadWizardConfig(WizardConfig & config, std::wstring & path, bool & invalid)` — Main.cpp:2171–2491
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadHandleBytes(HANDLE file, std::vector<BYTE> & bytes)` — Main.cpp:2562–2595
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool VerifyRuntimeBytes(const std::vector<BYTE> & bytes)` — Main.cpp:2596–2652
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool LoadRuntime(Runtime & runtime, const WizardConfig & config)` — Main.cpp:2653–2808
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool WaitForRuntime(const Runtime & runtime, DWORD & symbol_state, DWORD & import_state, DWORD & init_state)` — Main.cpp:2809–2892
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes)` — Main.cpp:2893–2926
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool InspectDll(const std::wstring & path, DWORD flags, FileInformation & info, std::vector<BYTE> & bytes, std::wstring & sha256, DWORD * validation_out = nullptr)` — Main.cpp:2927–3030
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SnapshotWorkingSets(std::vector<std::pair<DWORD, SIZE_T>> & out)` — Main.cpp:3082–3141
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD FindProcess(const std::wstring & requested_name)` — Main.cpp:3149–3208
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool RefreshTarget(TargetSelection & target)` — Main.cpp:3214–3279
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SelectTarget(const std::wstring & configured_name, TargetSelection & target, bool & cancelled, int timeout_ms)` — Main.cpp:3280–3376
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const wchar_t * ArchitectureName(Architecture architecture)` — Main.cpp:3377–3389
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveConfiguredPayload(const std::wstring & dll_dir, const std::wstring & payload_name, const std::wstring & expected_sha256,
        DWORD flags, FileInformation & info, std::vector<BYTE> & bytes)` — Main.cpp:3392–3452
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void ReportPayloadCapabilities(const std::vector<BYTE> & payload, DWORD flags)` — Main.cpp:3453–3519
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void DescribeFlags(DWORD flags)` — Main.cpp:3520–3560
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD BuildFlags(const WizardConfig & config)` — Main.cpp:3561–3616
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PauseBeforeExit()` — Main.cpp:3617–3662
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `const wchar_t * DescribeNtStatus(DWORD status)` — Main.cpp:3663–3711
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PrintFailureHint(DWORD code, DWORD adv_code = 0)` — Main.cpp:3712–3827
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PrintRuntimeFailure(DWORD symbol_state, DWORD import_state, DWORD init_state)` — Main.cpp:3828–3906
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool InjectionFailureIsRetryable(DWORD result)` — Main.cpp:3907–3931
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `BOOL CALLBACK HideWindowCallback(HWND hwnd, LPARAM param)` — Main.cpp:3938–3950
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void HideProcessWindows(DWORD pid)` — Main.cpp:3958–3967
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool StartIfAbsent(const std::wstring & image_name, DWORD & pid_out)` — Main.cpp:4027–4114
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int RunInteractiveWizard(Runtime & runtime)` — Main.cpp:4116–5271
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int RunWizardWithFaultReport(Runtime & runtime)` — Main.cpp:5279–5295
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prevInstance, PWSTR cmdShow, int showCmd)` — Main.cpp:5296–5548
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `DiscardResultLogOnSuccess` (Main.cpp:210–223):
  const auto name = XOR_STR_W(L"AMEGER_DISCARD_RESULT_LOG");
- keyword lines in `MakeRandomExeFileName` (Main.cpp:237–280):
  if (gen && gen(nullptr, entropy, sizeof(entropy), 0x00000002) >= 0)
  tick *= 0xBF58476D1CE4E5B9ull;
  entropy[i] = static_cast<unsigned char>((tick >> ((i % 8) * 8)) & 0xFFu);
- keyword lines in `VerbosePrint` (Main.cpp:894–1173):
  plain.push_back(static_cast<char>(ch & 0xFF));
  { "  0x",               L"Thread Hijack" },
  { "SR_AcquireThread",   L"Thread Hijack" },
- keyword lines in `ConfirmBeforeDetection` (Main.cpp:1321–1441):
  // Extended keys arrive from _getch as a 0 or 0xE0 prefix followed
  // by the scan code; HOME is 0x47 and END is 0x4F.
  if (scan == 0x47)
  if (scan == 0x4F)
  while ((GetAsyncKeyState(VK_HOME) & 0x8000) || (GetAsyncKeyState(VK_END) & 0x8000))
  const bool home_down = (GetAsyncKeyState(VK_HOME) & 0x8000) != 0;
  const bool end_down = (GetAsyncKeyState(VK_END) & 0x8000) != 0;
  while (GetAsyncKeyState(VK_HOME) & 0x8000)
  while (GetAsyncKeyState(VK_END) & 0x8000)
- keyword lines in `PickHijackThreadTid` (Main.cpp:1637–1890):
  using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
  NtQuerySystemInformationFn NtQuery = nullptr;
  auto api_name = XOR_STR_A("NtQuerySystemInformation");
  NtQuery = ReCa<NtQuerySystemInformationFn>(
  if (!NtQuery)
  LONG status = NtQuery(5, buffer.data(), size, &size);
  while (static_cast<DWORD>(status) == 0xC0000004u)
  status = NtQuery(5, buffer.data(), size, &size);
  size_t offset = 0;
  if (offset + offsetof(SYSTEM_PROCESS_INFORMATION, Threads) > buffer.size())
  const auto * proc = ReCa<const SYSTEM_PROCESS_INFORMATION *>(buffer.data() + offset);
  const size_t threads_base = offset + offsetof(SYSTEM_PROCESS_INFORMATION, Threads);
  auto api_name = XOR_STR_A("NtQueryInformationThread");
  offset += proc->NextEntryOffset;
- keyword lines in `IsValidDeployedFileName` (Main.cpp:2023–2043):
  if (c < 0x20 || c == 0x7F)
- keyword lines in `ParseExportMap` (Main.cpp:2044–2109):
  if (c <= 0 || c > 0x7F)
  if (c <= 0 || c > 0x7F)
- keyword lines in `LoadWizardConfig` (Main.cpp:2171–2491):
  if (!config_text.empty() && config_text.front() == 0xFEFF)
  else if (manual && EqualsNoCase(key, XOR_STR_W(L"SetPageProtections").get()))
- keyword lines in `ReadHandleBytes` (Main.cpp:2562–2595):
  LOG(0,  L"%lsFailed To Query Runtime Size = 0x%08X%ls\n", kRed, GetLastError(), kReset);
  LOG(0,  L"%lsFailed To Read Runtime = 0x%08X (%zu Of %zu Bytes)%ls\n", kRed, read_error, total, bytes.size(), kReset);
- keyword lines in `VerifyRuntimeBytes` (Main.cpp:2596–2652):
  LOG(0,  L"%lsRuntime DLL PE Validation Failed = 0x%08X%ls\n", kRed, validation_result, kReset);
  expected_hash.push_back(hex[(word >> shift) & 0x0F]);
- keyword lines in `LoadRuntime` (Main.cpp:2653–2808):
  HANDLE runtime_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  LOG(0,  L"%lsFailed To Open Runtime For Verification = 0x%08X%ls\n", kRed, GetLastError(), kReset);
  runtime.module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  HANDLE verify_reopen = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  LOG(0,  L"%lsFailed To Load Runtime = %ls (0x%08X)%ls\n", kRed, path.c_str(), load_error, kReset);
- keyword lines in `WaitForRuntime` (Main.cpp:2809–2892):
  Trace::Note(L"Symbol Poll Timed Out After %llu ms (%u Polls) | State = 0x%08lX",
  Trace::Note(L"Symbols Ready In %llu ms (%u Polls) | State = 0x%08lX",
  Trace::Note(L"Import Poll Timed Out After %llu ms (%u Polls) | State = 0x%08lX",
  Trace::Note(L"Imports Ready In %llu ms (%u Polls) | State = 0x%08lX",
- keyword lines in `InspectDll` (Main.cpp:2927–3030):
  const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
  if (nt_offset > bytes.size() || bytes.size() - nt_offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
  std::memcpy(&signature, bytes.data() + nt_offset, sizeof(signature));
  std::memcpy(&file_header, bytes.data() + nt_offset + sizeof(DWORD), sizeof(file_header));
  const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  if (file_header.SizeOfOptionalHeader < sizeof(WORD) || optional_offset > bytes.size() || file_header.SizeOfOptionalHeader > bytes.size() - optional_offset)
  std::memcpy(&magic, bytes.data() + optional_offset, sizeof(magic));
  size_t directory_offset = 0;
  directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
  directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
  if (info.architecture == Architecture::Unknown || directory_offset + (static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) + 1) * sizeof(IMAGE_DATA_DIRECTORY) > file_header.SizeOfOptionalHeader)
  const size_t count_offset = directory_offset - sizeof(DWORD);
  std::memcpy(&directory_count, bytes.data() + optional_offset + count_offset, sizeof(directory_count));
  if (directory_count > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
  const size_t com_offset = directory_offset + static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) * sizeof(IMAGE_DATA_DIRECTORY);
  std::memcpy(&com_directory, bytes.data() + optional_offset + com_offset, sizeof(com_directory));
- keyword lines in `SnapshotWorkingSets` (Main.cpp:3082–3141):
  using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
  NtQuerySystemInformationFn query = nullptr;
  query = ReCa<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
  while (static_cast<DWORD>(status) == 0xC0000004u)
  size_t offset = 0;
  if (offset + sizeof(SYSTEM_PROCESS_INFORMATION) > buffer.size())
  const auto * proc = ReCa<const SYSTEM_PROCESS_INFORMATION *>(buffer.data() + offset);
  const DWORD pid = static_cast<DWORD>(ReCa<ULONG_PTR>(proc->UniqueProcessId) & 0xFFFFFFFF);
  offset += proc->NextEntryOffset;
- keyword lines in `ResolveConfiguredPayload` (Main.cpp:3392–3452):
  LOG(0,  L"%lsNot A Usable DLL (PE Validation 0x%08X). Need x64 DLL With Relocations, No .NET.%ls\n",
- keyword lines in `ReportPayloadCapabilities` (Main.cpp:3453–3519):
  const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
  if (nt_offset > payload.size() || payload.size() - nt_offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
  std::memcpy(&file_header, payload.data() + nt_offset + sizeof(DWORD), sizeof(file_header));
  const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  optional_offset > payload.size() ||
  file_header.SizeOfOptionalHeader > payload.size() - optional_offset)
  std::memcpy(&optional, payload.data() + optional_offset, sizeof(optional));
  const size_t offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + static_cast<size_t>(index) * sizeof(IMAGE_DATA_DIRECTORY);
  if (offset + sizeof(IMAGE_DATA_DIRECTORY) > file_header.SizeOfOptionalHeader)
  std::memcpy(&out, payload.data() + optional_offset + offset, sizeof(out));
- keyword lines in `DescribeFlags` (Main.cpp:3520–3560):
  { INJ_NO_DONOR_SCAN,               L"INJ_NO_DONOR_SCAN" },
  LOG(0, L"  %ls[*]%ls Decoded Load Flags = 0x%08lX\n", kDim, kReset, static_cast<unsigned long>(flags));
  LOG(0, L"      %ls%s%ls 0x%08X  %ls\n",
  LOG(0, L"      %ls[!]%ls 0x%08lX  Undecoded Bit(s)\n", kYellow, kReset, static_cast<unsigned long>(unexplained));
- keyword lines in `BuildFlags` (Main.cpp:3561–3616):
  flags |= INJ_NO_DONOR_SCAN;
- keyword lines in `DescribeNtStatus` (Main.cpp:3663–3711):
  const wchar_t * DescribeNtStatus(DWORD status)
  case 0xC0000001u: return L"UNSUCCESSFUL";
  case 0xC0000002u: return L"NOT_IMPLEMENTED";
  case 0xC0000005u: return L"ACCESS_VIOLATION";
  case 0xC0000006u: return L"IN_PAGE_ERROR";
  case 0xC0000008u: return L"INVALID_HANDLE";
  case 0xC000000Du: return L"INVALID_PARAMETER";
  case 0xC0000017u: return L"NO_MEMORY";
  case 0xC0000018u: return L"CONFLICTING_ADDRESSES";
  case 0xC0000022u: return L"ACCESS_DENIED";
  case 0xC0000023u: return L"BUFFER_TOO_SMALL";
  case 0xC0000033u: return L"OBJECT_NAME_INVALID";
  case 0xC0000035u: return L"OBJECT_NAME_COLLISION";
  case 0xC0000043u: return L"SHARING_VIOLATION";
  case 0xC000006Du: return L"LOGON_FAILURE";
  case 0xC000007Fu: return L"DISK_FULL";
  case 0xC00000A0u: return L"MEMORY_NOT_ALLOCATED";
  case 0xC00000E5u: return L"INTERNAL_ERROR";
  case 0xC00000FDu: return L"STACK_OVERFLOW";
  case 0xC0000135u: return L"DLL_NOT_FOUND";
  case 0xC0000138u: return L"ORDINAL_NOT_FOUND";
  case 0xC0000139u: return L"ENTRYPOINT_NOT_FOUND";
  case 0xC000013Au: return L"CONTROL_C_EXIT";
  case 0xC0000142u: return L"DLL_INIT_FAILED";
  case 0xC000014Au: return L"ILLEGAL_FLOAT_CONTEXT";
  case 0xC000014Bu: return L"PIPE_BROKEN";
  case 0xC0000194u: return L"POSSIBLE_DEADLOCK";
  case 0xC00001A5u: return L"INVALID_EXCEPTION_HANDLER";
  case 0xC0000203u: return L"USER_SESSION_DELETED";
  case 0xC0000205u: return L"INSUFF_SERVER_RESOURCES";
  case 0xC0000206u: return L"INVALID_BUFFER_SIZE";
  case 0xC0000225u: return L"NOT_FOUND";
  case 0xC0000235u: return L"HANDLE_NOT_CLOSABLE";
  case 0xC000026Bu: return L"DLL_INIT_FAILED_LOGOFF";
  case 0xC000026Du: return L"DFS_UNAVAILABLE";
  case 0xC0000374u: return L"HEAP_CORRUPTION";
  case 0xC0000409u: return L"STACK_BUFFER_OVERRUN (__fastfail: cookie or GS failure)";
  case 0xC000040Au: return L"NO_S4U_PROT_SUPPORT";
  case 0xC000040Bu: return L"CROSSREALM_DELEGATION_FAILURE";
  case 0xC000041Du: return L"FATAL_USER_CALLBACK_EXCEPTION";
  case 0xC0000481u: return L"APISET_NOT_HOSTED";
  case 0xC0000482u: return L"APISET_NOT_PRESENT";
  case 0x40000015u: return L"FATAL_APP_EXIT";
- keyword lines in `PrintFailureHint` (Main.cpp:3712–3827):
  LOG(0, L"Target Is Likely Protected Or Blocks Remote RW/RX Allocations.\n");
  else if (code == SR_HT_ERR_OPEN_REFUSED)
  else if (code == SR_HT_ERR_NO_THREADS)
  else if (code == SR_ERR_TARGET_EXITED)
  // with exactly 0x40010006 before the guard covered dependencies).
  if (adv_code == 0x40010006u || adv_code == 0x40010082u)
  LOG(0, L"  The Target Exited With DBG_PRINTEXCEPTION_C (0x%08X): An OutputDebugString Call Went\n",
  else if (adv_code == 0xC00000FDu)
  LOG(0, L"  The Target Exited With STATUS_STACK_OVERFLOW (0xC00000FD): A Stack Evaluation Ran\n");
  else if (code == SR_HT_ERR_REMOTE_PENDING_TIMEOUT)
  LOG(0, L"Reason: Unclassified Failure 0x%08lX; See The Runtime Error Header.\n",
- keyword lines in `PrintRuntimeFailure` (Main.cpp:3828–3906):
  LOG(0,  L"%lsUnsupported Windows Build: Local Build %lu (Code 0x%08X).%ls\n",
  LOG(0,  L"%lsUnsupported Windows Version (Code 0x%08X).%ls\n",
  LOG(0,  L"%lsFailed To Initialize The Runtime = 0x%08X%ls\n", kRed, init_state, kReset);
  LOG(0,  L"%lsFailed To Load Symbols = 0x%08X%ls\n", kRed, symbol_state, kReset);
  LOG(0,  L"%lsFailed To Resolve Imports = 0x%08X%ls\n", kRed, import_state, kReset);
- keyword lines in `InjectionFailureIsRetryable` (Main.cpp:3907–3931):
  if (result >= 0x00400000u && result < 0x00500000u)
  if (result >= 0x10200000u && result < 0x10300000u)
- keyword lines in `RunInteractiveWizard` (Main.cpp:4116–5271):
  Trace::Note(L"Symbol State = 0x%08lX", static_cast<unsigned long>(symbol_state));
  Trace::Note(L"Import State = 0x%08lX", static_cast<unsigned long>(import_state));
  LOG(0, L"  %ls[!]%ls Thread Sponsor Pre-Open Failed (0x%08X); Runtime Will Search.\n",
  Trace::Note(L"Thread Sponsor Handle = 0x%08X (TID 0x%04lX)",
  LOG(0, L"  %ls[!]%ls Could Not Open The Target For Read-Only Verification (0x%08X).\n",
  // its granted access IS 0x1010 unless the escalation ran, and the
  // NtQueryObject readback was tried here and could not be relied
  escalated ? L"0x00000410 (Full Query | VM Read)" : L"0x00001010 (Query-Limited | VM Read)",
  LOG(0, L"Requested Sponsor TID %ls0x%04lX%s | Timeout %ls%lu ms%s (Runtime May Reject It; Hijacked Thread Reported On Completion)...\n",
  Trace::Note(L"Flags = 0x%08lX", static_cast<unsigned long>(data.Flags));
  Trace::Note(L"Sponsor Proc = 0x%08X", static_cast<unsigned>(data.hHandleValue));
  Trace::Note(L"Sponsor TID = 0x%08X (Handle 0x%08X)",
  Trace::Note(L"Return Value = 0x%08lX | Elapsed = %llu ms", static_cast<unsigned long>(result),
  if (detail.AdvErrorCode >= 0xC0000000u)
  LOG(0, L"  Adv Is An NTSTATUS From The Target: 0x%08X (%ls).\n",
  detail.AdvErrorCode, DescribeNtStatus(detail.AdvErrorCode));
  if (result >= 0x00400000u && result < 0x00500000u)
  Trace::Note(L"Map Stats: Cleaned = 0x%08X | Residual = 0x%08X | Verified = %u | CachedCopy = %u",
  Trace::Note(L"Thread Exec: TID = 0x%04X | Success = %u | Return Value = 0x%08X | Iterations = %u | Elapsed = %u ms",
  Trace::Note(L"Shell Stack Top = 0x%llX | Window = 0x%llX..0x%llX | Size = %u Bytes | Victim Spill = %u Bytes | Cycles = %llu",
  Trace::Note(L"Exec Telemetry: DllMain = %d | Lock = 0x%08X | Unlock = 0x%08X | TLS = %u/%u/%u",
  Trace::Note(L"Completion Event: Signaled = %u | Status = 0x%08X | Debug-Print Guard = %ls | ODS Imports Redirected = %u | TLS Data = %u | Index = %u | Restored = %u | Bit Cleared = %u | Slot Restored = %u | Entry Unlinked = %u",
  (ExecTelemetry.DebugPrintVehInstalled & 0x10u) ? L"Yes" : L"No",
  ExecTelemetry.DebugPrintVehInstalled & 0xFu,
  LOG(0, L"  %ls[+]%ls Thread Context Restored To Original On TID: %ls0x%04lX%s.\n",
  LOG(0, L"  %ls[!]%ls Thread Context %sNOT Restored%s On TID: %s0x%04lX%s (Code 0x%08lX) - It May Still Be Running Donor Code.\n",
  LOG(0, L"  %ls[!]%ls Sponsor TID %ls0x%04lX%ls Not Usable; Hijacked TID %ls0x%04lX%ls Instead (Donor Scan Fallback).\n",
  VirtualQueryEx(targetHandle, data.hDllOut, &head, sizeof(head)) ? head.Protect : 0;
  while (committed < 0x4000000ULL)
  switch (mbi.Protect)
  LOG(0, L"    [%ls%ls%ls] Image Base %p | First Region Protect %ls%s%s | State %s\n",
  kGreen, stealth::StealthPageDesc(base_prot), kReset,
  L"| Loader Lock 0x%08X/0x%08X | Hijacked TID 0x%04X\n",
  swprintf_s(list + wcslen(list), _countof(list) - wcslen(list), L"%ls0x%04llX%s",
  LOG(0, L"    Either A Mapped Page Is Not RX As Expected, Or The Image Could Not Be Queried\n");
  { L"In-Shell Execution Telemetry", exec_telemetry_read, L"RDTSC Timing, DllMain Result, Loader-Lock, TLS" },
  { L"Page Protections / W^X",         !wx_violated, L"VirtualQueryEx Walk Of The Mapped Image" },
  LOG(0, L"0x%08X (%s)\n", static_cast<unsigned>(result),
  LOG(0, L"Shell Signaled The Host Event | NtSetEvent = 0x%08X | Handle Closed In Target\n",
  LOG(0, L"Not Observed | Status = 0x%08X (The State Poll Still Confirmed Completion)\n",
  // A3: the packed field decodes into its two mechanisms. Bit 0x10
  const unsigned ods_redirects = ExecTelemetry.DebugPrintVehInstalled & 0xFu;
  const bool veh_installed = (ExecTelemetry.DebugPrintVehInstalled & 0x10u) != 0;
  row(L"Debug-Print Protection... ", debug_print_guard_read ? debug_print_guard_ok : true);
  // against the measured TSC frequency. The verdict follows the
  LOG(0, L"0x%08X / 0x%08X\n",
  LOG(0, L"Lock = 0x%08X | Unlock = 0x%08X\n",
  LOG(0, L"TID 0x%04X | Success = %u | Routine Return Value = 0x%08X | %u Poll(s) Over %u ms\n",
  LOG(0, L"Dedicated %u-Byte Stack | Pivot RSP = 0x%llX (%s) | %s | Victim Stack Spill = %u Bytes | Shell Stack Observations = %u\n",
  LOG(0, L"Original RIP = 0x%llX | Original RSP = 0x%llX | Shell Window = 0x%llX..0x%llX | FP Mode %ls\n",
  LOG(0, L"Cleaned Mask = 0x%08X | Residual = 0x%08X | %s\n",
- keyword lines in `RunWizardWithFaultReport` (Main.cpp:5279–5295):
  L"\n%ls[x]%ls The Launcher Faulted During The Run: Exception 0x%08lX. "

D:\Ameger\Injector\Interface\Source\PCH\PCH.cpp — 1 lines — sha12:1CE37CEB4D40
INCLUDES:
- "PCH.h" [project] (PCH.cpp:1)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- none

D:\Ameger\Mapper\Mapper\App\Main.cpp — 1216 lines — sha12:2944EF0F09EA
INCLUDES:
- <Windows.h> [system] (Main.cpp:18)
- <iostream> [system] (Main.cpp:20)
- <string> [system] (Main.cpp:21)
- <vector> [system] (Main.cpp:22)
- <filesystem> [system] (Main.cpp:23)
- <sstream> [system] (Main.cpp:24)
- <iomanip> [system] (Main.cpp:25)
- <cstring> [system] (Main.cpp:26)
- <cstdlib> [system] (Main.cpp:27)
- <bcrypt.h> [system] (Main.cpp:32)
- <wintrust.h> [system] (Main.cpp:33)
- <softpub.h> [system] (Main.cpp:34)
- "../Mapper/Mapper.hpp" [project] (Main.cpp:40)
- "../PE/PE.hpp" [project] (Main.cpp:42)
- "../Utilities/Utilities.hpp" [project] (Main.cpp:43)
- "../Utilities/Console.hpp" [project] (Main.cpp:44)
- "../Provider/Driver.hpp" [project] (Main.cpp:45)
- "../Symbols/Handler/SymbolsHandler.hpp" [project] (Main.cpp:46)
- "Hypervisor.h" [project] (Main.cpp:52)
- "AmgSharedApp.h" [project] (Main.cpp:53)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `const wchar_t* StatusName(NTSTATUS status)` — Main.cpp:78–99
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DWORD RunningBuildNumber()` — Main.cpp:104–110
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool DescribeDriverImage(const std::wstring& path, std::vector<BYTE>* out_image)` — Main.cpp:258–353
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* string when the console input ends(closed or redirected to nothing),
	 * which the caller treats as "no path was given".
	 *
	 * out_image receives the validated bytes, the same ones DescribeDriverImage
	 * summarised.
	 */
	std::wstring PromptForDriverPath(std::vector<BYTE>* out_image)` — Main.cpp:363–404
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int PromptIsHypervisor()` — Main.cpp:420–458
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IndPagesAvailable()` — Main.cpp:466–469
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void PauseBeforeExit()` — Main.cpp:480–490
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)` — Main.cpp:499–519
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int paramExists(const int argc, wchar_t** argv, const wchar_t* param)` — Main.cpp:526–537
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsOptionValue(const int argc, wchar_t** argv, int i)` — Main.cpp:543–553
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool IsElevated()` — Main.cpp:566–585
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `void help()` — Main.cpp:586–592
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int wmain(const int argc, wchar_t** argv)` — Main.cpp:593–1216
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* MmAllocateIndependentPagesEx changed signature in 24 H2(build 26100).
	 * Driver.cpp still calls it with the pre-24H2 shape (size, -1, 0, 0),
	 * which is correct only for earlier builds. The signature cannot be
	 * verified from here, so this refuses on 26100 and later rather than
	 * calling a routine with arguments it may not accept. The default pool
	 * mode is unaffected and is the verified path.
	 *
	 * This runs before the driver file is read and before Driver::Load, so a
	 * refused run has not touched the kernel.
	 */
	if (indPagesMode)` — Main.cpp:647–673
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* There is deliberately no HideMemory() fallback here. It covers
			 * the whole resident range, executable span included, which is the
			 * exact livelock ProtectSelf is being given the span to avoid.
			 */
			if (!Hypervisor::Protect(text_base, text_size))` — Main.cpp:1151–1158
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `StatusName` (Main.cpp:78–99):
  case (NTSTATUS)0xc0350057:           return L"STATUS_HV_SUPPORT_CHECK_FAILED";
- keyword lines in `DescribeDriverImage` (Main.cpp:258–353):
  const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(image.data(), image.size());
  address << L"0x" << std::hex << std::setw(16) << std::setfill(L'0')
  entry << L"0x" << std::hex << static_cast<unsigned int>(nt_headers->OptionalHeader.AddressOfEntryPoint);
- keyword lines in `IndPagesAvailable` (Main.cpp:466–469):
  bool IndPagesAvailable() {
- keyword lines in `IsOptionValue` (Main.cpp:543–553):
  if (paramExists(argc, argv, L"offsetsPath") == i - 1)
- keyword lines in `help` (Main.cpp:586–592):
  LogRaw(L"[+] Usage: Mapper.exe [--free [--force-free]][--indPages][--PassAllocationPtr][--copy-header][--hide][--no-forensics]");
  LogRaw(L"[--dontUpdateOffsets [--offsetsPath \"FilePath\"]] [driver.sys]" << std::endl);
- keyword lines in `wmain` (Main.cpp:593–1216):
  bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
  * MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100).
  if (indPagesMode) {
  Log(L"[-] --indPages: could not determine the running Windows build; refusing to use it." << std::endl);
  Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
  Log(L"[-] --indPages is not supported on Windows build " << Val(build) << L"." << std::endl);
  Log(L"[-] MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100); the call this mapper uses is only valid before that." << std::endl);
  Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
  Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
  int FilePathParamIdx = paramExists(argc, argv, L"offsetsPath");
  std::wstring offsetFilePath = Utilities::GetCurrentAppFolder() + L"\\Offsets.ini";
  Log("[-] Can't set --offsetsPath without set --dontUpdateOffsets" << std::endl);
  Log(L"[-] --offsetsPath requires a file path argument" << std::endl);
  offsetFilePath = argv[FilePathParamIdx + 1];
  Log(L"[+] Setting Offsets File Path To: " << Val(offsetFilePath) << std::endl);
  L"free", L"force-free", L"indPages", L"PassAllocationPtr", L"copy-header",
  L"hide", L"no-forensics", L"dontUpdateOffsets", L"offsetsPath", L"shared-block-va",
  //The argument after --offsetsPath is its value, not a flag.
  * Skipping option values matters: --offsetsPath takes one, and an offsets
  * --offsetsPath a path that ends in .sys and it was taken as the driver, the
  * offsets file was never read from where it was asked for, and the run went
  //where MmAllocateIndependentPagesEx changed (26100+) it falls back to
  auto enableIndPages = []() {
  if (IndPagesAvailable()) {
  if (enableIndPages())
  indPagesMode = true;
  if (enableIndPages())
  indPagesMode = true;
  if (!SymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? Utilities::GetCurrentAppFolder() + L"\\" + SYMBOL_TOOL_EXE : L"")) {
  if (indPagesMode) {
  mode = Mapper::AllocationMode::AllocateIndependentPages;
  * keeps it alive, so the offsets the stub writes remain readable after Mapper.exe
  * allocate a local block as a fallback so direct runs still record offsets.
  * ProtectSelf blanks the mapped image in the nested page table but has to
  if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
  const ULONG64 offset = (text_rva >= header_skip) ? text_rva - header_skip : 0;
  if (offset >= resident_size) {
  const ULONG64 available = resident_size - offset;
  text_base = resident_base + offset;
  * ProtectSelf rewrites the NPT for the mapped image but leaves
  * exact livelock ProtectSelf is being given the span to avoid.
  if (!Hypervisor::Protect(text_base, text_size)) {
- keyword lines in `H2` (Main.cpp:647–673):
  * MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100).
  if (indPagesMode) {
  Log(L"[-] --indPages: could not determine the running Windows build; refusing to use it." << std::endl);
  Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
  Log(L"[-] --indPages is not supported on Windows build " << Val(build) << L"." << std::endl);
  Log(L"[-] MmAllocateIndependentPagesEx changed signature in 24H2 (build 26100); the call this mapper uses is only valid before that." << std::endl);
  Log(L"[-] Use the default pool mode on this build: drop --indPages." << std::endl);
  Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
- keyword lines in `HideMemory` (Main.cpp:1151–1158):
  * exact livelock ProtectSelf is being given the span to avoid.
  if (!Hypervisor::Protect(text_base, text_size)) {

D:\Ameger\Mapper\Mapper\Mapper\Mapper.cpp — 838 lines — sha12:46A075CD014A
INCLUDES:
- "Mapper.hpp" [project] (Mapper.cpp:1)
- <Windows.h> [system] (Mapper.cpp:2)
- <iostream> [system] (Mapper.cpp:3)
- <random> [system] (Mapper.cpp:4)
- "../Utilities/Utilities.hpp" [project] (Mapper.cpp:5)
- "../Utilities/Console.hpp" [project] (Mapper.cpp:7)
- "../Provider/Driver.hpp" [project] (Mapper.cpp:8)
- "../App/NT.hpp" [project] (Mapper.cpp:9)
- "../PE/PE.hpp" [project] (Mapper.cpp:10)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `* target of each fixup is a file controlled RVA(the block's VirtualAddress
 * plus the entry's 12-bit offset), so it has to be proved to lie inside that
 * copy before it is written: a block whose VirtualAddress is outside the image
 * would otherwise patch memory past the end of the mapper's own allocation.
 */
bool Mapper::RelocateImageByDelta(const PE::vec_relocs& relocs, const ULONG64 delta, const ULONG64 image_base, const ULONG64 image_size)` — Mapper.cpp:25–62
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uintptr_t RandomSecurityCookie()` — Mapper.cpp:80–93
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Mapper::FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base)` — Mapper.cpp:112–222
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveImportFromKernel(const Mapper::ImportLookup& request, void*, ULONG64& out_address)` — Mapper.cpp:246–255
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Mapper::ResolveImports(const PE::vec_imports& imports, ImportResolver resolver, void* context)` — Mapper.cpp:256–307
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `ULONG64 Mapper::MapDriver(BYTE* data, size_t data_size, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, NTSTATUS* exitCode, SIZE_T* residentSize)` — Mapper.cpp:328–838
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `RVA` (Mapper.cpp:25–62):
  * plus the entry's 12-bit offset), so it has to be proved to lie inside that
  const uint16_t offset = current_reloc.item[i] & 0xFFF;
  << Val(Hex(current_reloc.address + offset))
  const ULONG64 target = current_reloc.address + offset;
- keyword lines in `Mapper::FixSecurityCookie` (Mapper.cpp:112–222):
  auto headers = PE::GetNtHeaders(local_image, image_size);
  const size_t cookie_field_end = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(uintptr_t);
  static constexpr uintptr_t kDefaultCookie = 0x2B992DDFA232;
  * cookie (0x2B992DDFA232) has, and everything that compares against the
  * 0x139 (subcode 2) inside the driver on its first protected function.
  new_cookie = RandomSecurityCookie() & static_cast<uintptr_t>(0x0000FFFFFFFFFFFFull);
- keyword lines in `Mapper::MapDriver` (Mapper.cpp:328–838):
  const PIMAGE_NT_HEADERS64 nt_headers = PE::GetNtHeaders(data, data_size);
  if (mode == AllocationMode::AllocateIndependentPages)
  kernel_image_base = Driver::MmAllocateIndependentPagesEx(image_size);
  //Page aligned, so the image occupies whole pages: a driver that hides
  kernel_image_base = Driver::AllocatePool(Nt::POOL_TYPE::NonPagedPool, image_size);
  if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
  if (mode == AllocationMode::AllocateIndependentPages)
  auto ProtectionToString = [](ULONG prot) -> const char* {
  if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
  prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
  else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
  else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
  << L" Prot: " << Val(ProtectionToString(prot))
  if (!Driver::MmSetPageProtection(secAddr, secSize, prot)) {
  * Reached by hooking NtAddAtom (see Driver::CallKernelFunction), which
  Log(L"[!] ntoskrnl.NtAddAtom was not restored; the image is kept because the "
  if (mode == AllocationMode::AllocateIndependentPages)
  free_status = Driver::MmFreeIndependentPages(realBase, image_size);
  if (mode == AllocationMode::AllocateIndependentPages)
  free_status = Driver::MmFreeIndependentPages(kernel_image_base, image_size);

D:\Ameger\Mapper\Mapper\PE\PE.cpp — 403 lines — sha12:110F7209C660
INCLUDES:
- "PE.hpp" [project] (PE.cpp:6)
- <Windows.h> [system] (PE.cpp:8)
- <string> [system] (PE.cpp:10)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `PIMAGE_NT_HEADERS64 PE::GetNtHeaders(void* image_base, size_t image_size)` — PE.cpp:11–45
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool PE::GetSectionTable(void* image_base, size_t image_size, PIMAGE_SECTION_HEADER& out_sections, uint16_t& out_count)` — PE.cpp:54–92
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool PE::GetRelocs(void* image_base, size_t image_size, vec_relocs& relocs)` — PE.cpp:93–163
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool PE::GetImports(void* image_base, size_t image_size, vec_imports& imports)` — PE.cpp:164–336
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool PE::VerifyNoAbsoluteReferences(void* image_base, size_t image_size)` — PE.cpp:345–403
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `PE::GetNtHeaders` (PE.cpp:11–45):
  PIMAGE_NT_HEADERS64 PE::GetNtHeaders(void* image_base, size_t image_size) {
  //e_magic is at offset 0 and e_lfanew at 0x3C, so the DOS header has to fit
  //entries and the offset of the section table - is a different width or a
  //different offset there, so parsing one as PE32+ yields values that look
- keyword lines in `PE::GetSectionTable` (PE.cpp:54–92):
  const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);
  //as an offset into the buffer that can be range checked without any pointer
  //The NT header's offset is e_lfanew, taken from the DOS header, rather than a
  //and truncating, which turns every e_lfanew below 264 into an offset of 0.
  //e_lfanew is the field GetNtHeaders just validated and used to place the
  const size_t nt_offset = static_cast<size_t>(dos_header->e_lfanew);
  const size_t table_offset = nt_offset
  + offsetof(IMAGE_NT_HEADERS, OptionalHeader)
  if (table_offset > image_size || table_bytes > image_size - table_offset)
  reinterpret_cast<BYTE*>(image_base) + table_offset);
- keyword lines in `PE::GetRelocs` (PE.cpp:93–163):
  const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);
- keyword lines in `PE::GetImports` (PE.cpp:164–336):
  const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);
  auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<ULONG64>(image_base) + import_va);
  while (reinterpret_cast<ULONG64>(current_import_descriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image_limit) {
  import_function_data.ordinal = static_cast<uint16_t>(name_table->u1.Ordinal & 0xFFFF);
- keyword lines in `PE::VerifyNoAbsoluteReferences` (PE.cpp:345–403):
  const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base, image_size);
  for (ULONG32 offset = 0; offset + sizeof(ULONG64) <= scan_length; offset += sizeof(ULONG64)) {
  const ULONG64 value = *reinterpret_cast<const ULONG64*>(start + offset);

D:\Ameger\Mapper\Mapper\Provider\Driver.cpp — 3444 lines — sha12:1187AB4C6485
INCLUDES:
- "Driver.hpp" [project] (Driver.cpp:16)
- <Windows.h> [system] (Driver.cpp:18)
- <string> [system] (Driver.cpp:20)
- <fstream> [system] (Driver.cpp:21)
- <filesystem> [system] (Driver.cpp:22)
- <memory> [system] (Driver.cpp:23)
- <random> [system] (Driver.cpp:24)
- <sstream> [system] (Driver.cpp:25)
- <vector> [system] (Driver.cpp:26)
- <iostream> [system] (Driver.cpp:27)
- "Provider.hpp" [project] (Driver.cpp:28)
- "Resource.hpp" [project] (Driver.cpp:30)
- "../Utilities/Utilities.hpp" [project] (Driver.cpp:31)
- "../Utilities/Console.hpp" [project] (Driver.cpp:32)
- "../Service/Service.hpp" [project] (Driver.cpp:33)
- "../App/NT.hpp" [project] (Driver.cpp:34)
- "../PE/PE.hpp" [project] (Driver.cpp:35)
- "../Symbols/Handler/SymbolsHandler.hpp" [project] (Driver.cpp:36)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct PatchedEntry (Driver.cpp:1849) fields/constants: `entry_address`, `original`
- struct KernelModuleHeaders (Driver.cpp:2489) fields/constants: `image_size`, `export_rva`, `export_size`
FUNCTIONS:
- `bool IsKernelAddress(uint64_t value)` — Driver.cpp:106–108
  Summary: Determines whether a value is a kernel address.
- `bool ProbeKernelAddressMapped(uint64_t address)` — Driver.cpp:112–133
  Summary: Checks whether a kernel address is mapped.
- `bool ProbeKernelRangeMapped(uint64_t address, uint64_t size)` — Driver.cpp:138–158
  Summary: Checks whether an entire kernel range is mapped.
- `* Replaces srand(time(NULL) * GetCurrentThreadId()) + rand(). That seed is
 * guessable - two runs started in the same second on the same thread id
 * collide - and rand() is a low quality LCG whose output is predictable from a
 * few samples. Both consumers want bytes an observer cannot anticipate: the
 * provider name is matched against kernel structures during cleanup, and the
 * file overwrite is forensic.
 *
 * Seeded lazily on first use so there is no separate init step to forget, and
 * shared by every consumer so the name and the wipe draw from one stream.
 */
static std::mt19937_64& RandomEngine()` — Driver.cpp:163–176
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* The shape is unchanged from the rand() version: 10..29 characters drawn from
 * the 52 letters in alphanum, so every forensic matcher downstream still sees
 * the same format.
 */
std::wstring Driver::GetDriverNameW()` — Driver.cpp:185–207
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::IsRunning()` — Driver.cpp:226–234
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NTSTATUS Driver::AcquireDebugPrivilege()` — Driver.cpp:238–251
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* Any failure calls Unload(), so a partially loaded run leaves nothing behind.
 */
NTSTATUS Driver::Load()` — Driver.cpp:264–436
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint32_t VerifyWdFilterListHead(uint64_t block_base, uint32_t candidate_offset)` — Driver.cpp:466–507
  Summary: Validates the head pointer of the Warden filter list.
- `* too(or the zero an unused slot holds), so a misaligned pair of fields is
 * caught by the contents rather than by their shape.
 *
 * The number of entries checked is capped: it is the count's own claim, not a
 * window of the array, so a large count on a correct pair is verified fully
 * enough without turning a wrong pair into a long scan.
 */
static bool WdFilterCountAndArrayAgree(uint64_t block_base, uint32_t count_offset, uint32_t array_offset)` — Driver.cpp:516–563
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool FindWdFilterRuntimeDriverBlock(uint64_t block_base,
	uint32_t& out_count_offset, uint32_t& out_array_offset, uint32_t& out_list_offset)` — Driver.cpp:585–627
  Summary: Finds a Warden runtime driver block.
- `bool WdFilterFileNameMatches(const std::wstring& candidate, const std::wstring& driver_name)` — Driver.cpp:659–673
  Summary: Compares a candidate filter file name against a driver name.
- `bool WdFilterFindNameInEntry(uintptr_t entry, const std::wstring& driver_name,
	uint32_t& out_offset, UNICODE_STRING& out_str, std::wstring& out_name)` — Driver.cpp:679–723
  Summary: Searches a Warden filter entry for a driver name.
- `bool WdFilterFindDriverInfo(uintptr_t entry, uintptr_t& out_info)` — Driver.cpp:729–752
  Summary: Resolves the driver info pointer from a Warden filter entry.
- `* not contain this provider(nothing to remove) and when the entry was
 * removed. Returns false only when a partial write may have occurred.
 */
bool Driver::ClearWdFilterDriverList()` — Driver.cpp:776–1130
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NTSTATUS Driver::Unload()` — Driver.cpp:1150–1326
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size)` — Driver.cpp:1327–1337
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::ReadMemory(uint64_t address, void* buffer, uint64_t size)` — Driver.cpp:1346–1348
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::WriteMemory(uint64_t address, void* buffer, uint64_t size)` — Driver.cpp:1352–1354
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* Internal types whose layout is not in the public PDBs(_PiDDBCacheEntry,
 * HashBucketEntry and the WdFilter driver info) still need field offsets.
 * Instead of trusting a hardcoded number, locate the field by content: scan the
 * object for a UNICODE_STRING that actually contains the string we are looking
 * for. A match is its own proof, so the offset can be trusted afterwards, and a
 * miss is a clean abort instead of a corrupted kernel structure.
 */

//Read the string a UNICODE_STRING points at, after checking that the structure
//itself is plausible: a kernel range pointer, a non zero length that fits the
//field and is a whole number of characters, and a MaximumLength that covers
//the Length. Returns false rather than following a bad pointer.
static bool ReadWideStringField(const UNICODE_STRING& text, std::wstring& out)` — Driver.cpp:1382–1408
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint32_t FindUnicodeStringFieldByContent(uint64_t object, size_t object_size, const std::wstring& needle)` — Driver.cpp:1426–1441
  Summary: Finds a Unicode string field by content inside a kernel object.
- `uint64_t PteAddressForBase(uint64_t pte_base, uint64_t virtual_address)` — Driver.cpp:1481–1484
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t PteAddressFor(uint64_t virtual_address)` — Driver.cpp:1488–1490
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t SelfMapIndex(uint64_t pte_base)` — Driver.cpp:1508–1510
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t PdeBaseFor(uint64_t pte_base)` — Driver.cpp:1511–1514
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t PdeAddressForBase(uint64_t pde_base, uint64_t virtual_address)` — Driver.cpp:1517–1520
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t PdeAddressFor(uint64_t virtual_address)` — Driver.cpp:1523–1525
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ResolveMmPteBase()` — Driver.cpp:1538–1576
  Summary: Resolves the MM PTE base needed for kernel read/write operations.
- `* the ntoskrnl image base, whose 2 MB PDE(or 4K PTE, on a build that does not
 * use large pages) must be a present supervisor leaf. Kernel page tables are
 * shared by every process, so the entry read back is the same no matter whose
 * context the provider's copy runs in, and everything the mapper needs to write
 * (the NtAddAtom page in ntoskrnl's read-only .text) is a kernel address anyway.
 *
 * Reading a PTE for a large-page VA returns the page content, not an entry, so
 * the probe checks the PDE for the ntoskrnl image and never treats that content
 * as a PTE - a mistake that an earlier version made and that led straight to a
 * write into the read-only .text page.
 *
 * The addresses are computed with the candidate base explicitly. They cannot use
 * PteAddressFor here: that reads the verified base, which this function is what
 * sets, so during the probe it is still zero and every address computed from it
 * is wrong - that is what made an earlier version report 0 valid entries and
 * disable the read-only write primitive.
 */
static bool ProbePteSelfMapBase()` — Driver.cpp:1587–1810
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `*      when the page is part of a large page(PS=1), otherwise the 4K PTE
 *   4. save that entry, then set RW and clear NX on it
 *   5. perform the write
 *   6. restore every saved entry
 *
 * The original entries are restored on every path after they are read,
 * including when the write fails, so a failed attempt does not leave kernel
 * pages writable.
 *
 * No TLB invalidation is performed between the patch and the write. That is
 * not an oversight and cannot be fixed from here: see the note at the write
 * itself, which explains why the invalidation this function would need is not
 * reachable without recursing into this same function.
 */
	bool Driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size)` — Driver.cpp:1824–1970
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Driver::MmAllocateIndependentPagesEx(uint32_t size)` — Driver.cpp:1991–2011
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::MmFreeIndependentPages(uint64_t address, uint32_t size)` — Driver.cpp:2014–2029
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `BOOLEAN Driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)` — Driver.cpp:2035–2060
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Driver::AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size)` — Driver.cpp:2066–2090
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Driver::AllocateContiguous(uint64_t size)` — Driver.cpp:2100–2123
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::MmFreeContiguousMemory(uint64_t address)` — Driver.cpp:2126–2140
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::FreePool(uint64_t address)` — Driver.cpp:2143–2157
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* max(floor, highest written field + its size) and the teardown used to bound its
 * read by the floor alone, so on a build whose resolved _DRIVER_OBJECT.DriverUnload
 * sits past 0x150 - which is exactly the case the max() in the constructor exists
 * to handle - ReadBoundedPointer refused, DestroyDriverObjectForEntry returned
 * false, and both pool blocks leaked. Deriving it from the same expression at
 * both ends means the two cannot disagree.
 *
 * Every field the constructor writes is included, not only DriverUnload: the
 * constructor's own bound has to cover all of them, and the teardown has to
 * agree with whatever the constructor actually sized.
 */
static uint64_t DriverObjectNeededSize()` — Driver.cpp:2192–2224
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ZeroKernelMemory(uint64_t destination, uint64_t size)` — Driver.cpp:2230–2239
  Summary: Zeros a bounded kernel memory range.
- `bool WriteBounded(uint64_t object, uint64_t object_size, uint32_t offset, const T& value)` — Driver.cpp:2249–2253
  Summary: Writes a bounded value into a kernel object at a fixed offset.
- `bool ReadBoundedPointer(uint64_t object, uint64_t object_size, uint32_t offset, uint64_t& out)` — Driver.cpp:2256–2261
  Summary: Reads a bounded pointer from a kernel object.
- `bool ReadBoundedULong(uint64_t object, uint64_t object_size, uint32_t offset, uint32_t& out)` — Driver.cpp:2264–2269
  Summary: Reads a bounded 32-bit value from a kernel object.
- `uint64_t Driver::CreateDriverObjectForEntry(uint64_t driver_start, uint64_t driver_size, uint64_t driver_section)` — Driver.cpp:2270–2407
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::DestroyDriverObjectForEntry(uint64_t driver_object)` — Driver.cpp:2408–2429
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ReadModuleString(uint64_t module_base, uint64_t module_size, uint32_t rva, std::string& out)` — Driver.cpp:2463–2479
  Summary: Reads a string field from a kernel module at an RVA.
- `operator bool()` — Driver.cpp:2496–2496
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `KernelModuleHeaders ReadKernelModuleHeaders(uint64_t kernel_module_base)` — Driver.cpp:2498–2527
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name)` — Driver.cpp:2550–2645
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::ClearMmUnloadedDrivers()` — Driver.cpp:2664–2814
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Driver::GetKernelModuleExportOrdinal(uint64_t kernel_module_base, uint16_t ordinal)` — Driver.cpp:2824–2883
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait)` — Driver.cpp:2888–2904
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::ExReleaseResourceLite(PVOID Resource)` — Driver.cpp:2907–2921
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `BOOLEAN Driver::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer)` — Driver.cpp:2924–2939
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `PVOID Driver::RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer)` — Driver.cpp:2943–2962
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Driver::ClearPiDDBCacheTable()` — Driver.cpp:3000–3172
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `* Matching is done on the expected name length first(the full path minus the
 * two characters of "\??") and then on the content, so the fast path only does
 * one small read for entries that cannot match.
 *
 * The entry is unlinked and its pool block freed, and the lock is released on
 * every path. An entry that does not verify is skipped rather than unlinked.
 */
bool Driver::ClearKernelHashBucketList()` — Driver.cpp:3182–3444
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `IsKernelAddress` (Driver.cpp:106–108):
  return value >= 0xFFFF000000000000ULL;
- keyword lines in `ProbeKernelRangeMapped` (Driver.cpp:138–158):
  if (size == 0 || size > 0x10000)
- keyword lines in `Driver::AcquireDebugPrivilege` (Driver.cpp:238–251):
  NTSTATUS Status = Nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
- keyword lines in `Unload` (Driver.cpp:264–436):
  //Replace every structural offset we can with the real one for this build.
  Driver::g_offsets.LoadFromSymbols();
  if (Driver::g_offsets.ResolvedFromSymbols)
  Log(L"[+] Structure offsets resolved from symbols for this build (" << Val(Driver::g_offsets.ResolvedFieldCount)
  Log(L"[!] Structure offsets partially resolved: " << Val(Driver::g_offsets.ResolvedFieldCount)
- keyword lines in `VerifyWdFilterListHead` (Driver.cpp:466–507):
  static uint32_t VerifyWdFilterListHead(uint64_t block_base, uint32_t candidate_offset) {
  if (!Driver::ReadMemory(block_base + candidate_offset, &head, sizeof(head)))
  const uint64_t self = block_base + candidate_offset;
  return candidate_offset;
  * offset in the block - so they are the reads most likely to be handed an
  return candidate_offset;
- keyword lines in `too` (Driver.cpp:516–563):
  static bool WdFilterCountAndArrayAgree(uint64_t block_base, uint32_t count_offset, uint32_t array_offset) {
  if (!Driver::ReadMemory(block_base + count_offset, &count, sizeof(count)) ||
  !Driver::ReadMemory(block_base + array_offset, &array, sizeof(array)))
  * This loop runs for every (count_offset, array_offset) candidate pair in the
- keyword lines in `FindWdFilterRuntimeDriverBlock` (Driver.cpp:585–627):
  uint32_t& out_count_offset, uint32_t& out_array_offset, uint32_t& out_list_offset) {
  constexpr uint32_t kScanWindow = 0x200;
  for (uint32_t offset = 0; offset < kScanWindow; offset += sizeof(void*)) {
  if (VerifyWdFilterListHead(block_base, offset)) {
  list_head = offset;
  for (uint32_t count_offset = 0; count_offset < kScanWindow; count_offset += sizeof(ULONG)) {
  if (count_offset == list_head)
  const int candidate_static = static_cast<int>(count_offset) + relative;
  const uint32_t array_offset = static_cast<uint32_t>(candidate_static);
  if (array_offset == count_offset || array_offset == list_head || array_offset >= kScanWindow)
  if (!WdFilterCountAndArrayAgree(block_base, count_offset, array_offset))
  out_count_offset = count_offset;
  out_array_offset = array_offset;
  out_list_offset = list_head;
- keyword lines in `WdFilterFindNameInEntry` (Driver.cpp:679–723):
  uint32_t& out_offset, UNICODE_STRING& out_str, std::wstring& out_name) {
  out_offset = static_cast<uint32_t>(off);
- keyword lines in `provider` (Driver.cpp:776–1130):
  //The offsets come from WdFilter's PDB, which is not always published.
  //Treat a missing offset like the module not being loaded: skip the
  Log("[INFO] WdFilter offsets unavailable, clear skipped" << std::endl);
  * not a public UDT, so its member offsets cannot come from the PDB. They
  * offset inside WdFilter's data.
  * The offsets are derived here from two properties that hold for the
  uint32_t runtime_count_offset = 0;
  uint32_t runtime_array_offset = 0;
  uint32_t runtime_list_offset = 0;
  if (!FindWdFilterRuntimeDriverBlock(MpBmDocOpenRules, runtime_count_offset, runtime_array_offset, runtime_list_offset)) {
  //how a missing module or missing offsets are treated above.
  const uintptr_t RuntimeDriversList_Head = MpBmDocOpenRules + runtime_list_offset;
  const uintptr_t RuntimeDriversCount = MpBmDocOpenRules + runtime_count_offset;
  uintptr_t RuntimeDriversArray = MpBmDocOpenRules + runtime_array_offset;
  Log(L"[+] WdFilter runtime driver block located at count " << Val(Hex(runtime_count_offset))
  << L", array " << Val(Hex(runtime_array_offset))
  << L", list head " << Val(Hex(runtime_list_offset)) << std::endl);
  if (list_array < 0xFFFF000000000000ULL) {
  if (reinterpret_cast<uintptr_t>(list_head.Flink) < 0xFFFF000000000000ULL ||
  reinterpret_cast<uintptr_t>(list_head.Blink) < 0xFFFF000000000000ULL) {
  Log("[INFO] WdFilter offsets unavailable, clear skipped" << std::endl);
  //faulted inside the provider (bugcheck 0x50), and a circular corruption
  Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
  //field offsets, so ci.dll's HashBucketEntry_DriverName (0x8) must not
  uint32_t wd_name_offset = 0;
  if (WdFilterFindNameInEntry(reinterpret_cast<uintptr_t>(Entry), Driver::GetDriverNameW(), wd_name_offset, Unicode_String, wd_matched_name)) {
  if (((uint64_t)Unicode_String.Buffer) < 0xFFFF000000000000ULL ||
  //Proven entry: its name matched by content at wd_name_offset.
  //Entry-0x10 alone cannot distinguish a wrong delta that happens
  //to equal a different live entry's pointer, and Entry-0x20 plus
  //0xDA18 alone is a value check, not a layout check. Both are
  //Discover the array base instead of assuming Entry-0x10: the
  //the info elsewhere that merely has 0xDA18 at some other
  //offset still fails unless the whole triple lines up.
  //or unmapped link previously became a write to kernel 0x8
  const uint64_t entry_flink_addr = entry_addr + offsetof(LIST_ENTRY, Flink);
  const uint64_t entry_blink_addr = entry_addr + offsetof(LIST_ENTRY, Blink);
  const uint64_t next_blink_addr = next_raw + offsetof(LIST_ENTRY, Blink);
  const uint64_t prev_flink_addr = prev_raw + offsetof(LIST_ENTRY, Flink);
  * address of the count field, offset by one so it can
  //a real zero must not wrap to 0xFFFFFFFF.
  << L" | name_off " << Val(Hex(static_cast<int32_t>(wd_name_offset)))
- keyword lines in `Driver::Unload` (Driver.cpp:1150–1326):
  * as long as the provider is resident - verified on a run where NtUnloadDriver
- keyword lines in `PDBs` (Driver.cpp:1382–1408):
  * HashBucketEntry and the WdFilter driver info) still need field offsets.
  * for. A match is its own proof, so the offset can be trusted afterwards, and a
  if ((uint64_t)text.Buffer < 0xFFFF000000000000ULL)
- keyword lines in `FindUnicodeStringFieldByContent` (Driver.cpp:1426–1441):
  for (uint32_t offset = 0; offset + sizeof(UNICODE_STRING) <= object_size; offset += sizeof(void*)) {
  if (!Driver::ReadMemory(object + offset, &candidate, sizeof(candidate)))
  return offset;
- keyword lines in `PteAddressForBase` (Driver.cpp:1481–1484):
  const uint64_t canonical = virtual_address & 0x0000FFFFFFFFFFFFULL;
- keyword lines in `SelfMapIndex` (Driver.cpp:1508–1510):
  return (pte_base >> 39) & 0x1FFULL;
- keyword lines in `PdeAddressForBase` (Driver.cpp:1517–1520):
  const uint64_t canonical = virtual_address & 0x0000FFFFFFFFFFFFULL;
- keyword lines in `ResolveMmPteBase` (Driver.cpp:1538–1576):
  const auto pte_base_offset = SymbolsHandler::GetInstance()->GetOffset(L"MmPteBase");
  if (pte_base_offset == 0) {
  if (!Driver::ReadMemory(Driver::ntoskrnlAddr + pte_base_offset, &pte_base, sizeof(pte_base))) {
  //(0x100..0x1FF). Checking the shape rejects a wrong symbol long before any
  const uint64_t kKernelHalf = 0xFFFF000000000000ULL;
  const uint64_t kLowIndexBits = 0x0000007FFFFFFFFFULL;
  const uint64_t index = (pte_base >> 39) & 0x1FFULL;
  index < 0x100ULL || index > 0x1FFULL) {
- keyword lines in `PDE` (Driver.cpp:1587–1810):
  * (the NtAddAtom page in ntoskrnl's read-only .text) is a kernel address anyway.
  * A 4K leaf: KUSER_SHARED_DATA (0xFFFFF78000000000) is a fixed single page
  * plausible frame number. That is the level the NtAddAtom hook has to patch,
  const uint64_t kUserSharedData = 0xFFFFF78000000000ULL;
  const uint64_t reported = ms.ullTotalPhys / 0x1000;
  << L" | PFN = " << Val(Hex((kusd_pte >> 12) & 0xFFFFFFFFFULL))
  const uint64_t kusd_pfn = (kusd_pte >> 12) & 0xFFFFFFFFFULL;
  const bool kusd_ok = kusd_read && (kusd_pte & 0x1) && !(kusd_pte & 0x4) && !(kusd_pte & (1ULL << 7)) &&
  << L" | PFN = " << Val(Hex((nt_pde >> 12) & 0xFFFFFFFFFULL))
  const uint64_t nt_pde_pfn = (nt_pde >> 12) & 0xFFFFFFFFFULL;
  const bool nt_2mb_ok = nt_pde_read && (nt_pde & 0x1) && !(nt_pde & 0x4) && (nt_pde & (1ULL << 7)) &&
  const uint64_t nt_pte_pfn = (nt_pte >> 12) & 0xFFFFFFFFFULL;
  const bool nt_4k_ok = nt_pte_read && (nt_pte & 0x1) && !(nt_pte & 0x4) && !(nt_pte & (1ULL << 7)) &&
  * addresses: the kernel alias 0xFFFFF78000000000 and the per-process user
  * alias 0x000000007FFE0000. Both PTEs live in the same self-mapped page
  * PTE for 0x000000007FFE0000 only yields the right entry while the provider's
  const uint64_t kUserSharedDataUser = 0x000000007FFE0000ULL;
  const uint64_t kusd_user_pfn = (kusd_user_pte >> 12) & 0xFFFFFFFFFULL;
  const bool kusd_user_ok = kusd_user_read && (kusd_user_pte & 0x1) && !(kusd_user_pte & (1ULL << 7)) &&
- keyword lines in `page` (Driver.cpp:1824–1970):
  const uint64_t first_page = address & ~0xFFFULL;
  const uint64_t last_page = (address + (uint64_t)size - 1) & ~0xFFFULL;
  const uint32_t page_count = (uint32_t)((last_page - first_page) / 0x1000) + 1;
  const uint64_t target = first_page + (uint64_t)page * 0x1000;
  * 0x50. Read the PDE and, when PS=1, patch the PDE instead.
  const bool large = (pde & 0x1) && (pde & (1ULL << 7));
  if (!(original & 0x1)) {
  Log(L"[-] Page-table entry " << Val(Hex(original))
  patched_value |= 0x2;             //RW
  * copy below fault inside the provider (bugcheck 0x50), so invalidating
  * function to write the read-only NtAddAtom page. Invalidating here by
- keyword lines in `Driver::MmAllocateIndependentPagesEx` (Driver.cpp:1991–2011):
  uint64_t Driver::MmAllocateIndependentPagesEx(uint32_t size)
  static uint64_t kernel_MmAllocateIndependentPagesEx = 0;
  if (!kernel_MmAllocateIndependentPagesEx)
  kernel_MmAllocateIndependentPagesEx = SymbolsHandler::GetInstance()->GetOffset(L"MmAllocateIndependentPagesEx");
  if (!kernel_MmAllocateIndependentPagesEx) {
  Log(L"[-] Failed to find MmAllocateIndependentPagesEx" << std::endl);
  kernel_MmAllocateIndependentPagesEx += Driver::ntoskrnlAddr;
  //(size, -1, 0, 0) matches the assumed MmAllocateIndependentPagesExFn above.
  if (!Driver::CallKernelFunction(&allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
- keyword lines in `Driver::MmFreeIndependentPages` (Driver.cpp:2014–2029):
  bool Driver::MmFreeIndependentPages(uint64_t address, uint32_t size)
  static uint64_t kernel_MmFreeIndependentPages = 0;
  if (!kernel_MmFreeIndependentPages)
  kernel_MmFreeIndependentPages = SymbolsHandler::GetInstance()->GetOffset(L"MmFreeIndependentPages");
  if (!kernel_MmFreeIndependentPages) {
  Log(L"[-] Failed to find MmFreeIndependentPages" << std::endl);
  kernel_MmFreeIndependentPages += Driver::ntoskrnlAddr;
  return Driver::CallKernelFunction<void>(nullptr, kernel_MmFreeIndependentPages, address, size);
- keyword lines in `Driver::MmSetPageProtection` (Driver.cpp:2035–2060):
  BOOLEAN Driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
  Log(L"[-] Invalid address passed to MmSetPageProtection" << std::endl);
  static uint64_t kernel_MmSetPageProtection = 0;
  if (!kernel_MmSetPageProtection)
  kernel_MmSetPageProtection = SymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
  if (!kernel_MmSetPageProtection) {
  Log(L"[-] Failed to find MmSetPageProtection" << std::endl);
  kernel_MmSetPageProtection += Driver::ntoskrnlAddr;
  if (!Driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
- keyword lines in `Driver::AllocatePool` (Driver.cpp:2066–2090):
  uint64_t Driver::AllocatePool(Nt::POOL_TYPE pool_type, uint64_t size) {
- keyword lines in `max` (Driver.cpp:2192–2224):
  * sits past 0x150 - which is exactly the case the max() in the constructor exists
  const auto& o = Driver::g_offsets;
  const auto require = [&needed](uint32_t offset, uint64_t width) {
  const uint64_t end = static_cast<uint64_t>(offset) + width;
- keyword lines in `ZeroKernelMemory` (Driver.cpp:2230–2239):
  const uint64_t chunk = (size - done) < sizeof(kZeroPage) ? (size - done) : sizeof(kZeroPage);
  if (!Driver::MemCopy(destination + done, reinterpret_cast<uint64_t>(kZeroPage), chunk))
- keyword lines in `WriteBounded` (Driver.cpp:2249–2253):
  static bool WriteBounded(uint64_t object, uint64_t object_size, uint32_t offset, const T& value) {
  if (offset > object_size || sizeof(T) > object_size - offset)
  return Driver::MemCopy(object + offset, reinterpret_cast<uint64_t>(&value), sizeof(T));
- keyword lines in `ReadBoundedPointer` (Driver.cpp:2256–2261):
  static bool ReadBoundedPointer(uint64_t object, uint64_t object_size, uint32_t offset, uint64_t& out) {
  if (offset > object_size || sizeof(uint64_t) > object_size - offset)
  return Driver::ReadMemory(object + offset, &out, sizeof(out));
- keyword lines in `ReadBoundedULong` (Driver.cpp:2264–2269):
  static bool ReadBoundedULong(uint64_t object, uint64_t object_size, uint32_t offset, uint32_t& out) {
  if (offset > object_size || sizeof(uint32_t) > object_size - offset)
  return Driver::ReadMemory(object + offset, &out, sizeof(out));
- keyword lines in `Driver::CreateDriverObjectForEntry` (Driver.cpp:2270–2407):
  if (driver_size > 0xFFFFFFFFull) {
  const auto& o = Driver::g_offsets;
  * The blocks cover every offset the resolved layout can name, plus the x64
  * offsets differ. Derived from the same expression DestroyDriverObjectForEntry
  const uint64_t extension = AllocatePool(Nt::POOL_TYPE::NonPagedPool, extension_needed);
  const uint64_t object = AllocatePool(Nt::POOL_TYPE::NonPagedPool, object_needed);
  * _DRIVER_EXTENSION begins with DriverObject, at offset 0 - the PDB type
  * version of this code that guessed "Size at 0, Driver at 0x18" would have
- keyword lines in `Driver::DestroyDriverObjectForEntry` (Driver.cpp:2408–2429):
  //_DRIVER_OBJECT offsets reach past it.
  if (!ReadBoundedPointer(driver_object, DriverObjectNeededSize(), Driver::g_offsets.DriverObject_DriverExtension, extension) ||
- keyword lines in `ReadKernelModuleHeaders` (Driver.cpp:2498–2527):
  if (dos_header.e_lfanew < 0 || dos_header.e_lfanew > kMaxNtHeaderOffset)
- keyword lines in `Driver::ClearMmUnloadedDrivers` (Driver.cpp:2664–2814):
  NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
  status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
  auto system_handle_inforamtion = static_cast<Nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);
  const Nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];
  if (!ReadMemory(object + g_offsets.FileObject_DeviceObject, &device_object, sizeof(device_object)) || !device_object) {
  Log(L"[-] Failed to find device_object (offset " << Val(Hex(g_offsets.FileObject_DeviceObject)) << L")" << std::endl);
  Log(L"[-] device_object is not a kernel address, the offsets do not match this build" << std::endl);
  if (!ReadMemory(device_object + g_offsets.DeviceObject_DriverObject, &driver_object, sizeof(driver_object)) || !driver_object) {
  Log(L"[-] Failed to find driver_object (offset " << Val(Hex(g_offsets.DeviceObject_DriverObject)) << L")" << std::endl);
  Log(L"[-] driver_object is not a kernel address, the offsets do not match this build" << std::endl);
  if (!ReadMemory(driver_object + g_offsets.DriverObject_DriverSection, &driver_section, sizeof(driver_section)) || !driver_section) {
  Log(L"[-] Failed to find driver_section (offset " << Val(Hex(g_offsets.DriverObject_DriverSection)) << L")" << std::endl);
  Log(L"[-] driver_section is not a kernel address, the offsets do not match this build" << std::endl);
  if (!ReadMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
  Log(L"[-] Failed to find driver name (offset " << Val(Hex(g_offsets.LdrEntry_BaseDllName)) << L")" << std::endl);
  if (((uint64_t)us_driver_base_dll_name.Buffer) < 0xFFFF000000000000ULL ||
  //an offset that is wrong for this build and happens to land on a different
  << Val(expected_name) << L"\", the offsets do not point at it; refusing to write" << std::endl);
  if (!WriteMemory(driver_section + g_offsets.LdrEntry_BaseDllName, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
- keyword lines in `Driver::RtlLookupElementGenericTableAvl` (Driver.cpp:2943–2962):
  PVOID Driver::RtlLookupElementGenericTableAvl(Nt::PRTL_AVL_TABLE Table, PVOID Buffer) {
- keyword lines in `Driver::ClearPiDDBCacheTable` (Driver.cpp:3000–3172):
  Nt::PRTL_AVL_TABLE PiDDBCacheTable = (Nt::PRTL_AVL_TABLE)(Driver::ntoskrnlAddr + PiDDBCacheTableOffset);
  * very binary carries. GetNtHeaders returns null for anything that is not a
  const auto provider_headers = PE::GetNtHeaders((void*)Resource::driver, sizeof(Resource::driver));
  Nt::PiDDBCacheEntry* pFoundEntry = (Nt::PiDDBCacheEntry*)LookupEntry(PiDDBCacheTable, timestamp, n.c_str());
  //DriverName field is located by content instead of by a hardcoded offset,
  //and only that verified offset is used below.
  //The scan window is the real size of _PiDDBCacheEntry, not a round 0x80.
  //The struct is 0x38 bytes, so a 0x80 window read up to 0x48 bytes past it -
  //examines offsets a UNICODE_STRING can actually occupy, and the real
  //DriverName (offset 0x10) is still inside that range.
  const uint32_t name_field = FindUnicodeStringFieldByContent((uint64_t)pFoundEntry, sizeof(Nt::PiDDBCacheEntry), needle);
  //The sentinel, not 0: _PiDDBCacheEntry.DriverName really does sit at 0x10
  if (!ReadMemory((uintptr_t)pFoundEntry + g_offsets.PiDDBCacheEntry_ListBlink, &prev, sizeof(_LIST_ENTRY*))) {
  if (!ReadMemory((uintptr_t)pFoundEntry + g_offsets.PiDDBCacheEntry_ListFlink, &next, sizeof(_LIST_ENTRY*))) {
  const uint64_t prev_flink_addr = reinterpret_cast<uint64_t>(prev) + offsetof(struct _LIST_ENTRY, Flink);
  const uint64_t next_blink_addr = reinterpret_cast<uint64_t>(next) + offsetof(struct _LIST_ENTRY, Blink);
  if (!ReadMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG))) {
  if (!WriteMemory((uintptr_t)PiDDBCacheTable + g_offsets.AvlTable_DeleteCount, &cacheDeleteCount, sizeof(ULONG))) {
- keyword lines in `first` (Driver.cpp:3182–3444):
  Nt::HashBucketEntry* prev = (Nt::HashBucketEntry*)g_KernelHashBucketList;
  Nt::HashBucketEntry* entry = 0;
  * kMaxExportEntries, kMaxNtHeaderOffset) and this one was not, while holding
  * g_HashCacheLock - an auto-boosted ERESOURCE. The 0x13C
  //The HashBucketEntry layout is not in the public PDB, so the DriverName offset
  //stays at its compiled default (0x8) and is confirmed by content on each
  //entry: the name is read from that offset and matched against this run's name.
  //A wrong offset cannot produce a UNICODE_STRING whose buffer holds our random
  //driver name, so a match is its own proof and the offset is never trusted on
  !ProbeKernelRangeMapped((uint64_t)entry, sizeof(Nt::HashBucketEntry))) {
  if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName, &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
  * DriverName is a UNICODE_STRING at entry+0x8, so its Buffer is
  * 0x28680043005C0070, is exactly MaximumLength(0x70) |
  * <padding> | Buffer&0xFFFF, which is the 0x3B that took a
  * session. Use offsetof(UNICODE_STRING, Buffer) so the layout
  if (!ReadMemory((uintptr_t)entry + g_offsets.HashBucketEntry_DriverName + offsetof(UNICODE_STRING, Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
  //DriverName offset produces a plausible-looking pointer into
  * read from the verified offset is the layout check. The stored
  * thread kept AutoBoostActive set and bugchecked 0x13C
  Nt::HashBucketEntry* Next = 0;

D:\Ameger\Mapper\Mapper\Service\Service.cpp — 191 lines — sha12:E8156A35D11F
INCLUDES:
- "Service.hpp" [project] (Service.cpp:9)
- <Windows.h> [system] (Service.cpp:11)
- <string> [system] (Service.cpp:12)
- <iostream> [system] (Service.cpp:13)
- "../Utilities/Console.hpp" [project] (Service.cpp:14)
- "../App/NT.hpp" [project] (Service.cpp:16)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `NTSTATUS Service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName)` — Service.cpp:19–128
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `NTSTATUS Service::StopAndRemove(const std::wstring& serviceName)` — Service.cpp:129–191
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `Service::RegisterAndStart` (Service.cpp:19–128):
  //NtLoadDriver needs this privilege, which a normal administrator token has
  NTSTATUS ntStatus = Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
  ntStatus = Nt::NtLoadDriver(&serviceStr);
  Log(L"[+] NtLoadDriver Status " << Val(Hex(ntStatus)) << std::endl);
  Log("[-] Can't delete service registry key after NtLoadDriver failure" << std::endl);
  * needs it. StopAndRemove does need it (NtUnloadDriver requires the same
  * NtUnloadDriver, which is why restoring it here does not block the
  Nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE, FALSE, &restored);
- keyword lines in `Service::StopAndRemove` (Service.cpp:129–191):
  * NtUnloadDriver needs SeLoadDriverPrivilege enabled, just like NtLoadDriver.
  * disabled again. Calling NtUnloadDriver without it fails with
  * STATUS_PRIVILEGE_NOT_HELD (0xc0000061): the driver stays loaded, its
  const NTSTATUS priv_status = Nt::RtlAdjustPrivilege(kSeLoadDriverPrivilege, TRUE, FALSE, &SeLoadDriverWasEnabled);
  Log(L"[-] Failed to enable SeLoadDriverPrivilege for NtUnloadDriver (" << Val(Hex(priv_status)) << L")" << std::endl);
  NTSTATUS st = Nt::NtUnloadDriver(&serviceStr);
  Log(L"[+] NtUnloadDriver Status: " << Val(Hex(st)) << std::endl);
  Nt::RtlAdjustPrivilege(kSeLoadDriverPrivilege, FALSE, FALSE, &restored);

D:\Ameger\Mapper\Mapper\Symbols\Engine\SymbolEngine.cpp — 611 lines — sha12:FE40B76E5316
INCLUDES:
- "SymbolEngine.hpp" [project] (SymbolEngine.cpp:20)
- "../../Utilities/Console.hpp" [project] (SymbolEngine.cpp:22)
- <Windows.h> [system] (SymbolEngine.cpp:23)
- <string> [system] (SymbolEngine.cpp:25)
- <memory> [system] (SymbolEngine.cpp:26)
- <random> [system] (SymbolEngine.cpp:27)
- <filesystem> [system] (SymbolEngine.cpp:28)
- <iostream> [system] (SymbolEngine.cpp:29)
- <iomanip> [system] (SymbolEngine.cpp:30)
- <cstdio> [system] (SymbolEngine.cpp:31)
- <dbghelp.h> [system] (SymbolEngine.cpp:32)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct DbgHelp (SymbolEngine.cpp:43) fields/constants: `module`, `path`, `here`, `enum`, `name`, `slot`, `false`
- struct DebugIdentity (SymbolEngine.cpp:148) fields/constants: `hasGuid`
FUNCTIONS:
- `bool Bind(const char* name, T& slot)` — SymbolEngine.cpp:65–72
  Summary: Binds a resolved symbol name to a function pointer slot.
- `bool BindAll()` — SymbolEngine.cpp:73–85
  Summary: Binds all resolved symbols to their slots.
- `bool Load()` — SymbolEngine.cpp:97–126
  Summary: Loads and parses a PDB file using debug help utilities.
- `const DbgHelp& Dbg()` — SymbolEngine.cpp:128–137
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `DebugIdentity IdentityOf(const SYMSRV_INDEX_INFOW& info)` — SymbolEngine.cpp:154–168
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool SameIdentity(const DebugIdentity& a, const DebugIdentity& b)` — SymbolEngine.cpp:169–174
  Summary: Compares two debug identities for equality.
- `bool GetFieldOffsetInternal(HANDLE hProcess, ULONG64 ModBase, const std::wstring& structName, const std::wstring& fieldName, ULONG64& outOffset, std::wstring& matchedName)` — SymbolEngine.cpp:468–551
  Summary: Uses symbol tools or DBGHelp to resolve a struct field offset from a PDB.

KEYWORD_LINES:
- keyword lines in `Load` (SymbolEngine.cpp:97–126):
  module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
- keyword lines in `IdentityOf` (SymbolEngine.cpp:154–168):
  DebugIdentity IdentityOf(const SYMSRV_INDEX_INFOW& info) {
- keyword lines in `GetFieldOffsetInternal` (SymbolEngine.cpp:468–551):
  //Members have to be enumerated before their offsets can be read;

D:\Ameger\Mapper\Mapper\Symbols\Handler\SymbolsHandler.cpp — 529 lines — sha12:23D1F2EC97F8
INCLUDES:
- "SymbolsHandler.hpp" [project] (SymbolsHandler.cpp:9)
- <algorithm> [system] (SymbolsHandler.cpp:11)
- <string> [system] (SymbolsHandler.cpp:12)
- <iostream> [system] (SymbolsHandler.cpp:13)
- <fstream> [system] (SymbolsHandler.cpp:14)
- <filesystem> [system] (SymbolsHandler.cpp:15)
- <utility> [system] (SymbolsHandler.cpp:16)
- <vector> [system] (SymbolsHandler.cpp:17)
- "../../Utilities/Utilities.hpp" [project] (SymbolsHandler.cpp:18)
- "../../Utilities/Console.hpp" [project] (SymbolsHandler.cpp:20)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- class ScopedPathChange (SymbolsHandler.cpp:34) fields/constants: `ReloadFile`, `length`, `truncation`, `had_value_`
- struct LoadedEntry (SymbolsHandler.cpp:277) fields/constants: `section`, `name`, `offset`
FUNCTIONS:
- `public: ScopedPathChange()` — SymbolsHandler.cpp:36–54
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool ParseOffset(const std::wstring& text, unsigned long long& out)` — SymbolsHandler.cpp:97–130
  Summary: Parses a wide-string offset into an unsigned long long.
- `bool RunSymbolTool(const std::wstring& tool_path, DWORD& exit_code)` — SymbolsHandler.cpp:147–192
  Summary: Runs the external symbol tool and captures its exit code.
- `bool SymbolsHandler::ReloadFile(const std::wstring& requestedPath, const std::wstring& updater)` — SymbolsHandler.cpp:194–517
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `unsigned long long SymbolsHandler::GetOffset(const std::wstring& name)` — SymbolsHandler.cpp:518–522
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `unsigned long long SymbolsHandler::GetFieldOffset(const std::wstring& structAndField)` — SymbolsHandler.cpp:526–529
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `ParseOffset` (SymbolsHandler.cpp:97–130):
  //No sign. An offset in this file is a byte count or an address, both
  //which then reads as a valid offset until whatever uses it is 2^64 bytes
- keyword lines in `RunSymbolTool` (SymbolsHandler.cpp:147–192):
  Log(L"[-] Failed to start the offset updater, error "
  Log(L"[-] The offset updater did not finish within 120s; terminating it" << std::endl);
- keyword lines in `SymbolsHandler::ReloadFile` (SymbolsHandler.cpp:194–517):
  //offsets instead of leaving nothing behind.
  Log(L"[-] Failed to update offsets (exit code " << Val(static_cast<unsigned long>(exitCode)) << L")" << std::endl);
  //themselves are a flat name = offset list.
  Log(L"[-] Failed to open offsets file" << std::endl);
  unsigned long long offset = 0;
  auto offset = Trim(line.substr(pos + 1));
  //the whole mapper down on a malformed offsets file. ParseOffset throws
  if (!ParseOffset(offset, parsed)) {
  Log(L"[-] Skipping malformed offset for " << Val(name) << std::endl);
  Log(L"[-] Duplicate entry for " << Val(name) << L" with conflicting offsets ("
  * This list groups them the way the mapper consumes them - the offsets the
  * for DriverEntry, then the extension members - so a wrong offset stands out
  * The order groups the offsets by what they are for rather than by the
  * so before the mapper reads it - but the line belongs with the offsets it
  * produced, and the head of the group is occupied by the offsets that are
  L"MmAllocateIndependentPagesEx",
  L"MmFreeIndependentPages",
  L"MmSetPageProtection",
  * last offset the mapper resolves before its first kernel call.
  << L" | Offset = " << Val(Hex(entry.offset)) << std::endl);
  << L" | Offset = " << Val(Hex(entry.offset)) << std::endl);
  Log(L"[-] " << Val(path) << L" does not describe this build's offsets"

D:\Ameger\Mapper\Mapper\Symbols\Main.cpp — 377 lines — sha12:65F05A91DA8A
INCLUDES:
- <Windows.h> [system] (Main.cpp:14)
- <algorithm> [system] (Main.cpp:16)
- <vector> [system] (Main.cpp:18)
- <string> [system] (Main.cpp:19)
- <utility> [system] (Main.cpp:20)
- <filesystem> [system] (Main.cpp:21)
- <fstream> [system] (Main.cpp:22)
- <iostream> [system] (Main.cpp:23)
- <sstream> [system] (Main.cpp:24)
- "Engine/SymbolEngine.hpp" [project] (Main.cpp:25)
- "../Utilities/Console.hpp" [project] (Main.cpp:27)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- struct ResolvedSymbol (Main.cpp:46) fields/constants: `name`, `offset`
- struct ResolvedField (Main.cpp:58) fields/constants: `structName`, `fieldName`, `matchedName`, `offset`, `optional`
FUNCTIONS:
- `bool Resolved()` — Main.cpp:64–65
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `int wmain()` — Main.cpp:71–377
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `wmain` (Main.cpp:71–377):
  { L"ntoskrnl.exe", L"MmAllocateIndependentPagesEx" },
  { L"ntoskrnl.exe", L"MmFreeIndependentPages" },
  { L"ntoskrnl.exe", L"MmSetPageProtection" },
  //Structure field offsets. Each one replaces a hardcoded numeric offset that
  //omitted from the report; the mapper derives their offsets at runtime by
  * build's real offsets, not a guess.
  //at runtime instead of trusting a compiled-in offset.
  const auto offsets = engine.GetOffset(pdbPath, symbols);
  if (offsets.size() != symbols.size()) {
  content << symbols[i] << L"=" << std::dec << offsets[i] << std::endl;
  * Publish anything that resolved, including one at offset 0.
  * The previous test was offset != 0, which dropped
  * its resolved offset is 0, and writing "=0" was mistaken for a
  content << fields[i].structName << L"." << fields[i].fieldName << L"=" << std::dec << fieldResults[i].offset << std::endl;
  resolvedSymbols.push_back({ symbols[i], offsets[i] });
  fieldResults[i].matchedName, fieldResults[i].offset, fields[i].optional });
  *   - the offsets the cleanup walks dereference to reach an object come
  L"MmAllocateIndependentPagesEx",
  L"MmFreeIndependentPages",
  L"MmSetPageProtection",
  Log(L"[+] Symbol " << Val(symbol.name) << L" Offset: " << Val(Hex(symbol.offset)) << std::endl);
  //Field | Offset = 0x.., so the name and the value are separated by a
  << L" (as " << Val(field.matchedName) << L") | Offset = " << Val(Hex(field.offset)) << std::endl);
  << L" | Offset = " << Val(Hex(field.offset)) << std::endl);
  //type stream, so the mapper derives its offset at runtime instead.
  //Group C: the PDBs the offsets were resolved from.

D:\Ameger\Mapper\Mapper\Utilities\Utilities.cpp — 209 lines — sha12:E2EA921D0743
INCLUDES:
- "Utilities.hpp" [project] (Utilities.cpp:6)
- "Console.hpp" [project] (Utilities.cpp:8)
- <Windows.h> [system] (Utilities.cpp:9)
- <iostream> [system] (Utilities.cpp:10)
- <string> [system] (Utilities.cpp:11)
- <vector> [system] (Utilities.cpp:12)
- <fstream> [system] (Utilities.cpp:13)
- "../App/NT.hpp" [project] (Utilities.cpp:14)
DEFINES:
- none
EXTERNS/USING/TYPEDEFS:
- none
TYPES:
- none
FUNCTIONS:
- `bool Utilities::ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer)` — Utilities.cpp:52–85
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `bool Utilities::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size)` — Utilities.cpp:86–97
  Summary: UNVERIFIED: signature recorded; body not fully read.
- `uint64_t Utilities::GetKernelModuleAddress(const std::string& module_name)` — Utilities.cpp:98–197
  Summary: UNVERIFIED: signature recorded; body not fully read.

KEYWORD_LINES:
- keyword lines in `Utilities::GetKernelModuleAddress` (Utilities.cpp:98–197):
  NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
  status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(Nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
  const auto modules = static_cast<Nt::PRTL_PROCESS_MODULES>(buffer);
  //OffsetToFileName is an offset into that field; a value past the end
