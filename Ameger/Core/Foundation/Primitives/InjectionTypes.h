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


	DWORD VictimStackBytes = 0;







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



	DWORD HeaderStructuralSize = 0;
	DWORD HeaderWipeSize = 0;
	DWORD HeaderWipeProtect = 0;
	DWORD HeaderScanBytes = 0;
	DWORD HeaderScanMZ = 0;
	DWORD HeaderScanPE = 0;



	DWORD VerifiedCachedCopy = 0;


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







#define SYSCALL_SAMPLE_COUNT	16

// Tier 2: the fake-stack pivot frame is 8 ntdll `ret` gadgets + 1 restore gadget
// (xchg rsp, rdi; ret) that hands RSP back to the real stack. Pre-populated at
// build time by BuildSyscallStubs; the sampler pivots RSP onto it before the syscall.
#define FAKE_STACK_SLOTS	9

// Written by the emitted syscall stubs inside the target (one ring slot per syscall issued
// through a sampled stub). The emitted sampler strides the ring by 96 bytes (`imul r14, 96`),
// so the sample MUST be exactly 96 bytes; the static_assert below enforces that. Frames[8] are
// the 8 stack qwords [rsp+0..56] captured AT SYSCALL TIME (while the shell stack is still
// mapped), so the verifier resolves them from the ring instead of re-reading the released stack.
struct SYSCALL_SAMPLE
{
	DWORD		ThreadId;		// offset 0   TEB->ClientId.UniqueThread (gs:0x48)
	ULONGLONG	Rsp;			// offset 8   captured RSP at the instant the syscall fires
	ULONGLONG	CycleCount;		// offset 16  TSC captured at the instant the syscall fires
	BYTE		FunctionId;		// offset 24  which remote stub (0..SC_REMOTE_STUB_COUNT-1) issued it
	ULONGLONG	Frames[8];		// offset 32  64 bytes = [rsp+0..56] captured at syscall time
};

static_assert(sizeof(SYSCALL_SAMPLE) == 96,
	"SYSCALL_SAMPLE must stride the sampler ring by exactly 96 bytes");

struct VERIFIABLE_EXEC_TELEMETRY
{
	ULONG_PTR LoaderLockCookie = 0;
	unsigned __int64 DllMainCyclesDelta = 0;
	PVOID TlsLastExecutedAddress = nullptr;
	PVOID InvertedTableEntryBase = nullptr;
	SIZE_T PreSectionSpanWiped = 0;





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


	DWORD TlsLoaderEntryUnlinked = 0;


	DWORD TlsLoaderEntryAbsent = 0;

	DWORD Reserved = 0;




	DWORD TlsIndex = 0;
	DWORD TlsHasData = 0;
	DWORD TlsIndexRestored = 0;
	DWORD TlsBitmapBitCleared = 0;
	DWORD TlsSlotCleared = 0;
	NTSTATUS TlsLockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;
	NTSTATUS TlsUnlockStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;



	DWORD CompletionEventSignaled = 0;
	NTSTATUS CompletionEventStatus = AMEGER_NTSTATUS_UNSUCCESSFUL;








	DWORD DebugPrintVehInstalled = 0;

	// Vector 7: live syscall-stack sampling ring, written by the emitted sampled stubs inside
	// the target. SyscallSampleIndex is the next slot to write (wraps mod SYSCALL_SAMPLE_COUNT).
	SYSCALL_SAMPLE SyscallSamples[SYSCALL_SAMPLE_COUNT];
	volatile LONG  SyscallSampleIndex = 0;

	// Tier 2 stack spoof: pre-populated at host build time by BuildSyscallStubs with 8 ntdll
	// `ret` (C3) gadgets followed by 1 restore gadget (xchg rsp, rdi; ret). The sampler block
	// pivots RSP onto FakeStack before the syscall; its RET chain unwinds FakeStack[0..7] then
	// the restore gadget, which reads the real RSP the sampler parked in SavedRealRsp and in
	// rdi, and returns to the shell's real return address.
	ULONGLONG FakeStack[FAKE_STACK_SLOTS];
	ULONGLONG SavedRealRsp = 0;
};

// Layout: 14 qwords + 26 dwords (no internal padding) + the 1536-byte ring (16 x 96) + the
// 4-byte index + the Tier 2 fake stack (9 x 8 qwords) + SavedRealRsp (8 bytes). The 4-byte
// index leaves 4 alignment bytes before the 8-byte FakeStack (and the round-up term also
// covers any trailing pad), so round the sum to a multiple of 8 the same way the compiler
// does. With the 96-byte sample the block is 1760 bytes; the 80-byte Tier 2 addition makes it 1840.
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) ==
	((14 * sizeof(ULONG_PTR) + 26 * sizeof(DWORD)
		+ SYSCALL_SAMPLE_COUNT * sizeof(SYSCALL_SAMPLE) + sizeof(LONG)
		+ FAKE_STACK_SLOTS * sizeof(ULONGLONG) + sizeof(ULONGLONG)
		+ (sizeof(ULONG_PTR) - 1)) & ~(sizeof(ULONG_PTR) - 1)),
	"the telemetry block is published a word at a time, so its size must be exact");
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) == 1840,
	"telemetry is 1760 + 80 (Tier 2 FakeStack[9] + SavedRealRsp) = 1840");
static_assert(sizeof(VERIFIABLE_EXEC_TELEMETRY) % sizeof(LONG) == 0,
	"the telemetry block is published a word at a time, so its size must be a whole number of words");
