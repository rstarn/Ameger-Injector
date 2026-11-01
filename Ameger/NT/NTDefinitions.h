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

typedef enum class _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation			= 0,
	SectionImageInformation			= 1
} SECTION_INFORMATION_CLASS;






typedef enum class _KTHREAD_STATE : ULONG
{
	Unknown = 0x00,
	Running = 0x02,
	Waiting = 0x05
} KTHREAD_STATE;

// The complete KWAIT_REASON table, transcribed from the installed SDK's
// 10.0.26100.0/km/wdm.h (`Executive`..`MaximumWaitReason`, 0x00..0x2B). Every ordinal has to
// stay numerically identical to the SDK's: one shifted entry turns WrQueue into a "self-waking
// delay" and rejects the one donor a wake nudge can actually reach.
typedef enum class _KWAIT_REASON : ULONG
{
	Executive			= 0x00,
	FreePage			= 0x01,
	PageIn				= 0x02,
	PoolAllocation		= 0x03,
	DelayExecution		= 0x04,
	Suspended			= 0x05,
	UserRequest			= 0x06,
	WrExecutive			= 0x07,
	WrFreePage			= 0x08,
	WrPageIn			= 0x09,
	WrPoolAllocation	= 0x0A,
	WrDelayExecution	= 0x0B,
	WrSuspended			= 0x0C,
	WrUserRequest		= 0x0D,
	WrSpare0			= 0x0E,
	WrQueue				= 0x0F,
	WrLpcReceive		= 0x10,
	WrLpcReply			= 0x11,
	WrVirtualMemory		= 0x12,
	WrPageOut			= 0x13,
	WrRendezvous		= 0x14,
	WrKeyedEvent		= 0x15,
	WrTerminated		= 0x16,
	WrProcessInSwap		= 0x17,
	WrCpuRateControl	= 0x18,
	WrCalloutStack		= 0x19,
	WrKernel			= 0x1A,
	WrResource			= 0x1B,
	WrPushLock			= 0x1C,
	WrMutex				= 0x1D,
	WrQuantumEnd		= 0x1E,
	WrDispatchInt		= 0x1F,
	WrPreempted			= 0x20,
	WrYieldExecution	= 0x21,
	WrFastMutex			= 0x22,
	WrGuardedMutex		= 0x23,
	WrRundown			= 0x24,
	WrAlertByThreadId	= 0x25,
	WrDeferredPreempt	= 0x26,
	WrPhysicalFault		= 0x27,
	WrIoRing			= 0x28,
	WrMdlCache			= 0x29,
	WrRcu				= 0x2A,
	MaximumWaitReason	= 0x2B
} KWAIT_REASON;

static_assert(static_cast<ULONG>(KWAIT_REASON::DelayExecution) == 4 &&
	static_cast<ULONG>(KWAIT_REASON::UserRequest) == 6 &&
	static_cast<ULONG>(KWAIT_REASON::WrDelayExecution) == 11 &&
	static_cast<ULONG>(KWAIT_REASON::WrUserRequest) == 13 &&
	static_cast<ULONG>(KWAIT_REASON::WrQueue) == 15 &&
	static_cast<ULONG>(KWAIT_REASON::MaximumWaitReason) == 43,
	"KWAIT_REASON must stay ordinal-identical to the SDK's wdm.h");

namespace WAIT_REASON_SAFE
{











	// The four reasons a suspended donor can be resumed out of. The ordinals come from
	// KWAIT_REASON above; the previous parallel byte table was shifted, so WrQueue (15) was
	// read as WrDelayExecution and treated as a self-waking delay, while WrUserRequest (13) -
	// a GUI thread parked in GetMessage, the one donor a PostThreadMessage can actually wake -
	// was rejected as unsafe.
	__forceinline bool IsSafe(unsigned char reason)
	{
		const KWAIT_REASON r = static_cast<KWAIT_REASON>(reason);

		return r == KWAIT_REASON::DelayExecution || r == KWAIT_REASON::UserRequest ||
			r == KWAIT_REASON::WrDelayExecution || r == KWAIT_REASON::WrUserRequest;
	}

	// True for the reasons whose wait expires on its own, so a failed wake nudge is tolerable
	// as long as the startup probe stays bounded.
	__forceinline bool IsDelay(unsigned char reason)
	{
		const KWAIT_REASON r = static_cast<KWAIT_REASON>(reason);

		return r == KWAIT_REASON::DelayExecution || r == KWAIT_REASON::WrDelayExecution;
	}

	// Wakeability ranking, shared by both donor pickers (the launcher's snapshot walk and the
	// runtime's own thread walk) so the two can never disagree. A donor only has to be woken so
	// it executes the stub the hijack parked on its RIP; how reliably that wake lands decides
	// the order candidates are tried in:
	//   Running       executes the stub as soon as it is resumed; nothing to wake.
	//   Nudgeable     WrUserRequest (13): a GUI thread parked in GetMessage, the one class
	//                 PostThreadMessageW reliably wakes.
	//   SelfExpiring  DelayExecution (4) / WrDelayExecution (11): the timer wakes it, so a nudge
	//                 failure is tolerable while the startup probe stays bounded.
	//   Unwakeable    UserRequest (6): neither nudgeable nor self-expiring, so a nudge failure
	//                 has to abandon the donor instead of burning the whole probe.
	//   Reject        not a donor at all (not running/waiting, or outside the safe set).
	enum class WAKE_CLASS : unsigned char
	{
		Running			= 0,
		Nudgeable		= 1,
		SelfExpiring	= 2,
		Unwakeable		= 3,
		Reject			= 4
	};

	struct WAIT_CANDIDATE
	{
		unsigned char State;
		unsigned char Reason;
	};

	__forceinline WAKE_CLASS Classify(const WAIT_CANDIDATE & Candidate)
	{
		if (Candidate.State == static_cast<unsigned char>(KTHREAD_STATE::Running))
		{
			return WAKE_CLASS::Running;
		}

		if (Candidate.State != static_cast<unsigned char>(KTHREAD_STATE::Waiting) || !IsSafe(Candidate.Reason))
		{
			return WAKE_CLASS::Reject;
		}

		const KWAIT_REASON r = static_cast<KWAIT_REASON>(Candidate.Reason);

		if (r == KWAIT_REASON::WrUserRequest)
		{
			return WAKE_CLASS::Nudgeable;
		}

		if (r == KWAIT_REASON::DelayExecution || r == KWAIT_REASON::WrDelayExecution)
		{
			return WAKE_CLASS::SelfExpiring;
		}

		return WAKE_CLASS::Unwakeable;
	}

	// Lower is better; Reject sorts last so a caller can compare ranks without special-casing.
	__forceinline int WakeRank(const WAIT_CANDIDATE & Candidate)
	{
		return static_cast<int>(Classify(Candidate));
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

// NtQuerySection(SectionBasicInformation) result (Track B step 7):
// answers whether the section is actually committed to its full size.
typedef struct _SECTION_BASIC_INFORMATION
{
	LARGE_INTEGER	BaseAddress;
	LARGE_INTEGER	Attribute;
	LARGE_INTEGER	MaximumSize;
	ULONG			PageProtection;
	ULONG			Attributes;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;

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
