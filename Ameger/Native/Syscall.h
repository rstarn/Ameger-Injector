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

#define SC_NtCreateSection				SC_NAME(NtCreateSection)
#define SC_NtMapViewOfSection			SC_NAME(NtMapViewOfSection)
#define SC_NtUnmapViewOfSection			SC_NAME(NtUnmapViewOfSection)
#define SC_NtQuerySection				SC_NAME(NtQuerySection)

#define SC_NtClose						SC_NAME(NtClose)

#pragma endregion

#pragma region stub layout

#define SC_STUB_SIZE			16
#define SC_STUB_AREA_ALIGN		0x10

#define SC_STUB_OFFSET_PROLOGUE	0
#define SC_STUB_OFFSET_OPCODE		3
#define SC_STUB_OFFSET_SERVICE		4
#define SC_STUB_OFFSET_SYSCALL		8
#define SC_STUB_TAIL_INDIRECT	14

// Vector 7 / Tier 2 sampled stub: the 190-byte stack-pivot sampler block is emitted after the
// service imm32 and before the gadget jmp. Layout below is derived from kSampleBlockRaw[190] in
// Syscall.cpp. The block records one SYSCALL_SAMPLE ring slot, then pivots RSP onto the
// pre-populated telemetry fake stack (8 rebased ntdll ret gadgets followed by the synthetic
// restore gadget) and captures Frames[8] at the pivoted rsp; the subsequent RET chain unwinds the
// fake stack and the restore gadget hands RSP back to the real one. The tail after the gadget jmp
// is plain NOP padding.
#define SC_STUB_OFFSET_SAMPLE			8
#define SC_SAMPLE_BLOCK_SIZE			190
#define SC_STUB_OFFSET_SAMPLED_SYSCALL	(SC_STUB_OFFSET_SAMPLE + SC_SAMPLE_BLOCK_SIZE) // 198: jmp [rip+disp]
#define SC_STUB_TAIL_SAMPLED			(SC_STUB_OFFSET_SAMPLED_SYSCALL + 6)              // 204: NOP tail start
#define SC_STUB_SIZE_SAMPLED			208                                                // 0xD0; tail (204..208) is NOP padding

// Tier 2: the synthetic restore gadget (xchg rsp, rdi; pop rdi; pop rsi; ret) emitted once per
// sampled stub slab, immediately after the 8-byte gadget slot, and referenced by
// telemetry->FakeStack[FAKE_STACK_SLOTS - 1].
#define SC_RESTORE_GADGET_SIZE		6

#pragma endregion

#define SC_REMOTE_STUB_COUNT		4

void *	SyscallStub(DWORD NameHash);

DWORD	SyscallResolveAll();

DWORD	SyscallServiceOfStub(const void * Stub);




void *	SyscallGadgetAddress();

size_t	SyscallGadgetPoolCount();

void *	SyscallGadgetAt(size_t Index);














// VERIFIABLE_EXEC_TELEMETRY is defined in InjectionTypes.h; forward-declared here so sampled
// stub emission can pre-populate the Tier 2 FakeStack without pulling in the full header.
struct VERIFIABLE_EXEC_TELEMETRY;

DWORD	BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count, ULONG_PTR RemoteBase = 0, ULONG_PTR RingBase = 0, ULONG_PTR SysIdxAddr = 0, VERIFIABLE_EXEC_TELEMETRY * pTelemetryOut = nullptr, ULONG_PTR TargetNtdllBase = 0);

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

using f_ScNtCreateSection = NTSTATUS(NTAPI *)(
	PHANDLE	SectionHandle,
	ACCESS_MASK	DesiredAccess,
	OBJECT_ATTRIBUTES *	ObjectAttributes,
	LARGE_INTEGER *	MaximumSize,
	ULONG	SectionPageProtection,
	ULONG	AllocationAttributes,
	HANDLE	FileHandle
	);

using f_ScNtMapViewOfSection = NTSTATUS(NTAPI *)(
	HANDLE		SectionHandle,
	HANDLE		ProcessHandle,
	PVOID		*	BaseAddress,
	ULONG_PTR	ZeroBits,
	SIZE_T		CommitSize,
	SIZE_T		*	SectionOffset,
	SIZE_T		*	ViewSize,
	ULONG		InheritDisposition,
	ULONG		AllocationType,
	ULONG		Win32Protect
	);

using f_ScNtUnmapViewOfSection = NTSTATUS(NTAPI *)(
	HANDLE	ProcessHandle,
	PVOID	BaseAddress
	);

using f_ScNtQuerySection = NTSTATUS(NTAPI *)(
	HANDLE				SectionHandle,
	SECTION_INFORMATION_CLASS	SectionInformationClass,
	PVOID				SectionInformation,
	ULONG				Length,
	PULONG			ReturnLength
	);

using f_ScNtClose = NTSTATUS(NTAPI *)(
	HANDLE	Handle
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

__forceinline NTSTATUS ScNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES * ObjectAttributes, LARGE_INTEGER * MaximumSize, ULONG PageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
	auto Stub = ReCa<f_ScNtCreateSection>(SyscallStub(SC_NtCreateSection));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageProtection, AllocationAttributes, FileHandle);
}

__forceinline NTSTATUS ScNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress,
	ULONG_PTR ZeroBits, SIZE_T CommitSize, SIZE_T * SectionOffset, SIZE_T * ViewSize,
	ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	auto Stub = ReCa<f_ScNtMapViewOfSection>(SyscallStub(SC_NtMapViewOfSection));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	// Track B step 6: per-arg logging immediately before the syscall.
	// Log both the pointer AND the pointed-to value for ViewSize / SectionOffset.
	LOG(1, "[+] ScNtMapViewOfSection args: hSection=0x%08X hProc=0x%08X pBase=0x%08X ZeroBits=0x%08X CommitSize=0x%08X pOffset=0x%08X (val=%d) pViewSize=0x%08X (val=0x%08X) Inherit=0x%08X AllocType=0x%08X Win32Protect=0x%08X\n",
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(SectionHandle) & 0xFFFFFFFF),
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(ProcessHandle) & 0xFFFFFFFF),
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(BaseAddress) & 0xFFFFFFFF),
		static_cast<unsigned>(ZeroBits),
		static_cast<unsigned>(static_cast<ULONG>(CommitSize)),
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(SectionOffset) & 0xFFFFFFFF),
		SectionOffset ? (int)*SectionOffset : -1,
		static_cast<unsigned>(reinterpret_cast<uintptr_t>(ViewSize) & 0xFFFFFFFF),
		ViewSize ? static_cast<unsigned>(static_cast<ULONG>(static_cast<ULONG_PTR>(*ViewSize)) & 0xFFFFFFFF) : 0,
		static_cast<unsigned>(InheritDisposition),
		static_cast<unsigned>(AllocationType),
		static_cast<unsigned>(Win32Protect));

	return Stub(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

__forceinline NTSTATUS ScNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
	auto Stub = ReCa<f_ScNtUnmapViewOfSection>(SyscallStub(SC_NtUnmapViewOfSection));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(ProcessHandle, BaseAddress);
}

__forceinline NTSTATUS ScNtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass,
	PVOID SectionInformation, ULONG Length, PULONG ReturnLength)
{
	auto Stub = ReCa<f_ScNtQuerySection>(SyscallStub(SC_NtQuerySection));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(SectionHandle, SectionInformationClass, SectionInformation, Length, ReturnLength);
}

__forceinline NTSTATUS ScNtClose(HANDLE Handle)
{
	auto Stub = ReCa<f_ScNtClose>(SyscallStub(SC_NtClose));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(Handle);
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
