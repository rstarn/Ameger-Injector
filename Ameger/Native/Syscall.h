#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "NT/Windows11.h"

// ------------------------------------------------------------------------------------------------
// Direct syscall layer.
//
// Every cross process operation performed by this project goes through a syscall instruction issued
// from a locally generated stub. Nothing is ever routed through a public ntdll export, so an inline
// hook (or a trampoline) placed on an ntdll entry point never observes, nor is even able to intercept,
// any of the operations below. That is the requirement against an anti-cheat whose only viable
// observation points are the resolved IAT of a shim module and the syscall boundary.
//
// Service numbers are never stored in the image. They are extracted from ntdll's own export table at
// run time (the "mov eax, imm32" prologue), and are validated against the syscall instruction that is
// expected to follow a healthy stub. When a prologue does not validate (inline hooked, patched, or
// obfuscated) the number is reconstructed from a table neighbour instead of being read directly.
// ------------------------------------------------------------------------------------------------

// Compile time FNV-1a over the export name. MSVC folds this to an immediate, so no API name string is
// emitted into the final image; only the resulting hash exists in .rdata.
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
#define SC_NtClose							SC_NAME(NtClose)

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
#define SC_STUB_WITH_RET		11
#define SC_STUB_AREA_ALIGN		0x10

// 4C 8B D1    mov  r10, rcx        -> offset 0
// B8 ss ss ss mov  eax, service    -> opcode at 3, immediate at 4
// 0F 05       syscall              -> offset 8
// C3          ret                  -> offset 10
#define SC_STUB_OFFSET_PROLOGUE	0
#define SC_STUB_OFFSET_OPCODE		3
#define SC_STUB_OFFSET_SERVICE		4
#define SC_STUB_OFFSET_SYSCALL		8
#define SC_STUB_OFFSET_RET		10

#pragma endregion

// Sized so a remote stub area can be dropped straight into an existing staging region. The count
// matches the number of cross-boundary entry points the remote shell actually calls through.
#define SC_REMOTE_STUB_COUNT		5

void *	SyscallStub(DWORD NameHash);

DWORD	SyscallResolveAll();

bool	SyscallReady();

// Copies a service number out of a locally built stub. Used for verification/diagnostics only.
DWORD	SyscallServiceOfStub(const void * Stub);

// Builds a self contained stub blob (SC_STUB_SIZE bytes per entry, SC_STUB_AREA_ALIGN aligned) into
// Destination. Returns the number of stubs written, or 0 on failure.
DWORD	BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count);

#pragma region typed wrappers

// x64 register convention shorthand: RCX, RDX, R8, R9, [rsp+0x20], [rsp+0x28].

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

using f_ScNtQuerySystemInformation = NTSTATUS(NTAPI *)(
	SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	void *						SystemInformation,
	ULONG						SystemInformationLength,
	ULONG *						ReturnLength
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

// Several of these services write their result through an optional pointer. Passing null for one of them
// is not uniformly safe: on this platform NtProtectVirtualMemory faults rather than skipping the write,
// so a null result pointer is substituted with a scratch local that is simply discarded. Every wrapper
// below therefore routes its optional result pointer through this helper.
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

// Every wrapper is a thin inline shim. They return STATUS_ENTRYPOINT_NOT_FOUND when the service could
// not be resolved, which keeps call sites free of null checks without masking a real failure.

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

__forceinline NTSTATUS ScNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, void * SystemInformation, ULONG SystemInformationLength, ULONG * ReturnLength)
{
	auto Stub = ReCa<f_ScNtQuerySystemInformation>(SyscallStub(SC_NtQuerySystemInformation));
	if (!Stub)
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return Stub(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
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

// Several of these services write their result through an optional pointer. Passing null for one of them
// is not uniformly safe: on this platform NtProtectVirtualMemory faults rather than skipping the write,
// so a null result pointer is substituted with a scratch local that is simply discarded. Every wrapper
// below therefore routes its optional result pointer through this helper.
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

// Drop in replacements for the Win32 helpers that used to be used for cross process work. They map
// exactly onto the operations the Win32 wrappers performed, minus the observable wrapper.

// Opens a process handle by pid. DesiredAccess is honoured verbatim - no implicit widening.
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

// Zeroes a remote region after making it writable. The scratch buffer is bounded by ChunkSize, so a
// region far larger than the buffer never needs a matching local allocation. Writing stops at the
// first chunk that cannot be written; the caller keeps ownership of the region and decides cleanup.
__forceinline void ScrubRemoteRegion(HANDLE ProcessHandle, void * BaseAddress, SIZE_T Size, SIZE_T ChunkSize)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !BaseAddress || !Size || !ChunkSize)
	{
		return;
	}

	if (!ScProtectMemory(ProcessHandle, BaseAddress, Size, PAGE_READWRITE))
	{
		return;
	}

	const SIZE_T Chunk = Size < ChunkSize ? Size : ChunkSize;
	BYTE * Zeros = ReCa<BYTE *>(VirtualAlloc(nullptr, Chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!Zeros)
	{
		return;
	}

	BYTE * Cursor = ReCa<BYTE *>(BaseAddress);
	SIZE_T Remaining = Size;
	while (Remaining)
	{
		const SIZE_T ThisChunk = Remaining < Chunk ? Remaining : Chunk;
		if (!ScWriteProcessMemory(ProcessHandle, Cursor, Zeros, ThisChunk, nullptr))
		{
			break;
		}

		Cursor += ThisChunk;
		Remaining -= ThisChunk;
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

// Win32 path of the owning image. Falls back to 0 rather than to a native format path so that a
// caller never ends up comparing a \Device\HarddiskVolume path with a Win32 one. Defined out of line
// because it carries its own scratch buffer.
DWORD ScGetProcessImageName(HANDLE ProcessHandle, wchar_t * Buffer, DWORD Characters);

// Semantically identical to GetExitCodeProcess.
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
