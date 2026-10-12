#pragma once

#include "System/Import/ImportHandler.h"
#include "System/Symbol/Offsets/DynamicOffsets.h"

// All Windows offsets are download-dependent (see DynamicOffsets.h):
//  - TEB SameTebFlags / loader-worker mask, PEB fields, KUSER cookie and
//    LDR/inverted/TLS layouts come from the downloaded ntdll.pdb via
//    ResolveDynamicOffsets (fail-closed when absent).
// No per-build TEB_SameTebFlags_* constants remain. There is deliberately no
// wait-stub machinery here any more (no return-address table, no alertability
// probe, no win32u load): victim selection is Running-only because hijacking
// a waiter corrupts its Rax (see FindHijackThread), so alertability is never
// tested and its decoder has nothing to feed.

// Snapshot cursor over processes/threads for victim selection.
// What: one NtQuerySystemInformation snapshot with a process cursor and a
//   thread sub-cursor plus handle-free state reads and the handle-needing TEB
//   worker probe. Why: the hijack search must filter on snapshot data first
//   and spend at most kMaxHandleProbes opens (see ThreadHijacking.cpp). How:
//   SetProcess anchors a PID, NextThread walks, Get*/Is* inspect the current
//   thread; RefreshInformation retakes the snapshot when the target churns.
class ProcessInformation
{
	SYSTEM_PROCESS_INFORMATION	* m_pCurrentProcess = nullptr;
	SYSTEM_PROCESS_INFORMATION	* m_pFirstProcess	= nullptr;
	SYSTEM_THREAD_INFORMATION	* m_pCurrentThread	= nullptr;

	ULONG m_BufferSize = 0;

	HANDLE m_hCurrentProcess = nullptr;

	DWORD m_CurrentThreadIndex = 0;

	f_NtQueryInformationProcess m_pNtQueryInformationProcess	= nullptr;
	f_NtQuerySystemInformation	m_pNtQuerySystemInformation		= nullptr;
	f_NtQueryInformationThread	m_pNtQueryInformationThread		= nullptr;

	// Optional pre-existing handle for the thread currently under inspection.
	// GetTEB otherwise opens the thread by TID, which is a fresh handle on a
	// target thread for every probe. When the caller already holds a usable
	// thread handle for that exact TID (the sponsor path holds a verified
	// duplicate), the query reuses it instead of opening again.
	HANDLE m_hCurrentThreadHandle = nullptr;
	DWORD m_CurrentThreadHandleTid = 0;

	// Resolves the handle to use for the current thread: the cached one when it
	// matches this TID, otherwise nullptr (caller opens by TID as before).
	HANDLE BorrowCurrentThreadHandle(DWORD tid) const;

	ProcessInformation(const ProcessInformation &) = delete;
	ProcessInformation & operator=(const ProcessInformation &) = delete;

public:

	ProcessInformation();
	~ProcessInformation();

	// Publishes an already-open handle for `tid` so subsequent thread queries
	// reuse it. Pass nullptr to clear. The handle is borrowed, never closed.
	void SetCurrentThreadHandle(HANDLE thread, DWORD tid);

	// Anchors the cursor on the process owning hTargetProc. Params: hTargetProc
	// (in). Returns: true when the snapshot contains that PID. Resets the
	// thread cursor to index 0.
	bool SetProcess(HANDLE hTargetProc);
	// Advances to the next thread in the current process. Returns: true when
	// the cursor moved; false at the end (cursor stays on the last entry).
	bool NextThread();

	// Retakes the system snapshot (same layout, fresh data). Returns: true on
	// success; the process/thread cursors are left for re-anchoring via
	// SetProcess. Call after Sleep() when threads churn.
	bool RefreshInformation();

	// Returns the current thread's TID, or 0 when the cursor is invalid.
	DWORD GetThreadId();

	// Reads the current thread's scheduler state/reason from snapshot data
	// (no handle). Params: state/reason (out). Returns: true when present.
	// Only the Running state is consumed (victim selection is Running-only);
	// the reason is returned for logging/diagnostics.
	bool GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason);
	// Returns the current thread's TEB base (may open the thread by TID, or
	// reuse the sponsor handle from SetCurrentThreadHandle). Null on failure.
	void * GetTEB();

	// True when the thread is a loader worker (never hijackable; hijacking it
	// guarantees Pending). Needs a thread handle via TEB SameTebFlags.
	bool IsThreadWorkerThread();
};