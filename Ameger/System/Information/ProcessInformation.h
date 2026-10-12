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
