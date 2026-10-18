#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Information/ProcessInformation.h"
#include "Native/Syscall.h"

#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) ReCa<SYSTEM_PROCESS_INFORMATION *>(ReCa<BYTE *>(pCurrent) + pCurrent->NextEntryOffset)

ProcessInformation::ProcessInformation()
{
	
	
	m_pNtQueryInformationProcess	= ReCa<f_NtQueryInformationProcess>	(SyscallStub(SC_NtQueryInformationProcess));
	m_pNtQuerySystemInformation		= ReCa<f_NtQuerySystemInformation>	(SyscallStub(SC_NtQuerySystemInformation));
	m_pNtQueryInformationThread		= ReCa<f_NtQueryInformationThread>	(SyscallStub(SC_NtQueryInformationThread));

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return;
	}

	m_BufferSize	= 0x10000;
	m_pFirstProcess = nullptr;

	LOG(3, "ProcessInformation Initialized\n");

}

ProcessInformation::~ProcessInformation()
{
	if (m_pFirstProcess)
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
	}
}

bool ProcessInformation::SetProcess(HANDLE hTargetProc)
{
	DWORD dwHandleInfo = 0;
	if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !GetHandleInformation(hTargetProc, &dwHandleInfo))
	{
		return false;
	}

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return false;
	}

	if (!m_pFirstProcess)
	{
		if (!RefreshInformation())
		{
			return false;
		}
	}

	
	
	
	if (hTargetProc == m_hCurrentProcess && m_ProcessLocated)
	{
		m_CurrentThreadIndex = 0;
		m_pCurrentThread = &m_pCurrentProcess->Threads[0];

		return true;
	}

	m_hCurrentProcess = hTargetProc;

	ULONG_PTR PID = ScGetProcessId(m_hCurrentProcess);
	if (!PID)
	{
		m_hCurrentProcess = nullptr;
		m_ProcessLocated = false;
		return false;
	}

	m_ProcessLocated = false;
	m_pCurrentProcess = m_pFirstProcess;
	BYTE * buffer_end = ReCa<BYTE *>(m_pFirstProcess) + m_BufferSize;

	for (;;)
	{
		if (m_pCurrentProcess->UniqueProcessId == ReCa<void *>(PID))
		{
			break;
		}

		auto pNext = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
		if (pNext == m_pCurrentProcess)
		{
			break;
		}

		
		if (ReCa<BYTE *>(pNext) + sizeof(SYSTEM_PROCESS_INFORMATION) > buffer_end)
		{
			break;
		}

		m_pCurrentProcess = pNext;
	}

	if (m_pCurrentProcess->UniqueProcessId != ReCa<void *>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_ProcessLocated = true;
	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInformation::NextThread()
{
	if (!m_pFirstProcess || !m_pCurrentProcess || !m_pCurrentProcess->NumberOfThreads)
	{
		return false;
	}

	if (m_CurrentThreadIndex == m_pCurrentProcess->NumberOfThreads - 1)
	{
		return false;
	}

	
	BYTE * buffer_end = ReCa<BYTE *>(m_pFirstProcess) + m_BufferSize;
	BYTE * next_thread_ptr = ReCa<BYTE *>(&m_pCurrentProcess->Threads[m_CurrentThreadIndex + 1]);
	if (next_thread_ptr + sizeof(SYSTEM_THREAD_INFORMATION) > buffer_end)
	{
		return false;
	}

	m_pCurrentThread = ReCa<SYSTEM_THREAD_INFORMATION *>(next_thread_ptr);
	++m_CurrentThreadIndex;

	return true;
}

bool ProcessInformation::RefreshInformation()
{
	
	
	
	m_ProcessLocated = false;

	if (m_pFirstProcess)
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;
	}

	m_pCurrentProcess = nullptr;
	m_pCurrentThread = nullptr;

	m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]());
	if (!m_pFirstProcess)
	{
		return false;
	}

	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);

	while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{

		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;

		if (size_out > 64 * 1024 * 1024)
		{
			return false;
		}

		ULONG next_size = size_out + 0x1000;
		if (next_size <= m_BufferSize)
		{
			next_size = m_BufferSize * 2;
		}
		if (next_size <= m_BufferSize)
		{
			return false;
		}

		m_BufferSize	= next_size;
		m_pFirstProcess = ReCa<SYSTEM_PROCESS_INFORMATION *>(new(std::nothrow) BYTE[m_BufferSize]());
		if (!m_pFirstProcess)
		{
			return false;
		}

		ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
	}

	if (NT_FAIL(ntRet))
	{
		delete[] ReCa<BYTE *>(m_pFirstProcess);
		m_pFirstProcess = nullptr;

		return false;
	}

	
	
	m_CurrentThreadIndex	= 0;
	m_pCurrentProcess		= m_pFirstProcess;
	m_pCurrentThread		= &m_pCurrentProcess->Threads[0];

	return true;
}

DWORD ProcessInformation::GetThreadId()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(ReCa<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

bool ProcessInformation::GetThreadState(KTHREAD_STATE & state, KWAIT_REASON & reason)
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	
	
	state	= static_cast<KTHREAD_STATE>(m_pCurrentThread->ThreadState);
	reason	= static_cast<KWAIT_REASON>(m_pCurrentThread->WaitReason);

	return true;
}

HANDLE ProcessInformation::BorrowCurrentThreadHandle(DWORD tid) const
{
	if (m_hCurrentThreadHandle && m_hCurrentThreadHandle != INVALID_HANDLE_VALUE && tid && m_CurrentThreadHandleTid == tid)
	{
		return m_hCurrentThreadHandle;
	}

	return nullptr;
}

void ProcessInformation::SetCurrentThreadHandle(HANDLE thread, DWORD tid)
{
	m_hCurrentThreadHandle = thread;
	m_CurrentThreadHandleTid = thread ? tid : 0;
}

void * ProcessInformation::GetTEB()
{
	if (!m_pCurrentThread || !m_pNtQueryInformationThread)
	{
		return nullptr;
	}

	const HANDLE borrowed = BorrowCurrentThreadHandle(MDWD(m_pCurrentThread->ClientId.UniqueThread));
	const bool owns_handle = borrowed == nullptr;
	HANDLE hThread = borrowed ? borrowed : ScOpenThread(MDWD(m_pCurrentThread->ClientId.UniqueThread), THREAD_QUERY_LIMITED_INFORMATION);
	if (!hThread)
	{
		return nullptr;
	}

	THREAD_BASIC_INFORMATION tbi{ 0 };
	auto ntRet = m_pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);

	if (owns_handle)
	{
		CloseHandle(hThread);
	}

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	return tbi.TebBaseAddress;
}

bool ProcessInformation::IsThreadWorkerThread()
{

	if (!m_pCurrentThread)
	{
		return true;
	}

	if (!g_DynamicOffsetsReady.load(std::memory_order_acquire) || !g_DynamicOffsets.TebSameTebFlags)
	{
		return true;
	}
	BYTE * teb = ReCa<BYTE *>(GetTEB());
	if (!teb)
	{

		return true;
	}

	USHORT TebInfo = 0;
	if (ScReadProcessMemory(m_hCurrentProcess, teb + g_DynamicOffsets.TebSameTebFlags, &TebInfo, sizeof(TebInfo), nullptr))
	{
		return ((TebInfo & g_DynamicOffsets.SameTebFlagsLoaderWorkerMask) != 0);
	}

	return true;
}
