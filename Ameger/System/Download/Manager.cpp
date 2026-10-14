#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Download/Manager.h"

#include <process.h>

unsigned __stdcall DownloadWatchdogEntry(void * param)
{
    static_cast<Manager *>(param)->WatchdogProc();

    return 0;
}

Manager::Manager()
{
}

Manager::~Manager()
{
    StopTimeout();

    if (m_hWatchdogWake)
    {
        CloseHandle(m_hWatchdogWake);
        m_hWatchdogWake = nullptr;
    }
}

bool Manager::StartWatchdog()
{
    if (m_hWatchdog)
    {
        return true;
    }

    if (!m_hWatchdogWake)
    {
        m_hWatchdogWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!m_hWatchdogWake)
        {
            LOG(2, "Manager: failed to create watchdog event: %08X\n", GetLastError());

            return false;
        }
    }

    m_bWatchdogStop.store(false);

    const uintptr_t thread_handle = _beginthreadex(nullptr, 0, DownloadWatchdogEntry, this, 0, nullptr);
    if (!thread_handle)
    {
        LOG(2, "Manager: failed to start download watchdog\n");

        return false;
    }

    m_hWatchdog = ReCa<HANDLE>(thread_handle);

    return true;
}

void Manager::StopWatchdog()
{
    if (!m_hWatchdog)
    {
        return;
    }

    m_bWatchdogStop.store(true);

    if (m_hWatchdogWake)
    {
        SetEvent(m_hWatchdogWake);
    }

    WaitForSingleObject(m_hWatchdog, INFINITE);
    CloseHandle(m_hWatchdog);
    m_hWatchdog = nullptr;
}

void Manager::WatchdogProc()
{
    while (!m_bWatchdogStop.load())
    {
        if (WaitForSingleObject(m_hWatchdogWake, 250) == WAIT_OBJECT_0)
        {
            break;
        }

        const ULONGLONG deadline = m_ullDeadline.load();
        if (!deadline || GetTickCount64() < deadline)
        {
            continue;
        }

        m_bTimedOut.store(true);
    }
}

bool Manager::SetTimeout(DWORD milliseconds)
{
    m_bTimedOut.store(false);
    m_dwTimeoutMs.store(milliseconds);

    if (!milliseconds)
    {
        m_ullDeadline.store(0);
        StopWatchdog();

        return true;
    }

    m_ullDeadline.store(GetTickCount64() + milliseconds);

    // Check if watchdog was already running before starting it
    bool was_running = (m_hWatchdog != nullptr);
    StartWatchdog();
    // If watchdog was already running, wake it so it re-checks the new deadline immediately
    // instead of waiting up to 250ms for its next wait cycle.
    if (was_running && m_hWatchdogWake)
    {
        SetEvent(m_hWatchdogWake);
    }
    return true;
}

void Manager::StopTimeout()
{
    m_ullDeadline.store(0);
    StopWatchdog();
}

bool Manager::TimedOut() const
{
    return m_bTimedOut.load();
}

void Manager::TouchDeadline()
{
    const DWORD timeout = m_dwTimeoutMs.load();
    if (timeout)
    {
        m_ullDeadline.store(GetTickCount64() + timeout);
    }
}
