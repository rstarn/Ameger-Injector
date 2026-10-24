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
            LOG(2, "Manager: Failed To Create Watchdog Event = %08X\n", GetLastError());

            return false;
        }
    }

    m_bWatchdogStop.store(false);

    const uintptr_t thread_handle = _beginthreadex(nullptr, 0, DownloadWatchdogEntry, this, 0, nullptr);
    if (!thread_handle)
    {
        LOG(2, "Manager: Failed To Start Download Watchdog\n");

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
            // The wake event is armed by StopWatchdog (a stop request) and by
            // SetTimeout on an already-running watchdog (a deadline refresh).
            // A stop exits; a refresh falls through so the loop re-reads the
            // new deadline instead of dying and leaving the timeout unarmed.
            if (m_bWatchdogStop.load())
            {
                break;
            }

            continue;
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

    const bool was_running = (m_hWatchdog != nullptr);
    if (!StartWatchdog())
    {
        // Without the watchdog the timeout is not armed: the latched flag
        // would never be set no matter what the deadline says, so the
        // deadline is withdrawn rather than left as a promise nothing keeps.
        m_ullDeadline.store(0);

        return false;
    }
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
