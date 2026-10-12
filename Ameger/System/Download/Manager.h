#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

class Manager
{

    std::atomic<ULONGLONG>  m_ullDeadline{0};
    std::atomic<DWORD>      m_dwTimeoutMs{0};
    std::atomic<bool>       m_bTimedOut{false};
    std::atomic<bool>       m_bWatchdogStop{false};
    HANDLE                  m_hWatchdog = nullptr;
    HANDLE                  m_hWatchdogWake = nullptr;

    bool StartWatchdog();
    void StopWatchdog();
    void WatchdogProc();

    friend unsigned __stdcall DownloadWatchdogEntry(void * param);

public:

    Manager();

    ~Manager();

    Manager(const Manager &) = delete;
    Manager & operator=(const Manager &) = delete;

    bool SetTimeout(DWORD milliseconds);
    void StopTimeout();
    bool TimedOut() const;

    void TouchDeadline();
};
