#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

class DownloadManager
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

    DownloadManager();

    ~DownloadManager();

    DownloadManager(const DownloadManager &) = delete;
    DownloadManager & operator=(const DownloadManager &) = delete;

    bool SetTimeout(DWORD milliseconds);
    void StopTimeout();
    bool TimedOut() const;

    void TouchDeadline();
};
