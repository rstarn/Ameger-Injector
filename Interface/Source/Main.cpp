#include "PCH.h"

#include "Launcher.h"

namespace
{

    constexpr size_t kConfigBlobMagicSize = 8;

#ifndef AMEGER_CONFIG_MAGIC_STR
#define AMEGER_CONFIG_MAGIC_STR "SYSCFG01"
#endif

    constexpr int kMaxLaunchAttempts = 3;
    constexpr int kResultRetryable = 3;
    // The payload mapped successfully but the verification gate did not run or
    // did not pass. This is not a load failure and must never be retried: a
    // retry would inject a second copy into the same target.
    constexpr int kResultMappedUnverified = 4;
    constexpr wchar_t kChildMarker[] = L"--ameger-child";
    constexpr wchar_t kRetryMarker[] = L"--ameger-retry=";
    constexpr wchar_t kParentPathMarker[] = L"--ameger-parent-path=";

    class StdoutParkGuard
    {
        int saved_stdout_fd_ = -1;
        int saved_stderr_fd_ = -1;
        HANDLE saved_stdout_handle_ = nullptr;
        HANDLE saved_stderr_handle_ = nullptr;
        HANDLE stdout_nul_ = INVALID_HANDLE_VALUE;
        HANDLE stderr_nul_ = INVALID_HANDLE_VALUE;

    public:
        StdoutParkGuard()
        {
            fflush(stdout);
            fflush(stderr);

            saved_stdout_fd_ = _dup(_fileno(stdout));
            saved_stderr_fd_ = _dup(_fileno(stderr));

            HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            int nul_fd = -1;
            if (nul != INVALID_HANDLE_VALUE)
            {
                nul_fd = _open_osfhandle(reinterpret_cast<intptr_t>(nul), _O_WRONLY);
                if (nul_fd == -1)
                {
                    CloseHandle(nul);
                }
            }
            if (saved_stdout_fd_ != -1 && nul_fd != -1)
            {
                (void)_dup2(nul_fd, _fileno(stdout));
            }
            if (nul_fd != -1)
            {
                _close(nul_fd);
            }

            nul = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            nul_fd = -1;
            if (nul != INVALID_HANDLE_VALUE)
            {
                nul_fd = _open_osfhandle(reinterpret_cast<intptr_t>(nul), _O_WRONLY);
                if (nul_fd == -1)
                {
                    CloseHandle(nul);
                }
            }
            if (saved_stderr_fd_ != -1 && nul_fd != -1)
            {
                (void)_dup2(nul_fd, _fileno(stderr));
            }
            if (nul_fd != -1)
            {
                _close(nul_fd);
            }

            saved_stdout_handle_ = GetStdHandle(STD_OUTPUT_HANDLE);
            saved_stderr_handle_ = GetStdHandle(STD_ERROR_HANDLE);
            stdout_nul_ = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            stderr_nul_ = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (stdout_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_OUTPUT_HANDLE, stdout_nul_);
            }
            if (stderr_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_ERROR_HANDLE, stderr_nul_);
            }
        }

        ~StdoutParkGuard()
        {
            fflush(stdout);
            fflush(stderr);

            if (saved_stdout_fd_ != -1)
            {
                (void)_dup2(saved_stdout_fd_, _fileno(stdout));
                _close(saved_stdout_fd_);
            }
            if (saved_stderr_fd_ != -1)
            {
                (void)_dup2(saved_stderr_fd_, _fileno(stderr));
                _close(saved_stderr_fd_);
            }
            if (stdout_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_OUTPUT_HANDLE, saved_stdout_handle_);
                CloseHandle(stdout_nul_);
            }
            if (stderr_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_ERROR_HANDLE, saved_stderr_handle_);
                CloseHandle(stderr_nul_);
            }
            clearerr(stdout);
            clearerr(stderr);
        }

        StdoutParkGuard(const StdoutParkGuard &) = delete;
        StdoutParkGuard & operator=(const StdoutParkGuard &) = delete;
    };

    class FileHandleGuard
    {
        HANDLE handle_ = INVALID_HANDLE_VALUE;

    public:
        FileHandleGuard() = default;

        explicit FileHandleGuard(HANDLE handle) : handle_(handle)
        {
        }

        ~FileHandleGuard()
        {
            reset();
        }

        FileHandleGuard(const FileHandleGuard &) = delete;
        FileHandleGuard & operator=(const FileHandleGuard &) = delete;

        FileHandleGuard(FileHandleGuard && other) noexcept : handle_(other.handle_)
        {
            other.handle_ = INVALID_HANDLE_VALUE;
        }

        FileHandleGuard & operator=(FileHandleGuard && other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = INVALID_HANDLE_VALUE;
            }
            return *this;
        }

        void reset(HANDLE handle = INVALID_HANDLE_VALUE)
        {
            if (handle_ && handle_ != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle_);
            }
            handle_ = handle;
        }

        HANDLE get() const noexcept
        {
            return handle_;
        }

        HANDLE release() noexcept
        {
            HANDLE h = handle_;
            handle_ = INVALID_HANDLE_VALUE;
            return h;
        }
    };


    bool FileExists(const std::wstring & path);

    // Whether the run transcript is removed once a run has succeeded. The
    // default is to keep it: the record of what a successful load did is the
    // one worth having. The setting comes from the configuration file, because
    // the launcher runs elevated and an elevated process does not inherit its
    // parent's environment.
    bool g_DiscardResultLogOnSuccess = false;

    // Whether this run was a test run. It is recorded so that the launcher
    // can mark the run as a test run in the places that are outside the
    // wizard, such as the final notification.
    bool g_TestMode = false;

    // Whether the payload was actually mapped into the target. The exit code
    // is not the same thing: a run that the operator cancelled also exits
    // with zero, and a cancelled run has nothing to show for itself, so its
    // transcript must not be treated as the record of a successful load.
    bool g_LoadCompleted = false;

    // Whether the operator asked for the "begin load?" confirmation to be
    // answered for them. It comes from the configuration file, because the
    // launcher runs elevated and an elevated process does not inherit its
    // parent's environment.
    bool g_AutoConfirm = false;

    bool DiscardResultLogOnSuccess()
    {
        if (g_DiscardResultLogOnSuccess)
        {
            return true;
        }
        wchar_t buffer[8] = {};
        // The decrypted name is kept as an object, not as a pointer into it:
        // the temporary's destructor wipes its buffer when it goes away.
        const auto name = XOR_STR_W(L"AMEGER_DISCARD_RESULT_LOG");
        const DWORD got = GetEnvironmentVariableW(name.get(), buffer, 4);
        return got == 1 && buffer[0] == L'1';
    }

    bool GetOwnExePath(std::wstring & out)
    {
        std::vector<wchar_t> buffer(static_cast<size_t>(MAX_PATH) * 2);
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (!length || length >= buffer.size())
        {
            return false;
        }
        out.assign(buffer.data(), length);
        return true;
    }

    bool MakeRandomExeFileName(std::wstring & out)
    {
        static const wchar_t kLetters[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        static const wchar_t kAlnum[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        unsigned char entropy[16] = {};
        bool haveCrypto = false;
        {
            auto bcryptName = XOR_STR_W(L"bcrypt.dll");
            HMODULE bcrypt = GetModuleHandleW(bcryptName.get());
            using BcryptGenFn = LONG(__stdcall *)(void *, unsigned char *, ULONG, ULONG);
            if (bcrypt)
            {
                auto procName = XOR_STR_A("BCryptGenRandom");
                auto gen = reinterpret_cast<BcryptGenFn>(GetProcAddress(bcrypt, procName.get()));
                if (gen && gen(nullptr, entropy, sizeof(entropy), 0x00000002) >= 0)
                {
                    haveCrypto = true;
                }
            }
        }
        if (!haveCrypto)
        {
            ULONGLONG tick = GetTickCount64() ^ (static_cast<ULONGLONG>(GetCurrentProcessId()) << 32);
            tick ^= reinterpret_cast<ULONG_PTR>(&entropy);
            for (size_t i = 0; i < sizeof(entropy); ++i)
            {
                tick ^= tick >> 29;
                tick *= 0xBF58476D1CE4E5B9ull;
                tick ^= tick >> 32;
                entropy[i] = static_cast<unsigned char>((tick >> ((i % 8) * 8)) & 0xFFu);
            }
        }
        const size_t length = 8 + (entropy[0] % 5);
        out.clear();
        out.reserve(length + 4);
        out += kLetters[entropy[1] % (_countof(kLetters) - 1)];
        for (size_t i = 1; i < length; ++i)
        {
            out += kAlnum[entropy[i + 1] % (_countof(kAlnum) - 1)];
        }
        out += L".exe";
        return out.size() > 4;
    }

    bool HasMarker(const std::wstring & commandLine, const wchar_t * marker)
    {
        return commandLine.find(marker) != std::wstring::npos;
    }

    int GetRetryIndex()
    {
        const std::wstring cmd = GetCommandLineW();
        const size_t pos = cmd.find(kRetryMarker);
        if (pos == std::wstring::npos)
        {
            return 0;
        }
        const wchar_t * tail = cmd.c_str() + pos + wcslen(kRetryMarker);
        wchar_t * end = nullptr;
        const unsigned long value = std::wcstoul(tail, &end, 10);
        if (tail == end || value > 16)
        {
            return 0;
        }
        return static_cast<int>(value);
    }

    std::wstring BuildForwardedArgs(int nextRetry, const std::wstring & parentPath, bool keepChild)
    {
        std::wstring cmd = GetCommandLineW();
        std::wstring rest;
        if (!cmd.empty())
        {
            size_t i = 0;
            while (i < cmd.size() && (cmd[i] == L' ' || cmd[i] == L'\t'))
            {
                ++i;
            }
            if (i < cmd.size() && cmd[i] == L'"')
            {
                ++i;
                while (i < cmd.size() && cmd[i] != L'"')
                {
                    ++i;
                }
                if (i < cmd.size())
                {
                    ++i;
                }
            }
            else
            {
                while (i < cmd.size() && cmd[i] != L' ' && cmd[i] != L'\t')
                {
                    ++i;
                }
            }
            rest = (i < cmd.size()) ? cmd.substr(i) : std::wstring();
        }
        // Each pass removes the markers this launcher owns from the argument
        // string, and the pass repeats until a pass changes nothing. The
        // length is what decides whether anything was removed, so no separate
        // "did I erase something" flag is needed.
        for (;;)
        {
            const size_t before = rest.size();

            size_t pos = rest.find(kRetryMarker);
            if (pos != std::wstring::npos)
            {
                size_t end = pos;
                while (end < rest.size() && rest[end] != L' ' && rest[end] != L'\t' && rest[end] != L'"')
                {
                    ++end;
                }
                rest.erase(pos, end - pos);
            }
            pos = rest.find(kParentPathMarker);
            if (pos != std::wstring::npos)
            {
                size_t start = pos;
                if (start > 0 && rest[start - 1] == L'"')
                {
                    --start;
                }
                size_t end = pos + wcslen(kParentPathMarker);
                if (end < rest.size() && rest[end] == L'"')
                {
                    ++end;
                    while (end < rest.size() && rest[end] != L'"')
                    {
                        ++end;
                    }
                    if (end < rest.size())
                    {
                        ++end;
                    }
                }
                else
                {
                    while (end < rest.size() && rest[end] != L' ' && rest[end] != L'\t')
                    {
                        ++end;
                    }
                }
                rest.erase(start, end - start);
            }
            if (!keepChild)
            {
                const size_t childPos = rest.find(kChildMarker);
                if (childPos != std::wstring::npos)
                {
                    rest.erase(childPos, wcslen(kChildMarker));
                }
            }

            if (rest.size() == before)
            {
                break;
            }
        }
        std::wstring out;
        if (keepChild)
        {
            out += L" ";
            out += kChildMarker;
        }
        out += L" --ameger-retry=" + std::to_wstring(nextRetry);
        if (!parentPath.empty())
        {
            out += L" --ameger-parent-path=\"" + parentPath + L"\"";
        }
        out += rest;
        return out;
    }

    DWORD FindTrustedBroker(DWORD excludePid)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            return 0;
        }
        FileHandleGuard snapGuard(snap);
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snap, &entry))
        {
            return 0;
        }
        const DWORD session = []() -> DWORD {
            DWORD id = 0;
            ProcessIdToSessionId(GetCurrentProcessId(), &id);
            return id;
        }();
        DWORD explorerSame = 0;
        DWORD explorerAny = 0;
        DWORD svchostSame = 0;
        DWORD svchostAny = 0;
        auto expectedExplorer = XOR_STR_W(L"explorer.exe");
        auto expectedSvchost = XOR_STR_W(L"svchost.exe");
        do
        {
            std::wstring name = entry.szExeFile;
            for (auto & c : name)
            {
                if (c >= L'A' && c <= L'Z')
                {
                    c = static_cast<wchar_t>(c - L'A' + L'a');
                }
            }
            const bool isExplorer = (name == expectedExplorer.get());
            const bool isSvchost = (name == expectedSvchost.get());
            if (!isExplorer && !isSvchost)
            {
                continue;
            }
            if (entry.th32ProcessID == GetCurrentProcessId() || entry.th32ProcessID == excludePid)
            {
                continue;
            }

            DWORD procSession = 0;
            ProcessIdToSessionId(entry.th32ProcessID, &procSession);
            if (isExplorer)
            {
                if (procSession == session && !explorerSame)
                {
                    explorerSame = entry.th32ProcessID;
                }
                if (!explorerAny)
                {
                    explorerAny = entry.th32ProcessID;
                }
            }
            else
            {
                if (procSession == session && !svchostSame)
                {
                    svchostSame = entry.th32ProcessID;
                }
                if (!svchostAny)
                {
                    svchostAny = entry.th32ProcessID;
                }
            }
        } while (Process32NextW(snap, &entry));
        if (explorerSame)
        {
            return explorerSame;
        }
        if (svchostSame)
        {
            return svchostSame;
        }
        if (explorerAny)
        {
            return explorerAny;
        }
        return svchostAny;
    }

    bool SpawnWithSpoofedParent(const std::wstring & exePath, const std::wstring & args, DWORD brokerPid)
    {
        if (exePath.empty() || !brokerPid)
        {
            return false;
        }
        HANDLE broker = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, brokerPid);
        if (!broker)
        {
            HANDLE token = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            {
                FileHandleGuard tokenGuard(token);
                LUID luid{};
                if (LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &luid))
                {
                    TOKEN_PRIVILEGES tp{};
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
                }
            }
            broker = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, brokerPid);
            if (!broker)
            {
                return false;
            }
        }
        FileHandleGuard brokerGuard(broker);

        SIZE_T attrSize = 0;
        (void)InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
        if (!attrSize)
        {
            return false;
        }
        std::vector<BYTE> attrBuffer(attrSize);
        auto * attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuffer.data());
        if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize))
        {
            return false;
        }
        HANDLE parentHandle = brokerGuard.get();
        const BOOL attrOk = UpdateProcThreadAttribute(attrs, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &parentHandle, sizeof(parentHandle), nullptr, nullptr);
        if (!attrOk)
        {
            DeleteProcThreadAttributeList(attrs);
            return false;
        }

        std::wstring cmdline = L"\"" + exePath + L"\"" + args;
        std::vector<wchar_t> cmdline_mutable(cmdline.begin(), cmdline.end());
        cmdline_mutable.push_back(L'\0');
        STARTUPINFOEXW si{};
        si.StartupInfo.cb = sizeof(si);
        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;
        si.lpAttributeList = attrs;
        PROCESS_INFORMATION pi{};
        const BOOL created = CreateProcessW(exePath.c_str(), cmdline_mutable.data(), nullptr, nullptr,
            FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            nullptr, nullptr, &si.StartupInfo, &pi);
        DeleteProcThreadAttributeList(attrs);
        if (!created)
        {
            return false;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    // Whether a file is one of the randomly named copies this tool makes.
    // The stem is what identifies it: MakeRandomExeFileName produces eight to
    // twelve letters and digits followed by the extension, and the first
    // character is always a letter. The length is measured on the stem
    // because the extension is not part of what makes the name random.
    bool IsDeletableSelfCopy(const std::wstring & own_path, const std::wstring & candidate)
    {
        const size_t own_slash = own_path.find_last_of(L"\\/");
        const size_t cand_slash = candidate.find_last_of(L"\\/");
        if (own_slash == std::wstring::npos || cand_slash == std::wstring::npos || cand_slash == 0)
        {
            return false;
        }

        const std::wstring own_dir = own_path.substr(0, own_slash + 1);
        const std::wstring cand_dir = candidate.substr(0, cand_slash + 1);
        if (_wcsicmp(own_dir.c_str(), cand_dir.c_str()) != 0)
        {
            return false;
        }

        const std::wstring name = candidate.substr(cand_slash + 1);
        if (name.size() < 4 || _wcsicmp(name.c_str() + name.size() - 4, L".exe") != 0)
        {
            return false;
        }

        const size_t stem = name.size() - 4;
        if (stem < 8 || stem > 12)
        {
            return false;
        }

        const auto is_letter = [](wchar_t c) { return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z'); };
        const auto is_alnum = [&](wchar_t c) { return is_letter(c) || (c >= L'0' && c <= L'9'); };

        if (!is_letter(name[0]))
        {
            return false;
        }

        for (size_t i = 1; i < stem; ++i)
        {
            if (!is_alnum(name[i]))
            {
                return false;
            }
        }

        return true;
    }

    // Removes the randomly named copy this process is running from. Only a
    // process that was launched with the child marker is a copy this tool
    // made; the operator's own file is never touched.
    void DeleteOwnSelfCopyIfChild()
    {
        if (!HasMarker(GetCommandLineW(), kChildMarker))
        {
            return;
        }

        std::wstring own;
        if (!GetOwnExePath(own))
        {
            return;
        }
        if (!IsDeletableSelfCopy(own, own))
        {
            return;
        }

        // The image file is opened with delete sharing, so this marks the
        // copy for removal while the process is still running.
        if (DeleteFileW(own.c_str()))
        {
            LOG(0, L"  %ls[+]%ls The Temporary Copy Was Removed.\n", kGreen, kReset);
        }
    }

    bool PolymorphicSelfRename(const std::wstring & parentHint)
    {
        const std::wstring cmd = GetCommandLineW();
        if (HasMarker(cmd, kChildMarker))
        {
            if (!parentHint.empty() && FileExists(parentHint))
            {
                std::wstring own;
                if (GetOwnExePath(own) && _wcsicmp(own.c_str(), parentHint.c_str()) != 0 &&
                    IsDeletableSelfCopy(own, parentHint))
                {
                    (void)DeleteFileW(parentHint.c_str());
                }
            }
            return true;
        }
        std::wstring own;
        if (!GetOwnExePath(own))
        {
            return true;
        }
        const size_t slash = own.find_last_of(L"\\/");
        const std::wstring dir = (slash == std::wstring::npos) ? std::wstring() : own.substr(0, slash + 1);
        if (dir.empty())
        {
            return true;
        }
        for (int i = 0; i < 8; ++i)
        {
            std::wstring randomName;
            if (!MakeRandomExeFileName(randomName))
            {
                continue;
            }
            const std::wstring next = dir + randomName;
            if (FileExists(next))
            {
                continue;
            }
            if (!CopyFileW(own.c_str(), next.c_str(), TRUE))
            {
                continue;
            }
            const DWORD broker = FindTrustedBroker(0);
            const std::wstring args = BuildForwardedArgs(GetRetryIndex(), own, true);
            if (broker && SpawnWithSpoofedParent(next, args, broker))
            {
                return false;
            }
            (void)DeleteFileW(next.c_str());
        }
        return true;
    }

    bool SpawnFreshRetryProcess(int nextRetry)
    {
        std::wstring own;
        if (!GetOwnExePath(own))
        {
            return false;
        }
        const size_t slash = own.find_last_of(L"\\/");
        const std::wstring dir = (slash == std::wstring::npos) ? std::wstring() : own.substr(0, slash + 1);
        if (dir.empty())
        {
            return false;
        }
        const DWORD currentParent = []() -> DWORD {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
            {
                return 0;
            }
            FileHandleGuard guard(snap);
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (!Process32FirstW(snap, &entry))
            {
                return 0;
            }
            const DWORD self = GetCurrentProcessId();
            do
            {
                if (entry.th32ProcessID == self)
                {
                    return entry.th32ParentProcessID;
                }
            } while (Process32NextW(snap, &entry));
            return 0;
        }();
        for (int i = 0; i < 8; ++i)
        {
            std::wstring randomName;
            if (!MakeRandomExeFileName(randomName))
            {
                continue;
            }
            const std::wstring next = dir + randomName;
            if (FileExists(next))
            {
                continue;
            }
            if (!CopyFileW(own.c_str(), next.c_str(), TRUE))
            {
                continue;
            }
            DWORD broker = FindTrustedBroker(currentParent);
            if (!broker || broker == currentParent)
            {
                broker = FindTrustedBroker(0);
            }
            const std::wstring args = BuildForwardedArgs(nextRetry, own, true);
            if (broker && SpawnWithSpoofedParent(next, args, broker))
            {
                return true;
            }
            (void)DeleteFileW(next.c_str());
        }
        return false;
    }

    static_assert(sizeof(MemoryInjectionData) == sizeof(MEMORY_INJECTIONDATA),
        "MemoryInjectionData must match the runtime's MEMORY_INJECTIONDATA layout");

    static_assert(offsetof(MemoryInjectionData, RawData) == offsetof(MEMORY_INJECTIONDATA, RawData),
        "MemoryInjectionData::RawData offset must match MEMORY_INJECTIONDATA::RawData");
    static_assert(offsetof(MemoryInjectionData, RawSize) == offsetof(MEMORY_INJECTIONDATA, RawSize),
        "MemoryInjectionData::RawSize offset must match MEMORY_INJECTIONDATA::RawSize");
    static_assert(offsetof(MemoryInjectionData, ProcessID) == offsetof(MEMORY_INJECTIONDATA, ProcessID),
        "MemoryInjectionData::ProcessID offset must match MEMORY_INJECTIONDATA::ProcessID");
    static_assert(offsetof(MemoryInjectionData, Flags) == offsetof(MEMORY_INJECTIONDATA, Flags),
        "MemoryInjectionData::Flags offset must match MEMORY_INJECTIONDATA::Flags");
    static_assert(offsetof(MemoryInjectionData, Timeout) == offsetof(MEMORY_INJECTIONDATA, Timeout),
        "MemoryInjectionData::Timeout offset must match MEMORY_INJECTIONDATA::Timeout");
    static_assert(offsetof(MemoryInjectionData, hHandleValue) == offsetof(MEMORY_INJECTIONDATA, hHandleValue),
        "MemoryInjectionData::hHandleValue offset must match MEMORY_INJECTIONDATA::hHandleValue");
    static_assert(offsetof(MemoryInjectionData, hDllOut) == offsetof(MEMORY_INJECTIONDATA, hDllOut),
        "MemoryInjectionData::hDllOut offset must match MEMORY_INJECTIONDATA::hDllOut");
    static_assert(offsetof(MemoryInjectionData, GenerateErrorLog) == offsetof(MEMORY_INJECTIONDATA, GenerateErrorLog),
        "MemoryInjectionData::GenerateErrorLog offset must match MEMORY_INJECTIONDATA::GenerateErrorLog");
    static_assert(offsetof(MemoryInjectionData, TargetTid) == offsetof(MEMORY_INJECTIONDATA, TargetTid),
        "MemoryInjectionData::TargetTid offset must match MEMORY_INJECTIONDATA::TargetTid");
    static_assert(offsetof(MemoryInjectionData, hThreadHandleValue) == offsetof(MEMORY_INJECTIONDATA, hThreadHandleValue),
        "MemoryInjectionData::hThreadHandleValue offset must match MEMORY_INJECTIONDATA::hThreadHandleValue");
    static_assert(offsetof(MemoryInjectionData, DllPath) == offsetof(MEMORY_INJECTIONDATA, DllPath),
        "MemoryInjectionData::DllPath offset must match MEMORY_INJECTIONDATA::DllPath");

    bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes);

    void EnableAnsi()
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    void PrintError(const wchar_t * message)
    {
        if (!message)
        {
            return;
        }

        HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            LOG(0,  L"%ls%ls%ls\n", kRed, message, kReset);
        }
        else
        {
            wchar_t line[1024]{};
            swprintf_s(line, L"%ls[x]%ls %ls", kRed, kReset, message);
            ameger_ui_log::AppendStripped(line);
        }
    }

    void PrintWarning(const wchar_t * message)
    {
        if (!message)
        {
            return;
        }

        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            LOG(0, L"%ls[!]%ls %ls\n", kYellow, message, kReset);
        }
        else
        {
            wchar_t line[1024]{};
            swprintf_s(line, L"  %ls[!]%ls %ls", kYellow, kReset, message);
            ameger_ui_log::AppendStripped(line);
        }
    }

    void StealthBeep(DWORD frequency, DWORD duration)
    {
        using BeepFn = BOOL (WINAPI *)(DWORD, DWORD);
        static BeepFn beep = nullptr;
        static bool resolved = false;
        if (!resolved)
        {
            resolved = true;
            auto mod_name = XOR_STR_W(L"kernel32.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());
            if (mod)
            {
                auto api_name = XOR_STR_A("Beep");
                beep = ReCa<BeepFn>(GetProcAddress(mod, api_name.get()));
            }
        }
        if (beep)
        {
            beep(frequency, duration);
        }
    }

    [[noreturn]] void TerminateInterface(int code)
    {
        fflush(stdout);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
        for (;;)
        {
            Sleep(1000);
        }
    }

    void __stdcall QuietPrint(const char *)
    {
    }

    std::atomic<const void *> g_RuntimeCategory{ nullptr };


    void __stdcall VerbosePrint(const char * text)
    {
        if (!text || !*text)
        {
            return;
        }

        if (strstr(text, "Type Not Found") || strstr(text, "Not Found In ") ||
            strstr(text, "Resolved Via") || strstr(text, "size ") == text ||
            strstr(text, "SymbolParser: Size ") ||
            strstr(text, "-> ID "))
        {
            return;
        }

        const int need = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
        if (need <= 1)
        {
            return;
        }
        std::vector<wchar_t> wide(static_cast<size_t>(need));
        if (MultiByteToWideChar(CP_UTF8, 0, text, -1, wide.data(), need) <= 0)
        {
            return;
        }

        size_t len = wide.size();
        while (len > 0 && wide[len - 1] == L'\0')
        {
            --len;
        }
        while (len > 0 && (wide[len - 1] == L'\n' || wide[len - 1] == L'\r'))
        {
            --len;
        }
        if (!len)
        {
            return;
        }

        std::vector<wchar_t> clean;
        clean.reserve(len);
        for (size_t i = 0; i < len; ++i)
        {
            if (wide[i] != L'\x1b')
            {
                clean.push_back(wide[i]);
                continue;
            }
            if (i + 1 < len && wide[i + 1] == L'[')
            {
                size_t j = i + 2;
                while (j < len && wide[j] >= L' ' && wide[j] <= L'?')
                {
                    ++j;
                }
                if (j < len && wide[j] >= L'@' && wide[j] <= L'~')
                {
                    ++j;
                }
                i = j - 1;
                continue;
            }
            if (i + 1 < len)
            {
                ++i;
            }
        }
        while (!clean.empty() && (clean.back() == L'\n' || clean.back() == L'\r'))
        {
            clean.pop_back();
        }
        if (clean.empty())
        {
            return;
        }

        const std::wstring line(clean.begin(), clean.end());
        std::string plain;
        plain.reserve(line.size());
        for (const wchar_t ch : line)
        {
            plain.push_back(static_cast<char>(ch & 0xFF));
        }

        struct Category
        {
            const char * probe;
            const wchar_t * title;
        };

        struct CensusBlock
        {
            std::wstring start;
            std::vector<std::wstring> rows;
            bool open = false;
        };
        static CensusBlock g_census;

        const bool is_census_start = plain.find("Candidate Thread Census") != std::string::npos;
        const bool is_census_row = plain.find("Selected") != std::string::npos ||
            plain.find("Skipped") != std::string::npos ||
            plain.find("Excluded") != std::string::npos ||
            plain.find("Wait Reason") != std::string::npos;

        const auto flush_census = []()
        {
            if (!g_census.open)
            {
                return;
            }

            g_census.open = false;

            std::vector<const std::wstring *> selected, excluded, skipped;

            for (const std::wstring & row : g_census.rows)
            {
                if (row.find(L"Selected") != std::wstring::npos)
                {
                    selected.push_back(&row);
                }
                else if (row.find(L"Excluded") != std::wstring::npos)
                {
                    excluded.push_back(&row);
                }
                else if (row.find(L"Skipped") != std::wstring::npos)
                {
                    skipped.push_back(&row);
                }
            }

            if (!g_census.start.empty())
            {
                LOG(0, L"       %ls%s%ls\n", kDim, g_census.start.c_str(), kReset);
            }

            for (const std::wstring & row : g_census.rows)
            {
                if (row.find(L"Wait Reason") != std::wstring::npos)
                {
                    LOG(0, L"       %ls%ls%ls\n", kDim, row.c_str(), kReset);
                    break;
                }
            }

            if (FullThreadCensusEnabled())
            {
                for (const std::wstring & row : g_census.rows)
                {
                    LOG(0, L"       %ls%ls%ls\n", kDim, row.c_str(), kReset);
                }
            }
            else
            {
                for (const std::wstring * row : selected)
                {
                    LOG(0, L"       %ls%ls%ls\n", kDim, row->c_str(), kReset);
                }
                for (const std::wstring * row : excluded)
                {
                    LOG(0, L"       %ls%ls%ls\n", kDim, row->c_str(), kReset);
                }
            }

            LOG(0, L"       %ls[%zu Considered: %zu Selected, %zu Excluded, %zu Skipped]%ls\n",
                kDim, selected.size() + excluded.size() + skipped.size(), selected.size(),
                excluded.size(), skipped.size(), kReset);

            if (!FullThreadCensusEnabled() && !skipped.empty())
            {
                LOG(0, L"       %ls(Set AMEGER_FULL_CENSUS=1 For The Full Listing)%ls\n", kDim, kReset);
            }

            g_census.rows.clear();
            g_census.start.clear();
        };

        if (is_census_start)
        {
            g_census.rows.clear();
            g_census.start = line;
            g_census.open = true;
            return;
        }

        if (g_census.open && is_census_row)
        {
            g_census.rows.push_back(line);
            return;
        }

        if (g_census.open)
        {
            flush_census();
        }
        static const Category kCategories[] =
        {
            { "[Syscall]",          L"Syscall Layer" },
            { "Service Name",       L"Syscall Layer" },
            { "]   [",              L"Syscall Layer" },
            { "Resolving Syscall Service Numbers", L"Syscall Layer" },
            { "ntdll Base:",        L"Syscall Layer" },
            { "Pass 1: Scanned",    L"Syscall Layer" },
            { "Pass 2: Reconstructed", L"Syscall Layer" },
            { "Building Syscall Stub Pool", L"Syscall Layer" },
            { "Stub Pool Built:",   L"Syscall Layer" },
            { "[ThreadHijack]",     L"Thread Hijack" },
            { "TID      State",      L"Thread Hijack" },
            { "  0x",               L"Thread Hijack" },
            { "Donor Round",        L"Thread Hijack" },
            { "SR_AcquireThread",   L"Thread Hijack" },
            { "Target Thread ",     L"Thread Hijack" },
            { "Remote Thread Shell",L"Thread Hijack" },
            { "Acquiring Thread",   L"Thread Hijack" },
            { "Acquired Target Thread", L"Thread Hijack" },
            { "pRoutine",           L"Thread Hijack" },
            { "RIP Replaced",       L"Thread Hijack" },
            { "Thread Resumed",     L"Thread Hijack" },
            { "Entering Wait State",L"Thread Hijack" },
            { "ShellData Retrieved",L"Thread Hijack" },
            { "Thread Context Restored", L"Thread Hijack" },
            { "ProcessInformation", L"Thread Hijack" },
            { "[Handle]",            L"Handle Acquisition" },
            { "HandleAcq:",         L"Handle Acquisition" },
            { "[ManualMap]",        L"Manual Map" },
            { "Begin In-Memory Load", L"Manual Map" },
            { "Shell Data Initialized", L"Manual Map" },
            { "ShellSize",          L"Manual Map" },
            { "Total Size",         L"Manual Map" },
            { "Written To Memory",  L"Manual Map" },
            { "Staging Code Promoted", L"Manual Map" },
            { "Shell Returned",     L"Manual Map" },
            { "ImageBase",          L"Manual Map" },
            { "Fetching Routine Data", L"Manual Map" },
            { "[HeaderCloak]",      L"Header Cloak" },
            { "SymbolLoader",      L"Symbol Loader" },
            { "SymbolParser",      L"Symbol Resolver" },
            { "DynamicOffsets",     L"Dynamic Offsets" },
            { "KcStrings",          L"String Self-Test" },
            { "Attached To Target Process", L"Target Acquisition" },
            { "Target Process Name",  L"Target Acquisition" },
            { "Validating Specified File", L"Target Acquisition" },
            { "File Validated",     L"Target Acquisition" },
            { "Acquired Target Process Handle", L"Target Acquisition" },
            { nullptr,              nullptr },
        };

        const wchar_t * title = nullptr;
        for (const Category * c = kCategories; c->probe; ++c)
        {
            if (plain.find(c->probe) != std::string::npos)
            {
                title = c->title;
                break;
            }
        }

        if (title && title != g_RuntimeCategory.load(std::memory_order_acquire))
        {
            g_RuntimeCategory.store(title, std::memory_order_release);
            LOG(0, L"       %ls--- Runtime: %ls ---%ls\n", kCyan, title, kReset);
        }

        for (size_t start = 0; start < line.size();)
        {
            size_t end = line.find(L'\n', start);
            if (end == std::wstring::npos)
            {
                end = line.size();
            }
            if (end > start)
            {
                LOG(0, L"       %ls%.*ls%ls\n", kDim, static_cast<int>(end - start), line.c_str() + start, kReset);
            }
            start = end + 1;
        }
    }

    void ResetRuntimeCategory()
    {
        g_RuntimeCategory.store(nullptr, std::memory_order_release);
    }

    void DetachInterfaceConsole()
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        const bool hasConsole = output && output != INVALID_HANDLE_VALUE &&
            GetConsoleMode(output, &mode) != FALSE;
        fflush(stdout);
        fflush(stderr);
        if (!hasConsole)
        {
            return;
        }
        FreeConsole();
    }

    bool InterfaceConsolePresent()
    {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        return input && input != INVALID_HANDLE_VALUE && output && output != INVALID_HANDLE_VALUE &&
            GetConsoleMode(input, &mode) != FALSE;
    }

    std::wstring TrimText(const std::wstring & text)
    {
        const size_t first = text.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
        {
            return std::wstring();
        }

        const size_t last = text.find_last_not_of(L" \t\r\n");
        std::wstring value = text.substr(first, last - first + 1);
        if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
        {
            value = value.substr(1, value.size() - 2);
        }
        return value;
    }

    bool ReadLine(const wchar_t * prompt, std::wstring & value)
    {
        fflush(stdout);
        LOG(0, L"%ls", prompt);
        if (!std::getline(std::wcin, value))
        {
            return false;
        }
        value = TrimText(value);
        return true;
    }

    bool ParseUnsigned(const std::wstring & text, unsigned long long & value)
    {
        if (text.empty() || text.front() == L'-')
        {
            return false;
        }

        wchar_t * end = nullptr;
        errno = 0;
        const unsigned long long parsed = std::wcstoull(text.c_str(), &end, 10);
        if (errno == ERANGE || end == text.c_str() || *end != L'\0')
        {
            return false;
        }

        value = parsed;
        return true;
    }

    // A size that may be zero, which means "no limit". A malformed value
    // leaves the existing setting alone rather than silently removing a
    // limit that was there on purpose.
    size_t ParseConfigSize(const std::wstring & text, size_t current)
    {
        unsigned long long parsed = 0;
        if (!ParseUnsigned(text, parsed) || parsed > (std::numeric_limits<size_t>::max)())
        {
            return current;
        }
        return static_cast<size_t>(parsed);
    }

    bool ParseDword(const std::wstring & text, DWORD & value)
    {
        unsigned long long parsed = 0;
        if (!ParseUnsigned(text, parsed) || parsed > (std::numeric_limits<DWORD>::max)())
        {
            return false;
        }

        value = static_cast<DWORD>(parsed);
        return true;
    }

    bool ReadYesNo(const wchar_t * prompt, bool default_value, bool & value)
    {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD console_mode = 0;
        const bool hasConsole = input && input != INVALID_HANDLE_VALUE &&
            GetConsoleMode(input, &console_mode) != FALSE;
        if (!hasConsole)
        {
            value = default_value;
            return true;
        }
        for (;;)
        {
            LOG(0, L"%ls [%ls]: ", prompt, default_value ? L"Y" : L"N");
            std::wstring text;
            if (!ReadLine(L"", text))
            {
                return false;
            }
            if (text.empty())
            {
                value = default_value;
                return true;
            }
            if (text == L"y" || text == L"Y" || _wcsicmp(text.c_str(), L"yes") == 0)
            {
                value = true;
                return true;
            }
            if (text == L"n" || text == L"N" || _wcsicmp(text.c_str(), L"no") == 0)
            {
                value = false;
                return true;
            }
            PrintWarning(L"Answer Y Or N.");
        }
    }

    enum class ConfirmationResult
    {
        Proceed,
        Cancelled,
        Unavailable,
    };

    ConfirmationResult ConfirmBeforeDetection()
    {
        // The confirmation is skipped when the operator asked for it to be.
        // The request comes from the configuration file as well as from the
        // environment, because the launcher runs elevated and an elevated
        // process does not inherit its parent's environment: an environment
        // variable set by the operator would never be seen here.
        wchar_t auto_confirm[8] = {};
        if (GetEnvironmentVariableW(L"AMEGER_AUTO_CONFIRM", auto_confirm, 8) == 1 && auto_confirm[0] == L'1')
        {
            return ConfirmationResult::Proceed;
        }
        if (g_AutoConfirm)
        {
            return ConfirmationResult::Proceed;
        }
        if (GetRetryIndex() > 0)
        {
            return ConfirmationResult::Proceed;
        }
        while ((GetAsyncKeyState(VK_HOME) & 0x8000) || (GetAsyncKeyState(VK_END) & 0x8000))
        {
            Sleep(10);
        }

        LOG(0, L"%ls[+]%ls Press HOME To Inject, END To Cancel.\n", kGreen, kReset);
        fflush(stdout);

        bool home_was_down = false;
        bool end_was_down = false;
        for (;;)
        {
            const bool home_down = (GetAsyncKeyState(VK_HOME) & 0x8000) != 0;
            const bool end_down = (GetAsyncKeyState(VK_END) & 0x8000) != 0;

            if (home_down && !home_was_down)
            {
                StealthBeep(1600, 70);
            }
            if (end_down && !end_was_down)
            {
                StealthBeep(320, 120);
            }
            home_was_down = home_down;
            end_was_down = end_down;

            if (home_down)
            {
                while (GetAsyncKeyState(VK_HOME) & 0x8000)
                {
                    Sleep(10);
                }
                return ConfirmationResult::Proceed;
            }
            if (end_down)
            {
                while (GetAsyncKeyState(VK_END) & 0x8000)
                {
                    Sleep(10);
                }
                return ConfirmationResult::Cancelled;
            }
            Sleep(25);
        }
    }

    std::wstring ExecutableDirectory()
    {
        std::vector<wchar_t> buffer(MAX_PATH * 2);
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!length || length >= buffer.size())
        {
            return std::wstring();
        }

        const std::wstring path(buffer.data(), length);
        const size_t slash = path.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash + 1);
    }

    std::wstring RuntimePath(const std::wstring & dll_dir, const std::wstring & runtime_name)
    {
        const std::wstring directory = ExecutableDirectory();
        if (directory.empty() || runtime_name.empty() || dll_dir.empty())
        {
            return std::wstring();
        }
        return directory + dll_dir + L"\\" + runtime_name;
    }

    bool FileExists(const std::wstring & path)
    {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    namespace Trace
    {
        constexpr size_t kMaxPhases = 64;

inline std::wstring Widen(const char * text)
        {
            if (!text || !*text)
            {
                return std::wstring();
            }
            const int need = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
            if (need <= 1)
            {
                return std::wstring();
            }
            std::wstring out(static_cast<size_t>(need - 1), L'\0');
            if (MultiByteToWideChar(CP_UTF8, 0, text, need, out.data(), need) <= 0)
            {
                return std::wstring();
            }
            return out;
        }

        struct PhaseRecord
        {
wchar_t name[48]{};
        ULONGLONG start_ms = 0;
        ULONGLONG elapsed_ms = 0;
        bool open = false;
        bool ok = true;
    };

        inline PhaseRecord (& Phases())[kMaxPhases]
        {
            static PhaseRecord phases[kMaxPhases];
            return phases;
        }

        inline size_t & PhaseCount()
        {
            static size_t count = 0;
            return count;
        }

        inline ULONGLONG & T0()
        {
            static ULONGLONG t0 = 0;
            return t0;
        }

        inline ULONGLONG NowMs()
        {
            return GetTickCount64();
        }

        inline void BeginSession()
        {
            T0() = NowMs();
            PhaseCount() = 0;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            LOG(0, L"\n====================================================================================================\n");
            LOG(0, L" [Ameger Injector] -- Full Procedure Trace (Start %02u:%02u:%02u.%03u | PID %lu)\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                static_cast<unsigned long>(GetCurrentProcessId()));
            LOG(0, L"====================================================================================================\n");
        }

        inline PhaseRecord & Begin(const wchar_t * name)
        {
            PhaseRecord (& phases)[kMaxPhases] = Phases();
            size_t & count = PhaseCount();
            if (count >= kMaxPhases)
            {
                return phases[kMaxPhases - 1];
            }
            PhaseRecord & rec = phases[count++];
            rec = PhaseRecord{};
            wcsncpy_s(rec.name, name, _TRUNCATE);
            rec.start_ms = NowMs() - T0();
            rec.open = true;
            ResetRuntimeCategory();
            LOG(0, L"\n[%02zu] %ls> %ls%s%s\n", count, kDim, name, kReset, kDim);
            return rec;
        }

        inline void End(bool ok = true)
        {
            PhaseRecord (& phases)[kMaxPhases] = Phases();
            const size_t count = PhaseCount();
            if (!count)
            {
                return;
            }
            PhaseRecord & rec = phases[count - 1];
            if (!rec.open)
            {
                return;
            }
            rec.elapsed_ms = NowMs() - T0() - rec.start_ms;
            rec.open = false;
            rec.ok = ok;
            LOG(0, L"     %ls[%ls]%ls %-44ls %ls%6llu ms%s  (+%llu ms)\n",
                ok ? kGreen : kRed, ok ? L"+" : L"x", kReset,
                rec.name, kGreen, rec.elapsed_ms, kReset, rec.start_ms);
        }

        inline void Note(const wchar_t * fmt, ...)
        {
            va_list args;
            va_start(args, fmt);
            const int need = _vscwprintf(fmt, args);
            va_end(args);
            if (need <= 0)
            {
                return;
            }
            std::vector<wchar_t> buffer(static_cast<size_t>(need) + 1);
            va_start(args, fmt);
            vswprintf_s(buffer.data(), buffer.size(), fmt, args);
            va_end(args);
            LOG(0, L"       %ls%s%ls\n", kDim, buffer.data(), kReset);
        }

        inline void Summary(const wchar_t * outcome)
        {
            PhaseRecord (& phases)[kMaxPhases] = Phases();
            const size_t count = PhaseCount();
            const ULONGLONG total = NowMs() - T0();

            LOG(0, L"\n====================================================================================================\n");
            LOG(0, L" [Phase Summary] %ls\n", outcome ? outcome : L"Completed");
            LOG(0, L"====================================================================================================\n");
            LOG(0, L"  %-3s %-46s %10s %8s %12s\n", L"#", L"Phase", L"Elapsed", L"Share", L"Start");

            for (size_t i = 0; i < count; ++i)
            {
                const double share = total ? (static_cast<double>(phases[i].elapsed_ms) * 100.0 / static_cast<double>(total)) : 0.0;
                const wchar_t * tint = phases[i].open ? kYellow : kGreen;
                LOG(0, L"  %ls%02zu%ls %-46s %ls%8llu ms%s %7.1f%% %10llu ms\n",
                    kDim, i + 1, kReset, phases[i].name, tint, phases[i].elapsed_ms, kReset,
                    share, phases[i].start_ms);
            }

            LOG(0, L"  %-50s %ls%8llu ms%s\n", L"Total Wall Time", kGreen, total, kReset);
            LOG(0, L"====================================================================================================\n");
        }
    }
    static_assert(sizeof(UNICODE_STRING) == 16);
    static_assert(sizeof(CLIENT_ID) == 16);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ClientId) == 40);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ThreadState) == 68);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, WaitReason) == 72);
    static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 0x50);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

    DWORD PickHijackThreadTid(DWORD target_pid, DWORD exclude_tid)
    {
        if (!target_pid)
        {
            return 0;
        }

        using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
        NtQuerySystemInformationFn NtQuery = nullptr;
        {
            auto mod_name = XOR_STR_W(L"ntdll.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());

            if (mod)
            {
                auto api_name = XOR_STR_A("NtQuerySystemInformation");
                NtQuery = ReCa<NtQuerySystemInformationFn>(
                    GetProcAddress(mod, api_name.get()));
            }
        }
        if (!NtQuery)
        {
            return 0;
        }

        std::vector<BYTE> buffer(1 << 20);
        ULONG size = static_cast<ULONG>(buffer.size());
        LONG status = NtQuery(5, buffer.data(), size, &size);
        while (static_cast<DWORD>(status) == 0xC0000004u)
        {
            ULONG grow = size > buffer.size() ? size : static_cast<ULONG>(buffer.size() * 2);
            if (grow > (16u << 20))
            {
                return 0;
            }

            buffer.resize(grow);
            size = grow;
            status = NtQuery(5, buffer.data(), size, &size);
        }

        if (status != 0)
        {
            return 0;
        }

        DWORD best_tid = 0;
        size_t offset = 0;
        for (;;)
        {
            if (offset + offsetof(SYSTEM_PROCESS_INFORMATION, Threads) > buffer.size())
            {
                break;
            }

            const auto * proc = ReCa<const SYSTEM_PROCESS_INFORMATION *>(buffer.data() + offset);
            if (static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(proc->UniqueProcessId)) == target_pid)
            {
                const size_t threads_base = offset + offsetof(SYSTEM_PROCESS_INFORMATION, Threads);
                const ULONG thread_count = proc->NumberOfThreads;

                auto is_safe_wait = [](unsigned char state, unsigned char reason) -> bool
                {
                    if (state != 5)
                    {
                        return false;
                    }
                    return WAIT_REASON_SAFE::IsSafe(reason);
                };
                auto score_walk = [&](DWORD avoid_tid, bool allow_wait) -> bool
                {
                    bool found = false;
                    for (ULONG index = 0; index < thread_count; ++index)
                    {
                        const size_t entry = threads_base + static_cast<size_t>(index) * sizeof(SYSTEM_THREAD_INFORMATION);
                        if (entry + sizeof(SYSTEM_THREAD_INFORMATION) > buffer.size())
                        {
                            break;
                        }

                        const auto * thread = ReCa<const SYSTEM_THREAD_INFORMATION *>(buffer.data() + entry);
                        const DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
                        if (!tid || tid == GetCurrentThreadId() || tid == exclude_tid || tid == avoid_tid)
                        {
                            continue;
                        }

                        const unsigned char thread_state = static_cast<unsigned char>(thread->ThreadState);
                        const unsigned char thread_reason = static_cast<unsigned char>(thread->WaitReason);
                        if (thread_state != 2 && !(allow_wait && is_safe_wait(thread_state, thread_reason)))
                        {
                            continue;
                        }

                        if (!found || tid < best_tid)
                        {
                            best_tid = tid;
                            found = true;
                        }
                    }
                    return found;
                };

                DWORD min_tid = 0;
                for (ULONG index = 0; index < thread_count; ++index)
                {
                    const size_t entry = threads_base + static_cast<size_t>(index) * sizeof(SYSTEM_THREAD_INFORMATION);
                    if (entry + sizeof(SYSTEM_THREAD_INFORMATION) > buffer.size())
                    {
                        break;
                    }
                    const auto * thread = ReCa<const SYSTEM_THREAD_INFORMATION *>(buffer.data() + entry);
                    const DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
                    if (!tid || tid == GetCurrentThreadId())
                    {
                        continue;
                    }
                    if (!min_tid || tid < min_tid)
                    {
                        min_tid = tid;
                    }
                }

                if (min_tid)
                {
                    score_walk(min_tid, false);
                }
                if (!best_tid)
                {
                    score_walk(0, false);
                }
                if (!best_tid && min_tid)
                {
                    score_walk(min_tid, true);
                }
                if (!best_tid)
                {
                    score_walk(0, true);
                }
                if (!best_tid)
                {
                    ULONG_PTR exe_base = 0;
                    SIZE_T exe_size = 0;
                    HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
                    if (msnap && msnap != INVALID_HANDLE_VALUE)
                    {
                        MODULEENTRY32 mod{ 0 };
                        mod.dwSize = sizeof(mod);
                        if (Module32First(msnap, &mod))
                        {
                            exe_base = reinterpret_cast<ULONG_PTR>(mod.modBaseAddr);
                            exe_size = static_cast<SIZE_T>(mod.modBaseSize);
                        }
                        CloseHandle(msnap);
                    }
                    HMODULE mod_ntdll = nullptr;
                    {
                        auto mod_name = XOR_STR_W(L"ntdll.dll");
                        mod_ntdll = GetModuleHandleW(mod_name.get());
                    }
                    using QueryThreadFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                    QueryThreadFn query = nullptr;
                    if (mod_ntdll)
                    {
                        auto api_name = XOR_STR_A("NtQueryInformationThread");
                        query = reinterpret_cast<QueryThreadFn>(GetProcAddress(mod_ntdll, api_name.get()));
                    }
                    DWORD best_any = 0;
                    DWORD best_exe = 0;
                    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (snap && snap != INVALID_HANDLE_VALUE)
                    {
                        THREADENTRY32 entry{ 0 };
                        entry.dwSize = sizeof(entry);
                        if (Thread32First(snap, &entry))
                        {
                            do
                            {
                                if (entry.th32OwnerProcessID != target_pid)
                                {
                                    continue;
                                }
                                const DWORD tid = entry.th32ThreadID;
                                if (!tid || tid == GetCurrentThreadId() || tid == exclude_tid)
                                {
                                    continue;
                                }
                                bool exe_start = false;
                                if (query && exe_base && exe_size)
                                {
                                    HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                                    if (ht)
                                    {
                                        PVOID start = nullptr;
                                        if (query(ht, 9, &start, sizeof(start), nullptr) == 0 && start)
                                        {
                                            const auto addr = reinterpret_cast<ULONG_PTR>(start);
                                            exe_start = addr >= exe_base && addr < exe_base + exe_size;
                                        }
                                        CloseHandle(ht);
                                    }
                                }
                                if (exe_start && (!best_exe || tid < best_exe))
                                {
                                    best_exe = tid;
                                }
                                if (!best_any || tid < best_any)
                                {
                                    best_any = tid;
                                }
                            } while (Thread32Next(snap, &entry));
                        }
                        CloseHandle(snap);
                    }
                    best_tid = best_exe ? best_exe : best_any;
                }

                break;
            }

            if (proc->NextEntryOffset < 8)
            {
                break;
            }

            offset += proc->NextEntryOffset;
        }

        return best_tid;
    }

    std::wstring CanonicalPath(const std::wstring & path)
    {
        std::vector<wchar_t> buffer(MAX_PATH * 4);
        const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (!length || length >= buffer.size())
        {
            return std::wstring();
        }
        return std::wstring(buffer.data(), length);
    }

    bool EqualsNoCase(const std::wstring & value, const wchar_t * expected)
    {
        return _wcsicmp(value.c_str(), expected) == 0;
    }

    // Locates the encrypted configuration beside the executable. The directory
    // is scanned once per run: the result cannot change while the process is
    // alive, and every caller reaching the same answer by re-walking the
    // directory would only widen the window in which the launcher and the
    // transcript could disagree about which file was used.
    std::wstring ConfigurationPathUncached()
    {
        const std::wstring directory = ExecutableDirectory();
        if (directory.empty())
        {
            return std::wstring();
        }

        const std::wstring pattern = directory + L"*.ini";
        WIN32_FIND_DATAW found{};
        HANDLE search = FindFirstFileW(pattern.c_str(), &found);
        if (search == INVALID_HANDLE_VALUE)
        {
            return std::wstring();
        }

        std::wstring match;
        bool ambiguous = false;
        do
        {

            if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                continue;
            }

            const std::wstring candidate = directory + found.cFileName;
            HANDLE file = CreateFileW(candidate.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                continue;
            }

            char head[8]{ 0 };
            DWORD read = 0;
            const BOOL ok = ReadFile(file, head, sizeof(head), &read, nullptr);
            CloseHandle(file);
            if (!ok || read != sizeof(head))
            {
                continue;
            }

            const char * probe = AMEGER_CONFIG_MAGIC_STR;
            bool magic = true;
            for (size_t i = 0; i < kConfigBlobMagicSize; ++i)
            {
                if (head[i] != probe[i])
                {
                    magic = false;
                    break;
                }
            }
            if (!magic)
            {
                continue;
            }

            if (!match.empty())
            {
                ambiguous = true;
                break;
            }
            match = CanonicalPath(candidate);
            if (match.empty())
            {
                ambiguous = true;
                break;
            }
        } while (FindNextFileW(search, &found));
        FindClose(search);

        if (ambiguous || match.empty() || !FileExists(match))
        {
            return std::wstring();
        }
        return match;
    }

    const std::wstring & ConfigurationPath()
    {
        struct Cache
        {
            std::wstring path;
            bool resolved = false;
        };

        static Cache cache;

        if (!cache.resolved)
        {
            cache.path = ConfigurationPathUncached();
            cache.resolved = true;
        }

        return cache.path;
    }

    bool ParseConfigBool(const std::wstring & value, bool default_value)
    {
        if (EqualsNoCase(value, L"y") || EqualsNoCase(value, L"yes") || EqualsNoCase(value, L"1") || EqualsNoCase(value, L"true"))
        {
            return true;
        }
        if (EqualsNoCase(value, L"n") || EqualsNoCase(value, L"no") || EqualsNoCase(value, L"0") || EqualsNoCase(value, L"false"))
        {
            return false;
        }
        return default_value;
    }

    bool IsValidDeployedFileName(const std::wstring & name)
    {
        if (name.empty() || name.size() > 64)
        {
            return false;
        }
        if (name.find(L'\\') != std::wstring::npos || name.find(L'/') != std::wstring::npos ||
            name.find(L':') != std::wstring::npos || name.find(L"..") != std::wstring::npos)
        {
            return false;
        }
        for (wchar_t c : name)
        {
            if (c < 0x20 || c == 0x7F)
            {
                return false;
            }
        }
        return true;
    }

    bool ParseExportMap(const std::wstring & value, std::vector<ExportNameMap> & map)
    {
        map.clear();
        if (value.empty())
        {
            return false;
        }

        size_t start = 0;
        for (;;)
        {
            const size_t comma = value.find(L',', start);
            const size_t length = comma == std::wstring::npos ? std::wstring::npos : comma - start;
            const std::wstring token = TrimText(value.substr(start, length));
            if (!token.empty())
            {
                const size_t equals = token.find(L'=');
                if (equals == std::wstring::npos)
                {
                    return false;
                }
                const std::wstring old_name = TrimText(token.substr(0, equals));
                const std::wstring new_name = TrimText(token.substr(equals + 1));
                if (old_name.empty() || new_name.empty() || old_name.size() != new_name.size())
                {
                    return false;
                }

                ExportNameMap entry;
                for (wchar_t c : old_name)
                {
                    if (c <= 0 || c > 0x7F)
                    {
                        return false;
                    }
                    entry.old_name.push_back(static_cast<char>(c));
                }
                for (wchar_t c : new_name)
                {
                    if (c <= 0 || c > 0x7F)
                    {
                        return false;
                    }
                    entry.new_name.push_back(static_cast<char>(c));
                }

                for (const ExportNameMap & existing : map)
                {
                    if (existing.old_name == entry.old_name || existing.new_name == entry.new_name)
                    {
                        return false;
                    }
                }
                map.push_back(entry);
            }

            if (comma == std::wstring::npos)
            {
                break;
            }
            start = comma + 1;
        }

        return !map.empty();
    }

    const std::string * FindMappedExportName(const std::vector<ExportNameMap> & map, const char * old_name)
    {
        if (!old_name)
        {
            return nullptr;
        }
        for (const ExportNameMap & entry : map)
        {
            if (entry.old_name == old_name)
            {
                return &entry.new_name;
            }
        }
        return nullptr;
    }

    static_assert(sizeof(AMEGER_CONFIG_MAGIC_STR) == kConfigBlobMagicSize + 1, "config magic must be 8 chars");

    bool HasConfigBlobMagic(const std::string & raw)
    {
        if (raw.size() <= kConfigBlobMagicSize)
        {
            return false;
        }

        const char * probe = AMEGER_CONFIG_MAGIC_STR;
        for (size_t i = 0; i < kConfigBlobMagicSize; ++i)
        {
            if (raw[i] != probe[i])
            {
                return false;
            }
        }

        return true;
    }

    bool DecryptConfigBlob(const std::string & raw, std::string & out)
    {
        out.clear();

        if (!HasConfigBlobMagic(raw))
        {
            return false;
        }

        DATA_BLOB input{};
        input.cbData = static_cast<DWORD>(raw.size() - kConfigBlobMagicSize);
        input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(raw.data() + kConfigBlobMagicSize));

        DATA_BLOB output{};
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        {
            return false;
        }

        out.assign(reinterpret_cast<const char *>(output.pbData), output.cbData);
        LocalFree(output.pbData);
        return true;
    }

    bool LoadWizardConfig(WizardConfig & config, std::wstring & path, bool & invalid)
    {
        config = WizardConfig{};
        invalid = false;
        path = ConfigurationPath();
        if (path.empty())
        {
            return false;
        }

        std::string raw_bytes;
        {
            std::ifstream raw_file(path, std::ios::binary | std::ios::ate);
            if (!raw_file.good())
            {
                invalid = true;
                return false;
            }

            const std::streamoff raw_size = raw_file.tellg();
            constexpr unsigned long long kMaxConfigBytes = 1024ULL * 1024ULL;
            if (raw_size < 0 || static_cast<unsigned long long>(raw_size) > kMaxConfigBytes)
            {
                invalid = true;
                return false;
            }

            raw_bytes.resize(static_cast<size_t>(raw_size));
            raw_file.seekg(0, std::ios::beg);
            raw_file.read(raw_bytes.data(), raw_size);
            if (!raw_file || raw_file.gcount() != raw_size)
            {
                invalid = true;
                return false;
            }
        }

        std::wstring config_text;
        std::string plaintext;
        if (DecryptConfigBlob(raw_bytes, plaintext))
        {
            raw_bytes.swap(plaintext);
        }
        else
        {

            invalid = true;
            return false;
        }
        if (!raw_bytes.empty())
        {
            const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw_bytes.c_str(), static_cast<int>(raw_bytes.size()), nullptr, 0);
            if (required <= 0)
            {
                invalid = true;
                return false;
            }

            config_text.resize(static_cast<size_t>(required), L'\0');
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw_bytes.c_str(), static_cast<int>(raw_bytes.size()), config_text.data(), required))
            {
                invalid = true;
                return false;
            }

            if (!config_text.empty() && config_text.front() == 0xFEFF)
            {
                config_text.erase(config_text.begin());
            }
        }

        std::wstringstream file(config_text);

        std::wstring section;
        std::wstring line;
        while (std::getline(file, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            const std::wstring text = TrimText(line);
            if (text.empty() || text.front() == L';' || text.front() == L'#')
            {
                continue;
            }
            if (text.size() >= 2 && text.front() == L'[' && text.back() == L']')
            {
                section = text.substr(1, text.size() - 2);
                continue;
            }

            const size_t separator = text.find(L'=');
            if (separator == std::wstring::npos)
            {
                continue;
            }

            const std::wstring key = TrimText(text.substr(0, separator));
            std::wstring value = TrimText(text.substr(separator + 1));
            bool quoted = false;
            size_t comment = std::wstring::npos;
            for (size_t i = 0; i < value.size(); ++i)
            {
                if (value[i] == L'"')
                {
                    quoted = !quoted;
                }
                else if (!quoted && (value[i] == L';' || value[i] == L'#'))
                {
                    comment = i;
                    break;
                }
            }
            if (comment != std::wstring::npos)
            {
                value = TrimText(value.substr(0, comment));
            }
            if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
            {
                value = value.substr(1, value.size() - 2);
            }

            const bool general = EqualsNoCase(section, XOR_STR_W(L"General").get());
            const bool manual = EqualsNoCase(section, XOR_STR_W(L"ManualMap").get());
            if (general && EqualsNoCase(key, XOR_STR_W(L"SchemaVersion").get()))
            {
                DWORD parsed = 0;
                if (ParseDword(value, parsed) && parsed <= static_cast<DWORD>(INT_MAX))
                {
                    config.schema_version = static_cast<int>(parsed);
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"ProcessName").get()))
            {
                config.target_name = value;
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"PayloadSha256").get()))
            {
                config.expected_payload_sha256 = value;
                std::transform(config.expected_payload_sha256.begin(), config.expected_payload_sha256.end(), config.expected_payload_sha256.begin(), towupper);
            }

            else if (general && EqualsNoCase(key, XOR_STR_W(L"PayloadName").get()))
            {
                config.payload_name = value;
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"RuntimeName").get()))
            {
                config.runtime_name = value;
            }

            else if (general && EqualsNoCase(key, XOR_STR_W(L"DllDir").get()))
            {
                if (!value.empty())
                {
                    if (!IsValidDeployedFileName(value))
                    {
                        config = WizardConfig{};
                        invalid = true;
                        return false;
                    }
                    config.dll_dir = value;
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"ExportMap").get()))
            {
                if (!ParseExportMap(value, config.export_map))
                {
                    config = WizardConfig{};
                    invalid = true;
                    return false;
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"HandleHijacking").get()))
            {
                config.handle_hijacking = ParseConfigBool(value, config.handle_hijacking);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"HijackScan").get()))
            {
                config.hijack_scan = ParseConfigBool(value, config.hijack_scan);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"SponsorRoundtrip").get()))
            {
                config.sponsor_roundtrip = ParseConfigBool(value, config.sponsor_roundtrip);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"VerboseTrace").get()))
            {
                config.verbose_trace = ParseConfigBool(value, config.verbose_trace);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"Quiet").get()))
            {
                config.quiet = ParseConfigBool(value, config.quiet);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"TestMode").get()))
            {
                config.test_mode = ParseConfigBool(value, config.test_mode);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"DetachConsole").get()))
            {
                config.detach_console = ParseConfigBool(value, config.detach_console);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"Timeout").get()))
            {
                DWORD parsed = 0;

                if (ParseDword(value, parsed) && parsed >= 1000 && parsed <= static_cast<DWORD>(INT_MAX))
                {
                    config.timeout = static_cast<int>(parsed);
                }
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"DiscardResultLogOnSuccess").get()))
            {
                config.discard_result_log_on_success = ParseConfigBool(value, config.discard_result_log_on_success);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"AutoConfirm").get()))
            {
                config.auto_confirm = ParseConfigBool(value, config.auto_confirm);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"SurveyMaxRegions").get()))
            {
                config.survey_max_regions = ParseConfigSize(value, config.survey_max_regions);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"SurveyMaxMb").get()))
            {
                config.survey_max_mb = ParseConfigSize(value, config.survey_max_mb);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"SurveyMaxSampleRegions").get()))
            {
                config.survey_max_sample_regions = ParseConfigSize(value, config.survey_max_sample_regions);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"DonorOwnerBlocklist").get()))
            {
                config.donor_owner_blocklist = value;
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"TestTarget").get()))
            {
                const std::wstring trimmed = TrimText(value);
                if (!trimmed.empty())
                {
                    config.test_target = trimmed;
                }
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"ExecuteTLS").get()))
            {
                config.execute_tls = ParseConfigBool(value, config.execute_tls);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"RunDLLMain").get()))
            {
                config.run_dllmain = ParseConfigBool(value, config.run_dllmain);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"LockLoaderLock").get()))
            {
                config.loader_lock = ParseConfigBool(value, config.loader_lock);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"ResolveImports").get()))
            {
                config.resolve_imports = ParseConfigBool(value, config.resolve_imports);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"EnableExceptions").get()))
            {
                config.exceptions = ParseConfigBool(value, config.exceptions);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"InitSecurityCookie").get()))
            {
                config.security_cookie = ParseConfigBool(value, config.security_cookie);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"SetPageProtections").get()))
            {
                config.page_protections = ParseConfigBool(value, config.page_protections);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"ResolveDelayImports").get()))
            {
                config.delay_imports = ParseConfigBool(value, config.delay_imports);
            }
            else if (manual && EqualsNoCase(key, XOR_STR_W(L"CleanDataDirectories").get()))
            {
                config.clean_data = ParseConfigBool(value, config.clean_data);
            }
        }

        if (config.schema_version != 1)
        {
            config = WizardConfig{};
            invalid = true;
            return false;
        }

        {
            bool valid_hash = config.expected_payload_sha256.size() == 64;
            for (wchar_t value : config.expected_payload_sha256)
            {
                valid_hash = valid_hash && ((value >= L'0' && value <= L'9') || (value >= L'A' && value <= L'F'));
            }
            if (!valid_hash)
            {
                config = WizardConfig{};
                invalid = true;
                return false;
            }
        }

        if (config.target_name.empty())
        {
            config = WizardConfig{};
            invalid = true;
            return false;
        }

        if (!IsValidDeployedFileName(config.payload_name) ||
            !IsValidDeployedFileName(config.runtime_name) ||
            config.export_map.empty())
        {
            config = WizardConfig{};
            invalid = true;
            return false;
        }
        return true;
    }

    std::wstring Sha256Hex(const std::vector<BYTE> & bytes)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD object_length = 0;
        DWORD result_length = 0;
        DWORD hash_length = 0;
        std::vector<BYTE> hash_object;
        std::vector<BYTE> hash_bytes;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &result_length, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &result_length, 0) < 0)
        {
            if (algorithm)
            {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            return std::wstring();
        }

        try
        {
            hash_object.resize(object_length);
            hash_bytes.resize(hash_length);
        }
        catch (const std::bad_alloc &)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return std::wstring();
        }

        if (BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG) < 0)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return std::wstring();
        }

        size_t offset = 0;
        while (offset < bytes.size())
        {
            const ULONG chunk = static_cast<ULONG>((std::min)(bytes.size() - offset, static_cast<size_t>(ULONG_MAX)));
            if (BCryptHashData(hash, const_cast<BYTE *>(bytes.data() + offset), chunk, 0) < 0)
            {
                BCryptDestroyHash(hash);
                BCryptCloseAlgorithmProvider(algorithm, 0);
                return std::wstring();
            }
            offset += chunk;
        }

        const NTSTATUS finish_status = BCryptFinishHash(hash, hash_bytes.data(), hash_length, 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (finish_status < 0)
        {
            return std::wstring();
        }

        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring result;
        result.reserve(hash_bytes.size() * 2);
        for (BYTE value : hash_bytes)
        {
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 0x0F]);
        }
        return result;
    }

    bool ReadHandleBytes(HANDLE file, std::vector<BYTE> & bytes)
    {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size))
        {
            LOG(0,  L"%lsFailed To Query Runtime Size = 0x%08X%ls\n", kRed, GetLastError(), kReset);
            return false;
        }
        if (size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > PE_IMAGE::MAX_IMAGE_SIZE)
        {
            LOG(0,  L"%lsInvalid Runtime Size = %lld Bytes%ls\n", kRed, size.QuadPart, kReset);
            return false;
        }

        bytes.resize(static_cast<size_t>(size.QuadPart));
        size_t total = 0;
        while (total < bytes.size())
        {
            DWORD read = 0;
            const size_t remaining = bytes.size() - total;
            const BOOL read_ok = ReadFile(file, bytes.data() + total, static_cast<DWORD>(remaining), &read, nullptr);

            const DWORD read_error = read_ok ? ERROR_SUCCESS : GetLastError();
            if (!read_ok || read == 0)
            {
                LOG(0,  L"%lsFailed To Read Runtime = 0x%08X (%zu Of %zu Bytes)%ls\n", kRed, read_error, total, bytes.size(), kReset);
                bytes.clear();
                return false;
            }
            total += read;
        }
        return true;
    }

    bool VerifyRuntimeBytes(const std::vector<BYTE> & bytes)
    {
        PE_IMAGE::OPTIONS options;
        options.RequireDll = true;
        options.RequireExports = true;
        options.EnableExceptions = true;
        PE_IMAGE::VIEW view;
        const DWORD validation_result = PE_IMAGE::Validate(bytes.data(), bytes.size(), IMAGE_FILE_MACHINE_AMD64, options, view);
        if (validation_result != FILE_ERR_SUCCESS)
        {
            LOG(0,  L"%lsRuntime DLL PE Validation Failed = 0x%08X%ls\n", kRed, validation_result, kReset);
            return false;
        }

        constexpr uint32_t expected_words[] =
        {
            AMEGER_RUNTIME_DLL_HASH0,
            AMEGER_RUNTIME_DLL_HASH1,
            AMEGER_RUNTIME_DLL_HASH2,
            AMEGER_RUNTIME_DLL_HASH3,
            AMEGER_RUNTIME_DLL_HASH4,
            AMEGER_RUNTIME_DLL_HASH5,
            AMEGER_RUNTIME_DLL_HASH6,
            AMEGER_RUNTIME_DLL_HASH7
        };
        bool has_embedded_hash = false;
        for (uint32_t word : expected_words)
        {
            has_embedded_hash = has_embedded_hash || word != 0;
        }
        if (!has_embedded_hash)
        {
            PrintError(L"The Runtime Has No Embedded SHA-256. Build It With Build\\Executors\\Create.bat.");
            return false;
        }

        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring expected_hash;
        expected_hash.reserve(64);
        for (uint32_t word : expected_words)
        {
            for (int shift = 28; shift >= 0; shift -= 4)
            {
                expected_hash.push_back(hex[(word >> shift) & 0x0F]);
            }
        }

        const std::wstring actual_hash = Sha256Hex(bytes);
        if (actual_hash.empty() || _wcsicmp(actual_hash.c_str(), expected_hash.c_str()) != 0)
        {
            LOG(0,  L"%lsRuntime DLL SHA-256 Mismatch. Expected %ls, Got %ls%ls\n", kRed, expected_hash.c_str(), actual_hash.c_str(), kReset);
            return false;
        }

        return true;
    }

    bool LoadRuntime(Runtime & runtime, const WizardConfig & config)
    {
        const std::wstring path = RuntimePath(config.dll_dir, config.runtime_name);
        if (path.empty() || !FileExists(path))
        {
            PrintError((L"The Runtime DLL (" + config.runtime_name + L") Is Missing In " + config.dll_dir + L"\\ Next To The Executable.").c_str());
            return false;
        }

        HANDLE runtime_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (runtime_file == INVALID_HANDLE_VALUE)
        {
            LOG(0,  L"%lsFailed To Open Runtime For Verification = 0x%08X%ls\n", kRed, GetLastError(), kReset);
            return false;
        }

        FileHandleGuard runtime_guard(runtime_file);

        std::vector<BYTE> runtime_bytes;
        if (!ReadHandleBytes(runtime_file, runtime_bytes) || !VerifyRuntimeBytes(runtime_bytes))
        {
            return false;
        }

        DWORD load_error = ERROR_SUCCESS;
        bool export_map_complete = true;
        {
            StdoutParkGuard park;
            runtime.module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            load_error = GetLastError();
            if (runtime.module)
            {
                BY_HANDLE_FILE_INFORMATION verified_info{};
                BY_HANDLE_FILE_INFORMATION loaded_info{};
                HANDLE verify_reopen = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                const bool same_file =
                    GetFileInformationByHandle(runtime_file, &verified_info) &&
                    verify_reopen != INVALID_HANDLE_VALUE &&
                    GetFileInformationByHandle(verify_reopen, &loaded_info) &&
                    verified_info.dwVolumeSerialNumber == loaded_info.dwVolumeSerialNumber &&
                    verified_info.nFileIndexHigh == loaded_info.nFileIndexHigh &&
                    verified_info.nFileIndexLow == loaded_info.nFileIndexLow;
                if (verify_reopen != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(verify_reopen);
                }
                if (!same_file)
                {
                    LOG(0, L"%lsRuntime File Identity Changed Between Verification And Load; Refusing.%ls\n", kRed, kReset);
                    FreeLibrary(runtime.module);
                    runtime.module = nullptr;
                    return false;
                }

                auto resolve_export = [&](const char * old_name) -> FARPROC
                {
                    const std::string * mapped = FindMappedExportName(config.export_map, old_name);
                    if (!mapped)
                    {
                        export_map_complete = false;
                        return nullptr;
                    }
                    return GetProcAddress(runtime.module, mapped->c_str());
                };

                auto resolve_optional_export = [&](const char * old_name) -> FARPROC
                {
                    const std::string * mapped = FindMappedExportName(config.export_map, old_name);
                    return mapped ? GetProcAddress(runtime.module, mapped->c_str()) : nullptr;
                };

                auto exp_mem = XOR_STR_A("CoreExecute");
                runtime.memory_inject = reinterpret_cast<f_Memory_Inject>(resolve_export(exp_mem.get()));
                auto exp_sym = XOR_STR_A("CoreSymbolState");
                runtime.get_symbol_state = reinterpret_cast<f_GetSymbolState>(resolve_export(exp_sym.get()));
                auto exp_imp = XOR_STR_A("CoreImportState");
                runtime.get_import_state = reinterpret_cast<f_GetImportState>(resolve_export(exp_imp.get()));
                auto exp_init = XOR_STR_A("CoreStart");
                runtime.initialize_runtime = reinterpret_cast<f_InitializeRuntime>(resolve_export(exp_init.get()));
                auto exp_shut = XOR_STR_A("CoreStop");
                runtime.shutdown_runtime = reinterpret_cast<f_ShutdownRuntime>(resolve_export(exp_shut.get()));
                auto exp_dl = XOR_STR_A("CoreFetch");
                runtime.start_download = reinterpret_cast<f_StartDownload>(resolve_export(exp_dl.get()));
                auto exp_cb = XOR_STR_A("CoreSetTrace");
                runtime.set_raw_print_callback = reinterpret_cast<f_SetRawPrintCallback>(resolve_export(exp_cb.get()));
                auto exp_hij = XOR_STR_A("CoreAcqStats");
                runtime.get_last_hijack_stats = reinterpret_cast<f_GetLastHijackStats>(resolve_export(exp_hij.get()));
                auto exp_map = XOR_STR_A("CoreLoadStats");
                runtime.get_last_map_stats = reinterpret_cast<f_GetLastMapStats>(resolve_export(exp_map.get()));
                auto exp_str = XOR_STR_A("CoreStrStats");
                runtime.get_last_string_stats = reinterpret_cast<f_GetLastStringStats>(resolve_export(exp_str.get()));
                auto exp_tec = XOR_STR_A("CoreExecStats");
                runtime.get_last_thread_exec_stats = reinterpret_cast<f_GetLastThreadExecStats>(resolve_export(exp_tec.get()));
                auto exp_exec = XOR_STR_A("CoreExecTelemetry");
                runtime.get_last_exec_telemetry = reinterpret_cast<f_GetLastExecTelemetry>(resolve_optional_export(exp_exec.get()));

                auto exp_err = XOR_STR_A("CoreLastError");
                runtime.get_last_error_info = reinterpret_cast<f_GetLastErrorInfo>(resolve_export(exp_err.get()));

                auto exp_clear_err = XOR_STR_A("CoreClearLastError");
                runtime.clear_last_error_info = reinterpret_cast<f_ClearLastErrorInfo>(resolve_optional_export(exp_clear_err.get()));

                if (runtime.set_raw_print_callback)
                {
                    runtime.set_raw_print_callback(VerboseOutputEnabled() ? VerbosePrint : QuietPrint);
                }
            }
        }

        if (!runtime.module)
        {
            LOG(0,  L"%lsFailed To Load Runtime = %ls (0x%08X)%ls\n", kRed, path.c_str(), load_error, kReset);
            return false;
        }

        if (!export_map_complete)
        {
            PrintError(L"The Runtime Export Map Does Not Cover Every Export This Launcher Needs.");
            FreeLibrary(runtime.module);
            runtime.module = nullptr;
            return false;
        }

        if (!runtime.memory_inject || !runtime.get_symbol_state || !runtime.get_import_state || !runtime.initialize_runtime || !runtime.start_download)
        {
            PrintError(L"The Runtime DLL Does Not Expose The Required Functions.");
            FreeLibrary(runtime.module);
            runtime.module = nullptr;
            return false;
        }

        if (runtime.get_last_hijack_stats)
        {
            if (VerboseOutputEnabled()) { LOG(0, L"%ls[+]%ls Telemetry Export Found.\n\n", kGreen, kReset); }

        }
        else
        {
            LOG(0, L"  %ls[!]%ls Telemetry Export Missing; The Acquire Process Handle Step Will Show No Telemetry.\n", kYellow, kReset);
        }

        return true;
    }

    bool WaitForRuntime(const Runtime & runtime, DWORD & symbol_state, DWORD & import_state, DWORD & init_state)
    {
        constexpr ULONGLONG timeout = 120000;
        init_state = INJ_ERR_SUCCESS;

        const DWORD initialization_state = runtime.initialize_runtime();
        if (initialization_state != INJ_ERR_SUCCESS)
        {
            init_state = initialization_state;
            symbol_state = initialization_state;
            import_state = initialization_state;

            return false;
        }

        runtime.start_download();
        symbol_state = runtime.get_symbol_state();
        ULONGLONG deadline = GetTickCount64() + timeout;
        {
            const ULONGLONG poll_start = GetTickCount64();
            ULONGLONG last_report = poll_start;
            DWORD polls = 0;
            while (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
            {
                const ULONGLONG now = GetTickCount64();
                if (now >= deadline)
                {
                    Trace::Note(L"Symbol Poll Timed Out After %llu ms (%u Polls) | State = 0x%08lX",
                        static_cast<unsigned long long>(now - poll_start), polls,
                        static_cast<unsigned long>(symbol_state));
                    return false;
                }
                if (now - last_report >= 2000)
                {
                    last_report = now;
                    Trace::Note(L"Waiting For ntdll Symbols... %llu ms Elapsed | %u Polls",
                        static_cast<unsigned long long>(now - poll_start), polls);
                }
                Sleep(10);
                ++polls;
                symbol_state = runtime.get_symbol_state();
            }
            Trace::Note(L"Symbols Ready In %llu ms (%u Polls) | State = 0x%08lX",
                static_cast<unsigned long long>(GetTickCount64() - poll_start), polls,
                static_cast<unsigned long>(symbol_state));
        }
        if (symbol_state != INJ_ERR_SUCCESS)
        {
            return false;
        }

        import_state = runtime.get_import_state();
        deadline = GetTickCount64() + timeout;
        {
            const ULONGLONG poll_start = GetTickCount64();
            ULONGLONG last_report = poll_start;
            DWORD polls = 0;
            while (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
            {
                const ULONGLONG now = GetTickCount64();
                if (now >= deadline)
                {
                    Trace::Note(L"Import Poll Timed Out After %llu ms (%u Polls) | State = 0x%08lX",
                        static_cast<unsigned long long>(now - poll_start), polls,
                        static_cast<unsigned long>(import_state));
                    return false;
                }
                if (now - last_report >= 2000)
                {
                    last_report = now;
                    Trace::Note(L"Waiting For Import Resolution... %llu ms Elapsed | %u Polls",
                        static_cast<unsigned long long>(now - poll_start), polls);
                }
                Sleep(10);
                ++polls;
                import_state = runtime.get_import_state();
            }
            Trace::Note(L"Imports Ready In %llu ms (%u Polls) | State = 0x%08lX",
                static_cast<unsigned long long>(GetTickCount64() - poll_start), polls,
                static_cast<unsigned long>(import_state));
        }
        return import_state == INJ_ERR_SUCCESS;
    }

    bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > PE_IMAGE::MAX_IMAGE_SIZE)
        {
            CloseHandle(file);
            return false;
        }

        bytes.resize(static_cast<size_t>(size.QuadPart));
        size_t total = 0;
        while (total < bytes.size())
        {
            DWORD read = 0;
            const size_t remaining = bytes.size() - total;
            if (!ReadFile(file, bytes.data() + total, static_cast<DWORD>(remaining), &read, nullptr) || read == 0)
            {
                CloseHandle(file);
                bytes.clear();
                return false;
            }
            total += read;
        }

        CloseHandle(file);
        return true;
    }

    bool InspectDll(const std::wstring & path, DWORD flags, FileInformation & info, std::vector<BYTE> & bytes, std::wstring & sha256, DWORD * validation_out = nullptr)
    {
        bytes.clear();
        sha256.clear();
        if (!ReadFileBytes(path, bytes) || bytes.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, bytes.data(), sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        {
            return false;
        }

        const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
        if (nt_offset > bytes.size() || bytes.size() - nt_offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
        {
            return false;
        }

        DWORD signature = 0;
        std::memcpy(&signature, bytes.data() + nt_offset, sizeof(signature));
        if (signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        IMAGE_FILE_HEADER file_header{};
        std::memcpy(&file_header, bytes.data() + nt_offset + sizeof(DWORD), sizeof(file_header));
        const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (file_header.SizeOfOptionalHeader < sizeof(WORD) || optional_offset > bytes.size() || file_header.SizeOfOptionalHeader > bytes.size() - optional_offset)
        {
            return false;
        }

        WORD magic = 0;
        std::memcpy(&magic, bytes.data() + optional_offset, sizeof(magic));
        size_t directory_offset = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            info.architecture = file_header.Machine == IMAGE_FILE_MACHINE_I386 ? Architecture::X86 : Architecture::Unknown;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            info.architecture = file_header.Machine == IMAGE_FILE_MACHINE_AMD64 ? Architecture::X64 : Architecture::Unknown;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        }
        else
        {
            return false;
        }

        if (info.architecture == Architecture::Unknown || directory_offset + (static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) + 1) * sizeof(IMAGE_DATA_DIRECTORY) > file_header.SizeOfOptionalHeader)
        {
            return false;
        }

        DWORD directory_count = 0;
        const size_t count_offset = directory_offset - sizeof(DWORD);
        std::memcpy(&directory_count, bytes.data() + optional_offset + count_offset, sizeof(directory_count));
        info.dotnet = false;
        if (directory_count > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            IMAGE_DATA_DIRECTORY com_directory{};
            const size_t com_offset = directory_offset + static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) * sizeof(IMAGE_DATA_DIRECTORY);
            std::memcpy(&com_directory, bytes.data() + optional_offset + com_offset, sizeof(com_directory));
            info.dotnet = com_directory.VirtualAddress != 0 && com_directory.Size != 0;
        }

        if (info.architecture == Architecture::X64)
        {
            PE_IMAGE::OPTIONS options;
            options.RequireDll = true;
            options.RequireRelocations = true;
            options.ResolveImports = (flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
            options.ResolveDelayImports = (flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
            options.EnableExceptions = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
            options.InitializeSecurityCookie = (flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
            options.ExecuteTls = (flags & INJ_MM_EXECUTE_TLS) != 0;
            PE_IMAGE::VIEW view;
            const DWORD validation_result = PE_IMAGE::Validate(bytes.data(), bytes.size(), IMAGE_FILE_MACHINE_AMD64, options, view);
            if (validation_out)
            {
                *validation_out = validation_result;
            }
            if (validation_result != FILE_ERR_SUCCESS)
            {
                bytes.clear();
                return false;
            }
        }

        sha256 = Sha256Hex(bytes);
        if (sha256.empty())
        {
            bytes.clear();
            return false;
        }
        return true;
    }

    std::wstring NormalizeProcessName(std::wstring name)
    {
        const size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            name = name.substr(slash + 1);
        }
        if (name.find(L'.') == std::wstring::npos)
        {
            name += L".exe";
        }
        return name;
    }

    // Every process running under the given image name. The first name match
    // is not always the one that can be written to: several modern
    // applications run a helper under the same image name, and a helper that
    // has not published its loader list cannot be mapped into.
    std::vector<DWORD> FindProcesses(const std::wstring & requested_name)
    {
        std::vector<DWORD> found;
        const std::wstring name = NormalizeProcessName(requested_name);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return found;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
                {
                    found.push_back(entry.th32ProcessID);
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return found;
    }

    // The working set of a process, used only to tell a main instance apart
    // from the helpers that run beside it under the same image name.
    //
    // K32GetProcessMemoryInfo fails on a handle that carries only
    // PROCESS_QUERY_LIMITED_INFORMATION; it needs PROCESS_QUERY_INFORMATION
    // and PROCESS_VM_READ. The read right is asked for here and nowhere else,
    // and a process that refuses it simply reports a working set of zero
    // rather than being dropped from the candidate list.
    SIZE_T WorkingSetSize(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        if (!process)
        {
            return 0;
        }
        FileHandleGuard guard(process);

        PROCESS_MEMORY_COUNTERS counters{};
        counters.cb = sizeof(counters);
        if (!K32GetProcessMemoryInfo(process, &counters, sizeof(counters)))
        {
            return 0;
        }
        return static_cast<SIZE_T>(counters.WorkingSetSize);
    }

    // The process under the given image name that can actually be written to.
    // A candidate whose loader list has not been published is skipped, so the
    // launcher does not pick a helper process and fail later with a
    // confusing error. Among the candidates that qualify, the one with the
    // largest working set is taken, which is the main instance rather than
    // one of the helpers that run beside it.
    DWORD FindProcess(const std::wstring & requested_name)
    {
        const std::vector<DWORD> candidates = FindProcesses(requested_name);
        if (candidates.empty())
        {
            return 0;
        }

        DWORD best = 0;
        SIZE_T best_working_set = 0;
        for (DWORD pid : candidates)
        {
            ProcessIdentity identity{};
            if (!QueryProcessIdentity(pid, identity) || !identity.LoaderListAvailable())
            {
                continue;
            }
            const SIZE_T working_set = WorkingSetSize(pid);
            if (!best || working_set > best_working_set)
            {
                best = pid;
                best_working_set = working_set;
            }
        }

        if (best)
        {
            return best;
        }

        // No candidate could be shown to have a loader list. The first one is
        // returned anyway so the failure is the injection's own diagnostic and
        // not a silent "no such process": an unreadable PEB is not evidence
        // that the process cannot be written to.
        return candidates.front();
    }

    // Re-checks that the process the operator confirmed is still the process
    // that is about to be written to. A name-based target is resolved again
    // here, and a game that exits and is relaunched between the confirmation
    // and the load would otherwise be silently swapped for its replacement.
    bool RefreshTarget(TargetSelection & target)
    {
        if (target.by_name)
        {
            const DWORD pid = FindProcess(target.requested_name);
            if (!pid)
            {
                return false;
            }
            ProcessIdentity current{};
            if (!QueryProcessIdentity(pid, current))
            {
                return false;
            }
            if (target.identity.pid == 0)
            {
                target.identity = current;
            }
            else if (!target.identity.Matches(current))
            {
                LOG(0, L"  %ls[!]%ls The Target Was Replaced Between Confirmation And Load "
                        L"(PID %lu Is Not The Process That Was Confirmed); Refusing To Continue.\n",
                    kYellow, kReset, static_cast<unsigned long>(pid));
                return false;
            }
            else if (current.loader_list_state == LoaderListState::NotPublished)
            {
                LOG(0, L"  %ls[!]%ls The Target Has Not Published Its Loader List; "
                        L"There Is Nothing To Map Into.\n", kYellow, kReset);
                return false;
            }
            target.pid = pid;
            target.name = current.name;
            target.architecture = current.architecture;
            return true;
        }

        ProcessIdentity current{};
        if (!QueryProcessIdentity(target.pid, current))
        {
            return false;
        }
        if (target.identity.pid == 0)
        {
            // A target that was named by its process identifier rather than by
            // its image name has no earlier observation to compare against.
            // This one is taken now and is what a later refresh checks.
            target.identity = current;
        }
        else if (!target.identity.Matches(current))
        {
            LOG(0, L"  %ls[!]%ls The Target Was Replaced Between Confirmation And Load "
                    L"(PID %lu Is Not The Process That Was Confirmed); Refusing To Continue.\n",
                kYellow, kReset, static_cast<unsigned long>(target.pid));
            return false;
        }
        else if (current.loader_list_state == LoaderListState::NotPublished)
        {
            LOG(0, L"  %ls[!]%ls The Target Has Not Published Its Loader List; "
                    L"There Is Nothing To Map Into.\n", kYellow, kReset);
            return false;
        }
        target.name = current.name;
        target.architecture = current.architecture;
        return true;
    }

    bool SelectTarget(const std::wstring & configured_name, TargetSelection & target, bool & cancelled, int timeout_ms)
    {
        cancelled = false;
        if (configured_name.empty())
        {

            PrintError(XOR_STR_W(L"No Target Process Is Configured (ProcessName Is Empty).").get());
            return false;
        }
        target.requested_name = NormalizeProcessName(configured_name);
        target.by_name = true;
        HANDLE probeInput = GetStdHandle(STD_INPUT_HANDLE);
        DWORD probeMode = 0;
        const bool hasConsoleForWait = probeInput && probeInput != INVALID_HANDLE_VALUE &&
            GetConsoleMode(probeInput, &probeMode) != FALSE;
        if (hasConsoleForWait)
        {
            LOG(0, L"%ls[+]%ls Waiting For %ls... (Press Q To Quit)\n", kGreen, kReset, target.requested_name.c_str());
        }
        const ULONGLONG wait_timeout = timeout_ms > 0 ? static_cast<ULONGLONG>(timeout_ms) : 60000ULL;
        const ULONGLONG deadline = GetTickCount64() + wait_timeout;
        for (;;)
        {
            const DWORD found = FindProcess(target.requested_name);
            if (found)
            {
                ProcessIdentity identity{};
                if (QueryProcessIdentity(found, identity) && identity.LoaderListAvailable())
                {
                    target.pid = found;
                    target.name = identity.name;
                    target.architecture = identity.architecture;
                    target.identity = identity;
                    if (hasConsoleForWait)
                    {
                        LOG(0, L"%ls[+]%ls %ls Detected | PID = %ls%lu%ls\n", kGreen, kReset, target.name.c_str(), kGreen, static_cast<unsigned long>(found), kReset);
                    }
                    return true;
                }
            }

            if (!hasConsoleForWait)
            {
                if (GetTickCount64() >= deadline)
                {
                    wchar_t wait_message[512]{};
                    swprintf_s(wait_message, L"Timed Out After %lu ms Waiting For %ls To Start (Headless; No Console To Cancel With).",
                        static_cast<unsigned long>(wait_timeout), target.requested_name.c_str());
                    PrintError(wait_message);
                    return false;
                }
                Sleep(100);
                continue;
            }
            HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
            const DWORD input_wait = (input && input != INVALID_HANDLE_VALUE) ? WaitForSingleObject(input, 50) : WAIT_TIMEOUT;
            if (input_wait == WAIT_OBJECT_0)
            {
                DWORD console_mode = 0;
                if (GetConsoleMode(input, &console_mode))
                {
                    if (_kbhit())
                    {
                        const int key = _getch();
                        if (key == 'q' || key == 'Q')
                        {
                            cancelled = true;
                            return false;
                        }
                    }
                }
                else
                {
                    std::wstring line;
                    if (!std::getline(std::wcin, line))
                    {
                        cancelled = true;
                        return false;
                    }

                    line = TrimText(line);
                    if (line == L"q" || line == L"Q")
                    {
                        cancelled = true;
                        return false;
                    }
                }
            }
            if (std::wcin.eof())
            {
                cancelled = true;
                return false;
            }
            Sleep(50);
        }
    }

    const wchar_t * ArchitectureName(Architecture architecture)
    {
        switch (architecture)
        {
            case Architecture::X86:
                return L"x86";
            case Architecture::X64:
                return L"x64";
            default:
                return L"unknown";
        }
    }

    DWORD BuildFlags(const WizardConfig & config);

    bool ResolveConfiguredPayload(const std::wstring & dll_dir, const std::wstring & payload_name, const std::wstring & expected_sha256,
        DWORD flags, FileInformation & info, std::vector<BYTE> & bytes)
    {
        bytes.clear();

        const std::wstring directory = ExecutableDirectory();
        if (directory.empty() || payload_name.empty() || dll_dir.empty())
        {
            PrintError(L"The Payload Is Not Configured (The Deployment Payload Name Is Empty).");
            return false;
        }

        const std::wstring path = directory + dll_dir + L"\\" + payload_name;
        if (!FileExists(path))
        {
            PrintError((L"The Payload DLL (" + payload_name + L") Is Missing In " + dll_dir + L"\\ Next To The Executable.").c_str());
            return false;
        }

        DWORD validation_code = FILE_ERR_SUCCESS;
        std::wstring sha256;
        if (!InspectDll(path, flags, info, bytes, sha256, &validation_code))
        {
            if (validation_code != FILE_ERR_SUCCESS)
            {
                LOG(0,  L"%lsNot A Usable DLL (PE Validation 0x%08X). Need x64 DLL With Relocations, No .NET.%ls\n",
                    kYellow, validation_code, kReset);
            }
            else
            {
                PrintWarning(L"Not A Usable DLL.");
            }
            return false;
        }

        if (expected_sha256.empty())
        {
            PrintError(XOR_STR_W(L"The Payload Pin Is Missing (PayloadSha256 Is Empty); Refusing To Load Without A Pinned Digest.").get());
            return false;
        }
        if (_wcsicmp(expected_sha256.c_str(), sha256.c_str()) != 0)
        {
            LOG(0,  L"%lsPayload SHA-256 Mismatch. Expected %ls, Got %ls%ls\n", kRed, expected_sha256.c_str(), sha256.c_str(), kReset);
            return false;
        }

        if (info.dotnet)
        {
            PrintError(L".NET Assemblies Are Not Supported In This Memory-Loading Build.");
            return false;
        }
        if (info.architecture == Architecture::X86)
        {
            PrintError(L"x86 DLLs Are Not Supported In This x64-Only Build.");
            return false;
        }

        if (VerboseOutputEnabled()) { LOG(0, L"Verified SHA-256 = %ls%ls%ls\n", kGreen, sha256.c_str(), kReset); }
        return true;
    }

    void ReportPayloadCapabilities(const std::vector<BYTE> & payload, DWORD flags)
    {
        if (payload.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return;
        }

        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, payload.data(), sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        {
            return;
        }

        const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
        if (nt_offset > payload.size() || payload.size() - nt_offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
        {
            return;
        }

        IMAGE_FILE_HEADER file_header{};
        std::memcpy(&file_header, payload.data() + nt_offset + sizeof(DWORD), sizeof(file_header));

        const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            optional_offset > payload.size() ||
            file_header.SizeOfOptionalHeader > payload.size() - optional_offset)
        {
            return;
        }

        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, payload.data() + optional_offset, sizeof(optional));
        if (optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return;
        }

        auto directory_at = [&](DWORD index, IMAGE_DATA_DIRECTORY & out) -> bool
        {
            if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
            {
                return false;
            }

            const size_t offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + static_cast<size_t>(index) * sizeof(IMAGE_DATA_DIRECTORY);
            if (offset + sizeof(IMAGE_DATA_DIRECTORY) > file_header.SizeOfOptionalHeader)
            {
                return false;
            }

            std::memcpy(&out, payload.data() + optional_offset + offset, sizeof(out));

            return true;
        };

        IMAGE_DATA_DIRECTORY exports{};
        const bool has_exports = directory_at(IMAGE_DIRECTORY_ENTRY_EXPORT, exports) && exports.Size != 0;

        if (has_exports && (flags & INJ_MM_CLEAN_DATA_DIR) != 0)
        {
            LOG(0, L"  %ls[*]%ls CleanDataDirectories Is On; The Payload's Export Directory Is Erased During The Load.\n",
                kDim, kReset);
            LOG(0, L"      Anything That Resolves This Payload By Export Name Afterwards Will Fail.\n");
        }
    }

    void DescribeFlags(DWORD flags)
    {
        struct FlagBit { DWORD bit; const wchar_t * name; };
        static const FlagBit kBits[] =
        {
            { INJ_ERASE_HEADER,                L"INJ_ERASE_HEADER" },
            { INJ_HANDLE_HIJACKING,            L"INJ_HANDLE_HIJACKING" },
            { INJ_NO_DONOR_SCAN,               L"INJ_NO_DONOR_SCAN" },
            { INJ_SKIP_SPONSOR_ROUNDTRIP,      L"INJ_SKIP_SPONSOR_ROUNDTRIP" },
            { INJ_MM_CLEAN_DATA_DIR,           L"INJ_MM_CLEAN_DATA_DIR" },
            { INJ_MM_RESOLVE_IMPORTS,          L"INJ_MM_RESOLVE_IMPORTS" },
            { INJ_MM_RESOLVE_DELAY_IMPORTS,    L"INJ_MM_RESOLVE_DELAY_IMPORTS" },
            { INJ_MM_EXECUTE_TLS,              L"INJ_MM_EXECUTE_TLS" },
            { INJ_MM_ENABLE_EXCEPTIONS,        L"INJ_MM_ENABLE_EXCEPTIONS" },
            { INJ_MM_SET_PAGE_PROTECTIONS,     L"INJ_MM_SET_PAGE_PROTECTIONS" },
            { INJ_MM_INIT_SECURITY_COOKIE,     L"INJ_MM_INIT_SECURITY_COOKIE" },
            { INJ_MM_RUN_DLL_MAIN,             L"INJ_MM_RUN_DLL_MAIN" },
            { INJ_MM_RUN_UNDER_LDR_LOCK,       L"INJ_MM_RUN_UNDER_LDR_LOCK" },
            { INJ_MM_MAP_FROM_MEMORY,          L"INJ_MM_MAP_FROM_MEMORY" },
        };

        LOG(0, L"  %ls[*]%ls Decoded Load Flags = 0x%08lX\n", kDim, kReset, static_cast<unsigned long>(flags));
        for (const FlagBit & fb : kBits)
        {
            const bool set = (flags & fb.bit) != 0;
            LOG(0, L"      %ls%s%ls 0x%08X  %ls\n",
                set ? kGreen : kDim, set ? L"[x]" : L"[ ]", kReset,
                fb.bit, fb.name);
        }
        DWORD accounted = 0;
        for (const FlagBit & fb : kBits)
        {
            accounted |= fb.bit;
        }
        const DWORD unexplained = flags & ~accounted;
        if (unexplained)
        {
            LOG(0, L"      %ls[!]%ls 0x%08lX  Undecoded Bit(s)\n", kYellow, kReset, static_cast<unsigned long>(unexplained));
        }
    }
DWORD BuildFlags(const WizardConfig & config)
    {
        DWORD flags = 0;

        flags |= INJ_ERASE_HEADER;
        if (config.handle_hijacking)
        {
            flags |= INJ_HANDLE_HIJACKING;
            if (!config.hijack_scan)
            {
                flags |= INJ_NO_DONOR_SCAN;
            }

            if (!config.sponsor_roundtrip)
            {
                flags |= INJ_SKIP_SPONSOR_ROUNDTRIP;
            }
        }
        if (config.run_dllmain)
        {
            flags |= INJ_MM_RUN_DLL_MAIN;
        }
        if (config.page_protections)
        {
            flags |= INJ_MM_SET_PAGE_PROTECTIONS;
        }
        if (config.loader_lock)
        {
            flags |= INJ_MM_RUN_UNDER_LDR_LOCK;
        }
        if (config.exceptions)
        {
            flags |= INJ_MM_ENABLE_EXCEPTIONS;
        }
        if (config.resolve_imports)
        {
            flags |= INJ_MM_RESOLVE_IMPORTS;
        }
        if (config.security_cookie)
        {
            flags |= INJ_MM_INIT_SECURITY_COOKIE;
        }
        if (config.delay_imports)
        {
            flags |= INJ_MM_RESOLVE_DELAY_IMPORTS;
        }
        if (config.clean_data)
        {
            flags |= INJ_MM_CLEAN_DATA_DIR;
        }
        if (config.execute_tls)
        {
            flags |= INJ_MM_EXECUTE_TLS;
        }
        return flags;
    }

    void PauseBeforeExit()
    {

        if (!InterfaceConsolePresent())
        {
            return;
        }

        LOG(0, L"\nPress Enter To Exit...\n");
        fflush(stdout);

        std::wcin.clear();

        std::streamsize avail = std::wcin.rdbuf()->in_avail();
        if (avail > 0)
        {
            std::wcin.ignore(avail, L'\n');
        }

        clearerr(stdin);

        fflush(stdin);
        std::wcin.clear();

        HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (hInput != INVALID_HANDLE_VALUE && GetConsoleMode(hInput, &mode))
        {
            DWORD events = 0;
            if (GetNumberOfConsoleInputEvents(hInput, &events))
            {
                while (events > 0)
                {
                    INPUT_RECORD rec;
                    DWORD read = 0;
                    if (!ReadConsoleInputW(hInput, &rec, 1, &read) || read == 0)
                        break;
                    GetNumberOfConsoleInputEvents(hInput, &events);
                }
            }
        }

        std::wstring ignored;
        std::getline(std::wcin, ignored);
    }
    const wchar_t * DescribeNtStatus(DWORD status)
    {
        switch (status)
        {
        case 0xC0000001u: return L"UNSUCCESSFUL";
        case 0xC0000002u: return L"NOT_IMPLEMENTED";
        case 0xC0000005u: return L"ACCESS_VIOLATION";
        case 0xC0000006u: return L"IN_PAGE_ERROR";
        case 0xC0000008u: return L"INVALID_HANDLE";
        case 0xC000000Du: return L"INVALID_PARAMETER";
        case 0xC0000017u: return L"NO_MEMORY";
        case 0xC0000018u: return L"CONFLICTING_ADDRESSES";
        case 0xC0000022u: return L"ACCESS_DENIED";
        case 0xC0000023u: return L"BUFFER_TOO_SMALL";
        case 0xC0000033u: return L"OBJECT_NAME_INVALID";
        case 0xC0000035u: return L"OBJECT_NAME_COLLISION";
        case 0xC0000043u: return L"SHARING_VIOLATION";
        case 0xC000006Du: return L"LOGON_FAILURE";
        case 0xC000007Fu: return L"DISK_FULL";
        case 0xC00000A0u: return L"MEMORY_NOT_ALLOCATED";
        case 0xC00000E5u: return L"INTERNAL_ERROR";
        case 0xC00000FDu: return L"STACK_OVERFLOW";
        case 0xC0000135u: return L"DLL_NOT_FOUND";
        case 0xC0000138u: return L"ORDINAL_NOT_FOUND";
        case 0xC0000139u: return L"ENTRYPOINT_NOT_FOUND";
        case 0xC000013Au: return L"CONTROL_C_EXIT";
        case 0xC0000142u: return L"DLL_INIT_FAILED";
        case 0xC000014Au: return L"ILLEGAL_FLOAT_CONTEXT";
        case 0xC000014Bu: return L"PIPE_BROKEN";
        case 0xC0000194u: return L"POSSIBLE_DEADLOCK";
        case 0xC00001A5u: return L"INVALID_EXCEPTION_HANDLER";
        case 0xC0000203u: return L"USER_SESSION_DELETED";
        case 0xC0000205u: return L"INSUFF_SERVER_RESOURCES";
        case 0xC0000206u: return L"INVALID_BUFFER_SIZE";
        case 0xC0000225u: return L"NOT_FOUND";
        case 0xC0000235u: return L"HANDLE_NOT_CLOSABLE";
        case 0xC000026Bu: return L"DLL_INIT_FAILED_LOGOFF";
        case 0xC000026Du: return L"DFS_UNAVAILABLE";
        case 0xC0000374u: return L"HEAP_CORRUPTION";
        case 0xC0000409u: return L"STACK_BUFFER_OVERRUN (__fastfail: cookie or GS failure)";
        case 0xC000040Au: return L"NO_S4U_PROT_SUPPORT";
        case 0xC000040Bu: return L"CROSSREALM_DELEGATION_FAILURE";
        case 0xC000041Du: return L"FATAL_USER_CALLBACK_EXCEPTION";
        case 0xC0000481u: return L"APISET_NOT_HOSTED";
        case 0xC0000482u: return L"APISET_NOT_PRESENT";
        case 0x40000015u: return L"FATAL_APP_EXIT";
        default: return L"Unknown";
        }
    }

    void PrintFailureHint(DWORD code)
    {
        if (code == INJ_ERR_OUT_OF_MEMORY_EXT)
        {
            LOG(0, L"Reason: VirtualAllocEx Failed In Target (Adv 5 = ACCESS_DENIED, 998/3E6 = NOACCESS).\n");
            LOG(0, L"Target Is Likely Protected Or Blocks Remote RW/RX Allocations.\n");
            LOG(0, L"Staging Uses RW->RX (No RWX At Birth); Image Uses RW->RX.\n");
            LOG(0, L"Try Testing On notepad.exe.\n");
        }
        else if (code == INJ_ERR_CANT_OPEN_PROCESS)
        {
            LOG(0, L"Reason: OpenProcess Denied. Run Elevated.\n");
        }
        else if (code == INJ_MM_ERR_DLLMAIN_FAILED)
        {
            LOG(0, L"Reason: The Mapping, Imports, TLS And Loader-Lock Stages All Succeeded; The Payload's\n");
            LOG(0, L"Own DllMain(DLL_PROCESS_ATTACH) Returned False, I.e. The Payload Refused To Initialize.\n");
            LOG(0, L"This Is State/Thread Dependent, Not A Mapping Fault. Load Earlier In The Target's Startup:\n");
            LOG(0, L"Relaunch The Game And Load Once The Launcher Reports Its Symbol Download Is Complete.\n");
            LOG(0, L"A Failed Attempt Also Leaves Loader Bookkeeping In The Target That Cannot Be Reclaimed\n");
            LOG(0, L"(Inverted-Table Entry, TLS Index/Block Have No Removal API And Point Into The Freed\n");
            LOG(0, L"Image), So Relaunch The Game Before Trying Again.\n");
        }
        else if (code == INJ_MM_ERR_TLS_CALLBACK_RANGE)
        {
            LOG(0, L"Reason: A Payload TLS Callback Pointer/Array Fell Outside The Mapped Image,\n");
            LOG(0, L"So Only A Prefix Of Its Callbacks Ran. This Is Payload-Specific, Not A Mapping\n");
            LOG(0, L"Fault. Relaunch The Target Before Trying Another Payload.\n");
        }
        else if (code == INJ_ERR_HANDLE_HIJACK_FAILED)
        {
            LOG(0, L"Reason: Handle Acquisition Found No Donor; The Path Is Donor-Only And Fails Closed.\n");
            LOG(0, XOR_STR_W(L"Check The Handle-Acquisition Settings In The Deployed Configuration, Or Run Elevated So The\n").get());
            LOG(0, L"Sponsor Pre-Open Succeeds.\n");
        }
        else if (code == SR_HT_ERR_OPEN_REFUSED)
        {
            LOG(0, L"Reason: Thread Handle Acquisition Found No Donor; The Path Is Donor-Only And\n");
            LOG(0, L"Fails Closed (There Is No Direct OpenThread Fallback). Run Elevated So The Sponsor\n");
            LOG(0, L"Thread Pre-Open Succeeds, Or Retry While The Target Is Active.\n");
        }
        else if (code == SR_HT_ERR_NO_THREADS)
        {
            LOG(0, L"Reason: No Usable Donor Thread Found. Retry While The Target Is Active.\n");
        }
        else if (code == SR_ERR_TARGET_EXITED)
        {
            LOG(0, L"Reason: The Target Process Exited During Loading.\n");
        }
        else if (code == SR_HT_ERR_REMOTE_PENDING_TIMEOUT)
        {
            LOG(0, L"Note: The Payload Timed Out, But The Thread Context Was Restored Automatically.\n");
            LOG(0, L"Reason: The Victim Thread Never Scheduled The Donor Stub (State Stayed Pending),\n");
            LOG(0, L"So The Memory-Loading Shell Never Started. This Is Thread Selection, Not A Verification Issue:\n");
            LOG(0, XOR_STR_W(L"CleanDataDirectories Is Unrelated - Keep It Enabled.\n").get());
            LOG(0, L"The Runtime Now Retries: Each Donor Gets A Short Startup Probe, An Unscheduled\n");
            LOG(0, L"Thread Is Rolled Back And Excluded, And The Next Candidate Is Tried Inside The\n");
            LOG(0, L"Same Timeout Budget. Raising The Timeout Widens How Many Donors Get Probed.\n");
        }
        else if (code == INJ_ERR_WINDOWS_VERSION)
        {
            LOG(0, L"Reason: The OS Version Gate Could Not Identify The Windows Release.\n");
            LOG(0, L"The Runtime Requires Windows 11 (Build 22000+); This Is An Environment\n");
            LOG(0, L"Issue, Not A Mapping Or Symbol Failure.\n");
        }
        else if (code == INJ_ERR_WINDOWS_BUILD_UNSUPPORTED)
        {
            LOG(0, L"Reason: The OS Gate Rejected The Host - Windows 11 (Build 22000+) Is Required\n");
            LOG(0, L"And This Build Is Outside The Supported Families (21H2 22000+, 22H2/23H2 22621+,\n");
            LOG(0, L"24H2 26100+, 25H2 26200+, 26H2 26300-26999; Builds Above The Ceiling Are Refused).\n");
            LOG(0, L"This Is An Environment Issue, Not A Mapping Or Symbol Failure. Update Windows.\n");
        }
        else if (code == INJ_ERR_GET_MODULE_HANDLE_FAIL)
        {
            LOG(0, L"Reason: The Runtime Could Not Locate Its Own Image In The Target While Resolving\n");
            LOG(0, L"The Remote ntdll Base. The Handoff Succeeded, But The Module List The Runtime\n");
            LOG(0, L"Walked Was Not The One It Was Loaded Into.\n");
        }
        else if (code == INJ_ERR_NTDLL_LAYOUT_MISMATCH)
        {
            LOG(0, L"Reason: The Target's ntdll Base Does Not Match The Host's, So The Hardcoded Syscall\n");
            LOG(0, L"Stubs Cannot Be Reused There. This Is Version Skew Between The Launcher's ntdll And\n");
            LOG(0, L"The Target's, Or A Loader That Relocated It; Rebuilding Against The Matching Windows\n");
            LOG(0, L"Build Restores The Assumption. The Path Fails Closed Rather Than Guessing.\n");
        }
        else
        {

            LOG(0, L"Reason: Unclassified Failure 0x%08lX; See The Runtime Error Header.\n",
                static_cast<unsigned long>(code));
        }
    }

    void PrintRuntimeFailure(DWORD symbol_state, DWORD import_state, DWORD init_state)
    {

        if (init_state == INJ_ERR_WINDOWS_BUILD_UNSUPPORTED || init_state == INJ_ERR_WINDOWS_VERSION)
        {
            DWORD local_build = 0;
            {
                auto ntdll_name = XOR_STR_W(L"ntdll.dll");
                HMODULE ntdll = GetModuleHandleW(ntdll_name.get());
                if (ntdll)
                {
                    struct RtlOsVersionInfo
                    {
                        ULONG dwOSVersionInfoSize;
                        ULONG dwMajorVersion;
                        ULONG dwMinorVersion;
                        ULONG dwBuildNumber;
                        ULONG dwPlatformId;
                        WCHAR szCSDVersion[128];
                    };
                    using RtlGetVersionFn = LONG(__stdcall *)(RtlOsVersionInfo *);
                    auto api_name = XOR_STR_A("RtlGetVersion");
                    auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
                        GetProcAddress(ntdll, api_name.get()));
                    if (rtl_get_version)
                    {
                        RtlOsVersionInfo info{};
                        info.dwOSVersionInfoSize = sizeof(info);
                        if (rtl_get_version(&info) == 0)
                        {
                            local_build = info.dwBuildNumber;
                        }
                    }
                }
            }
            if (local_build)
            {
                LOG(0,  L"%lsUnsupported Windows Build: Local Build %lu (Code 0x%08X).%ls\n",
                    kRed, static_cast<unsigned long>(local_build), init_state, kReset);
            }
            else
            {
                LOG(0,  L"%lsUnsupported Windows Version (Code 0x%08X).%ls\n",
                    kRed, init_state, kReset);
            }
            PrintError(L"Supported: Windows 11 21H2 (22000), 22H2/23H2 (22621-22631), 24H2 (26100+), 25H2 (26200+), 26H2 (26300-26999).");
            PrintError(L"Builds Above 26999 Have No Validated Loader Layout And Are Refused.");
            PrintError(L"Windows 10 And Older Builds Are Not Supported By This x64/Win11-Only Build.");
            PrintError(L"Failed To Initialize The Runtime (OS Gate, Not A Symbol Download Failure).");
            return;
        }
        if (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
        {
            PrintError(L"Timeout Waiting For Symbol Initialization (120s).");
            PrintError(L"Check Internet Access And Windows Symbol Server Reachability.");
        }
        else if (symbol_state != INJ_ERR_SUCCESS)
        {
            if (init_state != INJ_ERR_SUCCESS)
            {

                LOG(0,  L"%lsFailed To Initialize The Runtime = 0x%08X%ls\n", kRed, init_state, kReset);
            }
            else
            {
                LOG(0,  L"%lsFailed To Load Symbols = 0x%08X%ls\n", kRed, symbol_state, kReset);
            }
        }
        else if (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
        {
            PrintError(L"Timeout Waiting For Import Resolution (120s).");
        }
        else if (import_state != INJ_ERR_SUCCESS)
        {
            LOG(0,  L"%lsFailed To Resolve Imports = 0x%08X%ls\n", kRed, import_state, kReset);
        }
        PrintError(L"Failed To Initialize The Runtime Or Download Symbols.");
    }

    bool InjectionFailureIsRetryable(DWORD result)
    {
        if (result >= 0x00400000u && result < 0x00500000u)
        {
            return false;
        }

        if (result >= 0x10200000u && result < 0x10300000u)
        {
            return false;
        }

        switch (result)
        {
        case INJ_ERR_FAILED_TO_LOAD_DLL:
        case INJ_ERR_VERIFY_RESULT_FAIL:
            return false;

        default:
            break;
        }

        return true;
    }

    // The window that is being hidden, and the process that owns it.
    struct HideWindowContext
    {
        DWORD pid = 0;
    };

    BOOL CALLBACK HideWindowCallback(HWND hwnd, LPARAM param)
    {
        const HideWindowContext * ctx = ReCa<const HideWindowContext *>(param);
        DWORD owner = 0;
        GetWindowThreadProcessId(hwnd, &owner);
        if (owner != ctx->pid)
        {
            return TRUE;
        }
        ShowWindow(hwnd, SW_HIDE);
        return TRUE;
    }

    // Hides the top level windows of a process.
    //
    // Starting the scratch target hidden is not enough on its own: several
    // modern images start a broker that hands off to the real instance, and
    // the real instance puts its own window up. The window belongs to the
    // process that was actually selected, so that is the one that is hidden.
    void HideProcessWindows(DWORD pid)
    {
        if (!pid)
        {
            return;
        }
        HideWindowContext context;
        context.pid = pid;
        EnumWindows(&HideWindowCallback, reinterpret_cast<LPARAM>(&context));
    }

    // A scratch target that test mode started itself. It is closed when the
    // run ends.
    //
    // Several modern images start a broker that hands off to the real
    // instance and then exits, so the process that was started is often not
    // the process that survives. The guard therefore records every instance
    // of the image that existed before the start, and closes every instance
    // that appeared after it. An instance the operator already had running is
    // never touched, and nothing is left behind either way.
    class ScratchTargetGuard
    {
        std::vector<DWORD> m_Preexisting;
        HANDLE m_Process = nullptr;
        std::wstring m_ImageName;
        bool m_Owns = false;

    public:
        ~ScratchTargetGuard()
        {
            if (!m_Owns)
            {
                return;
            }

            if (m_Process)
            {
                TerminateProcess(m_Process, 0);
                WaitForSingleObject(m_Process, 5000);
                CloseHandle(m_Process);
                m_Process = nullptr;
            }

            // The family is collected again here rather than at the start.
            // Several modern images start a broker that hands off to the real
            // instance afterwards, so the set of processes that belongs to this
            // run is only known once the run is over.
            for (DWORD pid : FindProcesses(m_ImageName))
            {
                if (std::find(m_Preexisting.begin(), m_Preexisting.end(), pid) != m_Preexisting.end())
                {
                    continue;
                }
                HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (!process)
                {
                    continue;
                }
                FileHandleGuard guard(process);
                TerminateProcess(process, 0);
            }
        }

        ScratchTargetGuard() = default;
        ScratchTargetGuard(const ScratchTargetGuard &) = delete;
        ScratchTargetGuard & operator=(const ScratchTargetGuard &) = delete;

        // Starts the image when no instance of it is running. Returns false
        // when one was already there, or when it could not be started.
        bool StartIfAbsent(const std::wstring & image_name, DWORD & pid_out)
        {
            pid_out = 0;
            if (image_name.empty())
            {
                return false;
            }

            m_Preexisting = FindProcesses(image_name);
            if (!m_Preexisting.empty())
            {
                // The operator already had one open. It is not ours to close.
                return false;
            }

            const std::wstring file = image_name.find(L'.') == std::wstring::npos
                ? image_name + L".exe"
                : image_name;

            // The image is resolved through the search path rather than
            // handed to CreateProcess as a bare name, so the process that
            // starts is the one the operator would have started.
            wchar_t resolved[MAX_PATH * 2]{};
            const DWORD found = SearchPathW(nullptr, file.c_str(), nullptr,
                static_cast<DWORD>(std::size(resolved)), resolved, nullptr);
            if (!found)
            {
                return false;
            }

            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            // The scratch target is started hidden. A test run is not
            // something that should put a window on the operator's desktop.
            // Hiding the window does not affect the target's loader list.
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;

            // The scratch target is started in the temporary directory rather
            // than in the launcher's own working directory. A process holds
            // its working directory open, so a target that inherited the
            // launcher's directory would keep that directory pinned for as
            // long as it lived, and a build that has to write into that
            // directory could not.
            wchar_t scratch_directory[MAX_PATH]{};
            const DWORD scratch_length = GetTempPathW(MAX_PATH, scratch_directory);
            const wchar_t * working_directory = nullptr;
            if (scratch_length && scratch_length < MAX_PATH)
            {
                working_directory = scratch_directory;
            }

            PROCESS_INFORMATION info{};
            // The process is started detached and without a console of its
            // own. A console of its own leaves the target's loader data
            // unpublished, which makes it impossible to map into.
            if (!CreateProcessW(resolved, nullptr, nullptr, nullptr, FALSE,
                DETACHED_PROCESS, nullptr, working_directory, &startup, &info))
            {
                return false;
            }

            CloseHandle(info.hThread);
            m_Process = info.hProcess;
            m_ImageName = file;
            m_Owns = true;
            pid_out = info.dwProcessId;

            // The image is given time to settle before the target is chosen.
            // Several modern images start a broker that hands off to the real
            // instance and then exits, and a target picked while the broker
            // is still leaving is a target that is about to be gone.
            {
                std::vector<DWORD> previous;
                for (int attempt = 0; attempt < 40; ++attempt)
                {
                    const std::vector<DWORD> current = FindProcesses(file);
                    if (current == previous)
                    {
                        break;
                    }
                    previous = current;
                    Sleep(100);
                }
            }

            return true;
        }
    };

    int RunInteractiveWizard(Runtime & runtime)
    {
        LOG(0, L"[Attempt %d/%d]\n\n", GetRetryIndex() + 1, kMaxLaunchAttempts);

        WizardConfig config;
        std::wstring config_path;
        bool config_invalid = false;
        Trace::BeginSession();

        Trace::Begin(L"Load + Decrypt Configuration");
        const bool config_loaded = LoadWizardConfig(config, config_path, config_invalid);
        if (!config_path.empty())
        {
            Trace::Note(L"Config Path = %ls", config_path.c_str());
        }
        if (config_loaded)
        {
            Trace::Note(L"Schema = %d | Target = %ls | Timeout = %d ms", config.schema_version,
                config.target_name.c_str(), config.timeout);
            Trace::Note(L"Payload = %ls | Runtime = %ls | Dll Dir = %ls", config.payload_name.c_str(),
                config.runtime_name.c_str(), config.dll_dir.c_str());
            Trace::Note(L"Payload Pin = %ls", config.expected_payload_sha256.c_str());
            Trace::Note(L"Export Map = %zu Entries", config.export_map.size());
            for (const ExportNameMap & e : config.export_map)
            {
                const std::wstring old_w = Trace::Widen(e.old_name.c_str());
                const std::wstring new_w = Trace::Widen(e.new_name.c_str());
                Trace::Note(L"  %ls -> %ls", old_w.c_str(), new_w.c_str());
            }
        }
        Trace::End();
        if (config_invalid || !config_loaded)
        {
            if (config_path.empty())
            {
                PrintError(XOR_STR_W(L"The Deployed Configuration Is Required But Was Not Found. Place It Next To The Executable.").get());
            }
            else
            {
                PrintError(XOR_STR_W(L"The Deployed Configuration Is Invalid; Fix The Schema, Target Or Per-Build Deployment Keys, Or Restore The File.").get());
            }
            Trace::Summary(L"Failed At Configuration");
            PauseBeforeExit();
            return 1;
        }

        Trace::Begin(L"Load Runtime DLL + Resolve Exports");
        if (!LoadRuntime(runtime, config))
        {
            Trace::End();
            Trace::Summary(L"Failed At Runtime Load");
            PauseBeforeExit();
            return 1;
        }
        Trace::Note(L"Module Base = %p", reinterpret_cast<void *>(runtime.module));
        Trace::Note(L"Execution = %ls", L"ThreadDonor");
        Trace::Note(L"Mode = %ls", L"MemoryLoading");
        Trace::End();

        Trace::Begin(L"Decode Load Flags");
        const DWORD preflight_flags = BuildFlags(config);
        DescribeFlags(preflight_flags);
        Trace::End();

        Trace::Begin(L"Resolve + Hash Payload");
        std::vector<BYTE> raw_data;
        FileInformation fileInformation;
        if (!ResolveConfiguredPayload(config.dll_dir, config.payload_name, config.expected_payload_sha256,
            preflight_flags, fileInformation, raw_data))
        {
            Trace::End();
            Trace::Summary(L"Failed At Payload Resolution");
            PauseBeforeExit();
            return 1;
        }
        // The payload bytes live in this process's heap for as long as the
        // attempt lasts. They are wiped on the way out, whatever the outcome,
        // so a copy of the payload is not left behind in the launcher's
        // memory.
        auto payload_scrub = MakeScopeExit([&raw_data]() noexcept
        {
            if (!raw_data.empty())
            {
                SecureZeroMemory(raw_data.data(), raw_data.size());
                std::vector<BYTE>().swap(raw_data);
            }
        });
        Trace::Note(L"Payload Size = %zu Bytes", raw_data.size());
        Trace::Note(L"Architecture = %ls", ArchitectureName(fileInformation.architecture));
        Trace::Note(L"Managed (.NET) = %ls", fileInformation.dotnet ? L"Yes" : L"No");
        Trace::End();

        ReportPayloadCapabilities(raw_data, preflight_flags);

        Trace::Begin(L"Runtime Init: Symbols + Imports");
        Trace::Note(L"Resolving Windows Symbols + Import Descriptors");
        DWORD symbol_state = INJ_ERR_SYMBOL_INIT_NOT_DONE;
        DWORD import_state = INJ_ERR_IMPORT_HANDLER_NOT_DONE;
        DWORD init_state = INJ_ERR_SUCCESS;
        if (!WaitForRuntime(runtime, symbol_state, import_state, init_state))
        {
            Trace::End();
            PrintRuntimeFailure(symbol_state, import_state, init_state);
            Trace::Summary(L"Failed At Runtime Initialisation");
            PauseBeforeExit();
            return kResultRetryable;
        }
        Trace::Note(L"Symbol State = 0x%08lX", static_cast<unsigned long>(symbol_state));
        Trace::Note(L"Import State = 0x%08lX", static_cast<unsigned long>(import_state));
        Trace::End();

        if (config.test_mode)
        {
            // Test mode changes what the tool is pointed at and makes the run
            // reliable against a scratch target. It does not change how much
            // the tool reports: the verbosity and the console are the
            // operator's settings, and a test that cannot be read is not a
            // test.
            config.target_name = config.test_target.empty() ? L"notepad.exe" : config.test_target;

            // The donor scan is the part that cannot be relied on against a
            // scratch target, so the direct handle is allowed when the scan
            // finds nothing.
            SetEnvironmentVariableW(L"INJ_ALLOW_DIRECT_FALLBACK", L"1");

            Trace::Begin(L"Test Mode");
            Trace::Note(L"The Target Is Forced To %ls", config.target_name.c_str());
            Trace::Note(L"The Donor Scan May Fall Back To A Direct Handle");
            Trace::Note(L"The Report Is Written To %ls", g_ResultLogName.c_str());
            Trace::End();

            LOG(0, L"%ls[*]%ls TEST MODE - The Target Is %ls, Not The Configured Process.\n",
                kYellow, kReset, config.target_name.c_str());
        }

        // The runtime runs inside this process, so a value published here is
        // what it sees. The block list cannot come from the environment the
        // launcher was started in, because the launcher runs elevated and an
        // elevated process does not inherit its parent's environment.
        if (!config.donor_owner_blocklist.empty())
        {
            SetEnvironmentVariableW(L"AMEGER_DONOR_OWNER_BLOCKLIST",
                config.donor_owner_blocklist.c_str());
        }
        g_DiscardResultLogOnSuccess = config.discard_result_log_on_success;
        g_TestMode = config.test_mode;
        g_AutoConfirm = config.auto_confirm;
        if (config.test_mode)
        {
            // A test run's transcript is the whole point of the run, so it is
            // never removed, and a test run does not stop to ask the operator
            // whether it may begin.
            g_DiscardResultLogOnSuccess = false;
            g_AutoConfirm = true;
        }

        // The scratch target is owned by this guard, so it is closed when the
        // wizard returns.
        ScratchTargetGuard scratch_target;

        // The transcript is current from the moment it is opened, so by the
        // time the wizard finishes it only has to be flushed. It stays open
        // for anything that is printed after this point, either by this
        // function as it unwinds or by the fault handler.
        auto transcript_guard = MakeScopeExit([&]() noexcept
        {
            ameger_ui_log::FlushResultLog();
        });

        Trace::Begin(L"Operator Confirmation");
        // The confirmation itself decides whether it is needed. A test run
        // never waits for an answer, because there is nobody to answer it.
        const ConfirmationResult confirmation = ConfirmBeforeDetection();
        if (confirmation == ConfirmationResult::Cancelled)
        {
            Trace::End();
            LOG(0, L"Cancelled.\n");
            Trace::Summary(L"Cancelled By Operator");
            return 0;
        }
        if (confirmation == ConfirmationResult::Unavailable)
        {
            Trace::End();
            Trace::Summary(L"Failed At Operator Confirmation");
            return 1;
        }
        Trace::End();

        Trace::Begin(L"Select Target Process");
        TargetSelection target;
        bool cancelled = false;
        if (config.test_mode)
        {
            // A scratch target is started here when the operator has none
            // open, so the run does not sit waiting for one to appear.
            DWORD scratch_pid = 0;
            if (scratch_target.StartIfAbsent(config.target_name, scratch_pid))
            {
                Trace::Note(L"A Scratch %ls Was Started (PID %lu); It And Any Instance That Came With It Are Closed When The Run Ends",
                    config.target_name.c_str(), static_cast<unsigned long>(scratch_pid));
            }
            else
            {
                Trace::Note(L"An Existing %ls Was Left Running By The Operator", config.target_name.c_str());
            }
        }
        if (!SelectTarget(config.target_name, target, cancelled, config.timeout))
        {
            Trace::End();
            if (cancelled)
            {
                LOG(0, L"Cancelled.\n");
                Trace::Summary(L"Cancelled By Operator");
                return 0;
            }
            Trace::Summary(L"Failed At Target Selection");
            return 2;
        }
        Trace::Note(L"PID = %lu", target.pid);
        Trace::Note(L"Name = %ls", target.name.c_str());
        Trace::Note(L"Architecture = %ls", ArchitectureName(target.architecture));
        Trace::End();

        if (config.test_mode)
        {
            // A test run puts no window on the operator's desktop. The window
            // belongs to the process that was actually selected, which is not
            // necessarily the one that was started.
            HideProcessWindows(target.pid);
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 Targets Are Not Supported In This x64-Only Build.");
            PauseBeforeExit();
            return 1;
        }

        if (target.architecture != Architecture::Unknown &&
            fileInformation.architecture != target.architecture)
        {
            LOG(0, L"Warning: DLL Is %ls But Target Is %ls.\n",
                ArchitectureName(fileInformation.architecture),
                ArchitectureName(target.architecture));
            bool proceed = false;
            if (!ReadYesNo(L"Continue Anyway?", false, proceed) || !proceed)
            {
                LOG(0, L"Cancelled.\n");
                return 0;
            }
        }

        const int timeout_value = config.timeout;

        LOG(0, L"\n");

        if (config.detach_console)
        {
            LOG(0, L"%ls[+]%ls Detaching Console; Running Headless From Here.\n", kGreen, kReset);
            fflush(stdout);
            DetachInterfaceConsole();
        }

        if (!RefreshTarget(target))
        {
            PrintError(L"The Target Is No Longer The Process That Was Confirmed (It Exited, Or It Was Replaced). "
                        L"Re-Run And Choose Faster.");
            PauseBeforeExit();
            return kResultRetryable;
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 Targets Are Not Supported In This x64-Only Build.");
            PauseBeforeExit();
            return 1;
        }

        HijackContext Context{};
        Context.TargetPid = target.pid;
        Context.TargetName = target.name;
        Context.Verbose = config.verbose_trace && !config.quiet;

        HANDLE threadSponsorRaw = nullptr;
        if (config.handle_hijacking)
        {
            Context.SponsorThreadAttempted = true;
            DWORD thread_sponsor_err = ERROR_SUCCESS;
            DWORD failed_sponsor_tid = 0;
            for (int attempt = 0; attempt < 8 && !threadSponsorRaw; ++attempt)
            {
                if (attempt > 0)
                {
                    Sleep(20);
                }

                const DWORD victim_tid = PickHijackThreadTid(target.pid, failed_sponsor_tid);
                if (!victim_tid)
                {

                    thread_sponsor_err = ERROR_NOT_FOUND;
                    continue;
                }

                threadSponsorRaw = OpenThread(INJ_THREAD_HIJACK_ACCESS,
                    FALSE, victim_tid);
                if (!threadSponsorRaw)
                {
                    thread_sponsor_err = GetLastError();
                    failed_sponsor_tid = victim_tid;
                }
            }

            if (threadSponsorRaw)
            {
                Context.SponsorThreadOpened = true;
                Context.SponsorThreadValue = ReCa<ULONG_PTR>(threadSponsorRaw);
                Context.SponsorTid = GetThreadId(threadSponsorRaw);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Thread Sponsor Pre-Open Failed (0x%08X); Runtime Will Search.\n",
                    kYellow, kReset, thread_sponsor_err);
            }
        }
        FileHandleGuard threadSponsorGuard(threadSponsorRaw);

        Trace::Begin(L"Pre-Open Donor Handles (Sponsor)");
        Trace::Note(L"Process Sponsor Handle = Not Obtained (Runtime Acquisition Only)");
        if (threadSponsorRaw)
        {
            Trace::Note(L"Thread Sponsor Handle = 0x%08X (TID 0x%04lX)",
                static_cast<unsigned>(ReCa<ULONG_PTR>(threadSponsorRaw)),
                static_cast<unsigned long>(Context.SponsorTid));
        }
        else
        {
            Trace::Note(L"Thread Sponsor Handle = Not Obtained (Runtime Will Search)");
        }
        Trace::End();

        HANDLE targetHandle = nullptr;
        {
            // The debug-port probes in the verification suite need the broader
            // query right; the limited right stays as the fallback for targets
            // that refuse PROCESS_QUERY_INFORMATION.
            targetHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
            if (!targetHandle)
            {
                targetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
            }
        }
        FileHandleGuard targetHandleGuard(targetHandle);
        if (!targetHandle)
        {
            LOG(0, L"  %ls[!]%ls Could Not Open The Target For Read-Only Verification (0x%08X).\n",
                kYellow, kReset, GetLastError());
        }

        const DWORD flags = BuildFlags(config);

        MemoryInjectionData data{};
        data.RawData = raw_data.data();
        data.RawSize = static_cast<DWORD>(raw_data.size());
        data.ProcessID = target.pid;
        data.Flags = flags;
        data.Timeout = static_cast<DWORD>(timeout_value);
        data.GenerateErrorLog = true;

        data.hHandleValue = 0;
        data.TargetTid = Context.SponsorTid;
        data.hThreadHandleValue = threadSponsorRaw ? ReCa<ULONG_PTR>(threadSponsorRaw) : 0;
        data.DllPath = config.payload_name.c_str();

        LOG(0, L"\n");

        if (data.TargetTid)
        {
            LOG(0, L"Requested Sponsor TID %ls0x%04lX%s | Timeout %ls%lu ms%s (Runtime May Reject It; Hijacked Thread Reported On Completion)...\n",
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }
        else
        {
            LOG(0, L"Working (Runtime Thread Search, Timeout %ls%lu ms%s)...\n",
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }

        Trace::Begin(L"Memory Injection (Manual Map + Thread Hijack)");
        Trace::Note(L"Target PID = %lu", static_cast<unsigned long>(data.ProcessID));
        Trace::Note(L"Payload Bytes = %lu", static_cast<unsigned long>(data.RawSize));
        Trace::Note(L"Flags = 0x%08lX", static_cast<unsigned long>(data.Flags));
        Trace::Note(L"Timeout = %lu ms", static_cast<unsigned long>(data.Timeout));
        Trace::Note(L"Sponsor Proc = 0x%08X", static_cast<unsigned>(data.hHandleValue));
        Trace::Note(L"Sponsor TID = 0x%08X (Handle 0x%08X)",
            static_cast<unsigned>(data.TargetTid),
            static_cast<unsigned>(data.hThreadHandleValue));

        const ULONGLONG inject_begin_ms = GetTickCount64();

        if (runtime.clear_last_error_info)
        {
            runtime.clear_last_error_info();
            Trace::Note(L"Diagnostic Ring Cleared");
        }

        const DWORD result = runtime.memory_inject(reinterpret_cast<MEMORY_INJECTIONDATA *>(&data));
        const ULONGLONG inject_window_ms = GetTickCount64() - inject_begin_ms;

        Trace::Note(L"Return Value = 0x%08lX | Elapsed = %llu ms", static_cast<unsigned long>(result),
            static_cast<unsigned long long>(inject_window_ms));
        Trace::End();

        if (result != INJ_ERR_SUCCESS)
        {
            LOG(0, L"%ls[x]%ls Operation Failed With Code %08X%ls\n", kRed, kReset, result);
            if (config.test_mode)
            {
                LOG(0, L"%ls[x]%ls TEST MODE - This Was A Test Run Against A Scratch Target, Not The Configured Process.%ls\n",
                    kYellow, kReset, kReset);
            }
            PrintFailureHint(result);

            if (runtime.get_last_error_info)
            {
                LAST_ERROR_INFO detail{};
                const DWORD detail_status = runtime.get_last_error_info(&detail);

                if (detail_status == INJ_ERR_NO_LAST_ERROR)
                {
                    LOG(0, L"  Runtime Recorded No Diagnostic Detail For This Attempt.\n");
                }
                else if (detail_status == INJ_ERR_SUCCESS)
                {
                    LOG(0, L"  Runtime Detail: Adv = %08X | Line = %d | Native = %d\n",
                        detail.AdvErrorCode, detail.Line, detail.bNative);
                    if (detail.DllFileName[0])
                    {
                        LOG(0, L"  Payload: %ls\n", detail.DllFileName);
                    }
                    if (detail.AdvErrorCode >= 0xC0000000u)
                    {

                        LOG(0, L"  Adv Is An NTSTATUS From The Target: 0x%08X (%ls).\n",
                            detail.AdvErrorCode, DescribeNtStatus(detail.AdvErrorCode));
                    }
                }
            }

            if (result >= 0x00400000u && result < 0x00500000u)
            {
                LOG(0, L"  %ls[!]%ls Remote Mapping Reached The Shell; Unreclaimable Loader State May Remain.\n",
                    kYellow, kReset);
                LOG(0, L"      Relaunch The Target Before Attempting Another Load.\n");
            }
            targetHandleGuard.reset();
            threadSponsorGuard.reset();
            Trace::Summary(L"Failed During Injection");
            PauseBeforeExit();
            return InjectionFailureIsRetryable(result) ? kResultRetryable : 1;
        }

        threadSponsorGuard.reset();
        threadSponsorRaw = nullptr;

        Trace::Begin(L"Fetch Runtime Telemetry");
        HijackStats ProcessHijackStats{};
        HijackStats ThreadHijackStats{};
        if (runtime.get_last_hijack_stats)
        {
            runtime.get_last_hijack_stats(&ProcessHijackStats, &ThreadHijackStats);
            Trace::Note(L"Process Hijack: Attempted = %u | Success = %u | Source = %u | Donor = %u",
                ProcessHijackStats.Attempted, ProcessHijackStats.Success, ProcessHijackStats.Source,
                ProcessHijackStats.DonorPid);
        }
        MAP_STATS MapStats{};
        if (runtime.get_last_map_stats)
        {
            runtime.get_last_map_stats(&MapStats);
            Trace::Note(L"Map Stats: Cleaned = 0x%08X | Residual = 0x%08X | Verified = %u | CachedCopy = %u",
                MapStats.CleanedMask, MapStats.ResidualMask, MapStats.Verified, MapStats.VerifiedCachedCopy);
        }

        THREAD_EXEC_STATS ThreadExec{};
        if (runtime.get_last_thread_exec_stats)
        {
            runtime.get_last_thread_exec_stats(&ThreadExec);
            Trace::Note(L"Thread Exec: TID = 0x%04X | Success = %u | Return Value = 0x%08X | Iterations = %u | Elapsed = %u ms",
                ThreadExec.HijackedTid, ThreadExec.Success, ThreadExec.RoutineRet,
                ThreadExec.PollIterations, ThreadExec.ExecMs);
            Trace::Note(L"Scrubbed = %llu Bytes | Cycles = %llu",
                static_cast<unsigned long long>(ThreadExec.StackScrubbedBytes),
                static_cast<unsigned long long>(ThreadExec.RoutineCyclesDelta));
        }
        VERIFIABLE_EXEC_TELEMETRY ExecTelemetry{};
        if (runtime.get_last_exec_telemetry)
        {
            runtime.get_last_exec_telemetry(&ExecTelemetry);
            Trace::Note(L"Exec Telemetry: DllMain = %d | Lock = 0x%08X | Unlock = 0x%08X | TLS = %u/%u/%u",
                (int)ExecTelemetry.DllMainResult,
                (unsigned)ExecTelemetry.LdrLockStatus, (unsigned)ExecTelemetry.LdrUnlockStatus,
                ExecTelemetry.TlsCallbacksConfigured, ExecTelemetry.TlsCallbacksExecuted,
                ExecTelemetry.TlsCallbacksFailed);
        }
        Trace::End();
        Context.UsedTid = ThreadExec.HijackedTid;

        bool stealth_gate_ok = false;
        bool wx_violated = false;
        Trace::Begin(L"Stealth Verification Suite");
        if (targetHandle)
        {

            StealthVerifierBuffers buffers;
            {
                const std::wstring runtime_path = RuntimePath(config.dll_dir, config.runtime_name);
                buffers.runtime_path_known = !runtime_path.empty();
                buffers.runtime_read = buffers.runtime_path_known && ReadFileBytes(runtime_path, buffers.runtime_bytes);
            }
            buffers.survey_max_regions = config.survey_max_regions;
            buffers.survey_max_mb = config.survey_max_mb;
            buffers.survey_max_sample_regions = config.survey_max_sample_regions;

            stealth_gate_ok = stealth::SafeDebugAndVerifyStealth(targetHandle, data.hDllOut, flags, raw_data.data(), raw_data.size(),
                &ProcessHijackStats, &ThreadHijackStats, &Context, &MapStats, &ExecTelemetry, runtime.get_last_string_stats, true, target.pid, &wx_violated, config, buffers);
        }
        else
        {
            LOG(0, L"%ls[x]%ls Verification Could Not Run (No Target Handle); The Result Is Unproven.\n",
                kRed, kReset);
        }
        Trace::Note(L"Verification Gate = %s | W^X Violated = %s",
            stealth_gate_ok ? L"Pass" : L"Fail", wx_violated ? L"Yes" : L"No");
        Trace::End(stealth_gate_ok && !wx_violated);

        if (!runtime.get_last_thread_exec_stats || !ThreadExec.Attempted)
        {
            LOG(0, L"  %ls[!]%ls Thread Context Not Reported (No Telemetry, Or No Donor Was Attempted).\n", kYellow, kReset);
        }
        else if (ThreadExec.Success)
        {
            LOG(0, L"  %ls[+]%ls Thread Context Restored To Original On TID: %ls0x%04lX%s.\n",
                kGreen, kReset, kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Thread Context %sNOT Restored%s On TID: %s0x%04lX%s (Code 0x%08lX) - It May Still Be Running Donor Code.\n",
                kYellow, kReset, kYellow, kReset, kYellow,
                static_cast<unsigned long>(ThreadExec.HijackedTid), kReset,
                static_cast<unsigned long>(ThreadExec.FailCode));
        }

        if (ThreadExec.Attempted)
        {
            LOG(0, L"  %ls[+]%ls Donor-Scan Rounds: %ls%lu%ls (Donor-Thread Rounds Attempted Before Success Or Exhaustion).\n",
                kGreen, kReset, kGreen, static_cast<unsigned long>(ThreadExec.DonorRounds), kReset);
        }

        if (ThreadExec.Attempted && data.TargetTid && ThreadExec.HijackedTid
            && ThreadExec.HijackedTid != data.TargetTid)
        {
            LOG(0, L"  %ls[!]%ls Sponsor TID %ls0x%04lX%ls Not Usable; Hijacked TID %ls0x%04lX%ls Instead (Donor Scan Fallback).\n",
                kYellow, kReset,
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        LOG(0, L"\n");

        const bool had_target = (targetHandle != nullptr);
        stealth::VehFirstChanceSurvey veh_coverage_probe{};
        const bool veh_coverage_read = had_target &&
            stealth::QueryRemoteVehFirstChance(targetHandle, veh_coverage_probe) && veh_coverage_probe.readOk;
        struct ReleasedHandles
        {
            ULONGLONG values[3] = { 0, 0, 0 };
            unsigned count = 0;
        } released;

        const auto record = [&released](ULONGLONG h)
        {
            if (h && released.count < 3)
            {
                released.values[released.count++] = h;
            }
        };

        record(static_cast<ULONGLONG>(Context.SponsorThreadValue));
        record(ReCa<ULONGLONG>(targetHandle));

        if (had_target && data.hDllOut)
        {
            MEMORY_BASIC_INFORMATION head{};
            const DWORD base_prot =
                VirtualQueryEx(targetHandle, data.hDllOut, &head, sizeof(head)) ? head.Protect : 0;

            int post_rwx = 0, post_rx = 0, post_rw = 0, post_ro = 0, post_noaccess = 0;
            ULONGLONG committed = 0;
            bool walked = false;
            BYTE * cursor = ReCa<BYTE *>(data.hDllOut);
            while (committed < 0x4000000ULL)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(targetHandle, cursor, &mbi, sizeof(mbi)) || !mbi.RegionSize)
                {
                    break;
                }
                walked = true;
                if (mbi.State == MEM_COMMIT)
                {
                    committed += mbi.RegionSize;
                    switch (mbi.Protect)
                    {
                    case PAGE_EXECUTE_READWRITE: ++post_rwx; break;
                    case PAGE_EXECUTE_READ:
                    case PAGE_EXECUTE:          ++post_rx;  break;
                    case PAGE_READWRITE:        ++post_rw;  break;
                    case PAGE_READONLY:         ++post_ro;  break;
                    case PAGE_NOACCESS:         ++post_noaccess; break;
                    default: break;
                    }
                }
                else
                {
                    break; 
                }
                BYTE * next = ReCa<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cursor)
                {
                    break;
                }
                cursor = next;
            }

            if (walked)
            {
                LOG(0, L"\n  Post-State Re-Query Of The Mapped Image (Taken After The Verification Suite):\n");
                LOG(0, L"    [%ls%ls%ls] Image Base %p | First Region Protect %ls%s%s | State %s\n",
                    post_rwx ? L"x" : L"+", post_rwx ? kRed : kGreen, kReset,
                    data.hDllOut,
                    kGreen, stealth::StealthPageDesc(base_prot), kReset,
                    head.State == MEM_COMMIT ? L"MEM_COMMIT" : L"Not Committed");
                LOG(0, L"    [%ls%ls%ls] Committed Extent %llu KB | RX = %d | RW = %d | RO = %d | NOACCESS = %d | RWX = %d\n",
                    post_rwx ? L"x" : L"+", post_rwx ? kRed : kGreen, kReset,
                    static_cast<unsigned long long>(committed / 1024),
                    post_rx, post_rw, post_ro, post_noaccess, post_rwx);
                LOG(0, L"    [%ls%ls%ls] DllMain Result Read Back At Exit: %ls%s%s | TLS %u/%u Executed "
                        L"| Loader Lock 0x%08X/0x%08X | Hijacked TID 0x%04X\n",
                    L"+", kGreen, kReset,
                    ExecTelemetry.DllMainResult ? L"True" : L"False",
                    ExecTelemetry.DllMainResult ? kGreen : kRed, kReset,
                    ExecTelemetry.TlsCallbacksExecuted, ExecTelemetry.TlsCallbacksConfigured,
                    (unsigned)ExecTelemetry.LdrLockStatus, (unsigned)ExecTelemetry.LdrUnlockStatus,
                    (unsigned)ThreadExec.HijackedTid);
                if (post_rwx)
                {
                    LOG(0, L"    [%lsx%s] Warning: %d RWX Region(s) Observed In The Post-State Query.\n",
                        kRed, kReset, post_rwx);
                }
            }
            else
            {
                LOG(0, L"\n  [%lsx%s] Post-State Re-Query Failed: Image Base Not Queryable.\n", kRed, kReset);
            }
        }
        else if (!had_target)
        {
            LOG(0, L"\n  [%ls*%s] Post-State Re-Read Not Performed: No Target Handle Was Retained.\n", kDim, kReset);
        }

        targetHandleGuard.reset();
        threadSponsorGuard.reset();
        targetHandle = nullptr;
        threadSponsorRaw = nullptr;

        {
            wchar_t list[96] = {};
            for (unsigned i = 0; i < released.count; ++i)
            {
                swprintf_s(list + wcslen(list), _countof(list) - wcslen(list), L"%ls0x%04llX%s",
                    i ? L", " : L"", released.values[i], kReset);
            }
            if (released.count)
            {
                LOG(0, L"  %ls[+]%ls Closed %ls%u%ls Handle(s) Before Exit: %ls\n",
                    kGreen, kReset, kGreen, released.count, kReset, list);
            }
            else
            {
                LOG(0, L"  %ls[*]%ls No Handles Were Open At Cleanup (None Acquired This Run).\n", kDim, kReset);
            }
        }

        LOG(0, L"\n");
        if (!stealth_gate_ok)
        {
            if (!had_target)
            {

                LOG(0, L"%ls[x] Verification Not Performed%s - The Payload Is Mapped In The\n", kRed, kReset);
                LOG(0, L"    Target, But No Target Handle Was Available, So Neither The String-Encryption\n");
                LOG(0, L"    Gate Nor The W^X Posture Could Be Checked. The Result Is Unproven; Do Not\n");
                LOG(0, L"    Treat It As A Clean Load Until It Can Be Verified.\n");
            }
            else
            {
                LOG(0, L"%ls[x] Verification Gate Failed%s - The Payload Is Mapped In The Target, But The\n", kRed, kReset);
                LOG(0, L"    Runtime DLL Does Not Pass Verification (String-Encryption Or Forensic Posture).\n");
                LOG(0, L"    It Must Not Be Treated As A Clean Load: A Plaintext Symbol Name In .rdata Is\n");
                LOG(0, L"    Scannable, And Shipping It Defeats The Point Of The String Tiers.\n");
                LOG(0, L"    Fix The Leak And Rebuild Before Using This Build.\n");
            }
            LOG(0, L"    Exit Code %d Means Mapped-But-Unverified, Not A Load Failure: The Payload\n", kResultMappedUnverified);
            LOG(0, L"    Is Running In The Target; Only The Proof Of Its Posture Is Missing.\n");
            Trace::Summary(had_target ? L"Failed At Verification Gate" : L"Verification Not Performed");
            PauseBeforeExit();
            return kResultMappedUnverified;
        }
        if (wx_violated)
        {
            LOG(0, L"%ls[!] W^X Advisory:%s The W^X Posture Was Not Confirmed (See The Verify W^X Execution Step).\n", kYellow, kReset);
            LOG(0, L"    Either A Mapped Page Is Not RX As Expected, Or The Image Could Not Be Queried\n");
            LOG(0, L"    Or Bounded. The Load Is Functional, But This Weakens Confidence In The\n");
            LOG(0, L"    W^X Posture. Treat This Build As Suspect.\n\n");
        }

        {
            const bool exceptions_on = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
            const bool exec_telemetry_read = runtime.get_last_exec_telemetry != nullptr;
            // A re-read of the mapper's cached copy is not an independent check
            // of the target's memory: under INJ_ERASE_HEADER the in-image
            // directory table has already been wiped.
            const bool map_stats_cached = MapStats.Verified != 0 && MapStats.VerifiedCachedCopy != 0;
            const bool map_stats_read = runtime.get_last_map_stats != nullptr &&
                MapStats.Verified != 0 && !MapStats.VerifiedCachedCopy;
            stealth::VehFirstChanceSurvey veh_coverage{};
            const bool veh_checked = veh_coverage_read;
            if (veh_checked)
            {
                veh_coverage = veh_coverage_probe;
            }
            struct Coverage
            {
                const wchar_t * label;
                bool checked;
                const wchar_t * note;
            };
            wchar_t marker_coverage_note[64]{};
            swprintf_s(marker_coverage_note, L"%zu Markers Absent From The Runtime DLL", kStringMarkerCount);
            const Coverage coverage[] =
            {
                { L"In-Shell Execution Telemetry", exec_telemetry_read, L"RDTSC Timing, DllMain Result, Loader-Lock, TLS" },
                { L"Data-Directory Wipe Re-Read",    map_stats_read,
                    map_stats_cached ? L"Cache Consistency Only: In-Image Header Already Wiped"
                                     : L"Mapper-Side Re-Read Of The In-Image Table" },
                { L"Cross-Process Header Re-Read",   false, L"Impossible: Mapper Leaves The Header PAGE_NOACCESS" },
                { L"Page Protections / W^X",         !wx_violated, L"VirtualQueryEx Walk Of The Mapped Image" },
                { L"Forensic Posture (Runtime DLL)", stealth_gate_ok, L"Exports, Section Names, Debug Directory" },
                { L"String-Encryption Markers",      stealth_gate_ok, marker_coverage_note },
                { L"Payload Exception Unwinding",    exceptions_on, L"INJ_MM_ENABLE_EXCEPTIONS; SEH-Table Path" },
                { L"Target VEH First-Chance (PEB)",  veh_checked, L"RPM-Only CrossFlags PEB+80; Installs Nothing" },
            };

            constexpr size_t kCoverageCount = sizeof(coverage) / sizeof(coverage[0]);
            unsigned checked = 0, unchecked = 0;
            for (size_t i = 0; i < kCoverageCount; ++i)
            {
                checked += coverage[i].checked ? 1u : 0u;
                unchecked += coverage[i].checked ? 0u : 1u;
            }

            LOG(0, L"\n");
            LOG(0, L"  Verification Coverage (%ls%u Of %zu Capabilities Externally Checked%ls):\n",
                kGreen, checked, kCoverageCount, kReset);
            for (size_t i = 0; i < kCoverageCount; ++i)
            {
                LOG(0, L"    %ls%s%ls %-34ls %ls\n",
                    coverage[i].checked ? L"[+]" : L"[*]",
                    coverage[i].checked ? kGreen : kDim, kReset,
                    coverage[i].label, coverage[i].note);
            }
            if (unchecked)
            {
                LOG(0, L"  %ls[*]%ls %ls%u%ls Capabilit%s Not Checkable From Outside The Target - Reported As\n",
                    kDim, kReset, kYellow, unchecked, kReset, unchecked == 1 ? L"y Is" : L"ies Are");
                LOG(0, L"    Observations, Not Passes. A Green Gate Means Every Check That Could Run Did.\n");
            }
        }

        LOG(0, L"\n");
        LOG(0, L"Load Result (Every Value Below Was Read Back During This Run):\n");

        const auto row = [](const wchar_t * label, bool ok)
        {
            LOG(0, L"  [%ls%s%s] %ls", ok ? L"+" : L"x", ok ? kGreen : kRed, kReset, label);
        };

        row(L"Return Code............... ", result == INJ_ERR_SUCCESS);
        LOG(0, L"0x%08X (%s)\n", static_cast<unsigned>(result),
            result == INJ_ERR_SUCCESS ? L"INJ_ERR_SUCCESS" : L"Non-Zero");

        row(L"Mapped Image Base......... ", data.hDllOut != nullptr);
        LOG(0, L"%p\n", data.hDllOut);

        row(L"Inject Call Wall Time..... ", true);
        LOG(0, L"%llu ms (Timeout %lu ms)\n",
            static_cast<unsigned long long>(inject_window_ms),
            static_cast<unsigned long>(data.Timeout));

        row(L"DllMain(DLL_PROCESS_ATTACH) Returned ",
            ExecTelemetry.DllMainCyclesDelta == 0 ? true : ExecTelemetry.DllMainResult != 0);
        if (ExecTelemetry.DllMainCyclesDelta == 0)
        {
            LOG(0, L"Not Entered (No Entry Point; Cycle Counter 0)\n");
        }
        else
        {
            LOG(0, L"%s\n", ExecTelemetry.DllMainResult ? L"True" : L"False");
        }

        const bool tls_ok = ExecTelemetry.TlsCallbacksConfigured == ExecTelemetry.TlsCallbacksExecuted &&
            ExecTelemetry.TlsCallbacksFailed == 0;
        row(L"TLS Callbacks............. ", tls_ok);
        LOG(0, L"%u Executed Of %u Configured (%u Failed)\n",
            ExecTelemetry.TlsCallbacksExecuted, ExecTelemetry.TlsCallbacksConfigured,
            ExecTelemetry.TlsCallbacksFailed);

        const bool lock_attempted = ExecTelemetry.DllMainCyclesDelta != 0;
        const bool lock_ok = !lock_attempted ||
            (ExecTelemetry.LdrLockStatus == 0 && ExecTelemetry.LdrUnlockStatus == 0);
        row(L"Loader Lock Acquire/Release  ", lock_ok);
        if (!lock_attempted)
        {
            LOG(0, L"Not Attempted (Inside The DllMain Step; DllMain Not Entered)\n");
        }
        else
        {
            LOG(0, L"0x%08X / 0x%08X\n",
                (unsigned)ExecTelemetry.LdrLockStatus, (unsigned)ExecTelemetry.LdrUnlockStatus);
        }

        row(L"Thread Hijack............. ", ThreadExec.Success != 0);
        LOG(0, L"TID 0x%04X | Success = %u | Routine Return Value = 0x%08X | %u Poll(s) Over %u ms\n",
            (unsigned)ThreadExec.HijackedTid, (unsigned)ThreadExec.Success,
            (unsigned)ThreadExec.RoutineRet, (unsigned)ThreadExec.PollIterations,
            (unsigned)ThreadExec.ExecMs);

        row(L"Hijacked Stack Scrubbed... ", ThreadExec.StackScrubbedBytes != 0);
        LOG(0, L"%llu Bytes In %llu Cycles\n",
            static_cast<unsigned long long>(ThreadExec.StackScrubbedBytes),
            static_cast<unsigned long long>(ThreadExec.RoutineCyclesDelta));

        row(L"Thread Context Snapshot... ", ThreadExec.OldRip != 0);
        LOG(0, L"Original RIP = 0x%llX | Original RSP = 0x%llX | Post-Scrub Limit = 0x%llX | FP Mode %ls\n",
            static_cast<unsigned long long>(ThreadExec.OldRip),
            static_cast<unsigned long long>(ThreadExec.OldRsp),
            static_cast<unsigned long long>(ThreadExec.StackLimit),
            ThreadExec.FpMode ? L"XSAVE" : L"FXSAVE");

        row(L"Data Directories Wiped.... ", MapStats.Verified != 0 && MapStats.ResidualMask == 0);
        LOG(0, L"Cleaned Mask = 0x%08X | Residual = 0x%08X | %s\n",
            (unsigned)MapStats.CleanedMask, (unsigned)MapStats.ResidualMask,
            MapStats.VerifiedCachedCopy ? L"Cached Copy Only (Header Already Wiped; Not Independent)"
                : MapStats.Verified ? L"Re-Read From The In-Image Header"
                : L"Not Verified");

        row(L"W^X....................... ", !wx_violated);
        LOG(0, L"RWX Regions Found: %d (%s)\n", wx_violated ? 1 : 0,
            wx_violated ? L"Violated" : L"Enforced");

        row(L"Verification Gate......... ", stealth_gate_ok);
        LOG(0, L"%s\n", stealth_gate_ok ? L"Pass" : L"Fail");

        // A test run has to be recognisable as one at a glance, and it has to
        // be recognisable in the transcript long after the run is over. It is
        // not a failure, so it is not marked with the pass or fail marker.
        {
            const wchar_t * marker = config.test_mode ? L"!" : L"+";
            const wchar_t * tint = config.test_mode ? kYellow : kGreen;
            const wchar_t * mode = config.test_mode
                ? L"TEST MODE - The Target Was Forced To A Scratch Image, Not The Configured Process"
                : L"Normal - The Target Was The Configured Process";
            LOG(0, L"  [%ls%s%s] Run Mode.................. %ls\n", tint, marker, kReset, mode);
        }

            LOG(0, L"====================================================================================================\n");
            LOG(0, L"[Result] %ls%ls%ls Mapped At %p In %ls (PID %lu)\n",
                config.test_mode ? kYellow : kGreen,
                config.test_mode ? L"[TEST MODE] " : L"[+]",
                kReset, data.hDllOut, target.name.c_str(), static_cast<unsigned long>(target.pid));
            LOG(0, L"====================================================================================================\n");
        Trace::Summary(config.test_mode ? L"Success (Test Mode)" : L"Success");
        g_LoadCompleted = true;
        PauseBeforeExit();
        return 0;
    }
}

    // A structured exception that escapes the wizard is still a crash of the
    // launcher, and the transcript has to say so instead of ending in the
    // middle of a line with no explanation. The handler is a function of its
    // own because a frame that owns C++ objects cannot contain __try without
    // asking the whole frame to unwind, and the wizard is full of them.
    int RunWizardWithFaultReport(Runtime & runtime) noexcept
    {
        __try
        {
            return RunInteractiveWizard(runtime);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            wchar_t report[320]{};
            swprintf_s(report,
                L"\n%ls[x]%ls The Launcher Faulted During The Run: Exception 0x%08lX. "
                L"Everything Above This Line Is What It Printed Before The Fault.\n",
                kRed, kReset, static_cast<unsigned long>(GetExceptionCode()));
            ameger_ui_log::AppendStripped(report);
            return 1;
        }
    }

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prevInstance, PWSTR cmdShow, int showCmd)
{
    (void)instance;
    (void)prevInstance;
    (void)cmdShow;
    (void)showCmd;
    EnableAnsi();

    std::wstring parentHint;
    {
        const std::wstring cmd = GetCommandLineW();
        const size_t pos = cmd.find(kParentPathMarker);
        if (pos != std::wstring::npos)
        {
            size_t start = pos + wcslen(kParentPathMarker);
            if (start < cmd.size() && cmd[start] == L'"')
            {
                ++start;
                const size_t end = cmd.find(L'"', start);
                if (end != std::wstring::npos && end > start)
                {
                    parentHint = cmd.substr(start, end - start);
                }
            }
            else
            {
                size_t end = start;
                while (end < cmd.size() && cmd[end] != L' ' && cmd[end] != L'\t')
                {
                    ++end;
                }
                if (end > start)
                {
                    parentHint = cmd.substr(start, end - start);
                }
            }
        }
    }

    if (!PolymorphicSelfRename(parentHint))
    {
        return 0;
    }

    const int retryIndex = GetRetryIndex();

    // The transcript is named after the configuration, so that it sits next to
    // the file that produced it. When the configuration cannot be found or
    // read there is no name to take, and the name of the launcher itself is
    // used instead: a run that failed to find its configuration is exactly the
    // run that has to be read afterwards, so it must still leave a record.
    const std::wstring config_path = ConfigurationPath();
    {
        std::wstring stem;

        const size_t slash = config_path.find_last_of(L"\\/");
        const size_t dot = config_path.find_last_of(L'.');
        if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash + 1))
        {
            const size_t start = (slash == std::wstring::npos) ? 0 : slash + 1;
            stem = config_path.substr(start, dot - start);
        }
        else
        {
            std::wstring own;
            if (GetOwnExePath(own))
            {
                const size_t own_slash = own.find_last_of(L"\\/");
                std::wstring name = (own_slash == std::wstring::npos) ? own : own.substr(own_slash + 1);
                const size_t own_dot = name.find_last_of(L'.');
                if (own_dot != std::wstring::npos)
                {
                    name = name.substr(0, own_dot);
                }
                stem = name;
            }
        }

        if (!stem.empty())
        {
            // Each attempt gets its own transcript, so a failed attempt is
            // not overwritten by the retry that follows it.
            if (retryIndex > 0)
            {
                g_ResultLogName = stem + L".attempt" + std::to_wstring(retryIndex) + L".log";
            }
            else
            {
                g_ResultLogName = stem + L".log";
            }
        }
    }

    ameger_ui_log::ResetResultLog();

    // The transcript describes itself before anything else happens in the run.
    // A normal run repeats this information in the trace header further down,
    // but that header is produced by code that can fail; this one is written
    // first, so a run that never gets that far still says what it was.
    {
        SYSTEMTIME now{};
        GetLocalTime(&now);

        std::wstring own_path;
        GetOwnExePath(own_path);

        bool elevated = false;
        HANDLE token = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            TOKEN_ELEVATION elevation{};
            DWORD returned = 0;
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned))
            {
                elevated = elevation.TokenIsElevated != 0;
            }
            CloseHandle(token);
        }

        SYSTEM_INFO system_info{};
        GetNativeSystemInfo(&system_info);
        const wchar_t * architecture = system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
            ? L"x64" : L"x86";

        wchar_t header[1024]{};
        swprintf_s(header,
            L"[Ameger Injector Transcript]\n"
            L"  Started       = %04u-%02u-%02u %02u:%02u:%02u Local\n"
            L"  Process ID    = %lu\n"
            L"  Launcher      = %ls\n"
            L"  Configuration = %ls\n"
            L"  Transcript    = %ls\n"
            L"  Attempt       = %d Of %d\n"
            L"  Host          = %ls, %ls Integrity\n"
            L"\n",
            static_cast<unsigned>(now.wYear), static_cast<unsigned>(now.wMonth), static_cast<unsigned>(now.wDay),
            static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute), static_cast<unsigned>(now.wSecond),
            static_cast<unsigned long>(GetCurrentProcessId()),
            own_path.empty() ? L"(unknown)" : own_path.c_str(),
            config_path.empty() ? L"(not found)" : config_path.c_str(),
            g_ResultLogName.c_str(),
            retryIndex + 1, kMaxLaunchAttempts,
            architecture, elevated ? L"High" : L"Normal");

        if (!ameger_ui_log::BeginResultLog(header))
        {
            // Without a transcript file the run can still proceed; the console
            // output is unaffected and the failure is reported once, here.
            LOG(0, L"%ls[!]%ls Unable To Open The Transcript File; The Run Will Not Leave A Log.\n", kYellow, kReset);
        }
    }

    Runtime runtime;
    int result = 1;
    try
    {
        result = RunWizardWithFaultReport(runtime);
    }
    catch (const std::bad_alloc &)
    {
        PrintError(L"Out Of Memory During Loading; Aborting.");
        PauseBeforeExit();
        result = 1;
    }
    if (runtime.module)
    {
        if (runtime.shutdown_runtime)
        {
            runtime.shutdown_runtime();
        }
        // The entry points are dropped before the image is released, so a
        // later mistake cannot call into a module that is no longer mapped.
        runtime.memory_inject = nullptr;
        runtime.get_symbol_state = nullptr;
        runtime.get_import_state = nullptr;
        runtime.initialize_runtime = nullptr;
        runtime.shutdown_runtime = nullptr;
        runtime.start_download = nullptr;
        runtime.set_raw_print_callback = nullptr;
        runtime.get_last_hijack_stats = nullptr;
        runtime.get_last_map_stats = nullptr;
        runtime.get_last_string_stats = nullptr;
        runtime.get_last_thread_exec_stats = nullptr;
        runtime.get_last_exec_telemetry = nullptr;
        runtime.get_last_error_info = nullptr;
        runtime.clear_last_error_info = nullptr;
        FreeLibrary(runtime.module);
        runtime.module = nullptr;
    }

    // The transcript of the run.
    //
    // It is always written, whether the run succeeded or failed. The record of
    // a successful load is the one worth having, so removing it is something
    // that has to be asked for explicitly rather than something that happens
    // by default.
    ameger_ui_log::WriteResultLog();

    // A run that mapped the payload may still be asked to leave nothing
    // behind. A run that did not is never asked: the transcript of a run that
    // failed, or that was cancelled, is the only evidence of what happened.
    if (g_LoadCompleted && DiscardResultLogOnSuccess())
    {
        ameger_ui_log::DiscardResultLog();
    }
    ameger_ui_log::Clear();

    if (result == kResultRetryable && retryIndex + 1 < kMaxLaunchAttempts)
    {
        const int nextRetry = retryIndex + 1;
        if (SpawnFreshRetryProcess(nextRetry))
        {
            TerminateInterface(result);
        }
    }

    if (result == kResultRetryable && retryIndex + 1 >= kMaxLaunchAttempts)
    {
        const std::wstring message = g_TestMode
            ? L"Test Run Failed After 3 Attempts. The Full Log Is In " + g_ResultLogName + L"."
            : L"Operation Failed After 3 Attempts. The Full Log Is In " + g_ResultLogName + L".";
        LOG(0, L"%ls\n", message.c_str());
        result = 1;
    }

    // The copy this process is running from is removed last, after the retry
    // has been spawned from it.
    DeleteOwnSelfCopyIfChild();

    return result;
}




