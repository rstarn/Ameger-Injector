#include "PCH.h"

#include "Launcher.h"

#include <cstdarg>
#include <cstdio>

// Console output for the launcher.
//
// The transcript is kept in memory as it is produced and is written to disk at
// the end of the run, so a failed attempt can still be inspected afterwards.
// Removes the ANSI escape sequences from a fragment of console output. The
// transcript on disk and the stream written to a console that cannot render
// VT sequences both need the same cleaned text.
static std::wstring StripAnsiEscapes(const wchar_t * text)
{
    if (!text || !*text)
    {
        return {};
    }

    std::wstring clean;
    size_t len = 0;
    while (text[len])
    {
        ++len;
    }
    clean.reserve(len);
    for (size_t i = 0; text[i]; ++i)
    {
        if (text[i] == L'\x1b' && text[i + 1] == L'[')
        {
            size_t j = i + 2;
            while (text[j] && ((text[j] >= L'0' && text[j] <= L'9') || text[j] == L';' || text[j] == L':' ||
                text[j] == L'<' || text[j] == L'=' || text[j] == L'>' || text[j] == L'?' || text[j] == L'!'))
            {
                ++j;
            }
            while (text[j] && text[j] >= L' ' && text[j] <= L'/')
            {
                ++j;
            }
            if (text[j] && text[j] >= L'@' && text[j] <= L'~')
            {
                i = j;
                continue;
            }
        }
        else if (text[i] == L'\x1b' && (text[i + 1] == L'(' || text[i + 1] == L')' || text[i + 1] == L'#'))
        {
            if (text[i + 2])
            {
                i += 2;
                continue;
            }
        }
        clean += text[i];
    }
    return clean;
}

namespace ameger_ui_log
{
    constexpr size_t kMaxChars = 2097152;

static SRWLOCK & Lock()
{
    static SRWLOCK lock = SRWLOCK_INIT;
    return lock;
}

static std::wstring & Buffer()
{
    static std::wstring buffer;
    return buffer;
}

void AppendClean(const wchar_t * text)
{
    if (!text || !*text)
    {
        return;
    }
    AcquireSRWLockExclusive(&Lock());
    std::wstring & buf = Buffer();
    if (buf.size() < kMaxChars)
    {
        const size_t room = kMaxChars - buf.size();
        size_t take = wcslen(text);
        if (take > room)
        {
            take = room;
        }
        buf.append(text, take);
    }
    ReleaseSRWLockExclusive(&Lock());
}

void AppendStripped(const wchar_t * text)
{
    const std::wstring clean = StripAnsiEscapes(text);
    if (clean.empty())
    {
        return;
    }
    AppendClean(clean.c_str());
}

std::wstring Snapshot()
    {
        AcquireSRWLockShared(&Lock());
        std::wstring copy = Buffer();
        ReleaseSRWLockShared(&Lock());
        return copy;
    }

std::wstring ResultLogPath()
    {
        wchar_t module[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, module, MAX_PATH);
        if (!length || length >= MAX_PATH)
        {
            return {};
        }

        std::wstring path(module, length);
        const size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return {};
        }

        path.resize(slash + 1);
        path += g_ResultLogName;
        return path;
    }

void ResetResultLog()
{
    const std::wstring path = ResultLogPath();
    if (!path.empty())
    {
        DeleteFileW(path.c_str());
    }
}

// Removes the transcript outright. A clean run should not leave a record of
// what it did next to the launcher.
void DiscardResultLog()
{
    ResetResultLog();
}

void WriteResultLog()
    {
        std::wstring snapshot = Snapshot();
        if (snapshot.empty())
        {
            return;
        }

        const std::wstring path = ResultLogPath();
        if (path.empty())
        {
            return;
        }

        const int chars = static_cast<int>(snapshot.size());
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, snapshot.c_str(), chars, nullptr, 0, nullptr, nullptr);
        if (bytes <= 0)
        {
            return;
        }

        std::string utf8(static_cast<size_t>(bytes), '\0');
        WideCharToMultiByte(CP_UTF8, 0, snapshot.c_str(), chars, utf8.data(), bytes, nullptr, nullptr);

        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        DWORD written = 0;
        WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        CloseHandle(file);
    }

void Clear()
    {
        AcquireSRWLockExclusive(&Lock());
        Buffer().clear();
        ReleaseSRWLockExclusive(&Lock());
    }
} 




// Whether the attached console can render the ANSI sequences the tints are
// made of. A console that cannot is fed the cleaned text instead, so escape
// bytes never reach the screen.
static bool ConsoleSupportsColor()
{
    static const bool supported = []()
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!output || output == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        DWORD mode = 0;
        if (!GetConsoleMode(output, &mode))
        {
            return false;
        }
        return (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }();
    return supported;
}

int UiLog(int indent, const wchar_t * format, ...)
{
    if (!format)
    {
        return -1;
    }
    if (indent < 0)
    {
        indent = 0;
    }
    va_list args;
    va_start(args, format);
    int needed = _vscwprintf(format, args);
    va_end(args);
    if (needed <= 0)
    {
        return needed;
    }
    const size_t pad = static_cast<size_t>(indent) * 2;
    std::vector<wchar_t> buffer(pad + static_cast<size_t>(needed) + 1, L' ');
    va_start(args, format);
    const int written = vswprintf_s(buffer.data() + pad, buffer.size() - pad, format, args);
    va_end(args);
    if (written > 0)
    {
        const std::wstring clean = StripAnsiEscapes(buffer.data());
        ameger_ui_log::AppendClean(clean.c_str());
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            if (ConsoleSupportsColor())
            {
                fputws(buffer.data(), stdout);
            }
            else
            {
                fputws(clean.c_str(), stdout);
            }
            fflush(stdout);
        }
    }
    return written;
}


