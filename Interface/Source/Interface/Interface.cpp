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
            while (text[j] >= L' ' && text[j] <= L'/')
            {
                ++j;
            }
            if (text[j] >= L'@' && text[j] <= L'~')
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

// The transcript file, once it has been opened, and the number of characters of
// the buffer that are already in it. Everything logged after the file is opened
// is written immediately instead of being held until the end of the run, so a
// crash still leaves the lines that led up to it. Holding the whole transcript
// in memory and writing it once at the end means the runs that most need a
// record, the ones that die, are the ones that leave nothing.
static HANDLE & File()
{
    static HANDLE file = INVALID_HANDLE_VALUE;
    return file;
}

static size_t & Written()
{
    static size_t written = 0;
    return written;
}

static bool WriteUtf8(HANDLE file, const wchar_t * text, size_t chars)
{
    if (file == INVALID_HANDLE_VALUE || !text || !chars)
    {
        return true;
    }

    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(chars), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        return false;
    }

    std::string utf8(static_cast<size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(chars), utf8.data(), needed, nullptr, nullptr) != needed)
    {
        return false;
    }

    size_t offset = 0;
    while (offset < utf8.size())
    {
        const DWORD chunk = static_cast<DWORD>(utf8.size() - offset > 0x100000 ? 0x100000 : utf8.size() - offset);
        DWORD written = 0;
        if (!WriteFile(file, utf8.data() + offset, chunk, &written, nullptr) || !written)
        {
            return false;
        }
        offset += written;
    }

    return true;
}

static void CloseFile()
{
    HANDLE file = File();
    if (file != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(file);
        CloseHandle(file);
    }
    File() = INVALID_HANDLE_VALUE;
    Written() = 0;
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
    // Whatever has not reached the file yet is written now. This also covers
    // lines that were logged before the file was opened: they are still in the
    // buffer and are flushed by the first append that follows.
    size_t & written = Written();
    if (written < buf.size())
    {
        WriteUtf8(File(), buf.data() + written, buf.size() - written);
        written = buf.size();
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
    CloseFile();
    const std::wstring path = ResultLogPath();
    if (!path.empty())
    {
        DeleteFileW(path.c_str());
    }
}

bool BeginResultLog(const wchar_t * header)
{
    const std::wstring path = ResultLogPath();
    if (path.empty())
    {
        return false;
    }

    CloseFile();

    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    AcquireSRWLockExclusive(&Lock());
    File() = file;
    Written() = 0;

    std::wstring & buf = Buffer();
    if (header && *header)
    {
        buf.append(header);
    }

    const bool ok = WriteUtf8(file, buf.data(), buf.size());
    Written() = buf.size();
    ReleaseSRWLockExclusive(&Lock());

    return ok;
}

// Removes the transcript outright. A clean run should not leave a record of
// what it did next to the launcher.
void DiscardResultLog()
{
    CloseFile();
    const std::wstring path = ResultLogPath();
    if (!path.empty())
    {
        DeleteFileW(path.c_str());
    }
}

// Writes what has not reached the file yet and leaves it open. Anything logged
// afterwards is appended to the same file, so a line printed after the wizard
// returns is still part of the record.
void FlushResultLog()
    {
        AcquireSRWLockExclusive(&Lock());
        std::wstring & buf = Buffer();
        size_t & written = Written();
        if (written <= buf.size())
        {
            WriteUtf8(File(), buf.data() + written, buf.size() - written);
            written = buf.size();
        }
        ReleaseSRWLockExclusive(&Lock());
    }

// Writes what has not reached the file yet and closes it. The file is already
// open and current from BeginResultLog onward, so this only drains the tail; a
// second call is a no-op rather than a second copy of the whole transcript.
void WriteResultLog()
    {
        FlushResultLog();
        CloseFile();
    }

void Clear()
    {
        AcquireSRWLockExclusive(&Lock());
        Buffer().clear();
        Written() = 0;
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


