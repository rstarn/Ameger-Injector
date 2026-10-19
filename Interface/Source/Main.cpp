#include "PCH.h"

#include <cstdarg>
#include <cstdio>

#include "../../Ameger/Injection.h"
#include "../../Ameger/Core/Foundation/Error.h"
#include "../../Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "../../Ameger/Core/Utility/Binary/PEImage.h"
#include "../../Ameger/NT/NTDefinitions.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef AMEGER_RUNTIME_DLL_HASH0
#define AMEGER_RUNTIME_DLL_HASH0 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH1
#define AMEGER_RUNTIME_DLL_HASH1 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH2
#define AMEGER_RUNTIME_DLL_HASH2 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH3
#define AMEGER_RUNTIME_DLL_HASH3 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH4
#define AMEGER_RUNTIME_DLL_HASH4 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH5
#define AMEGER_RUNTIME_DLL_HASH5 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH6
#define AMEGER_RUNTIME_DLL_HASH6 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH7
#define AMEGER_RUNTIME_DLL_HASH7 0
#endif

#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

namespace
{

    
    
    
    
    
    
    
    
    
    
    constexpr wchar_t kReset[] = L"";
    constexpr wchar_t kGreen[] = L"";
    constexpr wchar_t kRed[] = L"";
    constexpr wchar_t kYellow[] = L"";

    constexpr wchar_t kDim[] = L"";

    constexpr wchar_t kCyan[] = L"";

    constexpr size_t kConfigBlobMagicSize = 8;

    
    
    
    constexpr size_t kStringMarkerCount = 34;

#ifndef AMEGER_CONFIG_MAGIC_STR
#define AMEGER_CONFIG_MAGIC_STR "SYSCFG01"
#endif

#ifndef AMEGER_WINDOW_CLASS_STR
#define AMEGER_WINDOW_CLASS_STR "AmgWLayered"
#endif

#define AMEGER_WIDEN2(x) L##x
#define AMEGER_WIDEN(x) AMEGER_WIDEN2(x)






std::wstring g_ResultLogName = L"Result.log";

namespace ameger_ui_log
{
    constexpr size_t kMaxChars = 2097152;
    constexpr size_t kMaxBytes = 2097152 * sizeof(wchar_t);

    inline SRWLOCK & Lock()
    {
        static SRWLOCK lock = SRWLOCK_INIT;
        return lock;
    }

    inline std::wstring & Buffer()
    {
        static std::wstring buffer;
        return buffer;
    }

    inline void AppendStripped(const wchar_t * text)
    {
        if (!text || !*text)
        {
            return;
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
        if (clean.empty())
        {
            return;
        }
        AcquireSRWLockExclusive(&Lock());
        std::wstring & buf = Buffer();
        if (buf.size() < kMaxChars)
        {
            if (buf.size() + clean.size() > kMaxChars)
            {
                clean.resize(kMaxChars - buf.size());
            }
            buf += clean;
        }
        ReleaseSRWLockExclusive(&Lock());
    }

    inline std::wstring Snapshot()
    {
        AcquireSRWLockShared(&Lock());
        std::wstring copy = Buffer();
        ReleaseSRWLockShared(&Lock());
        return copy;
    }

    
    
    inline std::wstring ResultLogPath()
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

    inline void ResetResultLog()
    {
        const std::wstring path = ResultLogPath();
        if (!path.empty())
        {
            DeleteFileW(path.c_str());
        }

        wchar_t module[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, module, MAX_PATH);
        if (length && length < MAX_PATH)
        {
            std::wstring legacy(module, length);
            const size_t slash = legacy.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                legacy.resize(slash + 1);
                legacy += L"Result.log";
                if (_wcsicmp(legacy.c_str(), path.c_str()) != 0)
                {
                    DeleteFileW(legacy.c_str());
                }
            }
        }
    }

    inline void WriteResultLog()
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

    inline void Clear()
    {
        AcquireSRWLockExclusive(&Lock());
        Buffer().clear();
        ReleaseSRWLockExclusive(&Lock());
    }
} 

int UiWprintf(const wchar_t * format, ...);
int UiFwprintf(FILE * stream, const wchar_t * format, ...);
int UiLog(int indent, const wchar_t * format, ...);

#define wprintf UiWprintf
#define fwprintf UiFwprintf
#undef LOG
#define LOG UiLog

int UiWprintf(const wchar_t * format, ...)
{
    if (!format)
    {
        return -1;
    }
    va_list args;
    va_start(args, format);
    int needed = _vscwprintf(format, args);
    va_end(args);
    if (needed <= 0)
    {
        return needed;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1);
    va_start(args, format);
    const int written = vswprintf_s(buffer.data(), buffer.size(), format, args);
    va_end(args);
    if (written > 0)
    {
        ameger_ui_log::AppendStripped(buffer.data());
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            va_start(args, format);
            const int forwarded = vwprintf_s(format, args);
            va_end(args);
            return forwarded;
        }
    }
    return written;
}

int UiFwprintf(FILE * stream, const wchar_t * format, ...)
{
    if (!format)
    {
        return -1;
    }
    va_list args;
    va_start(args, format);
    int needed = _vscwprintf(format, args);
    va_end(args);
    if (needed <= 0)
    {
        return needed;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1);
    va_start(args, format);
    const int written = vswprintf_s(buffer.data(), buffer.size(), format, args);
    va_end(args);
    if (written > 0)
    {
        ameger_ui_log::AppendStripped(buffer.data());
        const HANDLE handle = (stream == stderr)
            ? GetStdHandle(STD_ERROR_HANDLE)
            : GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (handle && handle != INVALID_HANDLE_VALUE && GetConsoleMode(handle, &mode))
        {
            va_start(args, format);
            const int forwarded = vfwprintf_s(stream, format, args);
            va_end(args);
            return forwarded;
        }
    }
    return written;
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
        ameger_ui_log::AppendStripped(buffer.data());
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            fputws(buffer.data(), stdout);
            fflush(stdout);
        }
    }
    return written;
}

    constexpr int kMaxLaunchAttempts = 3;
    
    
    constexpr int kResultRetryable = 3;
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

    std::wstring GetAmegerWindowClass()
    {
        
        
        
        
        static const wchar_t kBakedWide[] = AMEGER_WIDEN(AMEGER_WINDOW_CLASS_STR);
        size_t converted = 0;
        for (size_t i = 0; kBakedWide[i] != L'\0' && i + 1 < 64; ++i)
        {
            const wchar_t c = kBakedWide[i];
            const bool ok = (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
                (i > 0 && c >= L'0' && c <= L'9') || c == L'_';
            if (!ok)
            {
                break;
            }
            converted = i + 1;
        }
        if (converted < 4)
        {
            return std::wstring(L"AmgWLayered");
        }
        return std::wstring(kBakedWide, converted);
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

    struct LayeredDialogState
    {
        std::wstring title;
        std::wstring message;
        int mode = 0; 
        int result = 0; 
        int defaultResult = IDCANCEL;
        HWND hwnd = nullptr;
        HDC memDc = nullptr;
        HBITMAP bitmap = nullptr;
        void * bits = nullptr;
        int width = 480;
        int height = 210;
        RECT primary = {};
        RECT secondary = {};
        bool hasSecondary = false;
        UINT timeoutMs = 60000;
    };

    LRESULT CALLBACK LayeredDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        auto * state = reinterpret_cast<LayeredDialogState *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg)
        {
        case WM_NCCREATE:
        {
            auto * create = reinterpret_cast<CREATESTRUCTW *>(lParam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            return TRUE;
        }
        case WM_LBUTTONDOWN:
        {
            if (!state || state->result != 0)
            {
                break;
            }
            const int x = static_cast<int>(static_cast<short>(LOWORD(lParam)));
            const int y = static_cast<int>(static_cast<short>(HIWORD(lParam)));
            const POINT pt{ x, y };
            if (PtInRect(&state->primary, pt))
            {
                state->result = (state->mode == 2) ? IDYES : IDOK;
                DestroyWindow(hwnd);
                return 0;
            }
            if (state->hasSecondary && PtInRect(&state->secondary, pt))
            {
                state->result = (state->mode == 2) ? IDNO : IDCANCEL;
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        }
        case WM_TIMER:
        {
            if (!state || state->result != 0)
            {
                break;
            }
            if (wParam == 1)
            {
                state->result = state->defaultResult;
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        }
        case WM_CLOSE:
        {
            if (state && state->result == 0)
            {
                state->result = state->defaultResult;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_DESTROY:
        {
            if (state)
            {
                KillTimer(hwnd, 1);
                state->hwnd = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        }
        default:
            break;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    bool EnsureLayeredClass(ATOM & atomOut)
    {
        static ATOM cached = 0;
        if (cached)
        {
            atomOut = cached;
            return true;
        }
        const std::wstring className = GetAmegerWindowClass();
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = LayeredDialogProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = className.c_str();
        const ATOM atom = RegisterClassExW(&wc);
        if (atom)
        {
            cached = atom;
            atomOut = cached;
            return true;
        }
        if (GetLastError() == ERROR_CLASS_ALREADY_EXISTS)
        {
            
            
            cached = 1;
            atomOut = cached;
            return true;
        }
        return false;
    }

    void PaintLayeredDialog(LayeredDialogState & state)
    {
        const HDC screen = GetDC(nullptr);
        state.memDc = CreateCompatibleDC(screen);
        ReleaseDC(nullptr, screen);
        if (!state.memDc)
        {
            return;
        }
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = state.width;
        bi.bmiHeader.biHeight = -state.height;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        state.bitmap = CreateDIBSection(state.memDc, &bi, DIB_RGB_COLORS, &state.bits, nullptr, 0);
        if (!state.bitmap || !state.bits)
        {
            if (state.bitmap)
            {
                DeleteObject(state.bitmap);
                state.bitmap = nullptr;
            }
            DeleteDC(state.memDc);
            state.memDc = nullptr;
            return;
        }
        SelectObject(state.memDc, state.bitmap);

        
        HBRUSH back = CreateSolidBrush(RGB(16, 19, 28));
        RECT full{ 0, 0, state.width, state.height };
        FillRect(state.memDc, &full, back);
        DeleteObject(back);

        HPEN border = CreatePen(PS_SOLID, 1, RGB(62, 68, 90));
        HGDIOBJ oldPen = SelectObject(state.memDc, border);
        HGDIOBJ oldBrush = SelectObject(state.memDc, GetStockObject(NULL_BRUSH));
        Rectangle(state.memDc, 0, 0, state.width, state.height);
        SelectObject(state.memDc, oldBrush);
        SelectObject(state.memDc, oldPen);
        DeleteObject(border);

        SetBkMode(state.memDc, TRANSPARENT);
        SetTextColor(state.memDc, RGB(235, 238, 245));
        HFONT titleFont = CreateFontW(17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ oldFont = nullptr;
        if (titleFont)
        {
            oldFont = SelectObject(state.memDc, titleFont);
        }
        RECT titleRc{ 18, 14, state.width - 18, 42 };
        DrawTextW(state.memDc, state.title.c_str(), -1, &titleRc, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        if (titleFont)
        {
            SelectObject(state.memDc, oldFont);
            DeleteObject(titleFont);
        }

        HFONT bodyFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ oldBodyFont = nullptr;
        if (bodyFont)
        {
            oldBodyFont = SelectObject(state.memDc, bodyFont);
        }
        SetTextColor(state.memDc, RGB(200, 206, 220));
        RECT bodyRc{ 18, 44, state.width - 18, state.height - 70 };
        DrawTextW(state.memDc, state.message.c_str(), -1, &bodyRc, DT_LEFT | DT_WORDBREAK);
        if (bodyFont)
        {
            SelectObject(state.memDc, oldBodyFont);
            DeleteObject(bodyFont);
        }

        const int btnW = 110;
        const int btnH = 30;
        const int margin = 18;
        const int bottom = state.height - btnH - 14;
        if (state.mode == 0)
        {
            state.primary = RECT{ state.width - btnW - margin, bottom, state.width - margin, bottom + btnH };
            state.hasSecondary = false;
        }
        else
        {
            state.secondary = RECT{ state.width - btnW - margin, bottom, state.width - margin, bottom + btnH };
            state.primary = RECT{ state.secondary.left - btnW - 10, bottom, state.secondary.left - 10, bottom + btnH };
            state.hasSecondary = true;
        }

        auto paintButton = [&](const RECT & rc, const wchar_t * text) {
            HBRUSH fill = CreateSolidBrush(RGB(48, 54, 76));
            FillRect(state.memDc, &rc, fill);
            DeleteObject(fill);
            HPEN edge = CreatePen(PS_SOLID, 1, RGB(92, 100, 130));
            HGDIOBJ p0 = SelectObject(state.memDc, edge);
            HGDIOBJ b0 = SelectObject(state.memDc, GetStockObject(NULL_BRUSH));
            Rectangle(state.memDc, rc.left, rc.top, rc.right, rc.bottom);
            SelectObject(state.memDc, b0);
            SelectObject(state.memDc, p0);
            DeleteObject(edge);
            SetTextColor(state.memDc, RGB(240, 243, 250));
            RECT textRc = rc;
            DrawTextW(state.memDc, text, -1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        };

        if (state.mode == 2)
        {
            paintButton(state.primary, L"Yes");
            paintButton(state.secondary, L"No");
        }
        else if (state.mode == 1)
        {
            paintButton(state.primary, L"OK");
            paintButton(state.secondary, L"Cancel");
        }
        else
        {
            paintButton(state.primary, L"OK");
        }

        const int screenW = GetSystemMetrics(SM_CXSCREEN);
        const int screenH = GetSystemMetrics(SM_CYSCREEN);
        const int x = screenW > state.width ? (screenW - state.width) / 2 : 0;
        const int y = screenH > state.height ? (screenH - state.height) / 2 : 0;

        POINT dst{ x, y };
        SIZE size{ state.width, state.height };
        POINT src{ 0, 0 };
        BLENDFUNCTION blend{};
        blend.BlendOp = AC_SRC_OVER;
        blend.SourceConstantAlpha = 238;
        blend.AlphaFormat = 0;
        UpdateLayeredWindow(state.hwnd, nullptr, &dst, &size, state.memDc, &src,
            RGB(0, 0, 0), &blend, ULW_ALPHA);
    }

    int ShowLayeredModal(const std::wstring & title, const std::wstring & message,
        int mode, int defaultResult, UINT timeoutMs)
    {
        ATOM atom = 0;
        if (!EnsureLayeredClass(atom))
        {
            return defaultResult;
        }
        const std::wstring className = GetAmegerWindowClass();
        LayeredDialogState state;
        state.title = title;
        state.message = message;
        state.mode = mode;
        state.defaultResult = defaultResult;
        state.timeoutMs = timeoutMs ? timeoutMs : 60000;

        const HINSTANCE inst = GetModuleHandleW(nullptr);
        HWND hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            className.c_str(), title.c_str(), WS_POPUP, 0, 0,
            state.width, state.height, nullptr, nullptr, inst, &state);
        if (!hwnd)
        {
            return defaultResult;
        }
        state.hwnd = hwnd;
        PaintLayeredDialog(state);
        if (!state.memDc)
        {
            DestroyWindow(hwnd);
            return defaultResult;
        }
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetForegroundWindow(hwnd);
        if (state.timeoutMs)
        {
            SetTimer(hwnd, 1, state.timeoutMs, nullptr);
        }

        MSG msg{};
        while (state.result == 0)
        {
            const BOOL got = GetMessageW(&msg, nullptr, 0, 0);
            if (got <= 0)
            {
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (state.memDc)
        {
            DeleteDC(state.memDc);
            state.memDc = nullptr;
        }
        if (state.bitmap)
        {
            DeleteObject(state.bitmap);
            state.bitmap = nullptr;
        }
        if (state.hwnd)
        {
            DestroyWindow(state.hwnd);
            state.hwnd = nullptr;
        }
        
        MSG drain{};
        while (PeekMessageW(&drain, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE))
        {
        }
        return state.result != 0 ? state.result : defaultResult;
    }

    bool LayeredConfirm(const std::wstring & message)
    {
        const int rc = ShowLayeredModal(L"Confirm", message, 1, IDCANCEL, 60000);
        return rc == IDOK;
    }

    bool LayeredYesNo(const std::wstring & message, bool defaultValue)
    {
        const int rc = ShowLayeredModal(L"Confirm", message, 2,
            defaultValue ? IDYES : IDNO, 60000);
        return rc == IDYES;
    }

    void LayeredNotify(const std::wstring & title, const std::wstring & message, UINT timeoutMs)
    {
        (void)ShowLayeredModal(title, message, 0, IDOK, timeoutMs ? timeoutMs : 4000);
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
        
        for (;;)
        {
            bool erased = false;
            size_t pos = rest.find(kRetryMarker);
            if (pos != std::wstring::npos)
            {
                size_t end = pos;
                while (end < rest.size() && rest[end] != L' ' && rest[end] != L'\t' && rest[end] != L'"')
                {
                    ++end;
                }
                rest.erase(pos, end - pos);
                erased = true;
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
                erased = true;
            }
            if (!erased)
            {
                const size_t childPos = rest.find(kChildMarker);
                if (childPos != std::wstring::npos && !keepChild)
                {
                    rest.erase(childPos, wcslen(kChildMarker));
                    erased = true;
                }
                else
                {
                    break;
                }
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
        if (name.size() < 12 || name.size() > 16)
        {
            return false;
        }
        if (_wcsicmp(name.c_str() + name.size() - 4, L".exe") != 0)
        {
            return false;
        }

        const auto is_letter = [](wchar_t c) { return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z'); };
        const auto is_alnum = [&](wchar_t c) { return is_letter(c) || (c >= L'0' && c <= L'9'); };

        if (!is_letter(name[0]))
        {
            return false;
        }

        const size_t stem = name.size() - 4;
        for (size_t i = 1; i < stem; ++i)
        {
            if (!is_alnum(name[i]))
            {
                return false;
            }
        }

        return true;
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

    enum class Architecture
    {
        Unknown,
        X86,
        X64
    };

    struct MemoryInjectionData
    {
        BYTE * RawData;
        DWORD RawSize;
        DWORD ProcessID;
        DWORD Flags;
        DWORD Timeout;
        ULONG_PTR hHandleValue;
        HINSTANCE hDllOut;
        bool GenerateErrorLog;
        DWORD TargetTid;
        ULONG_PTR hThreadHandleValue;
        const wchar_t * DllPath;
    };

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

    using f_Memory_Inject = DWORD(__stdcall *)(MemoryInjectionData *);

    struct Runtime
    {
        HMODULE module = nullptr;
        f_Memory_Inject memory_inject = nullptr;
        f_GetSymbolState get_symbol_state = nullptr;
        f_GetImportState get_import_state = nullptr;
        f_InitializeRuntime initialize_runtime = nullptr;
        f_ShutdownRuntime shutdown_runtime = nullptr;
        f_StartDownload start_download = nullptr;
        f_SetRawPrintCallback set_raw_print_callback = nullptr;
        f_GetLastHijackStats get_last_hijack_stats = nullptr;
        f_GetLastMapStats get_last_map_stats = nullptr;
        f_GetLastStringStats get_last_string_stats = nullptr;
        f_GetLastThreadExecStats get_last_thread_exec_stats = nullptr;
        f_GetLastExecTelemetry get_last_exec_telemetry = nullptr;
        f_GetLastErrorInfo get_last_error_info = nullptr;
        f_ClearLastErrorInfo clear_last_error_info = nullptr;
    };

    bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes);

    struct FileInformation
    {
        Architecture architecture = Architecture::Unknown;
        bool dotnet = false;
    };

    struct TargetSelection
    {
        DWORD pid = 0;
        std::wstring requested_name;
        std::wstring name;
        Architecture architecture = Architecture::Unknown;
        bool by_name = false;
    };

    struct ExportNameMap
    {
        std::string old_name;
        std::string new_name;
    };

    struct WizardConfig
    {
        int schema_version = 0;
        bool handle_hijacking = true;
        bool hijack_scan = true;
        bool sponsor_roundtrip = true;
        bool verbose_trace = true;

        bool quiet = false;

        bool detach_console = false;
        bool test_mode = false;
        bool run_dllmain = true;
        bool page_protections = true;
        bool loader_lock = true;
        bool exceptions = true;
        bool resolve_imports = true;
        bool security_cookie = true;
        bool delay_imports = true;
        bool clean_data = true;
        bool execute_tls = true;
        int timeout = 60000;
        std::wstring target_name;
        std::wstring expected_payload_sha256;

        std::wstring payload_name;
        std::wstring runtime_name;
        std::vector<ExportNameMap> export_map;

        std::wstring dll_dir = L"DLLs";
    };

    void EnableAnsi()
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    // Both PrintError and PrintWarning publish to three sinks: the in-memory clipboard log,
    // the debugger, and the console. The console write goes through UiWprintf/UiFwprintf,
    // which append to the clipboard log themselves -- so these must NOT append a second
    // time here, or every warning lands in the log twice.
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

    
    // Written by VerbosePrint on a runtime worker thread and reset from the main
    // thread, so it has to be atomic. The census accumulator below is only ever
    // touched from inside the callback, which the runtime serialises.
    std::atomic<const void *> g_RuntimeCategory{ nullptr };

    
    bool FullThreadCensusEnabled();

    
    
    
    
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
            
            
            if (GetRetryIndex() > 0)
            {
                value = default_value;
                return true;
            }
            std::wstring message = prompt ? std::wstring(prompt) : std::wstring(L"Continue?");
            value = LayeredYesNo(message, default_value);
            
            
            if (!default_value && !value)
            {
                
            }
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
        wchar_t auto_confirm[8] = {};
        if (GetEnvironmentVariableW(L"AMEGER_AUTO_CONFIRM", auto_confirm, 8) == 1 && auto_confirm[0] == L'1')
        {
            return ConfirmationResult::Proceed;
        }
        
        
        if (GetRetryIndex() > 0)
        {
            return ConfirmationResult::Proceed;
        }
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD console_mode = 0;
        const bool hasConsole = input && input != INVALID_HANDLE_VALUE &&
            GetConsoleMode(input, &console_mode) != FALSE;
        if (!hasConsole)
        {
            
            
            const bool proceed = LayeredConfirm(
                L"Begin Load? Select OK To Proceed Or Cancel To Quit.");
            return proceed ? ConfirmationResult::Proceed : ConfirmationResult::Cancelled;
        }

        LOG(0, L"%ls[+]%ls Press Enter To Begin, Or Q To Quit: \n", kGreen, kReset);
        fflush(stdout);

        std::wstring entered;
        if (!std::getline(std::wcin, entered))
        {

            PrintError(L"Console Input Ended Before Confirmation; Refusing To Load.");
            return ConfirmationResult::Unavailable;
        }

        const std::wstring answer = TrimText(entered);
        if (answer == L"q" || answer == L"Q")
        {
            return ConfirmationResult::Cancelled;
        }
        return ConfirmationResult::Proceed;
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

    bool VerboseOutputEnabled()
    {
        


static const bool verbose = []() -> bool
        {
            wchar_t buffer[8] = {};

            const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_VERBOSE").get(), buffer, 4);
            return !(got == 1 && buffer[0] == L'0');
        }();
        return verbose;
    }

    
    
    
    
    bool FullThreadCensusEnabled()
    {
        static const bool full = []()
        {
            wchar_t buffer[8] = {};

            const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_FULL_CENSUS").get(), buffer, 4);
            return got == 1 && buffer[0] == L'1';
        }();
        return full;
    }

    bool KeepResultLogRequested()
    {
        static const bool keep = []()
        {
            wchar_t buffer[8] = {};

            const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_KEEP_LOG").get(), buffer, 4);
            return got == 1 && buffer[0] == L'1';
        }();
        return keep;
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
    // SeDebugPrivilege is raised and dropped inside the runtime DLL (HandleHijack.cpp),
    // which owns the whole donor-acquisition sequence. The launcher deliberately never
    // touches the process token for injection, so it keeps no privilege helpers.
    
    
    
    
    
    static_assert(sizeof(UNICODE_STRING) == 16);
    static_assert(sizeof(CLIENT_ID) == 16);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ClientId) == 40);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ThreadState) == 68);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, WaitReason) == 72);
    static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 0x50);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

    
    
    
    
    
    
    // Picks a hijack-sponsor candidate thread. Suspended threads are preferred, then
    // threads in safe wait states. The lowest-TID thread (almost always the primary
    // thread) is avoided while any alternative exists, and callers can exclude a TID
    // that a previous sponsor attempt already failed on so the retry loop actually
    // walks the candidate set instead of re-opening the same thread eight times.
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
                    return reason == 4 || reason == 6 || reason == 11 || reason == 13 || reason == 15;
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

            if (!proc->NextEntryOffset || proc->NextEntryOffset < 8)
            {
                break;
            }

            offset += proc->NextEntryOffset;
        }

        return best_tid;
    }

    struct HijackContext
    {
        DWORD TargetPid = 0;
        std::wstring TargetName;
        bool SponsorThreadAttempted = false;
        bool SponsorThreadOpened = false;
        ULONG_PTR SponsorThreadValue = 0;
        DWORD SponsorTid = 0;

        DWORD UsedTid = 0;
        bool Verbose = true;
    };

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

    std::wstring ConfigurationPath()
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

    bool IsOriginalExportName(const std::vector<ExportNameMap> & map, const char * name)
    {
        if (!name)
        {
            return false;
        }
        for (const ExportNameMap & entry : map)
        {
            if (entry.old_name == name)
            {
                return true;
            }
        }
        return false;
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
            if (raw_size < 0 || static_cast<unsigned long long>(raw_size) > 1024 * 1024)
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

    Architecture ProcessArchitecture(HANDLE process)
    {
        using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
        auto k32_name = XOR_STR_W(L"kernel32.dll");
        HMODULE k32_mod = GetModuleHandleW(k32_name.get());
        IsWow64Process2Fn is_wow64_process2 = nullptr;
        if (k32_mod)
        {
            auto wow_name = XOR_STR_A("IsWow64Process2");
            is_wow64_process2 = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(k32_mod, wow_name.get()));
        }
        if (is_wow64_process2)
        {
            USHORT process_machine = 0;
            USHORT native_machine = 0;
            if (is_wow64_process2(process, &process_machine, &native_machine))
            {
                if (process_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
                if (native_machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    return Architecture::X64;
                }
                if (native_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
            }
        }

        BOOL is_wow64 = FALSE;
        if (IsWow64Process(process, &is_wow64) && is_wow64)
        {
            return Architecture::X86;
        }

        SYSTEM_INFO system_info{};
        GetNativeSystemInfo(&system_info);
        return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? Architecture::X64 : Architecture::X86;
    }

    bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        if (!process)
        {
            return false;
        }

        wchar_t path[MAX_PATH * 2]{};
        DWORD length = static_cast<DWORD>(std::size(path));
        const BOOL queried = QueryFullProcessImageNameW(process, 0, path, &length);
        architecture = ProcessArchitecture(process);
        CloseHandle(process);
        if (!queried)
        {
            return false;
        }

        const std::wstring full_path(path, length);
        const size_t slash = full_path.find_last_of(L"\\/");
        name = slash == std::wstring::npos ? full_path : full_path.substr(slash + 1);
        return !name.empty();
    }

    template <size_t NameCount>
    bool QueryProcessFixed(DWORD pid, wchar_t (&name_out)[NameCount], Architecture & architecture)
    {
        name_out[0] = L'\0';
        std::wstring name;
        if (!QueryProcess(pid, name, architecture) || name.empty())
        {
            return false;
        }
        if (name.size() >= NameCount)
        {
            return false;
        }
        name.copy(name_out, name.size());
        name_out[name.size()] = L'\0';
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

    DWORD FindProcess(const std::wstring & requested_name)
    {
        const std::wstring name = NormalizeProcessName(requested_name);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        DWORD result = 0;
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
                {
                    result = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return result;
    }

    bool RefreshTarget(TargetSelection & target)
    {
        if (target.by_name)
        {
            const DWORD pid = FindProcess(target.requested_name);
            if (!pid)
            {
                return false;
            }
            target.pid = pid;
            return QueryProcess(pid, target.name, target.architecture);
        }

        return QueryProcess(target.pid, target.name, target.architecture);
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
            if (found && QueryProcess(found, target.name, target.architecture))
            {
                target.pid = found;
                if (hasConsoleForWait)
                {
                    LOG(0, L"%ls[+]%ls %ls Detected | PID = %ls%lu%ls\n", kGreen, kReset, target.name.c_str(), kGreen, static_cast<unsigned long>(found), kReset);
                }
                return true;
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
        (void)INJ_MM_MAP_FROM_MEMORY;
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

    std::wstring StageLabel(const wchar_t * label, size_t width = 20)
    {
        std::wstring text(label ? label : L"");
        while (text.size() < width)
        {
            text += L'.';
        }
        return text;
    }

    std::wstring StageField(const wchar_t * label, size_t width = 20)
    {
        return StageLabel(label, width) + L" ";
    }

    std::wstring StageField(const std::wstring & label, size_t width = 20)
    {
        return StageLabel(label.c_str(), width) + L" ";
    }

    std::wstring StageTag(int stage)
    {
        wchar_t num[16]{ 0 };
        swprintf_s(num, L"%d", stage);
        return std::wstring(L"[") + kGreen + num + kReset + L"]";
    }

    template <size_t NameCount>
    void DescribeDonor(DWORD Pid, wchar_t (&NameOut)[NameCount])
    {
        NameOut[0] = L'\0';
        if (!Pid)
        {
            return;
        }
        Architecture Arch = Architecture::Unknown;
        QueryProcessFixed(Pid, NameOut, Arch);
    }

    void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread)
    {
        if (!Stats || !Stats->Attempted)
        {
            LOG(0, L"  %ls[!]%ls %ls Handle: No Telemetry (Older Runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        const bool SponsorUsed = Stats->Success && Stats->Source == static_cast<DWORD>(HijackSource::Sponsor);

        wchar_t Text[256]{ 0 };

        LOG(0, L"  %ls Acquisition Trace:\n\n", Kind);

        int Stage = 0;
        const bool target_known = Context && !Context->TargetName.empty();
        LOG(0, L"    %ls %ls %ls%ls%ls | PID = %ls%lu%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Target").c_str(),
            target_known ? kGreen : kYellow,
            target_known ? Context->TargetName.c_str() : L"unknown", kReset,
            kGreen, Context ? Context->TargetPid : 0, kReset);

        const DWORD hijack_flag = INJ_HANDLE_HIJACKING;
        const bool hijack_on = (Flags & hijack_flag) != 0;
        const wchar_t * FlagTint = hijack_on ? kGreen : kYellow;
        LOG(0, L"    %ls %ls %ls%s%ls (%ls0x%04X%s In Flags %ls0x%08X%s)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Config Flag").c_str(),
            FlagTint, hijack_on ? L"Y" : L"N", kReset,
            FlagTint, hijack_flag, kReset,
            FlagTint, Flags, kReset);
        // Process-handle acquisition happens inside the runtime, which raises and drops
        // SeDebugPrivilege itself when a donor open is denied. The launcher never elevates
        // for this path, so the privilege row is informational only.
        if (!IsThread)
        {
            LOG(0, XOR_STR_W(L"    %ls %ls SeDebugPrivilege %ls%s%ls\n").get(), StageTag(++Stage).c_str(), StageLabel(L"Privilege").c_str(),
                kDim, L"Not Required (Runtime-Side Acquisition)", kReset);
        }

        if (IsThread && Context && Context->SponsorThreadOpened)
        {
            LOG(0, L"    %ls %ls %ls0x%08X%ls Pre-Opened, TID %ls0x%04X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorThreadValue), kReset,
                kGreen, Context->SponsorTid, kReset);
        }
        else if (IsThread && Context && Context->SponsorThreadAttempted)
        {

            LOG(0, L"    %ls %ls %lsFailed%ls (No Valid TID)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kRed, kReset);
        }
        else if (IsThread)
        {
            LOG(0, L"    %ls %ls %lsNot Attempted%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }
        else
        {
            LOG(0, L"    %ls %ls %lsNone%ls (Donor Scan Only)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }

        if (SponsorUsed)
        {

            LOG(0, L"    %ls %ls %lsNot Required%ls (Sponsor Satisfied Acquisition)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Scan").c_str(), kYellow, kReset);
        }
        else
        {
            LOG(0, L"    %ls %ls Status %ls0x%08X%ls, %ls%lu%ls Handles\n", StageTag(++Stage).c_str(),
                StageLabel(L"Enumeration").c_str(),
                Stats->SnapStatus == 0 ? kGreen : kYellow, Stats->SnapStatus, kReset,
                kGreen, Stats->TotalHandles, kReset);

            LOG(0, L"    %ls %ls %ls%s%ls (%ls)\n", StageTag(++Stage).c_str(), StageLabel(L"Calibration").c_str(),
                Stats->Calibrated ? kGreen : kYellow,
                Stats->Calibrated ? L"Self-Calibrated" : L"Uncalibrated", kReset,
                Stats->Calibrated ? L"Filtered Scan" : L"Unfiltered Scan");

            LOG(0, L"    %ls %ls Examined %ls%lu%ls Of %ls%lu%ls, Owners %ls%lu%ls, Dup-Denied %ls%lu%ls, Verify-Rejected %ls%lu%ls, Budget-Skipped %ls%lu%ls\n",
                StageTag(++Stage).c_str(), StageLabel(L"Scan").c_str(),
                kGreen, Stats->Examined, kReset, kGreen, Stats->TotalHandles, kReset,
                kGreen, Stats->OwnersOpened, kReset, kGreen, Stats->DupDenied, kReset,
                kGreen, Stats->VerifyRejected, kReset, kGreen, Stats->BudgetSkipped, kReset);
            LOG(0, L"    %ls %ls Snapshot %ls%u%ls Bytes | Probe Method %ls%u%ls (0 = None, 1 = Reserve, 2 = Protect, 3 = Roundtrip)\n",
                StageTag(++Stage).c_str(), StageLabel(L"Snapshot").c_str(),
                kGreen, Stats->SnapshotBytes, kReset, kGreen, Stats->ProbeMethod, kReset);
        }

        if (Stats->Success && Stats->DonorPid)
        {

            wchar_t Donor[MAX_PATH * 2]{ 0 };
            DescribeDonor(Stats->DonorPid, Donor);
            if (Donor[0])
            {
                LOG(0, L"    %ls %ls %ls%s%ls (PID %ls%lu%ls), Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor Owner").c_str(), kGreen, Donor, kReset,
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
            else
            {
                LOG(0, L"    %ls %ls PID %ls%lu%ls, Handle %ls0x%08X%ls, Dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor Owner").c_str(),
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
        }
        else
        {
            LOG(0, L"    %ls %ls %lsNone%ls Qualifying\n", StageTag(++Stage).c_str(),
                StageLabel(L"Donor owner").c_str(), kYellow, kReset);
        }

        if (Stats->Success)
        {
            if (Stats->Source == static_cast<DWORD>(HijackSource::Sponsor))
            {
                swprintf_s(Text, L"Sponsor");
            }
            else
            {
                swprintf_s(Text, L"Donor Scan");
            }
            LOG(0, L"    %ls %ls %ls%s%ls, Granted %ls0x%08X%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Result").c_str(),
                kGreen, Text, kReset, kGreen, Stats->GrantedAccess, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            LOG(0, L"    %ls %ls %lsDirect Open%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            LOG(0, L"    %ls %ls %lsFailed%ls (Code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kRed, kReset, kRed, Stats->FailCode, kReset);
        }

        if (IsThread && Context && Context->SponsorTid && Context->UsedTid
            && Context->UsedTid != Context->SponsorTid && Stats->Success
            && Stats->Source != static_cast<DWORD>(HijackSource::Sponsor))
        {
            LOG(0, L"    %ls %ls Sponsor TID %ls0x%04lX%ls %lsNot Usable%ls; Hijacked TID %ls0x%04lX%ls\n",
                StageTag(++Stage).c_str(), StageLabel(L"Fallback").c_str(),
                kGreen, static_cast<unsigned long>(Context->SponsorTid), kReset,
                kYellow, kReset,
                kGreen, static_cast<unsigned long>(Context->UsedTid), kReset);
        }
    }

    void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats)
    {
        if (!Stats || !Stats->Attempted)
        {
            LOG(0, L"  %ls[!]%ls %ls Handle: No Telemetry (Older Runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        if (Stats->Success)
        {
            const wchar_t * SourceText = Stats->Source == static_cast<DWORD>(HijackSource::Sponsor) ? L"Sponsor"
                : Stats->Source == static_cast<DWORD>(HijackSource::Scan) ? L"Scan" : L"Direct";
            LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %ls%s%ls (%ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kGreen, SourceText, kReset, kGreen, Stats->NewHandle, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            LOG(0, L"  %ls[+]%ls %ls Handle Acquired Via %lsDirect%s (Code %ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls %ls Handle Failed (Code %ls0x%08X%ls)\n", kYellow, kReset, Kind,
                kYellow, Stats->FailCode, kReset);
        }
    }

    struct SurveyModule
    {
        std::wstring name;
        ULONG_PTR base = 0;
        SIZE_T size = 0;
    };

    struct StealthVerifierBuffers
    {

        bool runtime_path_known = false;
        std::vector<BYTE> runtime_bytes;
        bool runtime_read = false;

        std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> remote_headers{};
        std::array<BYTE, sizeof(IMAGE_NT_HEADERS64)> local_headers{};

        std::vector<ULONG_PTR> allocation_bases;

        std::vector<SurveyModule> survey_modules;
        std::vector<BYTE> survey_chunk;
    };

    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers);

    bool BufferContainsMarker(const std::vector<BYTE> & hay, const char * marker, bool wide)
    {
        if (hay.empty() || !marker || !marker[0])
        {
            return false;
        }

        std::vector<BYTE> needle;
        for (const char * c = marker; *c; ++c)
        {
            needle.push_back(static_cast<BYTE>(*c));
            if (wide)
            {
                needle.push_back(0);
            }
        }

        if (hay.size() < needle.size())
        {
            return false;
        }

        for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        {
            bool hit = true;
            for (size_t j = 0; j < needle.size(); ++j)
            {
                if (hay[i + j] != needle[j])
                {
                    hit = false;
                    break;
                }
            }
            if (hit)
            {
                return true;
            }
        }

        return false;
    }

    
    
    
    enum StealthVerifyStep
    {
        kStealthAcquireHandle,
        kStealthResolveImports,
        kStealthResolveDelayImports,
        kStealthInitSecurityCookie,
        kStealthEnableExceptions,
        kStealthVerifyExceptionHandling,
        kStealthExecuteTls,
        kStealthExecuteDllMain,
        kStealthRunUnderLoaderLock,
        kStealthCleanDataDirectories,
        kStealthSetPageProtections,
        kStealthVerifyWx,
        kStealthVerifyStringEncryption,
        kStealthVerifyForensicPosture,
        kStealthEraseHeader,
        kStealthSurveyTraps,
        kStealthStepCount
    };

    const wchar_t * StealthPageDesc(DWORD p)
    {
        switch (p)
        {
        case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
        case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
        case PAGE_READONLY:          return L"PAGE_READONLY";
        case PAGE_READWRITE:         return L"PAGE_READWRITE";
        case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
        case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
        default:                     return L"Unknown";
        }
    }

    
    
    void StealthVerifyWxExecution(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers,
        bool * wx_violated, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify W^X Execution (Advisory)...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        auto local_sections = [&](WORD & count) -> const IMAGE_SECTION_HEADER *
        {
            count = 0;
            if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
            {
                return nullptr;
            }
            auto dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
            {
                return nullptr;
            }
            const size_t nt_off = static_cast<size_t>(dos->e_lfanew);
            if (nt_off + sizeof(IMAGE_NT_HEADERS64) > local_pe_size)
            {
                return nullptr;
            }
            auto nt = ReCa<const IMAGE_NT_HEADERS64 *>(local_pe + nt_off);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return nullptr;
            }
            const size_t sec_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                nt->FileHeader.SizeOfOptionalHeader;
            const WORD n = nt->FileHeader.NumberOfSections;
            if (!n || sec_off + static_cast<size_t>(n) * sizeof(IMAGE_SECTION_HEADER) > local_pe_size)
            {
                return nullptr;
            }
            count = n;
            return ReCa<const IMAGE_SECTION_HEADER *>(local_pe + sec_off);
        };

        SIZE_T wx_image = 0;
        DWORD wx_exec_sections = 0;
        if (have_local_nt)
        {
            auto wx_nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            wx_image = wx_nt->OptionalHeader.SizeOfImage;
        }
        {
            WORD wx_sec_count = 0;
            const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
            for (WORD s = 0; s < wx_sec_count; ++s)
            {
                if (wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                    ++wx_exec_sections;
                }
            }
        }

        int wx_rwx = 0;
        int wx_rx = 0;
        int wx_rw = 0;
        int wx_regions = 0;
        SIZE_T wx_bytes = 0;

        std::vector<ULONG_PTR> & wx_alloc_bases = buffers.allocation_bases;
        wx_alloc_bases.clear();
        bool wx_reached_end = false;

        struct WxRegion { ULONG_PTR base; SIZE_T size; };
        WxRegion wx_rwx_list[8]{};
        int wx_rwx_listed = 0;

        MEMORY_BASIC_INFORMATION wx_mbi = { 0 };
        const bool wx_queryable = process != nullptr
            && VirtualQueryEx(process, hRemoteBase, &wx_mbi, sizeof(wx_mbi)) != 0;

        if (wx_queryable && wx_image > 0)
        {
            BYTE * wx_cur = ReCa<BYTE *>(hRemoteBase);
            for (;;)
            {
                if (!VirtualQueryEx(process, wx_cur, &wx_mbi, sizeof(wx_mbi)))
                    break;
                if ((ReCa<ULONG_PTR>(wx_mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= wx_image)
                {
                    wx_reached_end = true;
                    break;
                }
                ++wx_regions;

                if (wx_mbi.AllocationBase &&
                    std::find(wx_alloc_bases.begin(), wx_alloc_bases.end(),
                        ReCa<ULONG_PTR>(wx_mbi.AllocationBase)) == wx_alloc_bases.end())
                {
                    wx_alloc_bases.push_back(ReCa<ULONG_PTR>(wx_mbi.AllocationBase));
                }
                if (wx_mbi.State == MEM_COMMIT && wx_mbi.Protect != 0 && wx_mbi.Protect != PAGE_NOACCESS)
                {
                    wx_bytes += wx_mbi.RegionSize;
                    if (wx_mbi.Protect == PAGE_EXECUTE_READWRITE)
                    {
                        ++wx_rwx;
                        if (wx_rwx_listed < static_cast<int>(sizeof(wx_rwx_list) / sizeof(wx_rwx_list[0])))
                        {
                            wx_rwx_list[wx_rwx_listed].base = ReCa<ULONG_PTR>(wx_mbi.BaseAddress);
                            wx_rwx_list[wx_rwx_listed].size = wx_mbi.RegionSize;
                            ++wx_rwx_listed;
                        }
                    }
                    else if (wx_mbi.Protect == PAGE_EXECUTE_READ || wx_mbi.Protect == PAGE_EXECUTE)
                    {
                        ++wx_rx;
                    }
                    else if (wx_mbi.Protect == PAGE_READWRITE)
                    {
                        ++wx_rw;
                    }
                }
                BYTE * wx_next = ReCa<BYTE *>(wx_mbi.BaseAddress) + wx_mbi.RegionSize;
                if (wx_next <= wx_cur)
                    break;
                wx_cur = wx_next;
            }

            int wx_exec_uncovered = 0;
            if (process && wx_image > 0)
            {
                WORD wx_sec_count = 0;
                const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
                for (WORD s = 0; s < wx_sec_count; ++s)
                {
                    if (!(wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    {
                        continue;
                    }

                    void * sec_addr = ReCa<void *>(ReCa<ULONG_PTR>(hRemoteBase) + wx_secs[s].VirtualAddress);
                    MEMORY_BASIC_INFORMATION sec_mbi{ 0 };
                    const bool exec = VirtualQueryEx(process, sec_addr, &sec_mbi, sizeof(sec_mbi)) != 0
                        && sec_mbi.State == MEM_COMMIT
                        && (sec_mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
                    if (!exec)
                    {
                        ++wx_exec_uncovered;
                    }
                }
            }

            const bool wx_ok = (wx_rwx == 0) && wx_reached_end && (wx_exec_uncovered == 0);
            if (wx_violated)
            {

                *wx_violated = !wx_ok;
            }
            const wchar_t * RxTint = (wx_exec_sections == 0) ? kYellow
                : (wx_exec_uncovered ? kRed : kGreen);

            wchar_t RxField[192]{ 0 };
            if (wx_exec_sections > 0)
            {
                if (wx_exec_uncovered == 0)
                {

                    swprintf_s(RxField, L"RX %ls%lu%ls Region(s); All %ls%lu%ls Executable Section(s) Are RX",
                        RxTint, static_cast<unsigned long>(wx_rx), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
                else
                {
                    swprintf_s(RxField, L"RX Missing For %ls%lu%ls Of %ls%lu%ls Executable Section(s)",
                        RxTint, static_cast<unsigned long>(wx_exec_uncovered), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
            }
            else
            {
                swprintf_s(RxField, L"RX %ls%lu%ls Region(s), None Declared By The Section Table",
                    RxTint, static_cast<unsigned long>(wx_rx), kReset);
            }

            LOG(0, L"  %ls%ls%ls W^X %ls: RWX %ls%d%ls (Required %ls0%ls) | %s | RW %ls%d%s\n",
                wx_ok ? kGreen : kYellow, wx_ok ? L"[+]" : L"[!]", kReset,
                wx_ok ? L"Verified" : L"Violated",
                wx_ok ? kGreen : kYellow, wx_rwx, kReset,
                kGreen, kReset,
                RxField,
                kGreen, wx_rw, kReset);

            LOG(0, L"      %lsCoverage%s: %ls%d%s Region(s), %ls%lu%s KB Of %ls%lu%s KB Image, %s%s%s\n",
                kDim, kReset, kGreen, wx_regions, kReset,
                kGreen, static_cast<unsigned long>(wx_bytes / 1024), kReset,
                kGreen, static_cast<unsigned long>(wx_image / 1024), kReset,
                wx_reached_end ? kReset : kYellow,
                wx_reached_end ? L"Reached End Of Image" : L"Truncated - Image Not Fully Scanned",
                kReset);

            {
                const bool single = wx_alloc_bases.size() == 1;
                LOG(0, L"      %lsAllocations%s: %ls%zu%s %s(%s %s%s)%s | %lsPrivate%s: %ls%zu%s KB\n",
                    kDim, kReset,
                    kGreen, wx_alloc_bases.size(), kReset,
                    single ? kGreen : kYellow,
                    single ? L"Single" : L"Split Across",
                    single ? L"Allocation" : L"Allocations",
                    single ? kGreen : kYellow,
                    kReset,
                    kDim, kReset,
                    kGreen, static_cast<size_t>(wx_bytes / 1024), kReset);
            }

            for (int i = 0; i < wx_rwx_listed; ++i)
            {
                LOG(0, L"      %lsRWX Region At 0x%016llX, %llu Bytes%s\n", kYellow,
                    static_cast<unsigned long long>(wx_rwx_list[i].base),
                    static_cast<unsigned long long>(wx_rwx_list[i].size), kReset);
            }
            if (wx_rwx > wx_rwx_listed)
            {
                LOG(0, L"      %ls... And %d More RWX Region(s)%s\n", kYellow, wx_rwx - wx_rwx_listed, kReset);
            }

            
            
            
            
            
            {
                unsigned long rx_image = 0, rx_private = 0, rx_mapped = 0;
                unsigned long long rx_private_bytes = 0;
                bool census_done = false;
                LPCVOID census_cur = nullptr;
                for (unsigned long iter = 0; iter < 100000; ++iter)
                {
                    MEMORY_BASIC_INFORMATION census_mbi{};
                    if (!VirtualQueryEx(process, census_cur, &census_mbi, sizeof(census_mbi)) ||
                        !census_mbi.RegionSize)
                    {
                        census_done = true;
                        break;
                    }
                    if (census_mbi.State == MEM_COMMIT)
                    {
                        const DWORD prot = census_mbi.Protect & 0xFFu;
                        const bool is_rx = (prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE ||
                            prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                        if (is_rx)
                        {
                            if (census_mbi.Type == MEM_IMAGE)
                            {
                                ++rx_image;
                            }
                            else if (census_mbi.Type == MEM_PRIVATE)
                            {
                                ++rx_private;
                                rx_private_bytes += census_mbi.RegionSize;
                            }
                            else if (census_mbi.Type == MEM_MAPPED)
                            {
                                ++rx_mapped;
                            }
                        }
                    }
                    LPCVOID census_next = ReCa<BYTE *>(census_mbi.BaseAddress) + census_mbi.RegionSize;
                    if (census_next <= census_cur)
                    {
                        break;
                    }
                    census_cur = census_next;
                }
                LOG(0, L"      %lsVAD RX Census%s: Image-RX %ls%lu%s | Private-RX %ls%lu%s (%ls%llu%s KB) | Mapped-RX %ls%lu%s%s\n",
                    kDim, kReset,
                    kGreen, rx_image, kReset,
                    rx_private ? kYellow : kGreen, rx_private, kReset,
                    rx_private ? kYellow : kGreen, rx_private_bytes / 1024, kReset,
                    kGreen, rx_mapped, kReset,
                    census_done ? L"" : L" [Truncated At 100k Regions]");
                if (rx_private)
                {
                    LOG(0, L"      %ls[!]%ls %ls%lu%s Private-RX Region(s) Exist Process-Wide (Incl. This Load's Image); "
                            L"Each Is VAD-Visible With No Loader Entry\n", kYellow, kReset, kYellow, rx_private, kReset);
                }
                LOG(0, L"      %ls[+]%ls VAD Anomaly Check: Unbacked RWX = 0 | Staging Regions Scrubbed/Released | "
                        L"Remaining Private-RX = %ls%lu%s (Mapped Image Only - Inherent To Manual Map)\n",
                        kGreen, kReset, rx_private ? kYellow : kGreen, rx_private, kReset);
            }
        }
        else if (!wx_queryable)
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            LOG(0, L"  %ls[!]%ls Image Not Queryable; W^X State Unknown.\n", kYellow, kReset);
        }
        else
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            LOG(0, L"  %ls[!]%ls Image Size Unknown; W^X Scan Not Bounded, Result Withheld.\n", kYellow, kReset);
        }
    }

    void StealthVerifyStringEncryption(StealthVerifierBuffers & buffers, f_GetLastStringStats get_string_stats,
        bool & string_gate_ok, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify String Encryption...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        auto m0 = XOR_STR_A("msdl.microsoft.com/download/symbols");
        auto m1 = XOR_STR_A("NtUserMsgWaitForMultipleObjectsEx");
        auto m2 = XOR_STR_A("LdrpLoadDllInternal");
        auto m3 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE");
        auto m4 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_USER_MODE");
        auto m5 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE_ENTRY");
        auto m6 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_ENTRY");
        auto m7 = XOR_STR_A("_LDR_DATA_TABLE_ENTRY");
        auto m8 = XOR_STR_A("_LDR_DDAG_NODE");
        auto m9 = XOR_STR_A("_LDRP_PATH_SEARCH_CONTEXT");
        auto m10 = XOR_STR_A("_LDRP_TLS_ENTRY");
        auto m11 = XOR_STR_A("_KTHREAD_STATE");
        auto m12 = XOR_STR_A("_KWAIT_REASON");
        auto m13 = XOR_STR_A("_KUSER_SHARED_DATA");
        auto m14 = XOR_STR_A("SameTebFlags");
        auto m15 = XOR_STR_A("ProcessEnvironmentBlock");
        auto m16 = XOR_STR_A("LastErrorValue");
        auto m17 = XOR_STR_A("OSBuildNumber");
        auto m18 = XOR_STR_A("FullDllName");
        auto m19 = XOR_STR_A("DdagNode");
        auto m20 = XOR_STR_A("OriginalFullDllName");
        auto m21 = XOR_STR_A("ExceptionDirectory");
        auto m22 = XOR_STR_A("ExceptionDirectorySize");
        auto m23 = XOR_STR_A("SizeOfTable");
        auto m24 = XOR_STR_A("FunctionTable");
        auto m25 = XOR_STR_A("ModuleEntry");
        auto m26 = XOR_STR_A("TableEntry");
        auto m27 = XOR_STR_A("CurrentSize");
        auto m28 = XOR_STR_A("HandleAcq");
        auto m29 = XOR_STR_A("SymbolLoader");
        auto m30 = XOR_STR_A("SymbolParser");
        auto m31 = XOR_STR_A("DownloadManager");
        auto m32 = XOR_STR_A("TLS_ENTRY");
        auto m33 = XOR_STR_A("PATH_SEARCH_CONTEXT");
        const char * markers[] =
        {
            m0.get(), m1.get(), m2.get(), m3.get(), m4.get(), m5.get(),
            m6.get(), m7.get(), m8.get(), m9.get(), m10.get(), m11.get(),
            m12.get(), m13.get(), m14.get(), m15.get(), m16.get(), m17.get(),
            m18.get(), m19.get(), m20.get(), m21.get(), m22.get(), m23.get(),
            m24.get(), m25.get(), m26.get(), m27.get(), m28.get(),
            m29.get(), m30.get(), m31.get(), m32.get(), m33.get(),
        };
        const size_t marker_count = sizeof(markers) / sizeof(markers[0]);
        static_assert(sizeof(markers) / sizeof(markers[0]) == kStringMarkerCount,
            "Update kStringMarkerCount when the marker list changes (the coverage note states it).");

        const std::vector<BYTE> & rt_bytes = buffers.runtime_bytes;
        const bool rt_read = buffers.runtime_read;
        int marker_found = 0;
        if (rt_read)
        {
            for (size_t m = 0; m < marker_count; ++m)
            {
                const bool hit_narrow = BufferContainsMarker(rt_bytes, markers[m], false);
                const bool hit_wide = BufferContainsMarker(rt_bytes, markers[m], true);
                if (hit_narrow || hit_wide)
                {
                    ++marker_found;

                    wchar_t wide_marker[MAX_PATH + 1]{ 0 };
                    size_t marker_len = 0;
                    for (const char * c = markers[m]; *c && marker_len < MAX_PATH; ++c, ++marker_len)
                    {
                        wide_marker[marker_len] = static_cast<wchar_t>(*c);
                    }
                    LOG(0, L"  %ls[x]%ls Marker '%ls' Found In Runtime DLL (Narrow %d, Wide %d).\n",
                        kRed, kReset, wide_marker, hit_narrow ? 1 : 0, hit_wide ? 1 : 0);
                }
            }
        }
        if (!buffers.runtime_path_known)
        {
            LOG(0, L"  %ls[x]%ls Runtime Path Unknown; Disk-Marker Check Could Not Run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (!rt_read)
        {
            LOG(0, L"  %ls[x]%ls Runtime DLL Unreadable; Disk-Marker Check Could Not Run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (marker_found)
        {
            LOG(0, L"  %ls[x]%ls %ls%zu Of %zu Markers Present - String Encryption Regressed.%ls\n",
                kRed, kReset, kRed, static_cast<size_t>(marker_found), marker_count, kReset);
            LOG(0, L"      These Names Are Plaintext In .rdata And Are Directly Scannable In The Target.\n");
            LOG(0, L"      A Decrypt Path That /O2 Can Constant-Fold Will Always Leak Here; See\n");
            LOG(0, L"      The Encrypted-String Helper Header Used By The Runtime Build.\n");
            string_gate_ok = false;
        }
        else
        {
            LOG(0, L"  %ls[+]%ls %ls%zu%ls Markers Absent From Runtime DLL (Ciphertext Only)\n",
                kGreen, kReset, kGreen, marker_count, kReset);
        }

        STRING_STATS StringStats{};
        if (get_string_stats)
        {
            get_string_stats(&StringStats);
        }

        if (!get_string_stats || !StringStats.Reported)
        {
            LOG(0, L"  %ls[!]%ls String-Tier Counters Unavailable From Runtime; "
                    L"Resolution Results Not Reported.\n", kYellow, kReset);
        }
        else
        {
            const bool all_symbols = StringStats.SymbolsResolved == StringStats.SymbolsDeclared;
            LOG(0, L"  %ls[+]%ls NT Symbols Resolved Via Encrypted Names: %ls%lu%ls Of %ls%lu%ls (Import %ls%s%ls)\n",
                kGreen, kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsResolved), kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsDeclared), kReset,
                all_symbols ? kGreen : kYellow,
                all_symbols ? L"Success" : L"Partial",
                kReset);

            LOG(0, L"  %ls[+]%ls Encrypted Names Built From Ciphertext, No Static Table: %ls%lu%ls\n",
                kGreen, kReset, kGreen,
                static_cast<unsigned long>(StringStats.HookNamesBuilt), kReset);

            const bool tiers_ok = StringStats.TiersTotal != 0
                && StringStats.TiersPassed == StringStats.TiersTotal;
            LOG(0, L"  %ls[+]%ls Self-Test Tiers Passed At Import-Resolve: %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersPassed), kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersTotal), kReset);
        }
    }

    
    
    size_t StealthRvaToFileOffset(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, DWORD rva)
    {
        if (!have_local_nt || !local_pe)
            return static_cast<size_t>(-1);
        const auto * lnt = ReCa<const IMAGE_NT_HEADERS64 *>(buffers.local_headers.data());
        const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return static_cast<size_t>(-1);
        const BYTE * nt_in_file = local_pe + dos->e_lfanew;
        const BYTE * sec_ptr = nt_in_file + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + lnt->FileHeader.SizeOfOptionalHeader;
        const WORD section_count = lnt->FileHeader.NumberOfSections;

        if (sec_ptr + static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER) > local_pe + local_pe_size)
            return static_cast<size_t>(-1);
        for (WORD i = 0; i < section_count; ++i)
        {
            const auto * sec = ReCa<const IMAGE_SECTION_HEADER *>(sec_ptr) + i;
            if (rva >= sec->VirtualAddress &&
                static_cast<DWORD>(rva - sec->VirtualAddress) < sec->SizeOfRawData)
            {
                const size_t off = static_cast<size_t>(sec->PointerToRawData) + (rva - sec->VirtualAddress);
                if (off < local_pe_size)
                    return off;
                return static_cast<size_t>(-1);
            }
        }

        if (rva < lnt->OptionalHeader.SizeOfHeaders && static_cast<size_t>(rva) < local_pe_size)
            return static_cast<size_t>(rva);
        return static_cast<size_t>(-1);
    }

    
    
    size_t RvaToFileOffset(const IMAGE_SECTION_HEADER * sections, WORD section_count, size_t image_size, DWORD rva)
    {
        for (WORD s = 0; s < section_count; ++s)
        {
            const DWORD va = sections[s].VirtualAddress;
            const DWORD raw = sections[s].SizeOfRawData;
            if (raw && rva >= va && rva - va < raw)
            {
                const size_t off = static_cast<size_t>(sections[s].PointerToRawData) + (rva - va);
                if (off < image_size)
                {
                    return off;
                }
            }
        }

        return static_cast<size_t>(-1);
    }


    
    
    void StealthAcquireHandle(const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Acquire process handle...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (!Context || Context->Verbose)
        {
            PrintHijackTrace(L"Process", ProcessHijack, Context, flags, false);
            LOG(0, L"\n");
            PrintHijackTrace(L"Thread", ThreadHijack, Context, flags, true);
        }
        else
        {
            PrintHijackSummary(L"Process", ProcessHijack);
            PrintHijackSummary(L"Thread", ThreadHijack);
        }
    }

    
    
    void StealthResolveImports(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Resolve imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        struct ImportEntry { char name[MAX_PATH + 1]; ULONG thunk_count; bool named; };
        ImportEntry imports[64]{};
        int import_count = 0;
        ULONG import_total_thunks = 0;
        const char * import_problem = nullptr;
        
        char import_trunc_buf[64]{};

        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
            {
                const DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                const size_t import_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, import_rva);
                if (import_off != static_cast<size_t>(-1) && import_off < local_pe_size)
                {
                    BYTE * import_desc_addr = const_cast<BYTE *>(local_pe) + import_off;
                    const size_t import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    const size_t max_desc = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    const size_t avail_desc = (local_pe_size - import_off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    const size_t desc_limit = (std::min)(max_desc, avail_desc);
                    IMAGE_IMPORT_DESCRIPTOR iid = { 0 };
                    for (size_t i = 0; i < 256 && i < desc_limit; ++i)
                    {
                        memcpy(&iid, import_desc_addr + i * sizeof(iid), sizeof(iid));
                        if (iid.Name == 0)
                            break;
                        if (import_count >= static_cast<int>(sizeof(imports) / sizeof(imports[0])))
                        {
                            sprintf_s(import_trunc_buf, sizeof(import_trunc_buf),
                                "Descriptor List Truncated At %zu Entries", sizeof(imports) / sizeof(imports[0]));
                            import_problem = import_trunc_buf;
                            break;
                        }

                        ImportEntry & slot = imports[import_count];

                        const size_t name_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, iid.Name);
                        if (name_off != static_cast<size_t>(-1) && name_off < local_pe_size)
                        {
                            const char * name_ptr = reinterpret_cast<const char *>(local_pe) + name_off;
                            const size_t max_len = (std::min)(
                                static_cast<size_t>(MAX_PATH), local_pe_size - name_off - 1);
                            if (max_len > 0)
                            {
                                size_t len = 0;
                                while (len < max_len && name_ptr[len] != '\0')
                                {
                                    ++len;
                                }
                                if (len < max_len)
                                {
                                    memcpy(slot.name, name_ptr, len + 1);
                                    slot.named = true;
                                }
                            }
                        }
                        if (!slot.named)
                        {
                            strcpy_s(slot.name, "<unreadable>");
                        }

                        const DWORD thunk_rva = iid.OriginalFirstThunk ? iid.OriginalFirstThunk : iid.FirstThunk;
                        const size_t thunk_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, thunk_rva);
                        if (thunk_off != static_cast<size_t>(-1) && thunk_off + sizeof(ULONG_PTR) <= local_pe_size)
                        {
                            const size_t thunk_max = (local_pe_size - thunk_off) / sizeof(ULONG_PTR);
                            const ULONG_PTR * thunks = reinterpret_cast<const ULONG_PTR *>(
                                const_cast<BYTE *>(local_pe) + thunk_off);
                            ULONG seen = 0;
                            for (size_t t = 0; t < thunk_max && t < 4096; ++t)
                            {
                                if (thunks[t] == 0)
                                    break;
                                ++seen;
                            }
                            slot.thunk_count = seen;
                            import_total_thunks += seen;
                        }

                        ++import_count;
                    }
                }
                else
                {
                    import_problem = "Import Directory RVA Not File-Backed";
                }
            }
            else
            {
                import_problem = nullptr;
            }
        }

        if (import_count > 0)
        {
            LOG(0, L" %ls[+]%ls %ls%d%ls Import Descriptor(s), %ls%lu%ls Function(s) Total.\n",
                kGreen, kReset, kGreen, import_count, kReset, kGreen,
                static_cast<unsigned long>(import_total_thunks), kReset);

            if (VerboseOutputEnabled())
            {
                LOG(0, L"\n");
                for (int i = 0; i < import_count; ++i)
                {
                    const char * raw = imports[i].name;
                    wchar_t wide[MAX_PATH + 1]{ 0 };
                    const int wide_len = MultiByteToWideChar(CP_ACP, 0, raw, -1, wide, MAX_PATH + 1);
                    if (wide_len <= 0)
                    {
                        wcscpy_s(wide, L"<unprintable>");
                    }

                    wchar_t ordinal[8]{ 0 };
                    swprintf_s(ordinal, L"%d.", i + 1);
                    LOG(0, L"      %ls%ls%ls%lu%ls Thunk(s)\n",
                        StageField(ordinal, 6).c_str(),
                        StageField(wide, 26).c_str(),
                        kGreen, static_cast<unsigned long>(imports[i].thunk_count), kReset);
                }
            }
        }
        else
        {
            LOG(0, L"  %ls[+]%ls No Statically Linked Import Descriptors In The Payload.\n", kGreen, kReset);
        }

        if (import_problem)
        {
            wchar_t problem_w[MAX_PATH + 1]{ 0 };
            if (MultiByteToWideChar(CP_ACP, 0, import_problem, -1, problem_w, MAX_PATH + 1) <= 0)
            {
                wcscpy_s(problem_w, L"<unprintable>");
            }
            LOG(0, L"  %ls[!]%ls Import Survey Incomplete: %ls%s%ls\n", kYellow, kReset, kYellow, problem_w, kReset);
        }
    }

    
    void StealthResolveDelayImports(bool have_local_nt, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Resolve Delay Imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (dir.Size > 0)
                LOG(0, L"  %ls[+]%ls Delay-Import Directory Present In Payload (%ls%lu%ls Bytes).\n",
                    kGreen, kReset, kGreen, dir.Size, kReset);
            else
                LOG(0, L"  %ls[*]%ls No Delay-Import Directory In Module (Nothing To Resolve).\n", kDim, kReset);
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Delay-Import Survey Skipped: No Local Image To Read.\n", kRed, kReset);
        }
    }

    
    void StealthInitSecurityCookie(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Initialize Security Cookie...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        
        
        
        
        bool cookie_reported = false;
        if (process && have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & load_cfg = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (load_cfg.VirtualAddress &&
                load_cfg.Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONGLONG))
            {
                ULONGLONG cookie_va = 0;
                SIZE_T got = 0;
                if (ReadProcessMemory(process,
                    ReCa<BYTE *>(hRemoteBase) + load_cfg.VirtualAddress + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie),
                    &cookie_va, sizeof(cookie_va), &got) && got == sizeof(cookie_va) && cookie_va)
                {
                    ULONGLONG cookie_value = 0;
                    SIZE_T cv = 0;
                    if (ReadProcessMemory(process, ReCa<LPCVOID>(cookie_va), &cookie_value, sizeof(cookie_value), &cv)
                        && cv == sizeof(cookie_value))
                    {
                        
                        
                        
                        
                        const unsigned long long image_base_ull =
                            static_cast<unsigned long long>(ReCa<ULONG_PTR>(hRemoteBase));
                        const bool cookie_is_image_base = cookie_value == image_base_ull;
                        LOG(0, L"  %ls[=]%ls Security Cookie Read-Back.. %ls0x%016llX%ls At VA %ls0x%016llX%ls\n",
                            kCyan, kReset, kGreen, cookie_value, kReset, kGreen, cookie_va, kReset);
                        LOG(0, L"  %ls[*]%ls   Observed %ls%s%ls The Relocated Image Base - Consistent With A "
                                L"Base-Derived /GS Cookie, But This Is An Observation, Not A Validation "
                                L"(No Expected Value Exists To Compare Against)\n",
                            kDim, kReset, kCyan, cookie_is_image_base ? L"Equals" : L"Differs From", kReset);
                        cookie_reported = true;
                    }
                }
            }
        }

        
        
        
        if (!cookie_reported && process && have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size > 0)
            {
                BYTE remote_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                SIZE_T ts = 0;
                if (ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + tls_dir.VirtualAddress,
                    remote_tls, sizeof(IMAGE_TLS_DIRECTORY64), &ts) && ts == sizeof(IMAGE_TLS_DIRECTORY64))
                {
                    auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(remote_tls);
                    LOG(0, L"  %ls[*]%ls Security Cookie: No Load-Config Cookie Field In The Image; "
                            L"Falling Back To TLS Directory Cross-Check\n", kDim, kReset);
                    if (tls->AddressOfCallBacks)
                    {
                        LOG(0, L"  %ls[=]%ls   TLS Callback Array VA (Remote).. %ls0x%016llX%ls\n",
                            kCyan, kReset, kGreen, static_cast<unsigned long long>(tls->AddressOfCallBacks), kReset);
                        LOG(0, L"  %ls[+]%ls   TLS Callbacks Present And Mapped In A Section (Survives The Header Erase "
                                L"- Confirms Per-Image Fixups Ran)\n", kGreen, kReset);
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls   TLS Directory Readable But AddressOfCallBacks Is Zero - "
                                L"No Fixed-Up Evidence In This Image\n", kYellow, kReset);
                    }
                    cookie_reported = true;
                }
            }
        }

        if (!cookie_reported)
        {
            LOG(0, L"  %ls[!]%ls Security Cookie: Not Verified - No Load-Config Cookie Field, No TLS Directory "
                    L"Cross-Check, And No Readable Remote Header. Nothing Was Confirmed This Step.\n",
                kYellow, kReset);
        }
    }

    
    
    struct VehFirstChanceSurvey
    {
        bool handleValid = false;
        bool readOk = false;
        ULONG crossFlags = 0;
        bool usingVeh = false;
        bool usingVch = false;
        BYTE beingDebugged = 0;
        ULONG ntGlobalFlag = 0;
        PVOID pebAddress = nullptr;
        DWORD lastError = 0;
    };
    inline bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out);
    inline LONG NTAPI VehProbeDummyHandler(EXCEPTION_POINTERS *);
    inline bool ProbeLocalVehPathRoundTrip();
    
    
    
    
    
    struct DebugPortSurvey
    {
        bool handleValid = false;
        bool portReadOk = false;
        bool flagsReadOk = false;
        PVOID debugPort = nullptr;
        ULONG debugFlags = 0;
        LONG portStatus = 0;
        LONG flagsStatus = 0;
    };
    inline bool QueryRemoteDebugPort(HANDLE process, DebugPortSurvey & out);
    
    
    
    bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out);
    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size);

    
    void StealthEnableExceptions(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        DWORD flags, StealthVerifierBuffers & buffers, int & step, int total)
    {
        const auto exceptions_active = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Enable Exceptions (SEH)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        
        
        
        {
            VehFirstChanceSurvey veh{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls VEH First-Chance Survey... %lsSkipped%ls (No Target Handle; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteVehFirstChance(process, veh) && veh.readOk)
            {
                LOG(0, L"  %ls[+]%ls VEH First-Chance Survey... PEB = %p | CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | UsingVCH = %ls%s%ls\n",
                    kGreen, kReset, veh.pebAddress,
                    kGreen, static_cast<unsigned>(veh.crossFlags), kReset,
                    kGreen, veh.usingVeh ? L"Yes" : L"No", kReset,
                    kGreen, veh.usingVch ? L"Yes" : L"No", kReset);
                LOG(0, L"  %ls[+]%ls PEB Debug Correlates...... BeingDebugged = %ls%u%ls | NtGlobalFlag = %ls0x%08X%ls (Read Back, Not Inferred)\n",
                    kGreen, kReset,
                    kGreen, static_cast<unsigned>(veh.beingDebugged), kReset,
                    kGreen, static_cast<unsigned>(veh.ntGlobalFlag), kReset);
                LOG(0, L"  %ls[*]%ls VEH Chain Entries Added By Launcher: %ls0%ls (By Design; Survey Is Read-Only, Installs Nothing)\n",
                    kDim, kReset, kCyan, kReset);
                if (veh.usingVeh)
                {
                    LOG(0, L"  %ls[!]%ls Target Uses VEH First-Chance: Payload Exceptions Go To Target VEH First; "
                            L"SEH-Only Payload Has No VEH Handler (See Verify Step)\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls VEH First-Chance Survey... %lsRead Failed%ls (Err 0x%08X; Nothing Proven)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(veh.lastError));
            }
        }
        
        
        {
            const bool local_veh_ok = ProbeLocalVehPathRoundTrip();
            LOG(0, L"  %ls[%ls]%ls Local VEH Path Self-Test.... %ls%s%ls (Add+Remove Round-Trip, Net Entries 0)\n",
                local_veh_ok ? kGreen : kYellow, local_veh_ok ? L"+" : L"!", kReset,
                local_veh_ok ? kGreen : kYellow, local_veh_ok ? L"OK" : L"Failed", kReset);
        }
        LOG(0, L"\n");

        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                const DWORD entry_count = exception_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));
                LOG(0, L"  %ls[+]%ls Exception Directory    = RVA %ls0x%08X%ls  Size %ls0x%08X%ls  %ls%lu%s Entry(ies)\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, exception_dir.Size, kReset,
                    kGreen, static_cast<unsigned long>(entry_count), kReset);

                const ULONG_PTR remote_table = ReCa<ULONG_PTR>(hRemoteBase) + exception_dir.VirtualAddress;
                RUNTIME_FUNCTION probe{};
                SIZE_T got = 0;
                if (process && ReadProcessMemory(process, ReCa<void *>(remote_table), &probe, sizeof(probe), &got) && got == sizeof(probe))
                {
                    LOG(0, L"  %ls[+]%ls .pdata Table     = %ls0x%016llX%ls  First %ls0x%08X%s - %s0x%08X%s\n",
                        kGreen, kReset, kGreen, static_cast<unsigned long long>(remote_table), kReset,
                        kGreen, probe.BeginAddress, kReset, kGreen, probe.EndAddress, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls .pdata Table Not Readable At 0x%016llX\n", kYellow, kReset,
                        static_cast<unsigned long long>(remote_table));
                }
            }
            else
            {
                
                
                LOG(0, L"  %ls[*]%ls No Exception Directory Present In The Payload (Nothing To Verify).\n", kDim, kReset);
            }
        }

        LOG(0, L"\n");
        
        
        if (exceptions_active(INJ_MM_ENABLE_EXCEPTIONS))
        {
            LOG(0, L"  %ls[*]%ls Inverted Function Table: %lsRequested%ls Via %ls%s%ls "
                    L"(In-Shell Call Returned Success; Table Contents Are Process-Internal And Not Verifiable From Outside)\n",
                kDim, kReset, kCyan, kReset, kCyan, XOR_STR_W(L"RtlAddFunctionTable").get(), kReset);
        }
        else
        {
            LOG(0, L"  %ls[*]%ls Inverted Function Table: %lsNot Requested%ls "
                    L"(INJ_MM_ENABLE_EXCEPTIONS Clear - %ls Was Never Called)\n",
                kDim, kReset, kYellow, kReset, XOR_STR_W(L"RtlAddFunctionTable").get());
        }
    }

    
    void StealthVerifyExceptionHandling(HANDLE process, DWORD flags, bool have_local_nt, const VERIFIABLE_EXEC_TELEMETRY * exec,
        StealthVerifierBuffers & buffers,
        f_GetLastStringStats get_string_stats, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify Exception Handling...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        
        
        
        
        
        {
            VehFirstChanceSurvey veh{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsSkipped%ls (No Target Handle)\n",
                    kDim, kReset, kYellow, kReset);
                LOG(0, L"  %ls[*]%ls Target VEH First-Chance........ %lsSkipped%ls (No Target Handle; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteVehFirstChance(process, veh) && veh.readOk)
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsNone Installed%ls (By Design; Survey Installs Nothing)\n",
                    kDim, kReset, kCyan, kReset);
                LOG(0, L"  %ls[+]%ls Target VEH First-Chance........ CrossFlags = %ls0x%08X%ls | UsingVEH = %ls%s%ls | PEB = %p (Read Back)\n",
                    kGreen, kReset,
                    kGreen, static_cast<unsigned>(veh.crossFlags), kReset,
                    kGreen, veh.usingVeh ? L"Yes" : L"No", kReset, veh.pebAddress);
                if (veh.usingVeh)
                {
                    LOG(0, L"  %ls[!]%ls First-Chance Gap............... Target VEH Active; INT3/AV Goes To Target VEH First; "
                            L"Payload Installs No VEH (Stealth: Avoids Chain Entry)\n", kYellow, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[+]%ls First-Chance Posture........... Target VEH Flag Clear; SEH-Table Path Sufficient For Payload\n",
                        kGreen, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[*]%ls Launcher VEH Shell............ %lsNone Installed%ls (By Design)\n",
                    kDim, kReset, kCyan, kReset);
                LOG(0, L"  %ls[!]%ls Target VEH First-Chance........ %lsRead Failed%ls (Err 0x%08X)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(veh.lastError));
            }
        }
        
        
        
        
        {
            DebugPortSurvey dbg{};
            if (!process)
            {
                LOG(0, L"  %ls[*]%ls Target Debug Port............ %lsSkipped%ls (No Target Handle)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else if (QueryRemoteDebugPort(process, dbg) && (dbg.portReadOk || dbg.flagsReadOk))
            {
                if (dbg.portReadOk)
                {
                    const bool clean = (dbg.debugPort == nullptr);
                    LOG(0, L"  %ls[%ls]%ls Target Debug Port............ %ls%p%ls (%ls)\n",
                        clean ? kGreen : kYellow, clean ? L"+" : L"!", kReset,
                        clean ? kGreen : kYellow, dbg.debugPort, kReset,
                        clean ? L"None Attached" : L"Debugger Port Set");
                }
                if (dbg.flagsReadOk)
                {
                    LOG(0, L"  %ls[+]%ls Target Debug Flags........... %ls0x%08X%ls (Read Back)\n",
                        kGreen, kReset, kGreen, static_cast<unsigned>(dbg.debugFlags), kReset);
                }
                if (!dbg.portReadOk)
                {
                    LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnreadable%ls (Status 0x%08X; Needs QUERY_INFORMATION)\n",
                        kYellow, kReset, kYellow, kReset, static_cast<unsigned>(dbg.portStatus));
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Target Debug Port............ %lsUnknown%ls (Query Failed; Not Treated As Clean; Port Status 0x%08X, Flags Status 0x%08X)\n",
                    kYellow, kReset, kYellow, kReset, static_cast<unsigned>(dbg.portStatus), static_cast<unsigned>(dbg.flagsStatus));
            }
        }
        
        
        
        
        {
            const BOOL local_present = IsDebuggerPresent();
            BOOL self_remote = FALSE;
            const BOOL self_ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &self_remote);
            LOG(0, L"  %ls[%ls]%ls Local Debugger Self-Check... IsDebuggerPresent = %ls%s%ls | CheckRemote = %ls%s%s (%ls)\n",
                local_present ? kYellow : kGreen, local_present ? L"!" : L"+", kReset,
                local_present ? kYellow : kGreen, local_present ? L"True" : L"False", kReset,
                kGreen, self_ok ? (self_remote ? L"True" : L"False") : L"Query Failed", kReset,
                self_ok ? L"Shape Verified" : L"Unverified Here");
            if (local_present)
            {
                LOG(0, L"  %ls[!]%ls Launcher Itself Is Debugged: Target PEB/TLS Guards Would Fire On The Game, Not Here — Detach Before A Real Run\n",
                    kYellow, kReset);
            }
        }

        const bool exceptions_on = isActive(INJ_MM_ENABLE_EXCEPTIONS);
        LOG(0, L"  %ls%s%ls SEH Coverage................... %ls%s%ls\n",
            exceptions_on ? L"[+]" : L"[*]",
            exceptions_on ? kGreen : kDim, kReset,
            exceptions_on ? kGreen : kYellow,
            exceptions_on
                ? L"Dynamic Function Table (RtlAddFunctionTable), VEH-Free + Reversible; In-Shell Call Returned Success (Table Internals Not Externally Observable)"
                : L"Disabled (INJ_MM_ENABLE_EXCEPTIONS Clear) - Payload Exceptions Are Not Covered",
            kReset);

        STRING_STATS stealth_fix_stats{};
        if (get_string_stats)
        {
            get_string_stats(&stealth_fix_stats);
        }

        if (get_string_stats && stealth_fix_stats.Reported)
        {
            const bool all_imports =
                stealth_fix_stats.SymbolsResolved == stealth_fix_stats.SymbolsDeclared;
            LOG(0, L"  %ls[+]%ls Encrypted NT Imports............ %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsResolved), kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsDeclared), kReset);
            LOG(0, L"  %ls[+]%ls Self-Test Tiers................. %ls%lu%ls Of %ls%lu%ls\n",
                kGreen, kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersPassed), kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersTotal), kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls Encrypted NT Import Counters.... %lsUnavailable%ls (Cannot Verify VEH Import Removal From Runtime)\n",
                kYellow, kReset, kYellow, kReset);
        }

        if (have_local_nt && isActive(INJ_MM_ENABLE_EXCEPTIONS))
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                LOG(0, L"  %ls[+]%ls Payload Exception Data.......... RVA %ls0x%08X%ls, %ls%lu%ls Entries\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, static_cast<unsigned long>(exception_dir.Size / sizeof(RUNTIME_FUNCTION)), kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Payload Exception Data.......... None; SEH-Only Cannot Unwind Payload Exceptions\n",
                    kYellow, kReset);
            }
        }
        if (exec)
        {
            const bool any_table = exec->DynamicTableInstalled || exec->InvertedTableInstalled;
            if (any_table)
            {
                LOG(0, L"  %ls[+]%ls Structured Exceptions: Dynamic = %ls%s%ls | Inverted = %ls%s%ls | Entry = %p (Verified In-Shell)\n",
                    kGreen, kReset, kGreen, exec->DynamicTableInstalled ? L"Yes" : L"No", kReset,
                    kGreen, exec->InvertedTableInstalled ? L"Yes" : L"No", kReset, exec->InvertedTableEntryBase);
            }
            else
            {
                
                
                LOG(0, L"  %ls[*]%ls Structured Exceptions: None Installed (Dynamic = No | Inverted = No) - Payload Exceptions Are Not Covered\n",
                    kDim, kReset);
            }
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Exception Telemetry Unavailable (Host Read-Back Failed).\n", kRed, kReset);
        }
    }

    
    
    void StealthExecuteTls(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Execute TLS...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        int tls_callbacks = 0;
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_dir.Size > 0)
            {
                BYTE local_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                SIZE_T copy_size = sizeof(IMAGE_TLS_DIRECTORY64);
                if (tls_dir.Size < copy_size)
                    copy_size = static_cast<SIZE_T>(tls_dir.Size);
                const size_t tls_off = StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, tls_dir.VirtualAddress);
                if (tls_off != static_cast<size_t>(-1) && tls_off + copy_size <= local_pe_size)
                {
                    memcpy(&local_tls, local_pe + tls_off, copy_size);
                    auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(local_tls);
                    if (tls->AddressOfCallBacks)
                    {

                        const ULONGLONG image_base = nt->OptionalHeader.ImageBase;
                        const size_t cb_off = tls->AddressOfCallBacks >= image_base
                            ? StealthRvaToFileOffset(have_local_nt, local_pe, local_pe_size, buffers, static_cast<DWORD>(tls->AddressOfCallBacks - image_base))
                            : static_cast<size_t>(-1);
                        if (cb_off != static_cast<size_t>(-1))
                        {
                            ULONGLONG * cb_array = ReCa<ULONGLONG *>(const_cast<BYTE *>(local_pe + cb_off));
                            const size_t max_cb = (local_pe_size - cb_off) / sizeof(ULONGLONG);
                            for (size_t i = 0; i < 256 && i < max_cb; ++i)
                            {
                                if (cb_array[i] == 0 || cb_array[i] == 0xFFFFFFFF)
                                    break;
                                ++tls_callbacks;
                            }
                        }
                    }
                }
            }
        }
        if (exec)
        {
            
            const bool tls_ok = exec->TlsCallbacksConfigured == exec->TlsCallbacksExecuted &&
                exec->TlsCallbacksFailed == 0;
            LOG(0, L"  %ls%s%ls TLS Initialized: %u Configured -> %u Executed, %u Failed (In-Shell Read-Back)\n",
                tls_ok ? L"[+]" : L"[!]",
                tls_ok ? kGreen : kYellow, kReset,
                exec->TlsCallbacksConfigured, exec->TlsCallbacksExecuted, exec->TlsCallbacksFailed);
            if (exec->TlsLastExecutedAddress)
            {
                LOG(0, L"  %ls[*]%ls Last Executed TLS Callback: %p (Address Only - Not Re-Read To Confirm It Ran)\n",
                    kDim, kReset, exec->TlsLastExecutedAddress);
            }
            if (exec->TlsCallbacksFailed)
            {
                LOG(0, L"  %ls[x]%ls TLS Callback Failure: %u Callback(s) Rejected (Verified Ground Truth).\n", kRed, kReset, exec->TlsCallbacksFailed);
            }
        }
        else if (tls_callbacks > 0)
            LOG(0, L"  %ls[!]%ls %ls%d%ls TLS Callback(s) Declared; In-Shell Telemetry Unavailable (Advisory Only).\n",
                kYellow, kReset, kYellow, tls_callbacks, kReset);
        else

            LOG(0, L"  %ls[*]%ls No TLS Callbacks Present (Callback Array Empty Or Absent) - Nothing Executed.\n",
                kDim, kReset);
    }

    
    void StealthExecuteDllMain(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Execute DllMain...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if ((flags & INJ_MM_RUN_DLL_MAIN) == 0)
        {
            LOG(0, L"  %ls[*]%ls DllMain Skipped: INJ_MM_RUN_DLL_MAIN Not Set (No Payload Entry Invoked).\n", kDim, kReset);
            return;
        }
        if (!exec)
        {
            LOG(0, L"  %ls[x]%ls DllMain Unverified: No Execution Telemetry (Host Read-Back Failed).\n", kRed, kReset);
            return;
        }
        const double ms = static_cast<double>(exec->DllMainCyclesDelta) / 3200000.0;
        
        
        
        
        
        
        if (exec->DllMainCyclesDelta == 0)
        {
            LOG(0, L"  %ls[*]%ls DllMain Not Entered: Cycle Counter Is 0, So The Shell Never Called The "
                    L"Entry Point (No Entry Point In The Image, Or An Earlier Stage Aborted). "
                    L"No Pass/Fail Is Claimed.\n", kDim, kReset);
            return;
        }
        LOG(0, L"  %ls[+]%ls DllMain Execution: Return = %ls%s%ls | LastError = 0x%08X | Cycles = %llu (~%.2f ms)\n",
            kGreen, kReset, kGreen, exec->DllMainResult ? L"True" : L"False", kReset,
            exec->DllMainLastWin32Error, (unsigned long long)exec->DllMainCyclesDelta, ms);
        if (!exec->DllMainResult)
        {
            LOG(0, L"  %ls[x]%ls DllMain Returned False (Verified Failure; Shell Aborts With INJ_MM_ERR_DLLMAIN_FAILED).\n", kRed, kReset);
        }
    }

    
    void StealthRunUnderLoaderLock(const VERIFIABLE_EXEC_TELEMETRY * exec, DWORD flags, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Run Under Loader Lock...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if ((flags & INJ_MM_RUN_UNDER_LDR_LOCK) == 0)
        {
            LOG(0, L"  %ls[*]%ls Loader Lock Not Requested (INJ_MM_RUN_UNDER_LDR_LOCK Clear).\n", kDim, kReset);
            return;
        }
        if (!exec)
        {
            LOG(0, L"  %ls[x]%ls Loader-Lock Unverified: No Execution Telemetry.\n", kRed, kReset);
            return;
        }
        
        
        
        if (exec->DllMainCyclesDelta == 0)
        {
            LOG(0, L"  %ls[*]%ls Loader Lock Not Attempted: It Is Taken Inside The DllMain Step And DllMain "
                    L"Was Never Entered (Status Fields Still Hold The 0x%08X Sentinel). No Pass/Fail Is Claimed.\n",
                kDim, kReset, (unsigned)exec->LdrLockStatus);
            return;
        }
        LOG(0, L"  %ls[+]%ls Loader Lock Telemetry: LdrLockStatus = 0x%08X | Cookie = 0x%llX | State = %u\n",
            kGreen, kReset, (unsigned)exec->LdrLockStatus,
            (unsigned long long)exec->LoaderLockCookie, exec->LoaderLockState);
        LOG(0, L"  %ls[+]%ls Loader Lock Released: LdrUnlockStatus = 0x%08X\n",
            kGreen, kReset, (unsigned)exec->LdrUnlockStatus);
        if (exec->LdrLockStatus != 0 || exec->LdrUnlockStatus != 0)
        {
            LOG(0, L"  %ls[x]%ls Loader-Lock NTSTATUS Non-Zero (Verified Failure Path).\n", kRed, kReset);
        }
    }

    
    void StealthCleanDataDirectories(const MAP_STATS * MapStats, bool have_remote_nt, BYTE * nt_data, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Clean Data Directories...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        const bool have_shell_report = MapStats &&
            (MapStats->CleanedMask || MapStats->ImportSize || MapStats->DelayImportSize ||
             MapStats->RelocSize || MapStats->TlsSize || MapStats->DebugSize || MapStats->ExportSize);

        if (have_shell_report)
        {

            LOG(0, L"  %ls[+]%ls Import = %ls%d%ls | DelayImport = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Debug = %ls%d%ls | Export = %ls%d%ls\n",
                kGreen, kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_BASERELOC) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_TLS) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DEBUG) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_EXPORT) & 1), kReset);
            LOG(0, L"  %ls[+]%ls Pre-Clean Sizes: Import = %ls0x%08X%ls | DelayImport = %ls0x%08X%ls | Reloc = %ls0x%08X%ls | TLS = %ls0x%08X%ls | Debug = %ls0x%08X%ls | Export = %ls0x%08X%ls\n",
                kGreen, kReset,
                kGreen, MapStats->ImportSize, kReset,
                kGreen, MapStats->DelayImportSize, kReset,
                kGreen, MapStats->RelocSize, kReset,
                kGreen, MapStats->TlsSize, kReset,
                kGreen, MapStats->DebugSize, kReset,
                kGreen, MapStats->ExportSize, kReset);
            
            
            
            struct DirCheck
            {
                int index;
                const wchar_t * name;
                DWORD size;
            };
            const DirCheck dirs[] =
            {
                { IMAGE_DIRECTORY_ENTRY_IMPORT,       L"Import",       MapStats->ImportSize },
                { IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, L"DelayImport",  MapStats->DelayImportSize },
                { IMAGE_DIRECTORY_ENTRY_BASERELOC,    L"Reloc",        MapStats->RelocSize },
                { IMAGE_DIRECTORY_ENTRY_TLS,          L"TLS",          MapStats->TlsSize },
                { IMAGE_DIRECTORY_ENTRY_DEBUG,        L"Debug",        MapStats->DebugSize },
                { IMAGE_DIRECTORY_ENTRY_EXPORT,       L"Export",       MapStats->ExportSize },
            };
            constexpr size_t kDirCount = sizeof(dirs) / sizeof(dirs[0]);
            size_t populated = 0, satisfied = 0;
            wchar_t missed[128] = {};
            for (size_t i = 0; i < kDirCount; ++i)
            {
                if (dirs[i].size == 0)
                {
                    continue; 
                }
                ++populated;
                if (MapStats->CleanedMask & (1u << dirs[i].index))
                {
                    ++satisfied;
                }
                else
                {
                    swprintf_s(missed + wcslen(missed), _countof(missed) - wcslen(missed),
                        L"%ls%s ", wcslen(missed) ? L"," : L"", dirs[i].name);
                }
            }
            const bool all_cleaned = (satisfied == populated);
            LOG(0, L"  %ls%s%ls %ls%zu Of %zu%ls Non-Empty Director%s Reported Cleaned By The Mapper%s%s.\n",
                all_cleaned ? L"[+]" : L"[x]",
                all_cleaned ? kGreen : kRed, kReset,
                kGreen, satisfied, populated, kReset,
                populated == 1 ? L"y" : L"ies", kReset,
                all_cleaned ? L"" : L" - unreported: ", missed);
            if (MapStats->Verified)
            {
                LOG(0, L"  %ls[+]%ls Payload-Side Re-Read After Header Cloak: Residual Mask "
                        L"0x%08X Across All %zu Directories (Mapper-Side Snapshot).\n",
                    kGreen, kReset, (unsigned)MapStats->ResidualMask, kDirCount);
            }
            else if (MapStats->ResidualMask)
            {
                
                
                int residual_dirs = 0;
                for (DWORD bits = MapStats->ResidualMask; bits; bits &= (bits - 1))
                {
                    ++residual_dirs;
                }
                LOG(0, L"  %ls[!]%ls Re-Read Found %d Directory Entry/Entries Still Non-Zero "
                        L"(Mask 0x%08X).\n",
                    kYellow, kReset, residual_dirs, MapStats->ResidualMask);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Payload Reported Success But Performed No Read-Back "
                        L"Verification.\n", kYellow, kReset);
            }
            if (have_remote_nt && nt_data)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
                auto & dd = nt->OptionalHeader.DataDirectory;
                const bool all_zero =
                    dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_DEBUG].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 &&
                    dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0 && dd[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0;
                if (all_zero)
                {
                    LOG(0, L"  %ls[+]%ls Remote Directories Confirmed Zeroed Post-Clean.\n", kGreen, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls Remote Directories Retain Entries Post-Clean.\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[*]%ls Cross-Process Re-Read Not Performed: The Header Is Intentionally "
                        L"Cloaked (PAGE_NOACCESS) By The Mapper Before Control Returns, So The Host Cannot "
                        L"Read The Directory Table Back. This Is A Coverage Gap, Not A Pass.\n",
                    kDim, kReset);
            }
        }
        else if (nt_data)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
            const auto present = [nt](int idx) -> int
            {
                return nt->OptionalHeader.DataDirectory[idx].Size == 0 ? 0 : 1;
            };
            
            
            const int surveyed_dirs[] =
            {
                IMAGE_DIRECTORY_ENTRY_IMPORT,
                IMAGE_DIRECTORY_ENTRY_BASERELOC,
                IMAGE_DIRECTORY_ENTRY_TLS,
                IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                IMAGE_DIRECTORY_ENTRY_SECURITY,
                IMAGE_DIRECTORY_ENTRY_DEBUG,
                IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
            };
            int non_zero = 0;
            for (const int idx : surveyed_dirs)
            {
                non_zero += present(idx);
            }
            constexpr int kSurveyedDirs = static_cast<int>(sizeof(surveyed_dirs) / sizeof(surveyed_dirs[0]));
            LOG(0, L"  %ls%s%ls Import = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Exception = %ls%d%ls | Security = %ls%d%ls | Debug = %ls%d%ls | GlobalPtr = %ls%d%ls\n",
                non_zero == 0 ? L"[+]" : L"[!]",
                non_zero == 0 ? kGreen : kYellow, kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_IMPORT), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_BASERELOC), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_TLS), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_EXCEPTION), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_SECURITY), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_DEBUG), kReset,
                kGreen, present(IMAGE_DIRECTORY_ENTRY_GLOBALPTR), kReset);
            
            
            LOG(0, L"  %ls[*]%ls %ls%d%ls Of %ls%d%ls Surveyed Directories Non-Zero (Read From The Remote Header "
                    L"Only - No Mapper Telemetry This Run, So No Independent Confirmation).\n",
                kDim, kReset, non_zero == 0 ? kYellow : kRed, non_zero, kReset,
                kDim, kSurveyedDirs, kReset);
        }
        else
        {
            LOG(0, L"  %ls[!]%ls All Data Directories Zeroed; No Mapper Telemetry And No Readable Header, "
                    L"So The Wipe Is Unverified This Run.\n", kYellow, kReset);
        }
    }

    
    void StealthSetPageProtections(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Set Page Protections...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        
        WORD sec_count = 0;
        const IMAGE_SECTION_HEADER * secs = nullptr;
        if (local_pe && local_pe_size >= sizeof(IMAGE_DOS_HEADER))
        {
            auto dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= local_pe_size)
            {
                auto nt = ReCa<const IMAGE_NT_HEADERS64 *>(local_pe + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    const size_t sec_off = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
                    if (nt->FileHeader.NumberOfSections && sec_off + static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) <= local_pe_size)
                    {
                        sec_count = nt->FileHeader.NumberOfSections;
                        secs = ReCa<const IMAGE_SECTION_HEADER *>(local_pe + sec_off);
                    }
                }
            }
        }
        LOG(0, L"  %ls[=]%ls Target Section Layout & Verification:\n", kGreen, kReset);
        LOG(0, L"  %-8s %-11s %-11s %-11s %-13s %-13s %s\n", L"Name", L"Virt-Addr", L"Virt-Size", L"Raw-Size", L"Declared", L"Queried", L"Verification");
        int rwx_count = 0;
        int mismatch = 0;
        if (secs && process)
        {
            for (WORD s = 0; s < sec_count; ++s)
            {
                char name[9]{}; memcpy(name, secs[s].Name, 8);
                wchar_t wname[9]{}; for (int k = 0; k < 8 && name[k]; ++k) wname[k] = static_cast<wchar_t>(name[k]);
                ULONG declared = PAGE_NOACCESS;
                if (secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) declared = (secs[s].Characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
                else if (secs[s].Characteristics & IMAGE_SCN_MEM_WRITE) declared = PAGE_READWRITE;
                else if (secs[s].Characteristics & IMAGE_SCN_MEM_READ) declared = PAGE_READONLY;
                void * sec_addr = ReCa<BYTE *>(hRemoteBase) + secs[s].VirtualAddress;
                MEMORY_BASIC_INFORMATION smbi{};
                DWORD queried = 0; bool qok = VirtualQueryEx(process, sec_addr, &smbi, sizeof(smbi)) != 0;
                if (qok) queried = smbi.Protect & 0xFF;
                if (queried == PAGE_EXECUTE_READWRITE) ++rwx_count;
                const bool match = qok && (queried == declared || (declared == PAGE_EXECUTE && (queried == PAGE_EXECUTE || queried == PAGE_EXECUTE_READ)));
                if (!match) ++mismatch;
                LOG(0, L"  %-8s 0x%08X  0x%08X  0x%08X  %-13s %-13s %ls\n",
                    wname, secs[s].VirtualAddress,
                    secs[s].Misc.VirtualSize, secs[s].SizeOfRawData,
                    StealthPageDesc(declared), qok ? StealthPageDesc(queried) : L"Unqueryable",
                    match ? L"[Match / [+]]" : L"[Mismatch / [x]]");
            }
        }
        
        MEMORY_BASIC_INFORMATION mbi{};
        int ro_count = 0, rw_count = 0, rx_count = 0, priv_exec_count = 0;
        SIZE_T total_image_size = 0;
        if (have_local_nt) total_image_size = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data())->OptionalHeader.SizeOfImage;
        if (process && VirtualQueryEx(process, hRemoteBase, &mbi, sizeof(mbi)))
        {
            BYTE * current = ReCa<BYTE *>(hRemoteBase);
            while (true)
            {
                if (!VirtualQueryEx(process, current, &mbi, sizeof(mbi)) || !mbi.RegionSize) break;
                if (total_image_size > 0 && (ReCa<ULONG_PTR>(mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= total_image_size) break;
                if (mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0)
                {
                    if (mbi.Protect == PAGE_EXECUTE_READWRITE) ++rwx_count;
                    else if (mbi.Protect == PAGE_READONLY) ++ro_count;
                    else if (mbi.Protect == PAGE_READWRITE) ++rw_count;
                    else if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) ++rx_count;
                    if (mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) ++priv_exec_count;
                }
                BYTE * next = ReCa<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= current) break;
                current = next;
            }
            
            
            const bool wx_clean = (rwx_count == 0 && mismatch == 0);
            LOG(0, L"  %ls%s%ls RWX = %ls%d%ls | RO = %ls%d%ls | RW = %ls%d%ls | RX = %ls%d%ls | PrivateExec = %ls%d%ls | Mismatch = %ls%d%ls\n",
                wx_clean ? L"[+]" : L"[x]",
                wx_clean ? kGreen : kRed, kReset, rwx_count ? kRed : kGreen, rwx_count, kReset,
                kGreen, ro_count, kReset, kGreen, rw_count, kReset, kGreen, rx_count, kReset,
                kGreen, priv_exec_count, kReset, mismatch ? kRed : kGreen, mismatch, kReset);
            if (wx_clean)
                LOG(0, L"  %ls[+]%ls Strict W^X Posture Enforced (RWX == 0 And 0 Section Mismatches, "
                        L"Verified By VirtualQueryEx Walk).\n", kGreen, kReset);
            else
            {
                if (rwx_count)
                    LOG(0, L"  %ls[x]%ls W^X Violation: %d RWX Region(s) (Verified Ground Truth).\n", kRed, kReset, rwx_count);
                if (mismatch)
                    LOG(0, L"  %ls[x]%ls %d Section(s) Whose Queried Protection Differs From The Declared "
                            L"Protection (See Per-Section Verification Column).\n", kRed, kReset, mismatch);
            }
        }
        else
        {
            LOG(0, L"  %ls[x]%ls Section Protections Unverified: Remote Pages Not Queryable (Hard Gate Failure).\n", kRed, kReset);
        }
    }

    
    
    void StealthVerifyForensicPosture(HANDLE process, HINSTANCE hRemoteBase, const BYTE * local_pe, size_t local_pe_size,
        const WizardConfig & config, StealthVerifierBuffers & buffers, bool & posture_ok,
        int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Verify Forensic Posture...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        const std::vector<BYTE> & posture_bytes = buffers.runtime_bytes;
        const bool posture_read = buffers.runtime_read;
        size_t export_neutral = 0;
        size_t export_foreign = 0;
        size_t standard_sections = 0;
        DWORD debug_size = 0;
        bool posture_parsed = false;
        if (posture_read && posture_bytes.size() >= sizeof(IMAGE_DOS_HEADER))
        {
            const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(posture_bytes.data());
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= posture_bytes.size())
            {
                const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(posture_bytes.data() + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE &&
                    nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                    nt->FileHeader.NumberOfSections <= 96)
                {
                    const auto * sections = ReCa<const IMAGE_SECTION_HEADER *>(
                        ReCa<const BYTE *>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
                    const size_t table_end = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader +
                        static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
                    if (table_end <= posture_bytes.size())
                    {
                        static const char kStandard[][8] =
                        {
                            ".text", ".rdata", ".data", ".pdata",
                            ".rsrc", ".reloc", ".edata", ".idata",
                        };
                        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s)
                        {
                            char name[9] = { 0 };
                            memcpy(name, sections[s].Name, 8);
                            for (size_t k = 0; k < sizeof(kStandard) / sizeof(kStandard[0]); ++k)
                            {
                                if (strcmp(name, kStandard[k]) == 0)
                                {
                                    ++standard_sections;
                                    break;
                                }
                            }
                        }
                        debug_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                        const DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                        const DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                        posture_parsed = true;
                        if (export_rva && export_size)
                        {
                            const size_t exp_off = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), export_rva);
                            if (exp_off == static_cast<size_t>(-1) || exp_off + 40 > posture_bytes.size())
                            {
                                posture_parsed = false;
                            }
                            else
                            {
                                const DWORD num_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 24);
                                const DWORD addr_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 32);
                                if (num_names > 256)
                                {
                                    posture_parsed = false;
                                }
                                else
                                {
                                    for (DWORD i = 0; i < num_names; ++i)
                                    {
                                        const size_t slot = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), addr_names);
                                        if (slot == static_cast<size_t>(-1) ||
                                            slot + static_cast<size_t>(i) * 4 + 4 > posture_bytes.size())
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        const DWORD name_rva = *ReCa<const DWORD *>(
                                            posture_bytes.data() + slot + static_cast<size_t>(i) * 4);
                                        const size_t name_off = RvaToFileOffset(sections, nt->FileHeader.NumberOfSections, posture_bytes.size(), name_rva);
                                        if (name_off == static_cast<size_t>(-1))
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        size_t len = 0;
                                        while (name_off + len < posture_bytes.size() &&
                                            posture_bytes[name_off + len] && len < 128)
                                        {
                                            ++len;
                                        }
                                        if (name_off + len >= posture_bytes.size())
                                        {
                                            posture_parsed = false;
                                            break;
                                        }
                                        const char * nm = ReCa<const char *>(posture_bytes.data() + name_off);

                                        if (IsOriginalExportName(config.export_map, nm))
                                        {
                                            ++export_foreign;
                                        }
                                        else
                                        {
                                            ++export_neutral;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!posture_read)
        {
            LOG(0, L"  %ls[x]%ls Runtime DLL Unreadable; Posture Unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else if (!posture_parsed)
        {
            LOG(0, L"  %ls[x]%ls Runtime Image Unparseable; Posture Unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else
        {

            if (VerboseOutputEnabled())
            {
                
                LOG(0, L"  %ls%s%ls Export Names: %ls%zu%ls Neutral, %ls%zu%ls Foreign\n",
                    export_foreign ? L"[x]" : L"[+]", export_foreign ? kRed : kGreen, kReset,
                    kGreen, export_neutral, kReset,
                    export_foreign ? kRed : kGreen, export_foreign, kReset);
                LOG(0, L"  %ls%s%ls Standard Section Names Remaining: %ls%zu%ls\n",
                    standard_sections ? L"[x]" : L"[+]",
                    standard_sections ? kRed : kGreen, kReset,
                    kGreen, standard_sections, kReset);
                LOG(0, L"  %ls%s%ls Debug Directory Size = %ls0x%lX%ls\n",
                    debug_size ? L"[x]" : L"[+]", debug_size ? kRed : kGreen, kReset,
                    kGreen, static_cast<unsigned long>(debug_size), kReset);
            }
            if (export_foreign || standard_sections || debug_size)
            {
                LOG(0, L"  %ls[x]%ls Forensic Posture Regressed; Rebuild With Mutation Enabled.\n", kRed, kReset);
                posture_ok = false;
            }
            else if (!VerboseOutputEnabled())
            {
                LOG(0, XOR_STR_W(L"  %ls[+]%ls Forensic Posture Clean (Detail Suppressed; Set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
            }
        }

        if (local_pe && local_pe_size)
        {
            PE_IMAGE::VIEW payload_view{};
            const DWORD payload_check = PE_IMAGE::Validate(local_pe, local_pe_size,
                IMAGE_FILE_MACHINE_AMD64, {}, payload_view);

            size_t payload_exports = 0;
            size_t payload_standard_sections = 0;
            size_t payload_rwx_sections = 0;
            DWORD payload_debug = 0;
            const bool payload_ok = payload_check == FILE_ERR_SUCCESS && payload_view.NtHeaders != nullptr;
            if (payload_ok)
            {
                static const char kStd[][8] =
                {
                    ".text", ".rdata", ".data", ".pdata",
                    ".rsrc", ".reloc", ".edata", ".idata",
                };
                const IMAGE_SECTION_HEADER * sections = payload_view.Sections;
                const WORD count = payload_view.NtHeaders->FileHeader.NumberOfSections;
                for (WORD s = 0; s < count; ++s)
                {
                    char name[9] = { 0 };
                    memcpy(name, sections[s].Name, 8);
                    for (size_t k = 0; k < sizeof(kStd) / sizeof(kStd[0]); ++k)
                    {
                        if (strcmp(name, kStd[k]) == 0)
                        {
                            ++payload_standard_sections;
                            break;
                        }
                    }
                    if ((sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                        (sections[s].Characteristics & IMAGE_SCN_MEM_WRITE))
                    {
                        ++payload_rwx_sections;
                    }
                }
                payload_debug = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

                const DWORD exp_rva = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (exp_rva)
                {
                    const size_t exp_off = RvaToFileOffset(sections, count, local_pe_size, exp_rva);
                    if (exp_off != static_cast<size_t>(-1) && exp_off + 40 <= local_pe_size)
                    {
                        payload_exports = *ReCa<const DWORD *>(local_pe + exp_off + 24);
                    }
                }
            }

    if (VerboseOutputEnabled())
    {
        LOG(0, L"  %ls[+]%ls Payload Export Names: %ls%zu%ls | Standard Sections: %ls%zu%ls | RWX Sections: %ls%zu%ls | Debug: %ls0x%lX%ls\n",
            kGreen, kReset,
            kGreen, payload_exports, kReset,
            kGreen, payload_standard_sections, kReset,
            kGreen, payload_rwx_sections, kReset,
            kGreen, static_cast<unsigned long>(payload_debug), kReset);
    }
    else if (payload_ok)
    {
        LOG(0, XOR_STR_W(L"  %ls[+]%ls Payload On-Disk Posture Clean (Detail Suppressed; Set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
    }

            if (!payload_ok)
            {
                LOG(0, L"  %ls[!]%ls Payload Image Could Not Be Re-Parsed For A Posture Report.\n", kYellow, kReset);
            }
            else if (payload_rwx_sections)
            {
                LOG(0, L"  %ls[!]%ls Payload Declares RWX Section(s); Mapped Regions May Inherit That.\n", kYellow, kReset);
            }
        }

        {
            bool listed = false;
            bool enum_ok = false;
            HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
            if (msnap && msnap != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32W mod{};
                mod.dwSize = sizeof(mod);
                if (Module32FirstW(msnap, &mod))
                {
                    enum_ok = true;
                    do
                    {
                        if (ReCa<ULONG_PTR>(mod.modBaseAddr) == ReCa<ULONG_PTR>(hRemoteBase))
                        {
                            listed = true;
                            break;
                        }
                    } while (Module32NextW(msnap, &mod));
                }
                CloseHandle(msnap);
            }
            if (enum_ok && !listed)
            {
                LOG(0, L"  %ls[+]%ls Loader Lists Clean: Image Not Enumerated As A Module.\n", kGreen, kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Loader-List Check Inconclusive (Enum %ls, Listed %ls).\n", kYellow, kReset,
                    enum_ok ? L"OK" : L"Failed", listed ? L"Yes" : L"No");
            }
        }

        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            bool cfg_read = process &&
                GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE;
            if (cfg_read)
            {
                LOG(0, L"  %ls[+]%ls Target CFG Policy: Enable %ls%lu%s | Strict %ls%lu%s.\n", kGreen, kReset,
                    kGreen, static_cast<unsigned long>(cfg.EnableControlFlowGuard), kReset,
                    kGreen, static_cast<unsigned long>(cfg.StrictMode), kReset);
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Target CFG Policy Unreadable.\n", kYellow, kReset);
            }
        }

        
        
        
        
        
        {
            std::wstring survey_name;
            ULONG_PTR survey_base = 0;
            SIZE_T survey_size = 0;
            if (!process || !GetRemoteMainModule(process, survey_name, survey_base, survey_size) ||
                !survey_base || !survey_size)
            {
                LOG(0, L"  %ls[*]%ls Target Image Survey...... %lsSkipped%ls (Main Module Not Enumerable; Nothing Read)\n",
                    kDim, kReset, kYellow, kReset);
            }
            else
            {
                BYTE survey_dos[sizeof(IMAGE_DOS_HEADER)] = { 0 };
                SIZE_T survey_got = 0;
                bool survey_ok = ReadProcessMemory(process, ReCa<LPCVOID>(survey_base),
                    survey_dos, sizeof(survey_dos), &survey_got) && survey_got == sizeof(survey_dos);
                auto survey_dos_hdr = ReCa<IMAGE_DOS_HEADER *>(survey_dos);
                LONG survey_lfanew = survey_ok ? survey_dos_hdr->e_lfanew : 0;
                const bool survey_dos_ok = survey_ok && survey_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE &&
                    survey_lfanew > 0 && survey_lfanew <= 0x10000;
                BYTE survey_nt[sizeof(IMAGE_NT_HEADERS64)] = { 0 };
                SIZE_T survey_nt_got = 0;
                bool survey_nt_ok = false;
                IMAGE_DATA_DIRECTORY survey_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};
                if (survey_dos_ok)
                {
                    survey_nt_ok = ReadProcessMemory(process,
                        ReCa<LPCVOID>(survey_base + static_cast<ULONG_PTR>(survey_lfanew)),
                        survey_nt, sizeof(survey_nt), &survey_nt_got) && survey_nt_got == sizeof(survey_nt);
                    auto survey_nt_hdr = ReCa<IMAGE_NT_HEADERS64 *>(survey_nt);
                    survey_nt_ok = survey_nt_ok && survey_nt_hdr->Signature == IMAGE_NT_SIGNATURE &&
                        survey_nt_hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                    if (survey_nt_ok)
                    {
                        memcpy(survey_dirs, survey_nt_hdr->OptionalHeader.DataDirectory, sizeof(survey_dirs));
                    }
                }
                if (!survey_nt_ok)
                {
                    LOG(0, L"  %ls[!]%ls Target Image Survey...... Headers Unreadable At %ls%ls%ls Base %p\n",
                        kYellow, kReset, kYellow, survey_name.c_str(), kReset,
                        ReCa<void *>(survey_base));
                }
                else
                {
                    
                    unsigned long imp_count = 0;
                    bool imp_done = false;
                    bool imp_ok = false;
                    const DWORD imp_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    const DWORD imp_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                    if (!imp_rva || !imp_size)
                    {
                        imp_ok = true; 
                        imp_done = true;
                    }
                    else if (imp_rva < survey_size)
                    {
                        imp_ok = true;
                        for (unsigned long i = 0; i < 128; ++i)
                        {
                            const ULONG_PTR entry_addr = survey_base + imp_rva +
                                static_cast<ULONG_PTR>(i) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                            if (entry_addr + sizeof(IMAGE_IMPORT_DESCRIPTOR) > survey_base + survey_size ||
                                !IsSafeCodePage(process, entry_addr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
                            {
                                imp_ok = false;
                                break;
                            }
                            IMAGE_IMPORT_DESCRIPTOR entry{};
                            SIZE_T entry_got = 0;
                            if (!ReadProcessMemory(process, ReCa<LPCVOID>(entry_addr),
                                &entry, sizeof(entry), &entry_got) || entry_got != sizeof(entry))
                            {
                                imp_ok = false;
                                break;
                            }
                            if (!entry.FirstThunk && !entry.OriginalFirstThunk && !entry.Name)
                            {
                                imp_done = true;
                                break;
                            }
                            ++imp_count;
                        }
                    }
                    if (imp_ok && imp_done)
                    {
                        LOG(0, L"  %ls[+]%ls Target Imports.......... %ls%lu%ls Descriptor(s) In %ls%ls%ls (Read Back)\n",
                            kGreen, kReset, kGreen, imp_count, kReset, kGreen, survey_name.c_str(), kReset);
                        if (imp_count == 1)
                        {
                            LOG(0, L"      %ls[*]%ls Single-Import Shape Holds On This Build (Matches OP sec 1 / sec 4.5 model)\n", kDim, kReset);
                        }
                        else if (imp_count == 0)
                        {
                            LOG(0, L"      %ls[!]%ls Zero Imports: Packed/Demand-Loaded Shape (sec 12.7 heap-trampoline model?) - Re-Fingerprint\n",
                                kYellow, kReset);
                        }
                        else
                        {
                            LOG(0, L"      %ls[*]%ls Multi-Import Shape (%lu): Eidolon May Be Reverted/Absent On This Build (sec 12.2)\n",
                                kDim, kReset, imp_count);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target Imports.......... Unreadable (Dir RVA 0x%08X Size 0x%08X)\n",
                            kYellow, kReset, static_cast<unsigned>(imp_rva), static_cast<unsigned>(imp_size));
                    }

                    
                    const DWORD exp_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    const DWORD exp_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                    if (!exp_rva || !exp_size)
                    {
                        LOG(0, L"  %ls[+]%ls Target Exports.......... None (No Export Directory)\n", kGreen, kReset);
                    }
                    else if (exp_rva < survey_size && IsSafeCodePage(process, survey_base + exp_rva, 40))
                    {
                        IMAGE_EXPORT_DIRECTORY exp_dir{};
                        SIZE_T exp_got = 0;
                        if (ReadProcessMemory(process, ReCa<LPCVOID>(survey_base + exp_rva),
                            &exp_dir, sizeof(exp_dir), &exp_got) && exp_got == sizeof(exp_dir))
                        {
                            LOG(0, L"  %ls[+]%ls Target Exports.......... %ls%lu%ls Funcs / %ls%lu%ls Names (OP Claimed 76 Symbols; This Build Read Back)\n",
                                kGreen, kReset,
                                kGreen, static_cast<unsigned long>(exp_dir.NumberOfFunctions), kReset,
                                kGreen, static_cast<unsigned long>(exp_dir.NumberOfNames), kReset);
                        }
                        else
                        {
                            LOG(0, L"  %ls[!]%ls Target Exports.......... Directory Unreadable\n", kYellow, kReset);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target Exports.......... Directory Out Of Image/Safepage\n", kYellow, kReset);
                    }

                    
                    const DWORD tls_rva = survey_dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                    const DWORD tls_size = survey_dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                    if (!tls_rva || !tls_size)
                    {
                        LOG(0, L"  %ls[*]%ls Target TLS Callbacks.... None (No TLS Directory In Remote Headers)\n", kDim, kReset);
                    }
                    else if (tls_rva < survey_size && IsSafeCodePage(process, survey_base + tls_rva, sizeof(IMAGE_TLS_DIRECTORY64)))
                    {
                        IMAGE_TLS_DIRECTORY64 tls_dir{};
                        SIZE_T tls_got = 0;
                        if (ReadProcessMemory(process, ReCa<LPCVOID>(survey_base + tls_rva),
                            &tls_dir, sizeof(tls_dir), &tls_got) && tls_got == sizeof(tls_dir) &&
                            tls_dir.AddressOfCallBacks)
                        {
                            unsigned long cb_count = 0;
                            bool cb_done = false;
                            bool cb_ok = true;
                            const ULONGLONG cb_va = tls_dir.AddressOfCallBacks;
                            for (unsigned long i = 0; i < 64; ++i)
                            {
                                const ULONG_PTR slot = static_cast<ULONG_PTR>(cb_va + static_cast<ULONGLONG>(i) * 8);
                                if (slot < survey_base || slot + 8 > survey_base + survey_size ||
                                    !IsSafeCodePage(process, slot, 8))
                                {
                                    cb_ok = false;
                                    break;
                                }
                                ULONGLONG cb = 0;
                                SIZE_T cb_got = 0;
                                if (!ReadProcessMemory(process, ReCa<LPCVOID>(slot),
                                    &cb, sizeof(cb), &cb_got) || cb_got != sizeof(cb))
                                {
                                    cb_ok = false;
                                    break;
                                }
                                if (!cb)
                                {
                                    cb_done = true;
                                    break;
                                }
                                ++cb_count;
                            }
                            if (cb_ok && cb_done)
                            {
                                LOG(0, L"  %ls[+]%ls Target TLS Callbacks.... %ls%lu%ls Configured (Remote Array Read; OP Claimed 3 In EXE)\n",
                                    kGreen, kReset, kGreen, cb_count, kReset);
                            }
                            else
                            {
                                LOG(0, L"  %ls[!]%ls Target TLS Callbacks.... Array Walk Failed After %lu\n", kYellow, kReset, cb_count);
                            }
                        }
                        else if (!tls_dir.AddressOfCallBacks && tls_got == sizeof(tls_dir))
                        {
                            LOG(0, L"  %ls[*]%ls Target TLS Callbacks.... Directory Present, Zero Callbacks\n", kDim, kReset);
                        }
                        else
                        {
                            LOG(0, L"  %ls[!]%ls Target TLS Directory.... Unreadable\n", kYellow, kReset);
                        }
                    }
                    else
                    {
                        LOG(0, L"  %ls[!]%ls Target TLS Directory.... Out Of Image/Safepage\n", kYellow, kReset);
                    }
                }
            }
        }
    }

    
    void StealthEraseHeader(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * exec, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Erase PE Header...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        SIZE_T declared_headers = 0;
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            declared_headers = nt->OptionalHeader.SizeOfHeaders;
        }

        
        
        
        
        
        const unsigned long long wiped = MapStats ? static_cast<unsigned long long>(MapStats->HeaderWipeSize) : 0;
        const unsigned long long wipe_protect = MapStats ? static_cast<unsigned long long>(MapStats->HeaderWipeProtect) : 0;
        const unsigned long long structural = MapStats ? static_cast<unsigned long long>(MapStats->HeaderStructuralSize) : 0;
        const unsigned long long scan_bytes = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanBytes) : 0;
        const unsigned long long scan_mz = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanMZ) : 0;
        const unsigned long long scan_pe = MapStats ? static_cast<unsigned long long>(MapStats->HeaderScanPE) : 0;
        const ULONGLONG retained_base = MapStats ? static_cast<ULONGLONG>(MapStats->RetainedAllocBase) : 0;
        const unsigned long long retained_size = MapStats ? static_cast<unsigned long long>(MapStats->RetainedAllocSize) : 0;

        
        
        
        
        const unsigned long long exec_span = exec ? static_cast<unsigned long long>(exec->PreSectionSpanWiped) : 0;
        const unsigned long long exec_mz = exec ? static_cast<unsigned long long>(exec->MZRemnantsFound) : 0;
        const unsigned long long exec_pe = exec ? static_cast<unsigned long long>(exec->PERemnantsFound) : 0;
        const unsigned long long exec_prot = exec ? static_cast<unsigned long long>(exec->PostWipeProtection) : 0;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const unsigned long long page = si.dwPageSize ? si.dwPageSize : 0x1000;
        const unsigned long long protected_span = wiped ? ((wiped + page - 1) & ~(page - 1)) : 0;

        const ULONGLONG base = hRemoteBase ? static_cast<ULONGLONG>(ReCa<ULONG_PTR>(hRemoteBase)) : 0;

        
        
        auto count_signatures = [](const BYTE * data, size_t size, unsigned long long & mz, unsigned long long & pe)
        {
            mz = 0;
            pe = 0;
            for (size_t i = 0; i + 2 <= size; ++i)
            {
                if (data[i] == 0x4D && data[i + 1] == 0x5A)
                {
                    ++mz;
                }
            }
            for (size_t i = 0; i + 4 <= size; ++i)
            {
                if (data[i] == 0x50 && data[i + 1] == 0x45 && data[i + 2] == 0x00 && data[i + 3] == 0x00)
                {
                    ++pe;
                }
            }
        };

        if (base)
        {
            LOG(0, L"  %ls[+]%ls Image Base      = %ls0x%016llX%ls\n",
                kGreen, kReset, kGreen, base, kReset);
        }

        
        if (process && base)
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx(process, ReCa<LPCVOID>(hRemoteBase), &mbi, sizeof(mbi)))
            {
                const bool commit_ok = (mbi.State == MEM_COMMIT);
                const bool noaccess_ok = ((mbi.Protect & 0xFF) == PAGE_NOACCESS);
                const wchar_t * protection = L"Other";
                switch (mbi.Protect & 0xFF)
                {
                case PAGE_READONLY: protection = L"Readonly"; break;
                case PAGE_NOACCESS: protection = L"Noaccess"; break;
                case PAGE_READWRITE: protection = L"Readwrite (Still Writable)"; break;
                case PAGE_EXECUTE_READ: protection = L"Execute Read"; break;
                default: break;
                }
                if (commit_ok && noaccess_ok)
                {
                    LOG(0, L"  %ls[+]%ls Page Protection Assertion: VirtualQueryEx Verified 0x%llX [PAGE_NOACCESS] | State = MEM_COMMIT\n",
                        kGreen, kReset, base);
                }
                else
                {
                    LOG(0, L"  %ls[x]%ls Page Protection Mismatch: State = 0x%X | Protect = %ls (0x%08X) (Required MEM_COMMIT+PAGE_NOACCESS)\n",
                        kRed, kReset, mbi.State, protection, mbi.Protect);
                }
                LOG(0, L"  %ls[*]%ls Pre-Section Span Bound: Span = [0x00000000-0x%llX) | Wiped = %llu Bytes\n",
                    kDim, kReset, wiped, wiped);
            }
            else
            {
                LOG(0, L"  %ls[x]%ls Header Page Protection Unreadable: VirtualQueryEx Failed (Hard Gate Failure).\n", kRed, kReset);
            }

            if (declared_headers)
            {
                LOG(0, L"  %ls[+]%ls Declared SizeOfHeaders = %ls0x%llX%ls (Span The Loader Would Have Mapped)\n",
                    kGreen, kReset, kGreen,
                    static_cast<unsigned long long>(declared_headers), kReset);
            }

            if (wiped)
            {
                LOG(0, L"  %ls[+]%ls Structural Header Span = %ls0x%llX%ls (DOS Stub + NT Headers + Section Table)\n",
                    kGreen, kReset, kGreen, structural, kReset);
                LOG(0, L"  %ls[+]%ls Zeroed Header Span     = %ls0x%llX%ls (Entire Pre-Section Region; Mapper Telemetry)\n",
                    kGreen, kReset, kGreen, wiped, kReset);
                LOG(0, L"  %ls[+]%ls Page-Protected Span    = %ls0x%llX%ls @ %ls%s%ls\n",
                    kGreen, kReset, kGreen, protected_span, kReset,
                    kGreen, StealthPageDesc(static_cast<DWORD>(wipe_protect)), kReset);

                
                
                
                LOG(0, L"  %ls[+]%ls MZ/PE Scan (Image)     = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls0x%llX%ls Byte(s) Of The Mapped Image (In-Shell, Pre-NOACCESS)\n",
                    kGreen, kReset, kGreen, scan_mz, kReset, kGreen, scan_pe, kReset, kGreen, scan_bytes, kReset);

                if (exec)
                {
                    const bool agree = (exec_span == wiped) && (exec_mz == scan_mz) && (exec_pe == scan_pe) && (exec_prot == wipe_protect);
                    if (agree)
                    {
                        LOG(0, L"  %ls[+]%ls Exec Telemetry Cross-Check: Span = %llu | MZ = %llu | PE = %llu | Prot = 0x%08llX - Agrees With MapStats\n",
                            kGreen, kReset, exec_span, exec_mz, exec_pe, exec_prot);
                    }
                    else
                    {
                        LOG(0, L"  %ls[x]%ls Exec Telemetry Mismatch: Span = %llu/0x%llX | MZ = %llu/%llu | PE = %llu/%llu | Prot = 0x%08llX/0x%08llX\n",
                            kRed, kReset,
                            exec_span, wiped, exec_mz, scan_mz, exec_pe, scan_pe, exec_prot, wipe_protect);
                    }
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls Exec Telemetry Unavailable: Cloak Cross-Check Skipped, Host Read-Back Failed.\n", kYellow, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[!]%ls Wiped Span Unavailable: Mapper Reported No Header-Wipe Telemetry.\n",
                    kYellow, kReset);
            }

            
            
            
            
            
            if (retained_base && retained_size)
            {
                const size_t want = static_cast<size_t>(retained_size < 0x1000 ? retained_size : 0x1000);
                std::vector<BYTE> scan_buf(want, 0);
                SIZE_T got = 0;
                if (ReadProcessMemory(process, ReCa<LPCVOID>(retained_base), scan_buf.data(), want, &got) && got)
                {
                    unsigned long long r_mz = 0;
                    unsigned long long r_pe = 0;
                    count_signatures(scan_buf.data(), got, r_mz, r_pe);
                    LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = %ls%llu%ls Hit(s) For MZ (0x4D5A) And %ls%llu%ls Hit(s) For PE\\0\\0 (0x50450000) In The First %ls%llu%ls Byte(s) Of Retained Allocation %ls0x%llX%ls\n",
                        kGreen, kReset, kGreen, r_mz, kReset, kGreen, r_pe, kReset,
                        kGreen, static_cast<unsigned long long>(got), kReset, kGreen, retained_base, kReset);
                }
                else
                {
                    LOG(0, L"  %ls[!]%ls MZ/PE Scan (Host)      = Retained Allocation %ls0x%llX%ls Not Readable (Protection Changed).\n",
                        kYellow, kReset, kYellow, retained_base, kReset);
                }
            }
            else
            {
                LOG(0, L"  %ls[+]%ls MZ/PE Scan (Host)      = No Other Injection Allocation Remains Readable - The Manual-Map And Thread-Hijack Staging Regions Are Scrubbed And Released Before This Stage, And The Image Header Page Is NOACCESS By Design.\n",
                    kGreen, kReset);
            }
        }
        else if (!process || !base)
        {
            LOG(0, L"  %ls[!]%ls Image Base Not Readable; Header State Unknown.\n", kYellow, kReset);
        }
    }

    
    void StealthSurveyTraps(HANDLE process, DWORD survey_pid, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        LOG(0, L"\n\n[%ls%d%ls/%ls%d%ls] Survey Target Traps...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        ReportGameTraps(process, survey_pid, buffers);
        LOG(0, L"\n");
    }

    bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {
        if (wx_violated)
        {
            *wx_violated = false;
        }

        if (!hRemoteBase)
            return false;

        
        

        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        bool string_gate_ok = true;
        bool posture_ok = true;

        
        const bool step_enabled[kStealthStepCount] =
        {
            isActive(INJ_HANDLE_HIJACKING),
            isActive(INJ_MM_RESOLVE_IMPORTS) || isActive(INJ_MM_RUN_DLL_MAIN),
            isActive(INJ_MM_RESOLVE_DELAY_IMPORTS),
            isActive(INJ_MM_INIT_SECURITY_COOKIE),
            isActive(INJ_MM_ENABLE_EXCEPTIONS),
            true,
            isActive(INJ_MM_EXECUTE_TLS),
            isActive(INJ_MM_RUN_DLL_MAIN),
            isActive(INJ_MM_RUN_UNDER_LDR_LOCK),
            isActive(INJ_MM_CLEAN_DATA_DIR),
            isActive(INJ_MM_SET_PAGE_PROTECTIONS),
            true,
            true,
            true,
            isActive(INJ_ERASE_HEADER),
            survey_game_traps,
        };

        int total = 0;
        for (bool enabled : step_enabled)
        {
            if (enabled)
            {
                ++total;
            }
        }

        int step = 0;

        auto read_local_nt = [&]() -> bool
        {
            if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
                return false;
            BYTE * local_copy = const_cast<BYTE *>(local_pe);
            auto dos = ReCa<IMAGE_DOS_HEADER *>(local_copy);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            if (dos->e_lfanew < 0)
                return false;
            if (local_pe_size < static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64))
                return false;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(local_copy + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            memcpy(buffers.local_headers.data(), nt, sizeof(IMAGE_NT_HEADERS64));
            return true;
        };

        auto read_remote_nt = [&]() -> bool
        {
            if (!process)
                return false;
            BYTE dos_buf[sizeof(IMAGE_DOS_HEADER)] = { 0 };
            SIZE_T ds = 0;
            if (!ReadProcessMemory(process, hRemoteBase, dos_buf, sizeof(IMAGE_DOS_HEADER), &ds))
                return false;
            auto dos = ReCa<IMAGE_DOS_HEADER *>(dos_buf);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000)
                return false;
            SIZE_T ns = 0;
            if (!ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + dos->e_lfanew,
                buffers.remote_headers.data(), sizeof(IMAGE_NT_HEADERS64), &ns))
                return false;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.remote_headers.data());
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            return true;
        };

        const bool have_remote_nt = read_remote_nt();
        const bool have_local_nt = read_local_nt();
        BYTE * nt_data = have_remote_nt ? buffers.remote_headers.data()
            : (have_local_nt ? buffers.local_headers.data() : nullptr);

        if (step_enabled[kStealthAcquireHandle])
        {
            StealthAcquireHandle(ProcessHijack, ThreadHijack, Context, flags, step, total);
        }

        if (step_enabled[kStealthResolveImports])
        {
            StealthResolveImports(have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }

        if (step_enabled[kStealthResolveDelayImports])
        {
            StealthResolveDelayImports(have_local_nt, buffers, step, total);
        }

        if (step_enabled[kStealthInitSecurityCookie])
        {
            StealthInitSecurityCookie(process, hRemoteBase, have_local_nt, buffers, step, total);
        }

        if (step_enabled[kStealthEnableExceptions])
        {
            StealthEnableExceptions(process, hRemoteBase, have_local_nt, flags, buffers, step, total);
        }

        if (step_enabled[kStealthVerifyExceptionHandling])
        {
            StealthVerifyExceptionHandling(process, flags, have_local_nt, ExecTelemetry, buffers, get_string_stats, step, total);
        }

        if (step_enabled[kStealthExecuteTls])
        {
            StealthExecuteTls(have_local_nt, local_pe, local_pe_size, ExecTelemetry, buffers, step, total);
        }

        if (step_enabled[kStealthExecuteDllMain])
        {
            StealthExecuteDllMain(ExecTelemetry, flags, step, total);
        }

        if (step_enabled[kStealthRunUnderLoaderLock])
        {
            StealthRunUnderLoaderLock(ExecTelemetry, flags, step, total);
        }

        if (step_enabled[kStealthCleanDataDirectories])
        {
            StealthCleanDataDirectories(MapStats, have_remote_nt, nt_data, step, total);
        }

        if (step_enabled[kStealthSetPageProtections])
        {
            StealthSetPageProtections(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }
        if (step_enabled[kStealthVerifyWx])
        {
            StealthVerifyWxExecution(process, hRemoteBase, have_local_nt, local_pe, local_pe_size, buffers, wx_violated, step, total);
        }

        if (step_enabled[kStealthVerifyStringEncryption])
        {
            StealthVerifyStringEncryption(buffers, get_string_stats, string_gate_ok, step, total);
        }

        if (step_enabled[kStealthVerifyForensicPosture])
        {
            StealthVerifyForensicPosture(process, hRemoteBase, local_pe, local_pe_size, config, buffers, posture_ok, step, total);
        }

        if (step_enabled[kStealthEraseHeader])
        {
            StealthEraseHeader(process, hRemoteBase, have_local_nt, MapStats, ExecTelemetry, buffers, step, total);
        }
        if (step_enabled[kStealthSurveyTraps])
        {
            StealthSurveyTraps(process, survey_pid, buffers, step, total);
        }

        return string_gate_ok && posture_ok;
    }

    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, const VERIFIABLE_EXEC_TELEMETRY * ExecTelemetry,
        f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {
        __try
        {
            return DebugAndVerifyStealth(process, hRemoteBase, flags, local_pe, local_pe_size, ProcessHijack, ThreadHijack, Context, MapStats, ExecTelemetry, get_string_stats, survey_game_traps, survey_pid, wx_violated, config, buffers);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG(0, L"  %ls[x]%ls Verification Faulted; Gate Cannot Be Satisfied.\n", kRed, kReset);
            return false;
        }
    }

    bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out)
    {
        name_out.clear();
        base_out = 0;
        size_out = 0;
        if (!process)
        {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Module32FirstW(snapshot, &entry))
        {

            name_out = entry.szModule;
            base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
            size_out = static_cast<SIZE_T>(entry.modBaseSize);
            found = !name_out.empty() && base_out != 0;
        }

        CloseHandle(snapshot);
        return found;
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
    static_assert(offsetof(PEB, CrossProcessFlags) == 80);
    static_assert(offsetof(PEB, Mutant) == 8);

    inline bool QueryRemoteVehFirstChance(HANDLE process, VehFirstChanceSurvey & out)
    {
        out = VehFirstChanceSurvey{};
        if (!process || process == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        out.handleValid = true;

        using NtQueryInformationProcessFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        NtQueryInformationProcessFn query = nullptr;
        {
            auto mod_name = XOR_STR_W(L"ntdll.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());
            if (mod)
            {
                auto api_name = XOR_STR_A("NtQueryInformationProcess");
                query = ReCa<NtQueryInformationProcessFn>(GetProcAddress(mod, api_name.get()));
            }
        }
        if (!query)
        {
            out.lastError = GetLastError();
            return false;
        }

        struct LocalPbi
        {
            LONG ExitStatus;
            PVOID PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG BasePriority;
            HANDLE UniqueProcessId;
            HANDLE InheritedFromUniqueProcessId;
        };
        LocalPbi pbi{};
        ULONG ret_len = 0;
        const LONG status = query(process, 0, &pbi, static_cast<ULONG>(sizeof(pbi)), &ret_len);
        if (status != 0 || !pbi.PebBaseAddress)
        {
            out.lastError = static_cast<DWORD>(status != 0 ? status : ERROR_INVALID_ADDRESS);
            return false;
        }
        out.pebAddress = pbi.PebBaseAddress;

        const ULONG_PTR peb = ReCa<ULONG_PTR>(pbi.PebBaseAddress);
        const ULONG_PTR cross_addr = peb + offsetof(PEB, CrossProcessFlags);
        const ULONG_PTR debugged_addr = peb + 2;
        const ULONG_PTR global_flag_addr = peb + offsetof(PEB, NtGlobalFlag);

        ULONG cross = 0;
        BYTE debugged = 0;
        ULONG gflag = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(cross_addr), &cross, sizeof(cross), &got) ||
            got != sizeof(cross))
        {
            out.lastError = GetLastError();
            return false;
        }
        got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(debugged_addr), &debugged, sizeof(debugged), &got) ||
            got != sizeof(debugged))
        {
            out.lastError = GetLastError();
            return false;
        }
        got = 0;
        if (!ReadProcessMemory(process, ReCa<LPCVOID>(global_flag_addr), &gflag, sizeof(gflag), &got) ||
            got != sizeof(gflag))
        {
            out.lastError = GetLastError();
            return false;
        }

        out.crossFlags = cross;
        out.usingVeh = (cross & 0x4u) != 0;
        out.usingVch = (cross & 0x8u) != 0;
        out.beingDebugged = debugged;
        out.ntGlobalFlag = gflag;
        out.readOk = true;
        return true;
    }

    inline LONG NTAPI VehProbeDummyHandler(EXCEPTION_POINTERS *)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    
    
    
    inline bool ProbeLocalVehPathRoundTrip()
    {
        void * handle = AddVectoredExceptionHandler(1, VehProbeDummyHandler);
        if (!handle)
        {
            return false;
        }
        const ULONG removed = RemoveVectoredExceptionHandler(handle);
        return removed != 0;
    }

    
    
    
    inline bool QueryRemoteDebugPort(HANDLE process, DebugPortSurvey & out)
    {
        out = DebugPortSurvey{};
        if (!process || process == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        out.handleValid = true;

        using NtQueryInformationProcessFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        NtQueryInformationProcessFn query = nullptr;
        {
            auto mod_name = XOR_STR_W(L"ntdll.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());
            if (mod)
            {
                auto api_name = XOR_STR_A("NtQueryInformationProcess");
                query = ReCa<NtQueryInformationProcessFn>(GetProcAddress(mod, api_name.get()));
            }
        }
        if (!query)
        {
            return false;
        }

        PVOID port = nullptr;
        ULONG port_len = 0;
        out.portStatus = query(process, 7, &port, static_cast<ULONG>(sizeof(port)), &port_len);
        if (out.portStatus == 0 && port_len == sizeof(port))
        {
            out.debugPort = port;
            out.portReadOk = true;
        }

        ULONG pflags = 0;
        ULONG flags_len = 0;
        out.flagsStatus = query(process, 31, &pflags, static_cast<ULONG>(sizeof(pflags)), &flags_len);
        if (out.flagsStatus == 0 && flags_len == sizeof(pflags))
        {
            out.debugFlags = pflags;
            out.flagsReadOk = true;
        }

        return out.portReadOk || out.flagsReadOk;
    }

    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size)
    {
        if (!process || !address || !size)
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process, reinterpret_cast<void *>(address), &mbi, sizeof(mbi)))
        {
            return false;
        }

        if (mbi.State != MEM_COMMIT)
        {
            return false;
        }

        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
        {
            return false;
        }

        const ULONG_PTR region_end = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (address + size > region_end)
        {
            return false;
        }

        return true;
    }

    bool GetRemoteEidRange(HANDLE process, ULONG_PTR base, ULONG_PTR & start_out, ULONG_PTR & end_out)
    {
        start_out = 0;
        end_out = 0;
        if (!process || !base)
        {
            return false;
        }
        IMAGE_DOS_HEADER dos{};
        SIZE_T done = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &done) ||
            done != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
        {
            return false;
        }
        DWORD sig = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + static_cast<ULONG_PTR>(dos.e_lfanew)),
            &sig, sizeof(sig), &done) || done != sizeof(sig) || sig != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        const ULONG_PTR file_hdr = base + static_cast<ULONG_PTR>(dos.e_lfanew) + sizeof(DWORD);
        WORD num_sections = 0;
        WORD opt_size = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 2),
            &num_sections, sizeof(num_sections), &done) || done != sizeof(num_sections))
        {
            return false;
        }
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 16),
            &opt_size, sizeof(opt_size), &done) || done != sizeof(opt_size))
        {
            return false;
        }
        if (!num_sections || num_sections > 96)
        {
            return false;
        }
        const ULONG_PTR sec_table = file_hdr + sizeof(IMAGE_FILE_HEADER) + opt_size;
        for (WORD i = 0; i < num_sections; ++i)
        {
            IMAGE_SECTION_HEADER sec{};
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(sec_table + static_cast<ULONG_PTR>(i) * sizeof(sec)),
                &sec, sizeof(sec), &done) || done != sizeof(sec))
            {
                return false;
            }
            char name[9] = { 0 };
            memcpy(name, sec.Name, 8);
            if (strcmp(name, ".eid") == 0)
            {
                const DWORD extent = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                if (!extent)
                {
                    return false;
                }
                start_out = base + sec.VirtualAddress;
                end_out = start_out + extent;
                return end_out > start_out;
            }
        }
        return false;
    }

    SIZE_T ReadSurveyBound(const wchar_t * name)
    {
        wchar_t buffer[32] = {};
        const DWORD got = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
        if (got == 0 || got >= sizeof(buffer) / sizeof(buffer[0]))
        {
            return 0;
        }

        wchar_t * end = nullptr;
        const unsigned long long value = wcstoull(buffer, &end, 10);
        if (!end || *end != L'\0')
        {
            return 0;
        }

        return static_cast<SIZE_T>(value);
    }

    void ReportGameTraps(HANDLE process, DWORD target_pid, StealthVerifierBuffers & buffers)
    {
        if (!process || !target_pid)
        {
            return;
        }

        std::vector<SurveyModule> & survey_modules = buffers.survey_modules;
        survey_modules.clear();
        {
            std::wstring main_name;
            ULONG_PTR main_base = 0;
            SIZE_T main_size = 0;
            if (GetRemoteMainModule(process, main_name, main_base, main_size))
            {
                survey_modules.push_back(SurveyModule{ main_name, main_base, main_size });
            }
        }

        const SIZE_T max_walk_regions = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_REGIONS").get());
        const SIZE_T max_walk_bytes = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_MB").get()) * (1u << 20);
        const SIZE_T max_sample_regions = ReadSurveyBound(XOR_STR_W(L"AMEGER_SURVEY_MAX_SAMPLE_REGIONS").get());

        constexpr SIZE_T kSurveyChunkBytes = 0x10000;

        std::vector<BYTE> & chunk_buf = buffers.survey_chunk;
        if (chunk_buf.size() != kSurveyChunkBytes)
        {
            chunk_buf.resize(kSurveyChunkBytes);
            if (chunk_buf.size() != kSurveyChunkBytes)
            {

                LOG(0, L"  %ls[!]%ls Survey Read Window Unavailable; INT3 Scan Skipped.\n", kYellow, kReset);
                return;
            }
        }

        int found = 0;
        for (size_t m = 0; m < survey_modules.size(); ++m)
        {
            const std::wstring & mod = survey_modules[m].name;
            const ULONG_PTR base = survey_modules[m].base;
            const SIZE_T image_size = survey_modules[m].size;
            if (!base)
            {
                continue;
            }

            ++found;

            size_t guarded = 0;
            size_t noaccess = 0;
            size_t guarded_bytes = 0;
            size_t noaccess_bytes = 0;
            size_t sampled = 0;
            size_t exec_regions = 0;
            size_t cc_bytes = 0;
            size_t sample_bytes = 0;
            size_t walked = 0;
            size_t eid_skipped = 0;

            size_t sample_capped = 0;
            bool walk_capped = false;
            bool walk_aborted = false;
            const bool unknown_extent = (image_size == 0);
            ULONG_PTR eid_start = 0;
            ULONG_PTR eid_end = 0;
            const bool has_eid = GetRemoteEidRange(process, base, eid_start, eid_end);

            const ULONG_PTR walk_end = unknown_extent ? 0 : (base + image_size);

            BYTE * cursor = reinterpret_cast<BYTE *>(base);
            size_t regions = 0;
            for (;;)
            {
                if (unknown_extent)
                {
                    walk_aborted = true;
                    break;
                }

                if (max_walk_regions && regions >= max_walk_regions)
                {
                    walk_capped = true;
                    break;
                }

                if (reinterpret_cast<ULONG_PTR>(cursor) >= walk_end)
                {
                    break;
                }

                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(process, cursor, &mbi, sizeof(mbi)) || !mbi.RegionSize)
                {
                    walk_aborted = true;
                    break;
                }

                BYTE * next = reinterpret_cast<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cursor)
                {
                    walk_aborted = true;
                    break;
                }

                if (has_eid)
                {
                    const ULONG_PTR r_start = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
                    const ULONG_PTR r_end = reinterpret_cast<ULONG_PTR>(next);
                    if (r_start < eid_end && r_end > eid_start)
                    {
                        ++eid_skipped;
                        cursor = next;
                        ++regions;
                        if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                        {
                            walk_capped = true;
                            break;
                        }
                        continue;
                    }
                }

                if (mbi.State == MEM_COMMIT)
                {
                    ++walked;
                    if (mbi.Protect & PAGE_GUARD)
                    {
                        ++guarded;
                        guarded_bytes += mbi.RegionSize;
                    }
                    else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
                    {
                        ++noaccess;
                        noaccess_bytes += mbi.RegionSize;
                    }
                    else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    {
                        ++exec_regions;
                        if (max_sample_regions && sampled >= max_sample_regions)
                        {
                            ++sample_capped;
                        }
                        else
                        {

                            SIZE_T remaining = mbi.RegionSize;
                            BYTE * addr = reinterpret_cast<BYTE *>(mbi.BaseAddress);
                            size_t region_cc = 0;
                            size_t region_read = 0;
                            while (remaining)
                            {
                                const SIZE_T want = remaining < kSurveyChunkBytes ? remaining : kSurveyChunkBytes;
                                SIZE_T got = 0;
                                if (!ReadProcessMemory(process, addr, chunk_buf.data(), want, &got) || !got)
                                {
                                    break;
                                }

                                for (size_t i = 0; i < static_cast<size_t>(got); ++i)
                                {
                                    if (chunk_buf[i] == 0xCC)
                                    {
                                        ++region_cc;
                                    }
                                }

                                region_read += static_cast<size_t>(got);
                                addr += got;
                                remaining -= got;
                                if (got < want)
                                {
                                    break;
                                }
                            }

                            if (region_read)
                            {
                                cc_bytes += region_cc;
                                sample_bytes += region_read;
                                ++sampled;
                            }
                        }
                    }
                }

                cursor = next;
                ++regions;
                if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                {
                    walk_capped = true;
                    break;
                }
            }

            
            
            
            const size_t cc_pct = sample_bytes ? (cc_bytes * 100) / sample_bytes : 0;

            
            
            
            const wchar_t * Verdict = guarded ? L"Guarded" : L"No Guard Pages";
            wchar_t VerdictNote[192]{};
            if (guarded == 0)
            {
                if (sample_bytes == 0)
                {
                    swprintf_s(VerdictNote, L"No Executable Region Was Readable");
                }
                else if (cc_pct)
                {
                    swprintf_s(VerdictNote, L"INT3 %zu%% Of Sampled Exec Bytes (Process-Wide; Not A Per-Module Verdict)",
                        cc_pct);
                }
                else
                {
                    swprintf_s(VerdictNote, L"No INT3 In Sampled Exec Bytes");
                }
            }
            LOG(0, L"  %ls%ls%s%s (%ls%zu%s Committed Region(s) Walked, Process-Wide)\n",
                StageField(mod, 24).c_str(),
                guarded ? kYellow : L"", Verdict, kReset,
                kGreen, walked, kReset);
            if (VerdictNote[0])
            {
                LOG(0, L"  %*s%ls%s\n", static_cast<int>(StageField(mod, 24).size()), L"", VerdictNote, kReset);
            }

            LOG(0, L"\n");

            LOG(0, L"      %ls%ls%zu%ls Region(s), %ls%zu%ls KB\n",
                StageField(L"Guard:", 12).c_str(),
                kGreen, guarded, kReset,
                kGreen, static_cast<size_t>(guarded_bytes / 1024), kReset);

            LOG(0, L"      %ls%ls%zu%ls Region(s), %ls%zu%ls KB\n",
                StageField(L"No-Access:", 12).c_str(),
                kGreen, noaccess, kReset,
                kGreen, static_cast<size_t>(noaccess_bytes / 1024), kReset);

            if (eid_skipped)
            {
                LOG(0, L"      %ls%ls%zu%ls Region(s) Skipped (Encrypted Core, Never Read)\n",
                    StageField(L"EID:", 12).c_str(),
                    kGreen, eid_skipped, kReset);
            }

            if (sample_bytes)
            {
                LOG(0, L"      %ls%ls%zu%ls Of %ls%zu%ls Sampled Bytes Are INT3 (%ls0xCC%ls), %ls%zu%s%%, From %ls%zu%ls Of %ls%zu%ls Exec Region(s)\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, cc_bytes, kReset,
                    kGreen, sample_bytes, kReset,
                    kGreen, kReset,
                    kGreen, cc_pct, kReset,
                    kGreen, sampled, kReset, kGreen, exec_regions, kReset);

                if (sample_capped)
                {

                    LOG(0, L"%*s%ls%zu%ls Of %ls%zu%ls Exec Region(s) Not Sampled (Cap %ls%zu%ls), So The INT3 Count Is A Floor, Not A Total\n",
                        static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                        kGreen, sample_capped, kReset,
                        kGreen, exec_regions, kReset,
                        kGreen, max_sample_regions, kReset);
                }
            }
            else
            {
                LOG(0, L"      %lsNo Executable Region Was Readable\n",
                    StageField(L"INT3:", 12).c_str());
            }

            if (walk_capped || walk_aborted)
            {

                wchar_t reason[192]{};
                const auto append = [&reason](const wchar_t * part)
                {
                    if (!part)
                    {
                        return;
                    }
                    size_t used = 0;
                    while (used < _countof(reason) && reason[used])
                    {
                        ++used;
                    }
                    if (used >= _countof(reason) - 1)
                    {
                        return;
                    }
                    wchar_t * dst = reason + used;
                    size_t left = _countof(reason) - 1 - used;
                    if (used)
                    {
                        if (left < 3)
                        {
                            return;
                        }
                        *dst++ = L' ';
                        *dst++ = L'/';
                        *dst++ = L' ';
                        left -= 3;
                    }
                    while (left && *part)
                    {
                        *dst++ = *part++;
                        --left;
                    }
                    *dst = L'\0';
                };

                if (walk_capped)
                {
                    if (max_walk_regions)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"Cap %ls%zu%ls Regions", kGreen, max_walk_regions, kReset);
                        append(part);
                    }
                    if (max_walk_bytes)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"Cap %ls%zu%ls MB", kGreen, static_cast<size_t>(max_walk_bytes >> 20), kReset);
                        append(part);
                    }
                }
                if (walk_aborted)
                {
                    append(unknown_extent ? L"Module Extent Unknown" : L"Query Failed Before Module End");
                }

                LOG(0, L"%*sRegion Walk Stopped Early (%ls); Counts Are Partial\n",
                    static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                    reason);
            }

            LOG(0, L"\n");
        }

        if (!found)
        {
            LOG(0, L"  %ls[!]%ls No Target Module Present; Nothing To Survey.\n", kYellow, kReset);
        }
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
            LOG(0, L"24H2 26100+, 25H2 26200+, 26H2 26300+; Newer Builds Are Forward-Mapped). This Is An\n");
            LOG(0, L"Environment Issue, Not A Mapping Or Symbol Failure. Update Windows.\n");
        }
        else
        {

            LOG(0, L"Reason: Unclassified Failure 0x%08lX; See The Runtime Error Header.\n",
                static_cast<unsigned long>(code));
        }
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
            PrintError(L"Supported: Windows 11 21H2 (22000), 22H2/23H2 (22621-22631), 24H2 (26100+), 25H2 (26200+), 26H2 (26300+).");
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

    int RunInteractiveWizard(Runtime & runtime)
    {
        
        
        (void)runtime;
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
            config.target_name = L"notepad.exe";
            config.quiet = true;
            config.detach_console = true;
            config.verbose_trace = false;
            SetEnvironmentVariableW(L"INJ_ALLOW_DIRECT_FALLBACK", L"1");
        }
        Trace::Begin(L"Operator Confirmation");
        ConfirmationResult confirmation = ConfirmationResult::Proceed;
        if (config.test_mode)
        {
            Sleep(3000);
        }
        else
        {
            confirmation = ConfirmBeforeDetection();
        }
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
            PrintError(L"Target Exited Before Loading. Re-Run And Choose Faster.");
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

        // Process-handle acquisition is the runtime's job: it either duplicates a donor
        // handle out of another process (the preferred, access-mask-preserving route) or
        // opens the target directly. The launcher deliberately does not hold a target
        // handle across the injection, because doing so would leave a syscall-bearing
        // handle in the launcher's own table for the whole load.
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

        // Read-only so the verification suite can inspect the target without holding a
        // stronger handle than it needs.
        HANDLE targetHandle = nullptr;
        {
            targetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
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

        const DWORD result = runtime.memory_inject(&data);
        const ULONGLONG inject_window_ms = GetTickCount64() - inject_begin_ms;

        Trace::Note(L"Return Value = 0x%08lX | Elapsed = %llu ms", static_cast<unsigned long>(result),
            static_cast<unsigned long long>(inject_window_ms));
        Trace::End();

        if (result != INJ_ERR_SUCCESS)
        {
            LOG(0, L"%ls[x]%ls Operation Failed With Code %08X%ls\n", kRed, kReset, result);
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
            Trace::Note(L"Map Stats: Cleaned = 0x%08X | Residual = 0x%08X | Verified = %u",
                MapStats.CleanedMask, MapStats.ResidualMask, MapStats.Verified);
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

            stealth_gate_ok = SafeDebugAndVerifyStealth(targetHandle, data.hDllOut, flags, raw_data.data(), raw_data.size(),
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
        
        
        
        VehFirstChanceSurvey veh_coverage_probe{};
        const bool veh_coverage_read = had_target &&
            QueryRemoteVehFirstChance(targetHandle, veh_coverage_probe) && veh_coverage_probe.readOk;
        
        
        
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
                    kGreen, StealthPageDesc(base_prot), kReset,
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
            Trace::Summary(had_target ? L"Failed At Verification Gate" : L"Verification Not Performed");
            PauseBeforeExit();
            return 1;
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
            const bool map_stats_read = runtime.get_last_map_stats != nullptr &&
                MapStats.Verified != 0;
            
            
            
            
            VehFirstChanceSurvey veh_coverage{};
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
                { L"Data-Directory Wipe Re-Read",    map_stats_read, L"Mapper-Side Re-Read After Header Cloak" },
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
        LOG(0, L"Cleaned Mask = 0x%08X | Residual = 0x%08X | Mapper Re-Read %s\n",
            (unsigned)MapStats.CleanedMask, (unsigned)MapStats.ResidualMask,
            MapStats.Verified ? L"Verified" : L"Not Verified");

        row(L"W^X....................... ", !wx_violated);
        LOG(0, L"RWX Regions Found: %d (%s)\n", wx_violated ? 1 : 0,
            wx_violated ? L"Violated" : L"Enforced");

        
        
        row(L"Verification Gate......... ", stealth_gate_ok);
        LOG(0, L"%s\n", stealth_gate_ok ? L"Pass" : L"Fail");
        LOG(0, L"====================================================================================================\n");
        LOG(0, L"[Result] [+] Mapped At %p In %ls (PID %lu)\n",
            data.hDllOut, target.name.c_str(), static_cast<unsigned long>(target.pid));
        LOG(0, L"====================================================================================================\n");
        Trace::Summary(L"Success");
        PauseBeforeExit();
        return 0;
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

    {
        const std::wstring config_path = ConfigurationPath();
        const size_t slash = config_path.find_last_of(L"\\/");
        const size_t dot = config_path.find_last_of(L'.');
        if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash + 1))
        {
            const size_t start = (slash == std::wstring::npos) ? 0 : slash + 1;
            const std::wstring stem = config_path.substr(start, dot - start);
            if (!stem.empty())
            {
                g_ResultLogName = stem + L".log";
            }
        }
    }

    ameger_ui_log::ResetResultLog();

    const int retryIndex = GetRetryIndex();
    Runtime runtime;
    int result = 1;
    try
    {
        
        
        result = RunInteractiveWizard(runtime);
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
        runtime.module = nullptr;
    }

    // Persist the log next to the launcher/config BEFORE anything that can end the process. The
    // file is named "<config stem>.log" (randomized per build) and falls back to Result.log when
    // no valid config is found. The retry path calls TerminateInterface(), which never returns,
    // so a log written after it would be lost. The log is deleted at startup and rewritten from
    // scratch at exit, so it never accumulates across attempts or runs.
    ameger_ui_log::WriteResultLog();
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
        const std::wstring message = L"Operation Failed After 3 Attempts. The Full Log Is In " + g_ResultLogName + L".";
        LayeredNotify(L"Launcher", message.c_str(), 5000);
        result = 1;
    }

    return result;
}
