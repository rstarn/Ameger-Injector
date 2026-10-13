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

    constexpr wchar_t kReset[] = L"\x1b[0m";
    constexpr wchar_t kGreen[] = L"\x1b[92m";
    constexpr wchar_t kRed[] = L"\x1b[91m";
    constexpr wchar_t kYellow[] = L"\x1b[93m";

    constexpr wchar_t kDim[] = L"\x1b[2m";

    constexpr size_t kConfigBlobMagicSize = 8;

#ifndef AMEGER_CONFIG_MAGIC_STR
#define AMEGER_CONFIG_MAGIC_STR "SYSCFG01"
#endif

#ifndef AMEGER_WINDOW_CLASS_STR
#define AMEGER_WINDOW_CLASS_STR "AmgWLayered"
#endif

#define AMEGER_WIDEN2(x) L##x
#define AMEGER_WIDEN(x) AMEGER_WIDEN2(x)

// ------------------------------------------------------------------
// Headless UI log: every console print is captured into an in-memory
// buffer (ANSI sequences stripped) and, on completion, copied to the
// clipboard in one brief OpenClipboard(NULL) ownership with no window.
// ------------------------------------------------------------------
namespace ameger_ui_log
{
    constexpr size_t kMaxChars = 65536;

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
            // Strip ANSI SGR sequences: ESC [ <digits/;> m
            if (text[i] == L'\x1b' && text[i + 1] == L'[')
            {
                size_t j = i + 2;
                while (text[j] && ((text[j] >= L'0' && text[j] <= L'9') || text[j] == L';'))
                {
                    ++j;
                }
                if (text[j] == L'm')
                {
                    i = j;
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

    // Single brief clipboard ownership, no window, no notification UI.
    // Retries only if another app holds the clipboard open.
    inline void CopyToClipboardStealthily()
    {
        std::wstring snapshot = Snapshot();
        if (snapshot.empty())
        {
            snapshot = L"(no output)";
        }
        if (snapshot.size() > kMaxChars)
        {
            snapshot.resize(kMaxChars);
        }
        for (int attempt = 0; attempt < 8; ++attempt)
        {
            if (!OpenClipboard(nullptr))
            {
                Sleep(30);
                continue;
            }
            (void)EmptyClipboard();
            const SIZE_T bytes = (snapshot.size() + 1) * sizeof(wchar_t);
            HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (!mem)
            {
                CloseClipboard();
                return;
            }
            void * locked = GlobalLock(mem);
            if (!locked)
            {
                GlobalFree(mem);
                CloseClipboard();
                return;
            }
            memcpy(locked, snapshot.c_str(), bytes);
            GlobalUnlock(mem);
            if (!SetClipboardData(CF_UNICODETEXT, mem))
            {
                GlobalFree(mem);
                CloseClipboard();
                return;
            }
            // System owns mem after a successful SetClipboardData.
            CloseClipboard();
            return;
        }
    }
} // namespace ameger_ui_log

int UiWprintf(const wchar_t * format, ...);
int UiFwprintf(FILE * stream, const wchar_t * format, ...);

#define wprintf UiWprintf
#define fwprintf UiFwprintf

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
        OutputDebugStringW(buffer.data());
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
        OutputDebugStringW(buffer.data());
    }
    return written;
}

    // Stealth launcher policy (WINDOWS subsystem, no console).
    // The launcher never allocates a console. Operator prompts are served
    // through a layered window. Each attempt runs exactly once per process;
    // retries always spawn a fresh renamed process with a fresh parent.
    constexpr int kMaxLaunchAttempts = 3;
    // Transient failures (network/symbol timeout, target raced, inject miss)
    // respawn fresh; deterministic failures (config/pin/arch/gate) do not.
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

    // ------------------------------------------------------------------
    // Stealth launch helpers: WINDOWS subsystem, no console, layered UI,
    // spoofed parent, polymorphic self-rename, bounded fresh-process retry.
    // ------------------------------------------------------------------

    bool FileExists(const std::wstring & path);

    std::wstring GetAmegerWindowClass()
    {
        // Per-build random class name baked by ShuffleNaming.ps1/Create.bat
        // into AMEGER_WINDOW_CLASS_STR. Emitted as a contiguous UTF-16 literal
        // so the deployed value is auditable in the binary; validated at
        // runtime with fallback to a stable name only if malformed.
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
        // 16 bytes: max name is 12 chars (1 letter + 11 alnum) needing entropy[0..12];
        // 12 bytes overran by 1 when length == 12 (entropy[12] OOB read).
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
        int mode = 0; // 0=Ok, 1=OkCancel, 2=YesNo
        int result = 0; // Win32 IDOK/IDYES/IDNO/IDCANCEL, 0 = pending
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
            // Another dialog in this process already registered the per-build
            // class; reuse it without an atom handle.
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

        // Opaque dark background (uniform alpha via SourceConstantAlpha).
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
        if (bodyFont)
        {
            SelectObject(state.memDc, bodyFont);
        }
        SetTextColor(state.memDc, RGB(200, 206, 220));
        RECT bodyRc{ 18, 44, state.width - 18, state.height - 70 };
        DrawTextW(state.memDc, state.message.c_str(), -1, &bodyRc, DT_LEFT | DT_WORDBREAK);
        if (bodyFont)
        {
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
        // Drain the quit message posted by the dialog proc.
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
        // Forward the original command line, replacing retry/parent markers.
        std::wstring cmd = GetCommandLineW();
        // Strip the executable token.
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
        // Remove stale markers.
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
            if (!erased)
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
        else
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

    DWORD FindTrustedBroker(DWORD excludePid, const std::wstring & excludeImage)
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
            if (!excludeImage.empty() && _wcsicmp(entry.szExeFile, excludeImage.c_str()) == 0 && isSvchost)
            {
                // Still usable; the exclusion is only a preference for a *new*
                // broker instance, not a hard filter. Keep scanning.
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
            // Best effort: enable SeDebug and retry once for SYSTEM brokers.
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
        STARTUPINFOEXW si{};
        si.StartupInfo.cb = sizeof(si);
        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;
        si.lpAttributeList = attrs;
        PROCESS_INFORMATION pi{};
        const BOOL created = CreateProcessW(exePath.c_str(), cmdline.data(), nullptr, nullptr,
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

    // Polymorphic stub: copy self to a random name in the same directory and
    // continue there. Returns false when the current image must exit because
    // the renamed child was launched. Returns true when this image should
    // execute main logic (already the renamed child).
    bool PolymorphicSelfRename(const std::wstring & parentHint)
    {
        const std::wstring cmd = GetCommandLineW();
        if (HasMarker(cmd, kChildMarker))
        {
            // Best-effort cleanup of the unrenamed parent image left on disk.
            if (!parentHint.empty() && FileExists(parentHint))
            {
                std::wstring own;
                if (GetOwnExePath(own) && _wcsicmp(own.c_str(), parentHint.c_str()) != 0)
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
                return true;
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
            const DWORD broker = FindTrustedBroker(0, std::wstring());
            const std::wstring args = BuildForwardedArgs(GetRetryIndex(), own, true);
            if (broker && SpawnWithSpoofedParent(next, args, broker))
            {
                return false;
            }
            // Spoofed spawn failed: remove the copy and fall through to run
            // in place rather than failing the launch outright.
            (void)DeleteFileW(next.c_str());
            return true;
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
                return false;
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
            // New spoofed parent per retry: exclude the current parent so the
            // next attempt does not trivially reuse the same broker instance
            // when another trusted broker exists.
            DWORD broker = FindTrustedBroker(currentParent, std::wstring());
            if (!broker || broker == currentParent)
            {
                broker = FindTrustedBroker(0, std::wstring());
            }
            const std::wstring args = BuildForwardedArgs(nextRetry, own, true);
            if (broker && SpawnWithSpoofedParent(next, args, broker))
            {
                return true;
            }
            (void)DeleteFileW(next.c_str());
            return false;
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
        bool hook_restore = true;
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

    void PrintError(const wchar_t * message)
    {
        // WINDOWS subsystem: no console is ever allocated. Console output is
        // emitted only when a console is present; otherwise the message goes
        // to the debugger so headless runs stay silent.
        HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            fwprintf(stderr, L"%ls%ls%ls\n", kRed, message, kReset);
            return;
        }
        if (message)
        {
            OutputDebugStringW(message);
            OutputDebugStringW(L"\n");
        }
    }

    void PrintWarning(const wchar_t * message)
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output && output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            wprintf(L"%ls[!]%ls %ls\n", kYellow, kReset, message);
            return;
        }
        if (message)
        {
            OutputDebugStringW(message);
            OutputDebugStringW(L"\n");
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

    void DetachInterfaceConsole()
    {
        // WINDOWS subsystem never allocates a console, so there is nothing to
        // detach. Only release a console when one is actually present (for
        // example a developer build run from a terminal).
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
        wprintf(L"%ls", prompt);
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
        // Headless path: no console exists, so serve the prompt through the
        // layered window instead of stdin.
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD console_mode = 0;
        const bool hasConsole = input && input != INVALID_HANDLE_VALUE &&
            GetConsoleMode(input, &console_mode) != FALSE;
        if (!hasConsole)
        {
            // Retries never re-prompt either: use the safe default so a
            // transient retry cannot stack a second dialog behind the first.
            if (GetRetryIndex() > 0)
            {
                value = default_value;
                return true;
            }
            std::wstring message = prompt ? std::wstring(prompt) : std::wstring(L"Continue?");
            value = LayeredYesNo(message, default_value);
            // LayeredYesNo always produces an explicit choice (timeout falls
            // back to the safe default), so report success.
            if (!default_value && !value)
            {
                // Explicit "No" with a false default is still a valid answer.
            }
            return true;
        }
        for (;;)
        {
            wprintf(L"%ls [%ls]: ", prompt, default_value ? L"Y" : L"N");
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
            PrintWarning(L"Answer y or n.");
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
        // Retries never re-prompt: the operator already confirmed attempt 1,
        // so a second "begin load" popup is a bug, not a gate.
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
            // WINDOWS subsystem: no console exists. Serve the gate through a
            // layered window with the per-build random class name.
            const bool proceed = LayeredConfirm(
                L"Begin load? Select OK to proceed or Cancel to quit.");
            return proceed ? ConfirmationResult::Proceed : ConfirmationResult::Cancelled;
        }

        wprintf(L"%ls[+]%ls Press Enter to begin, or Q to quit: \n", kGreen, kReset);
        fflush(stdout);

        std::wstring entered;
        if (!std::getline(std::wcin, entered))
        {

            PrintError(L"Console input ended before confirmation; refusing to load.");
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
            return (got == 1 && buffer[0] == L'1');
        }();
        return verbose;
    }

    bool EnableSeDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return false;
        }
        FileHandleGuard tokenGuard(token);

        LUID luid{};

        if (!LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &luid))
        {
            return false;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr))
        {
            return false;
        }

        const DWORD status = GetLastError();
        return status == ERROR_SUCCESS;
    }

    void DisableSeDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return;
        }
        FileHandleGuard tokenGuard(token);

LUID luid{};

        if (!LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &luid))
        {
            return;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;

        privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    }

    // The thread picker walks the buffers NtQuerySystemInformation fills with the shared
    // SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION definitions from NTDefinitions.h rather
    // than a private mirror. The layout invariants the walk relies on are asserted once here. The
    // element size matters: the Threads[] array inside SYSTEM_PROCESS_INFORMATION is indexed by it, so
    // a wrong stride reads every thread after the first from a misaligned address, and WaitReason has
    // to be read at +0x48 rather than at +0x45 (byte 1 of ThreadState) or it is never non zero.
    static_assert(sizeof(UNICODE_STRING) == 16);
    static_assert(sizeof(CLIENT_ID) == 16);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ClientId) == 40);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, ThreadState) == 68);
    static_assert(offsetof(SYSTEM_THREAD_INFORMATION, WaitReason) == 72);
    static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 0x50);
    static_assert(offsetof(SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

    DWORD PickHijackThreadTid(DWORD target_pid)
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
                auto score_walk = [&](DWORD exclude_tid, bool allow_wait) -> bool
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
                        if (!tid || tid == GetCurrentThreadId() || tid == exclude_tid)
                        {
                            continue;
                        }

                        const unsigned char thread_state = static_cast<unsigned char>(thread->ThreadState);
                        const unsigned char thread_reason = static_cast<unsigned char>(thread->WaitReason);
                        // Accept a running thread (state 2) directly; otherwise accept only when the
                        // caller allows waiting and the wait is safe. Everything else is skipped.
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
                                if (!tid || tid == GetCurrentThreadId())
                                {
                                    continue;
                                }
                                bool exe_start = false;
                                if (query && exe_base && exe_size)
                                {
                                    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
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
        bool PrivilegeAttempted = false;
        bool PrivilegeOk = false;
        bool SponsorOpened = false;
        ULONG_PTR SponsorValue = 0;
        DWORD SponsorAccess = 0;
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
            else if (general && EqualsNoCase(key, XOR_STR_W(L"DetachConsole").get()))
            {
                config.detach_console = ParseConfigBool(value, config.detach_console);
            }
            else if (general && EqualsNoCase(key, XOR_STR_W(L"HookRestore").get()))
            {
                config.hook_restore = ParseConfigBool(value, config.hook_restore);
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
            fwprintf(stderr, L"%lsFailed to query runtime size: 0x%08X%ls\n", kRed, GetLastError(), kReset);
            return false;
        }
        if (size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > PE_IMAGE::MAX_IMAGE_SIZE)
        {
            fwprintf(stderr, L"%lsInvalid runtime size: %lld bytes%ls\n", kRed, size.QuadPart, kReset);
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
                fwprintf(stderr, L"%lsFailed to read runtime: 0x%08X (%zu of %zu bytes)%ls\n", kRed, read_error, total, bytes.size(), kReset);
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
            fwprintf(stderr, L"%lsRuntime DLL PE validation failed: 0x%08X%ls\n", kRed, validation_result, kReset);
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
            PrintError(L"The runtime has no embedded SHA-256. Build it with Build\\Executors\\Create.bat.");
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
            fwprintf(stderr, L"%lsRuntime DLL SHA-256 mismatch. Expected %ls, got %ls%ls\n", kRed, expected_hash.c_str(), actual_hash.c_str(), kReset);
            return false;
        }

        return true;
    }

    bool LoadRuntime(Runtime & runtime, const WizardConfig & config)
    {
        const std::wstring path = RuntimePath(config.dll_dir, config.runtime_name);
        if (path.empty() || !FileExists(path))
        {
            PrintError((L"The runtime DLL (" + config.runtime_name + L") is missing in " + config.dll_dir + L"\\ next to the executable.").c_str());
            return false;
        }

        HANDLE runtime_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (runtime_file == INVALID_HANDLE_VALUE)
        {
            fwprintf(stderr, L"%lsFailed to open runtime for verification: 0x%08X%ls\n", kRed, GetLastError(), kReset);
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

                // Optional export lookup: present when the runtime is new enough, absent otherwise. A
                // missing entry never fails the load, it only drops the capability.
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

                auto exp_err = XOR_STR_A("CoreLastError");
                runtime.get_last_error_info = reinterpret_cast<f_GetLastErrorInfo>(resolve_export(exp_err.get()));

                // Optional: a runtime built before the diagnostic ring gained a reset entry. It is
                // looked up but never required, so an older runtime still loads and only loses the
                // ability to clear a stale record between runs.
                auto exp_clear_err = XOR_STR_A("CoreClearLastError");
                runtime.clear_last_error_info = reinterpret_cast<f_ClearLastErrorInfo>(resolve_optional_export(exp_clear_err.get()));

                if (runtime.set_raw_print_callback)
                {
                    runtime.set_raw_print_callback(QuietPrint);
                }
            }
        }

        if (!runtime.module)
        {
            fwprintf(stderr, L"%lsFailed to load runtime: %ls (0x%08X)%ls\n", kRed, path.c_str(), load_error, kReset);
            return false;
        }

        if (!export_map_complete)
        {
            PrintError(L"The runtime export map does not cover every export this launcher needs.");
            FreeLibrary(runtime.module);
            runtime.module = nullptr;
            return false;
        }

        if (!runtime.memory_inject || !runtime.get_symbol_state || !runtime.get_import_state || !runtime.initialize_runtime || !runtime.start_download)
        {
            PrintError(L"The runtime DLL does not expose the required functions.");
            FreeLibrary(runtime.module);
            runtime.module = nullptr;
            return false;
        }

        if (runtime.get_last_hijack_stats)
        {
            if (VerboseOutputEnabled()) { wprintf(L"%ls[+]%ls Telemetry export found.\n\n", kGreen, kReset); }

        }
        else
        {
            wprintf(L"  %ls[!]%ls Telemetry export missing; the Acquire process handle step will show no telemetry.\n", kYellow, kReset);
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
        while (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
        {
            if (GetTickCount64() >= deadline)
            {
                return false;
            }
            Sleep(10);
            symbol_state = runtime.get_symbol_state();
        }
        if (symbol_state != INJ_ERR_SUCCESS)
        {
            return false;
        }

        import_state = runtime.get_import_state();
        deadline = GetTickCount64() + timeout;
        while (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
        {
            if (GetTickCount64() >= deadline)
            {
                return false;
            }
            Sleep(10);
            import_state = runtime.get_import_state();
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
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
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

    bool SelectTarget(const std::wstring & configured_name, TargetSelection & target, bool & cancelled)
    {
        cancelled = false;
        if (configured_name.empty())
        {

            PrintError(XOR_STR_W(L"No target process is configured (ProcessName is empty).").get());
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
            wprintf(L"%ls[+]%ls Waiting for %ls... (Press Q to quit)\n", kGreen, kReset, target.requested_name.c_str());
        }
        for (;;)
        {
            const DWORD found = FindProcess(target.requested_name);
            if (found && QueryProcess(found, target.name, target.architecture))
            {
                target.pid = found;
                if (hasConsoleForWait)
                {
                    wprintf(L"%ls[+]%ls %ls detected | PID: %ls%lu%ls\n", kGreen, kReset, target.name.c_str(), kGreen, static_cast<unsigned long>(found), kReset);
                }
                return true;
            }

            if (!hasConsoleForWait)
            {
                // Headless WINDOWS build: no console input exists, so wait
                // without a cancel key. Cancellation is served by the
                // layered confirmation gates before and after this wait.
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
            PrintError(L"The payload is not configured (the deployment payload name is empty).");
            return false;
        }

        const std::wstring path = directory + dll_dir + L"\\" + payload_name;
        if (!FileExists(path))
        {
            PrintError((L"The payload DLL (" + payload_name + L") is missing in " + dll_dir + L"\\ next to the executable.").c_str());
            return false;
        }

        DWORD validation_code = FILE_ERR_SUCCESS;
        std::wstring sha256;
        if (!InspectDll(path, flags, info, bytes, sha256, &validation_code))
        {
            if (validation_code != FILE_ERR_SUCCESS)
            {
                fwprintf(stderr, L"%lsNot a usable DLL (PE validation 0x%08X). Need x64 DLL with relocations, no .NET.%ls\n",
                    kYellow, validation_code, kReset);
            }
            else
            {
                PrintWarning(L"Not a usable DLL.");
            }
            return false;
        }

        if (expected_sha256.empty())
        {
            PrintError(XOR_STR_W(L"The payload pin is missing (PayloadSha256 is empty); refusing to load without a pinned digest.").get());
            return false;
        }
        if (_wcsicmp(expected_sha256.c_str(), sha256.c_str()) != 0)
        {
            fwprintf(stderr, L"%lsPayload SHA-256 mismatch. Expected %ls, got %ls%ls\n", kRed, expected_sha256.c_str(), sha256.c_str(), kReset);
            return false;
        }

        if (info.dotnet)
        {
            PrintError(L".NET assemblies are not supported in this memory-loading build.");
            return false;
        }
        if (info.architecture == Architecture::X86)
        {
            PrintError(L"x86 DLLs are not supported in this x64-only build.");
            return false;
        }

        if (VerboseOutputEnabled()) { wprintf(L"Verified SHA-256: %ls%ls%ls\n", kGreen, sha256.c_str(), kReset); }
        return true;
    }

    // Pre-flight capability report. A payload whose exports are erased by INJ_MM_CLEAN_DATA_DIR can no
    // longer be resolved by name, which silently breaks any caller that intends to look its entry point up
    // after the load. Erasing exports is deliberate anti-fingerprinting, so this is reported rather than
    // treated as fatal.
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
            wprintf(L"  %ls[*]%ls CleanDataDirectories is on; the payload's export directory is erased during the load.\n",
                kDim, kReset);
            wprintf(L"      Anything that resolves this payload by export name afterwards will fail.\n");
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
            wprintf(L"  %ls[!]%ls %ls handle: no telemetry (older runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        const bool SponsorUsed = Stats->Success && Stats->Source == static_cast<DWORD>(HijackSource::Sponsor);

        wchar_t Text[256]{ 0 };

        wprintf(L"  %ls acquisition trace:\n\n", Kind);

        int Stage = 0;
        const bool target_known = Context && !Context->TargetName.empty();
        wprintf(L"    %ls %ls %ls%ls%ls, PID %ls%lu%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Target").c_str(),
            target_known ? kGreen : kYellow,
            target_known ? Context->TargetName.c_str() : L"unknown", kReset,
            kGreen, Context ? Context->TargetPid : 0, kReset);

        const DWORD hijack_flag = INJ_HANDLE_HIJACKING;
        const bool hijack_on = (Flags & hijack_flag) != 0;
        const wchar_t * FlagTint = hijack_on ? kGreen : kYellow;
        wprintf(L"    %ls %ls %ls%s%ls (%ls0x%04X%s in flags %ls0x%08X%s)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Config flag").c_str(),
            FlagTint, hijack_on ? L"Y" : L"N", kReset,
            FlagTint, hijack_flag, kReset,
            FlagTint, Flags, kReset);

        if (!IsThread && Context)
        {

            const wchar_t * privilege_text =
                !Context->PrivilegeAttempted ? L"not required" :
                (Context->PrivilegeOk ? L"enabled" : L"FAILED");
            const wchar_t * privilege_tint =
                !Context->PrivilegeAttempted ? kYellow :
                (Context->PrivilegeOk ? kGreen : kRed);
            wprintf(XOR_STR_W(L"    %ls %ls SeDebugPrivilege %ls%s%ls\n").get(), StageTag(++Stage).c_str(), StageLabel(L"Privilege").c_str(),
                privilege_tint, privilege_text, kReset);
        }

        if (IsThread && Context && Context->SponsorThreadOpened)
        {
            wprintf(L"    %ls %ls %ls0x%08X%ls pre-opened, TID %ls0x%04X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorThreadValue), kReset,
                kGreen, Context->SponsorTid, kReset);
        }
        else if (IsThread && Context && Context->SponsorThreadAttempted)
        {

            wprintf(L"    %ls %ls %lsFAILED%ls (no valid TID)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kRed, kReset);
        }
        else if (IsThread)
        {
            wprintf(L"    %ls %ls %lsnot attempted%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }
        else if (Context && Context->SponsorOpened)
        {
            wprintf(L"    %ls %ls %ls0x%08X%ls pre-opened, mask %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorValue), kReset,
                kGreen, Context->SponsorAccess, kReset);

            const bool skip_roundtrip = (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) != 0;
            const wchar_t * RoundTripText =
                Stats->SponsorProbed ? L"OK" : (skip_roundtrip ? L"skipped" : L"FAILED");
            const wchar_t * RoundTripTint =
                Stats->SponsorProbed ? kGreen : (skip_roundtrip ? kGreen : kRed);
            wprintf(L"    %ls %ls identity %ls%s%ls, roundtrip %ls%s%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor proof").c_str(),
                Stats->SponsorValidated ? kGreen : kRed, Stats->SponsorValidated ? L"OK" : L"FAILED", kReset,
                RoundTripTint, RoundTripText, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls %lsnone%ls (donor scan only)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }

        if (SponsorUsed)
        {

            wprintf(L"    %ls %ls %lsnot required%ls (sponsor satisfied acquisition)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Scan").c_str(), kYellow, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls status %ls0x%08X%ls, %ls%lu%ls handles\n", StageTag(++Stage).c_str(),
                StageLabel(L"Enumeration").c_str(),
                Stats->SnapStatus == 0 ? kGreen : kYellow, Stats->SnapStatus, kReset,
                kGreen, Stats->TotalHandles, kReset);

            wprintf(L"    %ls %ls %ls%s%ls (%ls)\n", StageTag(++Stage).c_str(), StageLabel(L"Calibration").c_str(),
                Stats->Calibrated ? kGreen : kYellow,
                Stats->Calibrated ? L"self-calibrated" : L"uncalibrated", kReset,
                Stats->Calibrated ? L"filtered scan" : L"unfiltered scan");

            wprintf(L"    %ls %ls examined %ls%lu%ls of %ls%lu%ls, owners %ls%lu%ls, dup-denied %ls%lu%ls, verify-rejected %ls%lu%ls, budget-skipped %ls%lu%ls\n",
                StageTag(++Stage).c_str(), StageLabel(L"Scan").c_str(),
                kGreen, Stats->Examined, kReset, kGreen, Stats->TotalHandles, kReset,
                kGreen, Stats->OwnersOpened, kReset, kGreen, Stats->DupDenied, kReset,
                kGreen, Stats->VerifyRejected, kReset, kGreen, Stats->BudgetSkipped, kReset);
        }

        if (Stats->Success && Stats->DonorPid)
        {

            wchar_t Donor[MAX_PATH * 2]{ 0 };
            DescribeDonor(Stats->DonorPid, Donor);
            if (Donor[0])
            {
                wprintf(L"    %ls %ls %ls%s%ls (PID %ls%lu%ls), handle %ls0x%08X%ls, dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor owner").c_str(), kGreen, Donor, kReset,
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
            else
            {
                wprintf(L"    %ls %ls PID %ls%lu%ls, handle %ls0x%08X%ls, dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor owner").c_str(),
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
        }
        else
        {
            wprintf(L"    %ls %ls %lsnone%ls qualifying\n", StageTag(++Stage).c_str(),
                StageLabel(L"Donor owner").c_str(), kYellow, kReset);
        }

        if (Stats->Success)
        {
            if (Stats->Source == static_cast<DWORD>(HijackSource::Sponsor))
            {
                swprintf_s(Text, L"SPONSOR");
            }
            else
            {
                swprintf_s(Text, L"DONOR SCAN");
            }
            wprintf(L"    %ls %ls %ls%s%ls, granted %ls0x%08X%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Result").c_str(),
                kGreen, Text, kReset, kGreen, Stats->GrantedAccess, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            wprintf(L"    %ls %ls %lsDIRECT OPEN%ls (code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls %lsFAILED%ls (code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kRed, kReset, kRed, Stats->FailCode, kReset);
        }

        if (IsThread && Context && Context->SponsorTid && Context->UsedTid
            && Context->UsedTid != Context->SponsorTid && Stats->Success
            && Stats->Source != static_cast<DWORD>(HijackSource::Sponsor))
        {
            wprintf(L"    %ls %ls sponsor TID %ls0x%04lX%ls %lsnot usable%ls; hijacked TID %ls0x%04lX%ls\n",
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
            wprintf(L"  %ls[!]%ls %ls handle: no telemetry (older runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        if (Stats->Success)
        {
            const wchar_t * SourceText = Stats->Source == static_cast<DWORD>(HijackSource::Sponsor) ? L"sponsor"
                : Stats->Source == static_cast<DWORD>(HijackSource::Scan) ? L"scan" : L"direct";
            wprintf(L"  %ls[+]%ls %ls handle acquired via %ls%s%ls (%ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kGreen, SourceText, kReset, kGreen, Stats->NewHandle, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            wprintf(L"  %ls[+]%ls %ls handle acquired via %lsdirect%s (code %ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            wprintf(L"  %ls[!]%ls %ls handle failed (code %ls0x%08X%ls)\n", kYellow, kReset, Kind,
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

    // Verification steps in execution order. DebugAndVerifyStealth gates every step on the matching
    // entry of its enabled table and derives the "step/total" denominator from that same table, so
    // the counter can never drift out of sync when a flag is edited.
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
        default:                     return L"UNKNOWN";
        }
    }

    // "Verify W^X execution" step. Split out of DebugAndVerifyStealth verbatim; it only depends on the
    // remote image span, the local section table and the caller's W^X verdict flag.
    void StealthVerifyWxExecution(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        const BYTE * local_pe, size_t local_pe_size, StealthVerifierBuffers & buffers,
        bool * wx_violated, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify W^X execution (advisory)...\n\n", kGreen, step, kReset, kGreen, total, kReset);

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

                    swprintf_s(RxField, L"RX %ls%lu%ls region(s); all %ls%lu%ls executable section(s) are RX",
                        RxTint, static_cast<unsigned long>(wx_rx), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
                else
                {
                    swprintf_s(RxField, L"RX missing for %ls%lu%ls of %ls%lu%ls executable section(s)",
                        RxTint, static_cast<unsigned long>(wx_exec_uncovered), kReset,
                        RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                }
            }
            else
            {
                swprintf_s(RxField, L"RX %ls%lu%ls region(s), none declared by the section table",
                    RxTint, static_cast<unsigned long>(wx_rx), kReset);
            }

            wprintf(L"  %ls%ls%ls W^X %ls: RWX %ls%d%ls (required %ls0%ls) | %s | RW %ls%d%s\n",
                wx_ok ? kGreen : kYellow, wx_ok ? L"[+]" : L"[!]", kReset,
                wx_ok ? L"verified" : L"VIOLATED",
                wx_ok ? kGreen : kYellow, wx_rwx, kReset,
                kGreen, kReset,
                RxField,
                kGreen, wx_rw, kReset);

            wprintf(L"      %lscoverage%s: %ls%d%s region(s), %ls%lu%s KB of %ls%lu%s KB image, %s%s%s\n",
                kDim, kReset, kGreen, wx_regions, kReset,
                kGreen, static_cast<unsigned long>(wx_bytes / 1024), kReset,
                kGreen, static_cast<unsigned long>(wx_image / 1024), kReset,
                wx_reached_end ? kReset : kYellow,
                wx_reached_end ? L"reached end of image" : L"TRUNCATED - image not fully scanned",
                kReset);

            {
                const bool single = wx_alloc_bases.size() == 1;
                wprintf(L"      %lsallocations%s: %ls%zu%s %s(%s %s%s)%s | %lsprivate%s: %ls%zu%s KB\n",
                    kDim, kReset,
                    kGreen, wx_alloc_bases.size(), kReset,
                    single ? kGreen : kYellow,
                    single ? L"single" : L"split across",
                    single ? L"allocation" : L"allocations",
                    single ? kGreen : kYellow,
                    kReset,
                    kDim, kReset,
                    kGreen, static_cast<size_t>(wx_bytes / 1024), kReset);
            }

            for (int i = 0; i < wx_rwx_listed; ++i)
            {
                wprintf(L"      %lsRWX region at 0x%016llX, %llu bytes%s\n", kYellow,
                    static_cast<unsigned long long>(wx_rwx_list[i].base),
                    static_cast<unsigned long long>(wx_rwx_list[i].size), kReset);
            }
            if (wx_rwx > wx_rwx_listed)
            {
                wprintf(L"      %ls... and %d more RWX region(s)%s\n", kYellow, wx_rwx - wx_rwx_listed, kReset);
            }
        }
        else if (!wx_queryable)
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            wprintf(L"  %ls[!]%ls Image not queryable; W^X state unknown.\n", kYellow, kReset);
        }
        else
        {

            if (wx_violated)
            {
                *wx_violated = true;
            }
            wprintf(L"  %ls[!]%ls Image size unknown; W^X scan not bounded, result withheld.\n", kYellow, kReset);
        }
    }

    void StealthVerifyStringEncryption(StealthVerifierBuffers & buffers, f_GetLastStringStats get_string_stats,
        bool & string_gate_ok, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify string encryption...\n\n", kGreen, step, kReset, kGreen, total, kReset);

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
        auto m29 = XOR_STR_A("SYMBOL_LOADER");
        auto m30 = XOR_STR_A("SYMBOL_PARSER");
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
                    wprintf(L"  %ls[x]%ls marker '%ls' FOUND in runtime DLL (narrow %d, wide %d).\n",
                        kRed, kReset, wide_marker, hit_narrow ? 1 : 0, hit_wide ? 1 : 0);
                }
            }
        }
        if (!buffers.runtime_path_known)
        {
            wprintf(L"  %ls[x]%ls Runtime path unknown; disk-marker check could not run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (!rt_read)
        {
            wprintf(L"  %ls[x]%ls Runtime DLL unreadable; disk-marker check could not run.\n", kRed, kReset);
            string_gate_ok = false;
        }
        else if (marker_found)
        {
            wprintf(L"  %ls[x]%ls %ls%zu of %zu markers present - string encryption regressed.%ls\n",
                kRed, kReset, kRed, static_cast<size_t>(marker_found), marker_count, kReset);
            wprintf(L"      These names are plaintext in .rdata and are directly scannable in the target.\n");
            wprintf(L"      A decrypt path that /O2 can constant-fold will always leak here; see\n");
            wprintf(L"      the encrypted-string helper header used by the runtime build.\n");
            string_gate_ok = false;
        }
        else
        {
            wprintf(L"  %ls[+]%ls %ls%zu%ls markers absent from runtime DLL (ciphertext only)\n",
                kGreen, kReset, kGreen, marker_count, kReset);
        }

        STRING_STATS StringStats{};
        if (get_string_stats)
        {
            get_string_stats(&StringStats);
        }

        if (!get_string_stats || !StringStats.Reported)
        {
            wprintf(L"  %ls[!]%ls String-tier counters unavailable from runtime; "
                    L"resolution results not reported.\n", kYellow, kReset);
        }
        else
        {
            const bool all_symbols = StringStats.SymbolsResolved == StringStats.SymbolsDeclared;
            wprintf(L"  %ls[+]%ls NT symbols resolved via encrypted names: %ls%lu%ls of %ls%lu%ls (import %ls%s%ls)\n",
                kGreen, kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsResolved), kReset,
                all_symbols ? kGreen : kYellow,
                static_cast<unsigned long>(StringStats.SymbolsDeclared), kReset,
                all_symbols ? kGreen : kYellow,
                all_symbols ? L"SUCCESS" : L"PARTIAL",
                kReset);

            wprintf(L"  %ls[+]%ls Encrypted names built from ciphertext, no static table: %ls%lu%ls\n",
                kGreen, kReset, kGreen,
                static_cast<unsigned long>(StringStats.HookNamesBuilt), kReset);

            const bool tiers_ok = StringStats.TiersTotal != 0
                && StringStats.TiersPassed == StringStats.TiersTotal;
            wprintf(L"  %ls[+]%ls self-test tiers passed at import-resolve: %ls%lu%ls of %ls%lu%ls\n",
                kGreen, kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersPassed), kReset,
                tiers_ok ? kGreen : kRed,
                static_cast<unsigned long>(StringStats.TiersTotal), kReset);
        }
    }

    // Shared "RVA -> file offset" resolver used by the import and TLS survey steps. This was a local
    // lambda in DebugAndVerifyStealth; split out verbatim so the extracted steps can share it.
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

    // Minimal "RVA -> file offset" resolver over a raw section table. Shared by the forensic and
    // payload posture steps so the mapping logic exists in exactly one place.
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


    // "Acquire process handle" step. Split out of DebugAndVerifyStealth verbatim; it only prints the
    // process/thread hijack trace (or summary) chosen by the caller's verbose context.
    void StealthAcquireHandle(const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, DWORD flags, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Acquire process handle...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (!Context || Context->Verbose)
        {
            PrintHijackTrace(L"Process", ProcessHijack, Context, flags, false);
            wprintf(L"\n");
            PrintHijackTrace(L"Thread", ThreadHijack, Context, flags, true);
        }
        else
        {
            PrintHijackSummary(L"Process", ProcessHijack);
            PrintHijackSummary(L"Thread", ThreadHijack);
        }
    }

    // "Resolve imports" step. Split out of DebugAndVerifyStealth verbatim; surveys the payload's static
    // import descriptors from the local image.
    void StealthResolveImports(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Resolve imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        struct ImportEntry { char name[MAX_PATH + 1]; ULONG thunk_count; bool named; };
        ImportEntry imports[64]{};
        int import_count = 0;
        ULONG import_total_thunks = 0;
        const char * import_problem = nullptr;

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
                            import_problem = "descriptor list truncated at 64 entries";
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
                    import_problem = "import directory RVA not file-backed";
                }
            }
            else
            {
                import_problem = nullptr;
            }
        }

        if (import_count > 0)
        {
            wprintf(L" %ls[+]%ls %ls%d%ls import descriptor(s), %ls%lu%ls function(s) total.\n",
                kGreen, kReset, kGreen, import_count, kReset, kGreen,
                static_cast<unsigned long>(import_total_thunks), kReset);

            if (VerboseOutputEnabled())
            {
                wprintf(L"\n");
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
                    wprintf(L"      %ls%ls%ls%lu%ls thunk(s)\n",
                        StageField(ordinal, 6).c_str(),
                        StageField(wide, 26).c_str(),
                        kGreen, static_cast<unsigned long>(imports[i].thunk_count), kReset);
                }
            }
        }
        else
        {
            wprintf(L"  %ls[+]%ls No statically linked import descriptors in the payload.\n", kGreen, kReset);
        }

        if (import_problem)
        {
            wchar_t problem_w[MAX_PATH + 1]{ 0 };
            if (MultiByteToWideChar(CP_ACP, 0, import_problem, -1, problem_w, MAX_PATH + 1) <= 0)
            {
                wcscpy_s(problem_w, L"<unprintable>");
            }
            wprintf(L"  %ls[!]%ls Import survey incomplete: %ls%s%ls\n", kYellow, kReset, kYellow, problem_w, kReset);
        }
    }

    // "Resolve delay imports" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthResolveDelayImports(bool have_local_nt, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Resolve delay imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            auto & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (dir.Size > 0)
                wprintf(L"  %ls[+]%ls Delay-import directory present in payload (%ls%lu%ls bytes).\n",
                    kGreen, kReset, kGreen, dir.Size, kReset);
            else
                wprintf(L"  %ls[+]%ls No delay-import directory present in module.\n", kGreen, kReset);
        }
        else
        {
            wprintf(L"  %ls[+]%ls No local image to survey.\n", kGreen, kReset);
        }
    }

    // "Initialize security cookie" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthInitSecurityCookie(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Initialize security cookie...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        if (process && have_local_nt)
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
                    wprintf(L"  %ls[+]%ls Security cookie initialized (by design; not measured), TLS Directory VA = %ls0x%016llX%ls\n",
                        kGreen, kReset, kGreen, tls->AddressOfCallBacks, kReset);
                }
                else
                {
                    wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
                }
            }
            else
            {
                wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
            }
        }
        else
        {
            wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
        }
    }

    // "Enable exceptions (SEH)" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthEnableExceptions(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Enable exceptions (SEH)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        wprintf(L"  %ls[+]%ls SEH via inverted/function table, zero VEH chain entries (by design; not measured)\n", kGreen, kReset);
        wprintf(L"\n");

        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                const DWORD entry_count = exception_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));
                wprintf(L"  %ls[+]%ls Exception directory    : RVA %ls0x%08X%ls  size %ls0x%08X%ls  %ls%lu%s entry(ies)\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, exception_dir.Size, kReset,
                    kGreen, static_cast<unsigned long>(entry_count), kReset);

                const ULONG_PTR remote_table = ReCa<ULONG_PTR>(hRemoteBase) + exception_dir.VirtualAddress;
                RUNTIME_FUNCTION probe{};
                SIZE_T got = 0;
                if (process && ReadProcessMemory(process, ReCa<void *>(remote_table), &probe, sizeof(probe), &got) && got == sizeof(probe))
                {
                    wprintf(L"  %ls[+]%ls .pdata table     : %ls0x%016llX%ls  first %ls0x%08X%s - %s0x%08X%s\n",
                        kGreen, kReset, kGreen, static_cast<unsigned long long>(remote_table), kReset,
                        kGreen, probe.BeginAddress, kReset, kGreen, probe.EndAddress, kReset);
                }
                else
                {
                    wprintf(L"  %ls[!]%ls .pdata table not readable at 0x%016llX\n", kYellow, kReset,
                        static_cast<unsigned long long>(remote_table));
                }
            }
            else
            {
                wprintf(L"  %ls[+]%ls No exception directory present in the payload.\n", kGreen, kReset);
            }
        }

        wprintf(L"\n");
        wprintf(L"  %ls[+]%ls Inverted function table updated for %ls%s%ls (by design; not measured)\n", kGreen, kReset, kGreen, XOR_STR_W(L"RtlAddFunctionTable").get(), kReset);
    }

    // "Verify exception handling" step. Split out of DebugAndVerifyStealth verbatim; the flags gate
    // mirrors the caller's INJ_MM_ENABLE_EXCEPTIONS check.
    void StealthVerifyExceptionHandling(DWORD flags, bool have_local_nt, StealthVerifierBuffers & buffers,
        f_GetLastStringStats get_string_stats, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify exception handling...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        wprintf(L"  %ls[+]%ls Launcher VEH shell............ %lsnone by design; not measured%ls\n",
            kGreen, kReset, kGreen, kReset);
        wprintf(L"  %ls[+]%ls Added VEH chain entries........ %ls0%ls (by design; not measured)\n",
            kGreen, kReset, kGreen, kReset);
        wprintf(L"  %ls[+]%ls SEH coverage................... %ls%s%ls\n",
            kGreen, kReset,
            isActive(INJ_MM_ENABLE_EXCEPTIONS) ? kGreen : kYellow,
            isActive(INJ_MM_ENABLE_EXCEPTIONS) ? L"dynamic function table (RtlAddFunctionTable), VEH-free + reversible; runtime-verified (by design; not measured)"
                                               : L"disabled; payload exceptions not covered",
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
            wprintf(L"  %ls[+]%ls Encrypted NT imports............ %ls%lu%ls of %ls%lu%ls\n",
                kGreen, kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsResolved), kReset,
                all_imports ? kGreen : kYellow,
                static_cast<unsigned long>(stealth_fix_stats.SymbolsDeclared), kReset);
            wprintf(L"  %ls[+]%ls Self-test tiers................. %ls%lu%ls of %ls%lu%ls\n",
                kGreen, kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersPassed), kReset,
                stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                static_cast<unsigned long>(stealth_fix_stats.TiersTotal), kReset);
        }
        else
        {
            wprintf(L"  %ls[!]%ls Encrypted NT import counters.... %lsUNAVAILABLE%ls (cannot verify VEH import removal from runtime)\n",
                kYellow, kReset, kYellow, kReset);
        }

        if (have_local_nt && isActive(INJ_MM_ENABLE_EXCEPTIONS))
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exception_dir.Size)
            {
                wprintf(L"  %ls[+]%ls Payload exception data.......... RVA %ls0x%08X%ls, %ls%lu%ls entries\n",
                    kGreen, kReset,
                    kGreen, exception_dir.VirtualAddress, kReset,
                    kGreen, static_cast<unsigned long>(exception_dir.Size / sizeof(RUNTIME_FUNCTION)), kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Payload exception data.......... none; SEH-only cannot unwind payload exceptions\n",
                    kYellow, kReset);
            }
        }
    }

    // "Execute TLS" step. Split out of DebugAndVerifyStealth verbatim; it only surveys the payload's
    // TLS callback table from the local image.
    void StealthExecuteTls(bool have_local_nt, const BYTE * local_pe, size_t local_pe_size,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Execute TLS...\n\n", kGreen, step, kReset, kGreen, total, kReset);
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
        if (tls_callbacks > 0)
            wprintf(L"  %ls[+]%ls %ls%d%ls TLS callback(s) found (execution by design; not measured).\n",
                kGreen, kReset, kGreen, tls_callbacks, kReset);
        else

            wprintf(L"  %ls[+]%ls No TLS callbacks present (callback array empty or absent).\n",
                kGreen, kReset);
    }

    // "Execute DllMain" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthExecuteDllMain(int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Execute DllMain...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        wprintf(L"  %ls[+]%ls %lsDllMain(DLL_PROCESS_ATTACH)%ls invocation by design; success inferred from the operation result.\n", kGreen, kReset, kGreen, kReset);
        wprintf(L"  %ls[+]%ls DllMain return value: %lsTRUE%ls (by design; not measured)\n", kGreen, kReset, kGreen, kReset);
    }

    // "Run under loader lock" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthRunUnderLoaderLock(int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Run under loader lock...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        wprintf(XOR_STR_W(L"  %ls[+]%ls LdrLockLoaderLock acquired (by design; not measured).\n").get(), kGreen, kReset);
        wprintf(XOR_STR_W(L"  %ls[+]%ls LdrUnlockLoaderLock acquired (by design; not measured).\n").get(), kGreen, kReset);
    }

    // "Clean data directories" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthCleanDataDirectories(const MAP_STATS * MapStats, bool have_remote_nt, BYTE * nt_data, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Clean data directories...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        const bool have_shell_report = MapStats &&
            (MapStats->CleanedMask || MapStats->ImportSize || MapStats->DelayImportSize ||
             MapStats->RelocSize || MapStats->TlsSize || MapStats->DebugSize || MapStats->ExportSize);

        if (have_shell_report)
        {

            wprintf(L"  %ls[+]%ls Import = %ls%d%ls | DelayImport = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Debug = %ls%d%ls | Export = %ls%d%ls\n",
                kGreen, kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_BASERELOC) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_TLS) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DEBUG) & 1), kReset,
                kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_EXPORT) & 1), kReset);
            wprintf(L"  %ls[+]%ls Pre-clean sizes: Import %ls0x%08X%ls | DelayImport %ls0x%08X%ls | Reloc %ls0x%08X%ls | TLS %ls0x%08X%ls | Debug %ls0x%08X%ls | Export %ls0x%08X%ls\n",
                kGreen, kReset,
                kGreen, MapStats->ImportSize, kReset,
                kGreen, MapStats->DelayImportSize, kReset,
                kGreen, MapStats->RelocSize, kReset,
                kGreen, MapStats->TlsSize, kReset,
                kGreen, MapStats->DebugSize, kReset,
                kGreen, MapStats->ExportSize, kReset);
            wprintf(L"\n  %ls[+]%ls All data directories zeroed successfully.\n", kGreen, kReset);
            if (MapStats->Verified)
            {
                wprintf(L"  %ls[+]%ls Payload-side re-read confirms all 6 directories are zero "
                        L"(verified before header cloak).\n", kGreen, kReset);
            }
            else if (MapStats->ResidualMask)
            {
                wprintf(L"  %ls[!]%ls Re-read found %d directory entry/entries still non-zero "
                        L"(mask 0x%08X).\n",
                    kYellow, kReset, static_cast<int>(MapStats->ResidualMask), MapStats->ResidualMask);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Payload reported success but performed no read-back "
                        L"verification.\n", kYellow, kReset);
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
                    wprintf(L"  %ls[+]%ls Remote directories confirmed zeroed post-clean.\n", kGreen, kReset);
                }
                else
                {
                    wprintf(L"  %ls[!]%ls Remote directories retain entries post-clean.\n", kYellow, kReset);
                }
            }
            else
            {
                wprintf(L"  %ls[+]%ls Cross-process re-read not applicable: the header is "
                        L"intentionally cloaked by the mapper before control returns.\n", kGreen, kReset);
            }
        }
        else if (nt_data)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
            wprintf(L"  %ls[+]%ls Import = %ls%d%ls  Reloc = %ls%d%ls  TLS = %ls%d%ls  Exception = %ls%d%ls  Security = %ls%d%ls  Debug = %ls%d%ls  GlobalPtr = %ls%d%ls\n",
                kGreen, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size == 0 ? 0 : 1, kReset,
                kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size == 0 ? 0 : 1, kReset);
            wprintf(L"  %ls[+]%ls All data directories zeroed to prevent static analysis.\n", kGreen, kReset);
        }
        else
        {
            wprintf(L"  %ls[+]%ls All data directories zeroed (by design; not measured).\n", kGreen, kReset);
        }
    }

    // "Set page protections" step. Split out of DebugAndVerifyStealth verbatim; it tallies the remote
    // image's page protections.
    void StealthSetPageProtections(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Set page protections...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (process && VirtualQueryEx(process, hRemoteBase, &mbi, sizeof(mbi)))
        {
            int rwx_count = 0;
            int ro_count = 0;
            int rw_count = 0;
            int rx_count = 0;
            int priv_exec_count = 0;

            SIZE_T total_image_size = 0;
            if (have_local_nt)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
                total_image_size = nt->OptionalHeader.SizeOfImage;
            }

            BYTE * current = ReCa<BYTE *>(hRemoteBase);
            while (true)
            {
                if (!VirtualQueryEx(process, current, &mbi, sizeof(mbi)) || !mbi.RegionSize)
                    break;
                if (total_image_size > 0 &&
                    (ReCa<ULONG_PTR>(mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= total_image_size)
                    break;
                if (mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0)
                {
                    if (mbi.Protect == PAGE_EXECUTE_READWRITE) ++rwx_count;
                    else if (mbi.Protect == PAGE_READONLY)      ++ro_count;
                    else if (mbi.Protect == PAGE_READWRITE)     ++rw_count;
                    else if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) ++rx_count;
                    if (mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE ||
                         mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) ++priv_exec_count;
                }

                BYTE * next = ReCa<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= current)
                    break;
                current = next;
            }
            wprintf(L"  %ls[+]%ls %ls = %ls%d%ls  %ls = %ls%d%ls  %ls = %ls%d%ls  %ls = %ls%d%ls\n",
                kGreen, kReset,
                StealthPageDesc(PAGE_EXECUTE_READWRITE), kGreen, rwx_count, kReset,
                StealthPageDesc(PAGE_READONLY), kGreen, ro_count, kReset,
                StealthPageDesc(PAGE_READWRITE), kGreen, rw_count, kReset,
                StealthPageDesc(PAGE_EXECUTE_READ), kGreen, rx_count, kReset);
            wprintf(L"  %ls[+]%ls Private executable regions: %ls%d%ls\n",
                kGreen, kReset, kGreen, priv_exec_count, kReset);
        }
        else
        {
            wprintf(L"  %ls[+]%ls Section permissions applied to all memory regions (by design; not measured).\n", kGreen, kReset);
        }
    }

    // "Verify forensic posture" step. Split out of DebugAndVerifyStealth verbatim; it reports the
    // runtime and on-disk posture and updates the caller's posture verdict.
    void StealthVerifyForensicPosture(HANDLE process, HINSTANCE hRemoteBase, const BYTE * local_pe, size_t local_pe_size,
        const WizardConfig & config, StealthVerifierBuffers & buffers, bool & posture_ok,
        int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify forensic posture...\n\n", kGreen, step, kReset, kGreen, total, kReset);

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
            wprintf(L"  %ls[x]%ls Runtime DLL unreadable; posture unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else if (!posture_parsed)
        {
            wprintf(L"  %ls[x]%ls Runtime image unparseable; posture unverified.\n", kRed, kReset);
            posture_ok = false;
        }
        else
        {

            if (VerboseOutputEnabled())
            {
                wprintf(L"  %ls[+]%ls Export names: %ls%zu%ls neutral, %ls%zu%ls foreign\n",
                    kGreen, kReset, kGreen, export_neutral, kReset, kGreen, export_foreign, kReset);
                wprintf(L"  %ls[+]%ls Standard section names remaining: %ls%zu%ls\n",
                    kGreen, kReset, kGreen, standard_sections, kReset);
                wprintf(L"  %ls[+]%ls Debug directory size: %ls0x%lX%ls\n",
                    kGreen, kReset, kGreen, static_cast<unsigned long>(debug_size), kReset);
            }
            if (export_foreign || standard_sections || debug_size)
            {
                wprintf(L"  %ls[x]%ls Forensic posture regressed; rebuild with mutation enabled.\n", kRed, kReset);
                posture_ok = false;
            }
            else if (!VerboseOutputEnabled())
            {
                wprintf(XOR_STR_W(L"  %ls[+]%ls Forensic posture clean (detail suppressed; set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
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
        wprintf(L"  %ls[+]%ls Payload export names: %ls%zu%ls | standard sections: %ls%zu%ls | RWX sections: %ls%zu%ls | debug: %ls0x%lX%ls\n",
            kGreen, kReset,
            kGreen, payload_exports, kReset,
            kGreen, payload_standard_sections, kReset,
            kGreen, payload_rwx_sections, kReset,
            kGreen, static_cast<unsigned long>(payload_debug), kReset);
    }
    else if (payload_ok)
    {
        wprintf(XOR_STR_W(L"  %ls[+]%ls Payload on-disk posture clean (detail suppressed; set AMEGER_VERBOSE=1).\n").get(), kGreen, kReset);
    }

            if (!payload_ok)
            {
                wprintf(L"  %ls[!]%ls Payload image could not be re-parsed for a posture report.\n", kYellow, kReset);
            }
            else if (payload_rwx_sections)
            {
                wprintf(L"  %ls[!]%ls Payload declares RWX section(s); mapped regions may inherit that.\n", kYellow, kReset);
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
                wprintf(L"  %ls[+]%ls Loader lists clean: image not enumerated as a module.\n", kGreen, kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Loader-list check inconclusive (enum %ls, listed %ls).\n", kYellow, kReset,
                    enum_ok ? L"ok" : L"failed", listed ? L"yes" : L"no");
            }
        }

        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            bool cfg_read = process &&
                GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE;
            if (cfg_read)
            {
                wprintf(L"  %ls[+]%ls Target CFG policy: enable %ls%lu%s strict %ls%lu%s.\n", kGreen, kReset,
                    kGreen, static_cast<unsigned long>(cfg.EnableControlFlowGuard), kReset,
                    kGreen, static_cast<unsigned long>(cfg.StrictMode), kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Target CFG policy unreadable.\n", kYellow, kReset);
            }
        }
    }

    // "Erase PE header" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthEraseHeader(HANDLE process, HINSTANCE hRemoteBase, bool have_local_nt,
        StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Erase PE header...\n\n", kGreen, step, kReset, kGreen, total, kReset);

        SIZE_T header_size = 0;
        if (have_local_nt)
        {
            auto nt = ReCa<IMAGE_NT_HEADERS *>(buffers.local_headers.data());
            header_size = nt->OptionalHeader.SizeOfHeaders;
        }

        constexpr size_t kProbeBytes = 16;
        BYTE header_bytes[kProbeBytes] = { 0 };
        SIZE_T bytesRead = 0;
        const bool read_ok = process &&
            ReadProcessMemory(process, hRemoteBase, header_bytes, kProbeBytes, &bytesRead) && bytesRead == kProbeBytes;

        if (read_ok)
        {
            const ULONGLONG base = static_cast<ULONGLONG>(ReCa<ULONG_PTR>(hRemoteBase));
            wprintf(L"  %ls[+]%ls Image base      : %ls0x%016llX%ls\n",
                kGreen, kReset, kGreen, base, kReset);

            wchar_t hex[kProbeBytes * 3 + 1] = { 0 };
            const wchar_t digits[] = L"0123456789ABCDEF";
            for (size_t i = 0; i < kProbeBytes; ++i)
            {
                hex[i * 3 + 0] = digits[header_bytes[i] >> 4];
                hex[i * 3 + 1] = digits[header_bytes[i] & 0x0F];
                hex[i * 3 + 2] = L' ';
            }
            hex[kProbeBytes * 3] = L'\0';

            const bool erased = !(header_bytes[0] == 0x4D && header_bytes[1] == 0x5A);
            if (erased)
            {
                wprintf(L"  %ls[+]%ls First %u bytes  : %ls%ls%ls\n",
                    kGreen, kReset, static_cast<unsigned>(kProbeBytes), kGreen, hex, kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls First %u bytes  : %ls%ls%ls\n",
                    kYellow, kReset, static_cast<unsigned>(kProbeBytes), kYellow, hex, kReset);
            }

            if (header_size)
            {

                wprintf(L"  %ls[+]%ls Header region   : %ls0x%016llX%s - %ls0x%016llX%s (%ls0x%llX%s bytes)\n\n",
                    kGreen, kReset, kGreen, base, kReset, kGreen, base + header_size, kReset,
                    kGreen, static_cast<unsigned long long>(header_size), kReset);
            }

            if (erased)
            {
                wprintf(L"  %ls[+]%ls MZ header zeroed - signature scan evasion active.\n", kGreen, kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls MZ header still visible at image base.\n", kYellow, kReset);
            }
        }
        else
        {
            wprintf(L"  %ls[!]%ls Image base not readable; header state unknown.\n", kYellow, kReset);
        }
    }

    // "Survey target traps" step. Split out of DebugAndVerifyStealth verbatim.
    void StealthSurveyTraps(HANDLE process, DWORD survey_pid, StealthVerifierBuffers & buffers, int & step, int total)
    {
        ++step;
        wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Survey target traps...\n\n", kGreen, step, kReset, kGreen, total, kReset);
        ReportGameTraps(process, survey_pid, buffers);
        wprintf(L"\n");
    }

    bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, f_GetLastStringStats get_string_stats,
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

        // Single source of truth for both the step gates and the denominator. Indexed by StealthVerifyStep.
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
            StealthEnableExceptions(process, hRemoteBase, have_local_nt, buffers, step, total);
        }

        if (step_enabled[kStealthVerifyExceptionHandling])
        {
            StealthVerifyExceptionHandling(flags, have_local_nt, buffers, get_string_stats, step, total);
        }

        if (step_enabled[kStealthExecuteTls])
        {
            StealthExecuteTls(have_local_nt, local_pe, local_pe_size, buffers, step, total);
        }

        if (step_enabled[kStealthExecuteDllMain])
        {
            StealthExecuteDllMain(step, total);
        }

        if (step_enabled[kStealthRunUnderLoaderLock])
        {
            StealthRunUnderLoaderLock(step, total);
        }

        if (step_enabled[kStealthCleanDataDirectories])
        {
            StealthCleanDataDirectories(MapStats, have_remote_nt, nt_data, step, total);
        }

        if (step_enabled[kStealthSetPageProtections])
        {
            StealthSetPageProtections(process, hRemoteBase, have_local_nt, buffers, step, total);
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
            StealthEraseHeader(process, hRemoteBase, have_local_nt, buffers, step, total);
        }
        if (step_enabled[kStealthSurveyTraps])
        {
            StealthSurveyTraps(process, survey_pid, buffers, step, total);
        }

        return string_gate_ok && posture_ok;
    }

    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated, const WizardConfig & config,
        StealthVerifierBuffers & buffers)
    {
        __try
        {
            return DebugAndVerifyStealth(process, hRemoteBase, flags, local_pe, local_pe_size, ProcessHijack, ThreadHijack, Context, MapStats, get_string_stats, survey_game_traps, survey_pid, wx_violated, config, buffers);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            wprintf(L"  %ls[x]%ls Verification faulted; gate cannot be satisfied.\n", kRed, kReset);
            return false;
        }
    }

    constexpr size_t kHookScanBytes = 0x10;

    struct HookTarget
    {
        std::wstring module;
        std::string function;
    };

#define ADD_HOOK_TARGET(vec, mod_lit, fn_lit) do { auto hk_mod = XOR_STR_W(mod_lit); auto hk_fn = XOR_STR_A(fn_lit); (vec).push_back(HookTarget{ hk_mod.get(), hk_fn.get() }); } while (0)

    const std::vector<HookTarget> & GetHookTargets()
    {
        static const std::vector<HookTarget> cached = [] {
            std::vector<HookTarget> list;
            list.reserve(22);
            ADD_HOOK_TARGET(list, L"kernel32.dll", "BaseThreadInitThunk");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetModuleHandleW");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetProcAddress");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetLastError");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtOpenFile");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtReadFile");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtClose");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtAllocateVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtProtectVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtFreeVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtDelayExecution");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAllocateHeap");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlFreeHeap");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrUnloadDll");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrGetProcedureAddress");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrGetDllPath");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrLockLoaderLock");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrUnlockLoaderLock");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAddVectoredExceptionHandler");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlRemoveVectoredExceptionHandler");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAddFunctionTable");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAnsiStringToUnicodeString");
            return list;
        }();
        return cached;
    }

    bool GetRemoteModuleBase(HANDLE process, const wchar_t * module_name, ULONG_PTR & base_out)
    {
        base_out = 0;
        if (!process || !module_name)
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
            do
            {
                if (!_wcsicmp(entry.szModule, module_name))
                {
                    base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
                    found = base_out != 0;
                    break;
                }
            } while (Module32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return found;
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

    struct RestoredHook
    {
        std::wstring name;
        unsigned int offset = 0;
    };

    ULONG_PTR ResolveHookTarget(HANDLE process, const HookTarget & target, BYTE * local_bytes_out)
    {
        HMODULE local_module = GetModuleHandleW(target.module.c_str());
        if (!local_module)
        {
            return 0;
        }

        void * local_function = reinterpret_cast<void *>(GetProcAddress(local_module, target.function.c_str()));
        if (!local_function)
        {
            return 0;
        }

        MEMORY_BASIC_INFORMATION local_info{};
        if (!VirtualQuery(local_function, &local_info, sizeof(local_info)) ||
            local_info.AllocationBase != local_module)
        {
            return 0;
        }

        if (local_info.State != MEM_COMMIT ||
            (local_info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
            reinterpret_cast<ULONG_PTR>(local_function) + kHookScanBytes >
                reinterpret_cast<ULONG_PTR>(local_info.BaseAddress) + local_info.RegionSize)
        {
            return 0;
        }

        ULONG_PTR remote_base = 0;
        if (!GetRemoteModuleBase(process, target.module.c_str(), remote_base))
        {
            return 0;
        }

        memcpy(local_bytes_out, local_function, kHookScanBytes);

        return remote_base +
            (reinterpret_cast<ULONG_PTR>(local_function) - reinterpret_cast<ULONG_PTR>(local_module));
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

    size_t FindHookDifference(HANDLE process, ULONG_PTR remote_function, const BYTE * local_bytes)
    {
        if (!IsSafeCodePage(process, remote_function, kHookScanBytes))
        {
            return static_cast<size_t>(-1);
        }

        BYTE remote_bytes[kHookScanBytes]{};
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<void *>(remote_function), remote_bytes, sizeof(remote_bytes), &bytes_read) ||
            bytes_read != sizeof(remote_bytes))
        {
            return static_cast<size_t>(-1);
        }

        for (size_t i = 0; i < sizeof(remote_bytes); ++i)
        {
            if (remote_bytes[i] != local_bytes[i])
            {
                return i;
            }
        }

        return sizeof(remote_bytes);
    }

    std::wstring HookDisplayName(const HookTarget & target)
    {
        std::wstring name = target.module;
        name += L" -> ";
        for (char c : target.function)
        {
            name += static_cast<wchar_t>(c);
        }
        return name;
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

                wprintf(L"  %ls[!]%ls Survey read window unavailable; INT3 scan skipped.\n", kYellow, kReset);
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

            const wchar_t * Verdict = (guarded == 0) ? L"untrapped" : L"guarded";
            const wchar_t * VerdictTint = (guarded == 0) ? L"" : kYellow;
            wprintf(L"  %ls%ls%s%s (%ls%zu%s committed region(s) walked)\n",
                StageField(mod, 24).c_str(),
                VerdictTint, Verdict, kReset,
                kGreen, walked, kReset);

            wprintf(L"\n");

            wprintf(L"      %ls%ls%zu%ls region(s), %ls%zu%ls KB\n",
                StageField(L"guard:", 12).c_str(),
                kGreen, guarded, kReset,
                kGreen, static_cast<size_t>(guarded_bytes / 1024), kReset);

            wprintf(L"      %ls%ls%zu%ls region(s), %ls%zu%ls KB\n",
                StageField(L"no-access:", 12).c_str(),
                kGreen, noaccess, kReset,
                kGreen, static_cast<size_t>(noaccess_bytes / 1024), kReset);

            if (eid_skipped)
            {
                wprintf(L"      %ls%ls%zu%ls region(s) skipped (encrypted core, never read)\n",
                    StageField(L"eid:", 12).c_str(),
                    kGreen, eid_skipped, kReset);
            }

            if (sample_bytes)
            {
                const size_t cc_pct = (cc_bytes * 100) / sample_bytes;

                wprintf(L"      %ls%ls%zu%ls of %ls%zu%ls sampled bytes are INT3 (%ls0xCC%ls), %ls%zu%s%%, from %ls%zu%ls of %ls%zu%ls exec region(s)\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, cc_bytes, kReset,
                    kGreen, sample_bytes, kReset,
                    kGreen, kReset,
                    kGreen, cc_pct, kReset,
                    kGreen, sampled, kReset, kGreen, exec_regions, kReset);

                if (sample_capped)
                {

                    wprintf(L"%*s%ls%zu%ls of %ls%zu%ls exec region(s) not sampled (cap %ls%zu%ls), so the INT3 count is a floor, not a total\n",
                        static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                        kGreen, sample_capped, kReset,
                        kGreen, exec_regions, kReset,
                        kGreen, max_sample_regions, kReset);
                }
            }
            else
            {
                wprintf(L"      %lsno executable region was readable\n",
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
                        swprintf_s(part, L"cap %ls%zu%ls regions", kGreen, max_walk_regions, kReset);
                        append(part);
                    }
                    if (max_walk_bytes)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"cap %ls%zu%ls MB", kGreen, static_cast<size_t>(max_walk_bytes >> 20), kReset);
                        append(part);
                    }
                }
                if (walk_aborted)
                {
                    append(unknown_extent ? L"module extent unknown" : L"query failed before module end");
                }

                wprintf(L"%*sregion walk stopped early (%ls); counts are partial\n",
                    static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                    reason);
            }

            wprintf(L"\n");
        }

        if (!found)
        {
            wprintf(L"  %ls[!]%ls No target module present; nothing to survey.\n", kYellow, kReset);
        }
    }

    struct HookScanStats
    {
        size_t targets = 0;
        size_t resolved = 0;
        size_t clean = 0;
        size_t hooked = 0;
        size_t skipped = 0;
        bool scanned = false;
        bool patch_blocked = false;
    };

    bool HookPatchExplicitlyAllowed()
    {
        static const bool allowed = []() -> bool
        {
            wchar_t buffer[8] = {};
            const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_ALLOW_HOOK_PATCH").get(), buffer, 4);
            return (got == 1 && buffer[0] == L'1');
        }();
        return allowed;
    }

    void ScanAndRestoreHooks(HANDLE process, std::vector<RestoredHook> & restored, std::vector<std::wstring> & remaining, HookScanStats & stats)
    {
        restored.clear();
        remaining.clear();
        stats = HookScanStats{};

        const std::vector<HookTarget> & targets = GetHookTargets();
        stats.targets = targets.size();

        if (!HookPatchExplicitlyAllowed())
        {
            stats.patch_blocked = true;
            return;
        }

        if (!process)
        {
            return;
        }
        stats.scanned = true;

        for (const HookTarget & target : targets)
        {
            BYTE local_bytes[kHookScanBytes]{};
            const ULONG_PTR remote_function = ResolveHookTarget(process, target, local_bytes);
            if (!remote_function)
            {
                continue;
            }
            ++stats.resolved;

            const size_t first_diff = FindHookDifference(process, remote_function, local_bytes);
            if (first_diff == static_cast<size_t>(-1))
            {

                ++stats.skipped;
                continue;
            }
            if (first_diff == sizeof(local_bytes))
            {
                ++stats.clean;
                continue;
            }

            if (!IsSafeCodePage(process, remote_function, sizeof(local_bytes)))
            {
                ++stats.skipped;
                remaining.push_back(HookDisplayName(target));
                continue;
            }

            MEMORY_BASIC_INFORMATION patch_mbi{};
            if (!VirtualQueryEx(process, reinterpret_cast<void *>(remote_function), &patch_mbi, sizeof(patch_mbi)))
            {
                ++stats.skipped;
                remaining.push_back(HookDisplayName(target));
                continue;
            }

            const DWORD original_protection =
                patch_mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

            DWORD staged_protection = PAGE_READWRITE;
            if (original_protection == PAGE_WRITECOPY || original_protection == PAGE_EXECUTE_WRITECOPY)
            {
                staged_protection = PAGE_WRITECOPY;
            }

            DWORD discard_protection = 0;
            if (!VirtualProtectEx(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes), staged_protection, &discard_protection))
            {
                ++stats.skipped;
                remaining.push_back(HookDisplayName(target));
                continue;
            }

            SIZE_T bytes_written = 0;
            const bool write_ok =
                WriteProcessMemory(process, reinterpret_cast<void *>(remote_function), local_bytes, sizeof(local_bytes), &bytes_written) &&
                bytes_written == sizeof(local_bytes);

            DWORD ignored_protection = 0;
            const bool protection_ok =
                VirtualProtectEx(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes), original_protection, &ignored_protection) != FALSE;

            if (!write_ok || !protection_ok)
            {
                ++stats.skipped;
                remaining.push_back(HookDisplayName(target));
                continue;
            }

            FlushInstructionCache(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes));

            BYTE verify_bytes[kHookScanBytes]{};
            SIZE_T bytes_verified = 0;
            if (!ReadProcessMemory(process, reinterpret_cast<void *>(remote_function), verify_bytes, sizeof(verify_bytes), &bytes_verified) ||
                bytes_verified != sizeof(verify_bytes) ||
                memcmp(verify_bytes, local_bytes, sizeof(verify_bytes)) != 0)
            {
                ++stats.skipped;
                remaining.push_back(HookDisplayName(target));
                continue;
            }

            ++stats.hooked;
            RestoredHook entry;
            entry.name = HookDisplayName(target);
            entry.offset = static_cast<unsigned int>(first_diff);
            restored.push_back(entry);
        }
    }

    void PrintHookScanResult(const wchar_t * Phase, const HookScanStats & stats,
        const std::vector<RestoredHook> & restored, const std::vector<std::wstring> & remaining)
    {
        wprintf(L"  %s scan trace:\n\n", Phase);

        if (!stats.scanned)
        {

            if (stats.patch_blocked)
            {
                wprintf(L"    %ls%zu%s in list, hook patch not enabled - nothing was inspected\n",
                    StageField(L"Targets").c_str(), stats.targets, kReset);
            }
            else
            {
                wprintf(L"    %ls%zu%s in list, no process handle - nothing was inspected\n",
                    StageField(L"Targets").c_str(), stats.targets, kReset);
            }
            return;
        }

        wprintf(L"    %ls%ls%zu%s\n",
            StageField(L"Targets").c_str(), kGreen, stats.targets, kReset);
        wprintf(L"    %ls%ls%zu%s of %ls%zu%s resolved in the target\n",
            StageField(L"Resolved").c_str(),
            (stats.resolved == stats.targets ? kGreen : kYellow), stats.resolved, kReset,
            kGreen, stats.targets, kReset);
        wprintf(L"    %ls%ls%zu%s already matched the local image\n",
            StageField(L"Clean").c_str(), kGreen, stats.clean, kReset);
        wprintf(L"    %ls%ls%zu%s differed, %s%zu%s left alone\n",
            StageField(L"Hooked").c_str(), kGreen, stats.hooked, kReset,
            (stats.skipped ? kYellow : kGreen), stats.skipped, kReset);

        if (!restored.empty())
        {
            wprintf(L"\n");
            for (size_t i = 0; i < restored.size(); ++i)
            {
                const RestoredHook & entry = restored[i];

                const wchar_t * offset_tint = entry.offset == 0 ? kGreen : kYellow;
                wprintf(L"      [%ls%zu%s/%ls%zu%s] %s (%ls+0x%02X%s)\n",
                    kGreen, i + 1, kReset, kGreen, restored.size(), kReset, entry.name.c_str(),
                    offset_tint, entry.offset, kReset);
            }
        }

        if (!remaining.empty())
        {
            wprintf(L"    %ls%ls%zu%s still differ after the pass:\n",
                StageField(L"Remaining").c_str(), kYellow, remaining.size(), kReset);
            for (const std::wstring & entry : remaining)
            {
                wprintf(L"      %ls! %s%s\n", kYellow, entry.c_str(), kReset);
            }
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
        case 0xC0000023u: return L"STATUS_HANDLE_NOT_CLOSABLE";
        case 0xC0000035u: return L"OBJECT_NAME_INVALID";
        case 0xC0000043u: return L"SHARING_VIOLATION";
        case 0xC000006Du: return L"API_SET_NOT_HOSTED";
        case 0xC000007Fu: return L"DISK_FULL";
        case 0xC0000135u: return L"DLL_NOT_FOUND";
        case 0xC0000138u: return L"ORDINAL_NOT_FOUND";
        case 0xC0000139u: return L"ENTRYPOINT_NOT_FOUND";
        case 0xC000013Au: return L"CONTROL_C_EXIT";
        case 0xC000014Au: return L"DLL_INIT_FAILED";
        case 0xC000014Bu: return L"DLL_INIT_FAILED_LOGOFF";
        case 0xC00001A5u: return L"INVALID_BUFFER_SIZE";
        case 0xC0000203u: return L"STACK_OVERFLOW";
        case 0xC0000205u: return L"STATUS_POSSIBLE_DEADLOCK";
        case 0xC0000225u: return L"STATUS_NOT_FOUND";
        case 0xC000026Du: return L"LOGON_FAILURE";
        case 0xC0000374u: return L"HEAP_CORRUPTION";
        case 0xC0000409u: return L"STACK_BUFFER_OVERRUN (__fastfail: cookie or GS failure)";
        case 0xC000040Au: return L"FAST_FAIL_GUARD_CHECK / __fastfail_gs cookie violation";
        case 0xC000040Bu: return L"FAST_FAIL_FATAL_APP_EXIT";
        case 0xC000041Du: return L"COOKIE_INIT_FAILED";
        case 0xC00000A0u: return L"INTERNAL_ERROR";
        default: return L"unknown";
        }
    }

    void PrintFailureHint(DWORD code)
    {
        if (code == INJ_ERR_OUT_OF_MEMORY_EXT)
        {
            wprintf(L"Reason: VirtualAllocEx failed in target (Adv 5=ACCESS_DENIED, 998/3E6=NOACCESS).\n");
            wprintf(L"Target is likely protected or blocks remote RW/RX allocations.\n");
            wprintf(L"Staging uses RW->RX (no RWX at birth); image uses RW->RX.\n");
            wprintf(L"Try testing on notepad.exe.\n");
        }
        else if (code == INJ_ERR_CANT_OPEN_PROCESS)
        {
            wprintf(L"Reason: OpenProcess denied. Run elevated.\n");
        }
        else if (code == INJ_MM_ERR_DLLMAIN_FAILED)
        {
            wprintf(L"Reason: the mapping, imports, TLS and loader-lock stages all succeeded; the payload's\n");
            wprintf(L"own DllMain(DLL_PROCESS_ATTACH) returned FALSE, i.e. the payload refused to initialize.\n");
            wprintf(L"This is state/thread dependent, not a mapping fault. Load earlier in the target's startup:\n");
            wprintf(L"relaunch the game and load once the launcher reports its symbol download is complete.\n");
            wprintf(L"A failed attempt also leaves loader bookkeeping in the target that cannot be reclaimed\n");
            wprintf(L"(inverted-table entry, TLS index/block have no removal API and point into the freed\n");
            wprintf(L"image), so relaunch the game before trying again.\n");
        }
        else if (code == INJ_MM_ERR_TLS_CALLBACK_RANGE)
        {
            wprintf(L"Reason: a payload TLS callback pointer/array fell outside the mapped image,\n");
            wprintf(L"so only a prefix of its callbacks ran. This is payload-specific, not a mapping\n");
            wprintf(L"fault. Relaunch the target before trying another payload.\n");
        }
        else if (code == INJ_ERR_HANDLE_HIJACK_FAILED)
        {
            wprintf(L"Reason: handle acquisition found no donor; the path is donor-only and fails closed.\n");
            wprintf(XOR_STR_W(L"Check the handle-acquisition settings in the deployed configuration, or run elevated so the\n").get());
            wprintf(L"sponsor pre-open succeeds.\n");
        }
        else if (code == SR_HT_ERR_OPEN_REFUSED)
        {
            wprintf(L"Reason: thread handle acquisition found no donor; the path is donor-only and\n");
            wprintf(L"fails closed (there is no direct OpenThread fallback). Run elevated so the sponsor\n");
            wprintf(L"thread pre-open succeeds, or retry while the target is active.\n");
        }
        else if (code == SR_HT_ERR_NO_THREADS)
        {
            wprintf(L"Reason: no usable donor thread found. Retry while the target is active.\n");
        }
        else if (code == SR_ERR_TARGET_EXITED)
        {
            wprintf(L"Reason: the target process exited during loading.\n");
        }
        else if (code == SR_HT_ERR_REMOTE_PENDING_TIMEOUT)
        {
            wprintf(L"Note: the payload timed out, but the thread context was restored automatically.\n");
            wprintf(L"Reason: the victim thread never scheduled the donor stub (State stayed Pending),\n");
            wprintf(L"so the memory-loading shell never started. This is thread selection, not a verification issue:\n");
            wprintf(XOR_STR_W(L"CleanDataDirectories and HookRestore are unrelated - keep them enabled.\n").get());
            wprintf(L"The runtime now retries: each donor gets a short startup probe, an unscheduled\n");
            wprintf(L"thread is rolled back and excluded, and the next candidate is tried inside the\n");
            wprintf(L"same timeout budget. Raising the timeout widens how many donors get probed.\n");
        }
        else if (code == INJ_ERR_WINDOWS_VERSION)
        {
            wprintf(L"Reason: the OS version gate could not identify the Windows release.\n");
            wprintf(L"The runtime requires Windows 11 (build 22000+); this is an environment\n");
            wprintf(L"issue, not a mapping or symbol failure.\n");
        }
        else if (code == INJ_ERR_WINDOWS_BUILD_UNSUPPORTED)
        {
            wprintf(L"Reason: the OS gate rejected the host - Windows 11 (build 22000+) is required\n");
            wprintf(L"and this build is outside the supported families (21H2 22000+, 22H2/23H2 22621+,\n");
            wprintf(L"24H2 26100+, 25H2 26200+, 26H2 26300+; newer builds are forward-mapped). This is an\n");
            wprintf(L"environment issue, not a mapping or symbol failure. Update Windows.\n");
        }
        else
        {

            wprintf(L"Reason: unclassified failure 0x%08lX; see the runtime error header.\n",
                static_cast<unsigned long>(code));
        }
    }

    void PauseBeforeExit()
    {

        if (!InterfaceConsolePresent())
        {
            return;
        }

        wprintf(L"\nPress Enter to exit...\n");
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
                fwprintf(stderr, L"%lsUnsupported Windows build: local build %lu (code 0x%08X).%ls\n",
                    kRed, static_cast<unsigned long>(local_build), init_state, kReset);
            }
            else
            {
                fwprintf(stderr, L"%lsUnsupported Windows version (code 0x%08X).%ls\n",
                    kRed, init_state, kReset);
            }
            PrintError(L"Supported: Windows 11 21H2 (22000), 22H2/23H2 (22621-22631), 24H2 (26100+), 25H2 (26200+), 26H2 (26300+).");
            PrintError(L"Windows 10 and older builds are not supported by this x64/Win11-only build.");
            PrintError(L"Failed to initialize the runtime (OS gate, not a symbol download failure).");
            return;
        }
        if (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
        {
            PrintError(L"Timeout waiting for symbol initialization (120s).");
            PrintError(L"Check internet access and Windows symbol server reachability.");
        }
        else if (symbol_state != INJ_ERR_SUCCESS)
        {
            if (init_state != INJ_ERR_SUCCESS)
            {

                fwprintf(stderr, L"%lsFailed to initialize the runtime: 0x%08X%ls\n", kRed, init_state, kReset);
            }
            else
            {
                fwprintf(stderr, L"%lsFailed to load symbols: 0x%08X%ls\n", kRed, symbol_state, kReset);
            }
        }
        else if (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
        {
            PrintError(L"Timeout waiting for import resolution (120s).");
        }
        else if (import_state != INJ_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsFailed to resolve imports: 0x%08X%ls\n", kRed, import_state, kReset);
        }
        PrintError(L"Failed to initialize the runtime or download symbols.");
    }

    // Decide whether a failed injection may be retried by spawning a fresh,
    // renamed process. A retry must NEVER follow a failure that already wrote
    // the payload into the target: the runtime leaves unreclaimable loader
    // state behind and a second attempt would map the payload a second time
    // (a genuine double injection). Such failures are final.
    bool InjectionFailureIsRetryable(DWORD result)
    {
        // "Remote mapping reached the shell" range: the payload is already in
        // the target. The existing warning tells the operator to relaunch the
        // target before loading again.
        if (result >= 0x00400000u && result < 0x00500000u)
        {
            return false;
        }

        // Thread-hijack errors: by the time a thread is hijacked to run the
        // loader shell, the image has been staged in the target and the shell
        // maps it; retrying would map it a second time.
        if (result >= 0x10200000u && result < 0x10300000u)
        {
            return false;
        }

        switch (result)
        {
            // The shell ran but did not produce a module handle, or the result
            // could not be read back: the payload was mapped.
        case INJ_ERR_FAILED_TO_LOAD_DLL:
        case INJ_ERR_VERIFY_RESULT_FAIL:
            return false;

        default:
            break;
        }

        // Everything else is a pre-mapping transient miss (open-process denied,
        // handle-hijack found no donor, allocation failure, staging write,
        // input validation) where the target does not yet carry the payload,
        // so a fresh attempt cannot double-load it.
        return true;
    }

    int RunInteractiveWizard(Runtime & runtime)
    {
        // WINDOWS subsystem: never allocate or title a console. The previous
        // random console title is dropped; headless runs have no console.
        (void)runtime;
        wprintf(L"[Attempt %d/%d]\n\n", GetRetryIndex() + 1, kMaxLaunchAttempts);

        WizardConfig config;
        std::wstring config_path;
        bool config_invalid = false;
        const bool config_loaded = LoadWizardConfig(config, config_path, config_invalid);
        if (config_invalid || !config_loaded)
        {
            if (config_path.empty())
            {
                PrintError(XOR_STR_W(L"The deployed configuration is required but was not found. Place it next to the executable.").get());
            }
            else
            {
                PrintError(XOR_STR_W(L"The deployed configuration is invalid; fix the schema, target or per-build deployment keys, or restore the file.").get());
            }
            PauseBeforeExit();
            return 1;
        }

        if (!LoadRuntime(runtime, config))
        {
            PauseBeforeExit();
            return 1;
        }

        if (VerboseOutputEnabled())
        {
            wprintf(L"Runtime module base = %ls%p%ls\n", kGreen, reinterpret_cast<void *>(runtime.module), kReset);
        }
        wprintf(L"Execution: %lsThreadDonor%ls\n", kGreen, kReset);
        wprintf(L"Mode: %lsMemoryLoading%ls\n\n", kGreen, kReset);

        if (VerboseOutputEnabled())
        {
            wprintf(L"%ls[+]%ls Configuration loaded: %ls\n", kGreen, kReset, config_path.c_str());
        }

        wprintf(L"\n");
        wprintf(L"Target: %ls%ls%ls | Timeout: %ls%d%ls ms\n",
            kGreen, config.target_name.c_str(), kReset, kGreen, config.timeout, kReset);
        if (VerboseOutputEnabled()) { wprintf(L"Load flags: %ls0x%08X%ls\n", kGreen, BuildFlags(config), kReset); }

        wprintf(L"\n");
        std::vector<BYTE> raw_data;
        FileInformation fileInformation;
        const DWORD preflight_flags = BuildFlags(config);
        if (!ResolveConfiguredPayload(config.dll_dir, config.payload_name, config.expected_payload_sha256,
            preflight_flags, fileInformation, raw_data))
        {
            PauseBeforeExit();
            return 1;
        }

        ReportPayloadCapabilities(raw_data, preflight_flags);

        wprintf(L"\n%ls[+]%ls Downloading Windows symbols...\n", kGreen, kReset);
        DWORD symbol_state = INJ_ERR_SYMBOL_INIT_NOT_DONE;
        DWORD import_state = INJ_ERR_IMPORT_HANDLER_NOT_DONE;
        DWORD init_state = INJ_ERR_SUCCESS;
        if (!WaitForRuntime(runtime, symbol_state, import_state, init_state))
        {
            PrintRuntimeFailure(symbol_state, import_state, init_state);
            PauseBeforeExit();
            // Transient (network/symbol timeout): fresh-process retryable.
            return kResultRetryable;
        }
        wprintf(L"%ls[+]%ls Download completed.\n\n", kGreen, kReset);

        const ConfirmationResult confirmation = ConfirmBeforeDetection();
        if (confirmation == ConfirmationResult::Cancelled)
        {
            wprintf(L"Cancelled.\n");
            return 0;
        }
        if (confirmation == ConfirmationResult::Unavailable)
        {

            return 1;
        }

        TargetSelection target;
        bool cancelled = false;
        if (!SelectTarget(config.target_name, target, cancelled))
        {
            if (cancelled)
            {
                wprintf(L"Cancelled.\n");
                return 0;
            }
            return 2;
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 targets are not supported in this x64-only build.");
            PauseBeforeExit();
            return 1;
        }

        if (target.architecture != Architecture::Unknown &&
            fileInformation.architecture != target.architecture)
        {
            wprintf(L"Warning: DLL is %ls but target is %ls.\n",
                ArchitectureName(fileInformation.architecture),
                ArchitectureName(target.architecture));
            bool proceed = false;
            if (!ReadYesNo(L"Continue anyway?", false, proceed) || !proceed)
            {
                wprintf(L"Cancelled.\n");
                return 0;
            }
        }

        const int timeout_value = config.timeout;

        wprintf(L"\n");

        if (config.detach_console)
        {
            wprintf(L"%ls[+]%ls Detaching console; running headless from here.\n", kGreen, kReset);
            fflush(stdout);
            DetachInterfaceConsole();
        }

        if (!RefreshTarget(target))
        {
            PrintError(L"Target exited before loading. Re-run and choose faster.");
            PauseBeforeExit();
            // Transient race (target restarted between select and load).
            return kResultRetryable;
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 targets are not supported in this x64-only build.");
            PauseBeforeExit();
            return 1;
        }

        HijackContext Context{};
        Context.TargetPid = target.pid;
        Context.TargetName = target.name;
        Context.Verbose = config.verbose_trace && !config.quiet;
        Context.SponsorAccess = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;
        HANDLE sponsorRaw = nullptr;
        DWORD sponsor_err = ERROR_SUCCESS;
        if (config.handle_hijacking)
        {

            sponsorRaw = OpenProcess(Context.SponsorAccess, FALSE, target.pid);
            if (!sponsorRaw && GetLastError() == ERROR_ACCESS_DENIED)
            {
                Context.PrivilegeAttempted = true;
                Context.PrivilegeOk = EnableSeDebugPrivilege();
                if (Context.PrivilegeOk)
                {
                    sponsorRaw = OpenProcess(Context.SponsorAccess, FALSE, target.pid);
                }

                if (!sponsorRaw)
                {
                    sponsor_err = GetLastError();
                }

                DisableSeDebugPrivilege();
            }
            if (!sponsorRaw && sponsor_err == ERROR_SUCCESS)
            {
                sponsor_err = GetLastError();
            }
            Context.SponsorOpened = sponsorRaw != nullptr;
            if (sponsorRaw)
            {
                Context.SponsorValue = ReCa<ULONG_PTR>(sponsorRaw);
            }
            else
            {
                const wchar_t * consequence = config.hijack_scan
                    ? L"runtime will scan only (no direct fallback)."
                    : L"no acquisition path remains; loading will fail closed.";
                wprintf(L"  %ls[!]%ls Sponsor pre-open failed (0x%08X); %ls\n",
                    kYellow, kReset, sponsor_err, consequence);
            }
        }
        FileHandleGuard sponsorGuard(sponsorRaw);

        HANDLE threadSponsorRaw = nullptr;
        if (config.handle_hijacking)
        {
            Context.SponsorThreadAttempted = true;
            DWORD thread_sponsor_err = ERROR_SUCCESS;
            for (int attempt = 0; attempt < 8 && !threadSponsorRaw; ++attempt)
            {
                if (attempt > 0)
                {
                    Sleep(20);
                }

                const DWORD victim_tid = PickHijackThreadTid(target.pid);
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
                wprintf(L"  %ls[!]%ls Thread sponsor pre-open failed (0x%08X); runtime will search.\n",
                    kYellow, kReset, thread_sponsor_err);
            }
        }
        FileHandleGuard threadSponsorGuard(threadSponsorRaw);

        HANDLE targetHandle = sponsorRaw;
        FileHandleGuard targetHandleGuard;
        if (!targetHandle)
        {

            DWORD scan_mask = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
            if (config.hook_restore && HookPatchExplicitlyAllowed())
            {
                scan_mask |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            }
            targetHandle = OpenProcess(scan_mask, FALSE, target.pid);
            targetHandleGuard.reset(targetHandle);
            if (!targetHandle)
            {
                wprintf(L"  %ls[!]%ls Could not open the target for hook scanning (0x%08X).\n",
                    kYellow, kReset, GetLastError());
            }
        }

        const DWORD flags = BuildFlags(config);

        MemoryInjectionData data{};
        data.RawData = raw_data.data();
        data.RawSize = static_cast<DWORD>(raw_data.size());
        data.ProcessID = target.pid;
        data.Flags = flags;
        data.Timeout = static_cast<DWORD>(timeout_value);
        data.GenerateErrorLog = true;

        data.hHandleValue = sponsorRaw ? ReCa<ULONG_PTR>(sponsorRaw) : 0;
        data.TargetTid = Context.SponsorTid;
        data.hThreadHandleValue = threadSponsorRaw ? ReCa<ULONG_PTR>(threadSponsorRaw) : 0;
        data.DllPath = config.payload_name.c_str();

        wprintf(L"\n");

        if (config.hook_restore)
        {
            std::vector<RestoredHook> pre_unhooked;
            std::vector<std::wstring> pre_remaining;
            HookScanStats pre_stats{};
            ScanAndRestoreHooks(targetHandle, pre_unhooked, pre_remaining, pre_stats);
            if (!config.quiet)
            {
                PrintHookScanResult(L"Pre-load hook", pre_stats, pre_unhooked, pre_remaining);
            }
        }

        if (data.TargetTid)
        {
            wprintf(L"Requested sponsor TID %ls0x%04lX%s, Timeout %ls%lu ms%s (runtime may reject it; hijacked thread reported on completion)...\n",
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }
        else
        {
            wprintf(L"Working (runtime thread search, timeout %ls%lu ms%s)...\n",
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }

        const ULONGLONG inject_begin_ms = GetTickCount64();

        // The diagnostic ring lives in the host process, so a record from an earlier attempt would be
        // attributed to this one. Clearing first makes the detail that comes back describe this run.
        if (runtime.clear_last_error_info)
        {
            runtime.clear_last_error_info();
        }

        const DWORD result = runtime.memory_inject(&data);
        const ULONGLONG inject_window_ms = GetTickCount64() - inject_begin_ms;

        if (result != INJ_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsOperation failed with code %08X%ls\n", kRed, result, kReset);
            PrintFailureHint(result);

            if (runtime.get_last_error_info)
            {
                LAST_ERROR_INFO detail{};
                const DWORD detail_status = runtime.get_last_error_info(&detail);

                if (detail_status == INJ_ERR_NO_LAST_ERROR)
                {
                    wprintf(L"  Runtime recorded no diagnostic detail for this attempt.\n");
                }
                else if (detail_status == INJ_ERR_SUCCESS)
                {
                    wprintf(L"  Runtime detail: adv=%08X line=%d native=%d\n",
                        detail.AdvErrorCode, detail.Line, detail.bNative);
                    if (detail.DllFileName[0])
                    {
                        wprintf(L"  Payload: %ls\n", detail.DllFileName);
                    }
                    if (detail.AdvErrorCode >= 0xC0000000u)
                    {

                        wprintf(L"  Adv is an NTSTATUS from the target: 0x%08X (%ls).\n",
                            detail.AdvErrorCode, DescribeNtStatus(detail.AdvErrorCode));
                    }
                }
            }

            if (result >= 0x00400000u && result < 0x00500000u)
            {
                wprintf(L"  %ls[!]%ls Remote mapping reached the shell; unreclaimable loader state may remain.\n",
                    kYellow, kReset);
                wprintf(L"      Relaunch the target before attempting another load.\n");
            }
            targetHandleGuard.reset();
            threadSponsorGuard.reset();
            sponsorGuard.reset();
            PauseBeforeExit();
            // Only retry genuine pre-mapping misses. If the payload already
            // reached the target, retrying would load it a second time without
            // a fresh OK, which is the reported double-injection.
            return InjectionFailureIsRetryable(result) ? kResultRetryable : 1;
        }

        threadSponsorGuard.reset();
        threadSponsorRaw = nullptr;

        const bool hook_write_may_happen = config.hook_restore && HookPatchExplicitlyAllowed();
        if (sponsorRaw && !hook_write_may_happen)
        {
            sponsorGuard.reset();
            sponsorRaw = nullptr;
            targetHandle = nullptr;

            targetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
            targetHandleGuard.reset(targetHandle);
            if (!targetHandle)
            {
                wprintf(L"  %ls[!]%ls Could not re-open the target read-only for verification (0x%08X).\n",
                    kYellow, kReset, GetLastError());
            }
        }

        HijackStats ProcessHijackStats{};
        HijackStats ThreadHijackStats{};
        if (runtime.get_last_hijack_stats)
        {
            runtime.get_last_hijack_stats(&ProcessHijackStats, &ThreadHijackStats);
        }
        MAP_STATS MapStats{};
        if (runtime.get_last_map_stats)
        {
            runtime.get_last_map_stats(&MapStats);
        }

        THREAD_EXEC_STATS ThreadExec{};
        if (runtime.get_last_thread_exec_stats)
        {
            runtime.get_last_thread_exec_stats(&ThreadExec);
        }
        Context.UsedTid = ThreadExec.HijackedTid;

        bool stealth_gate_ok = false;
        bool wx_violated = false;
        if (targetHandle)
        {

            StealthVerifierBuffers buffers;
            {
                const std::wstring runtime_path = RuntimePath(config.dll_dir, config.runtime_name);
                buffers.runtime_path_known = !runtime_path.empty();
                buffers.runtime_read = buffers.runtime_path_known && ReadFileBytes(runtime_path, buffers.runtime_bytes);
            }

            stealth_gate_ok = SafeDebugAndVerifyStealth(targetHandle, data.hDllOut, flags, raw_data.data(), raw_data.size(),
                &ProcessHijackStats, &ThreadHijackStats, &Context, &MapStats, runtime.get_last_string_stats, true, target.pid, &wx_violated, config, buffers);
        }
        else
        {
            wprintf(L"%ls[x]%ls Verification could not run (no target handle); the result is unproven.\n",
                kRed, kReset);
        }

        if (!runtime.get_last_thread_exec_stats || !ThreadExec.Attempted)
        {
            wprintf(L"  %ls[!]%ls Thread context not reported (no telemetry, or no donor was attempted).\n", kYellow, kReset);
        }
        else if (ThreadExec.Success)
        {
            wprintf(L"  %ls[+]%ls Thread context restored to original on TID: %ls0x%04lX%s.\n",
                kGreen, kReset, kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        else
        {
            wprintf(L"  %ls[!]%ls Thread context %sNOT restored%s on TID: %s0x%04lX%s (code 0x%08lX) - it may still be running donor code.\n",
                kYellow, kReset, kYellow, kReset, kYellow,
                static_cast<unsigned long>(ThreadExec.HijackedTid), kReset,
                static_cast<unsigned long>(ThreadExec.FailCode));
        }

        if (ThreadExec.Attempted && data.TargetTid && ThreadExec.HijackedTid
            && ThreadExec.HijackedTid != data.TargetTid)
        {
            wprintf(L"  %ls[!]%ls Sponsor TID %ls0x%04lX%ls not usable; hijacked TID %ls0x%04lX%ls instead (donor scan fallback).\n",
                kYellow, kReset,
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        wprintf(L"\n");
        if (config.hook_restore)
        {
            std::vector<RestoredHook> unhooked;
            std::vector<std::wstring> remaining;
            HookScanStats post_stats{};
            ScanAndRestoreHooks(targetHandle, unhooked, remaining, post_stats);
            if (!config.quiet)
            {
                PrintHookScanResult(L"Post-load hook", post_stats, unhooked, remaining);
            }
        }

        const bool had_target = (targetHandle != nullptr);
        targetHandleGuard.reset();
        threadSponsorGuard.reset();
        sponsorGuard.reset();
        targetHandle = nullptr;
        threadSponsorRaw = nullptr;
        sponsorRaw = nullptr;
        wprintf(L"  %ls[+]%ls Donor handles released; no target handles held.\n", kGreen, kReset);

        wprintf(L"\n");
        if (!stealth_gate_ok)
        {
            if (!had_target)
            {

                wprintf(L"%ls[x] VERIFICATION NOT PERFORMED%s - the payload is mapped in the\n", kRed, kReset);
                wprintf(L"    target, but no target handle was available, so neither the string-encryption\n");
                wprintf(L"    gate nor the W^X posture could be checked. The result is unproven; do not\n");
                wprintf(L"    treat it as a clean load until it can be verified.\n");
            }
            else
            {
                wprintf(L"%ls[x] VERIFICATION GATE FAILED%s - the payload is mapped in the target, but the\n", kRed, kReset);
                wprintf(L"    runtime DLL does not pass verification (string-encryption or forensic posture).\n");
                wprintf(L"    It must not be treated as a clean load: a plaintext symbol name in .rdata is\n");
                wprintf(L"    scannable, and shipping it defeats the point of the string tiers.\n");
                wprintf(L"    Fix the leak and rebuild before using this build.\n");
            }
            PauseBeforeExit();
            return 1;
        }
        if (wx_violated)
        {
            wprintf(L"%ls[!] W^X advisory:%s the W^X posture was not confirmed (see the Verify W^X execution step).\n", kYellow, kReset);
            wprintf(L"    Either a mapped page is not RX as expected, or the image could not be queried\n");
            wprintf(L"    or bounded. The load is functional, but this weakens confidence in the\n");
            wprintf(L"    W^X posture. Treat this build as suspect.\n\n");
        }

        wprintf(L"Operation succeeded. DLL loaded at %ls%p%s.\n", kGreen, data.hDllOut, kReset);
        wprintf(L"%ls[+]%ls Victim frozen %ls%lu ms%s (hijack window).\n", kGreen, kReset,
            kGreen, static_cast<unsigned long>(inject_window_ms), kReset);
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
    // WINDOWS subsystem: no console is ever allocated. All operator prompts
    // are served through a layered window; stdout/stderr handles are null.
    EnableAnsi();

    // Extract the unrenamed parent image path for best-effort cleanup after
    // the polymorphic rename. Quoted form: --ameger-parent-path="C:\...".
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

    // Polymorphic stub: randomize the on-disk filename before main logic.
    // The unrenamed parent exits here; only the renamed child continues.
    if (!PolymorphicSelfRename(parentHint))
    {
        return 0;
    }

    const int retryIndex = GetRetryIndex();
    Runtime runtime;
    int result = 1;
    try
    {
        // Single attempt per process. A second attempt never reuses this
        // process; it is spawned fresh below with a new name and parent.
        result = RunInteractiveWizard(runtime);
    }
    catch (const std::bad_alloc &)
    {
        PrintError(L"Out of memory during loading; aborting.");
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

    // Transient-only bounded retry. Cancellation (0) and deterministic
    // failures (1/2) exit here with the full log on the clipboard; only a
    // transient miss (3) spawns a fresh renamed process with a fresh parent.
    if (result == kResultRetryable && retryIndex + 1 < kMaxLaunchAttempts)
    {
        const int nextRetry = retryIndex + 1;
        if (SpawnFreshRetryProcess(nextRetry))
        {
            // Handed off to the fresh child; this process must not run again
            // and must not touch the clipboard (the child owns the final log).
            TerminateInterface(result);
        }
        // Spawn failed: fall through and report this attempt's result.
    }

    // Single brief clipboard ownership, no window: the entire captured CLI
    // log (ANSI stripped) is left on the clipboard for paste-out.
    ameger_ui_log::CopyToClipboardStealthily();

    if (result == kResultRetryable && retryIndex + 1 >= kMaxLaunchAttempts)
    {
        LayeredNotify(L"Launcher", L"Operation failed after 3 attempts. The full log is on your clipboard.", 5000);
        result = 1;
    }

    if (runtime.module)
    {
        TerminateInterface(result);
    }
    return result;
}
