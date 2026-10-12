#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"

// PCH implementation TU: anchors the precompiled header and hosts the trace
// sink plus the CRT invalid-parameter guard. What: SetRawPrintCallback stores
// the launcher callback; custom_print formats one line to it (or stdout);
// ImTheTrashMan swallows CRT parameter errors so a bad format never throws
// out of the trace path.
//
// No #pragma comment(lib) for dbghelp/wininet/urlmon/shlwapi: every one of
// those would place a static import in the shipped PE, and a manual-mapping
// carrier importing dbghelp.dll or wininet.dll is a textbook IOC. The two
// modules that are genuinely needed (dbghelp for PDB parsing, wininet for the
// symbol download) are resolved by name at the moment of use and freed again
// immediately after - see Core/Utility/Binary/DynamicAPI.h.

// Installs/clears the trace sink. Params: print (callback or null to mute).
// Returns INJ_ERR_SUCCESS always. Exported as CoreSetTrace (renamed per
// build); the launcher sets QuietPrint in production.
DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
#pragma EXPORT_FUNCTION("CoreSetTrace", __FUNCDNAME__)

	g_print_raw_callback.store(print);

	if (!print)
	{
		LOG(0, "Removed print callback\n");
	}
	else
	{
		LOG(0, "Set print callback\n");
	}

	return INJ_ERR_SUCCESS;
}

	// CRT invalid-parameter handler: intentionally ignores all args and returns,
	// so a formatting misuse in custom_print degrades to a dropped line instead
	// of an exception/crash on the injection path. noexcept because the CRT
	// invokes it through an extern "C" pointer, where an escaping exception is
	// undefined behaviour.
	void ImTheTrashMan(const wchar_t * expression, const wchar_t * function, const wchar_t * file, unsigned int line, uintptr_t pReserved) noexcept
	{
		UNREFERENCED_PARAMETER(expression);
		UNREFERENCED_PARAMETER(function);
		UNREFERENCED_PARAMETER(file);
		UNREFERENCED_PARAMETER(line);
		UNREFERENCED_PARAMETER(pReserved);
	}

// Formats one trace line with leading indent and routes it to the launcher
// callback (or stdout when none). Params: indention_offset (spaces, clamped
// >= 0), format + varargs (vsprintf_s; grown by 1 KB on ERANGE). Best-effort:
// allocation/format failures drop the line; never throws.
void custom_print(int indention_offset, const char * format, ...)
{
	if (indention_offset < 0)
	{
		indention_offset = 0;
	}

	if (!format)
	{
		return;
	}

	size_t size = 1024;
	char * buffer = new(std::nothrow) char[size + static_cast<size_t>(indention_offset)]();

	if (!buffer)
	{
		return;
	}

	memset(buffer, '\x20', indention_offset);

	auto old = _set_thread_local_invalid_parameter_handler(ImTheTrashMan);

	int result = 0;

	do
	{
		va_list args;
		va_start(args, format);

		int err = 0;
		result = vsprintf_s(buffer + indention_offset, size, format, args);

		if (result <= 0)
		{
			err = errno;
		}

		va_end(args);

		if (result < 0 && err == ERANGE)
		{
			delete[] buffer;

			size += 1024;
			buffer = new(std::nothrow) char[size + indention_offset]();

			if (!buffer)
			{
				break;
			}

			memset(buffer, '\x20', indention_offset);
		}
		else if (result < 0)
		{
			break;
		}
	} while (result < 0);

	_set_thread_local_invalid_parameter_handler(old);

	if (result > 0)
	{

		if (f_raw_print_callback callback = g_print_raw_callback.load())
		{
			callback(buffer);
		}
		else
		{
			auto len = strlen(buffer);

			if (len > 0)
			{
				if (buffer[len - 1] == '\n')
				{
					buffer[len - 1] = '\0';
				}

				puts(buffer);
			}
		}

	}

	if (buffer)
	{
		delete[] buffer;
	}
}