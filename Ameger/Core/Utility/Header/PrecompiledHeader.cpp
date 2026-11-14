#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"

static SRWLOCK g_print_lock = SRWLOCK_INIT;

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
	EXPORT_FUNCTION("CoreSetTrace", __FUNCDNAME__)

	g_print_raw_callback.store(print);

	if (!print)
	{
		LOG(0, XOR_STR_A("Removed Print Callback\n").get());
	}
	else
	{
		LOG(0, XOR_STR_A("Set Print Callback\n").get());
	}

	return INJ_ERR_SUCCESS;
}

	void ImTheTrashMan(const wchar_t * expression, const wchar_t * function, const wchar_t * file, unsigned int line, uintptr_t pReserved) noexcept
	{
		UNREFERENCED_PARAMETER(expression);
		UNREFERENCED_PARAMETER(function);
		UNREFERENCED_PARAMETER(file);
		UNREFERENCED_PARAMETER(line);
		UNREFERENCED_PARAMETER(pReserved);
	}

static void CustomPrintFormatted(int indention_offset, const char * format, va_list args, bool diag)
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
	const size_t diag_prefix_len = diag ? 7 : 0; // "[DIAG] "
	char * buffer = new(std::nothrow) char[size + static_cast<size_t>(indention_offset) + diag_prefix_len]();

	if (!buffer)
	{
		return;
	}

	memset(buffer, '\x20', indention_offset);
	if (diag)
	{
		memcpy(buffer + indention_offset, "[DIAG] ", diag_prefix_len);
	}

	auto old = _set_thread_local_invalid_parameter_handler(ImTheTrashMan);

	int result = 0;

	do
	{
		va_list args_copy;
		va_copy(args_copy, args);

		int err = 0;
		result = vsprintf_s(buffer + indention_offset + diag_prefix_len, size, format, args_copy);

		if (result <= 0)
		{
			err = errno;
		}

		va_end(args_copy);

		if (result < 0 && err == ERANGE)
		{
			delete[] buffer;

			size += 1024;
			buffer = new(std::nothrow) char[size + indention_offset + diag_prefix_len]();

			if (!buffer)
			{
				break;
			}

			memset(buffer, '\x20', indention_offset);
			if (diag)
			{
				memcpy(buffer + indention_offset, "[DIAG] ", diag_prefix_len);
			}
		}
		else if (result < 0)
		{
			break;
		}
	} while (result < 0);

	_set_thread_local_invalid_parameter_handler(old);

	if (result > 0)
	{
		AcquireSRWLockExclusive(&g_print_lock);

		if (f_raw_print_callback callback = g_print_raw_callback.load())
		{
			callback(buffer);
		}
		else
		{
			// Diagnostic output is file/callback-routed by design; only interleave to console when requested.
			if (!diag || AmegerDiagStreamEnabled())
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

		ReleaseSRWLockExclusive(&g_print_lock);
	}

	if (buffer)
	{
		delete[] buffer;
	}
}

void custom_print(int indention_offset, const char * format, ...)
{
	va_list args;
	va_start(args, format);
	CustomPrintFormatted(indention_offset, format, args, false);
	va_end(args);
}

void custom_diag_print(int indention_offset, const char * format, ...)
{
	va_list args;
	va_start(args, format);
	CustomPrintFormatted(indention_offset, format, args, true);
	va_end(args);
}
