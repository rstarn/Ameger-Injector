#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Error.h"

static SRWLOCK g_print_lock = SRWLOCK_INIT;

DWORD __stdcall SetRawPrintCallback(f_raw_print_callback print)
{
	EXPORT_FUNCTION("CoreSetTrace", __FUNCDNAME__)

	g_print_raw_callback.store(print);

	if (!print)
	{
		LOG(0, "Removed Print Callback\n");
	}
	else
	{
		LOG(0, "Set Print Callback\n");
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



		AcquireSRWLockExclusive(&g_print_lock);

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

		ReleaseSRWLockExclusive(&g_print_lock);
	}

	if (buffer)
	{
		delete[] buffer;
	}
}
