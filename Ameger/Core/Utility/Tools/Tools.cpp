#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Utility/Tools/Tools.h"
#include "Injection.h"
#include "System/Import/ImportHandler.h"

#include <bcrypt.h>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace
{

SRWLOCK g_ErrorLogLock = SRWLOCK_INIT;
}

namespace
{
	INIT_ONCE g_OSVersionInitOnce = INIT_ONCE_STATIC_INIT;

	BOOL CALLBACK InitOSVersionOnce(PINIT_ONCE, PVOID parameter, PVOID *)
	{
		DWORD * error_code = static_cast<DWORD *>(parameter);

		auto ntdll_name = XOR_STR_W(L"ntdll.dll");
		HMODULE hNtdll = GetModuleHandleW(ntdll_name.get());
		if (!hNtdll)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_GET_MODULE_HANDLE_FAIL;
			}
			return FALSE;
		}
		auto rtlver_name = XOR_STR_A("RtlGetVersion");
		using f_RtlGetVersion = LONG(NTAPI *)(PRTL_OSVERSIONINFOW);
		auto pRtlGetVersion = ReCa<f_RtlGetVersion>(GetProcAddress(hNtdll, rtlver_name.get()));
		if (!pRtlGetVersion)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_GET_PROC_ADDRESS_FAIL;
			}
			return FALSE;
		}
		RTL_OSVERSIONINFOW ver{};
		ver.dwOSVersionInfoSize = sizeof(ver);
		if (pRtlGetVersion(&ver) != 0)
		{
			if (error_code)
			{
				*error_code = INJ_ERR_WINDOWS_VERSION;
			}
			return FALSE;
		}

		DWORD v_hi = ver.dwMajorVersion;
		DWORD v_lo = ver.dwMinorVersion;

		if (v_lo > 99)
		{
			v_lo %= 100;
		}

		g_OSVersion = v_hi * 100 + v_lo;
		g_OSBuildNumber = ver.dwBuildNumber;

		return TRUE;
	}
}

DWORD GetOSVersion(DWORD * error_code)
{
	DWORD init_error = 0;
	if (!InitOnceExecuteOnce(&g_OSVersionInitOnce, InitOSVersionOnce, error_code ? error_code : &init_error, nullptr))
	{
		return 0;
	}

	return g_OSVersion;
}

DWORD GetOSBuildVersion()
{
	if (g_OSBuildNumber == 0)
	{
		GetOSVersion();
	}

	return g_OSBuildNumber;
}

bool GetSupportedWindowsLayout(DWORD build_number, WINDOWS_LAYOUT_FAMILY & layout_family)
{

	bool supported = true;

	if (build_number >= 26200)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_25H2;
		if (build_number != g_Windows11_25H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 25H2 layout (known RTM %lu); recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_25H2));
		}
	}
	else if (build_number >= 26100)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_24H2;
		if (build_number != g_Windows11_24H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 24H2 layout (known RTM %lu); recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_24H2));
		}
	}
	else if (build_number >= 22621 && build_number < 23000)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_22H2;
		if (build_number != g_Windows11_22H2 && build_number != g_Windows11_23H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 22H2/23H2 layout; recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else if (build_number >= 22000 && build_number < 22621)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
		if (build_number != g_Windows11_21H2)
		{
			LOG(1, "Forward-mapped Windows build %lu to 21H2 layout; recalibrate if loader drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else
	{
		supported = false;
	}

	return supported;
}

bool FileExistsW(const std::wstring & FilePath)
{
	const DWORD attributes = GetFileAttributesW(FilePath.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

DWORD ValidateDllFile(const std::wstring & FilePath, DWORD target_machine, DWORD flags)
{
	std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
	if (!file.good())
	{
		LOG(1, "Can't open file\n");

		return FILE_ERR_CANT_OPEN_FILE;
	}

	const std::streamoff file_size = file.tellg();
	if (file_size <= 0)
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}
	if (static_cast<unsigned long long>(file_size) > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(1, "Specified file is too large\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	try
	{
		std::vector<BYTE> data(static_cast<size_t>(file_size));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char *>(data.data()), file_size);
		if (!file || file.gcount() != file_size)
		{
			LOG(1, "Failed to read the complete file\n");

			return FILE_ERR_INVALID_FILE_SIZE;
		}

		PE_IMAGE::VIEW view;
		const DWORD validation_result = PE_IMAGE::Validate(data.data(), data.size(), target_machine, BuildPeValidationOptions(flags), view);
		if (validation_result != FILE_ERR_SUCCESS)
		{
			LOG(1, "PE validation failed: %08X\n", validation_result);
		}

		return validation_result;
	}
	catch (const std::bad_alloc &)
	{
		LOG(1, "Memory allocation failed\n");

		return FILE_ERR_MEMORY_ALLOCATION_FAILED;
	}
}

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags)
{
	if (!RawData || RawSize < sizeof(IMAGE_DOS_HEADER))
	{
		LOG(1, "Specified file is too small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	if (RawSize > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(1, "In-memory image exceeds the maximum supported size: %08X\n", RawSize);

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	PE_IMAGE::VIEW view;
	const DWORD validation_result = PE_IMAGE::Validate(RawData, RawSize, target_machine, BuildPeValidationOptions(flags), view);
	if (validation_result != FILE_ERR_SUCCESS)
	{
		LOG(1, "PE validation failed: %08X\n", validation_result);
	}

	return validation_result;
}

bool GetOwnModulePathW(std::wstring & out)
{
	wchar_t buffer[MAX_PATH * 2]{ 0 };
	DWORD mod_ret = GetModuleFileNameW(g_hInjMod, buffer, sizeof(buffer) / sizeof(wchar_t));
	if (!mod_ret || mod_ret >= sizeof(buffer) / sizeof(wchar_t))
	{
		return false;
	}

	std::wstring temp = buffer;
	auto pos = temp.find_last_of('\\');
	if (pos == std::wstring::npos)
	{
		return false;
	}

	out = temp.substr(0, pos + 1);

	return true;
}

bool GetSymbolCacheRoot(std::wstring & out)
{
	out.clear();

	wchar_t local_app_data[MAX_PATH]{ 0 };
	DWORD length = GetEnvironmentVariableW(XOR_STR_W(L"LOCALAPPDATA").get(), local_app_data, MAX_PATH);
	if (!length || length >= MAX_PATH)
	{

		length = GetTempPathW(MAX_PATH, local_app_data);
		if (!length || length >= MAX_PATH)
		{
			return false;
		}
	}

	std::wstring root(local_app_data, length);
	if (root.back() != L'\\')
	{
		root += L'\\';
	}

	static const wchar_t kAlphabet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	unsigned char pick[10]{ 0 };
	if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, pick, sizeof(pick), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		const ULONGLONG ticks = GetTickCount64();
		for (int i = 0; i < 10; ++i)
		{
			pick[i] = static_cast<unsigned char>((ticks >> (i * 5)) ^ (static_cast<ULONGLONG>(i) * 131ull) ^ (reinterpret_cast<ULONG_PTR>(&pick) >> 16));
		}
	}

	std::wstring leaf;
	leaf.reserve(10);

	leaf += static_cast<wchar_t>('a' + (pick[0] % 26));

	for (int i = 1; i < 10; ++i)
	{
		leaf += kAlphabet[pick[i] % (_countof(kAlphabet) - 1)];
	}

	leaf += L'\\';
	root += leaf;

	if (!CreateDirectoryW(root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		return false;
	}

	out = root;

	return true;
}

void DeleteSymbolCacheRoot(const std::wstring & root)
{
	if (root.empty())
	{
		return;
	}

	std::wstring pattern = root;
	if (pattern.back() != L'\\')
	{
		pattern += L'\\';
	}
	pattern += L'*';

	WIN32_FIND_DATAW find_data{ 0 };
	HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &find_data, FindExSearchNameMatch, nullptr, 0);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			const wchar_t * name = find_data.cFileName;

			if (name[0] == L'.' && (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0')))
			{
				continue;
			}

			std::wstring child = root;
			if (child.back() != L'\\')
			{
				child += L'\\';
			}
			child += name;

			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{

				std::wstring nested = child + L"\\*";

				WIN32_FIND_DATAW inner{ 0 };
				HANDLE inner_find = FindFirstFileExW(nested.c_str(), FindExInfoBasic, &inner, FindExSearchNameMatch, nullptr, 0);
				if (inner_find != INVALID_HANDLE_VALUE)
				{
					do
					{
						const wchar_t * inner_name = inner.cFileName;

						if (inner_name[0] == L'.' && (inner_name[1] == L'\0' || (inner_name[1] == L'.' && inner_name[2] == L'\0')))
						{
							continue;
						}

						std::wstring inner_child = child + L"\\" + inner_name;
						SetFileAttributesW(inner_child.c_str(), FILE_ATTRIBUTE_NORMAL);
						DeleteFileW(inner_child.c_str());
					} while (FindNextFileW(inner_find, &inner));

					FindClose(inner_find);
				}

				RemoveDirectoryW(child.c_str());
			}
			else
			{
				SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
				DeleteFileW(child.c_str());
			}
		} while (FindNextFileW(find, &find_data));

		FindClose(find);
	}

	RemoveDirectoryW(root.c_str());
}

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code)
{
	// IsWow64Process only answers "WOW64 or not", which is sufficient on an x64 host but misreports a
	// native ARM64 process on an ARM64 host. IsWow64Process2 reports the target's machine type and the
	// host's native machine, so the target's effective machine can be compared against the machine this
	// build targets. It is resolved dynamically because it does not exist before Windows 10 1709.
	using f_IsWow64Process2 = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);

	static f_IsWow64Process2 pIsWow64Process2 = []() -> f_IsWow64Process2
	{
		auto kernel32_name = XOR_STR_W(L"kernel32.dll");
		HMODULE hKernel32 = GetModuleHandleW(kernel32_name.get());
		if (!hKernel32)
		{
			return nullptr;
		}

		auto proc_name = XOR_STR_A("IsWow64Process2");
		return ReCa<f_IsWow64Process2>(GetProcAddress(hKernel32, proc_name.get()));
	}();

#if defined(_M_ARM64)
	constexpr USHORT kHostMachine = IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_AMD64)
	constexpr USHORT kHostMachine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_IX86)
	constexpr USHORT kHostMachine = IMAGE_FILE_MACHINE_I386;
#else
	constexpr USHORT kHostMachine = IMAGE_FILE_MACHINE_UNKNOWN;
#endif

	if (pIsWow64Process2)
	{
		USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
		USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

		if (!pIsWow64Process2(hTargetProc, &process_machine, &native_machine))
		{
			if (error_code)
			{
				*error_code = GetLastError();
			}

			return false;
		}

		if (error_code)
		{
			*error_code = ERROR_SUCCESS;
		}

		// A process that runs natively reports IMAGE_FILE_MACHINE_UNKNOWN for its own machine and the
		// host's native machine instead; either way the effective machine is the one that matters.
		const USHORT effective = process_machine != IMAGE_FILE_MACHINE_UNKNOWN ? process_machine : native_machine;

		return effective == kHostMachine;
	}

	BOOL bWOW64 = FALSE;
	if (!IsWow64Process(hTargetProc, &bWOW64))
	{
		if (error_code)
		{
			*error_code = GetLastError();
		}

		return false;
	}

	if (error_code)
	{
		*error_code = ERROR_SUCCESS;
	}

	return !bWOW64;
}

bool AllowDirectHandleFallback()
{
	static const bool allowed = []() -> bool
	{
		wchar_t buffer[8] = {};
		auto env_name = XOR_STR_W(L"INJ_ALLOW_DIRECT_FALLBACK");
		const DWORD got = GetEnvironmentVariableW(env_name.get(), buffer, 4);
		return (got == 1 && buffer[0] == L'1');
	}();

	return allowed;
}

namespace
{
	constexpr size_t kErrorRingCapacity = 16;

	struct ERROR_RING_RECORD
	{
		DWORD ErrorCode = 0;
		DWORD AdvErrorCode = 0;
		int Line = 0;
		DWORD Flags = 0;
		int bNative = 0;
		wchar_t DllFileName[MAX_PATH] = {};
		wchar_t TargetProcessExeFileName[MAX_PATH] = {};
	};

	ERROR_RING_RECORD g_ErrorRing[kErrorRingCapacity]{};
	size_t g_ErrorRingHead = 0;
	size_t g_ErrorRingCount = 0;

	std::wstring BasenameOnly(const std::wstring & path)
	{
		const size_t slash = path.find_last_of(L"\\/");

		return slash == std::wstring::npos ? path : path.substr(slash + 1);
	}
}

void ErrorLog(const ERROR_INFO & info)
{
	ERROR_RING_RECORD redacted{};
	redacted.ErrorCode = info.ErrorCode;
	redacted.AdvErrorCode = info.AdvErrorCode;
	redacted.Line = info.Line;
	redacted.Flags = info.Flags;
	redacted.bNative = info.bNative;

	const std::wstring dll_name = BasenameOnly(info.DllFileName);
	wcsncpy_s(redacted.DllFileName, _countof(redacted.DllFileName), dll_name.c_str(), _TRUNCATE);
	wcsncpy_s(redacted.TargetProcessExeFileName, _countof(redacted.TargetProcessExeFileName), info.TargetProcessExeFileName.c_str(), _TRUNCATE);

	AcquireSRWLockExclusive(&g_ErrorLogLock);
	g_ErrorRing[g_ErrorRingHead] = redacted;
	g_ErrorRingHead = (g_ErrorRingHead + 1) % kErrorRingCapacity;
	if (g_ErrorRingCount < kErrorRingCapacity)
	{
		++g_ErrorRingCount;
	}
	ReleaseSRWLockExclusive(&g_ErrorLogLock);

	LOG(1, "Load failed: code=%08X adv=%08X flags=%08X\n",
		info.ErrorCode, info.AdvErrorCode, info.Flags);
}

DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out)
{
#pragma EXPORT_FUNCTION("CoreLastError", __FUNCDNAME__)

	if (!Out)
	{
		return INJ_ERR_NO_DATA;
	}

	ERROR_RING_RECORD snapshot{};
	bool have_record = false;

	AcquireSRWLockShared(&g_ErrorLogLock);
	if (g_ErrorRingCount)
	{

		const size_t newest = (g_ErrorRingHead + kErrorRingCapacity - 1) % kErrorRingCapacity;
		snapshot = g_ErrorRing[newest];
		have_record = true;
	}
	ReleaseSRWLockShared(&g_ErrorLogLock);

	if (!have_record)
	{
		return INJ_ERR_NOT_IMPLEMENTED;
	}

	*Out = LAST_ERROR_INFO{};

	Out->ErrorCode = snapshot.ErrorCode;
	Out->AdvErrorCode = snapshot.AdvErrorCode;
	Out->Line = snapshot.Line;
	Out->Flags = snapshot.Flags;
	Out->bNative = snapshot.bNative;

	wcsncpy_s(Out->DllFileName, _countof(Out->DllFileName), snapshot.DllFileName, _TRUNCATE);
	wcsncpy_s(Out->TargetProcessExeFileName, _countof(Out->TargetProcessExeFileName), snapshot.TargetProcessExeFileName, _TRUNCATE);

	return INJ_ERR_SUCCESS;
}

bool StartAsyncWorker(ASYNC_WORKER_SLOT & slot, LPTHREAD_START_ROUTINE entry, void * param)
{
	slot.Thread = nullptr;
	slot.Done = nullptr;
	slot.Result = 0;

	if (!entry)
	{
		return false;
	}

	HANDLE done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!done)
	{
		return false;
	}

	slot.Done = done;
	HANDLE thread = CreateThread(nullptr, 0, entry, param, 0, nullptr);
	if (!thread)
	{
		CloseHandle(done);
		slot.Done = nullptr;
		return false;
	}

	slot.Thread = thread;
	return true;
}

bool AsyncWorkerStarted(const ASYNC_WORKER_SLOT & slot)
{
	return slot.Thread != nullptr;
}

bool PollAsyncWorker(ASYNC_WORKER_SLOT & slot)
{
	if (!slot.Done)
	{
		return false;
	}

	return WaitForSingleObject(slot.Done, 0) == WAIT_OBJECT_0;
}

void JoinAsyncWorker(ASYNC_WORKER_SLOT & slot)
{
	if (slot.Thread)
	{
		WaitForSingleObject(slot.Thread, INFINITE);
		CloseHandle(slot.Thread);
		slot.Thread = nullptr;
	}
	if (slot.Done)
	{
		CloseHandle(slot.Done);
		slot.Done = nullptr;
	}
}

std::wstring CharArrayToStdWstring(const char * szString)
{
	std::wstring out;
	if (szString)
	{
		const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, nullptr, 0);
		if (required > 1)
		{
			out.assign(static_cast<size_t>(required) - 1, L'\0');

			if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, out.data(), required))
			{
				out.clear();
			}
		}
	}

	return out;
}

void __stdcall StartDownload()
{
#pragma EXPORT_FUNCTION("CoreFetch", __FUNCDNAME__)

	const DWORD initialization_state = InitializeRuntime();
	if (initialization_state != INJ_ERR_SUCCESS)
	{
		LOG(0, "Runtime initialization failed: %08X\n", initialization_state);

		return;
	}

	LOG(0, "Beginning download(s)\n");

	sym_ntdll_native.SetDownload(true);
}
