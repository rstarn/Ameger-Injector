#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Utility/Tools/Tools.h"
#include "../../../Injection.h"
#include "System/Import/ImportHandler.h"

#include <bcrypt.h>

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
	// Builds above the validated ceiling are refused. Forward mapping is only
	// defensible within a release family whose loader layout was checked; it
	// is not a licence to accept an arbitrary future build.
	if (build_number > g_Windows11_KnownMaxBuild)
	{
		LOG(1, "Refusing Unknown Windows Build %lu: Newest Validated Layout Is 26H2 (Ceiling %lu)\n",
			static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_KnownMaxBuild));

		return false;
	}
	// Builds newer than the newest known release within the validated ceiling
	// are mapped onto the closest supported family. The loader layout only
	// changes at a release boundary, so a newer build is expected to share the
	// layout of the family it was released in.
	if (build_number >= 26300)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_26H2;
		if (build_number != g_Windows11_26H2)
		{
			LOG(1, "Forward-Mapped Windows Build %lu To 26H2 Layout (Known RTM %lu); Recalibrate If Loader Drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_26H2));
		}
	}
	else if (build_number >= 26200)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_25H2;
		if (build_number != g_Windows11_25H2)
		{
			LOG(1, "Forward-Mapped Windows Build %lu To 25H2 Layout (Known RTM %lu); Recalibrate If Loader Drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_25H2));
		}
	}
	else if (build_number >= 26100)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_24H2;
		if (build_number != g_Windows11_24H2)
		{
			LOG(1, "Forward-Mapped Windows Build %lu To 24H2 Layout (Known RTM %lu); Recalibrate If Loader Drifts\n",
				static_cast<unsigned long>(build_number), static_cast<unsigned long>(g_Windows11_24H2));
		}
	}
	else if (build_number >= 22621 && build_number < 23000)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_22H2;
		if (build_number != g_Windows11_22H2 && build_number != g_Windows11_23H2)
		{
			LOG(1, "Forward-Mapped Windows Build %lu To 22H2/23H2 Layout; Recalibrate If Loader Drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else if (build_number >= 22000 && build_number < 22621)
	{
		layout_family = WINDOWS_LAYOUT_FAMILY::Windows11_21H2;
		if (build_number != g_Windows11_21H2)
		{
			LOG(1, "Forward-Mapped Windows Build %lu To 21H2 Layout; Recalibrate If Loader Drifts\n",
				static_cast<unsigned long>(build_number));
		}
	}
	else
	{
		supported = false;
	}

	return supported;
}

DWORD ValidateDllFileInMemory(const BYTE * RawData, DWORD RawSize, DWORD target_machine, DWORD flags)
{
	if (!RawData || RawSize < sizeof(IMAGE_DOS_HEADER))
	{
		LOG(1, "Specified File Is Too Small\n");

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	if (RawSize > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(1, "In-Memory Image Exceeds The Maximum Supported Size = %08X\n", RawSize);

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	PE_IMAGE::VIEW view;
	const DWORD validation_result = PE_IMAGE::Validate(RawData, RawSize, target_machine, BuildPeValidationOptions(flags), view);
	if (validation_result != FILE_ERR_SUCCESS)
	{
		LOG(1, "PE Validation Failed = %08X\n", validation_result);
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
		leaf += kAlphabet[pick[i] % _countof(kAlphabet)];
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

bool BuildStablePdbCachePath(const std::wstring & pdb_name, const std::wstring & guid_and_age, std::wstring & out)
{
	out.clear();

	if (pdb_name.empty() || guid_and_age.empty())
	{
		return false;
	}

	if (pdb_name.find_first_of(L"\\/:") != std::wstring::npos || pdb_name.find(L"..") != std::wstring::npos ||
		guid_and_age.find_first_of(L"\\/:") != std::wstring::npos || guid_and_age.find(L"..") != std::wstring::npos)
	{
		return false;
	}

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

	// The layout follows the standard symbol-store shape so the file looks
	// like an ordinary debugging cache instead of a tool-specific artifact.
	root += XOR_STR_W(L"Symbols\\").get();
	root += pdb_name;
	root += L'\\';
	root += guid_and_age;
	root += L'\\';
	root += pdb_name;

	out = root;

	return true;
}

namespace
{
	// The scratch tree is walked iteratively rather than recursively so a
	// pathological depth cannot overflow the stack. Anything deeper than the
	// limit is left on disk and reported.
	constexpr size_t kMaxScratchTreeDepth = 64;

	struct ScratchTreeEntry
	{
		std::wstring Path;
		size_t Depth;
	};
	// Deleting the tree is a two phase operation: every file and directory is
	// collected first, then the directories are removed bottom up. Doing it in
	// one pass would require the whole tree to be held in memory.
	bool DeleteScratchTree(const std::wstring & root)
	{
		bool complete = true;
		// Directories are collected for the removal pass, subdirectories are
		// queued for the walk.
		std::vector<std::wstring> directories;
		std::vector<ScratchTreeEntry> pending;

		pending.push_back(ScratchTreeEntry{ root, 0 });

		while (!pending.empty())
		{
			const ScratchTreeEntry current = pending.back();
			pending.pop_back();

			std::wstring pattern = current.Path;
			if (pattern.back() != L'\\')
			{
				pattern += L'\\';
			}
			pattern += L'*';

			WIN32_FIND_DATAW find_data{ 0 };
			HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &find_data, FindExSearchNameMatch, nullptr, 0);
			if (find == INVALID_HANDLE_VALUE)
			{
				continue;
			}

			do
			{
				const wchar_t * name = find_data.cFileName;

				if (name[0] == L'.' && (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0')))
				{
					continue;
				}

				std::wstring child = current.Path;
				if (child.back() != L'\\')
				{
					child += L'\\';
				}
				child += name;

				if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);

					if (!DeleteFileW(child.c_str()))
					{
						LOG(1, "Failed To Delete A File In Scratch Storage = 0x%08X (%ls)\n", GetLastError(), child.c_str());

						complete = false;
					}

					continue;
				}
				// A reparse point is removed as a link, never followed. Following
				// one would delete whatever it points at, which is not ours to
				// delete.
				if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
				{
					if (!RemoveDirectoryW(child.c_str()))
					{
						LOG(1, "Failed To Remove A Reparse Point In Scratch Storage = 0x%08X (%ls)\n", GetLastError(), child.c_str());

						complete = false;
					}

					continue;
				}

				if (current.Depth + 1 >= kMaxScratchTreeDepth)
				{
					LOG(1, "Scratch Storage Is Deeper Than The Supported Limit And Was Left In Place = %ls\n", child.c_str());

					complete = false;

					continue;
				}

				pending.push_back(ScratchTreeEntry{ child, current.Depth + 1 });
				directories.push_back(child);
			} while (FindNextFileW(find, &find_data));

			FindClose(find);
		}

		for (size_t i = directories.size(); i > 0; --i)
		{
			if (!RemoveDirectoryW(directories[i - 1].c_str()))
			{
				const DWORD remove_error = GetLastError();

				if (remove_error != ERROR_FILE_NOT_FOUND && remove_error != ERROR_PATH_NOT_FOUND)
				{
					LOG(1, "Failed To Remove A Directory In Scratch Storage = 0x%08X (%ls)\n", remove_error, directories[i - 1].c_str());

					complete = false;
				}
			}
		}

		return complete;
	}
}

bool DeleteSymbolCacheRoot(const std::wstring & root)
{
	if (root.empty())
	{
		return false;
	}
	// Only a directory this library created may be removed. The check is on
	// the leaf name and on the parent directory, so an unrelated path that
	// happens to look similar is left alone.
	if (!IsOwnedScratchRoot(root))
	{
		LOG(1, "Refusing To Delete A Path That Is Not Owned Scratch Storage = %ls\n", root.c_str());

		return false;
	}

	const bool tree_cleared = DeleteScratchTree(root);
	// The root itself is removed after its contents. A root that is already
	// gone is not an error.
	if (RemoveDirectoryW(root.c_str()))
	{
		return tree_cleared;
	}

	const DWORD remove_error = GetLastError();

	return remove_error == ERROR_FILE_NOT_FOUND || remove_error == ERROR_PATH_NOT_FOUND;
}

bool IsNativeProcess(HANDLE hTargetProc, DWORD * error_code)
{
	// WOW64 targets are not supported by this build, so the target's machine
	// type has to match the host's exactly.
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
					*error_code = GetLastError();
				return false;
			}

			if (error_code)
				*error_code = ERROR_SUCCESS;

			const USHORT effective = process_machine != IMAGE_FILE_MACHINE_UNKNOWN ? process_machine : native_machine;
			return effective == kHostMachine;
		}

		BOOL bWOW64 = FALSE;
		if (!IsWow64Process(hTargetProc, &bWOW64))
		{
			if (error_code)
				*error_code = GetLastError();
			return false;
		}

		if (error_code)
			*error_code = ERROR_SUCCESS;

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

bool SymbolDownloadDisabled()
{
	static const bool disabled = []() -> bool
	{
		wchar_t buffer[8] = {};
		auto env_name = XOR_STR_W(L"AMEGER_SYMBOL_DOWNLOAD");
		const DWORD got = GetEnvironmentVariableW(env_name.get(), buffer, 4);
		return (got == 1 && buffer[0] == L'0');
	}();

	return disabled;
}

namespace
{
	constexpr size_t kRandomLeafLength = 10;
	// The scratch leaf is a fixed length random name. Recognising it by shape
	// rather than by a stored list is what makes it safe to delete later: a
	// path that does not match the shape was never ours.
	bool IsScratchLeafName(const std::wstring & leaf)
	{
		if (leaf == AMEGER_SCRATCH_LEAF_DIR)
		{
			return true;
		}

		if (leaf.size() != kRandomLeafLength)
		{
			return false;
		}

		for (size_t i = 0; i < leaf.size(); ++i)
		{
			const wchar_t c = leaf[i];

			const bool alnum =
				(c >= L'a' && c <= L'z') ||
				(c >= L'A' && c <= L'Z') ||
				(c >= L'0' && c <= L'9');

			if (!alnum)
			{
				return false;
			}
		}

		return leaf[0] >= L'a' && leaf[0] <= L'z';
	}

	std::wstring NormalizeTrailingSeparator(std::wstring path)
	{
		if (path.size() >= 2 && path.back() != L'\\' && path.back() != L'/')
		{
			path += L'\\';
		}

		return path;
	}

	std::wstring Lowercase(const std::wstring & text)
	{
		std::wstring out = text;

		for (size_t i = 0; i < out.size(); ++i)
		{
			wchar_t & c = out[i];
			if (c >= L'A' && c <= L'Z')
			{
				c = static_cast<wchar_t>(c - L'A' + L'a');
			}
		}

		return out;
	}
}

bool IsOwnedScratchRoot(const std::wstring & root)
{
	if (root.empty() || root.size() < 4)
	{
		return false;
	}

	if (root[1] != L':' || (root[2] != L'\\' && root[2] != L'/'))
	{
		return false;
	}

	const std::wstring normalized = NormalizeTrailingSeparator(root);

	const size_t drive_end = normalized.find_first_of(L"\\/", 3);
	if (drive_end == std::wstring::npos)
	{
		return false;
	}

	std::wstring leaf;
	for (size_t i = normalized.size() - 2; i > 0; --i)
	{
		const wchar_t c = normalized[i];
		if (c == L'\\' || c == L'/')
		{
			break;
		}

		leaf.insert(leaf.begin(), c);
	}

	if (!IsScratchLeafName(leaf))
	{
		return false;
	}
	// The directory this library runs from must never be deleted, even if a
	// scratch leaf happens to sit underneath it.
	std::wstring own_path;
	{
		wchar_t buffer[MAX_PATH * 2]{ 0 };
		const DWORD written = GetModuleFileNameW(g_hInjMod, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
		if (written && written < sizeof(buffer) / sizeof(buffer[0]))
		{
			const std::wstring full = buffer;
			const size_t slash = full.find_last_of(L"\\/");
			own_path = slash == std::wstring::npos ? std::wstring() : NormalizeTrailingSeparator(full.substr(0, slash));
		}
	}

	const std::wstring lower_root = Lowercase(normalized);

	const std::wstring windows_dir = []() -> std::wstring
	{
		wchar_t buffer[MAX_PATH]{ 0 };
		const DWORD length = GetWindowsDirectoryW(buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
		if (!length || length >= sizeof(buffer) / sizeof(buffer[0]))
		{
			return std::wstring();
		}

		return Lowercase(NormalizeTrailingSeparator(std::wstring(buffer, length)));
	}();

	if (!windows_dir.empty())
	{
		if (lower_root == windows_dir || lower_root.compare(0, windows_dir.size(), windows_dir) == 0)
		{
			return false;
		}
	}
	// A scratch root nested under the runtime's own directory is only
	// accepted when every path segment below it is a scratch leaf.
	if (!own_path.empty())
	{
		const std::wstring lower_own = Lowercase(own_path);

		if (lower_root == lower_own)
		{
			return false;
		}

		const bool nested = lower_root.compare(0, lower_own.size(), lower_own) == 0;
		if (nested)
		{
			std::wstring remainder = lower_root.substr(lower_own.size());
			if (!remainder.empty() && (remainder.front() == L'\\' || remainder.front() == L'/'))
			{
				remainder.erase(remainder.begin());
			}

			size_t first = 0;
			for (;;)
			{
				const size_t next = remainder.find_first_of(L"\\/", first);
				if (next == std::wstring::npos)
				{
					break;
				}

				if (!IsScratchLeafName(remainder.substr(first, next - first)))
				{
					return false;
				}

				first = next + 1;
			}
		}
	}

	return true;
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

	LOG(1, "Load Failed: Code = %08X | Adv = %08X | Flags = %08X\n",
		info.ErrorCode, info.AdvErrorCode, info.Flags);
}

DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out)
{
	EXPORT_FUNCTION("CoreLastError", __FUNCDNAME__)

	if (!Out)
	{
		return INJ_ERR_NO_DATA;
	}

	*Out = LAST_ERROR_INFO{};

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
		// Nothing has been logged yet, so there is no detail to report.
		return INJ_ERR_NO_LAST_ERROR;
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

DWORD __stdcall ClearLastErrorInfo()
{
	EXPORT_FUNCTION("CoreClearLastError", __FUNCDNAME__)

	AcquireSRWLockExclusive(&g_ErrorLogLock);
	for (size_t i = 0; i < kErrorRingCapacity; ++i)
	{
		g_ErrorRing[i] = ERROR_RING_RECORD{};
	}

	g_ErrorRingHead = 0;
	g_ErrorRingCount = 0;
	ReleaseSRWLockExclusive(&g_ErrorLogLock);

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

bool WaitAsyncWorkerThread(const ASYNC_WORKER_SLOT & slot)
{
	if (!slot.Thread)
	{
		return true;
	}

	return WaitForSingleObject(slot.Thread, INFINITE) == WAIT_OBJECT_0;
}

std::wstring CharArrayToStdWstring(const char * szString)
{
	std::wstring out;
	if (szString)
	{
		const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, nullptr, 0);
		if (required > 1)
		{
			out.assign(static_cast<size_t>(required), L'\0');

			if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szString, -1, out.data(), required))
			{
				out.clear();
			}
			else
			{
				out.resize(static_cast<size_t>(required) - 1);
			}
		}
	}

	return out;
}

void __stdcall StartDownload()
{
	EXPORT_FUNCTION("CoreFetch", __FUNCDNAME__)

	const DWORD initialization_state = InitializeRuntime();
	if (initialization_state != INJ_ERR_SUCCESS)
	{
		LOG(0, "Runtime Initialization Failed = %08X\n", initialization_state);

		return;
	}

	LOG(0, "Beginning Download(s)\n");

	sym_ntdll_native.SetDownload(true);
}
