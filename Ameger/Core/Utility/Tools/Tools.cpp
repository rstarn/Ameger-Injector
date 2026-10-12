#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Utility/Tools/Tools.h"
#include "Injection.h"
#include "System/Import/ImportHandler.h"

#include <bcrypt.h>
#include <iomanip>

// Host utility implementations (see Tools.h for the per-function contract).
// What: OS probes, PE validation wrappers, path/temp/scramble helpers, and
//   the serialized error log. Why here: shared logic every stage needs, kept
//   out of headers to avoid bloating the in-target shell. bcrypt is linked
//   for the payload SHA-256 pin check.
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

		// No PEB/TEB offsets here: version comes from RtlGetVersion (ntdll
		// export, no struct layout needed) instead of __readgsqword(0x60) +
		// hardcoded PEB field offsets. Fully dynamic, no per-build constants.
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

		// Clamp the minor into the 0..99 window the packing below assumes.
		// A conforming RTL_OSVERSIONINFOW always reports 0..9, so this is
		// defensive. The previous `for (; v_lo >= 10; v_lo /= 10)` divided by
		// 10 rather than reducing modulo 100, so any out-of-range report was
		// silently mangled (13 became 1) instead of folded into range.
		if (v_lo > 99)
		{
			v_lo %= 100;
		}

		// Packed as major * 100 + minor, the contract Tools.h documents
		// (Win10/11 => 1000, Win8.1 => 602, Win7 => 601).
		//
		// This used to be `v_hi * 10 + v_lo`, which yields 100 for Win11 and
		// matches neither the header nor any recognized packing: 100 is also
		// what a literal "major*100+minor" read of a bogus 1.0 release gives.
		// No consumer compares the value today - the OS gate is build-number
		// based (GetSupportedWindowsLayout) and Main.cpp only tests it against
		// zero - so the defect never fired. It is fixed here because the next
		// consumer that trusts the header would otherwise be handed a version
		// number 10x too small, and 22000-vs-2200 is exactly the class of
		// off-by-a-factor error this codebase documents against elsewhere.
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
	// 22H2 (22621) and 23H2 (22631) share the same ntdll/loader layout
	// (23H2 is a 22H2 enablement package), so they map to one family.
	// 24H2 (26100) and 25H2 (26200) are likewise layout-compatible within
	// their ranges. Exact-equality matching broke every 23H2 machine
	// (the most common Win11 gaming build) with INJ_ERR_WINDOWS_BUILD_UNSUPPORTED
	// (0x4E), which the UI then misreported as "Failed to load symbols".
	// Match by range and forward-map newer builds to the latest known family
	// instead of failing closed on each feature update.
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

	// Mirror ValidateDllFile's ceiling (:178). This path bounds every read
	// PE_IMAGE::Validate makes by the caller-supplied RawSize, so without an
	// upper bound a wrong RawSize reads past the caller's buffer instead of
	// being rejected.
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

// Builds the root that the symbol cache lives under for this run. The leaf is
// drawn per run from the OS CSPRNG, so two things that a stable name would
// expose are gone: a directory an observer can look for by name, and a
// directory an earlier run has already left behind. The caller owns the tree:
// DeleteSymbolCacheRoot() removes it again (PurgePdb -> ImportHandler ->
// launcher shutdown), so a completed run leaves nothing even though the leaf
// name is unpredictable.
bool GetSymbolCacheRoot(std::wstring & out)
{
	out.clear();

	wchar_t local_app_data[MAX_PATH]{ 0 };
	DWORD length = GetEnvironmentVariableW(XOR_STR_W(L"LOCALAPPDATA").get(), local_app_data, MAX_PATH);
	if (!length || length >= MAX_PATH)
	{
		// LOCALAPPDATA absent (stripped/service environment): fall back to the
		// system temp dir rather than the caller's module-directory fallback.
		// The module dir is the loudest possible home for a timestamped
		// ntdll.pdb; TEMP already contains arbitrary artifacts on this machine
		// and is swept by cleanup, so the PDB blends in instead of sitting a
		// multi-megabyte file beside the runtime. PurgePdb still deletes it
		// once imports resolve. An empty TEMP return falls through to the
		// caller, preserving its existing behavior as a last resort.
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

	// Random 10-character leaf, first character a letter so the name parses as
	// a plain directory name. Drawn from the same CSPRNG the temp-name helper
	// uses, with the tick counter as a fallback if the OS call fails.
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

	// Letters only for the first character.
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

// Removes the per-run symbol cache tree, including the PDB and the Symbols
// directory. Best effort: the tree is random-named and uninteresting on disk,
// so a failure to delete is reported but never allowed to fail the run that
// requested the removal.
void DeleteSymbolCacheRoot(const std::wstring & root)
{
	if (root.empty())
	{
		return;
	}

	// Depth-first: clear the two levels the loader creates (the Symbols
	// directory and the PDB inside it) plus the random root itself.
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
				// One nested level, then remove the directory.
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

// Stealth: no disk artifact. Failures stay in a volatile ring buffer
// (16 entries) and go to the debug callback only. The ring stores exactly the
// fields GetLastErrorInfo publishes - and nothing it deliberately drops. The
// full ERROR_INFO carries SourceFile/FunctionName (always empty, layout
// compat), TargetProcessId, HandleValue and the RawData pointer/size; keeping
// those in a global would put operator paths, PIDs and payload pointers into
// every crash dump of this process, which is precisely what the ring's contract
// forbids. Fixed arrays keep the record fully inside the ring buffer with no
// separate heap allocation per entry.
namespace
{
	constexpr size_t kErrorRingCapacity = 16;

	struct ERROR_RING_RECORD
	{
		DWORD ErrorCode = 0;
		DWORD AdvErrorCode = 0;
		int Line = 0;
		DWORD Flags = 0;
		INJECTION_MODE InjectionMode = INJECTION_MODE::IM_ManualMap;
		LAUNCH_METHOD LaunchMethod = LAUNCH_METHOD::LM_HijackThread;
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
	redacted.InjectionMode = info.InjectionMode;
	redacted.LaunchMethod = info.LaunchMethod;
	redacted.bNative = info.bNative;

	// Basename before storing so even a crash dump never holds an absolute
	// operator path. TargetProcessExeFileName is already a bare exe name (see
	// Inject_Internal QueryFullProcessImageNameW handling).
	const std::wstring dll_name = BasenameOnly(info.DllFileName);
	wcsncpy_s(redacted.DllFileName, _countof(redacted.DllFileName), dll_name.c_str(), _TRUNCATE);
	wcsncpy_s(redacted.TargetProcessExeFileName, _countof(redacted.TargetProcessExeFileName), info.TargetProcessExeFileName.c_str(), _TRUNCATE);
	// Deliberately NEVER stored: TargetProcessId, HandleValue, SourceFile,
	// FunctionName, RawData, RawSize. GetLastErrorInfo cannot publish what the
	// ring does not hold, so a dump of this process cannot surface them either.

	AcquireSRWLockExclusive(&g_ErrorLogLock);
	g_ErrorRing[g_ErrorRingHead] = redacted;
	g_ErrorRingHead = (g_ErrorRingHead + 1) % kErrorRingCapacity;
	if (g_ErrorRingCount < kErrorRingCapacity)
	{
		++g_ErrorRingCount;
	}
	ReleaseSRWLockExclusive(&g_ErrorLogLock);

	// Debug channel only (console/callback when the operator attaches one).
	// No PID, no full path, no file write.
	LOG(1, "Load failed: code=%08X adv=%08X flags=%08X mode=%d method=%d\n",
		info.ErrorCode, info.AdvErrorCode, info.Flags,
		static_cast<int>(info.InjectionMode), static_cast<int>(info.LaunchMethod));
}

DWORD __stdcall GetLastErrorInfo(LAST_ERROR_INFO * Out)
{
#pragma EXPORT_FUNCTION("CoreLastError", __FUNCDNAME__)

	if (!Out)
	{
		return INJ_ERR_NO_DATA;
	}

	// Take a copy under the lock so a concurrent ErrorLog cannot advance the
	// head between reading the index and reading the record. The ring record
	// is a plain fixed-array struct, so this copy shares nothing with the
	// ring and the flat POD below needs no further translation of heap state.
	ERROR_RING_RECORD snapshot{};
	bool have_record = false;

	AcquireSRWLockShared(&g_ErrorLogLock);
	if (g_ErrorRingCount)
	{
		// The newest record sits one slot behind the head.
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
	Out->InjectionMode = static_cast<int>(snapshot.InjectionMode);
	Out->LaunchMethod = static_cast<int>(snapshot.LaunchMethod);
	Out->bNative = snapshot.bNative;

	// wcsncpy_s with an explicit destination size truncates rather than
	// overrunning. The sources are already basename-redacted by ErrorLog, so no
	// absolute operator path leaves the process.
	wcsncpy_s(Out->DllFileName, _countof(Out->DllFileName), snapshot.DllFileName, _TRUNCATE);
	wcsncpy_s(Out->TargetProcessExeFileName, _countof(Out->TargetProcessExeFileName), snapshot.TargetProcessExeFileName, _TRUNCATE);

	// There is no "deliberately not copied" list any more: TargetProcessId,
	// HandleValue, SourceFile, FunctionName, RawData and RawSize were never
	// stored in the ring (see ErrorLog), so GetLastErrorInfo cannot publish
	// them even by mistake. The property is structural, not a checklist in a
	// comment.

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

	// Publish Done before the thread exists so a worker that runs immediately
	// can never observe or signal a null event. If creation fails the thread
	// never ran, so clearing the slot cannot race.
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
			// Same flag as the sizing call: without it the conversion silently
			// substitutes U+FFFD for invalid bytes, so a string that failed the
			// size probe could still yield a (corrupted) result here.
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
