#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection.h"
#include "Injection/ManualMapping/ManualMappingCore.h"
#include "System/Handle/HandleHijack.h"

DWORD __stdcall InitializeRuntime();

namespace
{

	DWORD OpenTargetProcess(DWORD Pid, DWORD AccessMask, DWORD Flags, ULONG_PTR SponsorValue, UniqueHandle & Out, ERROR_DATA & ErrorData)
	{
		Out.reset();

		if (Flags & INJ_HANDLE_HIJACKING)
		{
			HijackStats Stats{ };
			Stats.Attempted = 1;
			Stats.Source = static_cast<DWORD>(HijackSource::Scan);

			HANDLE ValidatedSponsorOwner = nullptr;

			if (SponsorValue)
			{
				HANDLE Sponsor = ReCa<HANDLE>(SponsorValue);
				if (ValidateProcessDonorHandle(Sponsor, Pid, AccessMask))
				{
					ValidatedSponsorOwner = Sponsor;
					Stats.SponsorValidated = 1;
					Stats.DonorHandle = PtrToUlong(Sponsor);
					HANDLE Duplicated = nullptr;
					bool duplicate_ok = DuplicateHandle(GetCurrentProcess(), Sponsor, GetCurrentProcess(),
						&Duplicated, AccessMask, FALSE, 0) && Duplicated && ValidateProcessDonorHandle(Duplicated, Pid, AccessMask);
					const bool roundtrip_ok = duplicate_ok &&
						((Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) != 0 || ProbeMemoryRoundtrip(Duplicated));
					if (duplicate_ok && roundtrip_ok)
					{
						Out.reset(Duplicated);
						Stats.Success = 1;
						Stats.Source = static_cast<DWORD>(HijackSource::Sponsor);
						Stats.DonorPid = GetCurrentProcessId();
						Stats.GrantedAccess = AccessMask;
						Stats.NewHandle = PtrToUlong(Duplicated);
						Stats.SponsorProbed = (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 1;
						Stats.FailCode = INJ_ERR_SUCCESS;
						RecordHijackOutcome(Stats, false);
						LOG(0, "Acquired target process handle from sponsor\n");

						return INJ_ERR_SUCCESS;
					}

					if (Duplicated)
					{
						CloseHandle(Duplicated);
					}
				}

				LOG(0, "Sponsor handle failed validation\n");
			}

			if (!(Flags & INJ_NO_DONOR_SCAN))
			{
				HANDLE Hijacked = nullptr;
				const DWORD SavedSponsorValidated = Stats.SponsorValidated;
				const DWORD SavedSponsorProbed = Stats.SponsorProbed;
				const DWORD SavedDonorHandle = Stats.DonorHandle;

				const DWORD HijackRet = HijackProcessHandle(Pid, AccessMask, Hijacked, &Stats,
					ValidatedSponsorOwner);
				Stats.SponsorValidated = SavedSponsorValidated;
				Stats.SponsorProbed = SavedSponsorProbed;
				if (Stats.Success == 0)
				{
					Stats.DonorHandle = SavedDonorHandle;
				}
				if (HijackRet == INJ_ERR_SUCCESS && Hijacked)
				{
					Out.reset(Hijacked);
					RecordHijackOutcome(Stats, false);
					LOG(0, "Acquired target process handle via acquisition\n");

					return INJ_ERR_SUCCESS;
				}

				LOG(0, "Handle acquisition found no donor (%08X)\n", HijackRet);
				Stats.FailCode = HijackRet;
			}
			else if (Stats.FailCode == INJ_ERR_SUCCESS)
			{
				Stats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			Stats.Source = static_cast<DWORD>(HijackSource::Scan);
			RecordHijackOutcome(Stats, false);
			LOG(0, "Handle acquisition found no donor; refusing (no direct fallback)\n");
			INIT_ERROR_DATA(ErrorData, Stats.FailCode ? Stats.FailCode : static_cast<DWORD>(INJ_ERR_HANDLE_HIJACK_FAILED));
			return INJ_ERR_HANDLE_HIJACK_FAILED;
		}

		Out.reset(OpenProcess(AccessMask, FALSE, Pid));
		if (!Out)
		{
			INIT_ERROR_DATA(ErrorData, GetLastError());
			return INJ_ERR_CANT_OPEN_PROCESS;
		}

		return INJ_ERR_SUCCESS;
	}

	class InjectionGateGuard
	{
		bool m_Acquired = false;

	public:
		InjectionGateGuard()
		{
			m_Acquired = InterlockedCompareExchange(&g_InjectionGate, 1, 0) == 0;
			if (m_Acquired)
			{
				SetEvent(g_hRunningEvent);
				ResetEvent(g_hInterruptEvent);
				ResetEvent(g_hInterruptedEvent);
			}
		}

		~InjectionGateGuard()
		{
			if (m_Acquired)
			{
				ResetEvent(g_hRunningEvent);
				InterlockedExchange(&g_InjectionGate, 0);
			}
		}

		explicit operator bool() const
		{
			return m_Acquired;
		}
	};
}

DWORD InitErrorStruct(const INJECTIONDATA_INTERNAL & Data, int Native, DWORD ErrorCode, const ERROR_DATA & error_data)
{
	if (ErrorCode && Data.GenerateErrorLog)
	{
		ERROR_INFO info{ };
		info.DllFileName				= Data.DllPath;
		info.TargetProcessExeFileName	= Data.TargetProcessExeFileName;
		info.TargetProcessId			= Data.ProcessID;
		info.InjectionMode				= Data.Mode;
		info.LaunchMethod				= Data.Method;
		info.Flags						= Data.Flags;
		info.HandleValue				= Data.hHandleValue;
		info.bNative					= Native;
		info.RawData					= Data.RawData;
		info.RawSize					= Data.RawSize;

		info.ErrorCode		= ErrorCode;
		info.AdvErrorCode	= error_data.AdvErrorCode;
		info.SourceFile		= error_data.szFileName;
		info.FunctionName	= error_data.szFunctionName;
		info.Line			= error_data.Line;

		ErrorLog(info);
	}

	return ErrorCode;
}

static DWORD Memory_InjectBody(MEMORY_INJECTIONDATA * pData)
{
	LOG(0, "CoreExecute called with pData = %p\n", pData);

	if (!pData)
	{
		LOG(0, "pData is invalid\n");

		return INJ_ERR_NO_DATA;
	}

	ERROR_DATA error_data{ 0 };

	try
	{
	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different operation in progress. Wait for the other operation to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData->RawData)
	{
		LOG(0, "No raw data\n");

		return INJ_ERR_NO_RAW_DATA;
	}

	if (pData->RawSize < sizeof(IMAGE_DOS_HEADER) || pData->RawSize > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(0, "In-memory payload size out of range: %08X\n", pData->RawSize);

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	InjectionGateGuard injection_guard;
	if (!injection_guard)
	{
		LOG(0, "Different operation in progress. Wait for the other operation to finish first.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	ResetHijackStats();
	ResetMapStats();
	ResetThreadExecStats();

	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;

	DWORD RetVal = INJ_ERR_SUCCESS;

	INJECTIONDATA_INTERNAL Data(pData);

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving imports failed: %08X\n", RetVal);

		error_data = import_handler_error_data;

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	pData->Mode = INJECTION_MODE::IM_ManualMap;
	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;
	Data.Mode = INJECTION_MODE::IM_ManualMap;
	Data.Flags |= INJ_MM_MAP_FROM_MEMORY;

	if (Data.Method != LAUNCH_METHOD::LM_HijackThread)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Only thread acquisition is supported in this build\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_INJ_METHOD, error_data);
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid process identifier specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	if (Data.Flags & INJ_HANDLE_HIJACKING)
	{

		access_mask |= PROCESS_DUP_HANDLE;
	}
	UniqueHandle hTargetProc;
	const DWORD OpenRet = OpenTargetProcess(Data.ProcessID, access_mask, Data.Flags, Data.hHandleValue, hTargetProc, error_data);
	if (OpenRet != INJ_ERR_SUCCESS)
	{

		if (error_data.AdvErrorCode == INJ_ERR_ADVANCED_NOT_DEFINED)
		{
			INIT_ERROR_DATA(error_data, GetLastError());
		}

		LOG(0, "OpenTargetProcess failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, OpenRet, error_data);
	}

	DWORD handle_info = 0;
	if (!GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid process handle: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached to target process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	DWORD size_inout = sizeof(szExePath) / sizeof(szExePath[0]);
	if (!QueryFullProcessImageNameW(hTargetProc, NULL, szExePath, &size_inout))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "QueryFullProcessImageNameW failed: %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::wstring::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed to extract exe name from path\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target process name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating specified file\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	DWORD wow_error = ERROR_SUCCESS;
	bool native_target = true;
	native_target = IsNativeProcess(hTargetProc, &wow_error);
	if (!native_target)
	{
		INIT_ERROR_DATA(error_data, wow_error != ERROR_SUCCESS ? wow_error : static_cast<DWORD>(INJ_ERR_ADVANCED_NOT_DEFINED));

		LOG(0, "32-bit targets not supported in this x64-only build\n");

		return InitErrorStruct(Data, false, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}
	FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_AMD64, Data.Flags);

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid file specified\n");

		return InitErrorStruct(Data, native_target, FileErr, error_data);
	}

	LOG(0, "File validated and prepared for load\n");

	HINSTANCE hOut = NULL;

	INJECTION_SOURCE Source;
	Source.FromMemory	= true;
	Source.RawData		= Data.RawData;
	Source.RawSize		= Data.RawSize;

	RetVal = MMAP_NATIVE::ManualMap(Source, hTargetProc, Data.Method, Data.Flags, hOut, Data.Timeout, Data.hThreadHandleValue, Data.TargetTid, error_data);

	LOG(0, "Load finished\n");

	pData->hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
	}
	catch (...)
	{
	if (pData)
	{
		pData->hDllOut = NULL;
	}

	LOG(0, "CoreExecute failed with an unhandled exception\n");

	if (pData && pData->GenerateErrorLog)
	{
		ERROR_INFO info{ };
		info.TargetProcessId			= pData->ProcessID;
		info.InjectionMode				= pData->Mode;
		info.LaunchMethod				= pData->Method;
		info.Flags						= pData->Flags;
		info.HandleValue				= pData->hHandleValue;
		info.RawData					= pData->RawData;
		info.RawSize					= pData->RawSize;

		info.ErrorCode		= INJ_ERR_UNHANDLED_EXCEPTION;
		info.AdvErrorCode	= error_data.AdvErrorCode;
		info.Line			= error_data.Line;

		ErrorLog(info);
	}

	return INJ_ERR_UNHANDLED_EXCEPTION;
	}
}

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData)
{
#pragma EXPORT_FUNCTION("CoreExecute", __FUNCDNAME__)

	return Memory_InjectBody(pData);
}

DWORD __stdcall GetSymbolState()
{
#pragma EXPORT_FUNCTION("CoreSymbolState", __FUNCDNAME__)

	try
	{
		const DWORD initialization_state = InitializeRuntime();
		if (initialization_state != INJ_ERR_SUCCESS)
		{
			return initialization_state;
		}

		if (!PollAsyncWorker(sym_ntdll_native_ret))
		{
			return INJ_ERR_SYMBOL_INIT_NOT_DONE;
		}

		DWORD sym_ret = sym_ntdll_native_ret.Result;
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			LOG(0, "Native symbol loading failed: %08X\n", sym_ret);

			return sym_ret;
		}

		LOG(0, "All symbols loaded\n");

		return SYMBOL_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Native symbol loading threw an exception\n");

		return SYMBOL_ERR_DOWNLOAD_FAILED;
	}
}

DWORD __stdcall GetImportState()
{
#pragma EXPORT_FUNCTION("CoreImportState", __FUNCDNAME__)

	try
	{
		const DWORD initialization_state = InitializeRuntime();
		if (initialization_state != INJ_ERR_SUCCESS)
		{
			return initialization_state;
		}

		if (!PollAsyncWorker(import_handler_ret))
		{
			return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
		}

		DWORD imp_ret = import_handler_ret.Result;
		if (imp_ret != INJ_ERR_SUCCESS)
		{
			LOG(0, "Import handler (native) failed: %08X\n", imp_ret);

			return imp_ret;
		}

		LOG(0, "Import handler finished\n");

		return INJ_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Import handler threw an exception\n");

		return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
	}
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA * pData)
{
	RawData				= pData->RawData;
	RawSize				= pData->RawSize;
	ProcessID			= pData->ProcessID;
	Mode				= pData->Mode;
	Method				= pData->Method;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	TargetTid			= pData->TargetTid;
	hThreadHandleValue	= pData->hThreadHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
}
