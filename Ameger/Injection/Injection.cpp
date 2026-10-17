#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Injection.h"
#include "Injection/ManualMapping/ManualMappingCore.h"
#include "System/Handle/HandleHijack.h"
#include "Native/Syscall.h"
DWORD __stdcall InitializeRuntime();

namespace
{

	DWORD OpenTargetProcess(DWORD pid, DWORD access_mask, DWORD flags, ULONG_PTR sponsor_value, UniqueHandle & out, ERROR_DATA & error_data)
	{
		out.reset();

		if (flags & INJ_HANDLE_HIJACKING)
		{
			HijackStats stats{ };
			stats.Attempted = 1;
			stats.Source = static_cast<DWORD>(HijackSource::Scan);

			HANDLE validated_sponsor_owner = nullptr;

			if (sponsor_value)
			{
				HANDLE sponsor = ReCa<HANDLE>(sponsor_value);
				if (ValidateProcessDonorHandle(sponsor, pid, access_mask))
				{
					validated_sponsor_owner = sponsor;
					stats.SponsorValidated = 1;
					stats.DonorHandle = PtrToUlong(sponsor);
					HANDLE duplicated = nullptr;
					bool duplicate_ok = NT_SUCCESS(ScNtDuplicateObject(GetCurrentProcess(), sponsor, GetCurrentProcess(),
						&duplicated, access_mask, FALSE, 0)) && duplicated && ValidateProcessDonorHandle(duplicated, pid, access_mask);
					const bool roundtrip_ok = duplicate_ok &&
						((flags & INJ_SKIP_SPONSOR_ROUNDTRIP) != 0 || ProbeMemoryRoundtrip(duplicated));
					if (duplicate_ok && roundtrip_ok)
					{
						out.reset(duplicated);
						stats.Success = 1;
						stats.Source = static_cast<DWORD>(HijackSource::Sponsor);
						stats.DonorPid = GetCurrentProcessId();
						stats.GrantedAccess = access_mask;
						stats.NewHandle = PtrToUlong(duplicated);
						stats.SponsorProbed = (flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 1;
						stats.ProbeMethod = (flags & INJ_SKIP_SPONSOR_ROUNDTRIP) ? 0 : 3;
						stats.FailCode = INJ_ERR_SUCCESS;
						RecordHijackOutcome(stats, false);
						LOG(0, "Acquired Target Process Handle From Sponsor\n");

						return INJ_ERR_SUCCESS;
					}

					if (duplicated)
					{
						CloseHandle(duplicated);
					}
				}

				LOG(0, "Sponsor Handle Failed Validation\n");
			}

			if (!(flags & INJ_NO_DONOR_SCAN))
			{
				HANDLE hijacked = nullptr;
				const DWORD saved_sponsor_validated = stats.SponsorValidated;
				const DWORD saved_sponsor_probed = stats.SponsorProbed;
				const DWORD saved_donor_handle = stats.DonorHandle;

				const DWORD hijack_ret = HijackProcessHandle(pid, access_mask, hijacked, &stats,
					validated_sponsor_owner);
				stats.SponsorValidated = saved_sponsor_validated;
				stats.SponsorProbed = saved_sponsor_probed;
				if (stats.Success == 0)
				{
					stats.DonorHandle = saved_donor_handle;
				}
				if (hijack_ret == INJ_ERR_SUCCESS && hijacked)
				{
					out.reset(hijacked);
					RecordHijackOutcome(stats, false);
					LOG(0, "Acquired Target Process Handle Via Acquisition\n");

					return INJ_ERR_SUCCESS;
				}

				LOG(0, "Handle Acquisition Found No Donor = %08X\n", hijack_ret);
				stats.FailCode = hijack_ret;
			}
			else if (stats.FailCode == INJ_ERR_SUCCESS)
			{
				stats.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			stats.Source = static_cast<DWORD>(HijackSource::Scan);
			RecordHijackOutcome(stats, false);

			if (!AllowDirectHandleFallback())
			{
				LOG(0, "Handle Acquisition Found No Donor; Refusing (No Direct Fallback)\n");
				INIT_ERROR_DATA(error_data, stats.FailCode ? stats.FailCode : static_cast<DWORD>(INJ_ERR_HANDLE_HIJACK_FAILED));
				return INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			LOG(0, "Handle Acquisition Found No Donor; Direct Fallback Enabled By INJ_ALLOW_DIRECT_FALLBACK\n");
		}

		out.reset(ScOpenProcess(pid, access_mask));
		if (!out)
		{
			INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);
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
		info.Flags						= Data.Flags;
		info.HandleValue				= Data.hHandleValue;
		info.bNative					= Native;
		info.RawData					= Data.RawData;
		info.RawSize					= Data.RawSize;

		info.ErrorCode		= ErrorCode;
		info.AdvErrorCode	= NormalizeAdvError(error_data.AdvErrorCode);
		info.Line			= error_data.Line;

		ErrorLog(info);
	}

	return ErrorCode;
}

static DWORD Memory_InjectBody(MEMORY_INJECTIONDATA * pData)
{
	// The export name is hoisted out of the macro argument list: nesting one function-like macro
	// inside another's argument list is fragile to preprocess, and the decrypted buffer has to
	// outlive the call anyway. tag.get() must stay the FORMAT argument, otherwise its own %p
	// would never be interpreted.
	{
		auto tag = XOR_STR_A("CoreExecute Called With pData = %p\n");
		LOG(0, tag.get(), pData);
	}

	if (!pData)
	{
		LOG(0, "pData Is Invalid\n");

		return INJ_ERR_NO_DATA;
	}

	ERROR_DATA error_data{ };

	try
	{
	if (WaitForSingleObject(g_hRunningEvent, 0) == WAIT_OBJECT_0)
	{
		LOG(0, "Different Operation In Progress. Wait For The Other Operation To Finish First.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	if (!pData->RawData)
	{
		LOG(0, "No Raw Data\n");

		return INJ_ERR_NO_RAW_DATA;
	}

	if (pData->RawSize < sizeof(IMAGE_DOS_HEADER) || pData->RawSize > PE_IMAGE::MAX_IMAGE_SIZE)
	{
		LOG(0, "In-Memory Payload Size Out Of Range = %08X\n", pData->RawSize);

		return FILE_ERR_INVALID_FILE_SIZE;
	}

	InjectionGateGuard injection_guard;
	if (!injection_guard)
	{
		LOG(0, "Different Operation In Progress. Wait For The Other Operation To Finish First.\n");

		return INJ_ERR_ALREADY_RUNNING;
	}

	ResetHijackStats();
	ResetMapStats();
	ResetThreadExecStats();
	ResetExecTelemetry();

	// Single source of truth for INJ_MM_MAP_FROM_MEMORY: the runtime always transfers the payload
	// in-memory, so the flag is forced here and never re-derived by the caller or the mapper.
	pData->Flags |= INJ_MM_MAP_FROM_MEMORY;

	DWORD RetVal = INJ_ERR_SUCCESS;

	INJECTIONDATA_INTERNAL Data(pData);

	RetVal = GetImportState();
	if (RetVal != INJ_ERR_SUCCESS)
	{
		LOG(0, "Resolving Imports Failed = %08X\n", RetVal);

		error_data = import_handler_error_data;

		return InitErrorStruct(Data, -1, INJ_ERR_IMPORT_HANDLER_NOT_DONE, error_data);
	}

	if (!Data.ProcessID)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Invalid Process Identifier Specified\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PID, error_data);
	}

	DWORD access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
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

		LOG(0, "OpenTargetProcess Failed = %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, OpenRet, error_data);
	}

	DWORD handle_info = 0;
	if (!GetHandleInformation(hTargetProc, &handle_info))
	{
		INIT_ERROR_DATA(error_data, GetLastError());

		LOG(0, "Invalid Process Handle = %08X\n", (DWORD)error_data.AdvErrorCode);

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_PROC_HANDLE, error_data);
	}

	LOG(0, "Attached To Target Process\n");

	wchar_t szExePath[MAX_PATH * 2]{ 0 };
	if (!ScGetProcessImageName(hTargetProc, szExePath, static_cast<DWORD>(sizeof(szExePath) / sizeof(szExePath[0]))))
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Could Not Resolve The Target Image Path\n");

		return InitErrorStruct(Data, -1, INJ_ERR_CANT_GET_EXE_FILENAME, error_data);
	}

	auto ExePath	= std::wstring(szExePath);
	auto ExeNamePos = ExePath.find_last_of('\\');

	if (ExeNamePos == std::wstring::npos)
	{
		INIT_ERROR_DATA(error_data, INJ_ERR_ADVANCED_NOT_DEFINED);

		LOG(0, "Failed To Extract EXE Name From Path\n");

		return InitErrorStruct(Data, -1, INJ_ERR_INVALID_EXE_PATH, error_data);
	}

	Data.TargetProcessExeFileName = ExePath.substr(ExeNamePos + 1);

	LOG(0, "Target Process Name = %ls\n", Data.TargetProcessExeFileName.c_str());

	LOG(0, "Validating Specified File\n");

	DWORD FileErr = FILE_ERR_SUCCESS;
	DWORD wow_error = ERROR_SUCCESS;
	bool native_target = true;
	native_target = IsNativeProcess(hTargetProc, &wow_error);
	if (!native_target)
	{
		INIT_ERROR_DATA(error_data, wow_error != ERROR_SUCCESS ? wow_error : static_cast<DWORD>(INJ_ERR_ADVANCED_NOT_DEFINED));

		LOG(0, "32-Bit Targets Not Supported In This x64-Only Build\n");

		return InitErrorStruct(Data, false, INJ_ERR_PLATFORM_MISMATCH, error_data);
	}
	FileErr = ValidateDllFileInMemory(Data.RawData, Data.RawSize, IMAGE_FILE_MACHINE_AMD64, Data.Flags);

	if (FileErr != FILE_ERR_SUCCESS)
	{
		INIT_ERROR_DATA(error_data, FileErr);

		LOG(0, "Invalid File Specified\n");

		return InitErrorStruct(Data, native_target, FileErr, error_data);
	}

	LOG(0, "File Validated And Prepared For Load\n");

	HINSTANCE hOut = NULL;

	INJECTION_SOURCE Source;
	Source.FromMemory	= true;
	Source.RawData		= Data.RawData;
	Source.RawSize		= Data.RawSize;

	RetVal = MMAP_NATIVE::ManualMap(Source, hTargetProc, Data.Flags, hOut, Data.Timeout, Data.hThreadHandleValue, Data.TargetTid, error_data);

	LOG(0, "Load Finished\n");

	pData->hDllOut = hOut;

	return InitErrorStruct(Data, native_target, RetVal, error_data);
	}
	catch (...)
	{
	if (pData)
	{
		pData->hDllOut = NULL;
	}

	{
		auto tag = XOR_STR_A("CoreExecute Failed With An Unhandled Exception\n");
		LOG(0, tag.get());
	}

	if (pData && pData->GenerateErrorLog)
	{
		ERROR_INFO info{ };
		info.TargetProcessId			= pData->ProcessID;
		info.Flags						= pData->Flags;
		info.HandleValue				= pData->hHandleValue;
		info.RawData					= pData->RawData;
		info.RawSize					= pData->RawSize;

		info.ErrorCode		= INJ_ERR_UNHANDLED_EXCEPTION;
		info.AdvErrorCode	= NormalizeAdvError(error_data.AdvErrorCode);
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

		// Done is signalled before the worker has finished emitting its trailing telemetry: the
		// SYMBOL_LOADER::Initialize marker and the whole SYMBOL_PARSER RVA dump are logged after it.
		// Waiting on the thread (without consuming the handles, which GetSymbolState still polls)
		// guarantees that output lands before completion is reported to the launcher.
		WaitAsyncWorkerThread(sym_ntdll_native_ret);

		DWORD sym_ret = sym_ntdll_native_ret.Result;
		if (sym_ret != SYMBOL_ERR_SUCCESS)
		{
			LOG(0, "Native Symbol Loading Failed = %08X\n", sym_ret);

			return sym_ret;
		}

		LOG(0, "All Symbols Loaded\n");

		return SYMBOL_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Native Symbol Loading Threw An Exception\n");

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

		// Same ordering guarantee as the symbol worker above.
		WaitAsyncWorkerThread(import_handler_ret);

		DWORD imp_ret = import_handler_ret.Result;
		if (imp_ret != INJ_ERR_SUCCESS)
		{
			LOG(0, "Import Handler (Native) Failed = %08X\n", imp_ret);

			return imp_ret;
		}

		LOG(0, "Import Handler Finished\n");

		return INJ_ERR_SUCCESS;
	}
	catch (...)
	{
		LOG(0, "Import Handler Threw An Exception\n");

		return INJ_ERR_IMPORT_HANDLER_NOT_DONE;
	}
}

INJECTIONDATA_INTERNAL::INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA * pData)
{
	RawData				= pData->RawData;
	RawSize				= pData->RawSize;
	ProcessID			= pData->ProcessID;
	Flags				= pData->Flags;
	Timeout				= pData->Timeout;
	hHandleValue		= pData->hHandleValue;
	TargetTid			= pData->TargetTid;
	hThreadHandleValue	= pData->hThreadHandleValue;
	GenerateErrorLog	= pData->GenerateErrorLog;
	hDllOut				= NULL;
	DllPath				= pData->DllPath ? pData->DllPath : L"";
}
