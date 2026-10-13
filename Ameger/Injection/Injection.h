#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

#include "../Injection.h"

#include <string>

DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData);

DWORD __stdcall GetSymbolState();

DWORD __stdcall GetImportState();

struct INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	BYTE *			RawData;
	DWORD			RawSize;

	DWORD			ProcessID;
	DWORD			Flags;
	DWORD			Timeout;
	ULONG_PTR		hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
	DWORD			TargetTid;
	ULONG_PTR		hThreadHandleValue;

	INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA	* pData);
};
