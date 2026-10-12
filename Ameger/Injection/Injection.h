#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

// Runtime-internal injection surface (not exported ABI).
//
// The public payload structs, flag words and exported entry points live once in
// the outer header (Ameger/Injection.h) so host and runtime cannot drift; this
// header adds only what the runtime needs internally.
#include "../Injection.h"

// In-memory injection entry (CoreExecute export). The only path: the launcher
// hands over caller-owned image bytes, so nothing on disk is involved.
// Params: pData (in/out descriptor; hDllOut filled on success).
// Returns: INJ_* code.
DWORD __stdcall Memory_Inject(MEMORY_INJECTIONDATA * pData);

// Readiness gates for the async workers. Returns: SUCCESS when ready,
// NOT_DONE while workers run, or the terminal failure code.
DWORD __stdcall GetSymbolState();

DWORD __stdcall GetImportState();

// Runtime-side request shape: the memory descriptor plus the fields the runtime
// derives on the way in (payload path, target image name). One struct exists so
// the injection worker has a single code path. The converting ctor references
// the caller's image bytes rather than owning them.
// hHandleValue/hThreadHandleValue are raw handle values revalidated inside the
// runtime, never trusted blindly.
struct INJECTIONDATA_INTERNAL
{
	std::wstring	DllPath;
	std::wstring	TargetProcessExeFileName;

	BYTE *			RawData;
	DWORD			RawSize;

	DWORD			ProcessID;
	INJECTION_MODE	Mode;
	LAUNCH_METHOD	Method;
	DWORD			Flags;
	DWORD			Timeout;
	ULONG_PTR		hHandleValue;
	HINSTANCE		hDllOut;
	bool			GenerateErrorLog;
	DWORD			TargetTid;
	ULONG_PTR		hThreadHandleValue;

	INJECTIONDATA_INTERNAL(const MEMORY_INJECTIONDATA	* pData);
};
