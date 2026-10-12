#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

struct DYNAMIC_NT_OFFSETS
{
	DWORD Ready = 0;

	DWORD TebSameTebFlags = 0;
	DWORD TebLastErrorValue = 0;
	DWORD TebProcessEnvironmentBlock = 0;

	DWORD PebOsMajorVersion = 0;
	DWORD PebOsMinorVersion = 0;
	DWORD PebOsBuildNumber = 0;
	DWORD PebLdr = 0;
	DWORD PebProcessHeap = 0;
	DWORD PebLoaderLock = 0;
	DWORD PebSize = 0;

	DWORD KuserCookie = 0;

	DWORD LdrEntryDllBase = 0;
	DWORD LdrEntrySizeOfImage = 0;
	DWORD LdrEntryFullDllName = 0;
	DWORD LdrEntryDdagNode = 0;
	DWORD LdrEntrySize = 0;
	DWORD LdrDdagNodeState = 0;
	DWORD LdrDdagNodeSize = 0;

	DWORD InvertedTableCount = 0;
	DWORD InvertedTableEntries = 0;
	DWORD InvertedEntryImageBase = 0;
	DWORD InvertedEntryImageSize = 0;
	DWORD InvertedEntryExceptionDirectory = 0;
	DWORD InvertedEntryExceptionDirectorySize = 0;
	DWORD InvertedEntrySize = 0;

	DWORD TlsEntryModuleEntry = 0;
	DWORD TlsEntrySize = 0;

	DWORD SameTebFlagsLoaderWorkerMask = 0x2000;

	DWORD ThreadStateRunning = 2;

	DWORD LdrpPathSearchContextSize = 0;

	DWORD LdrpPathSearchOriginalFullDllName = 0;
};

inline DYNAMIC_NT_OFFSETS g_DynamicOffsets{};

inline std::atomic<DWORD> g_DynamicOffsetsReady{ 0 };

DWORD ResolveDynamicOffsets();
