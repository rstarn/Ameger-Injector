#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"

struct DYNAMIC_NT_OFFSETS
{
	DWORD TebSameTebFlags = 0;
	DWORD TebLastErrorValue = 0;
	// A1: the current thread's 64 TLS slot pointers, and the PEB's inline
	// 64-bit TLS bitmap. LdrpHandleTlsData sets one bit and one slot; without
	// these the registration cannot be undone after a callbacks-only TLS block
	// has been processed.
	DWORD TebTlsSlots = 0;
	DWORD PebTlsBitmapBits = 0;

	DWORD PebLdr = 0;

	DWORD KuserCookie = 0;

	DWORD LdrEntryDllBase = 0;
	DWORD LdrEntrySize = 0;
	DWORD LdrEntrySizeOfImage = 0;
	DWORD LdrEntryFullDllName = 0;
	DWORD LdrEntryBaseDllName = 0;
	DWORD LdrEntryDdagNode = 0;
	DWORD LdrDdagNodeState = 0;
	DWORD LdrDdagNodeSize = 0;

	DWORD InvertedTableCount = 0;
	DWORD InvertedTableEntries = 0;
	DWORD InvertedEntryImageBase = 0;
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
