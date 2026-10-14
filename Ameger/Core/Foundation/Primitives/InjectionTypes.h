#pragma once

#include <Windows.h>

// The build has exactly one injection mode (manual map) and one launch method (thread hijack), so the
// former mode/method selectors are gone: there is no choice to make and no branch to take.

#define INJ_HANDLE_HIJACKING			0x0040

inline constexpr DWORD INJ_THREAD_HIJACK_ACCESS =
	THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
	THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION;

enum class HijackSource : DWORD
{
	Direct = 0,
	Scan = 1,
	Sponsor = 2
};

struct HijackStats
{

	DWORD Attempted = 0;
	DWORD Success = 0;
	DWORD Source = static_cast<DWORD>(HijackSource::Direct);
	DWORD FailCode = 0;

	DWORD DonorPid = 0;
	DWORD DonorHandle = 0;
	DWORD NewHandle = 0;
	DWORD GrantedAccess = 0;

	DWORD TotalHandles = 0;
	DWORD Examined = 0;
	DWORD DupDenied = 0;
	DWORD VerifyRejected = 0;
	DWORD OwnersOpened = 0;
	DWORD Calibrated = 0;
	DWORD SnapStatus = 0;
	DWORD BudgetSkipped = 0;

	DWORD SponsorValidated = 0;
	DWORD SponsorProbed = 0;
};

static_assert(sizeof(HijackStats) == 72);

struct THREAD_EXEC_STATS
{
	DWORD Attempted = 0;
	DWORD Success = 0;
	DWORD HijackedTid = 0;
	DWORD FailCode = 0;
	DWORD DonorRounds = 0;
};

static_assert(sizeof(THREAD_EXEC_STATS) == 20);

struct MAP_STATS
{
	DWORD CleanedMask = 0;
	DWORD ImportSize = 0;
	DWORD DelayImportSize = 0;
	DWORD DebugSize = 0;
	DWORD RelocSize = 0;
	DWORD TlsSize = 0;
	DWORD ExportSize = 0;
	DWORD Verified = 0;
	DWORD ResidualMask = 0;
	// PE-header erasure telemetry, written by MMI_CloakHeader. HeaderWipeSize is the true number of
	// header bytes zeroed (DOS stub + NT headers + section table, clamped to the image); it is not
	// the declared SizeOfHeaders. HeaderWipeProtect is the final page protection applied to the
	// wiped span. Both are surfaced by the launcher's "Erase PE header" verification step.
	DWORD HeaderWipeSize = 0;
	DWORD HeaderWipeProtect = 0;
};

static_assert(sizeof(MAP_STATS) == 44);

struct STRING_STATS
{
	DWORD SymbolsDeclared = 0;
	DWORD SymbolsResolved = 0;
	DWORD HookNamesBuilt = 0;
	DWORD TiersTotal = 0;
	DWORD TiersPassed = 0;
	DWORD Reported = 0;
	DWORD Reserved = 0;
};

static_assert(sizeof(STRING_STATS) == 28);
