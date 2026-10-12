#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Utility/Binary/DynamicAPI.h"

#include "System/Symbol/Loader/SymbolLoader.h"

// DbgHelp-backed PDB reader for symbols, types, and enums.
// What: binds the downloaded PDB to a fake process handle, then answers
//   address/type/offset queries for DynamicOffsets. Why: the only source of
//   version-correct LDR/TEB/KUSER layouts. How: Initialize once per PDB,
//   query via Get* (all fail-closed), Cleanup on shutdown. Non-copyable.
// Stealth: DbgHelp is never statically imported. m_Api/m_Module are resolved
// by name on each Initialize and released on Cleanup, so the shipped PE's
// import table never names dbghelp.dll and the module list carries it only
// while a PDB is actually open.
class SYMBOL_PARSER
{
	dyn::DbgHelpTable	m_Api{};
	HMODULE				m_Module		= nullptr;
	HANDLE				m_hProcess		= NULL;
	bool				m_bInitialized	= false;
	bool				m_bReady			= false;
	DWORD64				m_SymbolTable		= 0;

	SYMBOL_PARSER(const SYMBOL_PARSER &) = delete;
	SYMBOL_PARSER & operator=(const SYMBOL_PARSER &) = delete;

public:

	SYMBOL_PARSER();
	~SYMBOL_PARSER();

	// Binds the parser to a ready loader's PDB. Params: pSymbolObject (in,
	// must be IsReady). Returns: SYMBOL_* code. Must precede any Get* query.
	DWORD Initialize(const SYMBOL_LOADER * pSymbolObject);
	// Releases the DbgHelp session. Safe to call twice; pairs with Cleanup()
	// of the loader on shutdown.
	void Cleanup();

	// Resolves a symbol's RVA. Params: szSymbolName (in, e.g. loader export),
	// RvaOut (out). Returns: SYMBOL_* code; fails closed on unknown names.
	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);

	// PDB type queries: every Windows struct offset is resolved from the
	// downloaded ntdll.pdb instead of a hardcoded constant. All three are
	// fail-closed (non-zero SYMBOL_ERR_* when the type/field is absent).
	DWORD GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut);
	DWORD GetTypeSize(const char * szTypeName, ULONG64 & SizeOut);
	DWORD GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut);
	// Try several PDB spellings in order (e.g. "TEB", "_TEB"); first hit wins.
	DWORD GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut);
	DWORD GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut);
	// Enum constant (e.g. _KTHREAD_STATE::Running). Tries each type spelling.
	DWORD GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut);
};

inline SYMBOL_PARSER sym_parser;