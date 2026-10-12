#pragma once

#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Utility/Binary/DynamicAPI.h"

#include "System/Symbol/Loader/SymbolLoader.h"

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

	DWORD Initialize(const SYMBOL_LOADER * pSymbolObject);

	void Cleanup();

	DWORD GetSymbolAddress(const char * szSymbolName, DWORD & RvaOut);

	DWORD GetTypeId(const char * szTypeName, DWORD64 & TypeIdOut);
	DWORD GetTypeSize(const char * szTypeName, ULONG64 & SizeOut);
	DWORD GetFieldOffset(const char * szTypeName, const char * szFieldName, DWORD & OffsetOut);

	DWORD GetFieldOffsetAny(const char * const * TypeNames, size_t TypeCount, const char * szFieldName, DWORD & OffsetOut);
	DWORD GetTypeSizeAny(const char * const * TypeNames, size_t TypeCount, ULONG64 & SizeOut);

	DWORD GetEnumValueAny(const char * const * TypeNames, size_t TypeCount, const char * szConstantName, DWORD & ValueOut);
};

inline SYMBOL_PARSER sym_parser;
