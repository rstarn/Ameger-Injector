#include "Core/Utility/Header/PrecompiledHeader.h"
#include "Core/Utility/Binary/DynamicAPI.h"

#include "Core/Foundation/Error.h"

#include "System/Symbol/Loader/SymbolLoader.h"

namespace
{

	std::wstring FormatPdbGuid(const BYTE * guid_bytes)
	{
		static const wchar_t kHex[] = L"0123456789ABCDEF";

		auto HexPair = [&](BYTE b, std::wstring & out)
		{
			out += kHex[(b >> 4) & 0x0F];
			out += kHex[b & 0x0F];
		};

		std::wstring out;
		out.reserve(32);

		HexPair(guid_bytes[3], out);
		HexPair(guid_bytes[2], out);
		HexPair(guid_bytes[1], out);
		HexPair(guid_bytes[0], out);

		HexPair(guid_bytes[5], out);
		HexPair(guid_bytes[4], out);

		HexPair(guid_bytes[7], out);
		HexPair(guid_bytes[6], out);

		for (int i = 8; i < 16; ++i)
		{
			HexPair(guid_bytes[i], out);
		}

		return out;
	}

	HRESULT DownloadUrlToFile(const std::wstring & url, const std::wstring & dest,
		const std::atomic<bool> & interrupt, DownloadManager & mgr)
	{

		auto agent = XOR_STR_W(L"Windows-Update-Agent");

		dyn::WinInetTable api{};
		HMODULE module = nullptr;

		if (!dyn::LoadWinInet(api, module))
		{
			LOG(1, "SYMBOL_LOADER: WinINet unavailable (module or symbol missing)\n");

			return E_FAIL;
		}

		HRESULT result = E_FAIL;

		HINTERNET session = api.InternetOpenW(agent.get(), INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
		if (!session)
		{
			LOG(1, "SYMBOL_LOADER: InternetOpen failed: 0x%08X\n", GetLastError());

			dyn::ReleaseModule(module);

			return E_FAIL;
		}

		DWORD timeout = 60000;
		api.InternetSetOptionW(session, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
		api.InternetSetOptionW(session, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
		api.InternetSetOptionW(session, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
		api.InternetSetOptionW(session, INTERNET_OPTION_DATA_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

		HINTERNET request = api.InternetOpenUrlW(session, url.c_str(), nullptr, 0,
			INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
			0);
		if (!request)
		{
			LOG(1, "SYMBOL_LOADER: InternetOpenUrl failed: 0x%08X\n", GetLastError());

			api.InternetCloseHandle(session);

			dyn::ReleaseModule(module);

			return E_FAIL;
		}

		HANDLE file = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
		if (file == INVALID_HANDLE_VALUE)
		{
			LOG(1, "SYMBOL_LOADER: can't create PDB file: 0x%08X\n", GetLastError());
		}
		else
		{
			BYTE buffer[0x8000];
			for (;;)
			{
				if (interrupt.load() || mgr.TimedOut())
				{
					result = E_ABORT;

					break;
				}

				DWORD read = 0;
				if (!api.InternetReadFile(request, buffer, sizeof(buffer), &read))
				{
					LOG(1, "SYMBOL_LOADER: InternetReadFile failed: 0x%08X\n", GetLastError());

					break;
				}
				if (!read)
				{

					result = S_OK;

					break;
				}

				DWORD written = 0;
				if (!WriteFile(file, buffer, read, &written, nullptr) || written != read)
				{
					LOG(1, "SYMBOL_LOADER: write failed: 0x%08X\n", GetLastError());

					break;
				}

				mgr.TouchDeadline();
			}

			CloseHandle(file);
		}

		api.InternetCloseHandle(request);
		api.InternetCloseHandle(session);

		dyn::ReleaseModule(module);

		return result;
	}
}

SYMBOL_LOADER::SYMBOL_LOADER()
{
	m_hInterruptEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

SYMBOL_LOADER::~SYMBOL_LOADER()
{
	Cleanup();

	if (m_hInterruptEvent)
	{
		CloseHandle(m_hInterruptEvent);
	}
}

bool SYMBOL_LOADER::VerifyExistingPdb(const GUID & guid, DWORD age)
{
	LOG(2, "SYMBOL_LOADER::VerifyExistingPdb called\n");

	std::ifstream f(m_szPdbPath.c_str(), std::ios::binary | std::ios::ate);
	if (!f.is_open())
	{
		LOG(2, "SYMBOL_LOADER: failed to open PDB for verification\n");

		return false;
	}

	const auto file_size = f.tellg();
	if (file_size <= 0)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: invaild file size\n");

		return false;
	}

	size_t size_on_disk = static_cast<size_t>(file_size);
	if (!size_on_disk)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: invaild file size\n");

		return false;
	}

	char * pdb_raw = new(std::nothrow) char[size_on_disk];
	if (!pdb_raw)
	{
		f.close();

		LOG(2, "SYMBOL_LOADER: failed to allocate memory\n");

		return false;
	}

	f.seekg(0, std::ios::beg);
	if (!f.read(pdb_raw, static_cast<std::streamsize>(size_on_disk)) || f.gcount() != static_cast<std::streamsize>(size_on_disk))
	{
		delete[] pdb_raw;
		f.close();

		LOG(2, "SYMBOL_LOADER: failed to read PDB\n");

		return false;
	}
	f.close();

	LOG(2, "SYMBOL_LOADER: PDB loaded into memory\n");

	if (size_on_disk < sizeof(PDBHeader7))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: raw size smaller than PDBHeader7\n");

		return false;
	}

	auto * pPDBHeader = ReCa<PDBHeader7*>(pdb_raw);

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB signature mismatch\n");

		return false;
	}

	if (pPDBHeader->page_size <= 0 || pPDBHeader->file_page_count <= 0 || pPDBHeader->root_stream_page_number_list_number < 0)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB page metadata\n");

		return false;
	}

	const size_t page_size = static_cast<size_t>(pPDBHeader->page_size);
	if (static_cast<size_t>(pPDBHeader->file_page_count) > SIZE_MAX / page_size ||
		size_on_disk < static_cast<size_t>(pPDBHeader->file_page_count) * page_size)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB size smaller than page_size * page_count\n");

		return false;
	}

	const size_t root_page_list_offset = static_cast<size_t>(pPDBHeader->root_stream_page_number_list_number) * page_size;
	if (root_page_list_offset > size_on_disk - sizeof(int))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root page list\n");

		return false;
	}

	int root_page_number = *ReCa<int *>(pdb_raw + root_page_list_offset);
	if (root_page_number < 0 || root_page_number >= pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root page number\n");

		return false;
	}

	const size_t root_stream_offset = static_cast<size_t>(root_page_number) * page_size;
	if (root_stream_offset > size_on_disk - sizeof(RootStream7))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream offset\n");

		return false;
	}

	auto	* pRootStream		= ReCa<RootStream7 *>(pdb_raw + root_stream_offset);

	if (pRootStream->num_streams <= 0)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream\n");

		return false;
	}

	const size_t stream_header_bytes = sizeof(int) + static_cast<size_t>(pRootStream->num_streams) * sizeof(int);
	if (stream_header_bytes > size_on_disk - root_stream_offset)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid root stream\n");

		return false;
	}

	const size_t available_page_numbers = (size_on_disk - root_stream_offset - stream_header_bytes) / sizeof(int);
	size_t total_page_numbers = 0;

	for (int i = 0; i != pRootStream->num_streams; ++i)
	{
		const int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
		if (current_size < 0)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid stream size\n");

			return false;
		}

		total_page_numbers += static_cast<size_t>(current_size) / page_size + (static_cast<size_t>(current_size) % page_size ? 1 : 0);
		if (total_page_numbers > available_page_numbers)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid root stream page list\n");

			return false;
		}
	}

	std::map<int, std::vector<int>> streams;
	int current_page_number = 0;

	for (int i = 0; i != pRootStream->num_streams; ++i)
	{
		int current_size = pRootStream->stream_sizes[i] == 0xFFFFFFFF ? 0 : pRootStream->stream_sizes[i];
		if (current_size < 0)
		{
			delete[] pdb_raw;

			LOG(2, "SYMBOL_LOADER: invalid stream size\n");

			return false;
		}

		int current_page_count = current_size / pPDBHeader->page_size;
		if (current_size % pPDBHeader->page_size)
		{
			++current_page_count;
		}

		std::vector<int> numbers;

		for (int j = 0; j != current_page_count; ++j, ++current_page_number)
		{
			const int page_number = pRootStream->stream_sizes[pRootStream->num_streams + current_page_number];
			if (page_number < 0 || page_number >= pPDBHeader->file_page_count)
			{
				delete[] pdb_raw;

				LOG(2, "SYMBOL_LOADER: invalid stream page\n");

				return false;
			}

			numbers.push_back(page_number);
		}

		streams.insert({ i, numbers });
	}

	LOG(2, "SYMBOL_LOADER: PDB size parsed\n");

	const auto pdb_information_stream = streams.find(1);
	if (pdb_information_stream == streams.end() || pdb_information_stream->second.empty())
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: PDB information stream missing\n");

		return false;
	}

	auto pdbInformation_page_index = pdb_information_stream->second.front();
	if (pdbInformation_page_index < 0 || pdbInformation_page_index >= pPDBHeader->file_page_count)
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB information page\n");

		return false;
	}

	const size_t stream_data_offset = static_cast<size_t>(pdbInformation_page_index) * page_size;
	if (stream_data_offset > size_on_disk - sizeof(GUID_StreamData))
	{
		delete[] pdb_raw;

		LOG(2, "SYMBOL_LOADER: invalid PDB information stream\n");

		return false;
	}

	auto * stream_data = ReCa<GUID_StreamData *>(pdb_raw + stream_data_offset);

	int guid_eq = memcmp(&stream_data->guid, &guid, sizeof(GUID));
	const int stream_age = stream_data->age;
	const bool age_eq = stream_age >= 0 && static_cast<DWORD>(stream_age) == age;

	delete[] pdb_raw;

	auto ret = (guid_eq == 0);

	if (guid_eq != 0)
	{
		LOG(2, "SYMBOL_LOADER: guid mismatch\n");
	}
	else if (!age_eq)
	{
		LOG(2, "SYMBOL_LOADER: PDB age %d differs from module age %u; proceeding on GUID match\n", stream_age, age);
	}
	else
	{
		LOG(2, "SYMBOL_LOADER: guid match\n");
	}

	return ret;
}

DWORD SYMBOL_LOADER::Initialize(const std::wstring & szModulePath, const std::wstring & path, bool Redownload, bool AutoDownload)
{
	Cleanup();

	if (AutoDownload)
	{
		m_bStartDownload = true;
	}

	LOG(1, "SYMBOL_LOADER::Initialize called in thread %08lX (%lu)\n", GetCurrentThreadId(), GetCurrentThreadId());

	std::ifstream File(szModulePath.c_str(), std::ios::binary | std::ios::ate);
	if (!File.good())
	{
		LOG(1, "SYMBOL_LOADER: can't open module path\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}

	auto FileSize = File.tellg();
	if (FileSize <= 0)
	{
		LOG(1, "SYMBOL_LOADER: invalid file size\n");

		return SYMBOL_ERR_FILE_SIZE_IS_NULL;
	}

	BYTE * pRawData = new(std::nothrow) BYTE[static_cast<size_t>(FileSize)];
	if (!pRawData)
	{
		File.close();

		LOG(1, "SYMBOL_LOADER: can't allocate memory\n");

		return SYMBOL_ERR_CANT_ALLOC_MEMORY_NEW;
	}

	File.seekg(0, std::ios::beg);
	File.read(ReCa<char *>(pRawData), FileSize);
	if (!File || File.gcount() != FileSize)
	{
		delete[] pRawData;
		File.close();

		LOG(1, "SYMBOL_LOADER: short read of module file\n");

		return SYMBOL_ERR_CANT_OPEN_MODULE;
	}
	File.close();

	LOG(1, "SYMBOL_LOADER: ready to parse PE headers\n");

	PE_IMAGE::OPTIONS module_options;
	module_options.EnableExceptions = true;
	PE_IMAGE::VIEW module_view;
	const DWORD validation_result = PE_IMAGE::Validate(pRawData, static_cast<size_t>(FileSize), IMAGE_FILE_MACHINE_AMD64, module_options, module_view);
	if (validation_result != FILE_ERR_SUCCESS)
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid module layout: %08X\n", validation_result);

		return SYMBOL_ERR_INVALID_FILE_ARCHITECTURE;
	}

	IMAGE_DOS_HEADER * pDos = ReCa<IMAGE_DOS_HEADER *>(pRawData);
	IMAGE_NT_HEADERS * pNT = ReCa<IMAGE_NT_HEADERS *>(pRawData + pDos->e_lfanew);
	IMAGE_FILE_HEADER * pFile = &pNT->FileHeader;

	IMAGE_OPTIONAL_HEADER64 * pOpt64 = ReCa<IMAGE_OPTIONAL_HEADER64 *>(&pNT->OptionalHeader);

	LOG(1, "SYMBOL_LOADER: x64 target identified\n");

	DWORD ImageSize = pOpt64->SizeOfImage;

	BYTE * pLocalImageBase = ReCa<BYTE *>(VirtualAlloc(nullptr, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pLocalImageBase)
	{
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: can't allocate memory: 0x%08X\n", GetLastError());

		return SYMBOL_ERR_CANT_ALLOC_MEMORY;
	}

	memcpy(pLocalImageBase, pRawData, pOpt64->SizeOfHeaders);

	auto * pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pRawData + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}

	LOG(1, "SYMBOL_LOADER: sections mapped\n");

	IMAGE_DATA_DIRECTORY * pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	const bool debug_dir_in_image =
		pDataDir->VirtualAddress <= pOpt64->SizeOfImage &&
		sizeof(IMAGE_DEBUG_DIRECTORY) <= pOpt64->SizeOfImage - pDataDir->VirtualAddress;

	IMAGE_DEBUG_DIRECTORY * pDebugDir = ReCa<IMAGE_DEBUG_DIRECTORY *>(pLocalImageBase + pDataDir->VirtualAddress);

	if (!debug_dir_in_image || !pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: no PDB debug data\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	const DWORD codeview_offset = pDebugDir->AddressOfRawData;
	const DWORD codeview_size	= pDebugDir->SizeOfData;
	const bool codeview_record_ok =
		codeview_size != 0 &&
		codeview_offset <= pOpt64->SizeOfImage &&
		codeview_size <= pOpt64->SizeOfImage - codeview_offset;

	if (!codeview_record_ok)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: CodeView record outside the mapped image\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	PdbInformation * pdbInformation = ReCa<PdbInformation *>(pLocalImageBase + pDebugDir->AddressOfRawData);
	if (pdbInformation->Signature != 0x53445352)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: invalid PDB signature\n");

		return SYMBOL_ERR_NO_PDB_DEBUG_DATA;
	}

	m_szPdbPath = path;
	if (m_szPdbPath.empty())
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: empty download path\n");

		return SYMBOL_ERR_PATH_DOESNT_EXIST;
	}

	if (m_szPdbPath[m_szPdbPath.length() - 1] != '\\')
	{
		m_szPdbPath += '\\';
	}

	m_szRootPath = m_szPdbPath;

	LOG(1, "SYMBOL_LOADER: PDB signature identified\n");

	if (!CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
			delete[] pRawData;

			return SYMBOL_ERR_PATH_DOESNT_EXIST;
		}
	}

	m_szPdbPath += XOR_STR_W(L"Symbols\\").get();

	m_szPdbDir = m_szPdbPath;
	m_bCreatedPdbDir = false;
	if (CreateDirectoryW(m_szPdbPath.c_str(), nullptr))
	{
		m_bCreatedPdbDir = true;
	}
	else if (GetLastError() != ERROR_ALREADY_EXISTS)
	{
		LOG(1, "SYMBOL_LOADER: can't create/open download path: 0x%08X\n", GetLastError());

		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		return SYMBOL_ERR_CANT_CREATE_DIRECTORY;
	}

	const size_t pdb_name_offset = offsetof(PdbInformation, PdbFileName);
	const bool record_bounded = pDebugDir->SizeOfData > pdb_name_offset
		&& pDebugDir->AddressOfRawData <= pOpt64->SizeOfImage
		&& pdb_name_offset <= pOpt64->SizeOfImage - pDebugDir->AddressOfRawData;

	size_t pdb_name_capacity = 0;
	if (record_bounded)
	{
		pdb_name_capacity = pDebugDir->SizeOfData - pdb_name_offset;
		const size_t image_remaining = pOpt64->SizeOfImage - pDebugDir->AddressOfRawData - pdb_name_offset;
		if (pdb_name_capacity > image_remaining)
		{
			pdb_name_capacity = image_remaining;
		}
	}

	auto PdbFileName = (record_bounded && memchr(pdbInformation->PdbFileName, '\0', pdb_name_capacity) != nullptr)
		? CharArrayToStdWstring(pdbInformation->PdbFileName)
		: std::wstring();
	if (PdbFileName.empty() || PdbFileName.size() > 64 ||
		PdbFileName.find_first_of(L"\\/") != std::wstring::npos ||
		PdbFileName.find(L"..") != std::wstring::npos ||
		PdbFileName.find(L':') != std::wstring::npos)
	{
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		delete[] pRawData;

		LOG(1, "SYMBOL_LOADER: unsafe PDB file name\n");

		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}

	m_szPdbPath += PdbFileName;

	LOG(1, "SYMBOL_LOADER: PDB path = %ls\n", m_szPdbPath.c_str());

	m_Filesize = 0;
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
	{
		m_Filesize = file_attr_data.nFileSizeLow;

		if (!Redownload && !VerifyExistingPdb(pdbInformation->Guid, pdbInformation->Age))
		{
			LOG(1, "SYMBOL_LOADER: verification failed, PDB will be redownloaded\n");

			Redownload = true;
		}

		if (Redownload)
		{
			DeleteFileW(m_szPdbPath.c_str());
		}
	}
	else
	{
		LOG(1, "SYMBOL_LOADER: file doesn't exist, PDB will be downloaded\n");

		Redownload = true;
	}

	if (Redownload)
	{

		const std::wstring guid_filtered = FormatPdbGuid(ReCa<const BYTE *>(&pdbInformation->Guid));

		if (guid_filtered.size() != 32)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to parse GUID");

			return SYMBOL_ERR_CANT_CONVERT_PDB_GUID;
		}

		LOG(1, "SYMBOL_LOADER: PDB GUID resolved (%zu chars, value redacted)\n", guid_filtered.size());

		std::wstring url = KC_WSTR_LAYERED(L"https://msdl.microsoft.com/download/symbols/").c_str();
		url += PdbFileName;
		url += '/';
		url += guid_filtered;
		url += std::to_wstring(pdbInformation->Age);
		url += '/';
		url += PdbFileName;

		LOG(1, "SYMBOL_LOADER: fetching %ls (%lu bytes URL, GUID/age redacted)\n",
			PdbFileName.c_str(), static_cast<unsigned long>(url.size()));

		if (!m_bStartDownload)
		{
			LOG(1, "SYMBOL_LOADER: waiting for download start\n");
		}

		while (!m_bStartDownload && !m_bInterruptEvent)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		if (m_bInterruptEvent)
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: download interrupted\n");

			return SYMBOL_ERR_INTERRUPT;
		}

		LOG(1, "SYMBOL_LOADER: downloading PDB\n");

		constexpr DWORD kDownloadInactivityTimeoutMs = 60000;
		if (!m_DlMgr.SetTimeout(kDownloadInactivityTimeoutMs))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to arm download timeout\n");

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		HRESULT dl_hr = E_FAIL;
		bool dl_aborted = false;
		for (int attempt = 1; attempt <= 3; ++attempt)
		{
			if (m_DlMgr.TimedOut())
			{
				dl_aborted = true;
				break;
			}

			DeleteFileW(m_szPdbPath.c_str());

			dl_hr = DownloadUrlToFile(url, m_szPdbPath, m_bInterruptEvent, m_DlMgr);
			if (SUCCEEDED(dl_hr))
			{
				break;
			}
			LOG(1, "SYMBOL_LOADER: download attempt %d/3 failed: 0x%08X\n", attempt, dl_hr);
			if (dl_hr == E_ABORT || m_bInterruptEvent || m_DlMgr.TimedOut())
			{
				dl_aborted = true;
				break;
			}
			if (attempt < 3)
			{
				for (int waited = 0; waited < 100; ++waited)
				{
					if (m_bInterruptEvent || m_DlMgr.TimedOut())
					{
						dl_aborted = true;
						break;
					}
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				if (dl_aborted)
				{
					break;
				}
			}
		}

		const bool dl_timed_out = m_DlMgr.TimedOut();

		m_DlMgr.StopTimeout();

		if (FAILED(dl_hr))
		{

			DeleteFileW(m_szPdbPath.c_str());

			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			LOG(1, "SYMBOL_LOADER: failed to download file: 0x%08X\n", dl_hr);

			if (dl_timed_out)
			{
				LOG(1, "SYMBOL_LOADER: PDB download timed out\n");

				return SYMBOL_ERR_DOWNLOAD_FAILED;
			}

			return (dl_hr == E_ABORT || dl_aborted) ? SYMBOL_ERR_INTERRUPT : SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		LOG(1, "SYMBOL_LOADER: download finished\n");

		if (!VerifyExistingPdb(pdbInformation->Guid, pdbInformation->Age))
		{
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

			delete[] pRawData;

			DeleteFileW(m_szPdbPath.c_str());

			LOG(1, "SYMBOL_LOADER: downloaded PDB failed verification\n");

			return SYMBOL_ERR_DOWNLOAD_FAILED;
		}

		m_Filesize = 0;
	}

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);

	delete[] pRawData;

	LOG(1, "SYMBOL_LOADER: PDB verified\n");

	if (Redownload || !m_Filesize)
	{
		if (!GetFileAttributesExW(m_szPdbPath.c_str(), GetFileExInfoStandard, &file_attr_data))
		{
			LOG(1, "SYMBOL_LOADER: can't access PDB file: 0x%08X\n", GetLastError());

			DeleteFileW(m_szPdbPath.c_str());

			return SYMBOL_ERR_CANT_ACCESS_PDB_FILE;
		}

		m_Filesize = file_attr_data.nFileSizeLow;
	}

	m_hPdbFile = CreateFileW(m_szPdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (m_hPdbFile == INVALID_HANDLE_VALUE)
	{
		m_hPdbFile = nullptr;

		LOG(1, "SYMBOL_LOADER: can't open PDB file: 0x%08X\n", GetLastError());

		DeleteFileW(m_szPdbPath.c_str());

		return SYMBOL_ERR_CANT_OPEN_PDB_FILE;
	}

	m_bReady = true;

	return SYMBOL_ERR_SUCCESS;
}

void SYMBOL_LOADER::Cleanup()
{
	LOG(1, "SYMBOL_LOADER::Cleanup\n");

	m_bReady = false;

	if (m_hPdbFile && m_hPdbFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hPdbFile);
	}

	m_hPdbFile = nullptr;
}

void SYMBOL_LOADER::PurgePdb()
{
	if (m_szPdbPath.empty())
	{
		return;
	}

	const DWORD attributes = GetFileAttributesW(m_szPdbPath.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		return;
	}

	if (m_hPdbFile)
	{
		Cleanup();
	}

	if (!DeleteFileW(m_szPdbPath.c_str()))
	{
		LOG(1, "SYMBOL_LOADER: failed to purge cached PDB: 0x%08X\n", GetLastError());
		return;
	}

	LOG(1, "SYMBOL_LOADER: cached PDB purged from disk\n");
	m_Filesize = 0;

	if (m_bCreatedPdbDir && !m_szPdbDir.empty())
	{
		RemoveDirectoryW(m_szPdbDir.c_str());
		m_bCreatedPdbDir = false;
	}

	if (!m_szRootPath.empty())
	{
		DeleteSymbolCacheRoot(m_szRootPath);
		m_szRootPath.clear();
	}
}

void SYMBOL_LOADER::SetDownload(bool bDownload)
{
	m_bStartDownload = bDownload;
}

void SYMBOL_LOADER::Interrupt()
{
	LOG(1, "SYMBOL_LOADER::Interrupt\n");

	m_bInterruptEvent = true;

	if (m_hInterruptEvent)
	{
		if (!SetEvent(m_hInterruptEvent))
		{
			LOG(1, "SYMBOL_LOADER: SetEvent failed to trigger interrupt event: %08X\n", GetLastError());
		}
		else
		{
			LOG(1, "SYMBOL_LOADER: interrupt event set\n");
		}
	}
	else
	{
		LOG(1, "SYMBOL_LOADER: no interrupt event specified\n");
	}

}

const std::wstring & SYMBOL_LOADER::GetFilepath() const
{
	return m_szPdbPath;
}

DWORD SYMBOL_LOADER::GetFilesize() const
{
	return m_Filesize;
}

bool SYMBOL_LOADER::IsReady() const
{
	return m_bReady;
}
