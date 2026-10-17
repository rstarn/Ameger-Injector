#include "Core/Utility/Header/PrecompiledHeader.h"

#include "Native/Syscall.h"



inline bool SyscallVerbose()
{
    
    
    static const bool verbose = []() -> bool
    {
        wchar_t buffer[8] = {};
        const DWORD got = GetEnvironmentVariableW(XOR_STR_W(L"AMEGER_SYSCALL_VERBOSE").get(), buffer, 4);
        return !(got == 1 && buffer[0] == L'0');
    }();
    return verbose;
}





namespace
{
	void SilencedInvalidParameter(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t) noexcept
	{
	}
}

void SyscallLog(int level, const char * fmt, ...)
{
    if (!SyscallVerbose() && level > 0)
        return;

    if (!fmt)
        return;

    const _invalid_parameter_handler previous_handler =
        _set_thread_local_invalid_parameter_handler(SilencedInvalidParameter);

    va_list args;
    va_start(args, fmt);
    char buf[1024]{ 0 };
    const int written = vsprintf_s(buf, sizeof(buf), fmt, args);
    va_end(args);

    _set_thread_local_invalid_parameter_handler(previous_handler);

    if (written <= 0)
        return;

    f_raw_print_callback cb = g_print_raw_callback.load();
    if (cb)
    {
        cb(buf);
    }
    else
    {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        puts(buf);
    }
}




#define SC_LOG_OK(...)    SyscallLog(1, "[+] " __VA_ARGS__)
#define SC_LOG_WARN(...)  SyscallLog(1, "[!] " __VA_ARGS__)
#define SC_LOG_ERR(...)   SyscallLog(1, "[x] " __VA_ARGS__)
#define SC_LOG_INFO(...)  SyscallLog(1, "[*] " __VA_ARGS__)









namespace
{
	enum : DWORD
	{
		kServiceUnknown = 0xFFFFFFFF
	};

	struct SYSCALL_ENTRY
	{
		DWORD	NameHash	= 0;
		DWORD	Service		= kServiceUnknown;
		void *	Stub		= nullptr;
	};

	struct HARVESTED_ENTRY
	{
		DWORD	Rva			= 0;
		DWORD	Service		= 0;
	};

	
	SYSCALL_ENTRY g_SyscallTable[] =
	{
		{ SC_NtOpenProcess,					kServiceUnknown, nullptr },
		{ SC_NtOpenThread,					kServiceUnknown, nullptr },
		{ SC_NtDuplicateObject,				kServiceUnknown, nullptr },
		{ SC_NtClose,						kServiceUnknown, nullptr },
		{ SC_NtQuerySystemInformation,		kServiceUnknown, nullptr },
		{ SC_NtQueryInformationProcess,	kServiceUnknown, nullptr },
		{ SC_NtQueryInformationThread,		kServiceUnknown, nullptr },
		{ SC_NtAllocateVirtualMemory,		kServiceUnknown, nullptr },
		{ SC_NtFreeVirtualMemory,			kServiceUnknown, nullptr },
		{ SC_NtProtectVirtualMemory,		kServiceUnknown, nullptr },
		{ SC_NtCreateSection,				kServiceUnknown, nullptr },
		{ SC_NtMapViewOfSection,			kServiceUnknown, nullptr },
		{ SC_NtUnmapViewOfSection,			kServiceUnknown, nullptr },
		{ SC_NtWriteVirtualMemory,			kServiceUnknown, nullptr },
		{ SC_NtReadVirtualMemory,			kServiceUnknown, nullptr },
		{ SC_NtSuspendThread,				kServiceUnknown, nullptr },
		{ SC_NtResumeThread,				kServiceUnknown, nullptr },
		{ SC_NtGetContextThread,			kServiceUnknown, nullptr },
		{ SC_NtSetContextThread,			kServiceUnknown, nullptr },
	};

	constexpr size_t kSyscallTableCount	= sizeof(g_SyscallTable) / sizeof(g_SyscallTable[0]);
	constexpr DWORD	kStubAreaSize		= static_cast<DWORD>(kSyscallTableCount) * SC_STUB_SIZE;

	const char * kSyscallNames[kSyscallTableCount] =
	{
		"NtOpenProcess",
		"NtOpenThread",
		"NtDuplicateObject",
		"NtClose",
		"NtQuerySystemInformation",
		"NtQueryInformationProcess",
		"NtQueryInformationThread",
		"NtAllocateVirtualMemory",
		"NtFreeVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtWriteVirtualMemory",
		"NtReadVirtualMemory",
		"NtSuspendThread",
		"NtResumeThread",
		"NtGetContextThread",
		"NtSetContextThread",
	};

	struct RESOLUTION_INFO
	{
		bool Reconstructed = false;
		bool Hooked = false;
		DWORD Rva = 0;
		BYTE Prologue[4]{};
	};
	RESOLUTION_INFO g_Resolution[kSyscallTableCount]{};

	constexpr BYTE kInvalidService = 0xFF;

	constexpr BYTE kPrologueHealthy[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

	std::atomic<bool>	g_SyscallPoolReady{ false };
	std::atomic<void *>	g_SyscallPool{ nullptr };

	
	
	
	
	INIT_ONCE	g_SyscallOnce = INIT_ONCE_STATIC_INIT;
	SRWLOCK		g_SyscallLock{ };

	struct SyscallLockGuard
	{
	public:
		SyscallLockGuard()	{ AcquireSRWLockExclusive(&g_SyscallLock); }
		~SyscallLockGuard()	{ ReleaseSRWLockExclusive(&g_SyscallLock); }
	};

	BOOL CALLBACK InitializeLockOnce(PINIT_ONCE, PVOID, PVOID *)
	{
		
		return TRUE;
	}

	void EnsureLock()
	{
		InitOnceExecuteOnce(&g_SyscallOnce, InitializeLockOnce, nullptr, nullptr);
	}

	SYSCALL_ENTRY * FindEntry(DWORD NameHash)
	{
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			if (g_SyscallTable[i].NameHash == NameHash)
			{
				return &g_SyscallTable[i];
			}
		}

		return nullptr;
	}

	
	constexpr DWORD kStubProbeSize = 0x22;

	bool StubLooksHealthy(const BYTE * Code, DWORD Available, DWORD & ServiceOut)
	{
		if (!Code || Available < kStubProbeSize)
		{
			return false;
		}

		
		if (memcmp(Code, kPrologueHealthy, sizeof(kPrologueHealthy)) != 0)
		{
			return false;
		}

		const DWORD Candidate = *ReCa<const DWORD *>(Code + sizeof(kPrologueHealthy));

		
		
		if (Candidate > 0xFFFF)
		{
			return false;
		}

		
		
		for (DWORD i = sizeof(kPrologueHealthy) + sizeof(DWORD); i + 1 < Available && i <= 0x20; ++i)
		{
			if (Code[i] == 0x0F && Code[i + 1] == 0x05)
			{
				ServiceOut = Candidate;

				return true;
			}

			if (Code[i] == 0xC3 || Code[i] == 0xE9)
			{
				return false;
			}
		}

		return false;
	}

	bool BoundedRead(const BYTE * Base, DWORD Rva, SIZE_T Size, DWORD ImageSize)
	{
		if (!Base || !ImageSize)
		{
			return false;
		}

		if (Rva >= ImageSize || Size > ImageSize)
		{
			return false;
		}

		return static_cast<DWORD>(Rva) <= ImageSize - static_cast<DWORD>(Size);
	}

	const IMAGE_EXPORT_DIRECTORY * LocateExportDirectory(const BYTE * Ntdll, DWORD & ImageSizeOut)
	{
		ImageSizeOut = 0;

		if (!Ntdll)
		{
			return nullptr;
		}

		const auto * Dos = ReCa<const IMAGE_DOS_HEADER *>(Ntdll);
		if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return nullptr;
		}

		if (Dos->e_lfanew <= 0 || static_cast<DWORD>(Dos->e_lfanew) > 0x400)
		{
			return nullptr;
		}

		const auto * Nt = ReCa<const IMAGE_NT_HEADERS64 *>(Ntdll + Dos->e_lfanew);
		if (Nt->Signature != IMAGE_NT_SIGNATURE)
		{
			return nullptr;
		}

		if (Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return nullptr;
		}

		ImageSizeOut = Nt->OptionalHeader.SizeOfImage;
		if (!ImageSizeOut || ImageSizeOut > 0x8000000)
		{
			return nullptr;
		}

		const IMAGE_DATA_DIRECTORY & Dir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!Dir.VirtualAddress || !Dir.Size)
		{
			return nullptr;
		}

		if (!BoundedRead(Ntdll, Dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), ImageSizeOut))
		{
			return nullptr;
		}

		const auto * Export = ReCa<const IMAGE_EXPORT_DIRECTORY *>(Ntdll + Dir.VirtualAddress);
		if (!Export->NumberOfNames || Export->NumberOfNames > 0x8000)
		{
			return nullptr;
		}

		if (!BoundedRead(Ntdll, Export->AddressOfNames, sizeof(DWORD) * Export->NumberOfNames, ImageSizeOut) ||
			!BoundedRead(Ntdll, Export->AddressOfNameOrdinals, sizeof(WORD) * Export->NumberOfNames, ImageSizeOut) ||
			!BoundedRead(Ntdll, Export->AddressOfFunctions, sizeof(DWORD) * Export->NumberOfNames, ImageSizeOut))
		{
			return nullptr;
		}

		return Export;
	}

	const BYTE StubTemplate[SC_STUB_SIZE] =
	{
		0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00,
		0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90
	};

	void WriteStub(BYTE * Destination, DWORD Service)
	{
		memcpy(Destination, StubTemplate, SC_STUB_SIZE);
		*ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;
	}

bool BuildPool()
{
	SC_LOG_INFO("Building Syscall Stub Pool (%zu Entries, %u Bytes Each)...", kSyscallTableCount, SC_STUB_SIZE);

	
	
	
	
	
	
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		g_SyscallTable[i].Stub = nullptr;
	}
	BYTE * OldPool = ReCa<BYTE *>(g_SyscallPool.exchange(nullptr, std::memory_order_acq_rel));
	if (OldPool)
	{
		VirtualFree(OldPool, 0, MEM_RELEASE);
	}

	BYTE * Pool = ReCa<BYTE *>(VirtualAlloc(nullptr, kStubAreaSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!Pool)
	{
		SC_LOG_ERR("VirtualAlloc Failed For Stub Pool");
		return false;
	}

	DWORD Written = 0;
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		SYSCALL_ENTRY & Entry = g_SyscallTable[i];

		if (Entry.Service == kServiceUnknown || Entry.Service == kInvalidService)
		{
			continue;
		}

		WriteStub(Pool + (i * SC_STUB_SIZE), Entry.Service);
		Entry.Stub = Pool + (i * SC_STUB_SIZE);

		++Written;
	}

	if (!Written)
	{
		VirtualFree(Pool, 0, MEM_RELEASE);
		SC_LOG_ERR("No Valid Syscall Entries To Write");
		return false;
	}

	DWORD OldProtect = 0;
	if (!VirtualProtect(Pool, kStubAreaSize, PAGE_EXECUTE_READ, &OldProtect))
	{
		VirtualFree(Pool, 0, MEM_RELEASE);
		SC_LOG_ERR("VirtualProtect RX Failed");
		return false;
	}

	g_SyscallPool.store(Pool, std::memory_order_release);

	SC_LOG_OK("Stub Pool Built: %u/%zu Stubs At %p (RX)", Written, kSyscallTableCount, Pool);
	return true;
}
}

DWORD SyscallResolveAll()
{
	EnsureLock();
	SyscallLockGuard Guard;

	if (g_SyscallPoolReady.load(std::memory_order_acquire))
	{
		DWORD Ready = 0;
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			if (g_SyscallTable[i].Stub)
			{
				++Ready;
			}
		}

		SC_LOG_OK("Syscall Pool Already Ready (%u/%zu Stubs)", Ready, kSyscallTableCount);
		return Ready;
	}

	SC_LOG_INFO("Resolving Syscall Service Numbers From ntdll...");

	auto ntdll_name = XOR_STR_W(L"ntdll.dll");
	const BYTE * Ntdll = ReCa<const BYTE *>(GetModuleHandleW(ntdll_name.get()));
	if (!Ntdll)
	{
		SC_LOG_ERR("ntdll.dll Not Loaded");
		return 0;
	}

	DWORD ImageSize = 0;
	const IMAGE_EXPORT_DIRECTORY * Export = LocateExportDirectory(Ntdll, ImageSize);
	if (!Export)
	{
		SC_LOG_ERR("Failed To Locate ntdll Export Directory");
		return 0;
	}

	SC_LOG_INFO("ntdll Base: %p | ImageSize: 0x%X | Exports: %u", Ntdll, ImageSize, Export->NumberOfNames);

	
	
	
	
	std::vector<HARVESTED_ENTRY> HarvestedStorage;
	try
	{
		HarvestedStorage.reserve(512);
	}
	catch (...)
	{
		SC_LOG_ERR("Failed To Reserve Harvest Buffer");
		return 0;
	}
	HARVESTED_ENTRY * Harvested = nullptr;
	DWORD HarvestedCount = 0;
	constexpr DWORD kHarvestedCap = 0x4000;

	const auto * Names		= ReCa<const DWORD *>(Ntdll + Export->AddressOfNames);
	const auto * Ordinals	= ReCa<const WORD *>(Ntdll + Export->AddressOfNameOrdinals);
	const auto * Functions	= ReCa<const DWORD *>(Ntdll + Export->AddressOfFunctions);

	DWORD matched = 0;
	DWORD healthy = 0;
	DWORD rerouted = 0;
	DWORD oob = 0;

	for (DWORD i = 0; i < Export->NumberOfNames; ++i)
	{
		const DWORD NameRva = Names[i];
		if (!NameRva || !BoundedRead(Ntdll, NameRva, 2, ImageSize))
		{
			continue;
		}

		DWORD Hash = 0;
		{
			
			
			const DWORD NameLimit = ImageSize > NameRva ? ImageSize - NameRva : 0;
			const char * Name = ReCa<const char *>(Ntdll + NameRva);
			DWORD h = 0x811C9DC5u;
			bool terminated = false;
			for (DWORD n = 0; n < NameLimit && n < 256; ++n)
			{
				const char c = Name[n];
				if (!c)
				{
					terminated = true;
					break;
				}
				h ^= static_cast<BYTE>(c);
				h *= 0x01000193u;
			}
			if (!terminated)
			{
				continue;
			}
			Hash = h;
		}
		SYSCALL_ENTRY * Entry = FindEntry(Hash);
		const DWORD Rva = Functions[Ordinals[i]];

		if (!Rva || !BoundedRead(Ntdll, Rva, kStubProbeSize, ImageSize))
		{
			if (Entry)
			{
				Entry->Service = kInvalidService;
			}

			
			
			if (Entry)
			{
				++oob;
			}

			continue;
		}

		DWORD Service = kServiceUnknown;
		if (StubLooksHealthy(Ntdll + Rva, ImageSize - Rva, Service))
		{
			if (Entry && Entry->Service == kServiceUnknown)
			{
				Entry->Service = Service;
				const size_t idx = static_cast<size_t>(Entry - g_SyscallTable);
				if (idx < kSyscallTableCount)
				{
					g_Resolution[idx].Hooked = false;
					g_Resolution[idx].Reconstructed = false;
					g_Resolution[idx].Rva = Rva;
					memcpy(g_Resolution[idx].Prologue, Ntdll + Rva, 4);
				}
			}

			if (HarvestedCount < kHarvestedCap)
			{
				try
				{
					HarvestedStorage.push_back(HARVESTED_ENTRY{ Rva, Service });
					Harvested = HarvestedStorage.data();
					++HarvestedCount;
				}
				catch (...)
				{
					
				}
			}

			++healthy;
			if (Entry)
				++matched;
		}
		else if (Entry && Entry->Service == kServiceUnknown)
		{
			
			Entry->Service = kInvalidService;
			const size_t idx = static_cast<size_t>(Entry - g_SyscallTable);
			if (idx < kSyscallTableCount)
			{
				g_Resolution[idx].Hooked = true;
				g_Resolution[idx].Reconstructed = false;
				g_Resolution[idx].Rva = Rva;
				if (BoundedRead(Ntdll, Rva, 4, ImageSize))
				{
					memcpy(g_Resolution[idx].Prologue, Ntdll + Rva, 4);
				}
			}
			++rerouted;
		}
	}

	SC_LOG_INFO("Pass 1: Scanned %u Exports | Matched %u | Healthy %u | Rerouted %u | Unreadable %u",
		Export->NumberOfNames, matched, healthy, rerouted, oob);

	
	
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		if (g_SyscallTable[i].Service != kInvalidService)
		{
			continue;
		}

		for (DWORD j = 0; j < Export->NumberOfNames; ++j)
		{
			const DWORD NameRva = Names[j];
			if (!NameRva || !BoundedRead(Ntdll, NameRva, 2, ImageSize))
			{
				continue;
			}

			DWORD NameHash = 0;
			{
				const DWORD NameLimit = ImageSize > NameRva ? ImageSize - NameRva : 0;
				const char * Name = ReCa<const char *>(Ntdll + NameRva);
				DWORD h = 0x811C9DC5u;
				bool terminated = false;
				for (DWORD n = 0; n < NameLimit && n < 256; ++n)
				{
					const char c = Name[n];
					if (!c)
					{
						terminated = true;
						break;
					}
					h ^= static_cast<BYTE>(c);
					h *= 0x01000193u;
				}
				if (!terminated)
				{
					continue;
				}
				NameHash = h;
			}

			if (NameHash != g_SyscallTable[i].NameHash)
			{
				continue;
			}

			const DWORD Rva = Functions[Ordinals[j]];
			if (!Rva)
			{
				break;
			}

			
			const HARVESTED_ENTRY * Lower = nullptr;
			const HARVESTED_ENTRY * Upper = nullptr;

			for (DWORD k = 0; k < HarvestedCount; ++k)
			{
				if (Harvested[k].Rva < Rva)
				{
					if (!Lower || Harvested[k].Rva > Lower->Rva)
					{
						Lower = &Harvested[k];
					}
				}
				else if (Harvested[k].Rva > Rva)
				{
					if (!Upper || Harvested[k].Rva < Upper->Rva)
					{
						Upper = &Harvested[k];
					}
				}
			}

			if (Lower && Upper)
			{
				const DWORD span_rva		= Upper->Rva - Lower->Rva;
				const int	span_service	= static_cast<int>(Upper->Service) - static_cast<int>(Lower->Service);

				
				
				
				
				
				
				
				
				if (span_rva > 0 && span_service > 0 && (span_rva % static_cast<DWORD>(span_service)) == 0)
				{
					const DWORD stride_bytes = span_rva / static_cast<DWORD>(span_service);
					const DWORD offset_calls = (Rva - Lower->Rva) / stride_bytes;
					const int Reconstructed = static_cast<int>(Lower->Service) + static_cast<int>(offset_calls);
					if (Reconstructed > 0 && Reconstructed <= 0xFFFF)
					{
						g_SyscallTable[i].Service = static_cast<DWORD>(Reconstructed);
						g_Resolution[i].Reconstructed = true;
						SC_LOG_INFO("Recovered %s Via SSN 0x%04X + %u | Distance: 0x%X Bytes | Stride %u Bytes/SSN", kSyscallNames[i], Lower->Service, offset_calls, span_rva, stride_bytes);
					}
				}
			}

			break;
		}
	}

	DWORD reconstructed = 0;
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		if (g_SyscallTable[i].Service != kInvalidService && g_SyscallTable[i].Service != kServiceUnknown)
		{
			++reconstructed;
		}
	}
	SC_LOG_INFO("Pass 2: Reconstructed %u/%zu Services", reconstructed, kSyscallTableCount);

	if (!BuildPool())
	{
		SC_LOG_ERR("Failed To Build Syscall Stub Pool");
		return 0;
	}

	
	
	
	
	DWORD Ready = 0;
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		if (g_SyscallTable[i].Stub)
		{
			++Ready;
		}
	}

	
	SC_LOG_INFO("[Syscall] [*] Local ntdll.dll Base: %p (Size: 0x%X)\n", Ntdll, ImageSize);
	SC_LOG_INFO("[Syscall] [*] Export Census: %u Total Exports Harvested (%u Healthy)\n", Export->NumberOfNames, healthy);
	SC_LOG_INFO("[Syscall] [=] System Service Resolution Table:\n");
	SC_LOG_INFO("  Idx  Service Name              SSN      Status        Prologue      Address               Method\n");
	for (size_t ti = 0; ti < kSyscallTableCount; ++ti)
	{
		const DWORD svc = g_SyscallTable[ti].Service;
		const bool valid = (svc != kServiceUnknown && svc != static_cast<DWORD>(kInvalidService));
		const char * status = !valid ? "Failed" : (g_Resolution[ti].Reconstructed ? "Hooked" : (g_Resolution[ti].Hooked ? "Hooked" : "Clean"));
		const char * method = !valid ? "Unresolved" : (g_Resolution[ti].Reconstructed ? "Neighbor Interp" : "Direct Export");
		const void * addr = valid ? ReCa<const void *>(Ntdll + g_Resolution[ti].Rva) : nullptr;
		SC_LOG_INFO("  [%02zu] %-24s 0x%04X   %-8s    %02X %02X %02X %02X  %p  %s\n",
			ti, kSyscallNames[ti], valid ? svc : 0, status,
			g_Resolution[ti].Prologue[0], g_Resolution[ti].Prologue[1], g_Resolution[ti].Prologue[2], g_Resolution[ti].Prologue[3],
			addr, method);
	}
	{
		void * pool = g_SyscallPool.load(std::memory_order_acquire);
		MEMORY_BASIC_INFORMATION mbi{};
		DWORD rwx_count = 0;
		if (pool && VirtualQuery(pool, &mbi, sizeof(mbi)))
		{
			const bool is_rx = (mbi.Protect == PAGE_EXECUTE_READ);
			if (!is_rx && mbi.Protect == PAGE_EXECUTE_READWRITE)
			{
				rwx_count = 1;
			}
			if (is_rx)
			{
				SC_LOG_OK("[Syscall] [+] Stub Pool Staging: VA = %p | Size = 0x%X Bytes\n", pool, kStubAreaSize);
				
				
				
				SC_LOG_OK("[Syscall] [+] Memory Protection Query: Protect = 0x%08X (%s) | RWX Count = %u\n",
					mbi.Protect, "PAGE_EXECUTE_READ", rwx_count);
			}
			else
			{
				SC_LOG_ERR("[Syscall] [x] Stub Pool Protection Mismatch = 0x%08X (RWX = %u)\n", mbi.Protect, rwx_count);
			}
		}
		else
		{
			SC_LOG_ERR("[Syscall] [x] Stub Pool Not Queryable; Protection Unverified\n");
		}
	}

	
	
	
	if (Ready == kSyscallTableCount)
	{
		g_SyscallPoolReady.store(true, std::memory_order_release);
		SC_LOG_OK("Syscall Layer Ready: %u/%zu Stubs Built\n", Ready, kSyscallTableCount);
	}
	else
	{
		SC_LOG_WARN("Syscall Layer Incomplete: %u/%zu Stubs Built - %zu Unresolved\n",
			Ready, kSyscallTableCount, static_cast<size_t>(kSyscallTableCount - Ready));
	}
	return Ready;
}

void * SyscallStub(DWORD NameHash)
{
	
	
	if (!g_SyscallPoolReady.load(std::memory_order_acquire))
	{
		if (!SyscallResolveAll())
		{
			return nullptr;
		}
	}

	EnsureLock();
	SyscallLockGuard Guard;

	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		if (g_SyscallTable[i].NameHash == NameHash)
		{
			return g_SyscallTable[i].Stub;
		}
	}

	return nullptr;
}

DWORD SyscallServiceOfStub(const void * Stub)
{
	if (!Stub)
	{
		return 0;
	}

	const BYTE * Bytes = ReCa<const BYTE *>(Stub);

	if (memcmp(Bytes + SC_STUB_OFFSET_PROLOGUE, kPrologueHealthy, sizeof(kPrologueHealthy)) != 0)
	{
		return 0;
	}

	if (Bytes[SC_STUB_OFFSET_SYSCALL] != 0x0F || Bytes[SC_STUB_OFFSET_SYSCALL + 1] != 0x05)
	{
		return 0;
	}

	return *ReCa<const DWORD *>(Bytes + SC_STUB_OFFSET_SERVICE);
}

DWORD ScGetProcessImageName(HANDLE ProcessHandle, wchar_t * Buffer, DWORD Characters)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !Buffer || !Characters)
	{
		return 0;
	}

	
	
	
	ULONG Size = 0x400;
	std::vector<BYTE> Scratch;

	for (int attempt = 0; attempt < 4; ++attempt)
	{
		try
		{
			
			Scratch.assign(Size + sizeof(wchar_t) * 2, 0);
		}
		catch (...)
		{
			return 0;
		}

		const NTSTATUS Status = ScNtQueryInformationProcess(ProcessHandle, PROCESSINFOCLASS::ProcessImageFileNameWin32, Scratch.data(), Size + sizeof(wchar_t) * 2, &Size);

		if (Status == static_cast<NTSTATUS>(0xC0000004))
		{
			
			
			
			if (!Size)
			{
				const SIZE_T Attempted = Scratch.size();
				const ULONGLONG Grown = Attempted ? static_cast<ULONGLONG>(Attempted) * 2 : 0x800;
				Size = Grown > 0x10000 ? 0x10000 : static_cast<ULONG>(Grown);
				if (!Size)
				{
					return 0;
				}
			}

			continue;
		}

		if (NT_FAIL(Status))
		{
			return 0;
		}

		const auto * Name = ReCa<const UNICODE_STRING *>(Scratch.data());
		if (!Name->Length || !Name->szBuffer)
		{
			return 0;
		}

		const DWORD Length = static_cast<DWORD>(Name->Length / sizeof(wchar_t));
		if (Length >= Characters)
		{
			return 0;
		}

		memcpy(Buffer, Name->szBuffer, Name->Length);
		Buffer[Length] = L'\0';

		return Length;
	}

	return 0;
}

bool SyscallReady()
{
	return g_SyscallPoolReady.load(std::memory_order_acquire);
}

DWORD BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count)
{
	if (!Destination || !NameHashes || !Count || DestinationSize < static_cast<SIZE_T>(Count) * SC_STUB_SIZE)
	{
		return 0;
	}

	
	if (!g_SyscallPoolReady.load(std::memory_order_acquire))
	{
		if (!SyscallResolveAll())
		{
			return 0;
		}
	}

	EnsureLock();
	SyscallLockGuard Guard;

	
	
	DWORD Written = 0;

	for (DWORD i = 0; i < Count; ++i)
	{
		if (NameHashes[i] == 0)
		{
			continue;
		}

		for (size_t j = 0; j < kSyscallTableCount; ++j)
		{
			if (g_SyscallTable[j].NameHash != NameHashes[i] || !g_SyscallTable[j].Stub)
			{
				continue;
			}

			memcpy(Destination + (i * SC_STUB_SIZE), g_SyscallTable[j].Stub, SC_STUB_SIZE);

			++Written;
			break;
		}
	}

	return Written;
}
