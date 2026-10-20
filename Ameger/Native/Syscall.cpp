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
		{ SC_NtQuerySystemInformation,		kServiceUnknown, nullptr },
		{ SC_NtQueryInformationProcess,	kServiceUnknown, nullptr },
		{ SC_NtQueryInformationThread,		kServiceUnknown, nullptr },
		{ SC_NtAllocateVirtualMemory,		kServiceUnknown, nullptr },
		{ SC_NtFreeVirtualMemory,			kServiceUnknown, nullptr },
		{ SC_NtProtectVirtualMemory,		kServiceUnknown, nullptr },
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
		"NtQuerySystemInformation",
		"NtQueryInformationProcess",
		"NtQueryInformationThread",
		"NtAllocateVirtualMemory",
		"NtFreeVirtualMemory",
		"NtProtectVirtualMemory",
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

	constexpr DWORD kInvalidService = 0xFFFF0000;

	// ntdll's syscall stubs have been emitted with two different "mov r10, rcx"
	// encodings over the years. Both are accepted here so a build that ships the
	// other form is still recognised as a healthy stub instead of being written
	// off as a hooked one.
	constexpr BYTE kPrologueHealthyA[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };
	constexpr BYTE kPrologueHealthyB[4] = { 0x49, 0x89, 0xCA, 0xB8 };

	std::atomic<bool>	g_SyscallPoolReady{ false };
	std::atomic<void *>	g_SyscallPool{ nullptr };

	// The pool is built once and then treated as immutable. The lock only guards
	// the build itself; readers go through the atomic pool pointer and the table
	// entries, which are written before the pool is published.
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

	// A healthy ntdll stub is "mov r10, rcx" (in one of two encodings), followed by
	// "mov eax, <service number>", followed by "syscall" and "ret". The service
	// number is therefore always the DWORD that follows the three prologue bytes.
	bool StubLooksHealthy(const BYTE * Code, DWORD Available, DWORD & ServiceOut)
	{
		if (!Code || Available < kStubProbeSize)
		{
			return false;
		}

		const bool prologue_a = memcmp(Code, kPrologueHealthyA, sizeof(kPrologueHealthyA)) == 0;
		const bool prologue_b = memcmp(Code, kPrologueHealthyB, sizeof(kPrologueHealthyB)) == 0;

		if (!prologue_a && !prologue_b)
		{
			return false;
		}

		const DWORD Candidate = *ReCa<const DWORD *>(Code + sizeof(kPrologueHealthyA));

		// The service number is a 16-bit index; anything larger means the bytes are
		// not a service load at all.
		if (Candidate > 0xFFFF)
		{
			return false;
		}

		// The syscall instruction has to follow the service load within a short
		// window; a ret or a jump before it means this is not a plain syscall stub
		// (a hook trampoline, for instance).
		for (DWORD i = sizeof(kPrologueHealthyA) + sizeof(DWORD); i + 1 < Available && i <= 0x20; ++i)
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
		if (!Export->NumberOfNames || Export->NumberOfNames > 0x8000 ||
			!Export->NumberOfFunctions || Export->NumberOfFunctions > 0x8000)
		{
			return nullptr;
		}

		if (!BoundedRead(Ntdll, Export->AddressOfNames, sizeof(DWORD) * Export->NumberOfNames, ImageSizeOut) ||
			!BoundedRead(Ntdll, Export->AddressOfNameOrdinals, sizeof(WORD) * Export->NumberOfNames, ImageSizeOut) ||
			!BoundedRead(Ntdll, Export->AddressOfFunctions, sizeof(DWORD) * Export->NumberOfFunctions, ImageSizeOut))
		{
			return nullptr;
		}
		return Export;
	}

	// "mov r10, rcx" in its two encodings. On x64 a syscall entry point copies the
	// shadow-space copy of the first argument into R10 before issuing the
	// instruction, and the service number is loaded into EAX.
	constexpr BYTE kPrologueA[3] = { 0x4C, 0x8B, 0xD1 };
	constexpr BYTE kPrologueB[3] = { 0x49, 0x89, 0xCA };

	constexpr BYTE kOpMovEaxImm32 = 0xB8;
	constexpr BYTE kOpSyscall0 = 0x0F;
	constexpr BYTE kOpSyscall1 = 0x05;
	constexpr BYTE kOpJmpRip0 = 0xFF;
	constexpr BYTE kOpJmpRip1 = 0x25;
	constexpr BYTE kOpRet = 0xC3;

	struct NOP_PATTERN { BYTE Length; BYTE Bytes[4]; };

	// The stub tail is padded with a mix of multi-byte NOP encodings. The pattern is
	// picked from the service number, so two stubs never share a tail signature.
	constexpr NOP_PATTERN kNopPatterns[] =
	{
		{ 1, { 0x90, 0, 0, 0 } },
		{ 2, { 0x66, 0x90, 0, 0 } },
		{ 3, { 0x0F, 0x1F, 0x00, 0 } },
		{ 3, { 0x8D, 0x40, 0x00, 0 } },
		{ 4, { 0x0F, 0x1F, 0x40, 0x00 } },
	};

	void FillNoOpTail(BYTE * Destination, SIZE_T Size, DWORD Key)
	{
		if (!Destination || !Size)
		{
			return;
		}

		DWORD state = Key | 1u;
		SIZE_T written = 0;

		while (written < Size)
		{
			state = state * 1103515245u + 12345u;
			const NOP_PATTERN & pattern = kNopPatterns[(state >> 16) % _countof(kNopPatterns)];

			// The chosen pattern may not fit in the remaining space. Rather than
			// emitting a partial instruction, the tail is padded with single-byte
			// NOPs for the remainder.
			SIZE_T length = pattern.Length;
			if (length > Size - written)
			{
				for (SIZE_T i = written; i < Size; ++i)
				{
					Destination[i] = 0x90;
				}
				return;
			}

			for (SIZE_T i = 0; i < length; ++i)
			{
				Destination[written + i] = pattern.Bytes[i];
			}

			written += length;
		}
	}

	static void * FindSyscallGadget()
	{
		auto name = XOR_STR_W(L"ntdll.dll");
		const BYTE * base = ReCa<const BYTE *>(GetModuleHandleW(name.get()));
		if (!base) return nullptr;

		const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(base);
		if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

		const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
		if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

		const auto * sec = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
		{
			if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				const BYTE * start = base + sec[i].VirtualAddress;
				DWORD size = sec[i].Misc.VirtualSize;
				if (!size) size = sec[i].SizeOfRawData;
				for (DWORD j = 0; j + 2 < size; ++j)
				{
					if (start[j] == kOpSyscall0 && start[j + 1] == kOpSyscall1 && start[j + 2] == kOpRet)
					{
						return ReCa<void *>(const_cast<BYTE *>(start + j));
					}
				}
			}
		}

		return nullptr;
	}

	void * g_SyscallGadget = nullptr;

	// Emits one syscall stub into `Destination`.
	//
	// `StubAddress` and `GadgetSlotAddress` are the absolute addresses the stub and
	// the gadget slot will live at *in the process that executes the stub*. They are
	// not necessarily this process's addresses: a stub that is staged into a remote
	// process carries a RIP-relative displacement, and that displacement is only
	// correct when it is computed against the remote layout.
	//
	// Returns false when the indirect displacement does not fit in a signed 32-bit
	// field, in which case no stub is written.
	bool WriteStub(BYTE * Destination, DWORD Service, void * Gadget, ULONG_PTR GadgetSlotAddress, ULONG_PTR StubAddress)
	{
		// Prologue diversity: "mov r10, rcx" is encoded two different ways depending
		// on the service number, so a scanner cannot key on a single byte pattern.
		const DWORD mix = (Service * 2654435761u) ^ (Service >> 13);
		const BYTE * prologue = (mix & 1u) ? kPrologueB : kPrologueA;
		Destination[0] = prologue[0];
		Destination[1] = prologue[1];
		Destination[2] = prologue[2];
		Destination[3] = kOpMovEaxImm32;
		*ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;

		if (Gadget && GadgetSlotAddress)
		{
			// Indirect form: "jmp qword ptr [rip+disp32]" into the slot that holds the
			// ntdll gadget address. The displacement is relative to the end of the
			// instruction, i.e. to SC_STUB_TAIL_INDIRECT.
			const LONGLONG delta = static_cast<LONGLONG>(GadgetSlotAddress)
				- static_cast<LONGLONG>(StubAddress + SC_STUB_TAIL_INDIRECT);

			if (delta < INT32_MIN || delta > INT32_MAX)
			{
				return false;
			}

			Destination[SC_STUB_OFFSET_SYSCALL] = kOpJmpRip0;
			Destination[SC_STUB_OFFSET_SYSCALL + 1] = kOpJmpRip1;

			*ReCa<LONG *>(Destination + SC_STUB_OFFSET_SYSCALL + 2) = static_cast<LONG>(delta);

			FillNoOpTail(Destination + SC_STUB_TAIL_INDIRECT, SC_STUB_SIZE - SC_STUB_TAIL_INDIRECT, Service);
			return true;
		}

		// Direct form: "syscall ; ret" inline. Only used for the local pool when no
		// gadget could be located; remote stubs always take the indirect path.
		Destination[SC_STUB_OFFSET_SYSCALL] = kOpSyscall0;
		Destination[SC_STUB_OFFSET_SYSCALL + 1] = kOpSyscall1;
		Destination[SC_STUB_OFFSET_RET] = kOpRet;

		FillNoOpTail(Destination + SC_STUB_TAIL_DIRECT, SC_STUB_SIZE - SC_STUB_TAIL_DIRECT, Service);
		return true;
	}

bool BuildPool()
{
	void * gadget = SyscallGadgetAddress();
	SC_LOG_INFO("Building Syscall Stub Pool (%zu Entries, %u Bytes Each)...", kSyscallTableCount, SC_STUB_SIZE);
	// Every entry starts out unresolved. A failure half way through the build
	// must not leave a stale pointer behind that a later caller could jump
	// through.
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		g_SyscallTable[i].Stub = nullptr;
	}

	// The pool is allocated writable and promoted to execute-read once the bytes
	// are in place, so it is never simultaneously writable and executable.
	BYTE * Pool = ReCa<BYTE *>(VirtualAlloc(nullptr, kStubAreaSize + 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!Pool)
	{
		SC_LOG_ERR("VirtualAlloc Failed For Stub Pool");
		return false;
	}

	// One shared slot holds the ntdll gadget address. Every indirect stub jumps
	// through it, so the `syscall` instruction itself only ever exists inside a
	// legitimate system module.
	BYTE * const GadgetSlot = Pool + kStubAreaSize;

	// The indirect displacement is a signed 32-bit value relative to the end of
	// the jump instruction. The pool and its slot are always close enough for that,
	// but the check keeps the fallback explicit rather than accidental.
	const ptrdiff_t slot_delta = GadgetSlot - Pool;
	bool use_indirect = false;
	if (slot_delta > 0 && slot_delta < INT32_MAX)
	{
		use_indirect = true;
	}
	else
	{
		SC_LOG_WARN("Gadget Slot Out Of disp32 Range; Falling Back To Direct Syscall Stubs\n");
		gadget = nullptr;
	}

	DWORD Written = 0;
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		SYSCALL_ENTRY & Entry = g_SyscallTable[i];

		if (Entry.Service == kServiceUnknown || Entry.Service == kInvalidService)
		{
			continue;
		}

		BYTE * slot = Pool + (i * SC_STUB_SIZE);

		if (!WriteStub(slot, Entry.Service, use_indirect ? gadget : nullptr,
			use_indirect ? reinterpret_cast<ULONG_PTR>(GadgetSlot) : 0,
			reinterpret_cast<ULONG_PTR>(slot)))
		{
			SC_LOG_ERR("Syscall Stub Displacement Out Of Range For Entry %zu", i);
			continue;
		}

		Entry.Stub = slot;

		++Written;
	}

	if (!Written)
	{
		VirtualFree(Pool, 0, MEM_RELEASE);
		SC_LOG_ERR("No Valid Syscall Entries To Write");
		return false;
	}

	if (use_indirect)
	{
		*ReCa<void **>(GadgetSlot) = gadget;
	}

	DWORD OldProtect = 0;
	if (!VirtualProtect(Pool, kStubAreaSize + 16, PAGE_EXECUTE_READ, &OldProtect))
	{
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			g_SyscallTable[i].Stub = nullptr;
		}

		VirtualFree(Pool, 0, MEM_RELEASE);
		SC_LOG_ERR("VirtualProtect RX Failed");
		return false;
	}

	g_SyscallPool.store(Pool, std::memory_order_release);

	SC_LOG_OK("Stub Pool Built: %u/%zu Stubs At %p (RX)", Written, kSyscallTableCount, Pool);
	return true;
}
}

void * SyscallGadgetAddress()
{
	if (!g_SyscallGadget)
	{
		g_SyscallGadget = FindSyscallGadget();
	}

	return g_SyscallGadget;
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
	// The harvest buffer keeps every healthy export that was seen, not just the
	// ones this project cares about. The neighbour interpolation in pass two
	// needs those as reference points.
	// The harvest buffer keeps every healthy export that was seen, not just the
	// ones this project cares about. The neighbour interpolation in pass two
	// needs those as reference points.
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
		const WORD Ordinal = Ordinals[i];
		const DWORD Rva = Ordinal < Export->NumberOfFunctions ? Functions[Ordinal] : 0;

		if (!Rva || !BoundedRead(Ntdll, Rva, kStubProbeSize, ImageSize))
		{
			if (Entry)
			{
				Entry->Service = kInvalidService;
			}

			// The export resolves to an address that cannot be inspected. If it is
			// one of ours, the entry is parked for pass two to reconstruct.
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

	// Pass two: every entry that pass one could not read is retried. The service
	// numbers of the healthy exports on either side of it are used to interpolate
	// the missing one, which is how a hooked stub is recovered without executing
	// anything.
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

			const WORD Ordinal = Ordinals[j];
			if (Ordinal >= Export->NumberOfFunctions)
			{
				break;
			}

			const DWORD Rva = Functions[Ordinal];
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

				// The export table is ordered by address and the service numbers
				// increase with it, so the distance between two healthy neighbours
				// divided by their service-number gap gives the byte stride of one
				// service slot. The missing entry's service number is then its
				// offset from the lower neighbour in service slots.
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
	// The resolution table is printed for diagnostics: it shows which service
	// numbers were read straight out of ntdll and which were reconstructed.
	DWORD Ready = 0;
	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		if (g_SyscallTable[i].Stub)
		{
			++Ready;
		}
	}

	// The resolution table is printed for diagnostics: it shows which service
	// numbers were read straight out of ntdll and which were reconstructed.
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
	bool verification_passed = true;
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
				verification_passed = false;
			}
			if (is_rx)
			{
				SC_LOG_OK("[Syscall] [+] Stub Pool Staging: VA = %p | Size = 0x%X Bytes\n", pool, kStubAreaSize);
	// The pool is only armed once its live protection has been confirmed to be
	// execute-read.
				SC_LOG_OK("[Syscall] [+] Memory Protection Query: Protect = 0x%08X (%s) | RWX Count = %u\n",
					mbi.Protect, "PAGE_EXECUTE_READ", rwx_count);
			}
			else
			{
				SC_LOG_ERR("[Syscall] [x] Stub Pool Protection Mismatch = 0x%08X (RWX = %u)\n", mbi.Protect, rwx_count);
				verification_passed = false;
			}
		}
		else
		{
			SC_LOG_ERR("[Syscall] [x] Stub Pool Not Queryable; Protection Unverified\n");
			verification_passed = false;
		}
	}

	// The pool is only armed once its live protection has been confirmed to be
	// execute-read. An RWX pool, or a pool whose protection cannot be queried at
	// all, leaves the whole syscall layer unavailable rather than being used.
	if (!verification_passed)
	{
		SC_LOG_ERR("[Syscall] [x] Stub Pool W^X Verification Failed; Marking Layer Unavailable\n");
		g_SyscallPoolReady.store(false, std::memory_order_release);
		return 0;
	}

	g_SyscallPoolReady.store(true, std::memory_order_release);
	if (Ready == kSyscallTableCount)
	{
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

	
	const bool prologue_a = memcmp(Bytes + SC_STUB_OFFSET_PROLOGUE, kPrologueA, sizeof(kPrologueA)) == 0;
	const bool prologue_b = memcmp(Bytes + SC_STUB_OFFSET_PROLOGUE, kPrologueB, sizeof(kPrologueB)) == 0;
	if (!prologue_a && !prologue_b)
	{
		return 0;
	}

	if (Bytes[SC_STUB_OFFSET_OPCODE] != kOpMovEaxImm32)
	{
		return 0;
	}

	const BYTE op0 = Bytes[SC_STUB_OFFSET_SYSCALL];
	const BYTE op1 = Bytes[SC_STUB_OFFSET_SYSCALL + 1];

	const bool direct = (op0 == kOpSyscall0 && op1 == kOpSyscall1 && Bytes[SC_STUB_OFFSET_RET] == kOpRet);
	const bool indirect = (op0 == kOpJmpRip0 && op1 == kOpJmpRip1);

	if (!direct && !indirect)
	{
		return 0;
	}

	const DWORD Service = *ReCa<const DWORD *>(Bytes + SC_STUB_OFFSET_SERVICE);
	if (!Service || Service > 0xFFFF)
	{
		return 0;
	}

	return Service;
}

DWORD ScGetProcessImageName(HANDLE ProcessHandle, wchar_t * Buffer, DWORD Characters)
{
	if (!ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE || !Buffer || !Characters)
	{
		return 0;
	}
	// ProcessImageFileNameWin32 returns a UNICODE_STRING at the head of the
	// buffer with the name following it, so the buffer has to be large enough
	// for both. The size is grown on demand when the kernel reports a
	// mismatch.
	ULONG Size = 0x400;
	std::vector<BYTE> Scratch;

	// ProcessImageFileNameWin32 returns a UNICODE_STRING at the head of the buffer
	// with the name following it, so the buffer has to be large enough for both.
	// The size is grown on demand when the kernel reports a mismatch.
	for (int attempt = 0; attempt < 4; ++attempt)
	{
		try
		{
			// The kernel writes a UNICODE_STRING followed by the name, so a couple
			// of extra wide characters of head room are always reserved.
			Scratch.assign(Size + sizeof(wchar_t) * 2, 0);
		}
		catch (...)
		{
			return 0;
		}

		const NTSTATUS Status = ScNtQueryInformationProcess(ProcessHandle, PROCESSINFOCLASS::ProcessImageFileNameWin32, Scratch.data(), Size + sizeof(wchar_t) * 2, &Size);

		if (Status == static_cast<NTSTATUS>(0xC0000004))
		{
			ULONG Required = Size;
			if (Required <= Scratch.size())
			{
				const SIZE_T Attempted = Scratch.size();
				const ULONGLONG Grown = Attempted ? static_cast<ULONGLONG>(Attempted) * 2 : 0x800;
				Required = Grown > 0x10000 ? 0x10000 : static_cast<ULONG>(Grown);
			}
			Size = Required;
			if (!Size)
			{
				return 0;
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

DWORD BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count, ULONG_PTR RemoteBase)
{
	const SIZE_T stub_bytes = static_cast<SIZE_T>(Count) * SC_STUB_SIZE;

	// The trailing gadget slot is part of the contract: the stubs jump through it.
	if (!Destination || !NameHashes || !Count || DestinationSize < stub_bytes + sizeof(void *))
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

	// Remote stubs never carry an inline `syscall`; they jump through the ntdll
	// `syscall ; ret` gadget so the target process holds no `0F 05` pattern of its
	// own. The gadget lives in ntdll, which is mapped at the same base in the target
	// (verified before the staging buffer is built), so the same address is valid
	// in both processes.
	void * gadget = SyscallGadgetAddress();
	if (!gadget)
	{
		SC_LOG_ERR("Remote Syscall Stubs Require The ntdll Syscall Gadget");
		return 0;
	}

	const ULONG_PTR gadget_slot_local = reinterpret_cast<ULONG_PTR>(Destination) + stub_bytes;
	const ULONG_PTR gadget_slot_address = RemoteBase ? (RemoteBase + stub_bytes) : gadget_slot_local;

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

			BYTE * slot = Destination + (i * SC_STUB_SIZE);

			// The RIP-relative displacement has to be computed against the address
			// the stub will occupy in the process that runs it, not against this
			// process's copy of the staging buffer.
			const ULONG_PTR stub_address = RemoteBase
				? (RemoteBase + static_cast<ULONG_PTR>(i) * SC_STUB_SIZE)
				: reinterpret_cast<ULONG_PTR>(slot);

			if (!WriteStub(slot, g_SyscallTable[j].Service, gadget, gadget_slot_address, stub_address))
			{
				SC_LOG_ERR("Remote Syscall Stub %u Displacement Out Of Range", i);
				break;
			}

			if (SyscallServiceOfStub(slot) == 0)
			{
				break;
			}

			++Written;
			break;
		}
	}

	if (Written)
	{
		*reinterpret_cast<void **>(gadget_slot_local) = gadget;
	}

	return Written;
}
