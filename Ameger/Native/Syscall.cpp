#include "Core/Utility/Header/PrecompiledHeader.h"

#include <new>

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
		{ SC_NtCreateSection,				kServiceUnknown, nullptr },
		{ SC_NtMapViewOfSection,			kServiceUnknown, nullptr },
		{ SC_NtUnmapViewOfSection,			kServiceUnknown, nullptr },
		{ SC_NtQuerySection,				kServiceUnknown, nullptr },
		{ SC_NtClose,						kServiceUnknown, nullptr },
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
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtQuerySection",
		"NtClose",
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





	constexpr BYTE kPrologueHealthyA[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };
	constexpr BYTE kPrologueHealthyB[4] = { 0x49, 0x89, 0xCA, 0xB8 };

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

		const bool prologue_a = memcmp(Code, kPrologueHealthyA, sizeof(kPrologueHealthyA)) == 0;
		const bool prologue_b = memcmp(Code, kPrologueHealthyB, sizeof(kPrologueHealthyB)) == 0;

		if (!prologue_a && !prologue_b)
		{
			return false;
		}

		const DWORD Candidate = *ReCa<const DWORD *>(Code + sizeof(kPrologueHealthyA));



		if (Candidate > 0xFFFF)
		{
			return false;
		}




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




	constexpr BYTE kPrologueA[3] = { 0x4C, 0x8B, 0xD1 };
	constexpr BYTE kPrologueB[3] = { 0x49, 0x89, 0xCA };

	constexpr BYTE kOpMovEaxImm32 = 0xB8;
	constexpr BYTE kOpSyscall0 = 0x0F;
	constexpr BYTE kOpSyscall1 = 0x05;
	constexpr BYTE kOpJmpRip0 = 0xFF;
	constexpr BYTE kOpJmpRip1 = 0x25;
	constexpr BYTE kOpRet = 0xC3;

	// Vector 7: the syscall-sampler block emitted into each sampled remote stub, right before the
	// gadget jmp. 167 bytes (46 insns), verified byte-by-byte with capstone (keystone-assembled). It
	// records one SYSCALL_SAMPLE ring slot (ThreadId, RSP, TSC, FunctionId, Frames[8]) and advances
	// the ring index mod SYSCALL_SAMPLE_COUNT (16), while preserving every syscall argument register
	// (rcx/rdx/r8/r9/r10 and the SSN in eax). Frames[8] = [rsp+0..56] captured AT SYSCALL TIME from
	// the REAL stack (while the shell stack is still mapped), bracketed by push/pop rax so the SSN
	// in eax survives into the gadget's syscall. The three rip-relative disp32 fields and the
	// FunctionId imm8 are placeholders here and are filled per stub at emit time. r12 holds the real
	// RSP, r13 the ring-slot base, r14/r15 the running index (r15 incremented & stored mod 16); rsi/
	// rdi are never touched, and every callee-saved register used (r12-r15) is saved and restored.
	constexpr BYTE kSampleBlockRaw[167] =
{
	0x49,0x89,0xE4,                 // mov r12, rsp             r12 = real rsp (callee-saved, restored at end)
	0x41,0x54,                 // push r12
	0x41,0x55,                 // push r13
	0x41,0x56,                 // push r14
	0x41,0x57,                 // push r15
	0x65,0x44,0x8B,0x1C,0x25,0x48,0x00,0x00,0x00,                 // mov r11d, [gs:0x48]      TEB->ClientId.UniqueThread (TID); absolute gs:disp32 (ModRM 1C + SIB 25)
	0x44,0x8B,0x35,0x00,0x00,0x00,0x00,                 // mov r14d, [rip+SYSIDX]   current ring index            (disp32 filled per stub)
	0x4D,0x89,0xF7,                 // mov r15, r14             r15 = index (running copy for increment/store)
	0x4D,0x6B,0xF6,0x60,                 // imul r14, r14, 96        index * stride(96)
	0x4C,0x8D,0x2D,0x00,0x00,0x00,0x00,                 // lea r13, [rip+RING]      ring base (64-bit)            (disp32 filled per stub)
	0x4D,0x01,0xF5,                 // add r13, r14             slot = ring + index*96  (r13 = ring slot)
	0x45,0x89,0x5D,0x00,                 // mov [r13], r11d          ThreadId
	0x4D,0x89,0x65,0x08,                 // mov [r13+8], r12         Rsp (real rsp captured in r12)
	0x52,                 // push rdx                 save arg2 (rdtsc clobbers edx) -- REAL stack
	0x50,                 // push rax                 save SSN  (rdtsc clobbers eax) -- REAL stack
	0x0F,0x31,                 // rdtsc                    eax:edx = cycle
	0x41,0x89,0x45,0x10,                 // mov [r13+16], eax        CycleCount low
	0x41,0x89,0x55,0x14,                 // mov [r13+20], edx        CycleCount high
	0x58,                 // pop rax                  restore SSN
	0x5A,                 // pop rdx                  restore arg2
	0x41,0xC6,0x45,0x18,0x00,                 // mov [r13+24], imm8       FunctionId (imm8 filled per stub)
	0x50,                 // push rax                 push SSN so [rsp]=SSN; frame capture brackets the real stack
	0x48,0x8B,0x04,0x24,                 // mov rax, [rsp]           Frames[0]
	0x49,0x89,0x45,0x20,                 // mov [r13+32], rax
	0x48,0x8B,0x44,0x24,0x08,                 // mov rax, [rsp+8]         Frames[1]
	0x49,0x89,0x45,0x28,                 // mov [r13+40], rax
	0x48,0x8B,0x44,0x24,0x10,                 // mov rax, [rsp+16]        Frames[2]
	0x49,0x89,0x45,0x30,                 // mov [r13+48], rax
	0x48,0x8B,0x44,0x24,0x18,                 // mov rax, [rsp+24]        Frames[3]
	0x49,0x89,0x45,0x38,                 // mov [r13+56], rax
	0x48,0x8B,0x44,0x24,0x20,                 // mov rax, [rsp+32]        Frames[4]
	0x49,0x89,0x45,0x40,                 // mov [r13+64], rax
	0x48,0x8B,0x44,0x24,0x28,                 // mov rax, [rsp+40]        Frames[5]
	0x49,0x89,0x45,0x48,                 // mov [r13+72], rax
	0x48,0x8B,0x44,0x24,0x30,                 // mov rax, [rsp+48]        Frames[6]
	0x49,0x89,0x45,0x50,                 // mov [r13+80], rax
	0x48,0x8B,0x44,0x24,0x38,                 // mov rax, [rsp+56]        Frames[7]
	0x49,0x89,0x45,0x58,                 // mov [r13+88], rax
	0x58,                 // pop rax                  pop the SSN (unwind the push)
	0x41,0x83,0xC7,0x01,                 // add r15d, 1              index++
	0x41,0x83,0xE7,0x0F,                 // and r15d, 15             index &= 15 (mod SYSCALL_SAMPLE_COUNT)
	0x44,0x89,0x3D,0x00,0x00,0x00,0x00,                 // mov [rip+SYSIDX], r15d   store the new index           (disp32 filled per stub)
	0x41,0x5F,                 // pop r15
	0x41,0x5E,                 // pop r14
	0x41,0x5D,                 // pop r13
	0x41,0x5C,                 // pop r12
	};

	static_assert(_countof(kSampleBlockRaw) == SC_SAMPLE_BLOCK_SIZE, "sampler block must be 167 bytes");

	// Block-internal offsets (instruction starts) of the rip-relative disp32 fields + the imm8.
	// The 167-byte capture-only block has THREE rip-relative fields (SYSIDX-load, RING-lea,
	// SYSIDX-store) and ONE imm8 (FuncId). disp32 always sits at insn_start+3. kSampleOffFuncId is
	// the offset of the imm8 BYTE itself (WriteSampledStub writes FunctionId directly there); the
	// instruction `mov [r13+24], imm8` is 5 bytes (41 C6 45 18 imm8), so the imm8 is at 66+4 = 70.
	constexpr size_t kSampleOffSysIdxLoad  = 20;   // 44 8B 35 ..  (mov r14d, [rip+SYSIDX])
	constexpr size_t kSampleOffRingLea     = 34;   // 4C 8D 2D ..  (lea r13, [rip+RING])
	constexpr size_t kSampleOffFuncId      = 70;   // imm8 of 41 C6 45 18 imm8 (mov [r13+24], imm8)
	constexpr size_t kSampleOffSysIdxStore = 152;  // 44 89 3D ..  (mov [rip+SYSIDX], r15d)

	// Stub-space offset of the instruction that immediately FOLLOWS each rip-relative insn --
	// that is the RIP against which the disp32 is computed (matching WriteStub's convention).
	// Every rip-relative insn in this block is 7 bytes (REX+OP+ModRM+disp32).
	constexpr size_t kSampleNextSysIdxLoad  = SC_STUB_OFFSET_SAMPLE + kSampleOffSysIdxLoad  + 7; // 35
	constexpr size_t kSampleNextRingLea     = SC_STUB_OFFSET_SAMPLE + kSampleOffRingLea     + 7; // 49
	constexpr size_t kSampleNextSysIdxStore = SC_STUB_OFFSET_SAMPLE + kSampleOffSysIdxStore + 7; // 167

	struct NOP_PATTERN { BYTE Length; BYTE Bytes[4]; };



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

	struct SYSCALL_GADGET
	{
		void *	Addr		= nullptr;
		DWORD	FrameSize	= 0;
	};

	constexpr size_t kMaxGadgetPool = 32;
	SYSCALL_GADGET g_SyscallGadgetPool[kMaxGadgetPool]{};
	size_t g_SyscallGadgetPoolCount = 0;

	// Per-instance seeded PRNG (xorshift32), stored alongside the stub pool; avoids RtlRandomEx.
	struct GadgetPrng { uint32_t State; };
	GadgetPrng g_GadgetPrng{ 0 };

	uint32_t PrngNext(GadgetPrng & p)
	{
		uint32_t x = p.State;
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		p.State = x;
		return x ? x : 1u;
	}

	// HallWatch: a candidate `0F 05` gadget is valid if its first two bytes are the SYSCALL
	// opcode. The scan already confines candidates to ntdll.dll's executable sections, so a
	// valid candidate is guaranteed NOT in Ameger's private RX pool.
	static bool GadgetVerified(const BYTE * g)
	{
		return g != nullptr && g[0] == kOpSyscall0 && g[1] == kOpSyscall1;
	}

	static void FindSyscallGadgetPool()
	{
		if (g_SyscallGadgetPoolCount)
			return;

		auto name = XOR_STR_W(L"ntdll.dll");
		const BYTE * base = ReCa<const BYTE *>(GetModuleHandleW(name.get()));
		if (!base) return;

		const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(base);
		if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return;

		const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
		if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return;

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
						if (g_SyscallGadgetPoolCount < kMaxGadgetPool)
						{
							if (GadgetVerified(const_cast<BYTE *>(start + j)))
							{
								g_SyscallGadgetPool[g_SyscallGadgetPoolCount++] =
									SYSCALL_GADGET{ ReCa<void *>(const_cast<BYTE *>(start + j)), 0 };
							}
						}
					}
				}
			}
		}

		// Seed the per-instance PRNG from the base address (stable per process).
		g_GadgetPrng.State = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(base) ^ 0x9E3779B9u);
	}

	void * g_SyscallGadget = nullptr;

	void * SyscallGadgetPick()
	{
		FindSyscallGadgetPool();
		if (!g_SyscallGadgetPoolCount)
		{
			return nullptr;
		}

		const size_t idx = PrngNext(g_GadgetPrng) % g_SyscallGadgetPoolCount;
		return g_SyscallGadgetPool[idx].Addr;
	}



















	bool WriteStub(BYTE * Destination, DWORD Service, void * Gadget, ULONG_PTR GadgetSlotAddress, ULONG_PTR StubAddress)
	{
		if (!Destination || !Gadget || !GadgetSlotAddress || !StubAddress)
		{
			return false;
		}



		const DWORD mix = (Service * 2654435761u) ^ (Service >> 13);
		const BYTE * prologue = (mix & 1u) ? kPrologueB : kPrologueA;
		Destination[0] = prologue[0];
		Destination[1] = prologue[1];
		Destination[2] = prologue[2];
		Destination[3] = kOpMovEaxImm32;
		*ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;




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

	// HallWatch fallback: embed a direct `0F 05` syscall in the stub (no gadget indirection).
	bool WriteDirectStub(BYTE * Destination, DWORD Service)
	{
		if (!Destination)
		{
			return false;
		}

		const DWORD mix = (Service * 2654435761u) ^ (Service >> 13);
		const BYTE * prologue = (mix & 1u) ? kPrologueB : kPrologueA;
		Destination[0] = prologue[0];
		Destination[1] = prologue[1];
		Destination[2] = prologue[2];
		Destination[3] = kOpMovEaxImm32;
		*ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;

		// Direct syscall: 0F 05 (SYSCALL) at the opcode slot, then a RET.
		Destination[SC_STUB_OFFSET_SYSCALL] = kOpSyscall0;
		Destination[SC_STUB_OFFSET_SYSCALL + 1] = kOpSyscall1;
		Destination[SC_STUB_OFFSET_SYSCALL + 2] = kOpRet;

		FillNoOpTail(Destination + SC_STUB_TAIL_INDIRECT, SC_STUB_SIZE - SC_STUB_TAIL_INDIRECT, Service);
		return true;
	}

	// Vector 7: emit a sampled remote stub -- prologue + service, then the 167-byte capture-only
	// sampler block, then the gadget jmp, NOP-padded to SC_STUB_SIZE_SAMPLED. RingBase / SysIdxAddr
	// are the target addresses of VERIFIABLE_EXEC_TELEMETRY::SyscallSamples / ::SyscallSampleIndex.
	// The block captures 8 real-stack frames and advances the ring index; it does not pivot the stack.
	bool WriteSampledStub(BYTE * Destination, DWORD Service, ULONG_PTR GadgetSlotAddress, ULONG_PTR StubAddress,
		ULONG_PTR RingBase, ULONG_PTR SysIdxAddr, BYTE FunctionId, bool GadgetHealthy)
	{
		if (!Destination || !StubAddress || !RingBase || !SysIdxAddr)
		{
			return false;
		}

		const DWORD mix = (Service * 2654435761u) ^ (Service >> 13);
		const BYTE * prologue = (mix & 1u) ? kPrologueB : kPrologueA;
		Destination[0] = prologue[0];
		Destination[1] = prologue[1];
		Destination[2] = prologue[2];
		Destination[3] = kOpMovEaxImm32;
		*ReCa<DWORD *>(Destination + SC_STUB_OFFSET_SERVICE) = Service;

		memcpy(Destination + SC_STUB_OFFSET_SAMPLE, kSampleBlockRaw, SC_SAMPLE_BLOCK_SIZE);

		// Fill the three rip-relative disp32 fields. disp = target - (StubAddress + next_instr_off).
		const auto FillDisp = [&](size_t block_field_off, ULONG_PTR Target, size_t next_stub_off) -> bool
		{
			const LONGLONG d = static_cast<LONGLONG>(Target) - static_cast<LONGLONG>(StubAddress + next_stub_off);
			if (d < INT32_MIN || d > INT32_MAX)
			{
				return false;
			}

			*ReCa<LONG *>(Destination + SC_STUB_OFFSET_SAMPLE + block_field_off + 3) = static_cast<LONG>(d);
			return true;
		};

		if (!FillDisp(kSampleOffSysIdxLoad,  SysIdxAddr, kSampleNextSysIdxLoad))  return false;
		if (!FillDisp(kSampleOffRingLea,     RingBase,   kSampleNextRingLea))     return false;
		if (!FillDisp(kSampleOffSysIdxStore, SysIdxAddr, kSampleNextSysIdxStore)) return false;

		Destination[SC_STUB_OFFSET_SAMPLE + kSampleOffFuncId] = FunctionId;

		// Tail after the sampler block: either the gadget jmp (healthy) or a direct 0F 05; ret.
		if (GadgetHealthy)
		{
			const LONGLONG delta = static_cast<LONGLONG>(GadgetSlotAddress)
				- static_cast<LONGLONG>(StubAddress + SC_STUB_TAIL_SAMPLED);

			if (delta < INT32_MIN || delta > INT32_MAX)
			{
				return false;
			}

			Destination[SC_STUB_OFFSET_SAMPLED_SYSCALL] = kOpJmpRip0;
			Destination[SC_STUB_OFFSET_SAMPLED_SYSCALL + 1] = kOpJmpRip1;
			*ReCa<LONG *>(Destination + SC_STUB_OFFSET_SAMPLED_SYSCALL + 2) = static_cast<LONG>(delta);

			FillNoOpTail(Destination + SC_STUB_TAIL_SAMPLED, SC_STUB_SIZE_SAMPLED - SC_STUB_TAIL_SAMPLED, Service);
		}
		else
		{
			Destination[SC_STUB_OFFSET_SAMPLED_SYSCALL] = kOpSyscall0;
			Destination[SC_STUB_OFFSET_SAMPLED_SYSCALL + 1] = kOpSyscall1;
			Destination[SC_STUB_OFFSET_SAMPLED_SYSCALL + 2] = kOpRet;

			FillNoOpTail(Destination + SC_STUB_OFFSET_SAMPLED_SYSCALL + 3,
				SC_STUB_SIZE_SAMPLED - (SC_STUB_OFFSET_SAMPLED_SYSCALL + 3), Service);
		}

		return true;
	}

bool BuildPool()
{
	void * gadget = SyscallGadgetAddress();
	SC_LOG_INFO("Building Syscall Stub Pool (%zu Entries, %u Bytes Each)...", kSyscallTableCount, SC_STUB_SIZE);



	for (size_t i = 0; i < kSyscallTableCount; ++i)
	{
		g_SyscallTable[i].Stub = nullptr;
	}



	// Vector 7: HallWatch — re-read the chosen gadget's first two bytes before relying on it.
	const bool gadget_healthy = gadget &&
		ReCa<const BYTE *>(gadget)[0] == kOpSyscall0 &&
		ReCa<const BYTE *>(gadget)[1] == kOpSyscall1;

	if (!gadget_healthy)
	{
		SC_LOG_WARN("HallWatch Fallback Engaged: Gadget %p First Two Bytes = %02X %02X (Not 0F 05); Using Direct Stubs (Detectable)",
			gadget,
			gadget ? static_cast<unsigned>(ReCa<const BYTE *>(gadget)[0]) : 0,
			gadget ? static_cast<unsigned>(ReCa<const BYTE *>(gadget)[1]) : 0);
	}

	BYTE * Pool = ReCa<BYTE *>(VirtualAlloc(nullptr, kStubAreaSize + 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!Pool)
	{
		SC_LOG_ERR("VirtualAlloc Failed For Stub Pool");
		return false;
	}




	BYTE * const GadgetSlot = Pool + kStubAreaSize;





	if (gadget_healthy)
	{
		const ptrdiff_t slot_delta = GadgetSlot - Pool;
		if (slot_delta <= 0 || slot_delta >= INT32_MAX || !gadget)
		{
			for (size_t i = 0; i < kSyscallTableCount; ++i)
			{
				g_SyscallTable[i].Stub = nullptr;
			}

			VirtualFree(Pool, 0, MEM_RELEASE);
			SC_LOG_ERR("Stub Pool Layout Invalid Or ntdll Syscall Gadget Unavailable");
			return false;
		}
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

		if (!gadget_healthy)
		{
			// HallWatch fallback: direct 0F 05 embedded in the stub (detectable).
			if (!WriteDirectStub(slot, Entry.Service))
			{
				continue;
			}

			Entry.Stub = slot;
			++Written;
			continue;
		}

		if (!WriteStub(slot, Entry.Service, gadget, reinterpret_cast<ULONG_PTR>(GadgetSlot),
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

	if (gadget_healthy)
	{
		*ReCa<void **>(GadgetSlot) = gadget;
	}

	// Vector 7: frame synthesis — write the synthetic UNWIND_INFO into the pool's trailing
	// bytes while the region is still PAGE_READWRITE. The RX protection below would make
	// this write fault with 0xC0000005, so the write must precede it.
	struct UNWIND_INFO_LOCAL
	{
		uint16_t Version;
		uint16_t Flags;
		uint16_t CountOfCodes;
		uint16_t FrameSize;
	};

	constexpr DWORD kUnwindOffset = kStubAreaSize + 8;
	*ReCa<UNWIND_INFO_LOCAL *>(Pool + kUnwindOffset) = UNWIND_INFO_LOCAL{
		1, // Version
		0, // Flags
		0, // CountOfCodes
		0  // FrameSize = 0 (stubs don't push a frame)
	};

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

	// Vector 7: frame synthesis — register a synthetic .pdata table for the stub pool so a
	// stack walker resolves the stub addresses (not Ameger's private RX pool).
	{
		// The synthetic UNWIND_INFO (and kUnwindOffset) are written earlier, while the pool is
		// still writable. Here we register a synthetic .pdata table so the stack walker resolves
		// the stub addresses (not Ameger's private RX pool).
		std::vector<RUNTIME_FUNCTION> func_table;
		func_table.reserve(Written);
		for (size_t i = 0; i < kSyscallTableCount; ++i)
		{
			if (g_SyscallTable[i].Stub != nullptr)
			{
				const DWORD start = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(g_SyscallTable[i].Stub) -
					reinterpret_cast<ULONG_PTR>(Pool));
				func_table.push_back(RUNTIME_FUNCTION{
					start,
					start + SC_STUB_SIZE,
					kUnwindOffset
				});
			}
		}

		auto rtl_add_name = XOR_STR_A("RtlAddFunctionTable");
		auto ntdll_h = GetModuleHandleW(XOR_STR_W(L"ntdll.dll").get());
		auto add_fn = ReCa<BOOL(WINAPI *)(RUNTIME_FUNCTION *, DWORD, DWORD64)>
			(GetProcAddress(ntdll_h, rtl_add_name.get()));
		if (add_fn)
		{
			const BOOL added = add_fn(func_table.data(), static_cast<DWORD>(func_table.size()),
				static_cast<DWORD64>(reinterpret_cast<ULONG_PTR>(Pool)));
			SC_LOG_INFO("Frame Synthesis: %u Synthetic .pdata Entries Registered (Base %p) = %s",
				static_cast<unsigned>(func_table.size()), Pool, added ? "OK" : "FAILED");
		}
		else
		{
			SC_LOG_WARN("Frame Synthesis: %s Unavailable; Walker Resolution Unavailable", rtl_add_name.get());
		}
	}

	g_SyscallPool.store(Pool, std::memory_order_release);

	SC_LOG_OK("Stub Pool Built: %u/%zu Stubs At %p (RX)", Written, kSyscallTableCount, Pool);
	return true;
}
}

size_t SyscallGadgetPoolCount()
{
	FindSyscallGadgetPool();
	return g_SyscallGadgetPoolCount;
}

void * SyscallGadgetAt(size_t Index)
{
	FindSyscallGadgetPool();
	if (Index >= g_SyscallGadgetPoolCount)
	{
		return nullptr;
	}

	return g_SyscallGadgetPool[Index].Addr;
}

void * SyscallGadgetAddress()
{
	// Pick a gadget from the verified pool using the per-instance seeded PRNG (randomization across calls).
	void * pick = SyscallGadgetPick();
	if (pick)
	{
		g_SyscallGadget = pick;
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
				catch (const std::bad_alloc &)
				{



					LOG(2, "Syscall: The Harvest Table Could Not Grow; One Service Was Left Unresolved\n");
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

	// Vector 7: sampled stubs place the 167-byte sampler block at SC_STUB_OFFSET_SAMPLE,
	// so the syscall opcode (the gadget jmp, or a direct 0F 05 under the HallWatch fallback)
	// lives at SC_STUB_OFFSET_SAMPLED_SYSCALL instead of SC_STUB_OFFSET_SYSCALL.
	const bool sampled_layout = memcmp(Bytes + SC_STUB_OFFSET_SAMPLE, kSampleBlockRaw, 3) == 0;
	const size_t syscall_off = sampled_layout ? SC_STUB_OFFSET_SAMPLED_SYSCALL : SC_STUB_OFFSET_SYSCALL;

	const BYTE op0 = Bytes[syscall_off];
	const BYTE op1 = Bytes[syscall_off + 1];




	const bool indirect = (op0 == kOpJmpRip0 && op1 == kOpJmpRip1);
	const bool direct = (op0 == kOpSyscall0 && op1 == kOpSyscall1);

	if (!indirect && !direct)
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



			const ULONG Required = Size > 0x10000 ? 0x10000 : Size;

			const SIZE_T Attempted = Scratch.size();
			const ULONGLONG Grown = Attempted ? static_cast<ULONGLONG>(Attempted) * 2 : 0x800;
			const ULONGLONG Next = Grown > 0x10000 ? 0x10000 : Grown;

			Size = Next >= Required ? static_cast<ULONG>(Next) : Required;
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

DWORD BuildSyscallStubs(BYTE * Destination, SIZE_T DestinationSize, const DWORD * NameHashes, DWORD Count, ULONG_PTR RemoteBase, ULONG_PTR RingBase, ULONG_PTR SysIdxAddr, VERIFIABLE_EXEC_TELEMETRY * pTelemetryOut, ULONG_PTR TargetNtdllBase)
{
	// Vector 7: RingBase/SysIdxAddr non-zero -> emit the sampled variant (SC_STUB_SIZE_SAMPLED).
	const bool sampled = (RingBase != 0 && SysIdxAddr != 0);
	const SIZE_T stub_stride = sampled ? SC_STUB_SIZE_SAMPLED : SC_STUB_SIZE;
	const SIZE_T stub_bytes = static_cast<SIZE_T>(Count) * stub_stride;


	if (!Destination || !NameHashes || !Count || DestinationSize < stub_bytes + sizeof(void *))
	{
		return 0;
	}

	// pTelemetryOut / TargetNtdllBase are unused by the capture-only sampler. They are kept in the
	// signature so the ManualMapping call site -- and the later Tier 2 re-application -- do not change.
	(void)pTelemetryOut;
	(void)TargetNtdllBase;

	if (!g_SyscallPoolReady.load(std::memory_order_acquire))
	{
		if (!SyscallResolveAll())
		{
			return 0;
		}
	}

	EnsureLock();
	SyscallLockGuard Guard;






	void * gadget = SyscallGadgetAddress();
	if (!gadget)
	{
		SC_LOG_ERR("Remote Syscall Stubs Require The ntdll Syscall Gadget");
		return 0;
	}

	// Vector 7: HallWatch — re-read the gadget's first two bytes; if not 0F 05, use direct stubs.
	const bool gadget_healthy =
		ReCa<const BYTE *>(gadget)[0] == kOpSyscall0 &&
		ReCa<const BYTE *>(gadget)[1] == kOpSyscall1;

	if (!gadget_healthy)
	{
		SC_LOG_WARN("HallWatch Fallback Engaged (Remote Stubs): Gadget %p Bytes = %02X %02X (Not 0F 05); Direct Stubs (Detectable)",
			gadget,
			static_cast<unsigned>(ReCa<const BYTE *>(gadget)[0]),
			static_cast<unsigned>(ReCa<const BYTE *>(gadget)[1]));
	}

	// Capture-only sampler: no fake-stack pivot, no ret-gadget scan, no rebase.
	// (Tier 2 stack spoof is deferred -- the block samples the real stack.)

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

			BYTE * slot = Destination + (i * stub_stride);

			const ULONG_PTR stub_address = RemoteBase
				? (RemoteBase + static_cast<ULONG_PTR>(i) * stub_stride)
				: reinterpret_cast<ULONG_PTR>(slot);

			if (sampled)
			{
				// Vector 7: capture-only sampler block + gadget jmp (direct 0F 05; ret on HallWatch fallback).
				if (!WriteSampledStub(slot, g_SyscallTable[j].Service, gadget_slot_address, stub_address,
					RingBase, SysIdxAddr, static_cast<BYTE>(i), gadget_healthy))
				{
					SC_LOG_ERR("Sampled Remote Syscall Stub %u Displacement Out Of Range", i);
					break;
				}
			}
			else if (!gadget_healthy)
			{
				// HallWatch fallback: direct 0F 05 embedded in the stub (detectable).
				if (!WriteDirectStub(slot, g_SyscallTable[j].Service))
				{
					break;
				}
			}
			else
			{
				if (!WriteStub(slot, g_SyscallTable[j].Service, gadget, gadget_slot_address, stub_address))
				{
					SC_LOG_ERR("Remote Syscall Stub %u Displacement Out Of Range", i);
					break;
				}
			}

			if (SyscallServiceOfStub(slot) == 0)
			{
				break;
			}

			++Written;
			break;
		}
	}

	if (Written && gadget_healthy)
	{
		*reinterpret_cast<void **>(gadget_slot_local) = gadget;
	}

	return Written;
}
