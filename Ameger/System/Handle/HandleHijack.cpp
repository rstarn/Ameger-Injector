#include "Core/Utility/Header/PrecompiledHeader.h"

#include <TlHelp32.h>

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include "Core/Foundation/Primitives/ResourceGuard.h"
#include "Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "Core/Utility/Tools/Tools.h"
#include "System/Handle/HandleHijack.h"
#include "Native/Syscall.h"

namespace
{
	constexpr ULONG kSystemExtendedHandleInformation = 64;
	constexpr ULONG kSystemHandleInformation = 16;

	constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

	constexpr size_t kInitialEnumBytes = 1 << 20;
	constexpr size_t kMaxEnumBytes = 64ULL * 1024ULL * 1024ULL;

	constexpr size_t kMaxForeignOwners = 16;
	// The scan is bounded: at most this many foreign processes are opened and
	// at most this many duplication attempts are made, so a machine with a
	// very large handle table cannot turn the scan into an unbounded loop.
	constexpr size_t kMaxDupAttempts = 4096;

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL
	{
		PVOID Object;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	};

	struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL
	{
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
	};

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY
	{
		USHORT UniqueProcessId;
		USHORT CreatorBackTraceIndex;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	};

	struct SYSTEM_HANDLE_INFORMATION_LEGACY
	{
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY Handles[1];
	};

	using f_NtQuerySystemInformationLocal = NTSTATUS(__stdcall *)(ULONG, void *, ULONG, ULONG *);
	using f_NtDuplicateObjectLocal = NTSTATUS(__stdcall *)(HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG);

	struct NtdllHandles
	{
		f_NtQuerySystemInformationLocal NtQuerySystemInformation = nullptr;
		f_NtDuplicateObjectLocal NtDuplicateObject = nullptr;
	};

	__forceinline bool NtOk(NTSTATUS Status)
	{
		return Status >= 0;
	}

	bool ResolveNtdll(NtdllHandles & Out)
	{
		// The handle enumeration and the duplication both go through the syscall
		// layer, so the scan does not show up in the import table of this
		// module.
		Out.NtQuerySystemInformation = ReCa<f_NtQuerySystemInformationLocal>(SyscallStub(SC_NtQuerySystemInformation));
		Out.NtDuplicateObject = ReCa<f_NtDuplicateObjectLocal>(SyscallStub(SC_NtDuplicateObject));

		return Out.NtQuerySystemInformation && Out.NtDuplicateObject;
	}

	bool EnableSeDebugPrivilege()
	{
		HANDLE RawToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &RawToken))
		{
			return false;
		}

		UniqueHandle Token(RawToken);

		LUID Luid{ 0 };

		if (!LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &Luid))
		{
			return false;
		}

		TOKEN_PRIVILEGES Privileges{ 0 };
		Privileges.PrivilegeCount = 1;
		Privileges.Privileges[0].Luid = Luid;
		Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(Token.get(), FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr))
		{
			return false;
		}

		return GetLastError() == ERROR_SUCCESS;
	}

	std::atomic<USHORT> g_CachedProcessType{ 0 };
	std::atomic<USHORT> g_CachedThreadType{ 0 };

	// Every scan that may open foreign owners runs inside one
	// SeDebugPrivilegeScope, and the privilege is given back only by the last
	// scope that exits. The previous once-per-process guard let one scan's
	// teardown revoke the privilege while a concurrent scan was still using
	// it, and it skipped the enable for a later scan whenever an earlier scan
	// had already been through here - which left that later scan running
	// without the privilege at all.
	std::atomic<LONG> g_SeDebugScopes{ 0 };
	std::atomic<bool> g_SeDebugEnabled{ false };

	void EnsureSeDebugPrivilege()
	{
		if (EnableSeDebugPrivilege())
		{
			g_SeDebugEnabled.store(true, std::memory_order_release);
		}
	}

	void DisableSeDebugPrivilege()
	{
		HANDLE RawToken = nullptr;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &RawToken))
		{
			UniqueHandle Token(RawToken);

			LUID Luid{ 0 };
			if (LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &Luid))
			{
				// Disabling (clearing SE_PRIVILEGE_ENABLED) rather than
				// SE_PRIVILEGE_REMOVED: removal is irreversible for the token,
				// so a later scan could never re-enable it, and a token with
				// the privilege present but disabled is exactly the state an
				// elevated process is born with.
				TOKEN_PRIVILEGES Privileges{ 0 };
				Privileges.PrivilegeCount = 1;
				Privileges.Privileges[0].Luid = Luid;
				Privileges.Privileges[0].Attributes = 0;

				if (AdjustTokenPrivileges(Token.get(), FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr))
				{
					g_SeDebugEnabled.store(false, std::memory_order_release);
				}
			}
		}
	}

	class SeDebugPrivilegeScope
	{
	public:
		SeDebugPrivilegeScope()
		{
			g_SeDebugScopes.fetch_add(1, std::memory_order_acq_rel);
		}

		~SeDebugPrivilegeScope()
		{
			const LONG remaining = g_SeDebugScopes.fetch_sub(1, std::memory_order_acq_rel) - 1;
			if (remaining == 0 && g_SeDebugEnabled.load(std::memory_order_acquire))
			{
				DisableSeDebugPrivilege();
			}
		}

		SeDebugPrivilegeScope(const SeDebugPrivilegeScope &) = delete;
		SeDebugPrivilegeScope & operator=(const SeDebugPrivilegeScope &) = delete;
	};

	struct EnumSnapshot
	{
		std::vector<BYTE> Buffer;
		bool Extended = true;
	};

	DWORD QueryHandleSnapshot(const NtdllHandles & Ntdll, ULONG InfoClass, bool Extended, EnumSnapshot & Out, NTSTATUS & LastStatus)
	{
		size_t Size = kInitialEnumBytes;
		LastStatus = 0;

		for (;;)
		{
			try
			{
				Out.Buffer.resize(Size);
			}
			catch (...)
			{
				return INJ_ERR_OUT_OF_MEMORY_NEW;
			}

			ULONG Returned = 0;
			const NTSTATUS Status = Ntdll.NtQuerySystemInformation(InfoClass, Out.Buffer.data(),
				static_cast<ULONG>(Size), &Returned);
			LastStatus = Status;

			if (Status == kStatusInfoLengthMismatch)
			{
				if (Size >= kMaxEnumBytes)
				{
					return INJ_ERR_OUT_OF_MEMORY_EXT;
				}

				size_t Next = Returned > 0 ? (static_cast<size_t>(Returned) + 0x10000) : (Size * 2);
				if (Next <= Size)
				{
					Next = Size * 2;
				}
				if (Next > kMaxEnumBytes)
				{
					Next = kMaxEnumBytes;
				}

				Size = Next;
				continue;
			}

			if (!NtOk(Status))
			{
				return INJ_ERR_HANDLE_HIJACK_FAILED;
			}

			Out.Extended = Extended;
			return INJ_ERR_SUCCESS;
		}
	}

	DWORD QueryAnySnapshot(const NtdllHandles & Ntdll, EnumSnapshot & Out, NTSTATUS & LastStatus)
	{
		DWORD Result = QueryHandleSnapshot(Ntdll, kSystemExtendedHandleInformation, true, Out, LastStatus);
		if (Result == INJ_ERR_SUCCESS)
		{
			return Result;
		}

		if (Result == INJ_ERR_OUT_OF_MEMORY_NEW || Result == INJ_ERR_OUT_OF_MEMORY_EXT)
		{
			return Result;
		}

		return QueryHandleSnapshot(Ntdll, kSystemHandleInformation, false, Out, LastStatus);
	}

	bool FindOwnEntryType(const EnumSnapshot & Snapshot, DWORD SelfPid, ULONG_PTR HandleValue, USHORT & TypeIndexOut)
	{
		if (Snapshot.Extended)
		{
			if (Snapshot.Buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL))
			{
				return false;
			}

			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
			if (Header >= Snapshot.Buffer.size())
			{
				return false;
			}

			size_t Capacity = (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (static_cast<DWORD>(Entry.UniqueProcessId) == SelfPid && Entry.HandleValue == HandleValue)
				{
					TypeIndexOut = Entry.ObjectTypeIndex;
					return true;
				}
			}
		}
		else
		{
			if (Snapshot.Buffer.size() < sizeof(SYSTEM_HANDLE_INFORMATION_LEGACY))
			{
				return false;
			}

			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_LEGACY *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
			if (Header >= Snapshot.Buffer.size())
			{
				return false;
			}

			size_t Capacity = (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (static_cast<DWORD>(Entry.UniqueProcessId) == SelfPid &&
					static_cast<ULONG_PTR>(Entry.HandleValue) == HandleValue)
				{
					TypeIndexOut = static_cast<USHORT>(Entry.ObjectTypeIndex);
					return true;
				}
			}
		}

		return false;
	}
	// A donor handle is only accepted once it has been proven to work.
	// The probe has three strengths, selected by an environment variable so
	// the behaviour can be varied per machine without a rebuild:
	//
	//   Reserve  - allocate and release a page in the target (default)
	//   Protect  - re-apply the current protection to the first committed page
	//   None     - trust the handle without probing it
	//
	// The probe is deliberately cheap. It proves that the handle carries the
	// rights the injection needs without leaving anything behind.
	enum class VM_PROBE_POLICY
	{
		Reserve = 0,
		Protect = 1,
		None = 2
	};

	VM_PROBE_POLICY GetVmProbePolicy()
	{
		static const VM_PROBE_POLICY policy = []() -> VM_PROBE_POLICY
		{
			wchar_t buffer[16]{ 0 };
			auto env_name = XOR_STR_W(L"AMEGER_VM_PROBE");
			const DWORD got = GetEnvironmentVariableW(env_name.get(), buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])) - 1);

			if (got == 0 || got >= static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])) - 1)
			{
				return VM_PROBE_POLICY::Reserve;
			}

			const std::wstring value = LowercaseW(buffer);

			if (value == L"protect")
			{
				return VM_PROBE_POLICY::Protect;
			}

			if (value == L"none")
			{
				return VM_PROBE_POLICY::None;
			}

			if (value != L"reserve")
			{
				LOG(1, XOR_STR_A("HandleAcq: Unknown AMEGER_VM_PROBE Value, Using The Default (Reserve)\n").get());
			}

			return VM_PROBE_POLICY::Reserve;
		}();

		return policy;
	}

	bool ProbeQueryUsable(HANDLE Candidate, DWORD TargetPid)
	{
		if (ScGetProcessId(Candidate) != TargetPid)
		{
			return false;
		}

		wchar_t Name[MAX_PATH * 2]{ 0 };
		return ScGetProcessImageName(Candidate, Name, static_cast<DWORD>(sizeof(Name) / sizeof(Name[0]))) != 0;
	}

	bool ProbeVmOperation(HANDLE Candidate)
	{
		switch (GetVmProbePolicy())
		{
			case VM_PROBE_POLICY::None:
			{
				return true;
			}

			case VM_PROBE_POLICY::Protect:
			{
				// Re-applying the current protection is a no-op for the page, but it
				// is a real test: a handle without PROCESS_VM_OPERATION cannot
				// call it at all.
				MEMORY_BASIC_INFORMATION info{ 0 };
				if (!VirtualQueryEx(Candidate, nullptr, &info, sizeof(info)) || info.State != MEM_COMMIT)
				{
					return false;
				}

				if (!(info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
				{
					return false;
				}

				ULONG old_protect = 0;
				return ScProtectMemory(Candidate, info.BaseAddress, info.RegionSize, info.Protect, &old_protect);
			}

			case VM_PROBE_POLICY::Reserve:
			default:
			{
				break;
			}
		}
			// A page that can be reserved and released proves the handle carries
			// the virtual memory rights the mapping needs.
			void * Page = ScAllocateMemory(Candidate, 0x1000, PAGE_NOACCESS);
			if (!Page)
			{
				return false;
			}

			// The release can fail transiently, and a page left behind in the
			// target is a census-visible artifact, so it is retried. If it
			// still fails the rights are proven regardless - the allocation
			// itself required them - and the retained page is only reported.
			for (int attempt = 0; attempt < 3; ++attempt)
			{
				if (ScFreeMemory(Candidate, Page))
				{
					return true;
				}

				if (attempt + 1 < 3)
				{
					Sleep(1);
				}
			}

			LOG(1, "ProbeVmOperation: Release Failed Three Times; Page Retained In Target\n");

			return true;
	}

	bool VerifyProcessDonor(HANDLE Candidate, DWORD TargetPid)
	{
		if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetPid)
		{
			return false;
		}

		return ProbeQueryUsable(Candidate, TargetPid) && ProbeVmOperation(Candidate);
	}

	bool VerifyThreadDonor(HANDLE Candidate, DWORD TargetPid, DWORD TargetTid)
	{
		if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetTid)
		{
			return false;
		}

		return ScGetThreadId(Candidate) == TargetTid && ScGetProcessIdOfThread(Candidate) == TargetPid;
	}

	// The owners a donor handle can be taken from are visible in the audit
	// trail of every endpoint that watches handle access, and the credential
	// and session stores are watched more closely than anything else on the
	// system. A donor taken from one of them is the loudest signal this scan
	// can produce, so those owners are passed over.
	//
	// The list is built once per scan. It can be replaced at run time with a
	// comma separated set of image names, so it can be tuned without a
	// rebuild.
	class DonorOwnerBlocklist
	{
		std::vector<std::wstring> m_Names;

	public:
		DonorOwnerBlocklist()
		{
			wchar_t override_buffer[1024] = { 0 };
			const auto override_name = XOR_STR_W(L"AMEGER_DONOR_OWNER_BLOCKLIST");
			const DWORD override_length = GetEnvironmentVariableW(override_name.get(),
				override_buffer, static_cast<DWORD>(std::size(override_buffer)));
			if (override_length && override_length < std::size(override_buffer))
			{
				std::wstring current;
				for (DWORD i = 0; i <= override_length; ++i)
				{
					const wchar_t c = override_buffer[i];
					if (c == L',' || c == L'\0')
					{
						if (!current.empty())
						{
							m_Names.push_back(current);
						}
						current.clear();
					}
					else
					{
						current.push_back(c);
					}
				}
			}
			else
			{
				static const wchar_t * const kDefaultExcluded[] =
				{
					L"lsass.exe",
					L"csrss.exe",
					L"winlogon.exe",
					L"services.exe",
					L"smss.exe",
					L"SecurityHealthService.exe",
					L"MsMpEng.exe",
					L"dwm.exe",
					L"conhost.exe",
					L"fontdrvhost.exe",
					L"spoolsv.exe",
					L"wmiprvse.exe",
				};
				for (const wchar_t * candidate : kDefaultExcluded)
				{
					m_Names.emplace_back(candidate);
				}
			}
		}

		bool Excludes(const wchar_t * image_name) const
		{
			if (!image_name || !*image_name)
			{
				return false;
			}
			for (const std::wstring & candidate : m_Names)
			{
				if (_wcsicmp(image_name, candidate.c_str()) == 0)
				{
					return true;
				}
			}
			return false;
		}
	};

	// The image name of every running process, taken once from a single
	// snapshot. It lets a donor owner be recognised by name without opening
	// it for anything, which is the whole point of the block list.
	class ProcessImageIndex
	{
		std::unordered_map<DWORD, std::wstring> m_Names;

	public:
		void Build()
		{
			m_Names.clear();

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot == INVALID_HANDLE_VALUE)
			{
				return;
			}

			PROCESSENTRY32W entry{};
			entry.dwSize = sizeof(entry);
			if (Process32FirstW(snapshot, &entry))
			{
				do
				{
					if (entry.th32ProcessID)
					{
						m_Names[entry.th32ProcessID] = entry.szExeFile;
					}
				} while (Process32NextW(snapshot, &entry));
			}

			CloseHandle(snapshot);
		}

		const wchar_t * Find(DWORD pid) const
		{
			const auto it = m_Names.find(pid);
			if (it == m_Names.end())
			{
				return nullptr;
			}
			return it->second.c_str();
		}
	};

	HANDLE OpenOwnerCached(std::vector<std::pair<DWORD, UniqueHandle>> & Owners, DWORD OwnerPid)
	{
		for (auto & Owner : Owners)
		{
			if (Owner.first == OwnerPid)
			{
				return Owner.second ? Owner.second.get() : nullptr;
			}
		}

		UniqueHandle Owner(ScOpenProcess(OwnerPid, PROCESS_DUP_HANDLE));
		if (!Owner)
		{
			EnsureSeDebugPrivilege();
			Owner.reset(ScOpenProcess(OwnerPid, PROCESS_DUP_HANDLE));
		}

		HANDLE Raw = Owner ? Owner.get() : nullptr;
		if (!Raw)
		{
			return nullptr;
		}
		// The owner handles are cached so a process that owns many candidate
		// handles is only opened once.
		try
		{
			Owners.reserve(Owners.size() + 1);
			Owners.emplace_back(OwnerPid, UniqueHandle(Raw));
		}
		catch (...)
		{
			return nullptr;
		}

		Owner.release();

		return Raw;
	}

	DWORD ScanSnapshot(const NtdllHandles & Ntdll, const EnumSnapshot & Snapshot, DWORD SelfPid,
		DWORD TargetPid, DWORD TargetTid, bool ThreadScan, USHORT WantedType, bool HaveType, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats & Detail)
	{
		Out = nullptr;

		Detail.Examined = 0;
		Detail.DonorPid = 0;
		Detail.GrantedAccess = 0;
		Detail.OwnersOpened = 0;
		Detail.DupDenied = 0;
		Detail.VerifyRejected = 0;
		Detail.DonorHandle = 0;
		Detail.NewHandle = 0;
		Detail.TotalHandles = 0;
		Detail.BudgetSkipped = 0;
		Detail.Success = 0;
		Detail.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;

		// Probe method uses the documented encoding (0 = None, 1 = Reserve,
		// 2 = Protect, 3 = Roundtrip). A thread scan only verifies query rights,
		// so it reports None; a process scan reports the policy that
		// ProbeVmOperation will actually apply.
		if (ThreadScan)
		{
			Detail.ProbeMethod = 0;
		}
		else
		{
			switch (GetVmProbePolicy())
			{
			case VM_PROBE_POLICY::Protect:
				Detail.ProbeMethod = 2;
				break;

			case VM_PROBE_POLICY::None:
				Detail.ProbeMethod = 0;
				break;

			case VM_PROBE_POLICY::Reserve:
			default:
				Detail.ProbeMethod = 1;
				break;
			}
		}

		std::vector<std::pair<DWORD, UniqueHandle>> Owners;

		// The image names are collected once, before anything is opened. A
		// donor owner that is on the block list is passed over before that
		// owner process is ever opened.
		ProcessImageIndex ImageIndex;
		ImageIndex.Build();
		const DonorOwnerBlocklist Blocklist;
		size_t BlocklistedOwners = 0;

		std::unordered_set<ULONG_PTR> WrongObjects;
		size_t Examined = 0;
		size_t Duplicated = 0;
		size_t DupDenied = 0;
		size_t VerifyRejected = 0;
		size_t DupAttempts = 0;
		size_t BudgetSkipped = 0;
		bool BudgetHit = false;
		DWORD FoundDonorPid = 0;
		DWORD FoundGranted = 0;
		DWORD FoundDonorHandle = 0;
		DWORD FoundNewHandle = 0;

		const auto TryCandidate = [&](DWORD OwnerPid, ULONG_PTR HandleValue, PVOID Object) -> bool
		{
			if (DupAttempts >= kMaxDupAttempts)
			{

				++BudgetSkipped;
				BudgetHit = true;
				return false;
			}

			++DupAttempts;

			const HANDLE SourceValue = ReCa<HANDLE>(HandleValue);
			if (!SourceValue)
			{
				return false;
			}

			if (OwnerPid == SelfPid)
			{
				HANDLE DirectRaw = nullptr;
				if (!NtOk(Ntdll.NtDuplicateObject(GetCurrentProcess(), SourceValue, GetCurrentProcess(),
					&DirectRaw, DesiredAccess, 0, 0)) || !DirectRaw)
				{
					++DupDenied;
					if (DirectRaw)
					{
						CloseHandle(DirectRaw);
					}

					return false;
				}

				UniqueHandle Direct(DirectRaw);

				++Duplicated;
				const bool Ok = ThreadScan
					? VerifyThreadDonor(Direct.get(), TargetPid, TargetTid)
					: VerifyProcessDonor(Direct.get(), TargetPid);
				if (!Ok)
				{
					++VerifyRejected;
					if (Object)
					{
						WrongObjects.insert(ReCa<ULONG_PTR>(Object));
					}
					return false;
				}

				FoundDonorPid = OwnerPid;
				FoundGranted = DesiredAccess;
				FoundDonorHandle = static_cast<DWORD>(HandleValue);
				FoundNewHandle = PtrToUlong(Direct.get());
				Out = Direct.release();
				return true;
			}

			HANDLE Owner = nullptr;
			if (OwnerPid == TargetPid && TargetOwnerHandle)
			{
				Owner = TargetOwnerHandle;
			}
			else
			{
				if (OwnerPid != TargetPid)
				{
					// A donor from a process that watches handle access is
					// skipped before that process is opened. A skipped owner
					// was never verified, so it is not counted as a
					// verification failure.
					if (OwnerPid != SelfPid)
					{
						const wchar_t * owner_name = ImageIndex.Find(OwnerPid);
						if (Blocklist.Excludes(owner_name))
						{
							++BlocklistedOwners;
							return false;
						}
					}

					bool known = false;
					size_t foreign_opened = 0;
					for (auto & CachedOwner : Owners)
					{
						if (CachedOwner.first == OwnerPid)
						{
							known = true;
							break;
						}
						if (CachedOwner.first != TargetPid)
						{
							++foreign_opened;
						}
					}

					if (!known && foreign_opened >= kMaxForeignOwners)
					{
						// Opening an unbounded number of foreign processes would be
						// noisy and slow. The budget bounds how many are tried.
						++BudgetSkipped;
						return false;
					}
				}

				Owner = OpenOwnerCached(Owners, OwnerPid);
			}

			if (!Owner)
			{
				return false;
			}

			HANDLE DuplicatedRaw = nullptr;
			if (!NtOk(Ntdll.NtDuplicateObject(Owner, SourceValue, GetCurrentProcess(),
				&DuplicatedRaw, DesiredAccess, 0, 0)) || !DuplicatedRaw)
			{
				++DupDenied;
				if (DuplicatedRaw)
				{
					CloseHandle(DuplicatedRaw);
				}

				return false;
			}

			UniqueHandle DuplicatedHandle(DuplicatedRaw);

			++Duplicated;
			const bool Ok = ThreadScan
				? VerifyThreadDonor(DuplicatedHandle.get(), TargetPid, TargetTid)
				: VerifyProcessDonor(DuplicatedHandle.get(), TargetPid);
			if (!Ok)
			{
				++VerifyRejected;
				if (Object)
				{

					WrongObjects.insert(ReCa<ULONG_PTR>(Object));
				}
				return false;
			}

			FoundDonorPid = OwnerPid;
			FoundGranted = DesiredAccess;
			FoundDonorHandle = static_cast<DWORD>(HandleValue);
			FoundNewHandle = PtrToUlong(DuplicatedHandle.get());
			Out = DuplicatedHandle.release();
			return true;
		};

		struct Candidate
		{
			DWORD		OwnerPid;
			ULONG_PTR	HandleValue;
			PVOID		Object;
			ULONG		GrantedAccess;
		};

		std::vector<Candidate> Candidates;
		size_t TotalCount = 0;

		if (Snapshot.Extended)
		{
			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_EX_LOCAL *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			const size_t Capacity = Header < Snapshot.Buffer.size()
				? (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL)
				: 0;
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			TotalCount = Count;
			Candidates.reserve(Count);
			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (HaveType && Entry.ObjectTypeIndex != WantedType)
				{
					continue;
				}

				Candidates.push_back(Candidate{ static_cast<DWORD>(Entry.UniqueProcessId), Entry.HandleValue, Entry.Object, Entry.GrantedAccess });
			}
		}
		else
		{
			const auto * Info = ReCa<const SYSTEM_HANDLE_INFORMATION_LEGACY *>(Snapshot.Buffer.data());
			const size_t Header = offsetof(SYSTEM_HANDLE_INFORMATION_LEGACY, Handles);
			size_t Count = static_cast<size_t>(Info->NumberOfHandles);
			const size_t Capacity = Header < Snapshot.Buffer.size()
				? (Snapshot.Buffer.size() - Header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_LEGACY)
				: 0;
			if (Count > Capacity)
			{
				Count = Capacity;
			}

			TotalCount = Count;
			Candidates.reserve(Count);
			for (size_t Index = 0; Index < Count; ++Index)
			{
				const auto & Entry = Info->Handles[Index];
				if (HaveType && static_cast<USHORT>(Entry.ObjectTypeIndex) != WantedType)
				{
					continue;
				}

				Candidates.push_back(Candidate{ static_cast<DWORD>(Entry.UniqueProcessId),
					static_cast<ULONG_PTR>(Entry.HandleValue), Entry.Object, static_cast<ULONG>(Entry.GrantedAccess) });
			}
		}

		Detail.TotalHandles = static_cast<DWORD>(TotalCount);

		for (DWORD Pass = 0; Pass < 3 && !Out && !BudgetHit; ++Pass)
		{
			for (const auto & Entry : Candidates)
			{
				const bool is_target = Entry.OwnerPid == TargetPid;
				const bool is_self = Entry.OwnerPid == SelfPid;
				const bool belongs = Pass == 0 ? is_target
					: Pass == 1 ? (is_self && !is_target)
					: (!is_self && !is_target);
				if (!belongs)
				{
					continue;
				}

				if (Entry.Object && WrongObjects.find(ReCa<ULONG_PTR>(Entry.Object)) != WrongObjects.end())
				{
					continue;
				}
				// Only a handle whose granted access already covers what the
				// injection needs is worth duplicating. Checking the mask up
				// front avoids a duplication attempt per candidate.
				if ((Entry.GrantedAccess & DesiredAccess) != DesiredAccess)
				{
					continue;
				}

				++Examined;
				if (TryCandidate(Entry.OwnerPid, Entry.HandleValue, Entry.Object))
				{
					Detail.Examined = static_cast<DWORD>(Examined);
					Detail.DonorPid = FoundDonorPid;
					Detail.GrantedAccess = FoundGranted;
					Detail.DonorHandle = FoundDonorHandle;
					Detail.NewHandle = FoundNewHandle;
					Detail.OwnersOpened = static_cast<DWORD>(Owners.size());
					Detail.DupDenied = static_cast<DWORD>(DupDenied);
					Detail.VerifyRejected = static_cast<DWORD>(VerifyRejected);
					Detail.BudgetSkipped = static_cast<DWORD>(BudgetSkipped);
					Detail.Success = 1;
					Detail.FailCode = INJ_ERR_SUCCESS;
					Detail.SnapshotBytes = static_cast<DWORD>(Snapshot.Buffer.size() > 0xFFFFFFFF ? 0xFFFFFFFF : Snapshot.Buffer.size());
					LOG(1, "[Handle] [+] Donor Handle Acquired: Donor PID = %u | Donor Handle = 0x%08X\n", FoundDonorPid, FoundDonorHandle);
					LOG(1, "[Handle] [+] Duplicated Handle: Local = 0x%08X | Granted = 0x%08X\n", FoundNewHandle, FoundGranted);
					LOG(1, "[Handle] [*] Census: Total = %u | Examined = %llu | DupDenied = %llu | VerifyRejected = %llu | Owners = %llu | BudgetSkipped = %llu | Blocklisted = %llu\n",
						Detail.TotalHandles, (unsigned long long)Examined, (unsigned long long)DupDenied, (unsigned long long)VerifyRejected, (unsigned long long)Owners.size(), (unsigned long long)BudgetSkipped, (unsigned long long)BlocklistedOwners);
					return INJ_ERR_SUCCESS;
				}

				if (BudgetHit)
				{
					break;
				}
			}
		}

		LOG(1, XOR_STR_A("HandleAcq: No Donor (Examined %llu, Duplicated %llu, Filtered %d, Budget Hit %d, Blocklisted %llu)\n").get(),
			static_cast<unsigned long long>(Examined),
			static_cast<unsigned long long>(Duplicated),
			HaveType ? 1 : 0,
			BudgetHit ? 1 : 0,
			static_cast<unsigned long long>(BlocklistedOwners));

		Detail.Examined = static_cast<DWORD>(Examined);
		Detail.OwnersOpened = static_cast<DWORD>(Owners.size());
		Detail.DupDenied = static_cast<DWORD>(DupDenied);
		Detail.VerifyRejected = static_cast<DWORD>(VerifyRejected);
		Detail.BudgetSkipped = static_cast<DWORD>(BudgetSkipped);
		Detail.Success = 0;
		Detail.FailCode = INJ_ERR_HANDLE_HIJACK_FAILED;
		return INJ_ERR_HANDLE_HIJACK_FAILED;
	}

	DWORD HijackImpl(DWORD TargetPid, DWORD TargetTid, bool ThreadScan, DWORD DesiredAccess,
		HANDLE TargetOwnerHandle, HANDLE & Out, HijackStats * Detail)
	{
		Out = nullptr;

		HijackStats Local{ };
		Local.Attempted = 1;
		Local.Source = static_cast<DWORD>(HijackSource::Scan);

		SeDebugPrivilegeScope debug_privilege_scope;

		const auto Finish = [&](DWORD Code) -> DWORD
		{
			if (!Local.Success)
			{
				Local.FailCode = Code;
			}

			if (Detail)
			{
				*Detail = Local;
			}

			return Code;
		};

		if (!TargetPid || !DesiredAccess || (ThreadScan && !TargetTid))
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		NtdllHandles Ntdll{ };
		if (!ResolveNtdll(Ntdll))
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		const DWORD SelfPid = GetCurrentProcessId();
		if (!ThreadScan && TargetPid == SelfPid)
		{
			return Finish(INJ_ERR_HANDLE_HIJACK_FAILED);
		}

		USHORT WantedType = (ThreadScan ? g_CachedThreadType : g_CachedProcessType).load(std::memory_order_acquire);
		bool HaveType = WantedType != 0;

		UniqueHandle SelfProc;
		UniqueHandle SelfThread;
		if (!HaveType)
		{
			if (ThreadScan)
			{
				SelfThread.reset(ScOpenThread(GetCurrentThreadId(), THREAD_QUERY_LIMITED_INFORMATION));
			}
			else
			{
				SelfProc.reset(ScOpenProcess(SelfPid, PROCESS_QUERY_LIMITED_INFORMATION));
			}
		}

		EnumSnapshot Snap{ };
		NTSTATUS SnapStatus = 0;
		const DWORD SnapshotRet = QueryAnySnapshot(Ntdll, Snap, SnapStatus);
		if (SnapshotRet != INJ_ERR_SUCCESS)
		{
			Local.SnapStatus = static_cast<DWORD>(SnapStatus);
			return Finish(SnapshotRet);
		}

		Local.SnapStatus = static_cast<DWORD>(SnapStatus);

		if (!HaveType && !ThreadScan && SelfProc)
		{
			HaveType = FindOwnEntryType(Snap, SelfPid, ReCa<ULONG_PTR>(SelfProc.get()), WantedType);
		}
		else if (!HaveType && ThreadScan && SelfThread)
		{
			HaveType = FindOwnEntryType(Snap, SelfPid, ReCa<ULONG_PTR>(SelfThread.get()), WantedType);
		}

		if (HaveType)
		{
			(ThreadScan ? g_CachedThreadType : g_CachedProcessType).store(WantedType, std::memory_order_release);
		}
		else
		{
			LOG(1, XOR_STR_A("HandleAcq: Type Calibration Failed, Falling Back To Unfiltered Scan\n").get());
		}

		Local.Calibrated = HaveType ? 1 : 0;
		Local.SnapshotBytes = static_cast<DWORD>(Snap.Buffer.size() > 0xFFFFFFFF ? 0xFFFFFFFF : Snap.Buffer.size());
		LOG(1, "[Handle] [*] Handle Table Census: %llu Bytes | Calibrated = %d | Type = %u\n",
			(unsigned long long)Snap.Buffer.size(), HaveType ? 1 : 0, (unsigned)WantedType);

		const DWORD ScanRet = ScanSnapshot(Ntdll, Snap, SelfPid, TargetPid, TargetTid, ThreadScan, WantedType, HaveType, DesiredAccess, TargetOwnerHandle, Out, Local);
		if (Detail)
		{
			*Detail = Local;
		}

		return ScanRet;
	}
}

HijackStats g_ProcessHijackStats{ };
HijackStats g_ThreadHijackStats{ };

namespace
{

	// The block is published as a whole under one lock rather than a word at a
	// time: the export can be polled while a scan is still writing, and a
	// reader must see one run's fields or another's, never a mix of the two.
	SRWLOCK g_HijackStatsLock{ SRWLOCK_INIT };

	void StoreHijackStats(HijackStats & Dst, const HijackStats & Src)
	{
		AcquireSRWLockExclusive(&g_HijackStatsLock);
		Dst = Src;
		ReleaseSRWLockExclusive(&g_HijackStatsLock);
	}

	void LoadHijackStats(HijackStats & Src, HijackStats & Dst)
	{
		AcquireSRWLockShared(&g_HijackStatsLock);
		Dst = Src;
		ReleaseSRWLockShared(&g_HijackStatsLock);
	}
}

	bool ValidateProcessDonorHandle(HANDLE Candidate, DWORD TargetPid, DWORD DesiredAccess)
	{
	if (!Candidate || Candidate == INVALID_HANDLE_VALUE || !TargetPid)
	{
		return false;
	}

	const DWORD ActualPid = ScGetProcessId(Candidate);
	if (ActualPid != TargetPid)
	{
		LOG(1, "ValidateSponsor: PID Mismatch (Actual = %lu | Want = %lu)\n", ActualPid, TargetPid);
		return false;
	}

	wchar_t Name[MAX_PATH * 2]{ 0 };
	if (!ScGetProcessImageName(Candidate, Name, static_cast<DWORD>(sizeof(Name) / sizeof(Name[0]))))
	{
		LOG(1, "ValidateSponsor: Name Query Failed (PID = %lu)\n", TargetPid);
		return false;
	}

	if ((DesiredAccess & PROCESS_VM_OPERATION) && !ProbeVmOperation(Candidate))
	{
		return false;
	}

	return true;
}

	bool ProbeMemoryRoundtrip(HANDLE Candidate)
	{
	// A full round trip: allocate a page in the target, write a known byte,
	// read it back, and release the page. A handle that survives that is
	// usable for the injection, and the target is left exactly as it was.
		void * Page = ScAllocateMemory(Candidate, 0x1000, PAGE_READWRITE);
		if (!Page)
		{
			LOG(1, "ProbeRoundtrip: Alloc Failed\n");
			return false;
		}

		BYTE Written = 0xA5;
		BYTE Readout = 0;
		SIZE_T Done = 0;
		const bool Ok = ScWriteProcessMemory(Candidate, Page, &Written, sizeof(Written), &Done) && Done == sizeof(Written)
			&& ScReadProcessMemory(Candidate, Page, &Readout, sizeof(Readout), &Done) && Done == sizeof(Readout)
			&& Readout == Written;

		bool released = false;
		for (int attempt = 0; attempt < 2; ++attempt)
		{
			if (ScFreeMemory(Candidate, Page))
			{
				released = true;
				break;
			}

			if (attempt + 1 < 2)
			{
				Sleep(1);
			}
		}
		if (!released)
		{
			LOG(1, "ProbeRoundtrip: Release Failed Twice\n");
			return false;
		}

		if (!Ok)
		{
			LOG(1, "ProbeRoundtrip: Read/Write Mismatch\n");
		}

		return Ok;
	}

void ResetHijackStats()
{
	StoreHijackStats(g_ProcessHijackStats, HijackStats{});
	StoreHijackStats(g_ThreadHijackStats, HijackStats{});
}

void RecordHijackOutcome(const HijackStats & Stats, bool IsThread)
{
	StoreHijackStats(IsThread ? g_ThreadHijackStats : g_ProcessHijackStats, Stats);
}

void __stdcall GetLastHijackStats(HijackStats * ProcessOut, HijackStats * ThreadOut)
{
	EXPORT_FUNCTION("CoreAcqStats", __FUNCDNAME__)

	if (ProcessOut)
	{
		LoadHijackStats(g_ProcessHijackStats, *ProcessOut);
	}

	if (ThreadOut)
	{
		LoadHijackStats(g_ThreadHijackStats, *ThreadOut);
	}
}

DWORD HijackProcessHandle(DWORD TargetPid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)
{
	DWORD Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	try
	{
		Result = HijackImpl(TargetPid, 0, false, DesiredAccess, TargetOwnerHandle, OutHandle, Detail);
		if (Result == INJ_ERR_SUCCESS)
		{
			LOG(0, XOR_STR_A("HandleAcq: Acquired Process Handle For PID %lu\n").get(), TargetPid);
		}
	}
	catch (...)
	{
		LOG(0, "HijackProcessHandle: Unhandled Exception\n");
		OutHandle = nullptr;
		Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	return Result;
}

DWORD HijackThreadHandle(DWORD TargetPid, DWORD TargetTid, DWORD DesiredAccess, HANDLE & OutHandle, HijackStats * Detail, HANDLE TargetOwnerHandle)
{
	DWORD Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	try
	{
		Result = HijackImpl(TargetPid, TargetTid, true, DesiredAccess, TargetOwnerHandle, OutHandle, Detail);
		if (Result == INJ_ERR_SUCCESS)
		{
			LOG(0, XOR_STR_A("HandleAcq: Acquired Thread Handle %lu In PID %lu\n").get(), TargetTid, TargetPid);
		}
	}
	catch (...)
	{
		LOG(0, "HijackThreadHandle: Unhandled Exception\n");
		OutHandle = nullptr;
		Result = INJ_ERR_OUT_OF_MEMORY_NEW;
	}

	return Result;
}
