#include "Core/Utility/Header/PrecompiledHeader.h"
#include <unordered_set>
#include "Core/Foundation/Primitives/ResourceGuard.h"
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

	std::wstring LowercaseW(const std::wstring & text)
	{
		std::wstring out = text;

		for (size_t i = 0; i < out.size(); ++i)
		{
			wchar_t & c = out[i];
			if (c >= L'A' && c <= L'Z')
			{
				c = static_cast<wchar_t>(c - L'A' + L'a');
			}
		}

		return out;
	}

	bool ResolveNtdll(NtdllHandles & Out)
	{
		
		
		
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

	std::atomic<bool> g_DebugPrivilegeAttempted{ false };

	void EnsureSeDebugPrivilege()
	{
		bool expected = false;
		if (g_DebugPrivilegeAttempted.compare_exchange_strong(expected, true))
		{
			EnableSeDebugPrivilege();
		}
	}

	void RevokeSeDebugPrivilege()
	{
		HANDLE RawToken = nullptr;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &RawToken))
		{
			UniqueHandle Token(RawToken);

			LUID Luid{ 0 };
			if (LookupPrivilegeValueW(nullptr, XOR_STR_W(L"SeDebugPrivilege").get(), &Luid))
			{
				TOKEN_PRIVILEGES Privileges{ 0 };
				Privileges.PrivilegeCount = 1;
				Privileges.Privileges[0].Luid = Luid;

				Privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
				AdjustTokenPrivileges(Token.get(), FALSE, &Privileges, sizeof(Privileges), nullptr, nullptr);
			}
		}

		g_DebugPrivilegeAttempted.store(false, std::memory_order_release);
	}

	class SeDebugPrivilegeScope
	{
		bool m_Revoke = false;

	public:
		explicit SeDebugPrivilegeScope(bool revoke_on_exit)
			: m_Revoke(revoke_on_exit)
		{
		}

		~SeDebugPrivilegeScope()
		{
			if (m_Revoke && g_DebugPrivilegeAttempted.load(std::memory_order_acquire))
			{
				RevokeSeDebugPrivilege();
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

		
		
		void * Page = ScAllocateMemory(Candidate, 0x1000, PAGE_NOACCESS);
		if (!Page)
		{
			return false;
		}

		if (ScFreeMemory(Candidate, Page))
		{
			return true;
		}

		LOG(1, "ProbeVmOperation: Release Failed\n");

		return false;
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

		std::vector<std::pair<DWORD, UniqueHandle>> Owners;

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
						// Skip this donor only. Raising the global BudgetHit here would abort
						// every remaining candidate in this pass *and* both later passes, turning
						// a per-owner budget into a whole-scan budget.
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

				// NtDuplicateObject clamps the duplicate to the source object's existing
				// grant, so a donor that does not already hold every bit we need can only
				// ever produce a weaker handle that then fails verification. Reject it here
				// rather than spending a duplicate attempt on it.
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
					Detail.ProbeMethod = 1;
					LOG(1, "[Handle] [+] Donor Handle Acquired: Donor PID = %u | Donor Handle = 0x%08X\n", FoundDonorPid, FoundDonorHandle);
					LOG(1, "[Handle] [+] Duplicated Handle: Local = 0x%08X | Granted = 0x%08X\n", FoundNewHandle, FoundGranted);
					LOG(1, "[Handle] [*] Census: Total = %u | Examined = %llu | DupDenied = %llu | VerifyRejected = %llu | Owners = %llu | BudgetSkipped = %llu\n",
						Detail.TotalHandles, (unsigned long long)Examined, (unsigned long long)DupDenied, (unsigned long long)VerifyRejected, (unsigned long long)Owners.size(), (unsigned long long)BudgetSkipped);
					return INJ_ERR_SUCCESS;
				}

				if (BudgetHit)
				{
					break;
				}
			}
		}

		LOG(1, XOR_STR_A("HandleAcq: No Donor (Examined %llu, Duplicated %llu, Filtered %d, Budget Hit %d)\n").get(),
			static_cast<unsigned long long>(Examined),
			static_cast<unsigned long long>(Duplicated),
			HaveType ? 1 : 0,
			BudgetHit ? 1 : 0);

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

		const bool priv_previously_attempted = g_DebugPrivilegeAttempted.load(std::memory_order_acquire);
		SeDebugPrivilegeScope debug_privilege_scope(!priv_previously_attempted);

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

	void StoreHijackStats(HijackStats & Dst, const HijackStats & Src)
	{
		static_assert(sizeof(HijackStats) % sizeof(LONG) == 0, "HijackStats must be a whole number of LONGs");

		volatile LONG * dst = ReCa<volatile LONG *>(&Dst);
		const volatile LONG * src = ReCa<const volatile LONG *>(&Src);
		for (size_t i = 0; i < sizeof(HijackStats) / sizeof(LONG); ++i)
		{
			InterlockedExchange(&dst[i], src[i]);
		}
	}

	void LoadHijackStats(HijackStats & Src, HijackStats & Dst)
	{
		volatile LONG * src = ReCa<volatile LONG *>(&Src);
		LONG * dst = ReCa<LONG *>(&Dst);
		for (size_t i = 0; i < sizeof(HijackStats) / sizeof(LONG); ++i)
		{
			dst[i] = InterlockedCompareExchange(&src[i], 0, 0);
		}
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
#pragma EXPORT_FUNCTION("CoreAcqStats", __FUNCDNAME__)

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
