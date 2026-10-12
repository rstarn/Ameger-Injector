#pragma once

#include <Windows.h>

#include <type_traits>
#include <utility>

// Lightweight RAII guards (no STL handle deps, no exceptions).
// What: UniqueHandle (local HANDLE), RemoteAllocation (target address space),
//   ScopeExit/MakeScopeExit (rollback callback). Why: every acquisition path
//   has multiple early returns, and a leaked suspend or remote mapping is a
//   crash or a Warden-visible artifact. How: hold as a local; release() detaches
//   ownership when the resource must outlive the scope (documented recovery
//   leaks); reset() frees early. Move-only throughout.

// Owning wrapper for a local kernel HANDLE. Closes via CloseHandle on
// destruction/reset; treats both null and INVALID_HANDLE_VALUE as empty.
// Move-only: copying would double-close. reset() with no arg just releases.
class UniqueHandle
{
	HANDLE m_Handle = nullptr;

public:
	UniqueHandle() = default;

	explicit UniqueHandle(HANDLE handle) : m_Handle(handle)
	{
	}

	UniqueHandle(const UniqueHandle &) = delete;
	UniqueHandle & operator=(const UniqueHandle &) = delete;

	UniqueHandle(UniqueHandle && other) noexcept : m_Handle(other.m_Handle)
	{
		other.m_Handle = nullptr;
	}

	UniqueHandle & operator=(UniqueHandle && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Handle = other.m_Handle;
			other.m_Handle = nullptr;
		}

		return *this;
	}

	~UniqueHandle()
	{
		reset();
	}

	void reset(HANDLE handle = nullptr)
	{
		if (m_Handle && m_Handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_Handle);
		}

		m_Handle = handle;
	}

	// Non-owning peek; the guard still frees on scope exit.
	HANDLE get() const
	{
		return m_Handle;
	}

	// Detaches ownership without closing (for handles the target or another
	// owner must keep). Returns the raw value; the guard becomes empty.
	HANDLE release()
	{
		HANDLE handle = m_Handle;
		m_Handle = nullptr;
		return handle;
	}

	// True when a real handle is held (filters both null sentinels).
	explicit operator bool() const
	{
		return m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE;
	}

	// Implicit read as HANDLE for Win32 calls; never transfers ownership.
	operator HANDLE() const
	{
		return m_Handle;
	}
};

// Owning wrapper for a VirtualAllocEx block in another process. Frees via
// VirtualFreeEx(MEM_RELEASE) on destruction/reset. release() detaches so a
// possibly-live remote stub/mapping stays mapped (the documented recovery
// leak, reclaimed when the target exits). Move-only for the same reason as
// UniqueHandle.
class RemoteAllocation
{
	HANDLE m_Process = nullptr;
	void * m_Address = nullptr;

public:
	RemoteAllocation() = default;

	RemoteAllocation(HANDLE process, void * address) : m_Process(process), m_Address(address)
	{
	}

	RemoteAllocation(const RemoteAllocation &) = delete;
	RemoteAllocation & operator=(const RemoteAllocation &) = delete;

	RemoteAllocation(RemoteAllocation && other) noexcept : m_Process(other.m_Process), m_Address(other.m_Address)
	{
		other.m_Process = nullptr;
		other.m_Address = nullptr;
	}

	RemoteAllocation & operator=(RemoteAllocation && other) noexcept
	{
		if (this != &other)
		{
			reset();
			m_Process = other.m_Process;
			m_Address = other.m_Address;
			other.m_Process = nullptr;
			other.m_Address = nullptr;
		}

		return *this;
	}

	~RemoteAllocation()
	{
		reset();
	}

	// Frees the current block (if any), then optionally takes a new one.
	// Params: process/address (new ownership; defaults detach to empty).
	void reset(HANDLE process = nullptr, void * address = nullptr)
	{
		if (m_Process && m_Process != INVALID_HANDLE_VALUE && m_Address)
		{
			VirtualFreeEx(m_Process, m_Address, 0, MEM_RELEASE);
		}

		m_Process = process;
		m_Address = address;
	}

	// Non-owning peek at the remote base; the guard still frees it on exit.
	void * get() const
	{
		return m_Address;
	}

	// Detaches without freeing: use when the remote thread may still execute
	// from the block (timeout/recovery) so freeing would crash the target.
	void release()
	{
		m_Process = nullptr;
		m_Address = nullptr;
	}
};

// Runs a noexcept callback at scope exit unless dismissed. Used for remote
// scrub (secure-wipe) passes that must not throw past a live suspend.
// Template param Callback: callable type (deduced via MakeScopeExit).
// Dismiss via dismiss() when the guarded action completed another way.
template<typename Callback>
class ScopeExit
{
	Callback m_Callback;
	bool m_Active = true;

public:
	explicit ScopeExit(Callback callback) : m_Callback(std::move(callback))
	{
		static_assert(std::is_nothrow_invocable_v<Callback &>, "ScopeExit callback must be noexcept");
	}

	ScopeExit(const ScopeExit &) = delete;
	ScopeExit & operator=(const ScopeExit &) = delete;

	~ScopeExit()
	{
		if (m_Active)
		{
			m_Callback();
		}
	}

	// Cancels the exit callback (the guarded cleanup happened explicitly).
	void dismiss()
	{
		m_Active = false;
	}
};

// Deduction helper so call sites write MakeScopeExit([&]{...}) instead of
// naming the lambda type. Params: callback (must be noexcept-invocable;
// enforced by static_assert in the ctor). Returns: the ScopeExit guard.
template<typename Callback>
ScopeExit<Callback> MakeScopeExit(Callback callback)
{
	return ScopeExit<Callback>(std::move(callback));
}
