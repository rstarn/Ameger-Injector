#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../../../Mapper/Mapper/Mapper/Mapper.hpp"
#include "../../../Mapper/Mapper/Symbols/Handler/SymbolsHandler.hpp"
#include "../../../Mapper/Mapper/Provider/Driver.hpp"
#include "Client.h"

// Transcript logger (UiLog) lives in the Interface layer; forward-declare it so
// LOG(0, ...) in Client.cpp writes to the on-disk .log transcript.
int UiLog(int indent, const wchar_t * format, ...);
#ifdef LOG
#undef LOG
#endif
#define LOG UiLog

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

// Big-pool enumeration (SystemBigPoolInformation = 0x42) types.
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

typedef struct _BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;   // bit 0 of the address encodes the NonPaged flag
    };
    SIZE_T SizeInBytes;
    UCHAR Tag[4];
} BIGPOOL_ENTRY;

typedef struct _BIGPOOL_INFO {
    ULONG Count;
    BIGPOOL_ENTRY Entries[1];
} BIGPOOL_INFO;

#define SystemBigPoolInformation 0x42

// Layout sanity: BIGPOOL_ENTRY is 24 bytes (8 addr + 8 size + 4 tag + 4 pad);
// BIGPOOL_INFO.Entries sits at offset 8 (Count is 4 bytes, 4 pad for 8-byte align).
static_assert(sizeof(BIGPOOL_ENTRY) == 24, "BIGPOOL_ENTRY must be 24 bytes");
static_assert(offsetof(BIGPOOL_INFO, Entries) == 8, "BIGPOOL_INFO.Entries must be at offset 8");

namespace Kernel
{
    // The context grew with the T4 ring-buffer fields; assert the real size (96 bytes).
    static_assert(sizeof(AMEGER_KERNEL_CONTEXT) == 96, "AMEGER_KERNEL_CONTEXT must be 96 bytes");

    KernelClient::KernelClient() : m_ctx(nullptr), m_ringBuffer(nullptr), m_driverBase(0), m_lastStatus(0)
    {
    }

    KernelClient::~KernelClient()
    {
        Shutdown();
    }

    bool KernelClient::Initialize(const std::wstring& driverPath, const std::wstring& offsetsPath)
    {
        // Every failure path after an allocation cleans up what was reserved,
        // so a failed Initialize leaks neither buffer.
        auto fail = [this]() {
            if (m_ringBuffer) { VirtualFree(m_ringBuffer, 0, MEM_RELEASE); m_ringBuffer = nullptr; }
            if (m_ctx) { VirtualFree(m_ctx, 0, MEM_RELEASE); m_ctx = nullptr; }
            return false;
        };

        // 1. Allocate the 88-byte context (PAGE_READWRITE).
        m_ctx = static_cast<AMEGER_KERNEL_CONTEXT*>(
            VirtualAlloc(nullptr, sizeof(AMEGER_KERNEL_CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!m_ctx) {
            return false;
        }
        std::memset(m_ctx, 0, sizeof(*m_ctx));

        // 2. Allocate the ring buffer (AMEGER_RING_SIZE, PAGE_READWRITE).
        m_ringBuffer = VirtualAlloc(nullptr, AMEGER_RING_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!m_ringBuffer) {
            return fail();
        }
        std::memset(m_ringBuffer, 0, AMEGER_RING_SIZE);

        // 3. Fill the user-mode fields the driver reads.
        m_ctx->magic = AMEGER_KERNEL_CONTEXT_MAGIC;
        m_ctx->version = AMEGER_KERNEL_ABI_VERSION;
        m_ctx->ring_buffer_user_va = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(m_ringBuffer));
        m_ctx->ring_buffer_size = AMEGER_RING_SIZE;

        // Load the offsets file so the mapper engine can resolve kernel symbols and
        // structure field offsets during MapDriver. The updater argument is empty,
        // which ReloadFile treats as "no updater": it reads the file as-is and never
        // spawns anything, so nothing is attempted on an empty string.
        LOG(0, L"[Base] Loading Offsets.ini...\n");
        if (!SymbolsHandler::GetInstance()->ReloadFile(offsetsPath, L"")) {
            m_lastStatus = 0xE0000001;
            LOG(0, L"[-] [Base] ReloadFile Failed\n");
            return fail();
        }
        LOG(0, L"[Base] Offsets Loaded Successfully\n");

        // The provider must be loaded before MapDriver can talk to the kernel.
        // Driver::Load registers PdFwKrnl and opens its device (hDevice); MapDriver's
        // WriteMemory / CallKernelFunction / CreateDriverObjectForEntry all no-op when
        // hDevice is 0, which is what made the earlier probe return base == 0.
        LOG(0, L"[Base] Loading Provider (Driver::Load)...\n");
        const NTSTATUS provider_status = Driver::Load();   // 0 = STATUS_SUCCESS
        if (provider_status != 0) {
            m_lastStatus = static_cast<uint32_t>(provider_status);
            LOG(0, L"[-] [Base] Driver::Load Failed With NTSTATUS = 0x%08X\n", static_cast<uint32_t>(provider_status));
            return fail();
        }
        LOG(0, L"[Base] Provider Loaded Successfully\n");

        // Path B: if a previous run left the driver mapped, reconnect to it
        // instead of remapping. A hit skips the whole mapping path.
        LOG(0, L"[Base] Attempting Reconnect To Existing Driver...\n");
        if (TryReconnect())
        {
            LOG(0, L"[Base] Reconnected Successfully\n");
            return true;
        }
        LOG(0, L"[Base] No Existing Driver Found; Mapping Fresh\n");

        // Resolve the MmSetPageProtection kernel function address from the loaded
        // Offsets.ini symbols; the driver dereferences it to apply per-section
        // protections instead of the fragile MDL path.
        const ULONG64 mm_set_page_prot_offset = SymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
        if (mm_set_page_prot_offset == 0) {
            LOG(0, L"[-] [Base] MmSetPageProtection Offset Not Found In Offsets.ini\n");
            return fail();
        }
        m_ctx->mm_set_page_protection_addr = Driver::ntoskrnlAddr + mm_set_page_prot_offset;
        LOG(0, L"[Base] MmSetPageProtection Resolved To 0x%llX\n", static_cast<unsigned long long>(m_ctx->mm_set_page_protection_addr));

        // 4. Read the driver image from disk.
        HANDLE hFile = CreateFileW(driverPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return fail();
        }
        const DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<BYTE> image;
        image.resize(fileSize);
        DWORD bytesRead = 0;
        const bool readOk = ReadFile(hFile, image.data(), fileSize, &bytesRead, nullptr) &&
                            (fileSize == 0 || bytesRead == fileSize);
        CloseHandle(hFile);
        if (!readOk || fileSize == 0) {
            return fail();
        }

        // 5. Map and start the driver through the mapper engine (symbols come from Mapper.lib).
        LOG(0, L"[Base] Calling MapDriver...\n");
        LOG(0, L"[Base] Driver::hDevice = 0x%p, ntoskrnlAddr = 0x%llX\n",
            (void*)Driver::hDevice, static_cast<unsigned long long>(Driver::ntoskrnlAddr));

        // Diagnostic run: capture MapDriver's internal Log() output (it writes to
        // std::wcout, which is not captured in the .log transcript for an elevated
        // spawned process). Redirect wcout into a stringstream around the call.
        std::wstringstream capture;
        std::wstreambuf* oldBuf = std::wcout.rdbuf(capture.rdbuf());

        NTSTATUS status = static_cast<NTSTATUS>(-1);
        SIZE_T residentSize = 0;
        const ULONG64 base = Mapper::MapDriver(
            image.data(), image.size(),
            /*param1=*/0,
            /*param2=*/reinterpret_cast<ULONG64>(m_ctx),
            /*free=*/false,
            /*destroyHeader=*/false,
            /*mode=*/Mapper::AllocationMode::AllocateContiguous,
            /*PassAllocationAddressAsFirstParam=*/false,
            &status,
            &residentSize);
        std::wcout.rdbuf(oldBuf);
        LOG(0, L"[Base] MapDriver Internal Log:\n%ls\n", capture.str().c_str());

        m_driverBase = base;
        m_lastStatus = static_cast<uint32_t>(status);

        // 6. Verify the driver reported that it started; on failure the two
        // user-mode buffers are released rather than leaked. The two checks are
        // kept separate and logged distinctly so future runs can tell which one
        // failed.
        if (base == 0) {
            m_lastStatus = static_cast<uint32_t>(status);
            LOG(0, L"[-] [Base] MapDriver Returned 0 (MapStatus = 0x%08X)\n", static_cast<uint32_t>(status));
            return fail();
        }
        LOG(0, L"[Base] MapDriver Returned Base 0x%llX\n", static_cast<unsigned long long>(base));
        if (m_ctx->driver_started != 1) {
            m_lastStatus = static_cast<uint32_t>(status);
            LOG(0, L"[-] [Base] DriverStarted != 1 (Got = %u)\n", m_ctx->driver_started);
            return fail();
        }
        LOG(0, L"[Base] MapDriver Succeeded: Base = 0x%llX, ResidentSize = %zu, DriverError = 0x%X, LoadMode = %u\n",
            (unsigned long long)base, residentSize, m_ctx->driver_error, m_ctx->driver_load_mode);
        return true;
    }

    // Shared big-pool discovery: enumerate SystemBigPoolInformation, locate the
    // tagged anchor block, read it into outAnchor, and return the block's masked
    // kernel VA (NonPaged bit cleared) in outAnchorBlockVa. Preserves the same
    // diagnostic LOG lines the test transcript greps for.
    static bool ScanForAnchor(AMEGER_DRIVER_ANCHOR &outAnchor, uint64_t &outAnchorBlockVa)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto qsi = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (!qsi) return false;

        ULONG size = 0x10000;
        PVOID buf = nullptr;
        NTSTATUS st;
        for (int i = 0; i < 8; i++)
        {
            buf = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) return false;
            st = qsi(SystemBigPoolInformation, buf, size, &size);
            if (st == (NTSTATUS)0xC0000004L)  // STATUS_INFO_LENGTH_MISMATCH
            {
                VirtualFree(buf, 0, MEM_RELEASE);
                size *= 2;
                continue;
            }
            break;
        }
        if (st != 0) { VirtualFree(buf, 0, MEM_RELEASE); return false; }

        BIGPOOL_INFO *info = (BIGPOOL_INFO *)buf;

        // Case B diagnostics: report the total number of big-pool blocks scanned.
        LOG(0, L"[Base] BigPool: Scanned %lu Blocks\n", (unsigned long)info->Count);

        // Case B diagnostic: dump the first 16 blocks' raw tag bytes + size to
        // verify the tag field reads correctly (byte order / scale).
        const uint32_t dumpN = info->Count < 16 ? info->Count : 16;
        for (uint32_t i = 0; i < dumpN; i++)
        {
            const unsigned char* t = info->Entries[i].Tag;
            // SYSTEM_BIGPOOL_ENTRY packs the NonPaged flag into bit 0 of VirtualAddress;
            // clear it to get the actual block VA.
            uint64_t anchor_va = (uint64_t)(uintptr_t)info->Entries[i].VirtualAddress & ~(uint64_t)1;
            LOG(0, L"[Base] Block#%u Size = 0x%llX VA = 0x%llX Tag = %02X %02X %02X %02X\n",
                i,
                (unsigned long long)info->Entries[i].SizeInBytes,
                (unsigned long long)anchor_va,
                t[0], t[1], t[2], t[3]);
        }

        const uint32_t tag = AMEGER_ANCHOR_POOL_TAG;
        const unsigned char *tagBytes = (const unsigned char *)&tag;
        AMEGER_DRIVER_ANCHOR anchor = {};
        bool found = false;

        for (uint32_t i = 0; i < info->Count; i++)
        {
            if (memcmp(info->Entries[i].Tag, tagBytes, 4) != 0) continue;

            // SYSTEM_BIGPOOL_ENTRY packs the NonPaged flag into bit 0 of
            // VirtualAddress; clear it to get the actual block VA.
            uint64_t raw_va = (uint64_t)(uintptr_t)info->Entries[i].VirtualAddress;
            uint64_t anchor_va = raw_va & ~(uint64_t)1;   // clear NonPaged bit

            // Case B diagnostics: log each candidate block whose tag matches 'Sess'.
            LOG(0, L"[Base] Anchor Candidate VA = 0x%llX Size = %lu\n",
                (unsigned long long)anchor_va,
                (unsigned long)info->Entries[i].SizeInBytes);

            // The driver allocates AMEGER_ANCHOR_ALLOC_SIZE (0x1000) so the block is
            // visible in big pool; match any block at least as large as the struct.
            if (info->Entries[i].SizeInBytes < sizeof(AMEGER_DRIVER_ANCHOR)) continue;

            // Content-validate before trusting it.
            bool readOk = Driver::ReadMemory(anchor_va, &anchor, sizeof(anchor));
            LOG(0, L"[Base] Anchor ReadMemory = %s Magic = 0x%llX Version = %llu\n",
                readOk ? L"ok" : L"FAILED",
                (unsigned long long)anchor.magic,
                (unsigned long long)anchor.version);
            if (!readOk) continue;
            if (anchor.magic != AMEGER_ANCHOR_MAGIC || anchor.version != AMEGER_KERNEL_ABI_VERSION) continue;
            outAnchor = anchor;
            outAnchorBlockVa = anchor_va;
            found = true;
            break;
        }
        VirtualFree(buf, 0, MEM_RELEASE);
        return found;
    }

    bool KernelClient::TryReconnect()
    {
        if (!m_ctx)
        {
            return false;
        }

        // Discover the driver's tagged pool anchor and call its reconnect entry
        // point, so a still-mapped driver re-locks the new user buffers without
        // remapping its image.

        // 1. Discover the tagged pool anchor block (shared big-pool scan).
        AMEGER_DRIVER_ANCHOR anchor = {};
        uint64_t anchor_block_va = 0;
        if (!ScanForAnchor(anchor, anchor_block_va))
        {
            LOG(0, L"[Base] No Driver Anchor Found In BigPool; Falling Back To A Fresh Map\n");
            return false;
        }

        // 2. Call the driver's reconnect entry point with the fresh user context.
        NTSTATUS reconnect_status = static_cast<NTSTATUS>(-1);
        bool ok = Driver::CallKernelFunction(&reconnect_status, anchor.reconnect_fn_addr,
                                              reinterpret_cast<uint64_t>(m_ctx));
        if (!ok || reconnect_status != 0)
        {
            LOG(0, L"[-] [Base] Reconnect Failed (Call = %d, Status = 0x%08X)\n", ok, (uint32_t)reconnect_status);
            return false;
        }
        if (m_ctx->driver_started != 1) return false;

        m_driverBase = anchor.driver_base;
        LOG(0, L"[Base] Reconnected To The Running Driver: LoadMode = %u Base = 0x%llX\n",
            m_ctx->driver_load_mode, (unsigned long long)m_driverBase);
        return true;
    }

    bool KernelClient::ForceUnmap()
    {
        // 1. Discover the tagged anchor block via the shared big-pool scan.
        AMEGER_DRIVER_ANCHOR a = {};
        uint64_t anchor_block_va = 0;
        if (!ScanForAnchor(a, anchor_block_va))
        {
            LOG(0, L"[Base] No Driver To Unmap\n");
            return true;   // clean state: nothing to free
        }

        // 2. Only unmap when the driver is actively running.
        if (a.state != AMEGER_ANCHOR_STATE_ACTIVE)
        {
            LOG(0, L"[-] [Base] ForceUnmap: Anchor State = %u (Expected ACTIVE = 1); Aborting, Driver Left Mapped\n", a.state);
            return false;
        }

        // 3. Temp user context + ring buffer; fill the driver-read fields.
        AMEGER_KERNEL_CONTEXT *tempCtx = static_cast<AMEGER_KERNEL_CONTEXT*>(
            VirtualAlloc(nullptr, sizeof(AMEGER_KERNEL_CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!tempCtx) return false;
        void *tempRing = VirtualAlloc(nullptr, AMEGER_RING_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!tempRing) { VirtualFree(tempCtx, 0, MEM_RELEASE); return false; }

        std::memset(tempCtx, 0, sizeof(*tempCtx));
        tempCtx->magic = AMEGER_KERNEL_CONTEXT_MAGIC;
        tempCtx->version = AMEGER_KERNEL_ABI_VERSION;
        tempCtx->ring_buffer_user_va = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tempRing));
        tempCtx->ring_buffer_size = AMEGER_RING_SIZE;
        tempCtx->shutdown_flag = 0;

        // 4. Reconnect to lock tempCtx into the driver (sets g_KernelContext).
        NTSTATUS st_call = static_cast<NTSTATUS>(-1);
        const bool callOk = Driver::CallKernelFunction(&st_call, a.reconnect_fn_addr,
                                                       reinterpret_cast<uint64_t>(tempCtx));
        if (!callOk || st_call != 0)
        {
            LOG(0, L"[-] [Base] ForceUnmap: Reconnect Failed (Call = %d Status = 0x%08X); Aborting\n",
                callOk, (uint32_t)st_call);
            VirtualFree(tempRing, 0, MEM_RELEASE);
            VirtualFree(tempCtx, 0, MEM_RELEASE);
            return false;
        }

        // 5. Request the unmap through the driver's timer callback.
        tempCtx->shutdown_flag = AMEGER_SHUTDOWN_FLAG_UNMAP;

        // 6. Wait up to 500ms for the driver to reach unmap-ready.
        bool ready = false;
        const DWORD deadline = GetTickCount() + 500;
        while (GetTickCount() < deadline)
        {
            if (tempCtx->shutdown_complete == 1 && tempCtx->driver_error == 0xDEAF)
            {
                ready = true;
                break;
            }
            Sleep(20);
        }
        if (!ready)
        {
            LOG(0, L"[-] [Base] ForceUnmap: Driver Did Not Reach Unmap-Ready (DriverError = 0x%08X); Leaving Driver Mapped\n",
                (uint32_t)tempCtx->driver_error);
            VirtualFree(tempRing, 0, MEM_RELEASE);
            VirtualFree(tempCtx, 0, MEM_RELEASE);
            return false;
        }

        // 7. Grace window: let the driver's timer callback fully return before
        //    freeing any memory in the mapped image.
        Sleep(200);

        // 8. Resolve the free functions.
        const uint64_t pMmFree = Driver::GetKernelModuleExport(Driver::ntoskrnlAddr, "MmFreeContiguousMemory");
        const uint64_t pExFree = Driver::GetKernelModuleExport(Driver::ntoskrnlAddr, "ExFreePool");
        if (!pMmFree || !pExFree)
        {
            LOG(0, L"[-] [Base] ForceUnmap: Free Functions Unresolved (MmFree = %llu ExFree = %llu)\n",
                (unsigned long long)pMmFree, (unsigned long long)pExFree);
            VirtualFree(tempRing, 0, MEM_RELEASE);
            VirtualFree(tempCtx, 0, MEM_RELEASE);
            return false;
        }

        // 9-11. Free the driver image, then the fabricated driver object, then the
        //        anchor block LAST (its contents are already copied to `a`).
        const bool f1 = Driver::CallKernelFunction<void>(nullptr, pMmFree, a.driver_base);
        const bool f2 = Driver::CallKernelFunction<void>(nullptr, pExFree, a.driver_object_kva);
        const bool f3 = Driver::CallKernelFunction<void>(nullptr, pExFree, anchor_block_va);

        // 12. Free the temp user buffers.
        VirtualFree(tempRing, 0, MEM_RELEASE);
        VirtualFree(tempCtx, 0, MEM_RELEASE);

        LOG(0, L"[Base] ForceUnmap Complete: Img = %d Obj = %d Anchor = %d\n",
            (int)f1, (int)f2, (int)f3);
        return f1 && f2 && f3;
    }

    bool KernelClient::Reset()
    {
        // Pre-flight: is the provider already loaded (perhaps from a force-killed
        // prior run that left PdFwKrnl half-registered)? If the device can be
        // opened, skip Driver::Load() and go straight to ForceUnmap.
        HANDLE hTest = CreateFileW(L"\\\\.\\PdFwKrnl", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hTest != INVALID_HANDLE_VALUE)
        {
            LOG(0, L"[Base] Provider Already Loaded; Reusing For Unmap\n");
            CloseHandle(hTest);
            const bool ok = ForceUnmap();
            Driver::Unload();
            return ok;
        }

        const DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
        {
            LOG(0, L"[-] [Base] Reset: Provider Device Locked By Another Process (AccessDenied)\n");
            LOG(0, L"[-] [Base] Close Any Running Injector Processes And Retry, Or Reboot\n");
            return false;
        }

        // Not loaded: normal path - load the provider so the kernel-call helpers
        // (ReadMemory / CallKernelFunction / GetKernelModuleExport / ntoskrnlAddr)
        // resolve, run the unmap, then unload the provider.
        const NTSTATUS load_status = Driver::Load();
        if (load_status != 0)
        {
            LOG(0, L"[-] [Base] Reset: Driver::Load Failed (NTSTATUS = 0x%08X)\n", (uint32_t)load_status);
            return false;
        }
        const bool ok = ForceUnmap();
        Driver::Unload();
        return ok;
    }

    bool KernelClient::Ping()
    {
        if (!m_ctx || !m_ringBuffer)
        {
            return false;
        }
        AMEGER_KERNEL_COMMAND* cmd = static_cast<AMEGER_KERNEL_COMMAND*>(m_ringBuffer);
        cmd->type = AmegerCmdPing;
        Sleep(200);
        return m_ctx->driver_heartbeat > 0 && cmd->type == AmegerCmdNone;
    }

    bool KernelClient::Shutdown()
    {
        if (!m_ctx)
        {
            return false;
        }

        // 1. Signal the driver to shut down.
        m_ctx->shutdown_flag = 1;

        // 2. Wait up to 500ms for the driver to confirm via shutdown_complete.
        bool driver_confirmed = false;
        for (int i = 0; i < 50; i++)
        {
            if (m_ctx->shutdown_complete == 1)
            {
                driver_confirmed = true;
                break;
            }
            Sleep(10);
        }

        if (driver_confirmed)
        {
            // 3a. Path B: give the driver a 100ms grace window to finish
            // releasing its MDL locks, then free only the user buffers. The
            // driver image itself stays mapped (no UnloadDriver), so the next
            // run can reconnect through the pool anchor.
            Sleep(100);
            if (m_ringBuffer)
            {
                VirtualFree(m_ringBuffer, 0, MEM_RELEASE);
                m_ringBuffer = nullptr;
            }
            if (m_ctx)
            {
                VirtualFree(m_ctx, 0, MEM_RELEASE);
                m_ctx = nullptr;
            }
        }
        else
        {
            // 3b. Driver did not confirm - leave the user pages alive so the
            // driver's MDL does not point at freed memory. This leaks the two
            // buffers per failed Shutdown, which is preferable to a BSOD.
            LOG(0, L"[!] [Base] KernelClient::Shutdown Timed Out; Buffers Leaked To Avoid "
                L"MDL Use-After-Free\n");
        }

        // 4. Unload the provider. This unregisters PdFwKrnl and cleans its
        // PiDDB / MmUnloadedDrivers / hash-bucket entries.
        Driver::Unload();

        return driver_confirmed;
    }
}
