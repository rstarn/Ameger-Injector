#pragma once
#include <string>
#include <cstdint>
#include "../Bridge.h"

namespace Kernel {
    class KernelClient {
    public:
        KernelClient();
        ~KernelClient();

        bool Initialize(const std::wstring& driverPath, const std::wstring& offsetsPath);
        bool TryReconnect();  // find the running driver's pool anchor and call its reconnect entry point
        bool ForceUnmap();  // request the driver to unmap: free image, driver object, and anchor block
        bool Reset();      // load provider, ForceUnmap, unload provider — one-shot kernel-state reset
        bool Ping();
        bool Shutdown();   // true when the driver confirmed shutdown_complete

        uint64_t GetDriverBase() const { return m_driverBase; }
        uint32_t GetHeartbeat() const { return m_ctx ? m_ctx->driver_heartbeat : 0; }
        uint32_t GetLastCommandStatus() const {
            if (!m_ringBuffer)
                return 0;
            return static_cast<AMEGER_KERNEL_COMMAND*>(m_ringBuffer)->status;
        }
        uint32_t GetLastStatus() const { return m_lastStatus; }

    private:
        AMEGER_KERNEL_CONTEXT* m_ctx;
        void* m_ringBuffer;
        uint64_t m_driverBase;
        uint32_t m_lastStatus;
    };
}
