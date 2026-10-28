#pragma once
#include <stdint.h>

#define AMEGER_KERNEL_ABI_VERSION 1u
#define AMEGER_KERNEL_CONTEXT_MAGIC 0x4B414D47u  /* "KAMG" */

#define AMEGER_RING_SIZE 0x1000
#define AMEGER_MAX_COMMANDS 16

typedef enum _AMEGER_COMMAND_TYPE {
    AmegerCmdNone = 0,
    AmegerCmdPing = 1,
    AmegerCmdShutdown = 2
} AMEGER_COMMAND_TYPE;

typedef struct _AMEGER_KERNEL_COMMAND {
    uint32_t type;
    uint32_t status;
    uint64_t arg1;
    uint64_t arg2;
} AMEGER_KERNEL_COMMAND;

typedef struct _AMEGER_KERNEL_CONTEXT {
    uint32_t magic;
    uint32_t version;
    uint64_t reserved[2];

    uint32_t driver_started;
    uint32_t driver_load_mode;
    uint64_t driver_ntstatus;
    uint64_t driver_image_base;
    uint64_t probe_echo;

    /* T4 additions */
    uint64_t ring_buffer_user_va;
    uint64_t ring_buffer_size;
    uint32_t shutdown_flag;        /* User sets to 1 to request shutdown */
    uint32_t shutdown_complete;    /* Driver sets to 1 when it is safe for user to free memory */
    uint32_t driver_heartbeat;
    uint32_t driver_error;        /* Non-zero if MDL lock fails */
    uint64_t mm_set_page_protection_addr;
} AMEGER_KERNEL_CONTEXT;

/*
 * Path B: the driver maps once and stays mapped after shutdown. A tagged
 * kernel pool block ("anchor") records the driver base and the address of a
 * reconnect entry point, so the next user run discovers the still-mapped
 * driver through SystemBigPoolInformation instead of remapping.
 */
#define AMEGER_ANCHOR_POOL_TAG 0x73736553u   /* 'Sess' */
#define AMEGER_ANCHOR_MAGIC  0x4D4547415F48434Eull  /* "AMEGER_HCN" */

/* The live big-pool listing (SystemBigPoolInformation) only carries
 * page-aligned blocks (>= 0x1000) on this x64 system; a 0x80 block is
 * invisible to the query (verified: 18,064 blocks scanned, zero 'Sess'
 * matches, sampled blocks all >= 0x1000). Allocate the anchor at one page
 * so it is listed and discoverable on subsequent runs. */
#define AMEGER_ANCHOR_ALLOC_SIZE 0x1000u

/* Shutdown flag values written by user into AMEGER_KERNEL_CONTEXT.shutdown_flag:
 * 1 = normal shutdown (keep driver mapped, anchor -> IDLE),
 * 2 = unmap request (driver frees image/object/anchor, anchor -> UNMAPPING). */
#define AMEGER_SHUTDOWN_FLAG_NORMAL  1u
#define AMEGER_SHUTDOWN_FLAG_UNMAP   2u

/* Anchor lifecycle states. */
#define AMEGER_ANCHOR_STATE_IDLE      0u   /* ready for reconnect */
#define AMEGER_ANCHOR_STATE_ACTIVE   1u    /* driver running */
#define AMEGER_ANCHOR_STATE_UNMAPPING 2u    /* unmap in progress */

typedef struct _AMEGER_DRIVER_ANCHOR {
    uint64_t magic;             /* AMEGER_ANCHOR_MAGIC */
    uint32_t version;           /* AMEGER_KERNEL_ABI_VERSION */
    uint32_t state;            /* AMEGER_ANCHOR_STATE_* */
    uint64_t driver_base;       /* Kernel VA of the mapped image */
    uint64_t reconnect_fn_addr; /* Address of AmegerDriverReconnect */
    uint64_t current_ctx_kva;   /* Kernel VA of the locked user context, 0 when idle */
    uint64_t driver_object_kva; /* Kernel VA of the fabricated DRIVER_OBJECT */
} AMEGER_DRIVER_ANCHOR;

static_assert(sizeof(AMEGER_DRIVER_ANCHOR) == 48, "AMEGER_DRIVER_ANCHOR must be 48 bytes");

/*
 * Probe helpers the kernel driver calls before MDL-locking a user-mode VA.
 * MmProbeVirtualMemory is a kernel-only WDK API, so these are guarded by
 * _KERNEL_MODE_: user-mode consumers of this header (KernelClient) must not
 * resolve a kernel function.
 */
#ifdef _KERNEL_MODE_
static NTSTATUS ProbeForRead(void *Address, SIZE_T Length, SIZE_T Alignment)
{
    return MmProbeVirtualMemory(Address, Length, Alignment, ProbingReadOperation);
}

static NTSTATUS ProbeForWrite(void *Address, SIZE_T Length, SIZE_T Alignment)
{
    return MmProbeVirtualMemory(Address, Length, Alignment, ProbingWriteOperation);
}
#endif
