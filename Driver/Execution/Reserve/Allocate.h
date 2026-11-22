#ifndef AMGER_ALLOCATE_H
#define AMGER_ALLOCATE_H

/*
 * Allocate.h - Phase 1 (R17) image reservation in the target process.
 *
 * Contract: reserves SizeOfImage in the target and returns its user base.
 * Work runs in kernel mode through KeStackAttachProcess and Zw* on the current
 * process; no remote handles, no WriteProcessMemory and no VirtualAllocEx.
 * The paired release is the R3 rollback primitive.
 * Inputs: target PID, image size, output base pointer.
 * Outputs: NTSTATUS and the reserved base on success.
 * Failure modes: invalid arguments, dead target or allocation failure return
 * clean; no partial reservation is left by the reserve path.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"

/*
 * These process/VM prototypes live in ntifs.h, which cannot be included after
 * wdm.h in this translation unit. Declaring the documented signatures here
 * keeps the call type-checked; NtosKrnl.lib supplies the exports.
 */
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PEPROCESS Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, * PRKAPC_STATE;

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS* Process);

NTKERNELAPI VOID KeStackAttachProcess(
    PRKPROCESS Process,
    PRKAPC_STATE ApcState);

NTKERNELAPI VOID KeUnstackDetachProcess(
    PRKAPC_STATE ApcState);

NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

NTKERNELAPI NTSTATUS ZwFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

NTSTATUS AllocateReserveImage(
    HANDLE ProcessId,
    SIZE_T ImageSize,
    uint64_t* OutBase);

NTSTATUS AllocateReleaseImage(
    HANDLE ProcessId,
    uint64_t Base);

#endif /* AMGER_ALLOCATE_H */
