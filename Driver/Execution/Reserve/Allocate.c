#include "Allocate.h"

/*
 * ZwAllocateVirtualMemory requires PASSIVE_LEVEL and must be issued while
 * attached to the target process. KeStackAttachProcess raises to APC_LEVEL,
 * so only one short Zw call sits between attach and detach — Microsoft warns
 * that complex work while attached can deadlock asynchronous I/O.
 *
 * MEM_RESERVE with PAGE_READWRITE creates a non-executable, uncommitted VAD.
 * That avoids the ETW-TI executable-allocation signal and leaves the VAD
 * non-executable until Phase 2 promotes section protections. The base is
 * chosen by the memory manager (64 KiB granularity), never the PE's ImageBase.
 */

#define AMGER_ALLOCATE_MAX_IMAGE (512u * 1024u * 1024u)

NTSTATUS AllocateReserveImage(
    HANDLE ProcessId,
    SIZE_T ImageSize,
    uint64_t* OutBase) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    PVOID base = NULL;
    SIZE_T size;
    NTSTATUS status;

    if (OutBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutBase = 0u;

    if (ProcessId == NULL || ImageSize == 0u || ImageSize > AMGER_ALLOCATE_MAX_IMAGE) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    size = ImageSize;
    KeStackAttachProcess((PRKPROCESS)process, &apc);

    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(),
        &base,
        0u,
        &size,
        MEM_RESERVE,
        PAGE_READWRITE);

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);

    if (NT_SUCCESS(status) && base != NULL) {
        *OutBase = (uint64_t)(uintptr_t)base;
        return STATUS_SUCCESS;
    }
    return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
}

NTSTATUS AllocateReleaseImage(
    HANDLE ProcessId,
    uint64_t Base) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    PVOID base;
    SIZE_T size = 0u;
    NTSTATUS status;

    if (ProcessId == NULL || Base == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    base = (PVOID)(uintptr_t)Base;
    KeStackAttachProcess((PRKPROCESS)process, &apc);

    status = ZwFreeVirtualMemory(
        ZwCurrentProcess(),
        &base,
        &size,
        MEM_RELEASE);

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
    return status;
}
