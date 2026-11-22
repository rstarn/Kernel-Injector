#include "Injector.h"
#include "Reserve/Allocate.h"
#include "Mapping/Sections.h"

/*
 * Phase 1 reserves the image and Phase 2 maps its sections. Phases 3 through
 * 8 are still deferred, so a successfully mapped image is reverted as R3
 * rollback before returning NOT_IMPLEMENTED. Once the later phases land, that
 * revert moves to the failure path only.
 */

NTSTATUS InjectorExecute(
    const AMGER_INJECT_CONTEXT* Context,
    uint64_t* OutRemoteBase) {
    uint64_t remoteBase = 0u;
    NTSTATUS status;
    NTSTATUS revertStatus;
    HANDLE processId;

    if (OutRemoteBase != NULL) {
        *OutRemoteBase = 0u;
    }
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Context->AllocReport != NULL) {
        RtlZeroMemory(Context->AllocReport, sizeof(*Context->AllocReport));
        Context->AllocReport->TargetProcessId = Context->TargetProcessId;
        Context->AllocReport->ImageSize = (uint32_t)Context->ImageSize;
    }
    if (Context->MapReport != NULL) {
        RtlZeroMemory(Context->MapReport, sizeof(*Context->MapReport));
    }

    if (Context->ImageBase == NULL || Context->ImageSize == 0u ||
        Context->TargetProcessId == 0u || Context->Image == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    processId = (HANDLE)(uintptr_t)Context->TargetProcessId;

    status = AllocateReserveImage(processId, Context->ImageSize, &remoteBase);
    if (Context->AllocReport != NULL) {
        Context->AllocReport->Status = (uint32_t)status;
        Context->AllocReport->RemoteBase = remoteBase;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (Context->AllocReport != NULL) {
        Context->AllocReport->Flags = AMGER_ALLOC_FLAG_RESERVED;
    }

    status = MapSectionsMap(Context->Image, processId, remoteBase,
                            Context->MapReport);
    if (!NT_SUCCESS(status)) {
        revertStatus = MapSectionsRevert(processId, remoteBase);
        if (Context->MapReport != NULL) {
            if (NT_SUCCESS(revertStatus)) {
                Context->MapReport->Flags |= AMGER_MAP_FLAG_REVERTED;
            } else {
                Context->MapReport->Status = (uint32_t)revertStatus;
            }
        }
        if (Context->AllocReport != NULL && NT_SUCCESS(revertStatus)) {
            Context->AllocReport->Flags |= AMGER_ALLOC_FLAG_RELEASED;
        }
        return status;
    }

    revertStatus = MapSectionsRevert(processId, remoteBase);
    if (Context->MapReport != NULL && NT_SUCCESS(revertStatus)) {
        Context->MapReport->Flags |= AMGER_MAP_FLAG_REVERTED;
    }
    if (Context->AllocReport != NULL && NT_SUCCESS(revertStatus)) {
        Context->AllocReport->Flags |= AMGER_ALLOC_FLAG_RELEASED;
    }
    return STATUS_NOT_IMPLEMENTED;
}
