#include "Injector.h"
#include "Reserve/Allocate.h"
#include "Mapping/Sections.h"
#include "Relocate/Fixups.h"
#include "Imports/Lookup.h"
#include "Imports/Binding/Resolve.h"
#include "Dependencies/Table/Graph.h"
#include "Initialize/Runtime.h"

/*
 * Phase 1 reserves the image, Phase 2 copies it, Phase 3 applies relocations,
 * Phase 4 resolves imports, Phase 5 maps missing dependencies and rebinds,
 * then SectionsSeal promotes protections once. Phases 6 through 8 are still
 * deferred, so the image is reverted as R3 rollback before returning
 * NOT_IMPLEMENTED. Once the later phases land, that revert moves to the
 * failure path only.
 */

static VOID ReleaseDependencyBases(HANDLE ProcessId,
                                   const AMGER_DEP_REPORT* Report) {
    uint32_t index;

    if (Report == NULL) {
        return;
    }
    for (index = 0u; index < Report->BaseCount &&
                      index < AMGER_DEP_REPORT_MAX_BASES; ++index) {
        if (Report->Bases[index] != 0u) {
            (void)MapSectionsRevert(ProcessId, Report->Bases[index]);
        }
    }
}

static VOID MarkReverted(const AMGER_INJECT_CONTEXT* Context,
                         PAMGER_MAP_REPORT MapReport,
                         PAMGER_RELOC_REPORT RelocReport,
                         PAMGER_IMPORT_REPORT ImportReport,
                         PAMGER_DEP_REPORT DepReport,
                         NTSTATUS RevertStatus) {
    if (!NT_SUCCESS(RevertStatus)) {
        return;
    }
    if (Context->AllocReport != NULL) {
        Context->AllocReport->Flags |= AMGER_ALLOC_FLAG_RELEASED;
    }
    MapReport->Flags |= AMGER_MAP_FLAG_REVERTED;

    /* Do not publish an empty phase block just because the reservation was
     * released after an earlier phase failed. */

    if ((RelocReport->Flags & AMGER_RELOC_FLAG_APPLIED) != 0u) {
        RelocReport->Flags |= AMGER_RELOC_FLAG_REVERTED;
    }
    if ((ImportReport->Flags & AMGER_IMPORT_FLAG_RESOLVED) != 0u) {
        ImportReport->Flags |= AMGER_IMPORT_FLAG_REVERTED;
    }
    if ((DepReport->Flags & AMGER_DEP_FLAG_MAPPED) != 0u) {
        DepReport->Flags |= AMGER_DEP_FLAG_REVERTED;
    }
}

NTSTATUS InjectorExecute(
    const AMGER_INJECT_CONTEXT* Context,
    uint64_t* OutRemoteBase) {
    AMGER_MAP_REPORT localMap;
    AMGER_RELOC_REPORT localReloc;
    AMGER_IMPORT_REPORT localImport;
    AMGER_DEP_REPORT localDep;
    AMGER_INIT_REPORT localInit;
    PAMGER_MAP_REPORT mapReport;
    PAMGER_RELOC_REPORT relocReport;
    PAMGER_IMPORT_REPORT importReport;
    PAMGER_DEP_REPORT depReport;
    PAMGER_INIT_REPORT initReport;
    AMGER_INIT_CONTEXT init;
    uint64_t remoteBase = 0u;
    uint64_t delta;
    NTSTATUS status;
    NTSTATUS revertStatus;
    HANDLE processId;

    if (OutRemoteBase != NULL) {
        *OutRemoteBase = 0u;
    }
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&localMap, sizeof(localMap));
    RtlZeroMemory(&localReloc, sizeof(localReloc));
    RtlZeroMemory(&localImport, sizeof(localImport));
    RtlZeroMemory(&localDep, sizeof(localDep));
    RtlZeroMemory(&localInit, sizeof(localInit));
    mapReport = (Context->MapReport != NULL) ? Context->MapReport : &localMap;
    relocReport = (Context->RelocReport != NULL) ? Context->RelocReport : &localReloc;
    importReport = (Context->ImportReport != NULL) ? Context->ImportReport : &localImport;
    depReport = (Context->DepReport != NULL) ? Context->DepReport : &localDep;
    initReport = (Context->InitReport != NULL) ? Context->InitReport : &localInit;
    RtlZeroMemory(mapReport, sizeof(*mapReport));
    RtlZeroMemory(relocReport, sizeof(*relocReport));
    RtlZeroMemory(importReport, sizeof(*importReport));
    RtlZeroMemory(depReport, sizeof(*depReport));
    RtlZeroMemory(initReport, sizeof(*initReport));
    RtlZeroMemory(&init, sizeof(init));

    if (Context->AllocReport != NULL) {
        RtlZeroMemory(Context->AllocReport, sizeof(*Context->AllocReport));
    }

    if (Context->ImageBase == NULL || Context->ImageSize == 0u ||
        Context->TargetProcessId == 0u || Context->Image == NULL) {
        mapReport->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        mapReport->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
        relocReport->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        relocReport->FailureStage = AMGER_RELOC_STAGE_PARAMETERS;
        importReport->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        importReport->FailureStage = AMGER_IMPORT_STAGE_PARAMETERS;
        return STATUS_INVALID_PARAMETER;
    }

    processId = (HANDLE)(uintptr_t)Context->TargetProcessId;

    if (Context->AllocReport != NULL) {
        Context->AllocReport->TargetProcessId = Context->TargetProcessId;
        Context->AllocReport->ImageSize = Context->Image->SizeOfImage;
    }

    /* R17 reserves SizeOfImage, not the raw file size. The commit in Phase 2
     * asks for the same span; reserving the smaller file would make the commit
     * run past the VAD and return STATUS_CONFLICTING_ADDRESSES. */

    status = AllocateReserveImage(processId, Context->Image->SizeOfImage,
                                  &remoteBase);
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

    status = MapSectionsMap(Context->Image, processId, remoteBase, mapReport);
    if (!NT_SUCCESS(status)) {
        revertStatus = MapSectionsRevert(processId, remoteBase);
        MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
        return status;
    }

    delta = remoteBase - Context->Image->ImageBase;
    status = FixupsApply(Context->Image, processId, remoteBase, delta,
                         relocReport);
    if (!NT_SUCCESS(status)) {
        revertStatus = MapSectionsRevert(processId, remoteBase);
        MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
        return status;
    }

    /* Reset the private dependency registry once per inject. ResolveImports
     * is called repeatedly during dependency rounds and must not clear it. */

    LookupResetPrivate();
    status = ResolveImports(Context->Image, processId, remoteBase,
                            importReport);
    if (!NT_SUCCESS(status)) {
        revertStatus = MapSectionsRevert(processId, remoteBase);
        MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
        return status;
    }

    status = DependenciesResolve(Context->Image, processId, remoteBase,
                                 importReport, depReport);
    if (!NT_SUCCESS(status)) {
        ReleaseDependencyBases(processId, depReport);
        revertStatus = MapSectionsRevert(processId, remoteBase);
        MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
        return status;
    }

    {
        init.ProcessId = processId;
        init.RemoteBase = remoteBase;
        init.Image = Context->Image;
        init.Report = initReport;
        status = InitializePhase(&init);
        if (!NT_SUCCESS(status)) {
            ReleaseDependencyBases(processId, depReport);
            revertStatus = MapSectionsRevert(processId, remoteBase);
            MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
            return status;
        }
    }

    status = SectionsSeal(Context->Image, processId, remoteBase, mapReport);
    if (!NT_SUCCESS(status)) {
        InitializeRevert(&init);
        ReleaseDependencyBases(processId, depReport);
        revertStatus = MapSectionsRevert(processId, remoteBase);
        MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
        return status;
    }

    /* Phases 7 and 8 are still deferred, so this inject is reverted as an R3
     * rollback. InitializeRevert restores ntdll and releases the private APC
     * pages before the mapping is unmapped. Once Entry and Execute land, the
     * revert moves to the failure path only. */

    InitializeRevert(&init);
    ReleaseDependencyBases(processId, depReport);
    revertStatus = MapSectionsRevert(processId, remoteBase);
    MarkReverted(Context, mapReport, relocReport, importReport, depReport, revertStatus);
    return STATUS_NOT_IMPLEMENTED;
}
