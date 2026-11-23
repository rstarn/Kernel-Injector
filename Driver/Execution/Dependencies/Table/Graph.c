#include "Graph.h"
#include "../Images.h"
#include "../../Imports/Lookup.h"
#include "../../Imports/Binding/Resolve.h"

/*
 * Rounds are bounded: map the modules the primary image is missing, rebind it,
 * then resolve each dependency's own imports and repeat for any new names.
 * A module already in the loading state is a cycle and is counted, never
 * recursed into. Repeated dependencies only increment the refcount.
 */

#define AMGER_PENDING_MAX 64u

typedef struct _AMGER_PENDING {
    char Names[AMGER_PENDING_MAX][AMGER_DEP_MAX_NAME];
    uint32_t Count;
} AMGER_PENDING, * PAMGER_PENDING;

static WCHAR Lower(WCHAR value) {
    return (value >= L'A' && value <= L'Z') ? (WCHAR)(value + 0x20u) : value;
}

static BOOLEAN WideEqual(const WCHAR* left, uint32_t leftLength,
                         const WCHAR* right, uint32_t rightLength) {
    uint32_t index;
    if (leftLength != rightLength) {
        return FALSE;
    }
    for (index = 0u; index < leftLength; ++index) {
        if (Lower(left[index]) != Lower(right[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static VOID AnsiToWide(const char* ansi, WCHAR* wide, uint32_t capacity,
                       uint32_t* length) {
    uint32_t index = 0u;
    while (ansi[index] != 0 && index + 1u < capacity) {
        wide[index] = (WCHAR)(UCHAR)ansi[index];
        ++index;
    }
    wide[index] = 0;
    *length = index;
}

static VOID WideToAscii(const WCHAR* wide, uint32_t length, char* ascii,
                        SIZE_T capacity) {
    SIZE_T index;
    if (capacity == 0u) {
        return;
    }
    for (index = 0u; index < length && index + 1u < capacity; ++index) {
        ascii[index] = (char)wide[index];
    }
    ascii[index] = 0;
}

static VOID CopyName(char* destination, const char* source) {
    uint32_t index = 0u;
    while (source[index] != 0 && index + 1u < AMGER_DEP_MAX_NAME) {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = 0;
}

static BOOLEAN AsciiEqualNul(const char* left, const char* right) {
    while (*left != 0 && *right != 0) {
        if (*left != *right) {
            return FALSE;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static BOOLEAN PendingHas(const AMGER_PENDING* pending, const char* name) {
    uint32_t index;
    for (index = 0u; index < pending->Count; ++index) {
        if (AsciiEqualNul(pending->Names[index], name)) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID PendingAdd(AMGER_PENDING* pending, const char* name) {
    if (pending->Count >= AMGER_PENDING_MAX || PendingHas(pending, name)) {
        return;
    }
    CopyName(pending->Names[pending->Count], name);
    ++pending->Count;
}

static VOID CollectDeferred(AMGER_PENDING* pending,
                            const AMGER_IMPORT_REPORT* report) {
    uint32_t index;
    if (report == NULL) {
        return;
    }
    if (report->DeferredModuleCount != 0u &&
        report->DeferredModule[0] != 0) {
        PendingAdd(pending, report->DeferredModule);
    }
    for (index = 0u; index < report->DeferredModuleCount &&
                      index < 8u; ++index) {
        PendingAdd(pending, report->DeferredModules[index]);
    }
}

AMGER_DEP_ENTRY* GraphFind(AMGER_DEP_GRAPH* graph, const WCHAR* name,
                           uint32_t nameLength) {
    uint32_t index;
    if (graph == NULL || name == NULL) {
        return NULL;
    }
    for (index = 0u; index < graph->Count; ++index) {
        AMGER_DEP_ENTRY* entry = &graph->Entries[index];
        if (entry->State != AMGER_DEP_STATE_FREE &&
            WideEqual(entry->Name, entry->NameLength, name, nameLength)) {
            return entry;
        }
    }
    return NULL;
}

AMGER_DEP_ENTRY* GraphAdd(AMGER_DEP_GRAPH* graph, const WCHAR* name,
                          uint32_t nameLength, uint32_t depth) {
    AMGER_DEP_ENTRY* entry;
    if (graph == NULL || name == NULL || nameLength == 0u ||
        nameLength >= AMGER_DEP_MAX_NAME ||
        graph->Count >= AMGER_DEP_MAX_MODULES) {
        return NULL;
    }
    if (GraphFind(graph, name, nameLength) != NULL) {
        return NULL;
    }
    entry = &graph->Entries[graph->Count++];
    RtlZeroMemory(entry, sizeof(*entry));
    RtlCopyMemory(entry->Name, name, nameLength * sizeof(WCHAR));
    entry->NameLength = nameLength;
    entry->State = AMGER_DEP_STATE_LOADING;
    entry->Depth = depth;
    return entry;
}

VOID GraphReleaseAll(AMGER_DEP_GRAPH* graph) {
    uint32_t index;
    if (graph == NULL) {
        return;
    }
    for (index = 0u; index < graph->Count; ++index) {
        AMGER_DEP_ENTRY* entry = &graph->Entries[index];
        if (entry->Base != 0u) {
            (void)AllocateReleaseImage(graph->ProcessId, entry->Base);
            entry->Base = 0u;
        }
        entry->State = AMGER_DEP_STATE_FAILED;
    }
}

VOID GraphFreeBuffers(AMGER_DEP_GRAPH* graph) {
    uint32_t index;
    if (graph == NULL) {
        return;
    }
    for (index = 0u; index < graph->Count; ++index) {
        AMGER_DEP_ENTRY* entry = &graph->Entries[index];
        if (entry->Raw != NULL) {
            ExFreePool(entry->Raw);
            entry->Raw = NULL;
            entry->RawSize = 0u;
            entry->Image.Base = NULL;
        }
    }
}

static NTSTATUS ProcessPending(AMGER_DEP_GRAPH* graph,
                               AMGER_PENDING* pending,
                               uint32_t depth) {
    uint32_t index;

    for (index = 0u; index < pending->Count; ++index) {
        WCHAR name[AMGER_DEP_MAX_NAME];
        uint32_t nameLength = 0u;
        AMGER_DEP_ENTRY* entry;

        if (pending->Names[index][0] == 0) {
            continue;
        }
        AnsiToWide(pending->Names[index], name, AMGER_DEP_MAX_NAME, &nameLength);
        if (nameLength == 0u) {
            continue;
        }

        entry = GraphFind(graph, name, nameLength);
        if (entry != NULL) {
            if (entry->State == AMGER_DEP_STATE_LOADED) {
                if (entry->Counted == 0u) {
                    entry->Counted = 1u;
                    ++entry->RefCount;
                }
                continue;
            }
            if (entry->State == AMGER_DEP_STATE_LOADING) {
                ++graph->Report->Cycles;
                continue;
            }
            continue;
        }

        entry = GraphAdd(graph, name, nameLength, depth);
        if (entry == NULL) {
            ++graph->Report->Failures;
            continue;
        }
        if (!NT_SUCCESS(ImagesMapDependency(graph, entry))) {
            ++graph->Report->Failures;
            entry->State = AMGER_DEP_STATE_FAILED;
            return STATUS_UNSUCCESSFUL;
        }
        entry->State = AMGER_DEP_STATE_LOADED;
        entry->RefCount = 1u;
        if (!LookupRegisterPrivate(entry->Name, entry->NameLength,
                                   entry->Base, entry->Size)) {
            ++graph->Report->Failures;
            return STATUS_UNSUCCESSFUL;
        }
        ++graph->Report->ModulesRegistered;
        if (graph->Report->MappedNameCount < AMGER_DEP_REPORT_MAX_NAMES) {
            WideToAscii(entry->Name, entry->NameLength,
                        graph->Report->MappedNames[graph->Report->MappedNameCount],
                        AMGER_REPORT_NAME_LENGTH);
            ++graph->Report->MappedNameCount;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS DependenciesResolve(
    const AMGER_PE_IMAGE* primary,
    HANDLE processId,
    uint64_t primaryBase,
    PAMGER_IMPORT_REPORT primaryImports,
    PAMGER_DEP_REPORT out) {
    PAMGER_DEP_GRAPH graph = NULL;
    PAMGER_PENDING pending = NULL;
    uint32_t round;
    uint32_t index;
    uint32_t initialResolved;
    NTSTATUS status;
    NTSTATUS failureStatus = STATUS_UNSUCCESSFUL;

    if (primary == NULL || processId == NULL || primaryImports == NULL ||
        out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(out, sizeof(*out));
    out->DeferredBefore = primaryImports->DeferredCount;
    initialResolved = primaryImports->FunctionsResolved;

    /* Measure the loader list before any dependency work. */

    status = LookupCountLoaderModules(processId, &out->LoaderEntriesBefore);
    if (!NT_SUCCESS(status)) {
        out->Status = (uint32_t)status;
        out->FailureStage = AMGER_DEP_STAGE_PARAMETERS;
        return status;
    }

    /* The table embeds full PE descriptors and is far larger than the x64
     * kernel stack. Allocate both working structures from pool and release
     * them on every path. */

#pragma warning(suppress : 4996)
    graph = (PAMGER_DEP_GRAPH)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(*graph), AMGER_POOL_TAG_GRAPH);
#pragma warning(suppress : 4996)
    pending = (PAMGER_PENDING)ExAllocatePoolWithTag(
        PagedPool, sizeof(*pending), AMGER_POOL_TAG_PENDING);
    if (graph == NULL || pending == NULL) {
        if (graph != NULL) {
            ExFreePool(graph);
        }
        if (pending != NULL) {
            ExFreePool(pending);
        }
        out->Status = (uint32_t)STATUS_INSUFFICIENT_RESOURCES;
        out->FailureStage = AMGER_DEP_STAGE_PARAMETERS;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(graph, sizeof(*graph));
    RtlZeroMemory(pending, sizeof(*pending));
    graph->ProcessId = processId;
    graph->Report = out;
    out->PrimaryBase = primaryBase;

    for (round = 0u; round < AMGER_DEP_MAX_ROUNDS; ++round) {
        uint32_t before;
        AMGER_IMPORT_REPORT next;

        out->Rounds = round + 1u;
        out->FailureStage = AMGER_DEP_STAGE_ROUND;
        CollectDeferred(pending, primaryImports);
        before = graph->Count;

        status = ProcessPending(graph, pending, round);
        if (!NT_SUCCESS(status)) {
            failureStatus = status;
            goto failed;
        }
        if (graph->Count == before) {
            break;
        }

        out->FailureStage = AMGER_DEP_STAGE_IMPORT;
        RtlZeroMemory(&next, sizeof(next));
        status = ResolveImports(primary, processId, primaryBase, &next);
        if (!NT_SUCCESS(status)) {
            failureStatus = status;
            goto failed;
        }
        RtlCopyMemory(primaryImports, &next, sizeof(next));

        for (index = 0u; index < graph->Count; ++index) {
            AMGER_DEP_ENTRY* entry = &graph->Entries[index];
            AMGER_IMPORT_REPORT dependencyImports;

            if (entry->State != AMGER_DEP_STATE_LOADED) {
                continue;
            }
            RtlZeroMemory(&dependencyImports, sizeof(dependencyImports));
            status = ResolveImports(&entry->Image, processId, entry->Base,
                                    &dependencyImports);
            if (!NT_SUCCESS(status)) {
                failureStatus = status;
                goto failed;
            }
            entry->ImportsResolved = dependencyImports.FunctionsResolved;
            CollectDeferred(pending, &dependencyImports);
        }
    }

    for (index = 0u; index < graph->Count; ++index) {
        AMGER_DEP_ENTRY* entry = &graph->Entries[index];
        if (entry->State == AMGER_DEP_STATE_LOADED) {
            ++out->ModulesLoaded;
            out->DependencyImportsResolved += entry->ImportsResolved;
            if (entry->Base != 0u &&
                out->BaseCount < AMGER_DEP_REPORT_MAX_BASES) {
                out->Bases[out->BaseCount++] = entry->Base;
            }
        }
    }

    status = LookupCountLoaderModules(processId, &out->LoaderEntriesAfter);
    if (!NT_SUCCESS(status)) {
        failureStatus = status;
        out->FailureStage = AMGER_DEP_STAGE_PARAMETERS;
        goto failed;
    }
    out->DeferredAfter = primaryImports->DeferredCount;
    out->ReboundFunctions = primaryImports->FunctionsResolved > initialResolved
                                ? primaryImports->FunctionsResolved - initialResolved
                                : 0u;

    GraphFreeBuffers(graph);
    if (graph->Count != 0u) {
        out->Flags |= AMGER_DEP_FLAG_MAPPED;
    }
    ExFreePool(graph);
    ExFreePool(pending);
    out->FailureStage = AMGER_DEP_STAGE_NONE;
    out->Status = (uint32_t)STATUS_SUCCESS;
    return STATUS_SUCCESS;

failed:
    out->Status = (uint32_t)failureStatus;
    GraphReleaseAll(graph);
    GraphFreeBuffers(graph);
    ExFreePool(graph);
    ExFreePool(pending);
    out->Flags |= AMGER_DEP_FLAG_REVERTED;
    return failureStatus;
}
