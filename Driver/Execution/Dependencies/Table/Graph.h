#ifndef AMGER_GRAPH_H
#define AMGER_GRAPH_H

/*
 * Graph.h - Phase 5 dependency table (R18, R28).
 *
 * Tracks each dependency by name with a refcount, state and parent depth so a
 * module is mapped once and every repeated dependency bumps the refcount.
 * Mapping is synchronous and non-recursive, so no cycle can form. Holds the
 * raw image bytes for rebind rounds; every buffer is freed before seal.
 */

#include <wdm.h>
#include "../../../../Shared/Protocol.h"
#include "../../../Utilities/Parser/Format.h"
#include "../../Reserve/Allocate.h"

#define AMGER_POOL_TAG_GRAPH    0x20202020u  /* four spaces: neutral, printable */
#define AMGER_POOL_TAG_PENDING  0x21212121u  /* four '!': neutral, printable */

#define AMGER_DEP_MAX_MODULES   16u
#define AMGER_DEP_MAX_ROUNDS    4u
#define AMGER_DEP_MAX_FILE_SIZE (256u * 1024u * 1024u)
#define AMGER_DEP_MAX_NAME      64u

#define AMGER_DEP_STATE_FREE    0u
#define AMGER_DEP_STATE_LOADING 1u
#define AMGER_DEP_STATE_LOADED  2u
#define AMGER_DEP_STATE_FAILED  3u

typedef struct _AMGER_DEP_ENTRY {
    WCHAR Name[AMGER_DEP_MAX_NAME];
    uint32_t NameLength;
    uint64_t Base;
    uint32_t Size;
    uint32_t RefCount;
    uint32_t ImportsResolved;
    uint32_t State;
    uint32_t Depth;
    AMGER_PE_IMAGE Image;
    PUCHAR Raw;
    SIZE_T RawSize;
} AMGER_DEP_ENTRY, * PAMGER_DEP_ENTRY;

typedef struct _AMGER_DEP_GRAPH {
    HANDLE ProcessId;
    AMGER_DEP_ENTRY Entries[AMGER_DEP_MAX_MODULES];
    uint32_t Count;
    PAMGER_DEP_REPORT Report;
} AMGER_DEP_GRAPH, * PAMGER_DEP_GRAPH;

AMGER_DEP_ENTRY* GraphFind(AMGER_DEP_GRAPH* graph, const WCHAR* name,
                           uint32_t nameLength);
AMGER_DEP_ENTRY* GraphAdd(AMGER_DEP_GRAPH* graph, const WCHAR* name,
                          uint32_t nameLength, uint32_t depth);
VOID GraphReleaseAll(AMGER_DEP_GRAPH* graph);
VOID GraphFreeBuffers(AMGER_DEP_GRAPH* graph);

NTSTATUS DependenciesResolve(
    const AMGER_PE_IMAGE* Primary,
    HANDLE ProcessId,
    uint64_t PrimaryBase,
    PAMGER_IMPORT_REPORT PrimaryImports,
    PAMGER_DEP_REPORT Out);

#endif /* AMGER_GRAPH_H */
