#ifndef AMGER_DISPATCHER_H
#define AMGER_DISPATCHER_H

/*
 * Dispatcher.h - command execution over a captured snapshot.
 *
 * Contract: interprets one kernel-local command snapshot plus the validated
 * system mapping of its payload, and returns its NTSTATUS through OutStatus.
 * PING and STATUS are implemented. INJECT validates, parses, reserves, maps,
 * relocates, resolves imports, binds dependencies, runs phase 6 Initialize,
 * resolves the entry, calls the CRT entry and erases the PE headers in phase 7,
 * then seals the image; phases 0-7 are implemented and only phase 8 (Execute)
 * remains deferred, so a valid inject still reports NOT_IMPLEMENTED.
 * EJECT remains unimplemented.
 * Inputs: dispatch context (snapshot + payload mapping) and output status.
 * Outputs: NTSTATUS mirrored in *OutStatus on every path.
 * Failure modes: null arguments produce STATUS_INVALID_PARAMETER without
 * dereferencing the missing pointer.
 */

#include <wdm.h>

#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"
#include "../../Execution/Initialize/Runtime.h"

/*
 * AMGER_DISPATCH_CONTEXT - snapshot plus the payload bytes it describes.
 * PayloadSystemAddress is the kernel mapping of PayloadVirtualAddress inside
 * the registered MDL; it is NULL when PayloadSize is zero. The range has
 * already been bounds-checked by the bridge.
 */

typedef struct _AMGER_DISPATCH_CONTEXT {
    const AMGER_COMMAND_SNAPSHOT* Snapshot;
    PVOID PayloadSystemAddress;
    SIZE_T PayloadSize;
    SIZE_T PayloadOffset;
    uint16_t StageId;
    uint32_t Magic;

    /* First lifecycle teardown failure recorded by the bootstrap layer, or
     * zero. Published by the STATUS command so it is never silent. */

    uint32_t LastFailure;
    uint64_t ResultValue;

    /* Phase 0 output, published to the client through the report area. */

    AMGER_PE_IMAGE ParserImage;
    BOOLEAN ParserImageValid;
    uint32_t ParserStatus;
    AMGER_ALLOC_REPORT AllocReport;
    AMGER_MAP_REPORT MapReport;
    AMGER_RELOC_REPORT RelocReport;
    AMGER_IMPORT_REPORT ImportReport;
    AMGER_DEP_REPORT DepReport;
    AMGER_INIT_REPORT InitReport;
    AMGER_ENTRY_REPORT EntryReport;
} AMGER_DISPATCH_CONTEXT, * PAMGER_DISPATCH_CONTEXT;

/*
 * Contract: maps a validated dispatch context to an NTSTATUS.
 * Inputs: Context (never user-owned), OutStatus receives the final value.
 * Outputs: NTSTATUS equal to *OutStatus.
 * Failure modes: null arguments yield STATUS_INVALID_PARAMETER; an unknown command
 * yields STATUS_INVALID_PARAMETER and EJECT yields STATUS_NOT_IMPLEMENTED.
 */

NTSTATUS DispatcherDispatch(
    AMGER_DISPATCH_CONTEXT* Context,
    uint32_t* OutStatus);

#endif /* AMGER_DISPATCHER_H */
