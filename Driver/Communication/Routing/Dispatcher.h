#ifndef AMGER_DISPATCHER_H
#define AMGER_DISPATCHER_H

/*
 * Dispatcher.h - Phase 1 command execution over a captured snapshot.
 *
 * Contract: interprets one kernel-local command snapshot plus the validated
 * system mapping of its payload, and returns its NTSTATUS through OutStatus.
 * PING is implemented. INJECT validates the full request and reports that the
 * mapping engine is not yet linked; EJECT and STATUS remain unimplemented.
 * Inputs: dispatch context (snapshot + payload mapping) and output status.
 * Outputs: NTSTATUS mirrored in *OutStatus on every path.
 * Failure modes: null arguments produce STATUS_INVALID_PARAMETER without
 * dereferencing the missing pointer.
 */

#include <wdm.h>

#include "../../../Shared/Protocol.h"

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
} AMGER_DISPATCH_CONTEXT, * PAMGER_DISPATCH_CONTEXT;

/*
 * Contract: maps a validated dispatch context to an NTSTATUS.
 * Inputs: Context (never user-owned), OutStatus receives the final value.
 * Outputs: NTSTATUS equal to *OutStatus.
 * Failure modes: null arguments yield STATUS_INVALID_PARAMETER; unknown or
 * unimplemented commands yield STATUS_INVALID_PARAMETER / STATUS_NOT_IMPLEMENTED.
 */
NTSTATUS DispatcherDispatch(
    AMGER_DISPATCH_CONTEXT* Context,
    uint32_t* OutStatus);

#endif /* AMGER_DISPATCHER_H */
