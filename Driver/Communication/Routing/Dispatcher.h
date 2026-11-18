#ifndef AMGER_DISPATCHER_H
#define AMGER_DISPATCHER_H

/*
 * Dispatcher.h - Phase 1 command execution over a captured snapshot.
 *
 * Contract: interprets one kernel-local command snapshot and returns its
 * NTSTATUS through OutStatus. PING is implemented; INJECT, EJECT and STATUS
 * remain unimplemented. No mutable shared memory is read here.
 * Inputs: captured AMGER_COMMAND_SNAPSHOT and an output status pointer.
 * Outputs: NTSTATUS mirrored in *OutStatus on every path.
 * Failure modes: null arguments produce STATUS_INVALID_PARAMETER without
 * dereferencing the missing pointer.
 */

#include <wdm.h>

#include "../../../Shared/Protocol.h"

/*
 * Contract: maps a validated snapshot to an NTSTATUS.
 * Inputs: Snapshot (never user-owned), OutStatus receives the final value.
 * Outputs: NTSTATUS equal to *OutStatus.
 * Failure modes: null arguments yield STATUS_INVALID_PARAMETER; unknown or
 * unimplemented commands yield STATUS_INVALID_PARAMETER / STATUS_NOT_IMPLEMENTED.
 */
NTSTATUS DispatcherDispatch(
    const AMGER_COMMAND_SNAPSHOT* Snapshot,
    uint32_t* OutStatus);

#endif /* AMGER_DISPATCHER_H */
