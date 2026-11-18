#ifndef AMGER_DISPATCHER_H
#define AMGER_DISPATCHER_H

/*
 * Dispatcher.h - Phase 1 command execution.
 *
 * Contract: interprets one shared command header and writes its NTSTATUS into
 * the header's Status field. PING is implemented; later commands are refused.
 * Inputs: pointer to a writable shared AMGER_COMMAND_HEADER.
 * Outputs: NTSTATUS mirroring Header->Status.
 * Failure modes: a null pointer or an unknown Command yields
 * STATUS_INVALID_PARAMETER without touching a null header.
 */

#include <wdm.h>

#include "../../Shared/Protocol.h"

/*
 * Contract: interprets one shared command and writes its NTSTATUS to Status.
 * Inputs: writable AMGER_COMMAND_HEADER in the locked shared region.
 * Outputs: NTSTATUS mirroring Header->Status.
 * Failure modes: null header or unknown command returns
 * STATUS_INVALID_PARAMETER; Phase 1 commands other than PING return
 * STATUS_NOT_IMPLEMENTED.
 */
NTSTATUS DispatcherDispatch(volatile AMGER_COMMAND_HEADER* Header);

#endif /* AMGER_DISPATCHER_H */
