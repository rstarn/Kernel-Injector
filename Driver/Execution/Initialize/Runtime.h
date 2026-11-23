#ifndef AMGER_RUNTIME_H
#define AMGER_RUNTIME_H

/*
 * Runtime.h - Phase 6 (R12, R26, R6, R1, R5, R25, R23, R15, R19).
 *
 * Contract: consumes the same validated image descriptor as phases 1-5 and
 * initialises only state that a manually mapped module needs before its entry
 * point runs. Every field in AMGER_INIT_REPORT is read back from the target or
 * taken from a call that returned a status; no design claim is published.
 *
 * All work is kernel-origin. User-mode ntdll routines are reached through a
 * user APC whose stub lives in a private executable page owned by this phase,
 * never through a remote thread or a loader-list entry.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"

typedef struct _AMGER_INIT_CONTEXT {
    const AMGER_PE_IMAGE* Image;
    HANDLE ProcessId;
    uint64_t RemoteBase;
    PAMGER_INIT_REPORT Report;
} AMGER_INIT_CONTEXT, * PAMGER_INIT_CONTEXT;

NTSTATUS InitializePhase(const AMGER_INIT_CONTEXT* Context);
VOID InitializeRevert(const AMGER_INIT_CONTEXT* Context);

#endif /* AMGER_RUNTIME_H */
