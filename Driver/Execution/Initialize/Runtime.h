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

typedef struct _AMGER_ENTRY_SELECTION {
    uint32_t EntryKind;
    uint32_t EntryOrdinal;
    char     EntryName[AMGER_ENTRY_NAME_LENGTH];
} AMGER_ENTRY_SELECTION, * PAMGER_ENTRY_SELECTION;

NTSTATUS InitializePhase(const AMGER_INIT_CONTEXT* Context);
VOID InitializeRevert(const AMGER_INIT_CONTEXT* Context);

/* TRUE while any user APC queued by Phase 6 or 7 may still execute. The
 * injector must not release the image VAD until this returns FALSE: a late
 * APC's stub calls into the mapped image, so unmapping first crashes the
 * target process. */

BOOLEAN InitializeApcOutstanding(VOID);

/* Call once at the start of each inject. A prior inject that timed out leaves
 * its image and stub pages deliberately mapped, so its stale stub can still
 * run safely; clearing the counter here stops that one timeout from suppressing
 * rollback and TLS cleanup for every later inject. Injects are serialized by
 * the dispatcher's command mutex. */

VOID InitializeResetApcGate(VOID);

/* Phase 7 resolves the selected entry, calls the image's CRT entry once with
 * DLL_PROCESS_ATTACH through a dedicated user APC, then erases the mapped PE
 * headers while they are still writable. It must run after InitializePhase
 * and before SectionsSeal. */

NTSTATUS InvokeEntryPhase(const AMGER_INIT_CONTEXT* Context,
                          const AMGER_ENTRY_SELECTION* Selection,
                          PAMGER_ENTRY_REPORT Report);

#endif /* AMGER_RUNTIME_H */
