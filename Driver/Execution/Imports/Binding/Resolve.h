#ifndef AMGER_RESOLVE_H
#define AMGER_RESOLVE_H

/*
 * Resolve.h - Phase 4 (R10, R22, R4, R14, R9) import binding.
 *
 * Lives in Imports/Binding so the folder and file names differ.
 *
 * Contract: resolves the mapped image's static and delayed imports against
 * modules already present in the target, rewrites their IAT slots through one
 * MDL-locked system mapping, follows forwarded exports with a depth cap, and
 * invalidates stale bound-import data. Unresolved modules are recorded for
 * Phase 5 instead of failing the inject.
 */

#include <wdm.h>
#include "../../../../Shared/Protocol.h"
#include "../../../Utilities/Parser/Format.h"
#include "../../Reserve/Allocate.h"

NTSTATUS ResolveImports(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    PAMGER_IMPORT_REPORT Out);

#endif /* AMGER_RESOLVE_H */
