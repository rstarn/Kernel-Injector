#ifndef AMGER_FIXUPS_H
#define AMGER_FIXUPS_H

/*
 * Fixups.h - Phase 3 (R7) base relocations.
 *
 * Contract: applies DIR64 and HIGHLOW fixups to the already mapped image using
 * the difference between the manager-chosen base and the PE preferred base.
 * All writes go through one MDL-locked system mapping while attached to the
 * target. Pages are still RW at this point; they are sealed once, afterwards.
 * A missing or malformed .reloc directory fails clean - no partial fixups
 * survive because the whole reservation is released on failure.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"
#include "../Reserve/Allocate.h"

NTSTATUS FixupsApply(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    uint64_t Delta,
    PAMGER_RELOC_REPORT Out);

#endif /* AMGER_FIXUPS_H */
