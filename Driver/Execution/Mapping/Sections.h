#ifndef AMGER_SECTIONS_H
#define AMGER_SECTIONS_H

/*
 * Sections.h - Phase 2 (R8, R11) section mapping.
 *
 * Contract: commits the reserved image, copies headers and sections from the
 * parsed descriptor, then applies per-section protections. All target writes
 * go through an MDL-locked system mapping; protection changes use kernel-origin
 * Zw calls. The paired revert releases the whole reservation for R3 rollback.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"
#include "../Reserve/Allocate.h"

NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

NTSTATUS MapSectionsMap(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    PAMGER_MAP_REPORT Out);

NTSTATUS MapSectionsRevert(
    HANDLE ProcessId,
    uint64_t RemoteBase);

#endif /* AMGER_SECTIONS_H */
