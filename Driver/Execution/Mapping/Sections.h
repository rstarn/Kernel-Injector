#ifndef AMGER_SECTIONS_H
#define AMGER_SECTIONS_H

/*
 * Sections.h - Phase 2 (R8, R11) section mapping.
 *
 * Contract: commits the reserved image and copies headers and sections from
 * the parsed descriptor through an MDL-locked system mapping. Protection is a
 * separate pass: SectionsSeal promotes the image once, after every phase that
 * still needs to write (relocations, imports, initialization) has finished.
 * That keeps each code page RW -> RX exactly once with no RWX state.
 * The paired revert releases the whole reservation for R3 rollback.
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

NTSTATUS SectionsSeal(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    PAMGER_MAP_REPORT Out);

NTSTATUS MapSectionsRevert(
    HANDLE ProcessId,
    uint64_t RemoteBase);

#endif /* AMGER_SECTIONS_H */
