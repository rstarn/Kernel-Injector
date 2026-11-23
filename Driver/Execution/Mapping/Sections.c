#include "Sections.h"

/*
 * FileAlignment packs sections on disk; SectionAlignment spreads them in
 * memory. A flat copy is therefore wrong - every section is copied from its
 * RawOffset to RemoteBase + VirtualAddress, and the virtual tail beyond
 * SizeOfRawData is zero-filled.
 *
 * Copy and seal are deliberately separate. Relocations, imports and load-config
 * initialization all write into the mapped image, so the pages stay RW until
 * SectionsSeal runs. ETW-TI treats executable private memory and protection
 * fluctuation as high-signal: each code page is promoted RW -> RX exactly once
 * and is never touched again. Execute+write sections are promoted to
 * PAGE_EXECUTE_READ, so an RWX page is never produced.
 *
 * Protection is computed per page and merged into contiguous runs. Sections
 * with a sub-page SectionAlignment can share a page; OR-ing their
 * characteristics before the single ZwProtectVirtualMemory call avoids both a
 * wrong final protection and repeated protection events on the same page.
 */

#define AMGER_PAGE_SIZE 0x1000u
#define AMGER_PAGE_MASK 0x0FFFu

#define AMGER_SCN_CODE  0x20000000u
#define AMGER_SCN_READ  0x40000000u
#define AMGER_SCN_WRITE 0x80000000u

/* Two boundaries per section, plus the image start and end. */

#define AMGER_SEAL_MAX_BOUNDARIES (2u * AMGER_PE_MAX_SECTIONS + 2u)

typedef struct _AMGER_SEAL_RUN {
    uint32_t StartPage;
    uint32_t PageCount;
    ULONG Protection;
} AMGER_SEAL_RUN;

static ULONG ProtectionForSection(uint32_t characteristics) {
    const BOOLEAN execute = (characteristics & AMGER_SCN_CODE) != 0u;
    const BOOLEAN readable = (characteristics & AMGER_SCN_READ) != 0u;
    const BOOLEAN writable = (characteristics & AMGER_SCN_WRITE) != 0u;

    if (!execute && !readable && !writable) {
        return PAGE_NOACCESS;
    }
    if (execute) {
        return PAGE_EXECUTE_READ;
    }
    if (writable) {
        return PAGE_READWRITE;
    }
    return PAGE_READONLY;
}

static uint32_t PageOf(uint32_t rva) {
    return rva >> 12;
}

static uint32_t PageCeil(uint32_t bytes) {
    return (bytes + AMGER_PAGE_MASK) >> 12;
}

static uint32_t SectionSpan(const AMGER_PE_SECTION* section) {
    return section->VirtualSize > section->RawSize
               ? section->VirtualSize
               : section->RawSize;
}

static BOOLEAN AddBoundary(uint32_t* boundaries, uint32_t* count, uint32_t page) {
    uint32_t index = 0u;
    uint32_t shift;

    while (index < *count && boundaries[index] < page) {
        ++index;
    }
    if (index < *count && boundaries[index] == page) {
        return TRUE;
    }
    if (*count >= AMGER_SEAL_MAX_BOUNDARIES) {
        return FALSE;
    }
    for (shift = *count; shift > index; --shift) {
        boundaries[shift] = boundaries[shift - 1u];
    }
    boundaries[index] = page;
    ++*count;
    return TRUE;
}

NTSTATUS MapSectionsMap(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    PAMGER_MAP_REPORT Out) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    PMDL mdl = NULL;
    PUCHAR system = NULL;
    BOOLEAN attached = FALSE;
    BOOLEAN locked = FALSE;
    PVOID base;
    SIZE_T size;
    NTSTATUS status;
    uint32_t index;
    uint32_t copyLength;
    uint32_t zeroLength;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    if (Image == NULL || ProcessId == NULL || RemoteBase == 0u ||
        Image->Base == NULL || Image->SizeOfImage == 0u ||
        Image->SizeOfHeaders == 0u || Image->SizeOfHeaders > Image->SizeOfImage ||
        Image->NumberOfSections == 0u) {
        Out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        Out->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
        return STATUS_INVALID_PARAMETER;
    }

    Out->RemoteBase = RemoteBase;
    Out->ImageSize = Image->SizeOfImage;
    Out->SectionCount = Image->NumberOfSections;
    Out->HeaderBytes = Image->SizeOfHeaders;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        Out->Status = (uint32_t)status;
        Out->FailureStage = AMGER_MAP_STAGE_PROCESS;
        return status;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    base = (PVOID)(uintptr_t)RemoteBase;
    size = (SIZE_T)Image->SizeOfImage;
    Out->FailureStage = AMGER_MAP_STAGE_COMMIT;
    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &base, 0u, &size, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    Out->Flags |= AMGER_MAP_FLAG_COMMITTED;

    Out->FailureStage = AMGER_MAP_STAGE_MDL;
    mdl = IoAllocateMdl((PVOID)(uintptr_t)RemoteBase, Image->SizeOfImage,
                        FALSE, FALSE, NULL);
    if (mdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
        locked = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    system = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (system == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Out->FailureStage = AMGER_MAP_STAGE_COPY;
    RtlCopyMemory(system, Image->Base, Image->SizeOfHeaders);

    for (index = 0u; index < Image->NumberOfSections; ++index) {
        const AMGER_PE_SECTION* section = &Image->Sections[index];

        copyLength = section->VirtualSize < section->RawSize
                         ? section->VirtualSize
                         : section->RawSize;

        if (copyLength != 0u) {
            if ((uint64_t)section->RawOffset + copyLength > Image->Size ||
                (uint64_t)section->VirtualAddress + copyLength > Image->SizeOfImage) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }
            RtlCopyMemory(system + section->VirtualAddress,
                          Image->Base + section->RawOffset, copyLength);
            Out->BytesCopied += copyLength;
        }

        if (section->VirtualSize > section->RawSize) {
            zeroLength = section->VirtualSize - section->RawSize;
            if ((uint64_t)section->VirtualAddress + section->VirtualSize >
                Image->SizeOfImage) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }
            RtlZeroMemory(system + section->VirtualAddress + copyLength, zeroLength);
            Out->ZeroFilled += zeroLength;
        }
    }
    Out->Flags |= AMGER_MAP_FLAG_COPIED;
    Out->FailureStage = AMGER_MAP_STAGE_NONE;

done:
    if (mdl != NULL) {
        if (locked) {
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
    }
    if (attached) {
        KeUnstackDetachProcess(&apc);
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }
    Out->Status = (uint32_t)status;
    return status;
}

NTSTATUS SectionsSeal(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    PAMGER_MAP_REPORT Out) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    BOOLEAN attached = FALSE;
    uint32_t boundaries[AMGER_SEAL_MAX_BOUNDARIES];
    AMGER_SEAL_RUN runs[AMGER_SEAL_MAX_BOUNDARIES];
    uint32_t boundaryCount = 0u;
    uint32_t runCount = 0u;
    uint32_t imagePages;
    uint32_t headerPages;
    uint32_t index;
    uint32_t sectionIndex;
    uint32_t startPage;
    uint32_t endPage;
    uint32_t span;
    uint32_t characteristics;
    uint64_t startByte;
    SIZE_T length;
    uint64_t available;
    PVOID address;
    ULONG oldProtect;
    NTSTATUS status;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Do not zero Out: it already carries the commit/copy result of this map. */

    if (Image == NULL || ProcessId == NULL || RemoteBase == 0u ||
        Image->SizeOfImage == 0u || Image->SizeOfHeaders == 0u ||
        Image->SizeOfHeaders > Image->SizeOfImage) {
        Out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        Out->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
        return STATUS_INVALID_PARAMETER;
    }

    imagePages = PageCeil(Image->SizeOfImage);
    headerPages = PageCeil(Image->SizeOfHeaders);

    if (!AddBoundary(boundaries, &boundaryCount, 0u) ||
        !AddBoundary(boundaries, &boundaryCount, headerPages) ||
        !AddBoundary(boundaries, &boundaryCount, imagePages)) {
        Out->Status = (uint32_t)STATUS_INSUFFICIENT_RESOURCES;
        Out->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (index = 0u; index < Image->NumberOfSections; ++index) {
        const AMGER_PE_SECTION* section = &Image->Sections[index];
        span = SectionSpan(section);
        if (span == 0u) {
            continue;
        }
        if ((uint64_t)section->VirtualAddress + span > Image->SizeOfImage ||
            !AddBoundary(boundaries, &boundaryCount, PageOf(section->VirtualAddress)) ||
            !AddBoundary(boundaries, &boundaryCount,
                         PageCeil(section->VirtualAddress + span))) {
            Out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
            Out->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
            return STATUS_INVALID_PARAMETER;
        }
    }

    for (index = 0u; index + 1u < boundaryCount; ++index) {
        startPage = boundaries[index];
        endPage = boundaries[index + 1u];
        characteristics = 0u;

        if (startPage < headerPages) {
            characteristics |= AMGER_SCN_READ;
        }
        for (sectionIndex = 0u; sectionIndex < Image->NumberOfSections;
             ++sectionIndex) {
            const AMGER_PE_SECTION* section = &Image->Sections[sectionIndex];
            span = SectionSpan(section);
            if (span == 0u) {
                continue;
            }
            if (startPage >= PageOf(section->VirtualAddress) &&
                startPage < PageCeil(section->VirtualAddress + span)) {
                characteristics |= section->Characteristics;
            }
        }

        if (runCount != 0u &&
            runs[runCount - 1u].Protection == ProtectionForSection(characteristics) &&
            runs[runCount - 1u].StartPage + runs[runCount - 1u].PageCount == startPage) {
            runs[runCount - 1u].PageCount += endPage - startPage;
        } else {
            if (runCount >= AMGER_SEAL_MAX_BOUNDARIES) {
                Out->Status = (uint32_t)STATUS_INSUFFICIENT_RESOURCES;
                Out->FailureStage = AMGER_MAP_STAGE_PARAMETERS;
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            runs[runCount].StartPage = startPage;
            runs[runCount].PageCount = endPage - startPage;
            runs[runCount].Protection = ProtectionForSection(characteristics);
            ++runCount;
        }
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        Out->Status = (uint32_t)status;
        Out->FailureStage = AMGER_MAP_STAGE_PROCESS;
        return status;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    Out->FailureStage = AMGER_MAP_STAGE_PROTECT;
    for (index = 0u; index < runCount; ++index) {
        startByte = (uint64_t)runs[index].StartPage << 12;
        length = (SIZE_T)runs[index].PageCount << 12;
        available = (uint64_t)Image->SizeOfImage - startByte;
        if (length > available) {
            length = (SIZE_T)available;
        }
        if (length == 0u) {
            continue;
        }

        address = (PVOID)(uintptr_t)(RemoteBase + startByte);
        oldProtect = 0u;
        status = ZwProtectVirtualMemory(ZwCurrentProcess(), &address,
                                        &length, runs[index].Protection,
                                        &oldProtect);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
    }

    Out->Flags |= AMGER_MAP_FLAG_PROTECTED;
    Out->PageGroups = runCount;
    Out->FailureStage = AMGER_MAP_STAGE_NONE;
    Out->Status = (uint32_t)STATUS_SUCCESS;
    status = STATUS_SUCCESS;

done:
    if (attached) {
        KeUnstackDetachProcess(&apc);
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }
    if (!NT_SUCCESS(status)) {
        Out->Status = (uint32_t)status;
    }
    return status;
}

NTSTATUS MapSectionsRevert(
    HANDLE ProcessId,
    uint64_t RemoteBase) {
    return AllocateReleaseImage(ProcessId, RemoteBase);
}
