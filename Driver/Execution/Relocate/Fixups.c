#include "Fixups.h"

/*
 * The relocation directory describes the differences between the linked
 * base and the real base. Its entries are 16-bit values: the top four bits
 * are the fixup type, the low twelve are an offset from the block's PageRVA.
 * Relocation targets live in code and data sections, not inside .reloc, so
 * the MDL covers the whole mapped image rather than just the directory.
 *
 * Every field is read and written byte-wise: the directory is untrusted data
 * and x64 compilers may assume natural alignment for wider stores.
 */

#define AMGER_BASE_RELOCATION_DIRECTORY 5u

#define AMGER_REL_BASED_ABSOLUTE 0u
#define AMGER_REL_BASED_HIGHLOW  3u
#define AMGER_REL_BASED_DIR64    10u

static uint16_t ReadU16(const PUCHAR bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t ReadU32(const PUCHAR bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t ReadU64(const PUCHAR bytes) {
    return (uint64_t)ReadU32(bytes) | ((uint64_t)ReadU32(bytes + 4u) << 32);
}

static void WriteU32(PUCHAR bytes, uint32_t value) {
    bytes[0] = (UCHAR)(value & 0xFFu);
    bytes[1] = (UCHAR)((value >> 8) & 0xFFu);
    bytes[2] = (UCHAR)((value >> 16) & 0xFFu);
    bytes[3] = (UCHAR)((value >> 24) & 0xFFu);
}

static void WriteU64(PUCHAR bytes, uint64_t value) {
    WriteU32(bytes, (uint32_t)(value & 0xFFFFFFFFu));
    WriteU32(bytes + 4u, (uint32_t)(value >> 32));
}

NTSTATUS FixupsApply(
    const AMGER_PE_IMAGE* Image,
    HANDLE ProcessId,
    uint64_t RemoteBase,
    uint64_t Delta,
    PAMGER_RELOC_REPORT Out) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    PMDL mdl = NULL;
    PUCHAR system = NULL;
    BOOLEAN attached = FALSE;
    BOOLEAN locked = FALSE;
    const AMGER_PE_DIRECTORY* directory;
    PUCHAR block;
    PUCHAR target;
    uint32_t offset = 0u;
    uint32_t entryOffset;
    uint32_t pageRva;
    uint32_t blockSize;
    uint32_t entry;
    uint32_t entryType;
    uint32_t rvaOffset;
    uint32_t targetRva;
    uint32_t value32;
    uint32_t blocks = 0u;
    uint32_t fixups = 0u;
    uint32_t dir64 = 0u;
    uint32_t highLow = 0u;
    uint32_t skipped = 0u;
    uint64_t value64;
    NTSTATUS status;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    if (Image == NULL || ProcessId == NULL || RemoteBase == 0u ||
        Image->Base == NULL || Image->SizeOfImage == 0u ||
        Image->NumberOfRvaAndSizes <= AMGER_BASE_RELOCATION_DIRECTORY) {
        Out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        Out->FailureStage = AMGER_RELOC_STAGE_PARAMETERS;
        return STATUS_INVALID_PARAMETER;
    }

    directory = &Image->Directories[AMGER_BASE_RELOCATION_DIRECTORY];
    Out->Delta = Delta;
    Out->RemoteBase = RemoteBase;
    Out->RelocRva = directory->Rva;
    Out->RelocSize = directory->Size;

    /* R7: no .reloc directory means no safe base change, so fail cleanly. */

    if (directory->Rva == 0u || directory->Size < 8u ||
        directory->Rva >= Image->SizeOfImage ||
        directory->Size > Image->SizeOfImage - directory->Rva) {
        Out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        Out->FailureStage = AMGER_RELOC_STAGE_DIRECTORY;
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        Out->Status = (uint32_t)status;
        Out->FailureStage = AMGER_RELOC_STAGE_PROCESS;
        return status;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    Out->FailureStage = AMGER_RELOC_STAGE_MDL;
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

    Out->FailureStage = AMGER_RELOC_STAGE_BLOCK;
    while (offset + 8u <= directory->Size) {
        block = system + directory->Rva + offset;
        pageRva = ReadU32(block);
        blockSize = ReadU32(block + 4u);

        if (blockSize < 8u || (blockSize & 1u) != 0u ||
            blockSize > directory->Size - offset) {
            status = STATUS_INVALID_PARAMETER;
            Out->FailureStage = AMGER_RELOC_STAGE_BLOCK;
            goto done;
        }

        for (entryOffset = 8u; entryOffset + 2u <= blockSize;
             entryOffset += 2u) {
            entry = ReadU16(block + entryOffset);
            entryType = entry >> 12;
            rvaOffset = entry & 0x0FFFu;
            targetRva = pageRva + rvaOffset;

            if (targetRva < pageRva || targetRva > Image->SizeOfImage) {
                status = STATUS_INVALID_PARAMETER;
                Out->FailureStage = AMGER_RELOC_STAGE_ENTRY;
                goto done;
            }

            switch (entryType) {
            case AMGER_REL_BASED_ABSOLUTE:
                ++skipped;
                break;
            case AMGER_REL_BASED_HIGHLOW:
                if (targetRva > Image->SizeOfImage - 4u) {
                    status = STATUS_INVALID_PARAMETER;
                    Out->FailureStage = AMGER_RELOC_STAGE_ENTRY;
                    goto done;
                }
                target = system + targetRva;
                value32 = ReadU32(target);
                WriteU32(target, value32 + (uint32_t)Delta);
                ++highLow;
                ++fixups;
                break;
            case AMGER_REL_BASED_DIR64:
                if (targetRva > Image->SizeOfImage - 8u) {
                    status = STATUS_INVALID_PARAMETER;
                    Out->FailureStage = AMGER_RELOC_STAGE_ENTRY;
                    goto done;
                }
                target = system + targetRva;
                value64 = ReadU64(target);
                WriteU64(target, value64 + Delta);
                ++dir64;
                ++fixups;
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
                Out->FailureStage = AMGER_RELOC_STAGE_ENTRY;
                goto done;
            }
        }

        offset += blockSize;
        ++blocks;
    }

    Out->BlockCount = blocks;
    Out->FixupCount = fixups;
    Out->Dir64Count = dir64;
    Out->HighLowCount = highLow;
    Out->SkippedCount = skipped;
    Out->Flags |= AMGER_RELOC_FLAG_APPLIED;
    Out->FailureStage = AMGER_RELOC_STAGE_NONE;
    Out->Status = (uint32_t)STATUS_SUCCESS;
    status = STATUS_SUCCESS;

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
    if (!NT_SUCCESS(status)) {
        Out->Status = (uint32_t)status;
    }
    return status;
}
