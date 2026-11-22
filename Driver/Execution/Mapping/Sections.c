#include "Sections.h"

/*
 * FileAlignment packs sections on disk; SectionAlignment spreads them in
 * memory. A flat copy is therefore wrong — every section is copied from its
 * RawOffset to RemoteBase + VirtualAddress, and the virtual tail beyond
 * SizeOfRawData is zero-filled.
 *
 * Protections are applied once per region. ETW-TI treats executable private
 * memory and protection fluctuation as high-signal, so each code page goes
 * RW -> RX exactly once and is never touched again. Execute+write sections are
 * promoted to PAGE_EXECUTE_READ: writes are already complete, and RWX is never
 * produced.
 */

#define AMGER_PAGE_SIZE 0x1000u

#define AMGER_SCN_CODE  0x20000000u
#define AMGER_SCN_READ  0x40000000u
#define AMGER_SCN_WRITE 0x80000000u

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

static uint32_t RoundUpPage(uint32_t value) {
    return (value + AMGER_PAGE_SIZE - 1u) & ~(AMGER_PAGE_SIZE - 1u);
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
    ULONG oldProtect;
    NTSTATUS status;
    uint32_t index;
    uint32_t span;
    uint32_t copyLength;
    uint32_t zeroLength;
    SIZE_T protectLength;
    PVOID protectAddress;
    ULONG protection;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    if (Image == NULL || ProcessId == NULL || RemoteBase == 0u ||
        Image->Base == NULL || Image->SizeOfImage == 0u ||
        Image->SizeOfHeaders == 0u || Image->SizeOfHeaders > Image->SizeOfImage ||
        Image->NumberOfSections == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    Out->RemoteBase = RemoteBase;
    Out->ImageSize = Image->SizeOfImage;
    Out->SectionCount = Image->NumberOfSections;
    Out->HeaderBytes = Image->SizeOfHeaders;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    base = (PVOID)(uintptr_t)RemoteBase;
    size = (SIZE_T)Image->SizeOfImage;
    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &base, 0u, &size, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    Out->Flags |= AMGER_MAP_FLAG_COMMITTED;

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

    RtlCopyMemory(system, Image->Base, Image->SizeOfHeaders);

    for (index = 0u; index < Image->NumberOfSections; ++index) {
        const AMGER_PE_SECTION* section = &Image->Sections[index];

        span = section->VirtualSize > section->RawSize
                   ? section->VirtualSize : section->RawSize;
        copyLength = section->VirtualSize < section->RawSize
                         ? section->VirtualSize : section->RawSize;

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

        (void)span;
    }
    Out->Flags |= AMGER_MAP_FLAG_COPIED;

    if (locked) {
        MmUnlockPages(mdl);
        locked = FALSE;
    }
    IoFreeMdl(mdl);
    mdl = NULL;

    protectAddress = (PVOID)(uintptr_t)RemoteBase;
    protectLength = RoundUpPage(Image->SizeOfHeaders);
    if (protectLength > Image->SizeOfImage) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    oldProtect = 0u;
    status = ZwProtectVirtualMemory(ZwCurrentProcess(), &protectAddress,
                                    &protectLength, PAGE_READONLY, &oldProtect);
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    for (index = 0u; index < Image->NumberOfSections; ++index) {
        const AMGER_PE_SECTION* section = &Image->Sections[index];
        span = section->VirtualSize > section->RawSize
                   ? section->VirtualSize : section->RawSize;
        if (span == 0u) {
            continue;
        }
        protectLength = RoundUpPage(span);
        if ((uint64_t)section->VirtualAddress + protectLength > Image->SizeOfImage) {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        protectAddress = (PVOID)(uintptr_t)(RemoteBase + section->VirtualAddress);
        protection = ProtectionForSection(section->Characteristics);
        oldProtect = 0u;
        status = ZwProtectVirtualMemory(ZwCurrentProcess(), &protectAddress,
                                        &protectLength, protection, &oldProtect);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
    }
    Out->Flags |= AMGER_MAP_FLAG_PROTECTED;
    Out->PageGroups = 1u + Image->NumberOfSections;

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

NTSTATUS MapSectionsRevert(
    HANDLE ProcessId,
    uint64_t RemoteBase) {
    return AllocateReleaseImage(ProcessId, RemoteBase);
}
