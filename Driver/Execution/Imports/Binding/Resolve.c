#include "Resolve.h"
#include "../Lookup.h"

/*
 * All IAT writes stay inside the private image and go through the same MDL
 * pattern used by the mapping and relocation phases. Pages are still RW here;
 * SectionsSeal promotes them once after this pass. The target's PEB, loader
 * list and loaded modules are read only - no module is linked into the loader,
 * no user-mode API is called, and no VEH or INT3 trampoline is touched.
 */

#define AMGER_IMPORT_DESCRIPTOR_SIZE  20u
#define AMGER_DELAY_DESCRIPTOR_SIZE   32u
#define AMGER_MAX_THUNKS              8192u
#define AMGER_MAX_FORWARD_DEPTH       8u
#define AMGER_ORDINAL_FLAG            (1ull << 63)

#define AMGER_DIRECTORY_BOUND_IMPORT  11u
#define AMGER_OPTIONAL_DIRECTORIES    112u
#define AMGER_OPTIONAL_HEADER_OFFSET  24u

typedef struct _AMGER_RESOLVE_STATE {
    const AMGER_PE_IMAGE* Image;
    AMGER_LOOKUP_CONTEXT Lookup;
    PAMGER_IMPORT_REPORT Report;
    PUCHAR System;
    uint32_t Depth;
} AMGER_RESOLVE_STATE, * PAMGER_RESOLVE_STATE;

static uint32_t Read32(const PUCHAR bytes) {
    uint32_t value;
    RtlCopyMemory(&value, bytes, sizeof(value));
    return value;
}

static uint64_t Read64(const PUCHAR bytes) {
    uint64_t value;
    RtlCopyMemory(&value, bytes, sizeof(value));
    return value;
}

static void Write64(PUCHAR bytes, uint64_t value) {
    RtlCopyMemory(bytes, &value, sizeof(value));
}

static BOOLEAN InImage(const AMGER_PE_IMAGE* image, uint32_t rva, uint32_t length) {
    return rva < image->SizeOfImage && length <= image->SizeOfImage - rva;
}

static BOOLEAN ReadString(PUCHAR source, uint32_t available,
                          char* out, SIZE_T capacity) {
    SIZE_T index;
    if (capacity == 0u || available == 0u) {
        return FALSE;
    }
    for (index = 0u; index + 1u < capacity && index < available; ++index) {
        out[index] = (char)source[index];
        if (source[index] == 0u) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN AsciiEqual(const char* left, const char* right) {
    while (*left != 0 && *right != 0) {
        if (*left != *right) {
            return FALSE;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static VOID CopyAscii(char* destination, SIZE_T capacity, const char* source) {
    SIZE_T index;
    if (capacity == 0u) {
        return;
    }
    for (index = 0u; index + 1u < capacity && source[index] != 0; ++index) {
        destination[index] = source[index];
    }
    destination[index] = 0;
}

static VOID AnsiToWide(const char* ansi, WCHAR* wide, SIZE_T capacity) {
    SIZE_T index;
    for (index = 0u; ansi[index] != 0 && index + 1u < capacity; ++index) {
        wide[index] = (WCHAR)(UCHAR)ansi[index];
    }
    wide[index] = 0;
}

static NTSTATUS ResolveSymbol(
    PAMGER_RESOLVE_STATE state,
    const char* dllName,
    const char* symbolName,
    uint16_t ordinal,
    BOOLEAN byOrdinal,
    uint64_t* outAddress,
    uint64_t* outModuleBase) {
    WCHAR host[AMGER_LOOKUP_MAX_NAME];
    WCHAR converted[AMGER_LOOKUP_MAX_NAME];
    const WCHAR* moduleName;
    uint32_t moduleLength = 0u;
    BOOLEAN redirected = FALSE;
    uint64_t moduleBase = 0u;
    uint32_t moduleSize = 0u;
    AMGER_EXPORT_RESULT result;
    NTSTATUS status;
    uint64_t address;

    if (dllName == NULL || outAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *outAddress = 0u;
    if (outModuleBase != NULL) {
        *outModuleBase = 0u;
    }

    if (NT_SUCCESS(LookupResolveApiSet(&state->Lookup, dllName, host,
                                       sizeof(host), &moduleLength,
                                       &redirected)) &&
        redirected) {
        moduleName = host;
        if (moduleLength > AMGER_LOOKUP_MAX_NAME - 1u) {
            return STATUS_INVALID_PARAMETER;
        }
        host[moduleLength] = 0;
        state->Report->ApiSetRedirectCount++;
    } else {
        AnsiToWide(dllName, converted, sizeof(converted) / sizeof(converted[0]));
        while (converted[moduleLength] != 0 &&
               moduleLength < AMGER_LOOKUP_MAX_NAME - 1u) {
            ++moduleLength;
        }
        moduleName = converted;
    }
    if (moduleLength == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!LookupFindModule(&state->Lookup, moduleName, moduleLength,
                          &moduleBase, &moduleSize)) {
        /* Record the first unresolved import verbatim so the client can name
         * the dependency Phase 5 must provide instead of only showing a count. */
        if (state->Report->DeferredCount == 0u) {
            CopyAscii(state->Report->DeferredModule,
                      sizeof(state->Report->DeferredModule), dllName);
            CopyAscii(state->Report->DeferredSymbol,
                      sizeof(state->Report->DeferredSymbol),
                      byOrdinal ? "" : symbolName);
            state->Report->DeferredOrdinal = byOrdinal ? (uint32_t)ordinal : 0u;
        }
        {
            uint32_t slot;
            BOOLEAN present = FALSE;
            for (slot = 0u; slot < state->Report->DeferredModuleCount; ++slot) {
                if (AsciiEqual(state->Report->DeferredModules[slot], dllName)) {
                    present = TRUE;
                    break;
                }
            }
            if (!present && state->Report->DeferredModuleCount < 8u) {
                CopyAscii(state->Report->DeferredModules[state->Report->DeferredModuleCount],
                          AMGER_REPORT_NAME_LENGTH, dllName);
                ++state->Report->DeferredModuleCount;
            }
        }
        state->Report->UnresolvedCount++;
        state->Report->DeferredCount++;
        return STATUS_NOT_FOUND;
    }
    if (outModuleBase != NULL) {
        *outModuleBase = moduleBase;
    }

    status = LookupGetExport(moduleBase, moduleSize, symbolName, ordinal,
                             byOrdinal, &result);
    if (!NT_SUCCESS(status)) {
        state->Report->UnresolvedCount++;
        return status;
    }
    if (!result.Forwarded) {
        *outAddress = result.Address;
        return STATUS_SUCCESS;
    }

    state->Report->ForwardedCount++;
    if (state->Depth >= AMGER_MAX_FORWARD_DEPTH) {
        return STATUS_INVALID_PARAMETER;
    }
    ++state->Depth;
    status = ResolveSymbol(state, result.Module, result.Symbol, result.Ordinal,
                           result.ByOrdinal, &address, NULL);
    --state->Depth;
    if (NT_SUCCESS(status)) {
        *outAddress = address;
    }
    return status;
}

static NTSTATUS ResolveDescriptorTable(
    PAMGER_RESOLVE_STATE state,
    uint32_t tableRva,
    uint32_t tableSize,
    BOOLEAN delayed) {
    const AMGER_PE_IMAGE* image = state->Image;
    uint32_t descriptorSize = delayed ? AMGER_DELAY_DESCRIPTOR_SIZE
                                      : AMGER_IMPORT_DESCRIPTOR_SIZE;
    uint32_t descriptorCount = tableSize / descriptorSize;
    uint32_t index;

    if (descriptorCount == 0u || descriptorCount > 256u) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0u; index < descriptorCount; ++index) {
        uint32_t offset = tableRva + index * descriptorSize;
        PUCHAR descriptor;
        uint32_t nameRva;
        uint32_t lookupRva;
        uint32_t iatRva;
        uint32_t handleRva;
        char dllName[AMGER_LOOKUP_MAX_NAME];
        uint32_t thunkIndex;

        if (!InImage(image, offset, descriptorSize)) {
            return STATUS_INVALID_PARAMETER;
        }
        descriptor = state->System + offset;

        if (delayed) {
            uint32_t attributes = Read32(descriptor);
            nameRva = Read32(descriptor + 4u);
            handleRva = Read32(descriptor + 8u);
            iatRva = Read32(descriptor + 12u);
            lookupRva = Read32(descriptor + 16u);
            if ((attributes & 1u) == 0u) {
                nameRva -= (uint32_t)image->ImageBase;
                handleRva -= (uint32_t)image->ImageBase;
                iatRva -= (uint32_t)image->ImageBase;
                lookupRva -= (uint32_t)image->ImageBase;
            }
        } else {
            lookupRva = Read32(descriptor);
            nameRva = Read32(descriptor + 12u);
            iatRva = Read32(descriptor + 16u);
            handleRva = 0u;
        }

        if (nameRva == 0u && lookupRva == 0u && iatRva == 0u) {
            return STATUS_SUCCESS;
        }
        if (!InImage(image, nameRva, 1u) || !InImage(image, iatRva, 8u)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (lookupRva == 0u) {
            lookupRva = iatRva;
        }
        if (!InImage(image, lookupRva, 8u)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!ReadString(state->System + nameRva,
                        image->SizeOfImage - nameRva,
                        dllName, sizeof(dllName))) {
            return STATUS_INVALID_PARAMETER;
        }

        if (delayed) {
            state->Report->DelayModuleCount++;
        } else {
            state->Report->ModuleCount++;
        }

        for (thunkIndex = 0u; thunkIndex < AMGER_MAX_THUNKS; ++thunkIndex) {
            uint64_t thunk;
            uint64_t address = 0u;
            uint64_t moduleBase = 0u;
            uint32_t lookupOffset = lookupRva + thunkIndex * 8u;
            uint32_t iatOffset = iatRva + thunkIndex * 8u;
            NTSTATUS status;
            char symbol[AMGER_LOOKUP_MAX_SYMBOL];
            uint16_t ordinal = 0u;
            BOOLEAN byOrdinal = FALSE;

            if (!InImage(image, lookupOffset, 8u) ||
                !InImage(image, iatOffset, 8u)) {
                return STATUS_INVALID_PARAMETER;
            }
            thunk = Read64(state->System + lookupOffset);
            if (thunk == 0u) {
                break;
            }

            if ((thunk & AMGER_ORDINAL_FLAG) != 0u) {
                byOrdinal = TRUE;
                ordinal = (uint16_t)(thunk & 0xFFFFu);
                symbol[0] = 0;
            } else {
                uint32_t hintRva = (uint32_t)(thunk & 0x7FFFFFFFu);
                if (!InImage(image, hintRva, 4u) ||
                    !ReadString(state->System + hintRva + 2u,
                                image->SizeOfImage - hintRva - 2u,
                                symbol, sizeof(symbol))) {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            status = ResolveSymbol(state, dllName, symbol, ordinal, byOrdinal,
                                   &address, &moduleBase);
            if (!NT_SUCCESS(status)) {
                /* NOT_FOUND is an absent export or a module deferred to Phase 5.
                 * Any other status is a malformed table and must stay visible. */
                if (status != STATUS_NOT_FOUND) {
                    state->Report->LookupErrors++;
                }
                continue;
            }
            Write64(state->System + iatOffset, address);
            state->Report->FunctionsResolved++;
            if (byOrdinal) {
                state->Report->ByOrdinalCount++;
            } else {
                state->Report->ByNameCount++;
            }

            if (delayed && handleRva != 0u && moduleBase != 0u &&
                InImage(image, handleRva, 8u)) {
                /* The delay helper reads this slot; use the exact module that
                 * supplied the resolved export, including ApiSet hosts. */
                Write64(state->System + handleRva, moduleBase);
            }
        }
    }

    /* A table whose Size counts only non-null descriptors is still valid. */
    return STATUS_SUCCESS;
}

NTSTATUS ResolveImports(
    const AMGER_PE_IMAGE* image,
    HANDLE processId,
    uint64_t remoteBase,
    PAMGER_IMPORT_REPORT out) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    PMDL mdl = NULL;
    PUCHAR system = NULL;
    BOOLEAN attached = FALSE;
    BOOLEAN locked = FALSE;
    AMGER_RESOLVE_STATE state;
    NTSTATUS status;
    uint32_t boundOffset;

    if (out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(out, sizeof(*out));

    if (image == NULL || processId == NULL || remoteBase == 0u ||
        image->Base == NULL || image->SizeOfImage == 0u ||
        image->SizeOfHeaders == 0u || image->PeOffset == 0u) {
        out->Status = (uint32_t)STATUS_INVALID_PARAMETER;
        out->FailureStage = AMGER_IMPORT_STAGE_PARAMETERS;
        return STATUS_INVALID_PARAMETER;
    }

    out->RemoteBase = remoteBase;
    status = PsLookupProcessByProcessId(processId, &process);
    if (!NT_SUCCESS(status)) {
        out->Status = (uint32_t)status;
        out->FailureStage = AMGER_IMPORT_STAGE_PEB;
        return status;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    RtlZeroMemory(&state, sizeof(state));
    state.Image = image;
    state.Report = out;
    out->FailureStage = AMGER_IMPORT_STAGE_PEB;
    status = LookupInitialize(&state.Lookup);
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    out->FailureStage = AMGER_IMPORT_STAGE_MDL;
    mdl = IoAllocateMdl((PVOID)(uintptr_t)remoteBase, image->SizeOfImage,
                        FALSE, FALSE, NULL);
    if (mdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }
    __try {
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
        locked = TRUE;
    }
#pragma warning(suppress : 6320) /* deliberate: probe fault maps to a status */
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
    state.System = system;

    out->Flags |= AMGER_IMPORT_FLAG_RESOLVED;
    out->FailureStage = AMGER_IMPORT_STAGE_DESCRIPTOR;
    if (image->Directories[1u].Rva != 0u &&
        image->Directories[1u].Size != 0u) {
        status = ResolveDescriptorTable(&state, image->Directories[1u].Rva,
                                        image->Directories[1u].Size, FALSE);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
    }

    out->FailureStage = AMGER_IMPORT_STAGE_DELAY;
    if (image->NumberOfRvaAndSizes > 13u &&
        image->Directories[13u].Rva != 0u &&
        image->Directories[13u].Size != 0u) {
        status = ResolveDescriptorTable(&state, image->Directories[13u].Rva,
                                        image->Directories[13u].Size, TRUE);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
    }

    out->FailureStage = AMGER_IMPORT_STAGE_BOUND;
    if (image->NumberOfRvaAndSizes > AMGER_DIRECTORY_BOUND_IMPORT) {
        boundOffset = image->PeOffset + AMGER_OPTIONAL_HEADER_OFFSET +
                      AMGER_OPTIONAL_DIRECTORIES +
                      AMGER_DIRECTORY_BOUND_IMPORT * 8u;
        if (boundOffset + 8u > image->SizeOfHeaders) {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        Write64(system + boundOffset, 0u);
        out->Flags |= AMGER_IMPORT_FLAG_BOUND_CLEARED;
    }

    if (out->DeferredCount != 0u) {
        out->Flags |= AMGER_IMPORT_FLAG_DEFERRED;
    }
    out->FailureStage = AMGER_IMPORT_STAGE_NONE;
    out->Status = (uint32_t)STATUS_SUCCESS;
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
        out->Status = (uint32_t)status;
    }
    return status;
}
