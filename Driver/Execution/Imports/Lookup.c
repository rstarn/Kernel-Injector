#include "Lookup.h"

/*
 * Every field below lives in the target process. Reads are passive: MDL locking
 * is not needed because KeStackAttachProcess makes the target page tables
 * current, and a user-mode page fault at APC_LEVEL is still serviced. Each read
 * is bounded to the x64 user range and wrapped in SEH, so a malicious or torn
 * PEB/LDR/ApiSet structure fails the phase cleanly rather than faulting the
 * driver. Nothing here writes to the target.
 */

#define AMGER_USER_LIMIT 0x0000800000000000ull

#define AMGER_PE_OFFSET_FIELD    0x03cu
/* PE signature (4) + COFF file header (20) precede the optional header. */
#define AMGER_OPTIONAL_HEADER_OFFSET 24u
#define AMGER_OPTIONAL_HEADER_MAGIC_OFFSET 0u
#define AMGER_OPTIONAL_HEADER_DIRCOUNT_OFFSET 108u
#define AMGER_OPTIONAL_HEADER_DIRECTORIES_OFFSET 112u
#define AMGER_EXPORT_DIRECTORY_INDEX 0u
#define AMGER_EXPORT_DIRECTORY_MIN   40u

typedef struct _AMGER_UNICODE_VIEW {
    USHORT Length;
    USHORT MaximumLength;
    PVOID Buffer;
} AMGER_UNICODE_VIEW, * PAMGER_UNICODE_VIEW;

typedef struct _AMGER_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} AMGER_PROCESS_BASIC_INFORMATION, * PAMGER_PROCESS_BASIC_INFORMATION;

typedef struct _AMGER_PRIVATE_MODULE {
    WCHAR Name[AMGER_LOOKUP_MAX_NAME];
    uint32_t Length;
    uint64_t Base;
    uint32_t Size;
} AMGER_PRIVATE_MODULE, * PAMGER_PRIVATE_MODULE;

static AMGER_PRIVATE_MODULE g_privateModules[64];
static uint32_t g_privateCount = 0u;

static BOOLEAN UserRead(uint64_t address, PVOID destination, SIZE_T length) {
    if (address == 0u || length == 0u ||
        address >= AMGER_USER_LIMIT || length > AMGER_USER_LIMIT - address) {
        return FALSE;
    }
    __try {
        RtlCopyMemory(destination, (const VOID*)(uintptr_t)address, length);
    }
#pragma warning(suppress : 6320) /* deliberate: user read faults map to FALSE */
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static uint16_t Read16(const UCHAR* bytes) {
    uint16_t value;
    RtlCopyMemory(&value, bytes, sizeof(value));
    return value;
}

static uint32_t Read32(const UCHAR* bytes) {
    uint32_t value;
    RtlCopyMemory(&value, bytes, sizeof(value));
    return value;
}

static uint64_t Read64(const UCHAR* bytes) {
    uint64_t value;
    RtlCopyMemory(&value, bytes, sizeof(value));
    return value;
}

static WCHAR LowerW(WCHAR value) {
    return (value >= L'A' && value <= L'Z') ? (WCHAR)(value + 0x20u) : value;
}

static BOOLEAN WideEqual(const WCHAR* left, uint32_t leftLength,
                         const WCHAR* right, uint32_t rightLength) {
    uint32_t index;
    if (leftLength != rightLength) {
        return FALSE;
    }
    for (index = 0u; index < leftLength; ++index) {
        if (LowerW(left[index]) != LowerW(right[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static int32_t WideCompare(const WCHAR* left, uint32_t leftLength,
                           const WCHAR* right, uint32_t rightLength) {
    uint32_t index;
    uint32_t shared = leftLength < rightLength ? leftLength : rightLength;
    for (index = 0u; index < shared; ++index) {
        WCHAR a = LowerW(left[index]);
        WCHAR b = LowerW(right[index]);
        if (a < b) {
            return -1;
        }
        if (a > b) {
            return 1;
        }
    }
    if (leftLength < rightLength) {
        return -1;
    }
    return leftLength > rightLength ? 1 : 0;
}

static BOOLEAN ApiRead(uint64_t ns, uint64_t offset, PVOID destination,
                       SIZE_T length, uint32_t nsSize) {
    if (offset > nsSize || length > nsSize - offset) {
        return FALSE;
    }
    return UserRead(ns + offset, destination, length);
}

static BOOLEAN PrepareApiName(const char* ansi, WCHAR* wide, uint32_t* length) {
    uint32_t index;

    if (ansi[0] == 0) {
        return FALSE;
    }
    if (!((ansi[0] == 'a' || ansi[0] == 'A') &&
          (ansi[1] == 'p' || ansi[1] == 'P') &&
          (ansi[2] == 'i' || ansi[2] == 'I') &&
          (ansi[3] == '-')) &&
        !((ansi[0] == 'e' || ansi[0] == 'E') &&
          (ansi[1] == 'x' || ansi[1] == 'X') &&
          (ansi[2] == 't' || ansi[2] == 'T') &&
          (ansi[3] == '-'))) {
        return FALSE;
    }

    for (index = 0u; ansi[index] != 0 && index < AMGER_LOOKUP_MAX_NAME - 1u;
         ++index) {
        UCHAR value = (UCHAR)ansi[index];
        if (value >= 'A' && value <= 'Z') {
            value = (UCHAR)(value + 0x20u);
        }
        wide[index] = (WCHAR)value;
    }
    wide[index] = 0;
    *length = index;
    return index > 4u;
}

static BOOLEAN TrimApiName(WCHAR* name, uint32_t* length) {
    uint32_t index = *length;
    while (index > 0u && name[index - 1u] != L'-') {
        --index;
    }
    if (index <= 4u) {
        return FALSE;
    }
    *length = index - 1u;
    name[*length] = 0;
    return TRUE;
}

static NTSTATUS ResolveApiSetV6(uint64_t ns, uint32_t nsSize,
                                const WCHAR* name, uint32_t nameLength,
                                WCHAR* outHost, uint32_t* outLength) {
    UCHAR headerBytes[28];
    UCHAR hashBytes[8];
    UCHAR entryBytes[24];
    UCHAR valueBytes[20];
    uint32_t multiplier;
    uint32_t hash = 0u;
    uint32_t count;
    uint32_t entryOffset;
    uint32_t hashesOffset;
    uint32_t index;
    uint32_t low = 0u;
    uint32_t middle;
    uint32_t high;
    uint32_t foundIndex = 0u;
    BOOLEAN found = FALSE;
    uint32_t dataOffset;
    uint32_t valueCount;
    uint32_t valueOffset;
    uint32_t valueLength;

    if (!ApiRead(ns, 0u, headerBytes, sizeof(headerBytes), nsSize) ||
        Read32(headerBytes) != 6u) {
        return STATUS_INVALID_PARAMETER;
    }
    if (nsSize < sizeof(headerBytes)) {
        return STATUS_INVALID_PARAMETER;
    }
    count = Read32(headerBytes + 12u);
    entryOffset = Read32(headerBytes + 16u);
    hashesOffset = Read32(headerBytes + 20u);
    multiplier = Read32(headerBytes + 24u);
    if (count == 0u || count > 0x10000u || multiplier == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0u; index < nameLength; ++index) {
        hash = hash * multiplier + (uint32_t)LowerW(name[index]);
    }

    high = count - 1u;
    while (low <= high) {
        middle = low + ((high - low) >> 1);
        if (!ApiRead(ns, (uint64_t)hashesOffset + (uint64_t)middle * 8u,
                     hashBytes, sizeof(hashBytes), nsSize)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (hash < Read32(hashBytes)) {
            if (middle == 0u) {
                break;
            }
            high = middle - 1u;
        } else if (hash > Read32(hashBytes)) {
            low = middle + 1u;
        } else {
            foundIndex = Read32(hashBytes + 4u);
            found = TRUE;
            break;
        }
    }
    if (!found || foundIndex >= count) {
        return STATUS_NOT_FOUND;
    }

    if (!ApiRead(ns, (uint64_t)entryOffset + (uint64_t)foundIndex * 24u,
                 entryBytes, sizeof(entryBytes), nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    valueCount = Read32(entryBytes + 20u);
    dataOffset = Read32(entryBytes + 16u);
    if (valueCount == 0u || valueCount > 0x1000u) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ApiRead(ns, (uint64_t)dataOffset, valueBytes, sizeof(valueBytes),
                 nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    valueOffset = Read32(valueBytes + 12u);
    valueLength = Read32(valueBytes + 16u);
    if (valueOffset == 0u || valueLength == 0u ||
        (valueLength & 1u) != 0u || valueLength > AMGER_LOOKUP_MAX_NAME * 2u) {
        return STATUS_NOT_FOUND;
    }
    if (!ApiRead(ns, valueOffset, outHost, valueLength, nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    *outLength = valueLength / 2u;
    return STATUS_SUCCESS;
}

static NTSTATUS ResolveApiSetV4V2(uint64_t ns, uint32_t nsSize,
                                  const WCHAR* name, uint32_t nameLength,
                                  WCHAR* outHost, uint32_t* outLength) {
    UCHAR nsBytes[16];
    UCHAR entryBytes[24];
    UCHAR arrayBytes[8];
    UCHAR valueBytes[20];
    uint32_t version;
    uint32_t count;
    uint32_t entryStride;
    uint32_t entriesOffset;
    uint32_t low = 0u;
    uint32_t high;
    uint32_t middle;
    uint32_t nameOffset;
    uint32_t nameByteLength;
    uint32_t dataOffset = 0u;
    uint32_t valueStride;
    uint32_t hostOffset;
    uint32_t hostLength;
    BOOLEAN found = FALSE;
    WCHAR candidate[AMGER_LOOKUP_MAX_NAME];

    if (!ApiRead(ns, 0u, nsBytes, sizeof(nsBytes), nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    version = Read32(nsBytes);
    if (version == 4u) {
        count = Read32(nsBytes + 12u);
        entriesOffset = 16u;
        entryStride = 24u;
        valueStride = 20u;
    } else if (version == 2u) {
        count = Read32(nsBytes + 4u);
        entriesOffset = 8u;
        entryStride = 12u;
        valueStride = 16u;
    } else {
        return STATUS_NOT_SUPPORTED;
    }
    if (count == 0u || count > 0x10000u) {
        return STATUS_INVALID_PARAMETER;
    }

    high = count - 1u;
    while (low <= high) {
        middle = low + ((high - low) >> 1);
        if (!ApiRead(ns, (uint64_t)entriesOffset + (uint64_t)middle * entryStride,
                     entryBytes, entryStride, nsSize)) {
            return STATUS_INVALID_PARAMETER;
        }
        nameOffset = Read32(entryBytes + 4u);
        nameByteLength = Read32(entryBytes + 8u);
        if ((nameByteLength & 1u) != 0u ||
            nameByteLength / 2u > AMGER_LOOKUP_MAX_NAME - 1u) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!ApiRead(ns, nameOffset, candidate, nameByteLength, nsSize)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (WideEqual(name, nameLength, candidate, nameByteLength / 2u)) {
            found = TRUE;
            dataOffset = version == 4u ? Read32(entryBytes + 20u)
                                       : Read32(entryBytes + 8u);
            break;
        }
        if (WideCompare(name, nameLength, candidate, nameByteLength / 2u) < 0) {
            if (middle == 0u) {
                break;
            }
            high = middle - 1u;
        } else {
            low = middle + 1u;
        }
    }
    if (!found) {
        return STATUS_NOT_FOUND;
    }

    if (!ApiRead(ns, dataOffset, arrayBytes,
                 version == 4u ? 8u : 4u, nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!ApiRead(ns, dataOffset + (version == 4u ? 8u : 4u), valueBytes,
                 valueStride, nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (version == 4u) {
        hostOffset = Read32(valueBytes + 12u);
        hostLength = Read32(valueBytes + 16u);
    } else {
        hostOffset = Read32(valueBytes + 8u);
        hostLength = Read32(valueBytes + 12u);
    }
    if (hostOffset == 0u || hostLength == 0u ||
        (hostLength & 1u) != 0u || hostLength > AMGER_LOOKUP_MAX_NAME * 2u) {
        return STATUS_NOT_FOUND;
    }
    if (!ApiRead(ns, hostOffset, outHost, hostLength, nsSize)) {
        return STATUS_INVALID_PARAMETER;
    }
    *outLength = hostLength / 2u;
    return STATUS_SUCCESS;
}

static BOOLEAN MatchPrivateModule(const WCHAR* name, uint32_t length,
                                  uint64_t* outBase, uint32_t* outSize) {
    uint32_t index;
    for (index = 0u; index < g_privateCount; ++index) {
        if (WideEqual(name, length, g_privateModules[index].Name,
                      g_privateModules[index].Length)) {
            *outBase = g_privateModules[index].Base;
            *outSize = g_privateModules[index].Size;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN MatchLoaderModule(const AMGER_LOOKUP_CONTEXT* context,
                                 const WCHAR* name, uint32_t length,
                                 uint64_t* outBase, uint32_t* outSize) {
    uint64_t head;
    uint64_t entry;
    uint32_t visited;

    if (!UserRead(context->LdrHead + AMGER_PEB_LDR_LOAD_ORDER_OFFSET,
                  &head, sizeof(head))) {
        return FALSE;
    }
    entry = head;
    for (visited = 0u; visited < AMGER_LOOKUP_MAX_LIST; ++visited) {
        UCHAR raw[0x120];
        AMGER_UNICODE_VIEW dllName;
        uint64_t next;
        uint64_t base;
        uint32_t size;

        if (entry == 0u || !UserRead(entry, raw, sizeof(raw))) {
            return FALSE;
        }
        base = Read64(raw + AMGER_LDR_DLLBASE_OFFSET);
        size = Read32(raw + AMGER_LDR_SIZEOFIMAGE_OFFSET);
        RtlCopyMemory(&dllName, raw + AMGER_LDR_BASEDLLNAME_OFFSET,
                      sizeof(dllName));

        if (base != 0u && size != 0u && dllName.Length != 0u &&
            (dllName.Length & 1u) == 0u &&
            dllName.Length / 2u <= AMGER_LOOKUP_MAX_NAME - 1u) {
            WCHAR candidate[AMGER_LOOKUP_MAX_NAME];
            if (UserRead((uint64_t)(uintptr_t)dllName.Buffer, candidate,
                         dllName.Length) &&
                WideEqual(name, length, candidate, dllName.Length / 2u)) {
                *outBase = base;
                *outSize = size;
                return TRUE;
            }
        }

        next = Read64(raw);
        if (next == 0u || next == head) {
            return FALSE;
        }
        entry = next;
    }
    return FALSE;
}

static BOOLEAN ReadAsciiAt(uint64_t base, uint32_t size, uint32_t rva,
                           char* out, SIZE_T capacity) {
    uint64_t address;
    SIZE_T index;

    if (rva == 0u || rva >= size) {
        return FALSE;
    }
    address = base + rva;
    for (index = 0u; index + 1u < capacity && index < size - rva; ++index) {
        UCHAR value;
        if (!UserRead(address + index, &value, 1u)) {
            return FALSE;
        }
        out[index] = (char)value;
        if (value == 0u) {
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

static SIZE_T AsciiLength(const char* value) {
    SIZE_T length = 0u;
    while (value[length] != 0 && length < AMGER_LOOKUP_MAX_NAME) {
        ++length;
    }
    return length;
}

static BOOLEAN EndsWithDll(const char* value) {
    SIZE_T length = AsciiLength(value);
    if (length < 4u) {
        return FALSE;
    }
    value += length - 4u;
    return value[0] == '.' &&
           (value[1] == 'd' || value[1] == 'D') &&
           (value[2] == 'l' || value[2] == 'L') &&
           (value[3] == 'l' || value[3] == 'L');
}

NTSTATUS LookupInitialize(AMGER_LOOKUP_CONTEXT* Out) {
    AMGER_PROCESS_BASIC_INFORMATION info;
    uint64_t peb;
    uint64_t ldr;
    uint64_t apiSet;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    RtlZeroMemory(&info, sizeof(info));

    if (!NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), 0u,
                                              &info, sizeof(info), NULL))) {
        return STATUS_UNSUCCESSFUL;
    }
    peb = (uint64_t)(uintptr_t)info.PebBaseAddress;
    if (peb == 0u || peb >= AMGER_USER_LIMIT ||
        !UserRead(peb + AMGER_PEB_LDR_OFFSET, &ldr, sizeof(ldr)) ||
        !UserRead(peb + AMGER_PEB_APISET_OFFSET, &apiSet, sizeof(apiSet))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ldr == 0u || ldr >= AMGER_USER_LIMIT ||
        (apiSet != 0u && apiSet >= AMGER_USER_LIMIT)) {
        return STATUS_INVALID_PARAMETER;
    }

    Out->Peb = peb;
    Out->LdrHead = ldr;
    Out->ApiSetMap = apiSet;
    return STATUS_SUCCESS;
}

NTSTATUS LookupCountLoaderModules(HANDLE ProcessId, uint32_t* OutCount) {
    PEPROCESS process = NULL;
    KAPC_STATE apc;
    BOOLEAN attached = FALSE;
    AMGER_LOOKUP_CONTEXT context;
    uint64_t head = 0u;
    uint64_t entry;
    uint32_t visited;
    uint32_t count = 0u;
    NTSTATUS status;

    if (OutCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutCount = 0u;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    KeStackAttachProcess((PRKPROCESS)process, &apc);
    attached = TRUE;

    status = LookupInitialize(&context);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    if (!UserRead(context.LdrHead + AMGER_PEB_LDR_LOAD_ORDER_OFFSET,
                  &head, sizeof(head))) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    entry = head;
    for (visited = 0u; visited < AMGER_LOOKUP_MAX_LIST; ++visited) {
        UCHAR raw[0x120];
        uint64_t next;

        if (entry == 0u) {
            break;
        }
        if (!UserRead(entry, raw, sizeof(raw))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ++count;
        next = Read64(raw);
        if (next == 0u || next == head) {
            break;
        }
        entry = next;
    }

done:
    if (attached) {
        KeUnstackDetachProcess(&apc);
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }
    *OutCount = count;
    return status;
}

NTSTATUS LookupResolveApiSet(
    const AMGER_LOOKUP_CONTEXT* context,
    const char* ansiName,
    WCHAR* outHost,
    SIZE_T outCapacity,
    uint32_t* outLength,
    BOOLEAN* outRedirected) {
    WCHAR name[AMGER_LOOKUP_MAX_NAME];
    uint32_t length = 0u;
    uint32_t effectiveLength;
    UCHAR versionBytes[4];
    uint32_t namespaceSize;
    NTSTATUS status;

    if (outRedirected != NULL) {
        *outRedirected = FALSE;
    }
    if (context == NULL || context->ApiSetMap == 0u || ansiName == NULL ||
        outHost == NULL || outLength == NULL ||
        outCapacity / sizeof(WCHAR) < AMGER_LOOKUP_MAX_NAME) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!PrepareApiName(ansiName, name, &length)) {
        return STATUS_NOT_FOUND;
    }
    if (!UserRead(context->ApiSetMap, versionBytes, sizeof(versionBytes))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* v2 has no Size header; use the same upper bound as a v4/v6 Size field. */
    if (Read32(versionBytes) == 2u) {
        namespaceSize = 0x100000u;
    } else if (!UserRead(context->ApiSetMap + 4u, &namespaceSize,
                         sizeof(namespaceSize)) ||
               namespaceSize < 16u || namespaceSize > 0x100000u) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Read32(versionBytes) == 6u) {
        effectiveLength = length;
        if (!TrimApiName(name, &effectiveLength)) {
            return STATUS_NOT_FOUND;
        }
        status = ResolveApiSetV6(context->ApiSetMap, namespaceSize, name,
                                 effectiveLength, outHost, outLength);
    } else {
        effectiveLength = length - 4u;
        if (effectiveLength >= 4u &&
            name[effectiveLength - 4u] == L'.' &&
            LowerW(name[effectiveLength - 3u]) == L'd' &&
            LowerW(name[effectiveLength - 2u]) == L'l' &&
            LowerW(name[effectiveLength - 1u]) == L'l') {
            effectiveLength -= 4u;
        }
        if (effectiveLength == 0u) {
            return STATUS_NOT_FOUND;
        }
        RtlMoveMemory(name, name + 4u, effectiveLength * sizeof(WCHAR));
        name[effectiveLength] = 0;
        status = ResolveApiSetV4V2(context->ApiSetMap, namespaceSize, name,
                                   effectiveLength, outHost, outLength);
    }
    if (NT_SUCCESS(status) && outRedirected != NULL) {
        *outRedirected = TRUE;
    }
    return status;
}

BOOLEAN LookupFindModule(
    const AMGER_LOOKUP_CONTEXT* context,
    const WCHAR* name,
    uint32_t nameLength,
    uint64_t* outBase,
    uint32_t* outSize) {
    if (context == NULL || name == NULL || outBase == NULL || outSize == NULL ||
        nameLength == 0u || nameLength > AMGER_LOOKUP_MAX_NAME) {
        return FALSE;
    }
    if (MatchPrivateModule(name, nameLength, outBase, outSize)) {
        return TRUE;
    }
    return MatchLoaderModule(context, name, nameLength, outBase, outSize);
}

NTSTATUS LookupGetExport(
    uint64_t moduleBase,
    uint32_t moduleSize,
    const char* name,
    uint16_t ordinal,
    BOOLEAN byOrdinal,
    AMGER_EXPORT_RESULT* out) {
    UCHAR raw[4];
    UCHAR coff[24];
    UCHAR optional[128];
    UCHAR exportDir[AMGER_EXPORT_DIRECTORY_MIN];
    uint32_t peOffset;
    uint32_t magic;
    uint32_t directoryCount;
    uint32_t exportRva;
    uint32_t exportSize;
    uint32_t functionBase;
    uint32_t functionCount;
    uint32_t nameCount;
    uint32_t functionsRva;
    uint32_t namesRva;
    uint32_t ordinalsRva;
    uint32_t entryIndex = 0u;
    uint32_t index;
    uint32_t functionRva;
    char symbol[AMGER_LOOKUP_MAX_SYMBOL];
    char host[AMGER_LOOKUP_MAX_NAME];

    if (moduleBase == 0u || moduleSize < 0x1000u || out == NULL ||
        (!byOrdinal && name == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(out, sizeof(*out));

    if (!UserRead(moduleBase + AMGER_PE_OFFSET_FIELD, raw, 4u)) {
        return STATUS_INVALID_PARAMETER;
    }
    peOffset = Read32(raw);
    if (peOffset < 0x40u || (uint64_t)peOffset + 24u > moduleSize ||
        !UserRead(moduleBase + peOffset, coff, sizeof(coff)) ||
        Read32(coff) != 0x00004550u || Read16(coff + 4u) != 0x8664u) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!UserRead(moduleBase + peOffset + AMGER_OPTIONAL_HEADER_OFFSET, optional,
                  sizeof(optional))) {
        return STATUS_INVALID_PARAMETER;
    }
    magic = Read16(optional);
    directoryCount = Read32(optional + AMGER_OPTIONAL_HEADER_DIRCOUNT_OFFSET);
    if (magic != 0x020bu || directoryCount <= AMGER_EXPORT_DIRECTORY_INDEX) {
        return STATUS_INVALID_PARAMETER;
    }
    exportRva = Read32(optional + AMGER_OPTIONAL_HEADER_DIRECTORIES_OFFSET +
                       AMGER_EXPORT_DIRECTORY_INDEX * 8u);
    exportSize = Read32(optional + AMGER_OPTIONAL_HEADER_DIRECTORIES_OFFSET +
                        AMGER_EXPORT_DIRECTORY_INDEX * 8u + 4u);
    if (exportRva == 0u || exportSize < AMGER_EXPORT_DIRECTORY_MIN ||
        exportRva >= moduleSize || exportSize > moduleSize - exportRva ||
        !UserRead(moduleBase + exportRva, exportDir, sizeof(exportDir))) {
        return STATUS_INVALID_PARAMETER;
    }

    functionBase = Read32(exportDir + 16u);
    functionCount = Read32(exportDir + 20u);
    nameCount = Read32(exportDir + 24u);
    functionsRva = Read32(exportDir + 28u);
    namesRva = Read32(exportDir + 32u);
    ordinalsRva = Read32(exportDir + 36u);
    if (functionCount == 0u || functionCount > 0x10000u ||
        nameCount > 0x10000u || functionsRva == 0u ||
        (uint64_t)functionsRva + (uint64_t)functionCount * 4u > moduleSize) {
        return STATUS_INVALID_PARAMETER;
    }

    if (byOrdinal) {
        if (ordinal < functionBase) {
            return STATUS_NOT_FOUND;
        }
        entryIndex = (uint32_t)ordinal - functionBase;
        out->ByOrdinal = TRUE;
        out->Ordinal = ordinal;
        if (entryIndex >= functionCount) {
            return STATUS_NOT_FOUND;
        }
    } else {
        for (index = 0u; index < nameCount; ++index) {
            if (!UserRead(moduleBase + namesRva + (uint64_t)index * 4u,
                          raw, 4u)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!ReadAsciiAt(moduleBase, moduleSize, Read32(raw),
                             symbol, sizeof(symbol))) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!AsciiEqual(symbol, name)) {
                continue;
            }
            if (!UserRead(moduleBase + ordinalsRva + (uint64_t)index * 2u,
                          raw, 2u)) {
                return STATUS_INVALID_PARAMETER;
            }
            entryIndex = Read16(raw);
            if (entryIndex >= functionCount) {
                return STATUS_INVALID_PARAMETER;
            }
            break;
        }
        if (index == nameCount) {
            return STATUS_NOT_FOUND;
        }
    }

    if (!UserRead(moduleBase + functionsRva + (uint64_t)entryIndex * 4u,
                  raw, 4u)) {
        return STATUS_INVALID_PARAMETER;
    }
    functionRva = Read32(raw);
    if (functionRva == 0u || functionRva >= moduleSize) {
        return STATUS_NOT_FOUND;
    }

    if (functionRva >= exportRva &&
        (uint64_t)functionRva < (uint64_t)exportRva + exportSize) {
        char* dot;
        if (!ReadAsciiAt(moduleBase, moduleSize, functionRva,
                         out->Symbol, sizeof(out->Symbol))) {
            return STATUS_INVALID_PARAMETER;
        }
        dot = NULL;
        for (index = 0u; out->Symbol[index] != 0; ++index) {
            if (out->Symbol[index] == '.') {
                dot = &out->Symbol[index];
            }
        }
        if (dot == NULL) {
            return STATUS_INVALID_PARAMETER;
        }
        *dot = 0;
        RtlCopyMemory(host, out->Symbol, sizeof(host));
        RtlMoveMemory(out->Symbol, dot + 1u,
                      sizeof(out->Symbol) - (SIZE_T)(dot + 1u - out->Symbol));
        out->Forwarded = TRUE;
        if (out->Symbol[0] == '#') {
            uint32_t value = 0u;
            for (index = 1u; out->Symbol[index] != 0; ++index) {
                if (out->Symbol[index] < '0' || out->Symbol[index] > '9') {
                    return STATUS_INVALID_PARAMETER;
                }
                value = value * 10u + (uint32_t)(out->Symbol[index] - '0');
            }
            out->ByOrdinal = TRUE;
            out->Ordinal = (uint16_t)value;
            out->Symbol[0] = 0;
        }
        if (!EndsWithDll(host)) {
            SIZE_T hostLength = AsciiLength(host);
            if (hostLength + 4u < sizeof(out->Module)) {
                RtlCopyMemory(out->Module, host, hostLength);
                RtlCopyMemory(out->Module + hostLength, ".dll", 5u);
            }
        } else {
            RtlCopyMemory(out->Module, host, sizeof(out->Module));
        }
        out->Address = 0u;
        return STATUS_SUCCESS;
    }

    out->Address = moduleBase + functionRva;
    return STATUS_SUCCESS;
}

VOID LookupResetPrivate(VOID) {
    RtlZeroMemory(g_privateModules, sizeof(g_privateModules));
    g_privateCount = 0u;
}

BOOLEAN LookupRegisterPrivate(
    const WCHAR* name,
    uint32_t nameLength,
    uint64_t base,
    uint32_t size) {
    AMGER_PRIVATE_MODULE* entry;
    if (name == NULL || nameLength == 0u ||
        nameLength > AMGER_LOOKUP_MAX_NAME ||
        g_privateCount >= 64u) {
        return FALSE;
    }
    entry = &g_privateModules[g_privateCount++];
    RtlZeroMemory(entry, sizeof(*entry));
    RtlCopyMemory(entry->Name, name, nameLength * sizeof(WCHAR));
    entry->Length = nameLength;
    entry->Base = base;
    entry->Size = size;
    return TRUE;
}
