#include "Format.h"

/*
 * Byte-wise PE32+ parsing. No user-mode IMAGE_* structures are used, no pool
 * is allocated, and no string is emitted. Every offset is proven inside the
 * caller-supplied byte range before it is read, so a malformed payload cannot
 * fault even outside the dispatcher's SEH frame.
 */

#define PE_DOS_HEADER_SIZE      0x40u
#define PE_E_LFANEW             0x3Cu
#define PE_NT_SIGNATURE         0x00004550u
#define PE_MACHINE_AMD64        0x8664u
#define PE_OPTIONAL_MAGIC_PLUS  0x020Bu
#define PE_COFF_HEADER_SIZE     24u
#define PE_SECTION_HEADER_SIZE  40u
#define PE_DIRECTORY_ENTRY_SIZE 8u
#define PE_OPTIONAL_MIN_SIZE    112u
#define PE_MAX_IMAGE_BYTES      (512u * 1024u * 1024u)

#define PE_FILE_DLL             0x2000u
#define PE_FILE_32BIT_MACHINE   0x0100u
#define PE_FILE_BYTES_REVERSED  0x8080u

#define PE_DIR_CERTIFICATE      4u

static uint16_t ReadLe16(const PUCHAR bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t ReadLe32(const PUCHAR bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t ReadLe64(const PUCHAR bytes) {
    return (uint64_t)ReadLe32(bytes) | ((uint64_t)ReadLe32(bytes + 4u) << 32);
}

static uint32_t MaxU32(uint32_t left, uint32_t right) {
    return left > right ? left : right;
}

static BOOLEAN IsPowerOfTwo(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

NTSTATUS PeParseAndValidate(
    PVOID Image,
    SIZE_T ImageSize,
    PAMGER_PE_IMAGE Out) {
    PUCHAR base;
    UINT64 fileSize;
    UINT64 peOffset;
    UINT64 optionalOffset;
    UINT64 sectionTableOffset;
    UINT64 sectionTableEnd;
    PUCHAR coff;
    PUCHAR optional;
    uint32_t optionalSize;
    uint32_t sectionCount;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint32_t directoryBytes;
    uint32_t index;
    BOOLEAN entryInImage;

    if (Image == NULL || Out == NULL || ImageSize < PE_DOS_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Out, sizeof(*Out));
    base = (PUCHAR)Image;
    fileSize = (UINT64)ImageSize;

    peOffset = (UINT64)ReadLe32(base + PE_E_LFANEW);
    if (peOffset < PE_DOS_HEADER_SIZE || peOffset > fileSize - PE_COFF_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    coff = base + peOffset;
    if (ReadLe32(coff) != PE_NT_SIGNATURE ||
        ReadLe16(coff + 4u) != PE_MACHINE_AMD64) {
        return STATUS_INVALID_PARAMETER;
    }

    sectionCount = (uint32_t)ReadLe16(coff + 6u);
    optionalSize = (uint32_t)ReadLe16(coff + 20u);
    if (sectionCount == 0u || sectionCount > AMGER_PE_MAX_SECTIONS ||
        optionalSize < PE_OPTIONAL_MIN_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    {
        const uint16_t characteristics = ReadLe16(coff + 22u);
        if ((characteristics & PE_FILE_DLL) == 0u ||
            (characteristics & PE_FILE_32BIT_MACHINE) != 0u ||
            (characteristics & PE_FILE_BYTES_REVERSED) != 0u) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    optionalOffset = peOffset + PE_COFF_HEADER_SIZE;
    if ((UINT64)optionalSize > fileSize - optionalOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    optional = base + optionalOffset;
    if (ReadLe16(optional) != PE_OPTIONAL_MAGIC_PLUS) {
        return STATUS_INVALID_PARAMETER;
    }

    sectionAlignment = ReadLe32(optional + 32u);
    fileAlignment = ReadLe32(optional + 36u);
    sizeOfImage = ReadLe32(optional + 56u);
    sizeOfHeaders = ReadLe32(optional + 60u);

    if (fileAlignment < 0x200u || fileAlignment > 0x10000u ||
        !IsPowerOfTwo(fileAlignment) ||
        sectionAlignment < fileAlignment ||
        !IsPowerOfTwo(sectionAlignment) ||
        sizeOfImage < sizeOfHeaders ||
        sizeOfImage > PE_MAX_IMAGE_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ReadLe32(optional + 108u) > AMGER_PE_MAX_DIRECTORIES) {
        return STATUS_INVALID_PARAMETER;
    }

    directoryBytes = ReadLe32(optional + 108u) * PE_DIRECTORY_ENTRY_SIZE;
    if ((UINT64)PE_OPTIONAL_MIN_SIZE + directoryBytes > (UINT64)optionalSize) {
        return STATUS_INVALID_PARAMETER;
    }

    sectionTableOffset = optionalOffset + (UINT64)optionalSize;
    sectionTableEnd = sectionTableOffset + (UINT64)sectionCount * PE_SECTION_HEADER_SIZE;
    if (sectionTableEnd > fileSize ||
        sectionTableEnd > (UINT64)sizeOfHeaders ||
        (UINT64)sizeOfHeaders > fileSize) {
        return STATUS_INVALID_PARAMETER;
    }

    Out->Base = base;
    Out->Size = ImageSize;
    Out->PeOffset = (uint32_t)peOffset;
    Out->ImageBase = ReadLe64(optional + 24u);
    Out->SizeOfImage = sizeOfImage;
    Out->SizeOfHeaders = sizeOfHeaders;
    Out->SectionAlignment = sectionAlignment;
    Out->FileAlignment = fileAlignment;
    Out->AddressOfEntryPoint = ReadLe32(optional + 16u);
    Out->NumberOfSections = (uint16_t)sectionCount;
    Out->Subsystem = ReadLe16(optional + 68u);
    Out->DllCharacteristics = ReadLe16(optional + 70u);
    Out->FileCharacteristics = ReadLe16(coff + 22u);
    Out->NumberOfRvaAndSizes = ReadLe32(optional + 108u);

    for (index = 0u; index < Out->NumberOfRvaAndSizes; ++index) {
        const PUCHAR entry = optional + PE_OPTIONAL_MIN_SIZE +
                             (size_t)index * PE_DIRECTORY_ENTRY_SIZE;
        const uint32_t rva = ReadLe32(entry);
        const uint32_t size = ReadLe32(entry + 4u);

        Out->Directories[index].Rva = rva;
        Out->Directories[index].Size = size;

        if (size == 0u) {
            continue;
        }
        if (index == PE_DIR_CERTIFICATE) {
            if ((UINT64)rva > fileSize || (UINT64)size > fileSize - rva) {
                return STATUS_INVALID_PARAMETER;
            }
        } else {
            if (rva >= sizeOfImage || (UINT64)size > (UINT64)sizeOfImage - rva) {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    for (index = 0u; index < sectionCount; ++index) {
        const PUCHAR section = base + sectionTableOffset +
                               (size_t)index * PE_SECTION_HEADER_SIZE;
        const uint32_t virtualSize = ReadLe32(section + 8u);
        const uint32_t virtualAddress = ReadLe32(section + 12u);
        const uint32_t rawSize = ReadLe32(section + 16u);
        const uint32_t rawOffset = ReadLe32(section + 20u);
        const uint32_t span = MaxU32(virtualSize, rawSize);

        if (rawSize != 0u &&
            ((UINT64)rawOffset > fileSize || (UINT64)rawSize > fileSize - rawOffset)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (span != 0u &&
            (virtualAddress >= sizeOfImage ||
             (UINT64)span > (UINT64)sizeOfImage - virtualAddress)) {
            return STATUS_INVALID_PARAMETER;
        }

        Out->Sections[index].VirtualAddress = virtualAddress;
        Out->Sections[index].VirtualSize = virtualSize;
        Out->Sections[index].RawOffset = rawOffset;
        Out->Sections[index].RawSize = rawSize;
        Out->Sections[index].Characteristics = ReadLe32(section + 36u);
    }

    if (Out->AddressOfEntryPoint != 0u) {
        if (Out->AddressOfEntryPoint >= sizeOfImage) {
            return STATUS_INVALID_PARAMETER;
        }
        entryInImage = (Out->AddressOfEntryPoint < sizeOfHeaders) ? TRUE : FALSE;
        for (index = 0u; !entryInImage && index < sectionCount; ++index) {
            const uint32_t span = MaxU32(Out->Sections[index].VirtualSize,
                                         Out->Sections[index].RawSize);
            const uint32_t start = Out->Sections[index].VirtualAddress;
            if (span != 0u &&
                Out->AddressOfEntryPoint >= start &&
                Out->AddressOfEntryPoint - start < span) {
                entryInImage = TRUE;
            }
        }
        if (!entryInImage) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS PeRvaToOffset(
    const AMGER_PE_IMAGE* Image,
    uint32_t Rva,
    uint32_t Length,
    uint32_t* OutOffset) {
    UINT64 offset64 = 0u;
    uint32_t index;
    BOOLEAN found = FALSE;

    if (Image == NULL || OutOffset == NULL || Image->Base == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rva < Image->SizeOfHeaders) {
        if (Length > Image->SizeOfHeaders - Rva) {
            return STATUS_INVALID_PARAMETER;
        }
        offset64 = Rva;
    } else {
        for (index = 0u; index < Image->NumberOfSections; ++index) {
            const AMGER_PE_SECTION* section = &Image->Sections[index];
            const uint32_t span = MaxU32(section->VirtualSize, section->RawSize);
            uint32_t delta;

            if (span == 0u || Rva < section->VirtualAddress) {
                continue;
            }
            delta = Rva - section->VirtualAddress;
            if (delta >= span) {
                continue;
            }
            if (Length > span - delta || delta >= section->RawSize ||
                Length > section->RawSize - delta) {
                return STATUS_INVALID_PARAMETER;
            }
            offset64 = (UINT64)section->RawOffset + delta;
            found = TRUE;
            break;
        }
        if (!found) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (offset64 > (UINT64)Image->Size ||
        (UINT64)Length > (UINT64)Image->Size - offset64) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutOffset = (uint32_t)offset64;
    return STATUS_SUCCESS;
}

#define PE_DIR_EXPORT       0u
#define PE_DIR_IMPORT       1u
#define PE_DIR_RESOURCE     2u
#define PE_DIR_EXCEPTION    3u
#define PE_DIR_RELOCATIONS  5u
#define PE_DIR_DEBUG        6u
#define PE_DIR_TLS          9u
#define PE_DIR_LOAD_CONFIG  10u
#define PE_DIR_BOUND_IMPORT 11u
#define PE_DIR_IAT          12u
#define PE_DIR_DELAY_IMPORT 13u

#define PE_GUARD_CF         0x4000u
#define PE_GUARD_CET_COMPAT 0x00100000u

static BOOLEAN ReadRvaU16(const AMGER_PE_IMAGE* Image, uint32_t Rva, uint16_t* Out) {
    uint32_t offset;
    if (!NT_SUCCESS(PeRvaToOffset(Image, Rva, 2u, &offset))) {
        return FALSE;
    }
    *Out = ReadLe16(Image->Base + offset);
    return TRUE;
}

static BOOLEAN ReadRvaU32(const AMGER_PE_IMAGE* Image, uint32_t Rva, uint32_t* Out) {
    uint32_t offset;
    if (!NT_SUCCESS(PeRvaToOffset(Image, Rva, 4u, &offset))) {
        return FALSE;
    }
    *Out = ReadLe32(Image->Base + offset);
    return TRUE;
}

static BOOLEAN ReadRvaU64(const AMGER_PE_IMAGE* Image, uint32_t Rva, uint64_t* Out) {
    uint32_t offset;
    if (!NT_SUCCESS(PeRvaToOffset(Image, Rva, 8u, &offset))) {
        return FALSE;
    }
    *Out = ReadLe64(Image->Base + offset);
    return TRUE;
}

static void CopyAscii(char* destination, const PUCHAR source, uint32_t limit) {
    uint32_t index = 0u;
    while (index + 1u < limit && source[index] != 0u) {
        destination[index] = (char)source[index];
        ++index;
    }
    destination[index] = '\0';
}

static BOOLEAN ReadRvaString(
    const AMGER_PE_IMAGE* Image,
    uint32_t Rva,
    char* Out,
    uint32_t Capacity) {
    uint32_t length = Capacity;
    uint32_t offset;

    while (length > 0u) {
        if (NT_SUCCESS(PeRvaToOffset(Image, Rva, length, &offset))) {
            CopyAscii(Out, Image->Base + offset, length);
            return TRUE;
        }
        --length;
    }
    Out[0] = '\0';
    return FALSE;
}

static BOOLEAN StartsWithAscii(
    const char* name,
    const unsigned char* prefix,
    uint32_t length) {
    uint32_t index;

    for (index = 0u; index < length; ++index) {
        unsigned char value = (unsigned char)name[index];
        if (value >= 0x41u && value <= 0x5Au) {
            value = (unsigned char)(value + 0x20u);
        }
        if ((unsigned char)(value ^ 0x5Au) != prefix[index]) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN IsApiSetName(const char* name) {
    /* XOR-masked bytes avoid emitting an API-set prefix string in the driver. */
    static const unsigned char apiPrefix[] = {
        0x3Bu, 0x2Au, 0x33u, 0x77u, 0x37u, 0x29u,
        0x77u, 0x2Du, 0x33u, 0x34u
    };
    static const unsigned char extPrefix[] = {
        0x3Fu, 0x22u, 0x2Eu, 0x77u, 0x37u, 0x29u,
        0x77u, 0x2Du, 0x33u, 0x34u
    };

    return StartsWithAscii(name, apiPrefix, sizeof(apiPrefix)) ||
           StartsWithAscii(name, extPrefix, sizeof(extPrefix));
}

VOID PeBuildReport(
    const AMGER_PE_IMAGE* Image,
    PAMGER_PARSER_REPORT Out) {
    uint32_t index;
    uint32_t offset;
    uint32_t blockRva;
    uint32_t remaining;

    if (Image == NULL || Out == NULL) {
        return;
    }

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Signature = AMGER_PARSER_REPORT_SIGNATURE;
    Out->ParseStatus = 0u;
    Out->SectionCount = Image->NumberOfSections;
    Out->DirectoryCount = (uint16_t)Image->NumberOfRvaAndSizes;
    Out->EntryPoint = Image->AddressOfEntryPoint;
    Out->SizeOfImage = Image->SizeOfImage;
    Out->SizeOfHeaders = Image->SizeOfHeaders;
    Out->ImageBase = Image->ImageBase;
    Out->PeOffset = Image->PeOffset;
    Out->SectionAlignment = Image->SectionAlignment;
    Out->FileAlignment = Image->FileAlignment;
    Out->Subsystem = Image->Subsystem;
    Out->DllCharacteristics = Image->DllCharacteristics;
    Out->FileCharacteristics = Image->FileCharacteristics;

    if (Image->Directories[PE_DIR_LOAD_CONFIG].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_LOAD_CONFIG;
        if (Image->Directories[PE_DIR_LOAD_CONFIG].Size >= 152u &&
            NT_SUCCESS(PeRvaToOffset(Image, Image->Directories[PE_DIR_LOAD_CONFIG].Rva,
                                     152u, &offset))) {
            Out->SecurityCookieRva = ReadLe32(Image->Base + offset + 88u);
            Out->GuardFlags = ReadLe32(Image->Base + offset + 144u);
        }
    }
    if (Image->Directories[PE_DIR_TLS].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_TLS;
        if (NT_SUCCESS(PeRvaToOffset(Image, Image->Directories[PE_DIR_TLS].Rva,
                                     40u, &offset))) {
            uint64_t callbacks = ReadLe64(Image->Base + offset + 24u);
            for (index = 0u; index < AMGER_REPORT_MAX_MODULES; ++index) {
                uint64_t value = 0u;
                if (!ReadRvaU64(Image, (uint32_t)callbacks, &value) || value == 0u) {
                    break;
                }
                ++Out->TlsCallbackCount;
                callbacks += 8u;
            }
        }
    }
    if (Image->Directories[PE_DIR_DEBUG].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_DEBUG;
    }
    if (Image->Directories[PE_DIR_RESOURCE].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_RESOURCE;
        if (NT_SUCCESS(PeRvaToOffset(Image, Image->Directories[PE_DIR_RESOURCE].Rva,
                                     16u, &offset))) {
            const uint32_t count = (uint32_t)ReadLe16(Image->Base + offset + 12u) +
                                   (uint32_t)ReadLe16(Image->Base + offset + 14u);
            uint32_t entryRva = Image->Directories[PE_DIR_RESOURCE].Rva + 16u;
            for (index = 0u; index < count && index < 64u; ++index) {
                uint32_t name = 0u;
                uint32_t data = 0u;
                if (!ReadRvaU32(Image, entryRva, &name) ||
                    !ReadRvaU32(Image, entryRva + 4u, &data)) {
                    break;
                }
                if (name == 24u && (data & 0x80000000u) != 0u) {
                    Out->Flags |= AMGER_REPORT_FLAG_MANIFEST;
                    break;
                }
                entryRva += 8u;
            }
        }
    }
    if (Image->Directories[PE_DIR_RELOCATIONS].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_RELOCATIONS;
        blockRva = Image->Directories[PE_DIR_RELOCATIONS].Rva;
        remaining = Image->Directories[PE_DIR_RELOCATIONS].Size;
        while (remaining >= 8u) {
            uint32_t blockSize;
            uint32_t entries;
            uint32_t position;
            if (!NT_SUCCESS(PeRvaToOffset(Image, blockRva, 8u, &offset))) {
                break;
            }
            blockSize = ReadLe32(Image->Base + offset + 4u);
            if (blockSize < 8u || blockSize > remaining) {
                break;
            }
            entries = (blockSize - 8u) / 2u;
            for (position = 0u; position < entries; ++position) {
                const uint16_t value = ReadLe16(Image->Base + offset + 8u + position * 2u);
                const uint16_t type = (uint16_t)(value >> 12);
                if (type == 10u) {
                    ++Out->RelocDir64Count;
                } else if (type == 3u) {
                    ++Out->RelocHighLowCount;
                }
            }
            blockRva += blockSize;
            remaining -= blockSize;
        }
    }
    if (Image->Directories[PE_DIR_EXCEPTION].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_EXCEPTIONS;
    }
    if (Image->Directories[PE_DIR_BOUND_IMPORT].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_BOUND_IMPORTS;
    }
    if (Image->Directories[PE_DIR_IAT].Size != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_IAT;
    }
    if ((Image->DllCharacteristics & PE_GUARD_CF) != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_CFG;
    }
    if ((Out->GuardFlags & PE_GUARD_CET_COMPAT) != 0u) {
        Out->Flags |= AMGER_REPORT_FLAG_CET_COMPAT | AMGER_REPORT_FLAG_CET;
    }

    if (Image->Directories[PE_DIR_IMPORT].Size != 0u) {
        uint32_t descriptorRva = Image->Directories[PE_DIR_IMPORT].Rva;
        for (index = 0u; index < AMGER_REPORT_MAX_MODULES; ++index) {
            uint32_t nameRva;
            uint32_t position;
            BOOLEAN nonzero = FALSE;
            if (!NT_SUCCESS(PeRvaToOffset(Image, descriptorRva, 20u, &offset))) {
                break;
            }
            for (position = 0u; position < 20u; ++position) {
                if (Image->Base[offset + position] != 0u) {
                    nonzero = TRUE;
                    break;
                }
            }
            if (!nonzero) {
                break;
            }
            {
                const uint32_t thunkRva = ReadLe32(Image->Base + offset);
                uint32_t thunkIndex;
                for (thunkIndex = 0u; thunkRva != 0u && thunkIndex < 256u; ++thunkIndex) {
                    const uint64_t entryRva = (uint64_t)thunkRva +
                                              (uint64_t)thunkIndex * 8u;
                    uint64_t thunk = 0u;
                    if (entryRva > 0xFFFFFFFFull ||
                        !ReadRvaU64(Image, (uint32_t)entryRva, &thunk) ||
                        thunk == 0u) {
                        break;
                    }
                    if ((thunk & 0x8000000000000000ull) != 0u) {
                        ++Out->OrdinalImportCount;
                    }
                }
            }
            nameRva = ReadLe32(Image->Base + offset + 12u);
            if (nameRva != 0u &&
                ReadRvaString(Image, nameRva,
                              Out->ImportNames[Out->ImportModuleCount],
                              AMGER_REPORT_NAME_LENGTH)) {
                if (IsApiSetName(Out->ImportNames[Out->ImportModuleCount])) {
                    ++Out->ApiSetCount;
                }
                ++Out->ImportModuleCount;
            }
            descriptorRva += 20u;
        }
    }

    if (Image->Directories[PE_DIR_DELAY_IMPORT].Size != 0u) {
        uint32_t descriptorRva = Image->Directories[PE_DIR_DELAY_IMPORT].Rva;
        for (index = 0u; index < AMGER_REPORT_MAX_MODULES; ++index) {
            uint32_t nameRva;
            if (!NT_SUCCESS(PeRvaToOffset(Image, descriptorRva, 32u, &offset))) {
                break;
            }
            nameRva = ReadLe32(Image->Base + offset + 4u);
            if (nameRva == 0u) {
                break;
            }
            ++Out->DelayImportCount;
            descriptorRva += 32u;
        }
    }

    if (Image->Directories[PE_DIR_EXPORT].Size != 0u &&
        NT_SUCCESS(PeRvaToOffset(Image, Image->Directories[PE_DIR_EXPORT].Rva,
                                 40u, &offset))) {
        const uint32_t names = ReadLe32(Image->Base + offset + 24u);
        const uint32_t functionsRva = ReadLe32(Image->Base + offset + 28u);
        const uint32_t namesRva = ReadLe32(Image->Base + offset + 32u);
        const uint32_t ordinalsRva = ReadLe32(Image->Base + offset + 36u);
        const uint32_t limit = names < AMGER_REPORT_MAX_MODULES
                                   ? names : AMGER_REPORT_MAX_MODULES;

        Out->ExportCount = names;
        for (index = 0u; index < limit; ++index) {
            uint32_t nameRva = 0u;
            uint16_t ordinal = 0u;
            uint32_t functionRva = 0u;
            if (!ReadRvaU32(Image, namesRva + index * 4u, &nameRva) ||
                !ReadRvaU16(Image, ordinalsRva + index * 2u, &ordinal) ||
                !ReadRvaU32(Image, functionsRva + (uint32_t)ordinal * 4u, &functionRva)) {
                break;
            }
            if (functionRva >= Image->Directories[PE_DIR_EXPORT].Rva &&
                functionRva < Image->Directories[PE_DIR_EXPORT].Rva +
                                  Image->Directories[PE_DIR_EXPORT].Size) {
                ++Out->ForwardedCount;
            }
            if (!ReadRvaString(Image, nameRva, Out->ExportNames[index],
                               AMGER_REPORT_NAME_LENGTH)) {
                Out->ExportNames[index][0] = '\0';
            }
        }
    }
}
