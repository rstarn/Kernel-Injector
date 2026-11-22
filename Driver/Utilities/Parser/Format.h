#ifndef AMGER_FORMAT_H
#define AMGER_FORMAT_H

/*
 * Format.h - bounds-checked PE32+ image parser for the injection engine.
 *
 * Contract: converts a kernel-mapped raw payload into a validated descriptor
 * that every later injection phase consumes. The caller supplies the descriptor
 * on the stack; this module performs no pool allocation and emits no strings.
 * All offsets are read byte-wise so no user-mode IMAGE_* layout is assumed.
 * Inputs: kernel-mapped image bytes and their exact size.
 * Outputs: a zeroed-then-populated AMGER_PE_IMAGE on STATUS_SUCCESS.
 * Failure modes: STATUS_INVALID_PARAMETER for every malformed field; the
 * descriptor is left zeroed and must not be used.
 */

#include <wdm.h>
#include "../../../Shared/Protocol.h"

#define AMGER_PE_MAX_SECTIONS     96u
#define AMGER_PE_MAX_DIRECTORIES  16u

typedef struct _AMGER_PE_DIRECTORY {
    uint32_t Rva;
    uint32_t Size;
} AMGER_PE_DIRECTORY;

typedef struct _AMGER_PE_SECTION {
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint32_t RawOffset;
    uint32_t RawSize;
    uint32_t Characteristics;
} AMGER_PE_SECTION;

typedef struct _AMGER_PE_IMAGE {
    PUCHAR Base;
    SIZE_T Size;
    uint32_t PeOffset;
    uint64_t ImageBase;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint32_t AddressOfEntryPoint;
    uint16_t NumberOfSections;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint16_t FileCharacteristics;
    uint32_t NumberOfRvaAndSizes;
    AMGER_PE_DIRECTORY Directories[AMGER_PE_MAX_DIRECTORIES];
    AMGER_PE_SECTION Sections[AMGER_PE_MAX_SECTIONS];
} AMGER_PE_IMAGE, * PAMGER_PE_IMAGE;

/* Validates the image and fills Out. Never dereferences an unchecked offset. */
NTSTATUS PeParseAndValidate(
    PVOID Image,
    SIZE_T ImageSize,
    PAMGER_PE_IMAGE Out);

/* Maps an RVA range to a file offset. Fails when the range is not file-backed. */
NTSTATUS PeRvaToOffset(
    const AMGER_PE_IMAGE* Image,
    uint32_t Rva,
    uint32_t Length,
    uint32_t* OutOffset);

/* Best-effort extraction of the fields shown in the client console. Never
 * fails the injection: unknown or malformed tables are left empty. */
VOID PeBuildReport(
    const AMGER_PE_IMAGE* Image,
    PAMGER_PARSER_REPORT Out);

#endif /* AMGER_FORMAT_H */
