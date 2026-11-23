#include "Images.h"
#include "../../Execution/Mapping/Sections.h"
#include "../../Execution/Relocate/Fixups.h"

/*
 * File access uses only kernel handles, so ObRegisterCallbacks does not fire
 * and no user-mode API chain is created. The raw buffer is freed as soon as
 * the image is mapped; only the committed private image remains until the
 * final seal pass. A missing or malformed file fails the dependency cleanly.
 */

static VOID BuildSystemPath(WCHAR* path, SIZE_T capacity, const WCHAR* name) {
    static const WCHAR prefix[] = L"\\SystemRoot\\System32\\";
    SIZE_T index;
    SIZE_T nameLength = 0u;

    while (name[nameLength] != 0 && nameLength < AMGER_DEP_MAX_NAME) {
        ++nameLength;
    }
    for (index = 0u; index + 1u < capacity && prefix[index] != 0; ++index) {
        path[index] = prefix[index];
    }
    for (SIZE_T offset = 0u; index + 1u < capacity && offset < nameLength;
         ++offset, ++index) {
        path[index] = name[offset];
    }
    path[index] = 0;
}

NTSTATUS ImagesMapDependency(AMGER_DEP_GRAPH* graph, AMGER_DEP_ENTRY* entry) {
    WCHAR path[AMGER_DEP_MAX_NAME + 64u];
    UNICODE_STRING unicodePath;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    FILE_STANDARD_INFORMATION fileInfo;
    LARGE_INTEGER zeroOffset;
    HANDLE file = NULL;
    PUCHAR raw = NULL;
    SIZE_T rawSize = 0u;
    uint64_t base = 0u;
    uint64_t delta;
    AMGER_MAP_REPORT mapReport;
    AMGER_RELOC_REPORT relocReport;
    NTSTATUS status;

    if (graph == NULL || entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(path, sizeof(path));
    RtlZeroMemory(&mapReport, sizeof(mapReport));
    RtlZeroMemory(&relocReport, sizeof(relocReport));
    BuildSystemPath(path, sizeof(path) / sizeof(path[0]), entry->Name);
    RtlInitUnicodeString(&unicodePath, path);
    InitializeObjectAttributes(&attributes, &unicodePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    graph->Report->FailureStage = AMGER_DEP_STAGE_FILE;
    status = ZwCreateFile(&file,
                          FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                          &attributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0u);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ++graph->Report->FileOpens;

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    status = ZwQueryInformationFile(file, &ioStatus, &fileInfo,
                                    sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(file);
        return status;
    }
    if (fileInfo.EndOfFile.QuadPart <= 0x200 ||
        fileInfo.EndOfFile.QuadPart > AMGER_DEP_MAX_FILE_SIZE) {
        ZwClose(file);
        return STATUS_INVALID_PARAMETER;
    }
    rawSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
    RtlZeroMemory(&zeroOffset, sizeof(zeroOffset));

    /* Neutral numeric tag: no product or payload string in the pool header.
     * ExAllocatePool2 needs a newer NTDDI than this driver targets; suppress
     * only the deprecation diagnostic at this call site. */
#pragma warning(suppress : 4996)
    raw = (PUCHAR)ExAllocatePoolWithTag(PagedPool, rawSize, AMGER_POOL_TAG_RAW);
    if (raw == NULL) {
        ZwClose(file);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(raw, rawSize);

    status = ZwReadFile(file, NULL, NULL, NULL, &ioStatus,
                        raw, (ULONG)rawSize, &zeroOffset, NULL);
    ZwClose(file);
    if (!NT_SUCCESS(status) || ioStatus.Information != rawSize) {
        ExFreePool(raw);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    graph->Report->BytesRead += (uint32_t)rawSize;

    graph->Report->FailureStage = AMGER_DEP_STAGE_PARSE;
    RtlZeroMemory(&entry->Image, sizeof(entry->Image));
    status = PeParseAndValidate(raw, rawSize, &entry->Image);
    if (!NT_SUCCESS(status)) {
        ExFreePool(raw);
        return status;
    }

    graph->Report->FailureStage = AMGER_DEP_STAGE_ALLOCATE;
    status = AllocateReserveImage(graph->ProcessId, entry->Image.SizeOfImage,
                                  &base);
    if (!NT_SUCCESS(status)) {
        ExFreePool(raw);
        return status;
    }
    entry->Base = base;
    entry->Size = entry->Image.SizeOfImage;
    entry->Raw = raw;
    entry->RawSize = rawSize;

    graph->Report->FailureStage = AMGER_DEP_STAGE_MAP;
    status = MapSectionsMap(&entry->Image, graph->ProcessId, base, &mapReport);
    if (!NT_SUCCESS(status)) {
        goto failed;
    }

    graph->Report->FailureStage = AMGER_DEP_STAGE_RELOCATE;
    delta = base - entry->Image.ImageBase;
    status = FixupsApply(&entry->Image, graph->ProcessId, base, delta,
                         &relocReport);
    if (!NT_SUCCESS(status)) {
        goto failed;
    }

    graph->Report->FailureStage = AMGER_DEP_STAGE_NONE;
    ++graph->Report->ModulesMapped;
    return STATUS_SUCCESS;

failed:
    (void)AllocateReleaseImage(graph->ProcessId, base);
    entry->Base = 0u;
    ExFreePool(entry->Raw);
    entry->Raw = NULL;
    entry->RawSize = 0u;
    return status;
}
