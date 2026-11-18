#include "Bootstrap.h"

#include <wdm.h>

#include "../../Shared/Protocol.h"

/* Declared in ntddk.h / ntifs.h; local prototypes avoid pulling the full
 * kernel IFR headers into this translation unit. */
NTSTATUS ExUuidCreate(GUID* Uuid);
NTSTATUS NTAPI ZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);

static PDEVICE_OBJECT g_deviceObject = NULL;
static UNICODE_STRING g_deviceName;
static UNICODE_STRING g_symbolicLinkName;
static UNICODE_STRING g_bootstrapFilePath;
static WCHAR g_deviceNameBuffer[96];
static WCHAR g_symbolicLinkNameBuffer[96];
static WCHAR g_userPathBuffer[96];
static WCHAR g_filePathBuffer[96];
static BOOLEAN g_linkCreated = FALSE;
static BOOLEAN g_fileWritten = FALSE;
static BOOLEAN g_active = FALSE;

static VOID GuidToHex(const GUID* guid, WCHAR* output) {
    static const WCHAR digits[] = L"0123456789ABCDEF";
    const UCHAR* bytes = (const UCHAR*)guid;

    for (ULONG index = 0u; index < 16u; ++index) {
        output[index * 2u] = digits[(bytes[index] >> 4) & 0xFu];
        output[(index * 2u) + 1u] = digits[bytes[index] & 0xFu];
    }
    output[AMGER_GUID_HEX_LENGTH] = L'\0';
}

static VOID ComposeName(WCHAR* destination, const WCHAR* prefix, const WCHAR* hex) {
    ULONG position = 0u;

    while (*prefix != L'\0') {
        destination[position++] = *prefix++;
    }
    while (*hex != L'\0') {
        destination[position++] = *hex++;
    }
    destination[position] = L'\0';
}

static NTSTATUS WriteBootstrapFile(VOID) {
    static const WCHAR systemTempPath[] =
        L"\\??\\C:\\Windows\\Temp\\AmegerBootstrap.txt";

    ULONG position = 0u;
    while (systemTempPath[position] != L'\0') {
        g_filePathBuffer[position] = systemTempPath[position];
        ++position;
    }
    g_filePathBuffer[position] = L'\0';
    RtlInitUnicodeString(&g_bootstrapFilePath, g_filePathBuffer);

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &g_bootstrapFilePath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus;
    const NTSTATUS status = ZwCreateFile(
        &fileHandle,
        FILE_WRITE_DATA,
        &attributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0u);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    const ULONG byteCount =
        (ULONG)((wcslen(g_userPathBuffer) + 1u) * sizeof(WCHAR));
    const NTSTATUS writeStatus = ZwWriteFile(
        fileHandle, NULL, NULL, NULL, &ioStatus,
        g_userPathBuffer, byteCount, NULL, NULL);

    ZwClose(fileHandle);

    if (NT_SUCCESS(writeStatus)) {
        g_fileWritten = TRUE;
    }
    return writeStatus;
}

NTSTATUS BootstrapInitialize(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT* OutDeviceObject) {
    if (OutDeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutDeviceObject = NULL;

    GUID guid;
    NTSTATUS status = ExUuidCreate(&guid);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WCHAR hexBuffer[AMGER_GUID_HEX_LENGTH + 1u];
    GuidToHex(&guid, hexBuffer);

    ComposeName(g_deviceNameBuffer, AMGER_DEVICE_NAME_PREFIX, hexBuffer);
    ComposeName(g_symbolicLinkNameBuffer, AMGER_SYMBOLIC_LINK_PREFIX, hexBuffer);
    ComposeName(g_userPathBuffer, AMGER_USER_DEVICE_PREFIX, hexBuffer);

    RtlInitUnicodeString(&g_deviceName, g_deviceNameBuffer);
    RtlInitUnicodeString(&g_symbolicLinkName, g_symbolicLinkNameBuffer);

    status = IoCreateDevice(
        DriverObject,
        0u,
        &g_deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
        RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
        return status;
    }

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = NULL;
        RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
        RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
        return status;
    }
    g_linkCreated = TRUE;

    status = WriteBootstrapFile();
    if (!NT_SUCCESS(status)) {
        BootstrapDestroy();
        return status;
    }

    g_active = TRUE;
    *OutDeviceObject = g_deviceObject;
    return STATUS_SUCCESS;
}

VOID BootstrapDestroy(VOID) {
    if (g_fileWritten) {
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &g_bootstrapFilePath,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL, NULL);
        (void)ZwDeleteFile(&attributes);
        g_fileWritten = FALSE;
    }

    if (g_linkCreated) {
        IoDeleteSymbolicLink(&g_symbolicLinkName);
        g_linkCreated = FALSE;
    }

    if (g_deviceObject != NULL) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = NULL;
    }

    RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
    RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
    RtlZeroMemory(&g_bootstrapFilePath, sizeof(g_bootstrapFilePath));
    g_active = FALSE;
}

BOOLEAN BootstrapIsActive(VOID) {
    return g_active;
}
