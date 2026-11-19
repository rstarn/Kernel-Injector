    #include <ntddk.h>
#include <ntiologc.h>
#include <wdmsec.h>

#include "Bootstrap.h"

#include "../../../Shared/Protocol.h"

/* Project-owned device class GUID used by IoCreateDeviceSecure. */
static const GUID AMGER_DEVICE_CLASS_GUID = {
    0x7f5a2b14, 0x9c3e, 0x4d8a, { 0xb6, 0xf1, 0x0e, 0x2d, 0x4a, 0x8c, 0x9b, 0x73 }
};

/* SYSTEM and Builtin Administrators only; the client runs elevated. */
#define AMGER_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

/* Use the WDK-defined IO_ERR_DRIVER_ERROR for lifecycle cleanup failures.
 * Its message ("Driver detected an internal error in its data structures
 * for %1.") is supplied by the standard iologmsg.dll message source.
 * The original NTSTATUS is preserved in FinalStatus and DumpData[0].
 *
 * 0xC0040004: Sev=3 (STATUS_SEVERITY_ERROR), C=0 (Microsoft-defined),
 * Facility=0x004 (FACILITY_IO_ERROR_CODE), Code=0x004. */
C_ASSERT(IO_ERR_DRIVER_ERROR == (NTSTATUS)0xC0040004L);

/* UCHAR_MAX is not defined by the WDK kernel headers; the size passed to
 * IoAllocateErrorLogEntry must fit in UCHAR. */
#define AMGER_ERROR_LOG_SIZE_MAX 0xFFu

/* ZwDeleteFile is declared in ntifs.h, which cannot coexist with wdm.h here.
 * On x64 NTAPI (__stdcall) has no ABI effect, so this matches the WDK signature. */
NTSTATUS ZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);

static PDRIVER_OBJECT g_driverObject = NULL;
static PDEVICE_OBJECT g_deviceObject = NULL;
static UNICODE_STRING g_deviceName;
static UNICODE_STRING g_symbolicLinkName;
static UNICODE_STRING g_bootstrapFilePath;
static WCHAR g_deviceNameBuffer[96];
static WCHAR g_symbolicLinkNameBuffer[96];
static WCHAR g_userPathBuffer[96];
static WCHAR g_filePathBuffer[96];
static volatile LONG g_linkCreated = 0;
static volatile LONG g_fileCreated = 0;
static BOOLEAN g_active = FALSE;

/* Serializes file and symbolic-link deletion. All callers run at PASSIVE_LEVEL;
 * the mutex is held only around object-manager calls, never a spin lock, and a
 * two-state interlocked flag is insufficient to distinguish "absent" from
 * "deletion in progress" across concurrent KICK / CLOSE / unload teardown. */
static KMUTEX g_discoveryMutex;

static VOID ReportLifecycleFailure(NTSTATUS status) {
    const ULONG dumpDataSize = sizeof(ULONG);
    const SIZE_T allocationSize = sizeof(IO_ERROR_LOG_PACKET) + dumpDataSize;
    UCHAR entrySize;
    PIO_ERROR_LOG_PACKET packet;

    if (allocationSize > (SIZE_T)ERROR_LOG_MAXIMUM_SIZE ||
        allocationSize > (SIZE_T)AMGER_ERROR_LOG_SIZE_MAX) {
        return;
    }
    entrySize = (UCHAR)allocationSize;

    packet = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(
        g_driverObject != NULL ? (PVOID)g_driverObject : (PVOID)g_deviceObject,
        entrySize);
    if (packet == NULL) {
        return;
    }

    RtlZeroMemory(packet, allocationSize);

    packet->MajorFunctionCode = 0;
    packet->RetryCount = 0;
    packet->DumpDataSize = (USHORT)dumpDataSize;
    packet->NumberOfStrings = 0;
    packet->StringOffset = 0;
    packet->EventCategory = 0;
    packet->ErrorCode = IO_ERR_DRIVER_ERROR;
    packet->UniqueErrorValue = (ULONG)status;
    packet->FinalStatus = status;
    packet->SequenceNumber = 0;
    packet->IoControlCode = 0;
    packet->DeviceOffset.QuadPart = 0;
    packet->DumpData[0] = (ULONG)status;

    IoWriteErrorLogEntry(packet);
}

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

static NTSTATUS DeleteBootstrapFile(VOID) {
    if (InterlockedCompareExchange(&g_fileCreated, 0L, 1L) != 1L) {
        /* No file is owned; the resource is already absent. */
        RtlZeroMemory(&g_bootstrapFilePath, sizeof(g_bootstrapFilePath));
        return STATUS_SUCCESS;
    }

    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &g_bootstrapFilePath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    const NTSTATUS status = ZwDeleteFile(&attributes);
    if (NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_NOT_FOUND) {
        /* The file is gone (or was already absent); only now is its name safe
         * to discard. On failure the name stays valid so a retry can rebuild
         * the OBJECT_ATTRIBUTES from it. */
        RtlZeroMemory(&g_bootstrapFilePath, sizeof(g_bootstrapFilePath));
        return STATUS_SUCCESS;
    }

    /* Restore the claim: the file still exists and cleanup must retry. */
    InterlockedExchange(&g_fileCreated, 1L);
    return status;
}

static NTSTATUS WriteBootstrapFile(VOID) {
    static const WCHAR systemTempPath[] =
        L"\\SystemRoot\\Temp\\AmegerBootstrap.txt";

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
    const NTSTATUS createStatus = ZwCreateFile(
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

    if (!NT_SUCCESS(createStatus)) {
        return createStatus;
    }

    /* Creation succeeded: record ownership before attempting the write. */
    InterlockedExchange(&g_fileCreated, 1L);

    const ULONG byteCount =
        (ULONG)((wcslen(g_userPathBuffer) + 1u) * sizeof(WCHAR));
    const NTSTATUS writeStatus = ZwWriteFile(
        fileHandle, NULL, NULL, NULL, &ioStatus,
        g_userPathBuffer, byteCount, NULL, NULL);

    ZwClose(fileHandle);

    if (!NT_SUCCESS(writeStatus)) {
        /* Attempt to remove the partially written file; preserve the write
         * error and record any cleanup failure separately. */
        const NTSTATUS cleanupStatus = DeleteBootstrapFile();
        if (!NT_SUCCESS(cleanupStatus)) {
            ReportLifecycleFailure(cleanupStatus);
        }
        return writeStatus;
    }

    return STATUS_SUCCESS;
}

NTSTATUS BootstrapInitialize(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT* OutDeviceObject) {
    if (OutDeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutDeviceObject = NULL;
    KeInitializeMutex(&g_discoveryMutex, 0);
    g_driverObject = DriverObject;

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

    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl, AMGER_DEVICE_SDDL);

    status = IoCreateDeviceSecure(
        DriverObject,
        0u,
        &g_deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &AMGER_DEVICE_CLASS_GUID,
        &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
        RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
        return status;
    }

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    if (!NT_SUCCESS(status)) {
        /* Preserve the link failure; record any device-deletion failure. */
        const NTSTATUS cleanupStatus = BootstrapDestroyDevice();
        if (!NT_SUCCESS(cleanupStatus)) {
            ReportLifecycleFailure(cleanupStatus);
        }
        RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
        RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
        return status;
    }
    InterlockedExchange(&g_linkCreated, 1L);

    status = WriteBootstrapFile();
    if (!NT_SUCCESS(status)) {
        /* Preserve the original write failure; record cleanup failure. */
        const NTSTATUS cleanupStatus = BootstrapDestroy();
        if (!NT_SUCCESS(cleanupStatus)) {
            ReportLifecycleFailure(cleanupStatus);
        }
        return status;
    }

    g_active = TRUE;
    *OutDeviceObject = g_deviceObject;
    return STATUS_SUCCESS;
}

/* Removes the bootstrap file and symbolic link. g_discoveryMutex must be held
 * by the caller. Each name is discarded only after its resource is confirmed
 * gone, so a failed deletion leaves the name valid for a later retry. */
static NTSTATUS RemoveDiscoveryLocked(VOID) {
    NTSTATUS status = DeleteBootstrapFile();

    if (InterlockedCompareExchange(&g_linkCreated, 0L, 1L) == 1L) {
        const NTSTATUS linkStatus = IoDeleteSymbolicLink(&g_symbolicLinkName);
        if (NT_SUCCESS(linkStatus) || linkStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
            /* Link is gone (or was already absent); its name is safe to drop. */
            RtlZeroMemory(&g_symbolicLinkName, sizeof(g_symbolicLinkName));
        } else {
            /* Restore the claim and keep the name so cleanup can retry. */
            InterlockedExchange(&g_linkCreated, 1L);
            if (NT_SUCCESS(status)) {
                status = linkStatus;
            }
        }
    }

    return status;
}

NTSTATUS BootstrapRemoveDiscovery(VOID) {
    NTSTATUS status;

    /* Serialize with any concurrent CLOSE / unload teardown. The object-manager
     * calls run at PASSIVE_LEVEL under a mutex, never under g_regionLock. */
    KeWaitForSingleObject(&g_discoveryMutex, Executive, KernelMode, FALSE, NULL);
    status = RemoveDiscoveryLocked();
    KeReleaseMutex(&g_discoveryMutex, FALSE);

    return status;
}

NTSTATUS BootstrapDestroyDevice(VOID) {
    PDEVICE_OBJECT device = (PDEVICE_OBJECT)InterlockedExchangePointer(
        (PVOID*)&g_deviceObject, NULL);

    if (device != NULL) {
        IoDeleteDevice(device);
        /* Device deletion is unconditional; the name is no longer needed. */
        RtlZeroMemory(&g_deviceName, sizeof(g_deviceName));
    }
    return STATUS_SUCCESS;
}

NTSTATUS BootstrapDestroy(VOID) {
    NTSTATUS discoveryStatus;
    NTSTATUS deviceStatus;
    NTSTATUS finalStatus;
    BOOLEAN complete;

    /* One critical section covers discovery and device teardown so a concurrent
     * KICK cannot observe a half-removed bootstrap or race a second removal. */
    KeWaitForSingleObject(&g_discoveryMutex, Executive, KernelMode, FALSE, NULL);

    discoveryStatus = RemoveDiscoveryLocked();
    deviceStatus = BootstrapDestroyDevice();

    /* Report inactive only when every resource is actually gone. A failed file
     * or link deletion restores its flag, keeping the state retryable. */
    complete = (g_fileCreated == 0 && g_linkCreated == 0 && g_deviceObject == NULL) ? TRUE : FALSE;
    if (complete) {
        g_active = FALSE;
    }

    finalStatus = NT_SUCCESS(discoveryStatus) ? deviceStatus : discoveryStatus;

    KeReleaseMutex(&g_discoveryMutex, FALSE);

    if (!NT_SUCCESS(finalStatus)) {
        ReportLifecycleFailure(finalStatus);
    }
    return finalStatus;
}

VOID BootstrapReportCleanupFailure(NTSTATUS status) {
    ReportLifecycleFailure(status);
}

BOOLEAN BootstrapIsActive(VOID) {
    BOOLEAN active;

    KeWaitForSingleObject(&g_discoveryMutex, Executive, KernelMode, FALSE, NULL);
    active = g_active;
    KeReleaseMutex(&g_discoveryMutex, FALSE);
    return active;
}
