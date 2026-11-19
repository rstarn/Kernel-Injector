/*
 * Bootstrap.c - genuine driver object and the secured well-known device.
 *
 * Contract: the mapper-supplied DRIVER_OBJECT is never dereferenced. The
 * object handed to DriverEntry is fabricated by the loader stub and has an
 * invalid OBJECT_HEADER, so passing it to IoCreateDevice (which references
 * the driver object) faults inside ObfReferenceObject. BootstrapInitialize
 * instead calls IoCreateDriver(NULL, BootstrapCreateDriver), which returns an
 * object-manager-owned DRIVER_OBJECT with a valid OBJECT_HEADER, an allocated
 * DriverExtension and every MajorFunction[] entry pre-filled with
 * IopInvalidDeviceRequest. All kernel calls use that object. The single
 * reference IoCreateDriver returns is released only by
 * BootstrapReleaseDriverObject, and only after the device object (whose
 * creation took its own reference) has been deleted.
 *
 * Discovery is by well-known name only (see Protocol.h): the device and its
 * symbolic link are created unconditionally at DriverEntry and are not
 * concealed. BootstrapRemoveDiscovery removes only the symbolic link, so a
 * device that has served its first KICK is no longer openable by name while
 * the device object itself stays alive for the already-registered client.
 */

#include <ntifs.h>

#include "Bootstrap.h"

#include "../../../Shared/Protocol.h"

/* IoCreateDriver is documented (wdm.h) and exported by ntoskrnl.lib, but the
 * installed WDK header set does not declare it. The documented prototype is
 * repeated here so the call is type-checked; the link proves the export. */
NTKERNELAPI
NTSTATUS
IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction
    );

/* ObSetSecurityObjectByPointer is documented and exported by ntoskrnl.lib but
 * the installed WDK header set does not declare it. The documented prototype
 * is repeated here so the call is type-checked; the link proves the export. */
NTKERNELAPI
NTSTATUS
ObSetSecurityObjectByPointer(
    PVOID Object,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor
    );

/* The device is created with IoCreateDevice (not wdmsec.lib's
 * IoCreateDeviceSecure). wdmsec resolves a driver's service/registry state
 * through APIs that assume a normally loaded driver; that path faults for a
 * manually mapped image. The device DACL is therefore applied explicitly after
 * creation (see ApplyDeviceSecurity), so access never depends on the default
 * DACL inherited from the token the mapper happened to run under. */

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

static PDRIVER_OBJECT g_driverObject = NULL;
static PDEVICE_OBJECT g_deviceObject = NULL;
static UNICODE_STRING g_deviceName;
static UNICODE_STRING g_symbolicLinkName;
static volatile LONG g_linkCreated = 0;
static BOOLEAN g_active = FALSE;

/* Serializes symbolic-link deletion. All callers run at PASSIVE_LEVEL; the
 * mutex is held only around object-manager calls, never a spin lock, and the
 * interlocked link flag distinguishes "absent" from "deletion in progress"
 * across concurrent KICK / CLOSE / unload teardown. */
static KMUTEX g_discoveryMutex;

/* TRUE only once KeInitializeMutex has run. DriverEntry can fail before
 * BootstrapInitialize reaches that call (null output pointer), and a mapper may
 * still invoke DriverUnload afterwards, so every mutex user checks this flag
 * first instead of waiting on uninitialized mutex storage. */
static BOOLEAN g_discoveryReady = FALSE;

static VOID ReportLifecycleFailure(NTSTATUS status) {
    const ULONG dumpDataSize = sizeof(ULONG);
    const SIZE_T allocationSize = sizeof(IO_ERROR_LOG_PACKET) + dumpDataSize;
    UCHAR entrySize;
    PIO_ERROR_LOG_PACKET packet;

    /* A late teardown failure can run after both objects are gone. The error
     * log API requires a real object, so report nothing rather than NULL. */
    if (g_driverObject == NULL && g_deviceObject == NULL) {
        return;
    }

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

static NTSTATUS InitializeBootstrapSecurity(
    PISECURITY_DESCRIPTOR SecurityDescriptor,
    PACL Acl,
    ULONG AclSize,
    PSID SystemSid,
    PSID AdministratorsSid,
    ACCESS_MASK SystemAccess,
    ACCESS_MASK AdministratorsAccess) {
    SID_IDENTIFIER_AUTHORITY ntAuthority = {{0u, 0u, 0u, 0u, 0u, 5u}};
    NTSTATUS status;

    status = RtlInitializeSid(SystemSid, &ntAuthority, 1u);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *RtlSubAuthoritySid(SystemSid, 0u) = 18u; /* SECURITY_LOCAL_SYSTEM_RID */

    status = RtlInitializeSid(AdministratorsSid, &ntAuthority, 2u);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *RtlSubAuthoritySid(AdministratorsSid, 0u) = 32u;  /* BUILTIN domain */
    *RtlSubAuthoritySid(AdministratorsSid, 1u) = 544u; /* Administrators */

    status = RtlCreateAcl(Acl, AclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Two ACEs only: SYSTEM and Builtin Administrators. Every other principal,
     * including any token the loader happened to run under, receives no ACE and
     * is therefore denied access by the default-deny DACL semantics. */
    status = RtlAddAccessAllowedAce(
        Acl, ACL_REVISION, SystemAccess, SystemSid);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = RtlAddAccessAllowedAce(
        Acl, ACL_REVISION, AdministratorsAccess, AdministratorsSid);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlCreateSecurityDescriptor(
        SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlSetDaclSecurityDescriptor(
        SecurityDescriptor, TRUE, Acl, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* SE_DACL_PROTECTED is not applied here: the device is created fresh and
     * inherits nothing from an existing object, so the explicit DACL is all
     * obApplySecurityDescriptor installs. */
    return STATUS_SUCCESS;
}

/* Applies the explicit device DACL. Both principals receive FILE_ALL_ACCESS:
 * the driver opens its own device as SYSTEM, and the elevated client opens it
 * with GENERIC_READ|GENERIC_WRITE. No ACE is granted to anyone else, so the
 * device is no longer reachable through the default DACL of the loader token.
 * The descriptor is absolute and stack-resident; ObSetSecurityObjectByPointer
 * copies it into the object header before returning. */
static NTSTATUS ApplyDeviceSecurity(PDEVICE_OBJECT DeviceObject) {
    DECLSPEC_ALIGN(4) UCHAR aclStorage[128];
    DECLSPEC_ALIGN(4) UCHAR systemSidStorage[
        FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG)];
    DECLSPEC_ALIGN(4) UCHAR administratorsSidStorage[
        FIELD_OFFSET(SID, SubAuthority) + (2u * sizeof(ULONG))];
    SECURITY_DESCRIPTOR securityDescriptor;
    NTSTATUS status;

    status = InitializeBootstrapSecurity(
        &securityDescriptor,
        (PACL)aclStorage,
        sizeof(aclStorage),
        (PSID)systemSidStorage,
        (PSID)administratorsSidStorage,
        FILE_ALL_ACCESS,
        FILE_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return ObSetSecurityObjectByPointer(
        DeviceObject, DACL_SECURITY_INFORMATION, &securityDescriptor);
}

/* Runs inside IoCreateDriver with the genuine, object-manager-owned driver
 * object. Failure returns hand the object back to IoCreateDriver, which owns
 * cleanup: this callback must never call ObDereferenceObject on it. Bootstrap
 * resources that were already created are unwound here so the caller sees a
 * clean slate. */
static NTSTATUS BootstrapCreateDriver(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    UNREFERENCED_PARAMETER(RegistryPath);

    g_driverObject = DriverObject;

    RtlInitUnicodeString(&g_deviceName, AMGER_DEVICE_NAME);
    RtlInitUnicodeString(&g_symbolicLinkName, AMGER_SYMBOLIC_LINK);

    status = IoCreateDevice(
        DriverObject,
        0u,
        &g_deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* The device is published to user mode, so its DACL is fixed before the
     * symbolic link exposes it. A failure here leaves no name to reach it. */
    status = ApplyDeviceSecurity(g_deviceObject);
    if (!NT_SUCCESS(status)) {
        (void)BootstrapDestroyDevice();
        return status;
    }

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    if (!NT_SUCCESS(status)) {
        /* Preserve the link failure; record any device-deletion failure. */
        const NTSTATUS cleanupStatus = BootstrapDestroyDevice();
        if (!NT_SUCCESS(cleanupStatus)) {
            ReportLifecycleFailure(cleanupStatus);
        }
        return status;
    }
    InterlockedExchange(&g_linkCreated, 1L);

    g_active = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS BootstrapInitialize(
    PDEVICE_OBJECT* OutDeviceObject,
    PDRIVER_OBJECT* OutDriverObject) {
    NTSTATUS status;

    if (OutDeviceObject == NULL || OutDriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutDeviceObject = NULL;
    *OutDriverObject = NULL;

    KeInitializeMutex(&g_discoveryMutex, 0);
    g_discoveryReady = TRUE;

    /* Creates a genuine driver object and runs BootstrapCreateDriver against
     * it. The driver object is created unnamed: the device and symbolic link
     * carry the well-known name. */
    status = IoCreateDriver(NULL, BootstrapCreateDriver);
    if (!NT_SUCCESS(status)) {
        /* IoCreateDriver has already deleted the driver object it created and
         * the callback unwound its own bootstrap resources, so the pointer
         * held in g_driverObject is stale: never dereference or release it. */
        g_driverObject = NULL;
        return status;
    }

    *OutDeviceObject = g_deviceObject;
    *OutDriverObject = g_driverObject;
    return STATUS_SUCCESS;
}

VOID BootstrapReleaseDriverObject(VOID) {
    PDRIVER_OBJECT driver = (PDRIVER_OBJECT)InterlockedExchangePointer(
        (PVOID*)&g_driverObject, NULL);

    if (driver != NULL) {
        /* Drops the single reference IoCreateDriver returned to us. Callers
         * must have deleted the device object first: its creation took its own
         * reference on the driver object. Idempotent because the claim above
         * leaves NULL behind. */
        ObDereferenceObject(driver);
    }
}

/* Removes the symbolic link. g_discoveryMutex must be held by the caller. */
static NTSTATUS RemoveDiscoveryLocked(VOID) {
    NTSTATUS status = STATUS_SUCCESS;

    if (InterlockedCompareExchange(&g_linkCreated, 0L, 1L) == 1L) {
        const NTSTATUS linkStatus = IoDeleteSymbolicLink(&g_symbolicLinkName);
        if (NT_SUCCESS(linkStatus) || linkStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
            /* The link is gone (or was already absent); nothing to retry. */
        } else {
            /* Restore the claim: the link still exists and cleanup must retry. */
            InterlockedExchange(&g_linkCreated, 1L);
            status = linkStatus;
        }
    }

    return status;
}

NTSTATUS BootstrapRemoveDiscovery(VOID) {
    NTSTATUS status;

    /* Nothing was initialized, so there is nothing to remove. */
    if (!g_discoveryReady) {
        return STATUS_SUCCESS;
    }

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
    }
    return STATUS_SUCCESS;
}

NTSTATUS BootstrapDestroy(VOID) {
    NTSTATUS discoveryStatus;
    NTSTATUS deviceStatus;
    NTSTATUS finalStatus;
    BOOLEAN complete;

    /* Uninitialized mutex storage must never be waited on. A failed
     * BootstrapInitialize (or a DriverEntry that never reached it) leaves no
     * bootstrap resource to tear down. */
    if (!g_discoveryReady) {
        return STATUS_SUCCESS;
    }

    /* One critical section covers discovery and device teardown so a concurrent
     * KICK cannot observe a half-removed bootstrap or race a second removal. */
    KeWaitForSingleObject(&g_discoveryMutex, Executive, KernelMode, FALSE, NULL);

    discoveryStatus = RemoveDiscoveryLocked();
    deviceStatus = BootstrapDestroyDevice();

    /* Report inactive only when every resource is actually gone. A failed link
     * deletion restores its flag, keeping the state retryable. */
    complete = (g_linkCreated == 0 && g_deviceObject == NULL) ? TRUE : FALSE;
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

    if (!g_discoveryReady) {
        return FALSE;
    }

    KeWaitForSingleObject(&g_discoveryMutex, Executive, KernelMode, FALSE, NULL);
    active = g_active;
    KeReleaseMutex(&g_discoveryMutex, FALSE);
    return active;
}
