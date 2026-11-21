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
 * Discovery uses a name derived from the machine GUID (see Protocol.h): the
 * device and its symbolic link are created unconditionally at DriverEntry and
 * stay available for every client until DriverUnload. No command or client
 * exit removes the name. BootstrapDestroy removes the link and the device
 * together during unload; BootstrapRemoveDiscovery is its link-only helper.
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

static PDRIVER_OBJECT g_driverObject = NULL;
static PDEVICE_OBJECT g_deviceObject = NULL;
static UNICODE_STRING g_deviceName;
static UNICODE_STRING g_symbolicLinkName;
static WCHAR g_deviceNameBuffer[64];
static WCHAR g_linkNameBuffer[64];

/* Both names are "\Device\"/"\DosDevices\" prefixes followed by the 16 hash
 * digits. The device name additionally gets an 8-digit per-map unique suffix
 * (see InitializeDerivedNames), so assert that worst case here. 64 wchar_t is
 * ample for both, but keep the contract explicit so a future buffer shrink
 * cannot silently truncate a name and break client/driver agreement. */

AMGER_STATIC_ASSERT(ARRAYSIZE(g_deviceNameBuffer) >= 8u + AMGER_NAME_DIGITS + 8u + 1u,
                    "device name buffer too small for prefix + hash + unique suffix + NUL");
AMGER_ASSERT_NAME_BUFFER(ARRAYSIZE(g_linkNameBuffer), 12u);

static uint64_t g_machineHash = 0u;
static volatile LONG g_linkCreated = 0;
static BOOLEAN g_active = FALSE;

/* Serializes symbolic-link deletion. All callers run at PASSIVE_LEVEL; the
 * mutex is held only around object-manager calls, never a spin lock, and the
 * interlocked link flag distinguishes "absent" from "deletion in progress"
 * across concurrent CLOSE / unload teardown. */

static KMUTEX g_discoveryMutex;

/* TRUE only once KeInitializeMutex has run. DriverEntry can fail before
 * BootstrapInitialize reaches that call (null output pointer), and a mapper may
 * still invoke DriverUnload afterwards, so every mutex user checks this flag
 * first instead of waiting on uninitialized mutex storage. */

static BOOLEAN g_discoveryReady = FALSE;

/* Last teardown failure, kept in memory so a failure is never silent: a
 * debugger/attached diagnostics can read it, but nothing is written to the
 * Event Log or any other persistent store. */

static volatile LONG g_lastLifecycleFailure = 0;

static VOID ReportLifecycleFailure(NTSTATUS status) {
    if (NT_SUCCESS(status)) {
        return;
    }

    /* Keep the first failure: retries must not overwrite the original cause. */

    InterlockedCompareExchange(&g_lastLifecycleFailure, (LONG)status, 0L);

    /* Debugger-visible only. DbgPrintEx is filtered by DPFLTR level and leaves
     * no disk artifact, unlike IoWriteErrorLogEntry (Event Viewer). */

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "lifecycle failure: 0x%08X\n", (ULONG)status);
}

NTSTATUS BootstrapLastFailure(VOID) {
    return (NTSTATUS)InterlockedCompareExchange(&g_lastLifecycleFailure, 0L, 0L);
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
     * ObSetSecurityObjectByPointer installs. */

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

static void CopyWideString(WCHAR* destination, const WCHAR* source) {
    while (*source != L'\0') {
        *destination++ = *source++;

    }
    *destination = L'\0';

}

/* MachineGuid is available in both user and kernel mode at PASSIVE_LEVEL.
 * Failing to read it is not fatal: both sides then use the plain prefix. */

static NTSTATUS ReadMachineGuid(WCHAR* output, ULONG capacityBytes, USHORT* byteLength) {
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    UCHAR information[512];
    ULONG informationLength = 0u;
    NTSTATUS status;

    RtlInitUnicodeString(&keyName,
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueName, L"MachineGuid");
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
                             information, sizeof(information), &informationLength);
    if (NT_SUCCESS(status)) {
        const PKEY_VALUE_PARTIAL_INFORMATION partial =
            (PKEY_VALUE_PARTIAL_INFORMATION)information;
        if (partial->Type == REG_SZ &&
            partial->DataLength >= sizeof(WCHAR) &&
            partial->DataLength <= capacityBytes) {
            RtlCopyMemory(output, partial->Data, partial->DataLength);
            *byteLength = (USHORT)partial->DataLength;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    }

    ZwClose(keyHandle);
    return status;
}

static void InitializeDerivedNames(VOID) {

    /* Same 128-WCHAR capacity the client uses in ReadMachineHash. Both sides
     * must accept the same MachineGuid length or they derive different names /
     * hashes / IOCTLs and the client cannot connect at all. */

    WCHAR guid[128] = { 0 };
    USHORT guidBytes = 0u;
    LARGE_INTEGER now;
    static const WCHAR digits[] = L"0123456789ABCDEF";

    RtlZeroMemory(g_deviceNameBuffer, sizeof(g_deviceNameBuffer));
    RtlZeroMemory(g_linkNameBuffer, sizeof(g_linkNameBuffer));
    CopyWideString(g_deviceNameBuffer, L"\\Device\\");
    CopyWideString(g_linkNameBuffer, L"\\DosDevices\\");

    if (NT_SUCCESS(ReadMachineGuid(guid, sizeof(guid), &guidBytes)) &&
        guidBytes >= sizeof(WCHAR)) {
        g_machineHash = AmgerMachineHash(guid, (size_t)(guidBytes / sizeof(WCHAR)));
    } else {
        g_machineHash = AmgerMachineHash(AMGER_FALLBACK_GUID,
                                         sizeof(AMGER_FALLBACK_GUID) / sizeof(WCHAR) - 1u);
    }

    AmgerAppendName(g_deviceNameBuffer, ARRAYSIZE(g_deviceNameBuffer), g_machineHash);
    AmgerAppendName(g_linkNameBuffer, ARRAYSIZE(g_linkNameBuffer), g_machineHash);

    /* The Win32 link stays stable so clients keep resolving the same \\.\<hash>
     * path. The kernel device object gets a per-map unique suffix: IoDeleteDevice
     * can leave a name reserved while stale references drain, so a later map
     * must not fail with STATUS_OBJECT_NAME_COLLISION (0xC0000035). */

    KeQuerySystemTime(&now);
    {
        uint32_t unique = (uint32_t)((uint64_t)now.QuadPart & 0xFFFFFFFFull);
        size_t used = 0u;
        while (used < ARRAYSIZE(g_deviceNameBuffer) &&
               g_deviceNameBuffer[used] != L'\0') {
            ++used;
        }
        for (int index = 7; index >= 0 &&
                            used + 1u < ARRAYSIZE(g_deviceNameBuffer);
             --index) {
            g_deviceNameBuffer[used++] = digits[unique & 0xFu];
            unique >>= 4u;
        }
        if (used < ARRAYSIZE(g_deviceNameBuffer)) {
            g_deviceNameBuffer[used] = L'\0';
        }
    }

    RtlInitUnicodeString(&g_deviceName, g_deviceNameBuffer);
    RtlInitUnicodeString(&g_symbolicLinkName, g_linkNameBuffer);
}

ULONG64 BootstrapMachineHash(VOID) {
    return g_machineHash;
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

    InitializeDerivedNames();

    /* A previous mapping may have left the derived Win32 name behind: client
     * exit intentionally keeps it and unload can fail partway. Clear any stale
     * link first so IoCreateSymbolicLink cannot collide. The device object name
     * is unique per map, so it cannot collide either. */

    (void)IoDeleteSymbolicLink(&g_symbolicLinkName);

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

        /* Preserve the security failure; record any device-deletion failure so
         * cleanup is never silent, matching the symbolic-link path below. */

        const NTSTATUS cleanupStatus = BootstrapDestroyDevice();
        if (!NT_SUCCESS(cleanupStatus)) {
            ReportLifecycleFailure(cleanupStatus);
        }
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

        /* Defensive: clear the unload routine before dropping the final
         * reference. If any object-delete path were to invoke DriverUnload, it
         * would be a no-op; all teardown here is already idempotent, but this
         * removes even the speculative re-entry. DriverEntry installed it. */

        driver->DriverUnload = NULL;

        /* Drops the single reference IoCreateDriver returned to us. Callers
         * must have deleted the device object first: its creation took its own
         * reference on the driver object. Idempotent because the claim above
         * leaves NULL behind. */

        ObDereferenceObject(driver);
    }
}

/* Removes the symbolic link. g_discoveryMutex must be held by the caller.
 *
 * The Win32 link name is derived from MachineGuid and is identical across
 * maps, while the device object name carries a per-map unique suffix. A fast
 * unload -> remap while the old image's deferred teardown is still draining
 * lets a new map recreate the SAME name pointing at its NEW device. Deleting
 * by NAME here would then
 * remove the new map's link and strand its device.
 *
 * Instead, open the link with DELETE access, verify its target through that
 * SAME handle, and delete THAT object instance with ZwMakeTemporaryObject +
 * ZwClose. Object-manager deletion follows the handle, not a later name
 * lookup, so even if a remap replaced the name between our open and our close
 * we can only ever remove the object we verified as ours. Wait-free, no named
 * mutex, safe at PASSIVE_LEVEL under g_discoveryMutex. */

static NTSTATUS RemoveDiscoveryLocked(VOID) {
    NTSTATUS status = STATUS_SUCCESS;

    if (InterlockedCompareExchange(&g_linkCreated, 0L, 1L) == 1L) {
        HANDLE linkHandle = NULL;
        OBJECT_ATTRIBUTES attributes;
        WCHAR targetBuffer[128];
        UNICODE_STRING target;

        InitializeObjectAttributes(&attributes, &g_symbolicLinkName,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL, NULL);
        status = ZwOpenSymbolicLinkObject(&linkHandle, DELETE | GENERIC_READ,
                                          &attributes);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            return STATUS_SUCCESS; /* already gone; nothing to retry */
        }
        if (!NT_SUCCESS(status)) {

            /* Cannot open: restore the claim so cleanup can retry. */

            InterlockedExchange(&g_linkCreated, 1L);
            return status;
        }

        RtlInitEmptyUnicodeString(&target, targetBuffer, sizeof(targetBuffer));
        status = ZwQuerySymbolicLinkObject(linkHandle, &target, NULL);
        if (!NT_SUCCESS(status)) {
            ZwClose(linkHandle);
            InterlockedExchange(&g_linkCreated, 1L);
            return status;
        }

        if (RtlEqualUnicodeString(&target, &g_deviceName, TRUE)) {

            /* Ours. Make this exact object temporary and drop our handle;
             * the name and object are removed when the handle count hits zero.
             * A remap that recreated the name owns a DIFFERENT object, which
             * this handle does not reference, so it is left untouched. */

            status = ZwMakeTemporaryObject(linkHandle);
        }

        /* Not ours (a newer map's): close without deleting it. */

        ZwClose(linkHandle);

        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&g_linkCreated, 1L);
            return status;
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
