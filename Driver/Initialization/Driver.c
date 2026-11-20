/*
 * Driver.sys entry point for Phase 1.
 *
 * Contract: obtain a genuine driver object from the object manager, create the
 * secured well-known device on it, install the IOCTL dispatch and unload
 * routine, and return STATUS_SUCCESS. The device outlives every client and is
 * destroyed only by unload. DriverEntry failure unwinds
 * partial initialization directly because the OS does not call DriverUnload in
 * that case.
 * Inputs: the mapper-supplied DRIVER_OBJECT (rejected, never dereferenced) and
 * RegistryPath supplied by the loader stub.
 * Outputs: NTSTATUS describing initialization success.
 * Failure modes: any failed initialization step unwinds and returns status.
 */

#include <wdm.h>

#include "Startup/Bootstrap.h"
#include "../Communication/Endpoint/Bridge.h"

static VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    /* Enter terminal shutdown first so no REGISTER/KICK can be admitted while
     * the region and bootstrap resources are being torn down. */
    (void)BridgeBeginShutdown();
    const NTSTATUS regionStatus = BridgeReleaseResources();

    /* BootstrapDestroy reports its own failures through BootstrapReportCleanupFailure
     * (in-memory record + DbgPrintEx, no Event Log artifact). */
    const NTSTATUS destroyStatus = BootstrapDestroy();

    /* DriverUnload has no IRP channel to return a status. Keep every failure in
     * the in-memory record so it is observable rather than silently dropped. */
    if (!NT_SUCCESS(regionStatus)) {
        BootstrapReportCleanupFailure(regionStatus);
    }
    if (!NT_SUCCESS(destroyStatus)) {
        BootstrapReportCleanupFailure(destroyStatus);
    }

    /* The device object is gone, so the driver object can be released last. */
    BootstrapReleaseDriverObject();

    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT MapperDriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT deviceObject = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    NTSTATUS status;

    /* The mapper's fabricated DRIVER_OBJECT has an invalid OBJECT_HEADER:
     * ObfReferenceObject faults on it. It must never be dereferenced or passed
     * to any kernel API. A genuine object is created below instead. */
    UNREFERENCED_PARAMETER(MapperDriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    status = BootstrapInitialize(&deviceObject, &driverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    BridgeConfigure(BootstrapMachineHash());

    status = BridgeRegisterIoControl(driverObject, deviceObject);
    if (!NT_SUCCESS(status)) {
        /* Preserve the original failure; BootstrapDestroy logs cleanup failure. */
        (void)BootstrapDestroy();
        BootstrapReleaseDriverObject();
        return status;
    }

    driverObject->DriverUnload = DriverUnload;

    /* A normally loaded driver has the I/O manager clear this flag after
     * DriverEntry returns. A manually mapped image has no loader, and
     * IopParseDevice refuses to open a device that still carries
     * DO_DEVICE_INITIALIZING, so it is cleared here once dispatch is in place. */
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
