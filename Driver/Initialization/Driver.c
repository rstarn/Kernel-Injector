/*
 * InjectorDriver.sys entry point for Phase 1.
 *
 * Contract: create the one-shot secured bootstrap device, install the IOCTL
 * dispatch and unload routine, and return STATUS_SUCCESS. DriverEntry failure
 * unwinds partial initialization directly because the OS does not call
 * DriverUnload in that case.
 * Inputs: DriverObject and RegistryPath supplied by the kernel loader.
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

    /* BootstrapDestroy reports its own failures to the kernel error log. */
    (void)BootstrapDestroy();

    UNREFERENCED_PARAMETER(DriverObject);

    /* DriverUnload cannot return a status. Bridge release failures have no IRP
     * channel here, so post them to the kernel error log. */
    if (!NT_SUCCESS(regionStatus)) {
        BootstrapReportCleanupFailure(regionStatus);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = BootstrapInitialize(DriverObject, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BridgeRegisterIoControl(DriverObject, deviceObject);
    if (!NT_SUCCESS(status)) {
        /* Preserve the original failure; BootstrapDestroy logs cleanup failure. */
        (void)BootstrapDestroy();
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    /* The device is created here during DriverEntry, not dynamically after it
     * returns. The I/O manager clears DO_DEVICE_INITIALIZING when DriverEntry
     * returns, so all dispatch routines, security settings and bootstrap
     * resources are ready before the device can be opened. */
    return STATUS_SUCCESS;
}
