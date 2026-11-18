/*
 * InjectorDriver.sys entry point for Phase 1.
 *
 * Contract: create the one-shot bootstrap device, install the IOCTL dispatch,
 * and return STATUS_SUCCESS. Nothing else is initialized in Phase 1.
 * Inputs: DriverObject and RegistryPath supplied by the kernel loader (or by
 * the external manual mapper used for Phase 1 validation).
 * Outputs: NTSTATUS describing initialization success.
 * Failure modes: any failed initialization step unwinds and returns the
 * failing status; no dispatch is installed on failure.
 */

#include <wdm.h>

#include "Bootstrap.h"
#include "../Communication/Bridge.h"

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
        BootstrapDestroy();
        return status;
    }

    return STATUS_SUCCESS;
}
