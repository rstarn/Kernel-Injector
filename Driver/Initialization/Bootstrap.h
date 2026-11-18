#ifndef AMGER_BOOTSTRAP_H
#define AMGER_BOOTSTRAP_H

/*
 * Bootstrap.h - one-shot GUID device used to deliver the MDL region.
 *
 * Contract: creates a randomly named device and DOS symbolic link at
 * DriverEntry, writes the full user path to the bootstrap file, and removes all
 * of it once during BootstrapDestroy. No further connections are
 * accepted after destruction.
 * Inputs: DriverObject from DriverEntry and an output DEVICE_OBJECT pointer.
 * Outputs: NTSTATUS from initialization; device object on success.
 * Failure modes: GUID generation, device creation, link creation, or file write
 * failures unwind everything created so far and return the failing status.
 */

#include <wdm.h>

/*
 * Contract: creates the GUID device, symbolic link and bootstrap file.
 * Inputs: DriverObject from DriverEntry; OutDeviceObject receives the device.
 * Outputs: STATUS_SUCCESS and a valid device object.
 * Failure modes: any creation/write failure unwinds partial state and returns
 * the failing NTSTATUS; OutDeviceObject is left null.
 */
NTSTATUS BootstrapInitialize(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT* OutDeviceObject);

/*
 * Contract: removes the bootstrap file, symbolic link and device exactly once.
 * Inputs: none. Outputs: no names remain in the global namespace.
 * Failure modes: file deletion failure is ignored; object deletion errors are
 * not reported because the device is intentionally destroyed mid-IRP.
 */
VOID BootstrapDestroy(VOID);

/*
 * Contract: reports whether the bootstrap device still exists.
 * Inputs: none. Outputs: TRUE before destruction, FALSE afterwards.
 * Failure modes: none.
 */
BOOLEAN BootstrapIsActive(VOID);

#endif /* AMGER_BOOTSTRAP_H */
