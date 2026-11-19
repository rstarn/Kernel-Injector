#ifndef AMGER_BOOTSTRAP_H
#define AMGER_BOOTSTRAP_H

/*
 * Bootstrap.h - one-shot GUID device used to deliver the shared region.
 *
 * Contract: creates a randomly named secured device and DOS symbolic link at
 * DriverEntry, writes the full user path to the bootstrap file, and removes all
 * of it once. Discovery removal and device destruction are separate operations.
 * Inputs: DriverObject from DriverEntry and an output DEVICE_OBJECT pointer.
 * Outputs: NTSTATUS from initialization and from cleanup operations.
 * Failure modes: every partially created resource is unwound; deletion errors
 * are returned and flags remain set until the resource is actually gone.
 */

#include <wdm.h>

/*
 * Contract: creates the secured GUID device, symbolic link and bootstrap file.
 * Inputs: DriverObject; OutDeviceObject receives the device on success.
 * Outputs: STATUS_SUCCESS and a valid device object.
 * Failure modes: unwinds partial state and returns the failing NTSTATUS.
 */
NTSTATUS BootstrapInitialize(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT* OutDeviceObject);

/*
 * Contract: removes the bootstrap file and symbolic link. Idempotent.
 * Inputs: none. Outputs: STATUS_SUCCESS, or the first deletion error.
 * Failure modes: STATUS_OBJECT_NAME_NOT_FOUND is treated as success; other
 * errors are returned and leave the corresponding state flag set.
 */
NTSTATUS BootstrapRemoveDiscovery(VOID);

/*
 * Contract: deletes the device object. Idempotent.
 * Inputs: none. Outputs: STATUS_SUCCESS. Failure modes: none reported.
 */
NTSTATUS BootstrapDestroyDevice(VOID);

/*
 * Contract: removes discovery information, then destroys the device.
 * Inputs: none. Outputs: worst NTSTATUS from the two steps.
 * Failure modes: see BootstrapRemoveDiscovery.
 */
NTSTATUS BootstrapDestroy(VOID);

/*
 * Contract: reports a lifecycle cleanup failure to the kernel error log, which
 * persists after unload. Used for failures that have no IRP status channel.
 * Inputs: NTSTATUS to record. Outputs: none. Failure modes: a failed allocation
 * is ignored because logging must never change driver behaviour.
 */
VOID BootstrapReportCleanupFailure(NTSTATUS status);

/*
 * Contract: reports whether bootstrap initialization completed.
 * Inputs: none. Outputs: TRUE before destruction, FALSE afterwards.
 * Failure modes: none.
 */
BOOLEAN BootstrapIsActive(VOID);

#endif /* AMGER_BOOTSTRAP_H */
