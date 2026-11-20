#ifndef AMGER_BOOTSTRAP_H
#define AMGER_BOOTSTRAP_H

/*
 * Bootstrap.h - genuine driver object and the secured well-known device.
 *
 * Contract: asks the object manager for a genuine DRIVER_OBJECT through
 * IoCreateDriver, then creates a secured device named in Protocol.h on it,
 * along with its DOS symbolic link. Both stay available until DriverUnload:
 * client exit never removes the name or the device. Discovery removal and
 * device destruction are separate operations, and the driver-object reference
 * is released last.
 * Inputs: two output pointers from DriverEntry.
 * Outputs: NTSTATUS from initialization and from cleanup operations.
 * Failure modes: every partially created resource is unwound; deletion errors
 * are returned and the link flag remains set until the link is actually gone.
 *
 * The DRIVER_OBJECT supplied to DriverEntry is never accepted here. A manually
 * mapped image receives a fabricated object whose OBJECT_HEADER is invalid;
 * IoCreateDevice references the driver object and would fault on it. The
 * object returned by IoCreateDriver is owned by the object manager and has a
 * valid OBJECT_HEADER, an allocated DriverExtension and a complete
 * MajorFunction[] table, so kernel APIs may use it safely.
 */

#include <wdm.h>

/*
 * Contract: creates the genuine driver object, then the secured well-known
 * device and symbolic link on it.
 * Inputs: OutDeviceObject and OutDriverObject, both required and nulled on
 * entry.
 * Outputs: STATUS_SUCCESS with both pointers valid.
 * Failure modes: STATUS_INVALID_PARAMETER for a null output pointer; otherwise
 * unwinds partial state and returns the failing NTSTATUS. On failure the
 * driver object has already been deleted by IoCreateDriver and must not be
 * touched.
 */

NTSTATUS BootstrapInitialize(
    PDEVICE_OBJECT* OutDeviceObject,
    PDRIVER_OBJECT* OutDriverObject);

/*
 * Contract: releases the single reference IoCreateDriver returned for the
 * genuine driver object. Idempotent; a second call is a no-op.
 * Inputs: none. Outputs: none.
 * Failure modes: none. Must only be called after BootstrapDestroy /
 * BootstrapDestroyDevice has deleted the device object, because device
 * creation holds its own reference on the driver object.
 */

VOID BootstrapReleaseDriverObject(VOID);

/*
 * Contract: removes the symbolic link. Idempotent.
 * Inputs: none. Outputs: STATUS_SUCCESS, or the link deletion error.
 * Failure modes: STATUS_OBJECT_NAME_NOT_FOUND is treated as success; other
 * errors are returned and leave the link flag set so a later retry can run.
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
 * Contract: reports a lifecycle cleanup failure without a persistent artifact.
 * The status is kept in an in-memory record and emitted through DbgPrintEx, so
 * it is observable to an attached debugger but never written to Event Viewer.
 * Used for failures that have no IRP status channel.
 * Inputs: NTSTATUS to record. Outputs: none. Failure modes: none; reporting
 * must never change driver behaviour.
 */

VOID BootstrapReportCleanupFailure(NTSTATUS status);

/*
 * Contract: reads the first lifecycle failure recorded by
 * BootstrapReportCleanupFailure / BootstrapDestroy without clearing it, so a
 * caller can surface the failure through its own channel instead of leaving it
 * silent. The record is never reset while the driver is resident.
 * Inputs: none. Outputs: the first recorded failure, or STATUS_SUCCESS.
 */

NTSTATUS BootstrapLastFailure(VOID);

/*
 * Contract: reports whether bootstrap initialization completed.
 * Inputs: none. Outputs: TRUE before destruction, FALSE afterwards.
 * Failure modes: none.
 */

BOOLEAN BootstrapIsActive(VOID);

/* Per-machine hash derived from MachineGuid, shared with the bridge for
 * randomized IOCTL codes and the command magic. */

ULONG64 BootstrapMachineHash(VOID);

#endif /* AMGER_BOOTSTRAP_H */
