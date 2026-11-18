#ifndef AMGER_BRIDGE_H
#define AMGER_BRIDGE_H

/*
 * Bridge.h - IOCTL surface, region ownership and centralized cleanup.
 *
 * Contract: one shared region may be registered at a time. Registration is
 * serialized by a state machine; KICK holds a reference until command
 * processing finishes. MDL resources are released by BridgeCleanupConnection
 * (CLEANUP) and BridgeReleaseResources (CLOSE / unload).
 * Inputs: DriverObject/DeviceObject at setup; IRPs at dispatch.
 * Outputs: NTSTATUS from setup and from each completed IRP.
 * Failure modes: invalid buffers, invalid IOCTL access, inconsistent command
 * snapshots and concurrent registration are reported as NTSTATUS.
 */

#include <wdm.h>

/*
 * Contract: initializes synchronization and installs CREATE/CLOSE/DEVICE_CONTROL.
 * Inputs: DriverObject to modify and DeviceObject to validate.
 * Outputs: STATUS_SUCCESS with dispatch installed.
 * Failure modes: STATUS_INVALID_PARAMETER for either null pointer.
 */
NTSTATUS BridgeRegisterIoControl(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject);

/*
 * Contract: services REGISTER_SHARED_REGION and KICK with explicit completion.
 * Inputs: DeviceObject and IRP from the I/O manager.
 * Outputs: completed IRP whose status is the actual command outcome.
 * Failure modes: STATUS_INVALID_PARAMETER, STATUS_INVALID_DEVICE_STATE,
 * STATUS_INVALID_DEVICE_REQUEST or the dispatcher's NTSTATUS.
 */
NTSTATUS BridgeDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp);

/*
 * Contract: enters the terminal shutdown state atomically under g_regionLock
 * and marks the connection closing. Once set, shutdown is never cleared, so no
 * subsequent REGISTER or KICK is admitted even if bootstrap teardown fails and
 * must be retried. Idempotent. Called by CLOSE and unload before resource
 * release; g_ownerFile is left intact so the caller can still identify owner.
 * Inputs: none. Outputs: STATUS_SUCCESS. Failure modes: none.
 */
NTSTATUS BridgeBeginShutdown(VOID);

/*
 * Contract: idempotently releases the registered MDL, unlocks its pages and
 * clears all ownership state. Safe before any registration and after release.
 * Used by CLOSE and unload, which run after outstanding IRPs have completed.
 * Inputs: none. Outputs: STATUS_SUCCESS, or STATUS_DEVICE_BUSY if called while
 * a registration is in progress. Failure modes: no resource is left referenced
 * after a successful return.
 */
NTSTATUS BridgeReleaseResources(VOID);

/*
 * Contract: transitions the owner connection to Closing, rejects new
 * operations, and releases its MDL after active operations drain. The owner
 * file object remains recorded so IRP_MJ_CLOSE can remove the device. A bounded
 * wait keeps CLEANUP from blocking indefinitely; on timeout the state remains
 * Closing and the MDL is retained for CLOSE / unload.
 * Inputs: FileObject from the CLEANUP IRP stack location.
 * Outputs: STATUS_SUCCESS when nothing or the matching owner was released,
 * STATUS_DEVICE_BUSY while registration is still in progress, STATUS_TIMEOUT
 * when active operations did not drain within the bounded wait.
 */
NTSTATUS BridgeCleanupConnection(PFILE_OBJECT FileObject);

#endif /* AMGER_BRIDGE_H */
