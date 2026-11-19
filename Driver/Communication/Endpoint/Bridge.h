#ifndef AMGER_BRIDGE_H
#define AMGER_BRIDGE_H

/*
 * Bridge.h - IOCTL surface, region ownership and centralized cleanup.
 *
 * Contract: one shared region may be registered at a time. Registration is
 * serialized by a state machine; KICK holds a reference until command
 * processing finishes, and a mutex serializes use of the single command slot.
 * MDL resources are released by BridgeCleanupConnection
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
 * Contract: services REGISTER_SHARED_REGION, KICK and UNLOAD with explicit
 * completion. UNLOAD is owner-only and removes the device and its symbolic
 * link; the driver object stays resident so a later map can reuse the names.
 * Inputs: DeviceObject and IRP from the I/O manager.
 * Outputs: completed IRP whose status is the actual command outcome.
 * Failure modes: STATUS_INVALID_PARAMETER, STATUS_INVALID_DEVICE_STATE,
 * STATUS_ACCESS_DENIED, STATUS_INVALID_DEVICE_REQUEST or the dispatcher's
 * NTSTATUS.
 */
NTSTATUS BridgeDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp);

/*
 * Contract: enters the terminal shutdown state atomically under g_regionLock
 * and marks the connection closing. Once set, shutdown is never cleared, so no
 * subsequent REGISTER or KICK is admitted even if bootstrap teardown fails and
 * must be retried. Idempotent. Called only by DriverUnload before resource
 * release; client CLOSE never enters terminal shutdown.
 * Inputs: none. Outputs: STATUS_SUCCESS. Failure modes: none.
 */
NTSTATUS BridgeBeginShutdown(VOID);

/*
 * Contract: idempotently releases the registered MDL, unlocks its pages and
 * clears all ownership state. Safe before any registration and after release.
 * Used by CLOSE and unload, which run after outstanding IRPs have completed.
 * A registration still in progress is waited out (1 ms polling at
 * PASSIVE_LEVEL) before the region is released, so the device cannot be
 * deleted underneath the registration worker.
 * Inputs: none. Outputs: STATUS_SUCCESS. Failure modes: no resource is left
 * referenced after a successful return.
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
