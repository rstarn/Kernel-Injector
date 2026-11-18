#ifndef AMGER_BRIDGE_H
#define AMGER_BRIDGE_H

/*
 * Bridge.h - IOCTL surface and MDL lifetime owner.
 *
 * Contract: installs the device dispatch table, accepts exactly one shared
 * region registration, then services PING kicks through the shared header.
 * The MDL and locked pages stay in driver globals until Phase 8 adds teardown.
 * Inputs: DriverObject/DeviceObject at registration; IRPs at dispatch.
 * Outputs: NTSTATUS from registration and from each IRP completion.
 * Failure modes: invalid buffers, oversized regions, and faults while touching
 * the mapped region are reported as NTSTATUS without bugchecking.
 */

#include <wdm.h>

/*
 * Contract: installs default CREATE/CLOSE handling and the DEVICE_CONTROL
 * dispatch on the driver object.
 * Inputs: DriverObject to modify and DeviceObject to validate.
 * Outputs: STATUS_SUCCESS with the dispatch installed.
 * Failure modes: STATUS_INVALID_PARAMETER for either null pointer.
 */
NTSTATUS BridgeRegisterIoControl(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject);

/*
 * Contract: services REGISTER_SHARED_REGION (once) and KICK repeatedly.
 * Inputs: DeviceObject and IRP from the I/O manager.
 * Outputs: completed IRP; command outcome is written to shared Status.
 * Failure modes: invalid buffers give STATUS_INVALID_PARAMETER, an unmapped
 * user address gives STATUS_ACCESS_VIOLATION through the SEH guard, and a
 * kick before registration gives STATUS_INVALID_DEVICE_STATE.
 */
NTSTATUS BridgeDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp);

#endif /* AMGER_BRIDGE_H */
