#include "Bridge.h"

#include "Dispatcher.h"
#include "../Initialization/Bootstrap.h"
#include "../Utilities/Guard.h"
#include "../../Shared/Protocol.h"

static PMDL g_sharedMdl = NULL;
static PVOID g_sharedSystemAddress = NULL;
static SIZE_T g_sharedRegionSize = 0u;

typedef struct _AMGER_REGISTRATION_CONTEXT {
    PAMGER_SHARED_REGION_REQUEST RequestPointer;
    AMGER_SHARED_REGION_REQUEST Request;
    PMDL Mdl;
    PVOID SystemAddress;
    BOOLEAN Locked;
} AMGER_REGISTRATION_CONTEXT, * PAMGER_REGISTRATION_CONTEXT;

typedef struct _AMGER_KICK_CONTEXT {
    volatile AMGER_COMMAND_HEADER* Header;
} AMGER_KICK_CONTEXT, * PAMGER_KICK_CONTEXT;

static NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR information) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
}

static NTSTATUS RegistrationWorker(PVOID Context) {
    PAMGER_REGISTRATION_CONTEXT context = (PAMGER_REGISTRATION_CONTEXT)Context;

    context->Request = *context->RequestPointer;

    if (context->Request.VirtualAddress == 0u ||
        context->Request.Size < (uint64_t)sizeof(AMGER_COMMAND_HEADER) ||
        context->Request.Size > (uint64_t)AMGER_SHARED_REGION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    context->Mdl = IoAllocateMdl(
        (PVOID)(uintptr_t)context->Request.VirtualAddress,
        (ULONG)context->Request.Size,
        FALSE,
        FALSE,
        NULL);
    if (context->Mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmProbeAndLockPages(context->Mdl, UserMode, IoWriteAccess);
    context->Locked = TRUE;

    context->SystemAddress = MmGetSystemAddressForMdlSafe(
        context->Mdl, NormalPagePriority);
    if (context->SystemAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context->SystemAddress, sizeof(AMGER_COMMAND_HEADER));
    return STATUS_SUCCESS;
}

static NTSTATUS KickWorker(PVOID Context) {
    PAMGER_KICK_CONTEXT context = (PAMGER_KICK_CONTEXT)Context;

    if (context->Header == NULL ||
        context->Header->Magic != AMGER_MAGIC_NUMBER ||
        context->Header->Version != AMGER_PROTOCOL_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    return DispatcherDispatch(context->Header);
}

NTSTATUS BridgeRegisterIoControl(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject) {
    ULONG index;

    if (DriverObject == NULL || DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0u; index < IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        DriverObject->MajorFunction[index] = DefaultDispatch;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        BridgeDispatch;

    return STATUS_SUCCESS;
}

NTSTATUS BridgeDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack == NULL) {
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case AMGER_IOCTL_REGISTER_SHARED_REGION: {
        AMGER_REGISTRATION_CONTEXT context;
        NTSTATUS status;

        if (stack->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(AMGER_SHARED_REGION_REQUEST) ||
            Irp->AssociatedIrp.SystemBuffer == NULL) {
            return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
        }
        if (g_sharedMdl != NULL) {
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        RtlZeroMemory(&context, sizeof(context));
        context.RequestPointer =
            (PAMGER_SHARED_REGION_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        status = GuardExecute(RegistrationWorker, &context);
        if (!NT_SUCCESS(status)) {
            if (context.Mdl != NULL) {
                if (context.Locked) {
                    MmUnlockPages(context.Mdl);
                }
                IoFreeMdl(context.Mdl);
            }
            return CompleteIrp(Irp, status, 0u);
        }

        g_sharedMdl = context.Mdl;
        g_sharedSystemAddress = context.SystemAddress;
        g_sharedRegionSize = (SIZE_T)context.Request.Size;

        /* One-shot: remove name and device once the region is registered. */
        BootstrapDestroy();

        return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
    }

    case AMGER_IOCTL_KICK: {
        AMGER_KICK_CONTEXT context;

        if (g_sharedSystemAddress == NULL ||
            g_sharedRegionSize < (SIZE_T)sizeof(AMGER_COMMAND_HEADER)) {
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        context.Header = (volatile AMGER_COMMAND_HEADER*)g_sharedSystemAddress;
        /* The dispatcher writes the outcome into Header->Status; the IRP itself
         * always completes successfully as required by the Phase 1 protocol. */
        (void)GuardExecute(KickWorker, &context);

        return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
    }

    default:
        return CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0u);
    }
}
