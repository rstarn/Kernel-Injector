#include "Bridge.h"

#include "../Routing/Dispatcher.h"
#include "../../Initialization/Startup/Bootstrap.h"
#include "../../Utilities/Guard.h"
#include "../../../Shared/Protocol.h"

typedef enum _AMGER_REGION_STATE {
    RegionStateUnregistered = 0,
    RegionStateRegistering,
    RegionStateRegistered,
    RegionStateClosing
} AMGER_REGION_STATE;

typedef struct _AMGER_REGISTRATION_CONTEXT {
    PAMGER_SHARED_REGION_REQUEST RequestPointer;
    AMGER_SHARED_REGION_REQUEST Request;
    PFILE_OBJECT OwnerFile;
    PMDL Mdl;
    PVOID SystemAddress;
    BOOLEAN Locked;
} AMGER_REGISTRATION_CONTEXT, * PAMGER_REGISTRATION_CONTEXT;

typedef struct _AMGER_KICK_CONTEXT {
    volatile AMGER_COMMAND_HEADER* Header;
    uint32_t Status;
} AMGER_KICK_CONTEXT, * PAMGER_KICK_CONTEXT;

typedef struct _AMGER_STATUS_WRITE_CONTEXT {
    volatile AMGER_COMMAND_HEADER* Header;
    uint32_t Status;
} AMGER_STATUS_WRITE_CONTEXT, * PAMGER_STATUS_WRITE_CONTEXT;

static KSPIN_LOCK g_regionLock;
static AMGER_REGION_STATE g_regionState = RegionStateUnregistered;
static volatile LONG g_activeOperations = 0;
static PMDL g_sharedMdl = NULL;
static PVOID g_sharedSystemAddress = NULL;
static SIZE_T g_sharedRegionSize = 0u;
static PFILE_OBJECT g_ownerFile = NULL;
static BOOLEAN g_connectionClosing = FALSE;
/* Terminal, monotonic shutdown marker. Once set under g_regionLock it is never
 * cleared: the device and its symbolic link are being torn down and no future
 * REGISTER or KICK may be admitted, even if BootstrapDestroy must be retried. */
static BOOLEAN g_terminalShutdown = FALSE;
static BOOLEAN g_bootstrapPending = FALSE;
static NTSTATUS g_discoveryRemovalStatus = STATUS_SUCCESS;

/* Bootstrap discovery state is shared by the KICK, CLOSE and unload paths.
 * These accessors serialize reads/writes with g_regionLock. The deletion work
 * itself is serialized inside Bootstrap.c and is never run while this spinlock
 * is held, so no blocking object-manager call occurs at raised IRQL. */
static BOOLEAN BootstrapRemovalPending(VOID) {
    KIRQL oldIrql;
    BOOLEAN pending;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    pending = g_bootstrapPending;
    KeReleaseSpinLock(&g_regionLock, oldIrql);
    return pending;
}

static VOID MarkBootstrapPending(VOID) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    g_bootstrapPending = TRUE;
    KeReleaseSpinLock(&g_regionLock, oldIrql);
}

static VOID RecordDiscoveryRemoval(NTSTATUS removalStatus) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    g_discoveryRemovalStatus = removalStatus;
    if (NT_SUCCESS(removalStatus)) {
        g_bootstrapPending = FALSE;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
}

static VOID ReconcileDiscoveryStatus(NTSTATUS teardownStatus) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    if (!NT_SUCCESS(g_discoveryRemovalStatus) && NT_SUCCESS(teardownStatus)) {
        g_discoveryRemovalStatus = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
}

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

/* CLEANUP runs in the closing process context and releases the user-mapped
 * region. The device stays alive so the subsequent CLOSE IRP can be delivered
 * and can delete the device object safely. */
static NTSTATUS CleanupDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    status = BridgeCleanupConnection(stack != NULL ? stack->FileObject : NULL);
    return CompleteIrp(Irp, status, 0u);
}

/* CLOSE runs after CLEANUP and after outstanding IRPs are finished. The owner
 * initiates teardown; once terminal shutdown has begun, any later CLOSE retries
 * it, because a successful release clears g_ownerFile before the bootstrap
 * teardown that may still fail. */
static NTSTATUS CloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    KIRQL oldIrql;
    BOOLEAN owner = FALSE;
    BOOLEAN shutdownStarted = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (stack != NULL) {
        /* Read ownership and the terminal marker in one critical section: an
         * ordinary non-owner CLOSE never starts shutdown, but a CLOSE arriving
         * after shutdown began must retry even though the owner is gone. */
        KeAcquireSpinLock(&g_regionLock, &oldIrql);
        owner = (g_ownerFile != NULL && stack->FileObject == g_ownerFile);
        shutdownStarted = g_terminalShutdown;
        KeReleaseSpinLock(&g_regionLock, oldIrql);
    }

    if (owner || shutdownStarted) {
        NTSTATUS regionStatus;
        NTSTATUS destroyStatus;
        NTSTATUS status;

        if (owner) {
            /* Enter terminal shutdown before releasing ownership, so no new
             * REGISTER/KICK can be admitted in the window before the device
             * and symbolic link are removed by BootstrapDestroy(). */
            (void)BridgeBeginShutdown();
        }

        /* Idempotent: ReleaseRegion claims the MDL once with
         * InterlockedExchangePointer, and BootstrapDestroy is serialized by
         * g_discoveryMutex, so concurrent retries cannot double-free. */
        regionStatus = BridgeReleaseResources();
        destroyStatus = BootstrapDestroy();
        status = NT_SUCCESS(regionStatus) ? destroyStatus : regionStatus;

        /* A discovery-removal failure recorded during KICK is resolved if the
         * final teardown succeeded; otherwise it stays recorded for diagnosis.
         * The read/modify/write of the shared status is synchronized. */
        ReconcileDiscoveryStatus(destroyStatus);

        return CompleteIrp(Irp, status, 0u);
    }

    return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
}

static BOOLEAN RegionBeginRegistration(PFILE_OBJECT FileObject) {
    KIRQL oldIrql;
    BOOLEAN accepted;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    /* CLEANUP sets g_connectionClosing under this same lock. Once set, no new
     * registration is accepted for the closing connection, before any MDL is
     * allocated or any user pages are probed. */
    accepted = (!g_terminalShutdown &&
                !g_connectionClosing &&
                g_regionState == RegionStateUnregistered);
    if (accepted) {
        /* Record the owner before commit so CLEANUP can identify and mark an
         * in-progress registration as closing. */
        g_ownerFile = FileObject;
        g_regionState = RegionStateRegistering;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
    return accepted;
}

static VOID RegionAbortRegistration(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    if (g_regionState == RegionStateRegistering) {
        g_regionState = RegionStateUnregistered;
    }
    /* On a plain failure the owner may register again. If CLEANUP marked this
     * connection closing, keep the owner so CLOSE can still remove the device. */
    if (!g_connectionClosing) {
        g_ownerFile = NULL;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
}

static BOOLEAN RegionCommitRegistration(PAMGER_REGISTRATION_CONTEXT Context) {
    KIRQL oldIrql;
    BOOLEAN accepted;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    accepted = !g_connectionClosing && g_regionState == RegionStateRegistering;
    if (accepted) {
        g_sharedMdl = Context->Mdl;
        g_sharedSystemAddress = Context->SystemAddress;
        g_sharedRegionSize = (SIZE_T)Context->Request.Size;
        g_ownerFile = Context->OwnerFile;
        g_regionState = RegionStateRegistered;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
    return accepted;
}

static BOOLEAN RegionBeginOperation(
    PFILE_OBJECT FileObject,
    volatile AMGER_COMMAND_HEADER** OutHeader) {
    KIRQL oldIrql;
    BOOLEAN accepted;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    /* Ownership and every mapping invariant are validated under g_regionLock
     * before the operation reference is taken. A different, already-open file
     * object must never drive the owner's registered region, and no failure
     * path may increment g_activeOperations or the drain in ReleaseRegion
     * would strand the reference and block MDL reclamation forever. Terminal
     * shutdown and CLEANUP both set g_connectionClosing / move the region out
     * of Registered under this same lock, so a KICK can never acquire a
     * reference once teardown begins. All checks and the increment are one
     * atomic critical section. */
    accepted = (FileObject != NULL &&
                FileObject == g_ownerFile &&
                !g_terminalShutdown &&
                !g_connectionClosing &&
                g_regionState == RegionStateRegistered &&
                g_sharedSystemAddress != NULL &&
                g_sharedRegionSize >= sizeof(AMGER_COMMAND_HEADER));
    if (accepted) {
        InterlockedIncrement(&g_activeOperations);
        *OutHeader = (volatile AMGER_COMMAND_HEADER*)g_sharedSystemAddress;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
    return accepted;
}

static VOID RegionEndOperation(VOID) {
    InterlockedDecrement(&g_activeOperations);
}

static VOID RegionReleasePartial(PAMGER_REGISTRATION_CONTEXT Context) {
    if (Context->Mdl != NULL) {
        if (Context->Locked) {
            MmUnlockPages(Context->Mdl);
            Context->Locked = FALSE;
        }
        IoFreeMdl(Context->Mdl);
        Context->Mdl = NULL;
    }
    Context->SystemAddress = NULL;
}

static NTSTATUS RegistrationWorker(PVOID ContextParameter) {
    PAMGER_REGISTRATION_CONTEXT context = (PAMGER_REGISTRATION_CONTEXT)ContextParameter;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

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

static NTSTATUS CaptureSnapshot(
    volatile AMGER_COMMAND_HEADER* Header,
    AMGER_COMMAND_SNAPSHOT* Snapshot) {
    volatile AMGER_HEADER_CONTROL* control =
        (volatile AMGER_HEADER_CONTROL*)&Header->Reserved[0];
    ULONG attempt;

    for (attempt = 0u; attempt < AMGER_SEQUENCE_RETRY_LIMIT; ++attempt) {
        uint32_t first = (uint32_t)InterlockedCompareExchange(
            (volatile long*)&control->Sequence, 0L, 0L);
        if ((first & 1u) != 0u) {
            continue;
        }

        MemoryBarrier();
        Snapshot->Magic = Header->Magic;
        Snapshot->Version = Header->Version;
        Snapshot->Command = Header->Command;
        Snapshot->Status = Header->Status;
        Snapshot->PayloadVirtualAddress = Header->PayloadVirtualAddress;
        Snapshot->PayloadSize = Header->PayloadSize;
        Snapshot->TargetProcessId = Header->TargetProcessId;
        Snapshot->Options = Header->Options;
        Snapshot->CompletionEventHandle = Header->CompletionEventHandle;
        MemoryBarrier();

        if ((uint32_t)InterlockedCompareExchange(
                (volatile long*)&control->Sequence, 0L, 0L) == first) {
            return STATUS_SUCCESS;
        }
    }

    return STATUS_RETRY;
}

static NTSTATUS WriteStatusWorker(PVOID ContextParameter) {
    PAMGER_STATUS_WRITE_CONTEXT context = (PAMGER_STATUS_WRITE_CONTEXT)ContextParameter;
    if (context->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    context->Header->Status = context->Status;
    return STATUS_SUCCESS;
}

static NTSTATUS KickWorker(PVOID ContextParameter) {
    PAMGER_KICK_CONTEXT context = (PAMGER_KICK_CONTEXT)ContextParameter;
    AMGER_COMMAND_SNAPSHOT snapshot;
    NTSTATUS status;

    context->Status = AMGER_STATUS_PENDING;

    if (context->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = CaptureSnapshot(context->Header, &snapshot);
    if (!NT_SUCCESS(status)) {
        context->Status = (uint32_t)status;
        return status;
    }

    status = DispatcherDispatch(&snapshot, &context->Status);
    context->Header->Status = context->Status;
    return status;
}

NTSTATUS BridgeRegisterIoControl(
    PDRIVER_OBJECT DriverObject,
    PDEVICE_OBJECT DeviceObject) {
    if (DriverObject == NULL || DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeSpinLock(&g_regionLock);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DefaultDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CleanupDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BridgeDispatch;

    return STATUS_SUCCESS;
}

NTSTATUS BridgeBeginShutdown(VOID) {
    KIRQL oldIrql;

    /* Enter terminal shutdown atomically with the connection-close transition.
     * This runs before BridgeReleaseResources() clears g_ownerFile /
     * g_connectionClosing / g_regionState, so there is no window in which a
     * new CREATE+REGISTER could be admitted while BootstrapDestroy() is still
     * removing the device and symbolic link. g_ownerFile is deliberately left
     * intact so the current CLOSE path can still identify its owner. */
    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    g_terminalShutdown = TRUE;
    g_connectionClosing = TRUE;
    if (g_regionState == RegionStateRegistered) {
        g_regionState = RegionStateClosing;
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);

    return STATUS_SUCCESS;
}

static NTSTATUS ReleaseRegion(BOOLEAN ClearOwner, BOOLEAN BoundedWait) {
    KIRQL oldIrql;
    AMGER_REGION_STATE previous;
    PMDL mdl;
    LARGE_INTEGER interval;
    ULONG waitCount;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    previous = g_regionState;
    if (previous == RegionStateUnregistered) {
        /* Nothing is mapped, but CLOSE/unload still owns the connection state.
         * Drop the owner and closing marker under the lock so a fully released
         * region is idempotent and can never strand ownership. CLEANUP calls
         * with ClearOwner == FALSE and deliberately keeps ownership for CLOSE. */
        if (ClearOwner) {
            g_ownerFile = NULL;
            g_connectionClosing = FALSE;
        }
        KeReleaseSpinLock(&g_regionLock, oldIrql);
        return STATUS_SUCCESS;
    }
    if (previous == RegionStateRegistering) {
        KeReleaseSpinLock(&g_regionLock, oldIrql);
        return STATUS_DEVICE_BUSY;
    }

    /* Registered or Closing both proceed: Closing means a previous CLEANUP
     * timed out while an operation still held a reference, and this call is
     * the retry from CLOSE or unload. The state never returns to Registered. */
    g_regionState = RegionStateClosing;
    KeReleaseSpinLock(&g_regionLock, oldIrql);

    waitCount = 0u;
    interval.QuadPart = -10000LL; /* 1 ms */
    while (InterlockedCompareExchange(&g_activeOperations, 0L, 0L) != 0L) {
        if (BoundedWait && waitCount >= 1000u) {
            /* Keep Closing and the MDL intact. CLOSE / unload will retry after
             * the outstanding IRP has completed; no mapping is released here. */
            return STATUS_TIMEOUT;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (!BoundedWait) {
            continue;
        }
        ++waitCount;
    }

    /* Claim the MDL only after the drain succeeded. Competing CLOSE/unload
     * callers then cannot free the same MDL twice. */
    mdl = (PMDL)InterlockedExchangePointer((PVOID*)&g_sharedMdl, NULL);
    if (mdl != NULL) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    g_sharedSystemAddress = NULL;
    g_sharedRegionSize = 0u;
    if (ClearOwner) {
        g_ownerFile = NULL;
        g_connectionClosing = FALSE;
    }
    /* CLEANUP (ClearOwner == FALSE) leaves the closing marker set until CLOSE
     * or unload, so a late REGISTER on the same file object is still rejected. */
    g_regionState = RegionStateUnregistered;
    KeReleaseSpinLock(&g_regionLock, oldIrql);

    return STATUS_SUCCESS;
}

NTSTATUS BridgeReleaseResources(VOID) {
    /* CLOSE and unload run after outstanding IRPs have completed; wait without
     * an artificial cap so the region is always reclaimed exactly once. */
    return ReleaseRegion(TRUE, FALSE);
}

NTSTATUS BridgeCleanupConnection(PFILE_OBJECT FileObject) {
    KIRQL oldIrql;
    BOOLEAN owner;
    BOOLEAN shouldRelease = FALSE;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    owner = (FileObject != NULL && g_ownerFile == FileObject);
    if (owner) {
        /* Mark the connection closing and move a Registered region to Closing
         * atomically, under the same lock that RegionBeginOperation checks.
         * No new operation can acquire a reference between the two changes,
         * so an MDL can never be released while a KICK is using its mapping. */
        g_connectionClosing = TRUE;
        if (g_regionState == RegionStateRegistered) {
            g_regionState = RegionStateClosing;
        }
        /* A Registering owner can no longer commit; its worker releases the
         * temporary MDL. A Registered region (now Closing) or an already
         * Closing region proceeds to drain and release the committed MDL. */
        shouldRelease = (g_regionState == RegionStateClosing);
    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);

    if (!shouldRelease) {
        return STATUS_SUCCESS;
    }

    /* Keep g_ownerFile so CLOSE can still identify its owning connection.
     * CLEANUP uses a bounded wait: on timeout the state stays Closing and the
     * MDL stays intact for CLOSE or unload to reclaim. */
    return ReleaseRegion(FALSE, TRUE);
}

NTSTATUS BridgeDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

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
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0u ||
            Irp->AssociatedIrp.SystemBuffer == NULL) {
            return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
        }
        if (!RegionBeginRegistration(stack->FileObject)) {
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        RtlZeroMemory(&context, sizeof(context));
        context.RequestPointer =
            (PAMGER_SHARED_REGION_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        context.OwnerFile = stack->FileObject;

        status = GuardExecute(RegistrationWorker, &context);
        if (!NT_SUCCESS(status)) {
            RegionReleasePartial(&context);
            RegionAbortRegistration();
            return CompleteIrp(Irp, status, 0u);
        }

        if (!RegionCommitRegistration(&context)) {
            /* CLEANUP marked this connection Closing before the worker finished.
             * Release the temporary MDL exactly once and keep the owner recorded
             * for CLOSE. The registration IRP reports the cancellation. */
            RegionReleasePartial(&context);
            RegionAbortRegistration();
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        /* Keep the device alive until the first KICK reaches this driver. */
        MarkBootstrapPending();

        return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
    }

    case AMGER_IOCTL_KICK: {
        AMGER_KICK_CONTEXT context;
        AMGER_STATUS_WRITE_CONTEXT writeContext;
        volatile AMGER_COMMAND_HEADER* header = NULL;
        NTSTATUS status;
        NTSTATUS writeStatus;

        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0u ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0u) {
            return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
        }
        if (!RegionBeginOperation(stack->FileObject, &header)) {
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        context.Header = header;
        context.Status = AMGER_STATUS_PENDING;
        status = GuardExecute(KickWorker, &context);

        /* Always publish a final, non-pending status on every execution path.
         * Every write to the mapped header occurs while the operation reference
         * is still held, before RegionEndOperation releases the right to touch
         * this mapping. */
        writeContext.Header = header;
        writeContext.Status = (context.Status != AMGER_STATUS_PENDING)
                                  ? context.Status
                                  : (uint32_t)status;
        writeStatus = GuardExecute(WriteStatusWorker, &writeContext);

        RegionEndOperation();

        if (BootstrapRemovalPending()) {
            /* Remove discovery only; CLEANUP releases the MDL and CLOSE deletes
             * the device after all IRPs for this handle have finished. The file
             * and link deletion is serialized inside Bootstrap.c. */
            RecordDiscoveryRemoval(BootstrapRemoveDiscovery());
        }

        /* If the final status could not be published, the client cannot observe
         * the outcome, so this KICK must not be reported as a success. */
        if (NT_SUCCESS(status) && !NT_SUCCESS(writeStatus)) {
            status = writeStatus;
        }

        return CompleteIrp(Irp, status, 0u);
    }

    default:
        return CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0u);
    }
}
