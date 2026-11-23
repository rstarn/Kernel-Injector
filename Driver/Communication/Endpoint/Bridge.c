#include "Bridge.h"

#include "../Routing/Dispatcher.h"
#include "../../Initialization/Startup/Bootstrap.h"
#include "../../Utilities/Guard.h"
#include "../../../Shared/Protocol.h"
#include "../../Utilities/Parser/Format.h"

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
    PVOID UserAddress;
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

/* Serializes the log-ring read/select/write/publish sequence. KICK-originated
 * writers are already serialized by g_commandMutex, but REGISTER/CLEANUP/CLOSE/
 * UNLOAD/TeardownWriter call LogStage without it and could otherwise choose the
 * same ring slot and interleave fields. */

static KSPIN_LOCK g_logLock;
static KMUTEX g_commandMutex;

/* Serializes the whole region-teardown sequence. CLEANUP (bounded), CLOSE
 * (unbounded) and UNLOAD/DriverUnload can all call ReleaseRegion concurrently
 * on different IRPs. Without this, one caller can free the MDL while another
 * still holds a stale logAddress captured at entry, and LogStage writes through
 * freed pages -> bugcheck 0xA/0x50. All callers are PASSIVE_LEVEL. */

static KMUTEX g_teardownMutex;

/* Tracks in-flight IRPs so deferred teardown can WAIT for them to drain instead
 * of sleeping a fixed 50 ms. Each device dispatch acquires this lock on entry
 * and releases it after completing the IRP; TeardownWorker calls
 * IoReleaseRemoveLockAndWait so IoDeleteDevice only runs once no dispatch is
 * still touching the region/device. Once drained, further acquisitions fail
 * with STATUS_DELETE_PENDING, which the entry wrappers turn into a clean IRP
 * completion. */

static IO_REMOVE_LOCK g_removeLock;

/* Entry wrappers are defined at the end of this file (they call the dispatch
 * routines below, so they must appear after them). */

static NTSTATUS DefaultDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS CleanupDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS CloseDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS BridgeDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static AMGER_REGION_STATE g_regionState = RegionStateUnregistered;
static volatile LONG g_activeOperations = 0;
static PMDL g_sharedMdl = NULL;
static PVOID g_sharedUserAddress = NULL;
static PVOID g_sharedSystemAddress = NULL;
static SIZE_T g_sharedRegionSize = 0u;
static PFILE_OBJECT g_ownerFile = NULL;
static BOOLEAN g_connectionClosing = FALSE;

/* Terminal, monotonic shutdown marker. Only DriverUnload sets it, under
 * g_regionLock, when the device and its symbolic link are being destroyed.
 * Client exit never sets it: the device must stay openable by name. */

static BOOLEAN g_terminalShutdown = FALSE;
static ULONG g_ioctlRegister = 0u;
static ULONG g_ioctlKick = 0u;
static ULONG g_ioctlUnload = 0u;
static uint32_t g_magic = 0u;

/* UNLOAD must not delete the device while its own IRP is still in flight.
 * Queue the teardown to a work item after completing the IRP instead. */

static WORK_QUEUE_ITEM g_teardownWorkItem;
static BOOLEAN g_teardownQueued = FALSE;

static VOID TeardownWorker(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    /* Wait until every in-flight IRP has left its dispatch before deleting the
     * device. This replaces the old fixed 50 ms sleep: IoAcquireRemoveLock +
     * IoReleaseRemoveLockAndWait is the I/O manager's own synchronization, so
     * teardown proceeds exactly when the last IRP (including the UNLOAD IRP
     * still completing and the client's CLOSE IRP) has drained - never early,
     * never by guessing a duration. Once this returns, no new IRP can acquire
     * the lock (they fail STATUS_DELETE_PENDING), so deletion is race-free. */

    {
        NTSTATUS drainStatus = IoAcquireRemoveLock(&g_removeLock, NULL);
        if (NT_SUCCESS(drainStatus)) {
            IoReleaseRemoveLockAndWait(&g_removeLock, NULL);
        } else {

            /* Lock already drained/being drained by another teardown path. */

            BootstrapReportCleanupFailure(drainStatus);
        }
    }

    {
        const NTSTATUS regionStatus = BridgeReleaseResources();
        const NTSTATUS destroyStatus = BootstrapDestroy();

        /* Surface failures instead of discarding them: the in-memory record is
         * readable by a debugger and via BootstrapLastFailure, so a teardown
         * problem is never silent even though no Event Log entry is produced. */

        if (!NT_SUCCESS(regionStatus)) {
            BootstrapReportCleanupFailure(regionStatus);
        }
        if (!NT_SUCCESS(destroyStatus)) {
            BootstrapReportCleanupFailure(destroyStatus);
        }
    }

    /* Drop the IoCreateDriver reference last. If the client has not closed its
     * handle yet, the device object still holds its own reference on the driver
     * object and this drops ours to one; the object is then freed when that
     * handle closes. Otherwise this is the final reference and the object is
     * freed here. Either way no object-manager reference is leaked, and a later
     * map can still claim the same device and link names. The mapped image
     * itself stays resident — that is inherent to manual mapping and is the
     * mapper's responsibility to reclaim. */

    BootstrapReleaseDriverObject();
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
 * region. The device and its name stay alive so a later client can connect. */

static NTSTATUS CleanupDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    status = BridgeCleanupConnection(stack != NULL ? stack->FileObject : NULL);
    return CompleteIrp(Irp, status, 0u);
}

/* CLOSE runs after CLEANUP and after outstanding IRPs are finished. It only
 * releases the caller's region. The device object and symbolic link are never
 * touched here: they remain openable so the next client can connect by name.
 * Only DriverUnload enters terminal shutdown and destroys the bootstrap. */

static NTSTATUS CloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    KIRQL oldIrql;
    BOOLEAN owner = FALSE;
    BOOLEAN shutdownStarted = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (stack != NULL) {
        KeAcquireSpinLock(&g_regionLock, &oldIrql);
        owner = (g_ownerFile != NULL && stack->FileObject == g_ownerFile);
        shutdownStarted = g_terminalShutdown;
        KeReleaseSpinLock(&g_regionLock, oldIrql);
    }

    if (owner || shutdownStarted) {

        /* Idempotent: ReleaseRegion claims the MDL once with
         * InterlockedExchangePointer, so concurrent retries cannot double-free.
         * CLEANUP may have timed out; this unbounded pass reclaims the region. */

        const NTSTATUS status = BridgeReleaseResources();
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
     * allocated or any user pages are probed. A registration without a file
     * object would own a region that no CLEANUP/CLOSE could ever match, so it
     * is rejected here. */

    accepted = (FileObject != NULL &&
                !g_terminalShutdown &&
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
        g_sharedUserAddress = Context->UserAddress;
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
                g_sharedRegionSize >= AMGER_MINIMUM_REGION_SIZE);
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

/* Take an operation reference purely to guard a log write through the committed
 * mapping. Unlike RegionBeginOperation this does not require an owning file
 * object (REGISTER post-commit and UNLOAD use it), but it still validates under
 * g_regionLock that the mapping is Registered and takes the same reference the
 * drain in ReleaseRegion waits on. This closes the check-then-write race where
 * a concurrent CLEANUP could free the MDL between a NULL check and LogStage.
 * Every successful call MUST be paired with RegionEndOperation. */

static BOOLEAN RegionBeginLogRef(PVOID* OutAddress, SIZE_T* OutSize) {
    KIRQL oldIrql;
    BOOLEAN accepted;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    accepted = (!g_terminalShutdown &&
                !g_connectionClosing &&
                g_regionState == RegionStateRegistered &&
                g_sharedSystemAddress != NULL &&
                g_sharedRegionSize >= AMGER_MINIMUM_REGION_SIZE);
    if (accepted) {
        InterlockedIncrement(&g_activeOperations);
        *OutAddress = g_sharedSystemAddress;
        *OutSize = g_sharedRegionSize;

    }
    KeReleaseSpinLock(&g_regionLock, oldIrql);
    return accepted;
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
        context->Request.Size < (uint64_t)AMGER_MINIMUM_REGION_SIZE ||
        context->Request.Size > (uint64_t)AMGER_SHARED_REGION_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    context->UserAddress = (PVOID)(uintptr_t)context->Request.VirtualAddress;

    context->Mdl = IoAllocateMdl(
        context->UserAddress,
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

/* A payload range must lie entirely inside the registered user region. Without
 * this, a snapshot naming an arbitrary user address would turn the mapped MDL
 * into a kernel read/write primitive. Zero size means "no payload". */

static NTSTATUS ValidatePayloadRange(const AMGER_COMMAND_SNAPSHOT* Snapshot) {
    uint64_t regionStart;
    uint64_t payloadEnd;
    uint64_t payloadStart;

    if (Snapshot->PayloadSize == 0u) {
        return STATUS_SUCCESS;
    }
    if (g_sharedUserAddress == NULL || g_sharedSystemAddress == NULL ||
        g_sharedRegionSize < AMGER_MINIMUM_REGION_SIZE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    regionStart = (uint64_t)(uintptr_t)g_sharedUserAddress;

    /* The log tail is never part of the payload. */

    payloadEnd = regionStart + (uint64_t)g_sharedRegionSize -
                 AMGER_LOG_AREA_SIZE - AMGER_REPORT_AREA_SIZE;
    payloadStart = Snapshot->PayloadVirtualAddress;

    /* Subtraction form avoids overflow from a hostile PayloadSize. */

    if (payloadStart < regionStart + AMGER_PAYLOAD_OFFSET ||
        payloadStart > payloadEnd ||
        Snapshot->PayloadSize > payloadEnd - payloadStart) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS WriteStatusWorker(PVOID ContextParameter) {
    PAMGER_STATUS_WRITE_CONTEXT context = (PAMGER_STATUS_WRITE_CONTEXT)ContextParameter;
    if (context->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    context->Header->Status = context->Status;
    return STATUS_SUCCESS;
}

/* Appends one record to the log ring at the tail of the registered region.
 * The ring sequence is published last, so a reading client can detect a torn
 * record by sampling it twice. */

static VOID LogStage(PVOID SystemAddress,
                     SIZE_T RegionSize,
                     uint16_t Id,
                     uint32_t Status,
                     uint32_t Detail) {
    volatile AMGER_LOG_RING* ring = (volatile AMGER_LOG_RING*)(
        (PUCHAR)SystemAddress + RegionSize - sizeof(AMGER_LOG_RING));
    KIRQL oldIrql;

    /* Keep slot selection and publication atomic with respect to other writers.
     * The ring lives in MDL-locked, system-mapped pages, so it is safe to touch
     * at the raised IRQL of a spinlock. */

    KeAcquireSpinLock(&g_logLock, &oldIrql);
    uint32_t sequence = ring->Sequence;
    volatile AMGER_LOG_ENTRY* entry =
        &ring->Entries[sequence % AMGER_LOG_ENTRY_COUNT];

    ++sequence;
    entry->Sequence = sequence;
    entry->Id = Id;
    entry->Reserved = 0u;
    entry->Status = Status;
    entry->Detail = Detail;
    MemoryBarrier();
    ring->Sequence = sequence;
    KeReleaseSpinLock(&g_logLock, oldIrql);
}

static NTSTATUS KickWorker(PVOID ContextParameter) {
    PAMGER_KICK_CONTEXT context = (PAMGER_KICK_CONTEXT)ContextParameter;
    AMGER_COMMAND_SNAPSHOT snapshot;
    AMGER_DISPATCH_CONTEXT dispatch;
    NTSTATUS status;

    context->Status = AMGER_STATUS_PENDING;

    if (context->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Publish a zero result slot up front so every early return below cannot
     * leave a value from an earlier command visible to the client. */

    {
        PAMGER_RESULT_CONTROL result =
            (PAMGER_RESULT_CONTROL)&context->Header->Reserved[0];
        result->ResultValue = 0u;
        RtlZeroMemory((PVOID)&context->Header->Reserved[4], 60u);
        RtlZeroMemory((PUCHAR)g_sharedSystemAddress + g_sharedRegionSize -
                          AMGER_LOG_AREA_SIZE - AMGER_REPORT_AREA_SIZE,
                      AMGER_REPORT_AREA_SIZE);
        MemoryBarrier();
    }

    status = CaptureSnapshot(context->Header, &snapshot);
    if (status == STATUS_RETRY) {
        LogStage(g_sharedSystemAddress, g_sharedRegionSize,
                 (uint16_t)AMGER_LOG_ID_SNAPSHOT_RETRY,
                 (uint32_t)status, AMGER_SEQUENCE_RETRY_LIMIT);
    }
    LogStage(g_sharedSystemAddress, g_sharedRegionSize,
             (uint16_t)AMGER_LOG_ID_HEADER_VALIDATE, (uint32_t)status, 0u);
    if (!NT_SUCCESS(status)) {
        context->Status = (uint32_t)status;
        return status;
    }

    status = ValidatePayloadRange(&snapshot);
    LogStage(g_sharedSystemAddress, g_sharedRegionSize,
             (uint16_t)AMGER_LOG_ID_PAYLOAD_RANGE, (uint32_t)status, 0u);
    if (!NT_SUCCESS(status)) {
        context->Status = (uint32_t)status;
        return status;
    }

    dispatch.Snapshot = &snapshot;
    dispatch.PayloadSystemAddress = NULL;
    dispatch.PayloadSize = 0u;
    dispatch.PayloadOffset = 0u;
    dispatch.StageId = (uint16_t)AMGER_LOG_ID_COMMAND_DECODE;
    dispatch.ResultValue = 0u;
    dispatch.Magic = g_magic;

    /* Surface any recorded teardown failure through the STATUS command. The
     * record is read-only, so repeated queries see the same first failure. */

    dispatch.LastFailure = (uint32_t)BootstrapLastFailure();
    if (snapshot.PayloadSize != 0u) {
        const SIZE_T offset = (SIZE_T)(snapshot.PayloadVirtualAddress -
                                       (uint64_t)(uintptr_t)g_sharedUserAddress);
        dispatch.PayloadSystemAddress = (PVOID)((PUCHAR)g_sharedSystemAddress + offset);
        dispatch.PayloadSize = (SIZE_T)snapshot.PayloadSize;
        dispatch.PayloadOffset = offset;
    }

    status = DispatcherDispatch(&dispatch, &context->Status);

    /* Every command publishes the result slot in Reserved[8..15] (zero when it
     * produces no data), so a reader never sees a stale value from an earlier
     * command. The seqlock word at Reserved[0..3] is untouched. */

    {
        PAMGER_RESULT_CONTROL result =
            (PAMGER_RESULT_CONTROL)&context->Header->Reserved[0];
        MemoryBarrier();
        result->ResultValue = dispatch.ResultValue;
        MemoryBarrier();
    }

    /* Publish the full parser report into the dedicated area ahead of the log
     * tail. No string literal is emitted by the driver. */
    {
        PUCHAR reportArea = (PUCHAR)g_sharedSystemAddress + g_sharedRegionSize -
                            AMGER_LOG_AREA_SIZE - AMGER_REPORT_AREA_SIZE;
        AMGER_PARSER_REPORT report;

        if (dispatch.ParserImageValid) {
            PeBuildReport(&dispatch.ParserImage, &report);
        } else {
            RtlZeroMemory(&report, sizeof(report));
            report.Signature = AMGER_PARSER_REPORT_SIGNATURE;
            report.ParseStatus = dispatch.ParserStatus;
        }
        if (dispatch.AllocReport.Flags != 0u || dispatch.AllocReport.Status != 0u) {
            report.Allocation = dispatch.AllocReport;
        }
        if (dispatch.MapReport.Flags != 0u || dispatch.MapReport.Status != 0u) {
            report.Mapping = dispatch.MapReport;
        }
        if (dispatch.RelocReport.Flags != 0u || dispatch.RelocReport.Status != 0u) {
            report.Relocation = dispatch.RelocReport;
        }
        if (dispatch.ImportReport.Flags != 0u || dispatch.ImportReport.Status != 0u) {
            report.Imports = dispatch.ImportReport;
        }
        MemoryBarrier();
        RtlCopyMemory(reportArea, &report, sizeof(report));
        MemoryBarrier();
    }

    LogStage(g_sharedSystemAddress, g_sharedRegionSize,
             dispatch.StageId, (uint32_t)status, 0u);
    LogStage(g_sharedSystemAddress, g_sharedRegionSize,
             (uint16_t)AMGER_LOG_ID_RESULT, (uint32_t)status, 0u);
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
    KeInitializeSpinLock(&g_logLock);
    KeInitializeMutex(&g_commandMutex, 0);
    KeInitializeMutex(&g_teardownMutex, 0);
    IoInitializeRemoveLock(&g_removeLock, (ULONG)'grmA', 0u, 0u);

    /* Reset the one-shot teardown claim at initialization, not in the worker:
     * clearing it in the worker would allow a second queue of this same static
     * WORK_QUEUE_ITEM before TeardownWorker gets to run. */

    g_teardownQueued = FALSE;

    /* Install the remove-lock entry wrappers, not the raw dispatch routines.
     * Each wrapper holds an IRP reference for the whole dispatch so the
     * deferred teardown can drain them with IoReleaseRemoveLockAndWait. */

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DefaultDispatchEntry;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CleanupDispatchEntry;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseDispatchEntry;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BridgeDispatchEntry;

    return STATUS_SUCCESS;
}

NTSTATUS BridgeBeginShutdown(VOID) {
    KIRQL oldIrql;

    /* Enter terminal shutdown atomically with the connection-close transition.
     * This runs before BridgeReleaseResources() clears g_ownerFile /
     * g_connectionClosing / g_regionState, so no new CREATE+REGISTER can be
     * admitted while DriverUnload removes the device and symbolic link. */

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
    PVOID logAddress;
    SIZE_T logRegionSize;
    NTSTATUS result = STATUS_SUCCESS;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* Serialize all teardown: without this, two concurrent callers can both
     * capture a live logAddress, one frees the MDL, and the other writes through
     * the now-freed pages -> bugcheck. */

    KeWaitForSingleObject(&g_teardownMutex, Executive, KernelMode, FALSE, NULL);

    interval.QuadPart = -10000LL; /* 1 ms */
    logAddress = g_sharedSystemAddress;
    logRegionSize = g_sharedRegionSize;

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    while (g_regionState == RegionStateRegistering) {
        if (BoundedWait) {
            KeReleaseSpinLock(&g_regionLock, oldIrql);
            if (logAddress != NULL) {
                LogStage(logAddress, logRegionSize,
                         (uint16_t)AMGER_LOG_ID_CLEANUP_DRAIN,
                         (uint32_t)STATUS_DEVICE_BUSY, 0u);
            }
            result = STATUS_DEVICE_BUSY;
            goto done;
        }
        KeReleaseSpinLock(&g_regionLock, oldIrql);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        KeAcquireSpinLock(&g_regionLock, &oldIrql);
    }

    previous = g_regionState;
    if (previous == RegionStateUnregistered) {
        if (ClearOwner) {
            g_ownerFile = NULL;
            g_connectionClosing = FALSE;
        }
        KeReleaseSpinLock(&g_regionLock, oldIrql);
        goto done;
    }

    /* Registered or Closing both proceed; the state never returns to Registered. */

    g_regionState = RegionStateClosing;
    KeReleaseSpinLock(&g_regionLock, oldIrql);

    waitCount = 0u;
    while (InterlockedCompareExchange(&g_activeOperations, 0L, 0L) != 0L) {
        if (BoundedWait && waitCount >= 1000u) {
            if (logAddress != NULL) {
                LogStage(logAddress, logRegionSize,
                         (uint16_t)AMGER_LOG_ID_CLEANUP_DRAIN,
                         (uint32_t)STATUS_TIMEOUT,
                         (uint32_t)InterlockedCompareExchange(&g_activeOperations, 0L, 0L));
            }
            result = STATUS_TIMEOUT;
            goto done;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (!BoundedWait) {
            continue;
        }
        ++waitCount;
    }

    if (logAddress != NULL) {
        if (BoundedWait) {
            LogStage(logAddress, logRegionSize,
                     (uint16_t)AMGER_LOG_ID_CLEANUP_DRAIN,
                     (uint32_t)STATUS_SUCCESS, 0u);
        } else {
            LogStage(logAddress, logRegionSize,
                     (uint16_t)AMGER_LOG_ID_CLOSE_RECLAIM,
                     (uint32_t)STATUS_SUCCESS, (uint32_t)logRegionSize);
        }
    }

    mdl = (PMDL)InterlockedExchangePointer((PVOID*)&g_sharedMdl, NULL);
    if (mdl != NULL) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }

    KeAcquireSpinLock(&g_regionLock, &oldIrql);
    g_sharedUserAddress = NULL;
    g_sharedSystemAddress = NULL;
    g_sharedRegionSize = 0u;
    if (ClearOwner) {
        g_ownerFile = NULL;
        g_connectionClosing = FALSE;
    }
    g_regionState = RegionStateUnregistered;
    KeReleaseSpinLock(&g_regionLock, oldIrql);

done:
    KeReleaseMutex(&g_teardownMutex, FALSE);
    return result;
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

VOID BridgeConfigure(ULONG64 MachineHash) {
    g_ioctlRegister = CTL_CODE(AMGER_DEVICE_TYPE,
        AmgerIoctlFunction(AMGER_IOCTL_FUNCTION_REGISTER, MachineHash),
        AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS);
    g_ioctlKick = CTL_CODE(AMGER_DEVICE_TYPE,
        AmgerIoctlFunction(AMGER_IOCTL_FUNCTION_KICK, MachineHash),
        AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS);
    g_ioctlUnload = CTL_CODE(AMGER_DEVICE_TYPE,
        AmgerIoctlFunction(AMGER_IOCTL_FUNCTION_UNLOAD, MachineHash),
        AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS);
    g_magic = AmgerMagicValue(MachineHash);
}

NTSTATUS BridgeDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    ULONG code;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack == NULL) {
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
    }

    code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code == g_ioctlRegister) {
        AMGER_REGISTRATION_CONTEXT context;
        NTSTATUS status;

        if (stack->Parameters.DeviceIoControl.InputBufferLength !=
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

        status = GuardExecute(RegistrationWorker, &context, TRUE); /* probes user MDL */
        if (!NT_SUCCESS(status)) {
            if (context.SystemAddress != NULL) {
                LogStage(context.SystemAddress, (SIZE_T)context.Request.Size,
                         (uint16_t)AMGER_LOG_ID_REGISTER_MDL,
                         (uint32_t)status, (uint32_t)context.Request.Size);
            }
            RegionReleasePartial(&context);
            RegionAbortRegistration();
            return CompleteIrp(Irp, status, 0u);
        }

        LogStage(context.SystemAddress, (SIZE_T)context.Request.Size,
                 (uint16_t)AMGER_LOG_ID_REGISTER_MDL,
                 (uint32_t)STATUS_SUCCESS, (uint32_t)context.Request.Size);

        if (!RegionCommitRegistration(&context)) {

            /* CLEANUP marked this connection Closing before the worker finished.
             * Release the temporary MDL exactly once and keep the owner recorded
             * for CLOSE. The registration IRP reports the cancellation. */

            LogStage(context.SystemAddress, (SIZE_T)context.Request.Size,
                     (uint16_t)AMGER_LOG_ID_REGISTER_COMMIT,
                     (uint32_t)STATUS_INVALID_DEVICE_STATE,
                     (uint32_t)context.Request.Size);
            RegionReleasePartial(&context);
            RegionAbortRegistration();
            return CompleteIrp(Irp, STATUS_INVALID_DEVICE_STATE, 0u);
        }

        /* The committed mapping is now owned by the globals. Re-acquire a
         * region reference before logging through it so a concurrent CLEANUP
         * cannot race this write; the reference validates the region is still
         * the Registered one rather than trusting the now-aliasing local. */

        {
            PVOID logAddress = NULL;
            SIZE_T logSize = 0u;
            if (RegionBeginLogRef(&logAddress, &logSize)) {
                LogStage(logAddress, logSize,
                         (uint16_t)AMGER_LOG_ID_REGISTER_COMMIT,
                         (uint32_t)STATUS_SUCCESS, (uint32_t)context.Request.Size);
                RegionEndOperation();
            }
        }

        return CompleteIrp(Irp, STATUS_SUCCESS, 0u);
    } else if (code == g_ioctlKick) {
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

        /* A single shared command slot cannot safely serve concurrent KICKs.
         * Serialize snapshot, dispatch and status publication at PASSIVE_LEVEL.
         * The active-operation reference remains held while waiting, so CLEANUP
         * cannot release the MDL underneath a queued command. */

        status = KeWaitForSingleObject(
            &g_commandMutex, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(status)) {
            RegionEndOperation();
            return CompleteIrp(Irp, status, 0u);
        }

        context.Header = header;
        context.Status = AMGER_STATUS_PENDING;
        status = GuardExecute(KickWorker, &context, FALSE); /* never probes user memory */

        /* Always publish a final, non-pending status on every execution path.
         * Every write to the mapped header occurs while the operation reference
         * is still held, before RegionEndOperation releases the right to touch
         * this mapping. */

        writeContext.Header = header;
        writeContext.Status = (context.Status != AMGER_STATUS_PENDING)
                                  ? context.Status
                                  : (uint32_t)status;
        writeStatus = GuardExecute(WriteStatusWorker, &writeContext, FALSE); /* MDL-locked only */
        KeReleaseMutex(&g_commandMutex, FALSE);

        RegionEndOperation();

        /* If the final status could not be published, the client cannot observe
         * the outcome, so this KICK must not be reported as a success. */

        if (NT_SUCCESS(status) && !NT_SUCCESS(writeStatus)) {
            status = writeStatus;
        }

        return CompleteIrp(Irp, status, 0u);
    } else if (code == g_ioctlUnload) {
        BOOLEAN owner;
        BOOLEAN queueTeardown = FALSE;
        KIRQL oldIrql;
        NTSTATUS status;

        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0u ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0u) {
            return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0u);
        }

        KeAcquireSpinLock(&g_regionLock, &oldIrql);
        owner = (stack->FileObject != NULL &&
                 stack->FileObject == g_ownerFile &&
                 !g_terminalShutdown);
        if (owner) {

            /* Claim deferred teardown atomically with the owner check. Two
             * concurrent owner UNLOAD IRPs may both pass the owner test before
             * BridgeBeginShutdown publishes terminal shutdown; without this
             * atomic claim both would queue the same static WORK_QUEUE_ITEM,
             * corrupting the system work queue and bugchecking. Exactly one
             * caller wins the claim and queues teardown. */

            queueTeardown = !g_teardownQueued;
            g_teardownQueued = TRUE;
        }
        KeReleaseSpinLock(&g_regionLock, oldIrql);
        if (!owner) {
            return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0u);
        }

        /* Log while the mapping is still valid, under a region reference so a
         * concurrent CLEANUP cannot free the MDL between the check and the
         * write. After BridgeReleaseResources the pages are no longer ours. */

        {
            PVOID logAddress = NULL;
            SIZE_T logSize = 0u;
            if (RegionBeginLogRef(&logAddress, &logSize)) {
                LogStage(logAddress, logSize,
                         (uint16_t)AMGER_LOG_ID_UNLOAD_OWNER,
                         (uint32_t)STATUS_SUCCESS, 0u);
                RegionEndOperation();
            }
        }

        /* Enter terminal shutdown synchronously so no new REGISTER or KICK is
         * admitted, but defer the actual object deletion: IoDeleteDevice from
         * inside this IRP's dispatch can leave the driver object with an
         * in-flight request and has produced object-reference bugchecks. */

        status = BridgeBeginShutdown();
        if (!NT_SUCCESS(status)) {
            return CompleteIrp(Irp, status, 0u);
        }

        if (queueTeardown) {
            ExInitializeWorkItem(&g_teardownWorkItem, TeardownWorker, NULL);
            ExQueueWorkItem(&g_teardownWorkItem, DelayedWorkQueue);
        }

        /* Full teardown is deferred to TeardownWorker: it drains the region,
         * deletes the device and symbolic link, then drops the driver-object
         * reference last. The mapped image stays resident until the mapper
         * reclaims it, but no object-manager reference is leaked. */

        return CompleteIrp(Irp, status, 0u);
    } else {
        return CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0u);
    }
}

/* Remove-lock entry wrappers.
 *
 * Each holds a remove-lock reference across the entire dispatch, including
 * IoCompleteRequest, so TeardownWorker's IoReleaseRemoveLockAndWait cannot
 * delete the device while any IRP is still in flight. If the lock has already
 * been drained (teardown began), IoAcquireRemoveLock fails and the IRP is
 * completed with that status instead of touching a device being torn down.
 * The real dispatch routines below are unchanged; these only bracket them. */

static NTSTATUS DefaultDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS acquired = IoAcquireRemoveLock(&g_removeLock, Irp);
    NTSTATUS status;
    if (!NT_SUCCESS(acquired)) {
        return CompleteIrp(Irp, acquired, 0u);
    }
    status = DefaultDispatch(DeviceObject, Irp);
    IoReleaseRemoveLock(&g_removeLock, Irp);
    return status;
}

static NTSTATUS CleanupDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS acquired = IoAcquireRemoveLock(&g_removeLock, Irp);
    NTSTATUS status;
    if (!NT_SUCCESS(acquired)) {
        return CompleteIrp(Irp, acquired, 0u);
    }
    status = CleanupDispatch(DeviceObject, Irp);
    IoReleaseRemoveLock(&g_removeLock, Irp);
    return status;
}

static NTSTATUS CloseDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS acquired = IoAcquireRemoveLock(&g_removeLock, Irp);
    NTSTATUS status;
    if (!NT_SUCCESS(acquired)) {
        return CompleteIrp(Irp, acquired, 0u);
    }
    status = CloseDispatch(DeviceObject, Irp);
    IoReleaseRemoveLock(&g_removeLock, Irp);
    return status;
}

static NTSTATUS BridgeDispatchEntry(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS acquired = IoAcquireRemoveLock(&g_removeLock, Irp);
    NTSTATUS status;
    if (!NT_SUCCESS(acquired)) {
        return CompleteIrp(Irp, acquired, 0u);
    }
    status = BridgeDispatch(DeviceObject, Irp);
    IoReleaseRemoveLock(&g_removeLock, Irp);
    return status;
}
