#include "Runtime.h"
#include "../Imports/Lookup.h"
#include "../Reserve/Allocate.h"

/*
 * Phase 6 initialisation. Every substep writes a measured value into the
 * report. Nothing in this file states a design property as if it were an
 * observation: when a table is absent, the report says absent.
 *
 * User-mode ntdll routines are called through a user APC. The APC normal
 * routine is a stub in a private RX page owned by this phase; its arguments
 * are a job block in a second private RW page. No remote thread is created
 * and no loader-list entry is inserted.
 */

#define AMGER_PAGE_SIZE_4K        0x1000u
#define AMGER_MAX_TLS_CALLBACKS   16u
#define AMGER_MAX_JOBS            8u

/* EmitStub emits 21 bytes of prologue + 65 per job + 22 bytes of epilogue.
 * Size the emitter buffer from the same constants instead of a guessed 512. */

#define AMGER_STUB_PROLOGUE       21u
#define AMGER_STUB_PER_JOB        65u
#define AMGER_STUB_EPILOGUE       22u
#define AMGER_STUB_MAX            (AMGER_STUB_PROLOGUE + \
                                   (AMGER_STUB_PER_JOB * AMGER_MAX_JOBS) + \
                                   AMGER_STUB_EPILOGUE)
#define AMGER_APC_WAIT_MS         8000u
#define AMGER_MAX_NEW_THREADS     16u

#define AMGER_PEB_TLS_BITMAP      0x078u
#define AMGER_PEB_TLS_EXPANSION   0x238u
#define AMGER_TEB_TLS_POINTER     0x058u
#define AMGER_TLS_MINIMUM         64u
#define AMGER_TLS_EXPANSION_MAX   1024u
/* A private 4 KiB page holds 512 pointers; cap the usable index to that so
 * array + index*8 never writes past the page we install in the TEB. */

#define AMGER_TLS_INDEX_MAX       (AMGER_PAGE_SIZE_4K / sizeof(uint64_t))

#define AMGER_R25_RING            32u
#define AMGER_R25_MAX_PAGES       16u

#define AMGER_LC_SECURITY_COOKIE  0x058u
#define AMGER_LC_GUARD_CHECK      0x070u
#define AMGER_LC_GUARD_FLAGS      0x090u
#define AMGER_LC_MIN_SIZE         0x094u

#define AMGER_DIRECTORY_TLS       9u
#define AMGER_DIRECTORY_LOAD_CFG  10u
#define AMGER_DIRECTORY_EXCEPTION 3u
#define AMGER_DIRECTORY_RESOURCE  2u

/* Declarations omitted by the WDK headers but supplied by ntoskrnl.lib. */

NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID PsGetThreadTeb(PETHREAD Thread);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize);
NTKERNELAPI ULONG RtlRandomEx(PULONG Seed);
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
NTKERNELAPI HANDLE PsGetCurrentProcessId(VOID);
NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);
NTKERNELAPI BOOLEAN KeTestAlertThread(KPROCESSOR_MODE AlertMode);
NTKERNELAPI HANDLE PsGetThreadProcessId(PETHREAD Thread);

/* R25: a system-wide thread-notify callback. Its only safe job is enqueueing
 * an event and arming a passive-level work item; every user-memory access,
 * TLS-slot install and user-APC queue happens in that work item. */

typedef VOID (*AMGER_THREAD_NOTIFY_ROUTINE)(
    HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
NTKERNELAPI NTSTATUS PsSetCreateThreadNotifyRoutine(
    AMGER_THREAD_NOTIFY_ROUTINE Routine);
NTKERNELAPI NTSTATUS PsRemoveCreateThreadNotifyRoutine(
    AMGER_THREAD_NOTIFY_ROUTINE Routine);

typedef VOID (*AMGER_KERNEL_APC_ROUTINE)(
    struct _KAPC* Apc, PVOID* NormalRoutine, PVOID* NormalContext,
    PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef VOID (*AMGER_NORMAL_ROUTINE)(
    PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID (*AMGER_RUNADOWN_ROUTINE)(struct _KAPC* Apc);

typedef enum _AMGER_APC_ENVIRONMENT {
    AmgerOriginalApcEnvironment = 0
} AMGER_APC_ENVIRONMENT;

NTKERNELAPI VOID KeInitializeApc(
    PRKAPC Apc, PRKTHREAD Thread, AMGER_APC_ENVIRONMENT Environment,
    AMGER_KERNEL_APC_ROUTINE KernelRoutine,
    AMGER_RUNADOWN_ROUTINE RundownRoutine,
    AMGER_NORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode, PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(
    PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2,
    KPRIORITY Increment);

typedef struct _AMGER_JOB {
    uint64_t Function;
    uint64_t Arg1;
    uint64_t Arg2;
    uint64_t Arg3;
    uint64_t Result;
} AMGER_JOB, * PAMGER_JOB;

#define AMGER_JOB_BLOCK_SIZE   (8u + (AMGER_MAX_JOBS * sizeof(AMGER_JOB)) + 8u)
#define AMGER_COMPLETION_OFF   (8u + (AMGER_MAX_JOBS * sizeof(AMGER_JOB)))
#define AMGER_STUB_STARTED_OFF (AMGER_COMPLETION_OFF + 4u)
#define AMGER_STUB_STARTED_MARK 0x5A5AA5A5u

typedef struct _AMGER_RUNTIME_STATE {
    PEPROCESS Process;
    HANDLE ProcessId;
    uint64_t RemoteBase;
    const AMGER_PE_IMAGE* Image;
    PAMGER_INIT_REPORT Report;
    AMGER_LOOKUP_CONTEXT Lookup;

    uint64_t CodePage;
    uint64_t DataPage;
    uint32_t PageSize;

    uint64_t HookFunction;
    uint64_t HookStub;
    uint64_t HookTrampoline;
    UCHAR Original[13];
    BOOLEAN DetourStubsReady;
    BOOLEAN DetourInstalled;
    BOOLEAN LeaveCodePage;
    uint32_t PendingApcs;

    uint64_t NtdllBase;
    uint32_t NtdllSize;
    uint64_t RtlAddFunctionTable;

    uint64_t PdataRemote;
    uint32_t PdataEntries;
    uint32_t PdataJobIndex;
    BOOLEAN PdataQueued;

    uint64_t TlsCallbacks[AMGER_MAX_TLS_CALLBACKS];
    uint32_t TlsCallbackCount;
    uint64_t TlsRaw;
    uint32_t TlsRawBytes;
    uint64_t TlsIndexAddress;
    uint64_t TlsBitsAddress;
    uint32_t TlsBitsSize;
    uint32_t TlsIndexValue;
    BOOLEAN TlsIndexAllocated;

    uint32_t LoadConfigRva;
    uint32_t LoadConfigSize;
    uint32_t StructSize;
    uint32_t GuardFlags;
    uint64_t CfgCheckAddress;
    uint64_t CfgCheckPointerAddress;
    uint64_t CfgCheckBefore;
    BOOLEAN CfgCheckExternal;
    uint64_t CfgCheckAfter;
    uint64_t RetGadget;

    uint64_t TlsBlocks[AMGER_MAX_NEW_THREADS];
    uint64_t TlsArrays[AMGER_MAX_NEW_THREADS];
    uint64_t OriginalArrays[AMGER_MAX_NEW_THREADS];
    uint64_t TlsTebs[AMGER_MAX_NEW_THREADS];
    BOOLEAN TlsArrayReplaced[AMGER_MAX_NEW_THREADS];
    HANDLE TlsThreadIds[AMGER_MAX_NEW_THREADS];
    UCHAR* TlsTemplate;
    uint32_t TlsBlockCount;
    uint32_t ThreadsPatched;
    uint32_t ThreadCallbacks;
    uint32_t ApcRuns;
    uint32_t ApcFailures;
} AMGER_RUNTIME_STATE, * PAMGER_RUNTIME_STATE;

static AMGER_RUNTIME_STATE g_state;
/* Separate from g_state so RtlZeroMemory on entry cannot release a guard
 * held by an in-flight initialization. */

static volatile long g_initBusy = 0L;

typedef struct _AMGER_R25_EVENT {
    HANDLE ProcessId;
    HANDLE ThreadId;
    BOOLEAN Create;
} AMGER_R25_EVENT, * PAMGER_R25_EVENT;

typedef struct _AMGER_R25_STATE {
    volatile long Enabled;
    volatile long Gate;
    HANDLE ProcessId;
    PEPROCESS Process;
    AMGER_R25_EVENT Ring[AMGER_R25_RING];
    volatile long Head;
    volatile long Tail;
    WORK_QUEUE_ITEM WorkItem;
    BOOLEAN WorkItemReady;
    volatile long PendingApcs;
    uint64_t Codes[AMGER_R25_MAX_PAGES];
    uint64_t Datas[AMGER_R25_MAX_PAGES];
    uint64_t Blocks[AMGER_R25_MAX_PAGES];
    uint64_t Arrays[AMGER_R25_MAX_PAGES];
    uint64_t Tebs[AMGER_R25_MAX_PAGES];
    HANDLE Tids[AMGER_R25_MAX_PAGES];
    uint32_t PageCount;
    volatile long CreateSeen;
    volatile long DeleteSeen;
    volatile long Dropped;
    volatile long AttachQueued;
    volatile long AttachFailed;
    volatile long DetachObserved;
} AMGER_R25_STATE, * PAMGER_R25_STATE;

static AMGER_R25_STATE g_r25;

static NTSTATUS AllocatePrivatePage(PAMGER_RUNTIME_STATE state,
                                    uint64_t* out, ULONG protect);
static VOID ReleasePrivatePage(PAMGER_RUNTIME_STATE state, uint64_t* page);
static BOOLEAN WriteProtectedCode(PAMGER_RUNTIME_STATE state,
                                  uint64_t address, const VOID* data,
                                  SIZE_T length);

/* ------------------------------------------------------------------ */
/* Measured user memory access                                         */
/* ------------------------------------------------------------------ */

static BOOLEAN UserRead(PEPROCESS process, uint64_t address,
                        PVOID buffer, SIZE_T length) {
    SIZE_T done = 0u;
    if (process == NULL || address == 0u || buffer == NULL || length == 0u) {
        return FALSE;
    }
    return NT_SUCCESS(MmCopyVirtualMemory(
        process, (PVOID)(uintptr_t)address,
        PsGetCurrentProcess(), buffer,
        length, KernelMode, &done)) && done == length;
}

static BOOLEAN UserWrite(PEPROCESS process, uint64_t address,
                         const VOID* buffer, SIZE_T length) {
    SIZE_T done = 0u;
    if (process == NULL || address == 0u || buffer == NULL || length == 0u) {
        return FALSE;
    }
    return NT_SUCCESS(MmCopyVirtualMemory(
        PsGetCurrentProcess(), (PVOID)buffer,
        process, (PVOID)(uintptr_t)address,
        length, KernelMode, &done)) && done == length;
}

static NTSTATUS Fail(PAMGER_RUNTIME_STATE state, uint32_t stage,
                     NTSTATUS status) {
    state->Report->FailureStage = stage;
    state->Report->Status = (uint32_t)status;
    return status;
}

static uint64_t Remote(PAMGER_RUNTIME_STATE state, uint32_t rva) {
    return state->RemoteBase + (uint64_t)rva;
}

/* ------------------------------------------------------------------ */
/* R2 - resolve the ntdll routines Phase 6 actually calls              */
/* ------------------------------------------------------------------ */

static NTSTATUS ResolveRoutines(PAMGER_RUNTIME_STATE state) {
    AMGER_EXPORT_RESULT result;
    static const WCHAR ntdllName[] = L"ntdll.dll";
    KAPC_STATE apc;
    NTSTATUS status = STATUS_SUCCESS;

    /* LookupGetExport dereferences user addresses directly, so the caller
     * must be attached to the target for the whole resolution. */

    KeStackAttachProcess((PRKPROCESS)state->Process, &apc);

    if (!LookupFindModule(&state->Lookup, ntdllName, 9u,
                          &state->NtdllBase, &state->NtdllSize)) {
        status = STATUS_NOT_FOUND;
        goto done;
    }

    RtlZeroMemory(&result, sizeof(result));
    if (!NT_SUCCESS(LookupGetExport(state->NtdllBase, state->NtdllSize,
                                    "RtlAddFunctionTable", 0u, FALSE,
                                    &result)) ||
        result.Address == 0u || result.Forwarded) {
        status = STATUS_NOT_FOUND;
        goto done;
    }
    state->RtlAddFunctionTable = result.Address;

    /* RtlPcToFileHeader is the routine whose behaviour R23 changes. */

    RtlZeroMemory(&result, sizeof(result));
    if (!NT_SUCCESS(LookupGetExport(state->NtdllBase, state->NtdllSize,
                                    "RtlPcToFileHeader", 0u, FALSE,
                                    &result)) ||
        result.Address == 0u || result.Forwarded) {
        status = STATUS_NOT_FOUND;
        goto done;
    }
    state->HookFunction = result.Address;
    state->Report->RoutineCount = 2u;
    state->Report->RoutinesResolved = 2u;

done:
    KeUnstackDetachProcess(&apc);
    if (!NT_SUCCESS(status)) {
        return Fail(state, AMGER_INIT_STAGE_ROUTINES, status);
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* R12 / R26 / R19 - load config, cookie, CFG                          */
/* ------------------------------------------------------------------ */

static NTSTATUS ValidateLoadConfig(PAMGER_RUNTIME_STATE state) {
    AMGER_PE_DIRECTORY directory;
    UCHAR field[8];
    uint32_t offset;
    uint32_t size;
    uint64_t value;
    uint64_t rva;

    directory = state->Image->Directories[AMGER_DIRECTORY_LOAD_CFG];
    state->Report->LoadConfigRva = directory.Rva;
    state->Report->LoadConfigSize = directory.Size;
    if (directory.Rva == 0u || directory.Size < AMGER_LC_MIN_SIZE) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    if (!NT_SUCCESS(PeRvaToOffset(state->Image, directory.Rva,
                                  AMGER_LC_MIN_SIZE, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }

    state->Report->StructSize = 0u;
    if (!NT_SUCCESS(PeRvaToOffset(state->Image, directory.Rva, 4u, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    RtlCopyMemory(field, state->Image->Base + offset, 4u);
    size = (uint32_t)(field[0] | (field[1] << 8) |
                      ((uint32_t)field[2] << 16) | ((uint32_t)field[3] << 24));
    state->Report->StructSize = size;
    if (size < AMGER_LC_MIN_SIZE || size > directory.Size ||
        size > 0x400u ||
        !NT_SUCCESS(PeRvaToOffset(state->Image, directory.Rva, size, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }

    if (!NT_SUCCESS(PeRvaToOffset(
            state->Image, directory.Rva + AMGER_LC_GUARD_FLAGS,
            4u, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    RtlCopyMemory(field, state->Image->Base + offset, 4u);
    state->GuardFlags = (uint32_t)(field[0] | (field[1] << 8) |
                                  ((uint32_t)field[2] << 16) |
                                  ((uint32_t)field[3] << 24));
    state->Report->GuardFlags = state->GuardFlags;

    if (!NT_SUCCESS(PeRvaToOffset(
            state->Image, directory.Rva + AMGER_LC_SECURITY_COOKIE,
            8u, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    RtlCopyMemory(field, state->Image->Base + offset, 8u);
    value = 0u;
    for (size = 0u; size < 8u; ++size) {
        value |= ((uint64_t)field[size]) << (size * 8u);
    }
    if (value == 0u || value < state->Image->ImageBase ||
        value - state->Image->ImageBase >= state->Image->SizeOfImage) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    state->Report->CookieRva = (uint32_t)(value - state->Image->ImageBase);

    if (!NT_SUCCESS(PeRvaToOffset(
            state->Image, directory.Rva + AMGER_LC_GUARD_CHECK,
            8u, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_LOAD_CONFIG, STATUS_INVALID_PARAMETER);
    }
    RtlCopyMemory(field, state->Image->Base + offset, 8u);
    value = 0u;
    for (size = 0u; size < 8u; ++size) {
        value |= ((uint64_t)field[size]) << (size * 8u);
    }
    /* A zero GuardCFCheckFunctionPointer is the documented representation of
     * "no CFG check pointer in this image". It is a valid value: RetargetCfg
     * skips non-instrumented images and records the zero as CfgCheckBefore. */

    rva = value - state->Image->ImageBase;
    if (value < state->Image->ImageBase || rva >= state->Image->SizeOfImage) {
        /* On a CFG-instrumented image this field can hold the native address
         * of ntdll's guard dispatch routine rather than an image VA. Record
         * it as an external pointer; the relocation patch pass rewrites the
         * image copies of the old value. */

        state->CfgCheckExternal = TRUE;
    } else {
        state->CfgCheckExternal = FALSE;
    }
    state->CfgCheckAddress = Remote(state,
                                    directory.Rva + AMGER_LC_GUARD_CHECK);
    if (!state->CfgCheckExternal) {
        state->CfgCheckPointerAddress = Remote(state, (uint32_t)rva);
        state->CfgCheckBefore =
            value + (state->RemoteBase - state->Image->ImageBase);
    } else {
        state->CfgCheckPointerAddress = 0u;
        state->CfgCheckBefore = value;
    }
    state->Report->CfgCheckBefore = state->CfgCheckBefore;

    state->Report->Flags |= AMGER_INIT_FLAG_LOAD_CONFIG;
    return STATUS_SUCCESS;
}

static NTSTATUS InitCookie(PAMGER_RUNTIME_STATE state) {
    ULONG seed;
    uint64_t cookie;
    uint64_t complement;
    uint64_t where;
    uint64_t readBack;

    seed = (ULONG)(uintptr_t)&seed ^
           (ULONG)(uintptr_t)PsGetCurrentProcessId();
    seed ^= (ULONG)(state->RemoteBase >> 32u);
    cookie = ((uint64_t)RtlRandomEx(&seed) << 32u) |
             (uint64_t)RtlRandomEx(&seed);
    if (cookie == 0u || cookie == ~(uint64_t)0u) {
        cookie = 0x9E3779B97F4A7C15ull ^ state->RemoteBase;
    }
    complement = ~cookie;
    if (state->Image->SizeOfImage < 16u ||
        state->Report->CookieRva > state->Image->SizeOfImage - 16u) {
        return Fail(state, AMGER_INIT_STAGE_COOKIE, STATUS_INVALID_PARAMETER);
    }
    where = Remote(state, state->Report->CookieRva);

    if (!UserWrite(state->Process, where, &cookie, 8u) ||
        !UserWrite(state->Process, where + 8u, &complement, 8u) ||
        !UserRead(state->Process, where, &readBack, 8u)) {
        return Fail(state, AMGER_INIT_STAGE_COOKIE, STATUS_ACCESS_VIOLATION);
    }
    if (readBack != cookie) {
        return Fail(state, AMGER_INIT_STAGE_COOKIE, STATUS_UNSUCCESSFUL);
    }
    state->Report->CookieLow = (uint32_t)cookie;
    state->Report->Flags |= AMGER_INIT_FLAG_COOKIE;
    return STATUS_SUCCESS;
}

/* The loader creates an activation context for an ID-1/ID-2 RT_MANIFEST only
 * inside LoadLibrary, and stores it in the loader data entry. A manual map has
 * neither, and Phase 4 resolves imports without SxS binding, so activating a
 * manifest here would neither affect resolution nor reach the entry thread.
 * R6 is therefore implemented as a measured, bounded inventory of the actual
 * resource tree: presence, manifest ID, byte count and a content hash. No user
 * API is called and no target state is changed. */

static uint16_t ReadLe16Kernel(const UCHAR* bytes) {
    return (uint16_t)((uint16_t)bytes[0u] | ((uint16_t)bytes[1u] << 8u));
}

static uint32_t ReadLe32Kernel(const UCHAR* bytes) {
    return (uint32_t)bytes[0u] | ((uint32_t)bytes[1u] << 8u) |
           ((uint32_t)bytes[2u] << 16u) | ((uint32_t)bytes[3u] << 24u);
}

static uint32_t HashKernelBytes(const UCHAR* bytes, uint32_t length) {
    uint32_t hash = 2166136261u;
    uint32_t i;

    for (i = 0u; i < length; ++i) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

/* Reads one resource directory header. Every read goes through PeRvaToOffset
 * so no kernel dereference ever targets an unverified file offset. */

static BOOLEAN ReadResourceHeader(PAMGER_RUNTIME_STATE state, uint32_t rva,
                                  uint32_t* named, uint32_t* ids) {
    UCHAR header[16];
    uint32_t offset;

    if (!NT_SUCCESS(PeRvaToOffset(state->Image, rva, 16u, &offset))) {
        return FALSE;
    }
    RtlCopyMemory(header, state->Image->Base + offset, sizeof(header));
    *named = ReadLe16Kernel(header + 12u);
    *ids = ReadLe16Kernel(header + 14u);
    return TRUE;
}

/* Finds a resource entry by numeric ID and returns its raw OffsetToData field. */

static BOOLEAN FindResourceId(PAMGER_RUNTIME_STATE state, uint32_t directoryRva,
                              uint32_t wantedId, uint32_t* dataField) {
    uint32_t named = 0u;
    uint32_t ids = 0u;
    uint32_t i;
    uint32_t offset;
    UCHAR entry[8];

    if (!ReadResourceHeader(state, directoryRva, &named, &ids)) {
        return FALSE;
    }
    for (i = 0u; i < named + ids && i < 64u; ++i) {
        if (!NT_SUCCESS(PeRvaToOffset(state->Image,
                                      directoryRva + 16u + (i * 8u),
                                      8u, &offset))) {
            return FALSE;
        }
        RtlCopyMemory(entry, state->Image->Base + offset, sizeof(entry));
        if (ReadLe32Kernel(entry) == wantedId) {
            *dataField = ReadLe32Kernel(entry + 4u);
            return TRUE;
        }
    }
    return FALSE;
}

/* Returns the first ID-named child of a directory with its numeric ID. */

static BOOLEAN FindFirstResourceChild(PAMGER_RUNTIME_STATE state,
                                      uint32_t directoryRva, uint32_t* id,
                                      uint32_t* dataField) {
    uint32_t named = 0u;
    uint32_t ids = 0u;
    uint32_t i;
    uint32_t offset;
    UCHAR entry[8];
    uint32_t value;

    if (!ReadResourceHeader(state, directoryRva, &named, &ids)) {
        return FALSE;
    }
    for (i = 0u; i < named + ids && i < 64u; ++i) {
        if (!NT_SUCCESS(PeRvaToOffset(state->Image,
                                      directoryRva + 16u + (i * 8u),
                                      8u, &offset))) {
            return FALSE;
        }
        RtlCopyMemory(entry, state->Image->Base + offset, sizeof(entry));
        value = ReadLe32Kernel(entry);
        if ((value & 0x80000000u) == 0u) {
            *id = value;
            *dataField = ReadLe32Kernel(entry + 4u);
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS DetectActivation(PAMGER_RUNTIME_STATE state) {
    AMGER_PE_DIRECTORY resource =
        state->Image->Directories[AMGER_DIRECTORY_RESOURCE];
    uint32_t typeField = 0u;
    uint32_t nameField = 0u;
    uint32_t langField = 0u;
    uint32_t manifestId = 0u;
    uint32_t dataRva;
    uint32_t offset = 0u;
    uint32_t manifestRva;
    uint32_t manifestSize;
    UCHAR dataEntry[16];

    state->Report->ActivationStatus = (uint32_t)STATUS_NOT_FOUND;
    state->Report->ManifestState = AMGER_MANIFEST_ABSENT;
    state->Report->ManifestId = 0u;
    state->Report->ManifestBytes = 0u;
    state->Report->ManifestHash = 0u;

    if (resource.Rva == 0u || resource.Size == 0u) {
        return STATUS_SUCCESS;
    }
    if (!FindResourceId(state, resource.Rva, 24u, &typeField) ||
        (typeField & 0x80000000u) == 0u) {
        return STATUS_SUCCESS;
    }
    if (!FindFirstResourceChild(state,
                                resource.Rva + (typeField & 0x7FFFFFFFu),
                                &manifestId, &nameField) ||
        (nameField & 0x80000000u) == 0u) {
        state->Report->ManifestState = AMGER_MANIFEST_MALFORMED;
        state->Report->ActivationStatus = (uint32_t)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!FindFirstResourceChild(state,
                                resource.Rva + (nameField & 0x7FFFFFFFu),
                                &manifestId, &langField) ||
        (langField & 0x80000000u) != 0u) {
        state->Report->ManifestState = AMGER_MANIFEST_MALFORMED;
        state->Report->ActivationStatus = (uint32_t)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    dataRva = resource.Rva + langField;
    if (!NT_SUCCESS(PeRvaToOffset(state->Image, dataRva, 16u, &offset))) {
        state->Report->ManifestState = AMGER_MANIFEST_MALFORMED;
        state->Report->ActivationStatus = (uint32_t)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    RtlCopyMemory(dataEntry, state->Image->Base + offset, sizeof(dataEntry));
    manifestRva = ReadLe32Kernel(dataEntry);
    manifestSize = ReadLe32Kernel(dataEntry + 4u);
    if (manifestSize == 0u || manifestSize > 0x100000u ||
        manifestRva == 0u ||
        !NT_SUCCESS(PeRvaToOffset(state->Image, manifestRva,
                                  manifestSize, &offset))) {
        state->Report->ManifestBytes = manifestSize;
        state->Report->ManifestState = AMGER_MANIFEST_MALFORMED;
        state->Report->ActivationStatus = (uint32_t)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    state->Report->ManifestId = manifestId;
    state->Report->ManifestBytes = manifestSize;
    state->Report->ManifestHash =
        HashKernelBytes(state->Image->Base + offset, manifestSize);
    state->Report->ManifestState =
        manifestId == 1u ? AMGER_MANIFEST_ID1 :
        manifestId == 2u ? AMGER_MANIFEST_ID2 :
        manifestId == 3u ? AMGER_MANIFEST_ID3 : AMGER_MANIFEST_OTHER;
    state->Report->ActivationStatus = (uint32_t)STATUS_NOT_SUPPORTED;
    state->Report->Flags |= AMGER_INIT_FLAG_ACTIVATION;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* R1 / R5 - TLS index, data slots and the callback array              */
/* ------------------------------------------------------------------ */

static NTSTATUS InitTls(PAMGER_RUNTIME_STATE state) {
    AMGER_PE_DIRECTORY directory = state->Image->Directories[AMGER_DIRECTORY_TLS];
    UCHAR raw[40];
    UCHAR pointer[8];
    uint64_t start;
    uint64_t end;
    uint64_t callbacks;
    uint64_t indexAddress;
    uint64_t peb;
    uint64_t rtlBitmap;
    uint64_t bitmap;
    uint32_t bitmapSize;
    uint32_t offset;
    /* 32 dwords covers the 1024-bit expansion bitmap (128 bytes); this is far
     * below the 4 KiB stack buffer that previously exhausted the kernel stack. */

    uint32_t bits[AMGER_TLS_EXPANSION_MAX / 32u];
    uint32_t index;
    uint32_t bitPos;
    uint32_t i;

    if (directory.Rva == 0u || directory.Size < 40u ||
        !NT_SUCCESS(PeRvaToOffset(state->Image, directory.Rva, 40u, &offset))) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_NOT_FOUND);
    }
    RtlCopyMemory(raw, state->Image->Base + offset, sizeof(raw));
    start = 0u; end = 0u; callbacks = 0u; indexAddress = 0u;
    for (i = 0u; i < 8u; ++i) {
        start |= ((uint64_t)raw[i]) << (i * 8u);
        end |= ((uint64_t)raw[8u + i]) << (i * 8u);
        indexAddress |= ((uint64_t)raw[16u + i]) << (i * 8u);
        callbacks |= ((uint64_t)raw[24u + i]) << (i * 8u);
    }
    if (indexAddress < state->Image->ImageBase ||
        indexAddress - state->Image->ImageBase >= state->Image->SizeOfImage) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_INVALID_PARAMETER);
    }
    if (start == 0u || end <= start || start < state->Image->ImageBase ||
        end - state->Image->ImageBase > state->Image->SizeOfImage ||
        (uint32_t)(end - start) == 0u ||
        (uint32_t)(end - start) > AMGER_PAGE_SIZE_4K) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_INVALID_PARAMETER);
    }

    if (callbacks != 0u) {
        uint64_t callbacksRemote;
        if (callbacks < state->Image->ImageBase ||
            callbacks - state->Image->ImageBase >= state->Image->SizeOfImage) {
            return Fail(state, AMGER_INIT_STAGE_TLS_CALLBACK, STATUS_INVALID_PARAMETER);
        }
        callbacksRemote = Remote(state,
            (uint32_t)(callbacks - state->Image->ImageBase));
        for (i = 0u; i < AMGER_MAX_TLS_CALLBACKS; ++i) {
            if (!UserRead(state->Process,
                          callbacksRemote + ((uint64_t)i * 8u),
                          pointer, 8u)) {
                break;
            }
            {
                uint64_t address = 0u;
                uint32_t j;
                for (j = 0u; j < 8u; ++j) {
                    address |= ((uint64_t)pointer[j]) << (j * 8u);
                }
                if (address == 0u) {
                    break;
                }
                /* The array is read from the mapped image, so DIR64 fixups
                 * may already have converted entries to runtime addresses.
                 * Accept either form and normalize to a runtime address. */

                if (address >= state->RemoteBase &&
                    address - state->RemoteBase < state->Image->SizeOfImage) {
                    state->TlsCallbacks[i] = address;
                } else if (address >= state->Image->ImageBase &&
                    address - state->Image->ImageBase <
                        state->Image->SizeOfImage) {
                    state->TlsCallbacks[i] = state->RemoteBase +
                        (address - state->Image->ImageBase);
                } else {
                    return Fail(state, AMGER_INIT_STAGE_TLS_CALLBACK,
                                STATUS_INVALID_PARAMETER);
                }
            }
        }
        state->TlsCallbackCount = i;
        state->Report->TlsCallbackCount = i;
    }

    /* x64 PEB+0x78 is RTL_BITMAP* (Size at +0, Buffer at +8). When all 64
     * primary slots are used, Windows allocates from TlsExpansionBitmap at
     * PEB+0x238 (RTL_BITMAP*, 1024 bits), with real index = 64 + bit position.
     * This is the documented OS mechanism for an exhausted primary bitmap. */

    peb = (uint64_t)(uintptr_t)PsGetProcessPeb(state->Process);
    if (peb == 0u ||
        !UserRead(state->Process, peb + AMGER_PEB_TLS_BITMAP,
                  &rtlBitmap, sizeof(rtlBitmap))) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_INVALID_DEVICE_STATE);
    }
    if (rtlBitmap == 0u ||
        !UserRead(state->Process, rtlBitmap, &bitmapSize, sizeof(bitmapSize)) ||
        bitmapSize < AMGER_TLS_MINIMUM ||
        bitmapSize > AMGER_TLS_EXPANSION_MAX ||
        !UserRead(state->Process, rtlBitmap + 8u, &bitmap, sizeof(bitmap)) ||
        bitmap == 0u || bitmap >= 0x0000800000000000ull ||
        !UserRead(state->Process, bitmap, bits, (bitmapSize + 7u) / 8u)) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_INVALID_DEVICE_STATE);
    }
    state->Report->TlsBitmapSize = bitmapSize;
    state->Report->TlsBitmapBuffer = bitmap;
    state->Report->TlsBitmapBits0 = bits[0];
    state->Report->TlsBitmapBits1 = bits[1];

    bitPos = 0xFFFFFFFFu;
    for (i = 0u; i < 64u; ++i) {
        if ((bits[i >> 5u] & (1u << (i & 31u))) == 0u) {
            bitPos = i;
            break;
        }
    }

    if (bitPos == 0xFFFFFFFFu) {
        /* Primary exhausted: use PEB->TlsExpansionBitmap. */

        uint64_t expansion = 0u;
        uint64_t expansionBuffer = 0u;
        uint32_t expansionSize = 0u;

        if (!UserRead(state->Process, peb + AMGER_PEB_TLS_EXPANSION,
                      &expansion, sizeof(expansion)) ||
            expansion == 0u ||
            !UserRead(state->Process, expansion, &expansionSize,
                      sizeof(expansionSize)) ||
            expansionSize < AMGER_TLS_MINIMUM ||
            expansionSize > AMGER_TLS_EXPANSION_MAX ||
            !UserRead(state->Process, expansion + 8u, &expansionBuffer,
                      sizeof(expansionBuffer)) ||
            expansionBuffer == 0u ||
            expansionBuffer >= 0x0000800000000000ull) {
            return Fail(state, AMGER_INIT_STAGE_TLS_INDEX,
                        STATUS_NOT_SUPPORTED);
        }
        RtlZeroMemory(bits, sizeof(bits));
        if (!UserRead(state->Process, expansionBuffer, bits,
                      (expansionSize + 7u) / 8u)) {
            return Fail(state, AMGER_INIT_STAGE_TLS_INDEX,
                        STATUS_INVALID_DEVICE_STATE);
        }
        state->Report->TlsBitmapSize = expansionSize;
        state->Report->TlsBitmapBuffer = expansionBuffer;
        state->Report->TlsBitmapBits0 = bits[0];
        state->Report->TlsBitmapBits1 = bits[1];
        state->TlsBitsSize = (expansionSize + 7u) / 8u;

        bitPos = 0xFFFFFFFFu;
        for (i = 0u; i < expansionSize && i < AMGER_TLS_EXPANSION_MAX; ++i) {
            /* Leave any index whose slot would exceed our private page. */

            if (AMGER_TLS_MINIMUM + i >= AMGER_TLS_INDEX_MAX) {
                break;
            }
            if ((bits[i >> 5u] & (1u << (i & 31u))) == 0u) {
                bitPos = i;
                bitmap = expansionBuffer;
                break;
            }
        }
        if (bitPos == 0xFFFFFFFFu) {
            return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_NOT_SUPPORTED);
        }
        index = AMGER_TLS_MINIMUM + bitPos;
    } else {
        index = bitPos;
        state->TlsBitsSize = (bitmapSize + 7u) / 8u;
    }
    bits[bitPos >> 5u] |= 1u << (bitPos & 31u);
    state->TlsBitsAddress = bitmap;

    /* COW-honoring write through the memory manager, then read back. */

    if (!WriteProtectedCode(state, bitmap, bits, state->TlsBitsSize)) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_ACCESS_VIOLATION);
    }
    /* Claim the bit for rollback as soon as the write succeeds. A failed
     * read-back below still has to clear it, otherwise the target's PEB keeps
     * a reserved TLS slot with no matching TEB data. */
    state->TlsIndexValue = index;
    state->TlsIndexAllocated = TRUE;
    {
        uint32_t verify[AMGER_TLS_EXPANSION_MAX / 32u];
        RtlZeroMemory(verify, sizeof(verify));
        if (!UserRead(state->Process, bitmap, verify, state->TlsBitsSize) ||
            RtlCompareMemory(verify, bits, state->TlsBitsSize) != state->TlsBitsSize) {
            return Fail(state, AMGER_INIT_STAGE_TLS_INDEX,
                        STATUS_ACCESS_VIOLATION);
        }
    }
    state->TlsIndexAddress = Remote(state,
        (uint32_t)(indexAddress - state->Image->ImageBase));
    state->TlsRaw = Remote(state, (uint32_t)(start - state->Image->ImageBase));
    state->TlsRawBytes = (uint32_t)(end - start);
    state->Report->TlsIndex = index;
    state->Report->TlsRawBytes = state->TlsRawBytes;
    state->Report->Flags |= AMGER_INIT_FLAG_TLS_INDEX;

    if (!UserWrite(state->Process, state->TlsIndexAddress,
                   &index, sizeof(index))) {
        return Fail(state, AMGER_INIT_STAGE_TLS_INDEX, STATUS_ACCESS_VIOLATION);
    }
    return STATUS_SUCCESS;
}

/* Gives every current thread of the target a private copy of the image's TLS
 * template and stores it in its ThreadLocalStoragePointer slot. A primary
 * index (<64) fits the array Windows already provides. An expansion index
 * (>=64) needs a larger array, so a private 512-pointer page is installed in
 * the TEB and the existing slots are copied into it. */

static NTSTATUS PatchThreadSlots(PAMGER_RUNTIME_STATE state) {
    ULONG size = 0x10000u;
    PVOID buffer = NULL;
    NTSTATUS status;
    UCHAR* cursor;
    PETHREAD thread;
    PVOID teb;
    uint64_t array;
    uint64_t block;
    uint32_t count;
    uint32_t i;
    uint32_t index;
    uint32_t attempts;
    BOOLEAN found = FALSE;

    if (state->TlsIndexValue >= AMGER_TLS_INDEX_MAX ||
        state->TlsRawBytes == 0u) {
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, STATUS_NOT_SUPPORTED);
    }
#pragma warning(suppress : 4996)
    state->TlsTemplate = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPoolNx, state->TlsRawBytes, 'grmD');
    if (state->TlsTemplate == NULL) {
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS,
                    STATUS_INSUFFICIENT_RESOURCES);
    }
    if (!UserRead(state->Process, state->TlsRaw,
                  state->TlsTemplate, state->TlsRawBytes)) {
        ExFreePoolWithTag(state->TlsTemplate, 'grmD');
        state->TlsTemplate = NULL;
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, STATUS_ACCESS_VIOLATION);
    }

    for (attempts = 0u;; ++attempts) {
        LARGE_INTEGER interval;
#pragma warning(suppress : 4996)
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, size, 'grmT');
        if (buffer == NULL) {
            ExFreePoolWithTag(state->TlsTemplate, 'grmD');
            state->TlsTemplate = NULL;
            return Fail(state, AMGER_INIT_STAGE_THREAD_TLS,
                        STATUS_INSUFFICIENT_RESOURCES);
        }
        status = ZwQuerySystemInformation(5, buffer, size, &size);
        if (NT_SUCCESS(status)) break;
        ExFreePoolWithTag(buffer, 'grmT');
        buffer = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(state->TlsTemplate, 'grmD');
            state->TlsTemplate = NULL;
            return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, status);
        }
        size *= 2u;
        /* Retry a transient length race a bounded number of times. */

        if (attempts >= 4u) {
            ExFreePoolWithTag(state->TlsTemplate, 'grmD');
            state->TlsTemplate = NULL;
            return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, STATUS_RETRY);
        }
        interval.QuadPart = -10000LL; /* 1 ms */
        (void)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    cursor = (UCHAR*)buffer;
    for (;;) {
        ULONG next = *(ULONG*)cursor;
        count = *(ULONG*)(cursor + 4u);
        if (*(HANDLE*)(cursor + 0x50u) == state->ProcessId) {
            found = TRUE;
            UCHAR* threads = cursor + 0x100u;
            for (i = 0u; i < count && state->TlsBlockCount < AMGER_MAX_NEW_THREADS;
                 ++i) {
                UCHAR* entry = threads + (i * 0x50u);
                HANDLE tid = *(HANDLE*)(entry + 0x30u);
                if (tid == NULL ||
                    !NT_SUCCESS(PsLookupThreadByThreadId(tid, &thread))) {
                    state->Report->TlsThreadSkipMask |= 0x1u;
                    continue;
                }
                teb = PsGetThreadTeb(thread);
                ObDereferenceObject(thread);
                if (teb == NULL ||
                    !UserRead(state->Process,
                              (uint64_t)(uintptr_t)teb + AMGER_TEB_TLS_POINTER,
                              &array, sizeof(array))) {
                    state->Report->TlsThreadSkipMask |= 0x2u;
                    continue;
                }
                {
                    uint64_t originalArray = array;
                    BOOLEAN replaced = FALSE;
                    uint32_t needSlots = state->TlsIndexValue + 1u;

                    /* The array must hold at least needSlots pointers. Windows
                     * expands it lazily for index >= 64; a private page holds
                     * 512 pointers, enough for any expansion index we pick. */

                    if (array == 0u ||
                        (needSlots > AMGER_TLS_MINIMUM && array != 0u)) {
                        uint64_t fresh = 0u;
                        if (!NT_SUCCESS(AllocatePrivatePage(state, &fresh,
                                                            PAGE_READWRITE))) {
                            state->Report->TlsThreadSkipMask |= 0x4u;
                            continue;
                        }
                        if (array != 0u) {
                            /* Preserve every existing slot below our index.
                             * We claim the first free expansion bit, so all
                             * other in-use indices are lower and must survive
                             * the array replacement. needSlots is at most
                             * AMGER_TLS_INDEX_MAX, so keep never exceeds the
                             * 512-pointer page we install. */

                            uint32_t keep = needSlots * 8u;
                            UCHAR* copy;
#pragma warning(suppress : 4996)
                            copy = (UCHAR*)ExAllocatePoolWithTag(
                                NonPagedPoolNx, keep, 'grmC');
                            if (copy != NULL) {
                                if (UserRead(state->Process, array, copy, keep)) {
                                    (void)UserWrite(state->Process, fresh,
                                                    copy, keep);
                                }
                                ExFreePoolWithTag(copy, 'grmC');
                            }
                        }
                        if (!UserWrite(state->Process,
                                       (uint64_t)(uintptr_t)teb +
                                           AMGER_TEB_TLS_POINTER,
                                       &fresh, sizeof(fresh))) {
                            state->Report->TlsThreadSkipMask |= 0x8u;
                            ReleasePrivatePage(state, &fresh);
                            continue;
                        }
                        array = fresh;
                        replaced = TRUE;
                    }

                    if (!NT_SUCCESS(AllocatePrivatePage(state, &block,
                                                        PAGE_READWRITE))) {
                        state->Report->TlsThreadSkipMask |= 0x10u;
                        if (replaced) {
                            (void)UserWrite(state->Process,
                                (uint64_t)(uintptr_t)teb +
                                    AMGER_TEB_TLS_POINTER,
                                &originalArray, sizeof(originalArray));
                            ReleasePrivatePage(state, &array);
                        }
                        continue;
                    }
                    if (!UserWrite(state->Process, block, state->TlsTemplate,
                                   state->TlsRawBytes) ||
                        !UserWrite(state->Process,
                                   array + ((uint64_t)state->TlsIndexValue * 8u),
                                   &block, sizeof(block))) {
                        state->Report->TlsThreadSkipMask |= 0x20u;
                        ReleasePrivatePage(state, &block);
                        if (replaced) {
                            (void)UserWrite(state->Process,
                                (uint64_t)(uintptr_t)teb +
                                    AMGER_TEB_TLS_POINTER,
                                &originalArray, sizeof(originalArray));
                            ReleasePrivatePage(state, &array);
                        }
                        continue;
                    }
                    state->OriginalArrays[state->TlsBlockCount] = originalArray;
                    state->TlsBlocks[state->TlsBlockCount] = block;
                    state->TlsArrays[state->TlsBlockCount] = array;
                    state->TlsArrayReplaced[state->TlsBlockCount] = replaced;
                    state->TlsTebs[state->TlsBlockCount] =
                        (uint64_t)(uintptr_t)teb;
                    state->TlsThreadIds[state->TlsBlockCount] = tid;
                    ++state->TlsBlockCount;
                }
            }
            break;
        }
        if (next == 0u) break;
        cursor += next;
    }

    ExFreePoolWithTag(buffer, 'grmT');
    state->Report->TlsSnapshotCount = count;
    if (!found) {
        state->Report->TlsThreadSkipMask |= 0x40u; /* process not in snapshot */
    }
    index = state->TlsBlockCount;
    state->ThreadsPatched = index;
    state->Report->ThreadsPatched = index;
    if (index == 0u) {
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, STATUS_NOT_FOUND);
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Private pages, user APC stub and job execution                     */
/* ------------------------------------------------------------------ */

static NTSTATUS AllocatePrivatePage(PAMGER_RUNTIME_STATE state,
                                    uint64_t* out, ULONG protect) {
    PVOID base = NULL;
    SIZE_T size = AMGER_PAGE_SIZE_4K;
    KAPC_STATE apc;
    NTSTATUS status;

    KeStackAttachProcess((PRKPROCESS)state->Process, &apc);
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0u,
                                     &size, MEM_COMMIT, protect);
    KeUnstackDetachProcess(&apc);
    if (!NT_SUCCESS(status) || base == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    *out = (uint64_t)(uintptr_t)base;
    return STATUS_SUCCESS;
}

static VOID ApcKernelRoutine(struct _KAPC* apc,
                             PVOID* normalRoutine, PVOID* normalContext,
                             PVOID* argument1, PVOID* argument2) {
    UNREFERENCED_PARAMETER(normalRoutine);
    UNREFERENCED_PARAMETER(normalContext);
    UNREFERENCED_PARAMETER(argument1);
    UNREFERENCED_PARAMETER(argument2);
    InterlockedDecrement((volatile long*)&g_state.PendingApcs);
    ExFreePool(apc);
}

static VOID ApcRundownRoutine(struct _KAPC* apc) {
    InterlockedDecrement((volatile long*)&g_state.PendingApcs);
    ExFreePool(apc);
}

/* A user APC is delivered only when the target thread returns to user mode
 * with UserApcPending set. Queuing it is not enough when the thread waits in
 * KernelMode (typical for a GUI message loop): KiSignalThreadForApc refuses to
 * "unwait" such a thread. A special kernel APC is delivered immediately and
 * runs its KernelRoutine in the target thread's context, where
 * KeTestAlertThread(UserMode) sets UserApcPending for the queued user APC. */

static VOID AlertBoosterKernelRoutine(
    struct _KAPC* apc, PVOID* normalRoutine, PVOID* normalContext,
    PVOID* argument1, PVOID* argument2) {
    UNREFERENCED_PARAMETER(normalRoutine);
    UNREFERENCED_PARAMETER(normalContext);
    UNREFERENCED_PARAMETER(argument1);
    UNREFERENCED_PARAMETER(argument2);
    (VOID)KeTestAlertThread(UserMode);
    ExFreePool(apc);
}

static VOID AlertBoosterRundownRoutine(struct _KAPC* apc) {
    ExFreePool(apc);
}

/* Allocates and queues one special kernel APC that forces user-APC delivery.
 * Ownership of the KAPC transfers to the kernel/rundown routine. */

static BOOLEAN QueueAlertBooster(PETHREAD thread) {
    PRKAPC apc;

#pragma warning(suppress : 4996 28197)
    apc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAPC), 'grmP');
    if (apc == NULL) {
        return FALSE;
    }
    KeInitializeApc(apc, (PRKTHREAD)thread, AmgerOriginalApcEnvironment,
                    AlertBoosterKernelRoutine, AlertBoosterRundownRoutine,
                    NULL, KernelMode, NULL);
    if (!KeInsertQueueApc(apc, NULL, NULL, 0)) {
        ExFreePoolWithTag(apc, 'grmP');
        return FALSE;
    }
    return TRUE;
}

/* Emits a generic call stub. Job i is called with three register arguments;
 * the result is written back into the job block and a completion dword is
 * published last so the kernel can observe a finished run without racing. */

static VOID EmitDisp32(UCHAR* code, uint32_t* used, uint32_t value) {
    code[(*used)++] = (UCHAR)(value & 0xFFu);
    code[(*used)++] = (UCHAR)((value >> 8u) & 0xFFu);
    code[(*used)++] = (UCHAR)((value >> 16u) & 0xFFu);
    code[(*used)++] = (UCHAR)((value >> 24u) & 0xFFu);
}

static VOID EmitMovR10(UCHAR* code, uint32_t* used, uint64_t block) {
    uint32_t j;
    code[(*used)++] = 0x49u; code[(*used)++] = 0xBAu;
    for (j = 0u; j < 8u; ++j) {
        code[(*used)++] = (UCHAR)(block >> (j * 8u));
    }
}

static VOID EmitStub(UCHAR* code, uint64_t block, uint32_t count) {
    uint32_t used = 0u;
    uint32_t i;
    uint32_t base;

    /* Publish a marker before any job runs. A completion timeout can then be
     * classified: marker absent means the APC was never delivered, marker
     * present but completion absent means the stub ran and a job faulted. */

    EmitMovR10(code, &used, block);
    code[used++] = 0x41u; code[used++] = 0xC7u; code[used++] = 0x82u;
    EmitDisp32(code, &used, AMGER_STUB_STARTED_OFF);
    code[used++] = (UCHAR)(AMGER_STUB_STARTED_MARK & 0xFFu);
    code[used++] = (UCHAR)((AMGER_STUB_STARTED_MARK >> 8u) & 0xFFu);
    code[used++] = (UCHAR)((AMGER_STUB_STARTED_MARK >> 16u) & 0xFFu);
    code[used++] = (UCHAR)((AMGER_STUB_STARTED_MARK >> 24u) & 0xFFu);

    for (i = 0u; i < count; ++i) {
        base = 8u + (i * (uint32_t)sizeof(AMGER_JOB));

        /* r10 is volatile; reload before every call. */

        EmitMovR10(code, &used, block);

        /* AMGER_JOB: Function@+0, Arg1@+8, Arg2@+16, Arg3@+24, Result@+32 */

        code[used++] = 0x49u; code[used++] = 0x8Bu; code[used++] = 0x8Au;
        EmitDisp32(code, &used, base + 8u);   /* arg1 -> rcx */
        code[used++] = 0x49u; code[used++] = 0x8Bu; code[used++] = 0x92u;
        EmitDisp32(code, &used, base + 16u);  /* arg2 -> rdx */
        code[used++] = 0x4Du; code[used++] = 0x8Bu; code[used++] = 0x82u;
        EmitDisp32(code, &used, base + 24u);  /* arg3 -> r8 */
        code[used++] = 0x49u; code[used++] = 0x8Bu; code[used++] = 0x82u;
        EmitDisp32(code, &used, base);        /* function -> rax */

        code[used++] = 0x48u; code[used++] = 0x83u;
        code[used++] = 0xECu; code[used++] = 0x28u;
        code[used++] = 0xFFu; code[used++] = 0xD0u;
        code[used++] = 0x48u; code[used++] = 0x83u;
        code[used++] = 0xC4u; code[used++] = 0x28u;

        /* r10 was clobbered by the call; reload before storing the result. */

        EmitMovR10(code, &used, block);
        code[used++] = 0x49u; code[used++] = 0x89u; code[used++] = 0x82u;
        EmitDisp32(code, &used, base + 32u);  /* result */
    }

    EmitMovR10(code, &used, block);
    code[used++] = 0x41u; code[used++] = 0xC7u; code[used++] = 0x82u;
    EmitDisp32(code, &used, AMGER_COMPLETION_OFF);
    code[used++] = 1u; code[used++] = 0u; code[used++] = 0u;
    code[used++] = 0u;
    code[used++] = 0xC3u; /* ret */
}

static NTSTATUS FindThread(PAMGER_RUNTIME_STATE state, PETHREAD* out) {
    ULONG size = 0x10000u;
    PVOID buffer = NULL;
    NTSTATUS status;
    UCHAR* cursor;
    ULONG count;
    ULONG i;
    HANDLE tid = NULL;
    uint32_t attempts = 0u;

    /* Match the bounded growth used by PatchThreadSlots: a malformed size
     * sequence must not grow the buffer without limit. */

    for (;;) {
#pragma warning(suppress : 4996)
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, size, 'grmT');
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = ZwQuerySystemInformation(5, buffer, size, &size);
        if (NT_SUCCESS(status)) {
            break;
        }
        ExFreePoolWithTag(buffer, 'grmT');
        buffer = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return status;
        }
        if (++attempts >= 4u || size > 0x1000000u) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        size *= 2u;
    }

    cursor = (UCHAR*)buffer;
    for (;;) {
        ULONG next = *(ULONG*)cursor;
        count = *(ULONG*)(cursor + 4u);
        if (*(HANDLE*)(cursor + 0x50u) == state->ProcessId) {
            UCHAR* threads = cursor + 0x100u;
            /* A user APC is delivered when the target thread transitions back
             * to user mode. A thread already executing user code (Running) does
             * not re-check its user-APC queue until its next kernel transition,
             * so it can leave the APC pending for the whole bounded wait. A
             * thread in an alertable wait (typically state 5, Waiting) delivers
             * the APC as soon as it is queued. Prefer that class, then fall back
             * to Ready and Running. This matches the "prefer prompt queue
             * waits" wakeability rule used by the execution phase. */

            /* Best case: a thread blocked in a user request wait (WaitReason 8
             * UserRequest / 9 WrUserRequest). Such a wait is normally UserMode
             * with a message-pump return path, so a pending user APC is
             * delivered promptly. WaitReason lives at +0x48 of each 0x50-byte
             * SYSTEM_THREAD_INFORMATION entry. */

            for (i = 0u; i < count && tid == NULL; ++i) {
                UCHAR* thread = threads + (i * 0x50u);
                ULONG waitReason = *(ULONG*)(thread + 0x48u);
                if (*(ULONG*)(thread + 0x44u) == 5u &&
                    (waitReason == 8u || waitReason == 9u) &&
                    *(HANDLE*)(thread + 0x30u) != NULL) {
                    tid = *(HANDLE*)(thread + 0x30u);
                }
            }
            for (i = 0u; i < count && tid == NULL; ++i) {
                UCHAR* thread = threads + (i * 0x50u);
                if (*(ULONG*)(thread + 0x44u) == 5u &&
                    *(HANDLE*)(thread + 0x30u) != NULL) {
                    tid = *(HANDLE*)(thread + 0x30u);
                }
            }
            for (i = 0u; i < count && tid == NULL; ++i) {
                UCHAR* thread = threads + (i * 0x50u);
                if (*(ULONG*)(thread + 0x44u) == 1u &&
                    *(HANDLE*)(thread + 0x30u) != NULL) {
                    tid = *(HANDLE*)(thread + 0x30u);
                }
            }
            for (i = 0u; i < count && tid == NULL; ++i) {
                UCHAR* thread = threads + (i * 0x50u);
                if (*(ULONG*)(thread + 0x44u) == 2u &&
                    *(HANDLE*)(thread + 0x30u) != NULL) {
                    tid = *(HANDLE*)(thread + 0x30u);
                }
            }
            break;
        }
        if (next == 0u) {
            break;
        }
        cursor += next;
    }

    if (tid == NULL) {
        ExFreePoolWithTag(buffer, 'grmT');
        return STATUS_NOT_FOUND;
    }
    status = PsLookupThreadByThreadId(tid, out);
    ExFreePoolWithTag(buffer, 'grmT');
    return status;
}

/* Writes the job block and generic stub while the code page is still RW. */

static NTSTATUS PrepareApcStub(PAMGER_RUNTIME_STATE state, AMGER_JOB* jobs,
                               uint32_t count, uint64_t* outStub) {
    UCHAR code[AMGER_STUB_MAX];
    UCHAR block[AMGER_JOB_BLOCK_SIZE];

    if (count == 0u || count > AMGER_MAX_JOBS) {
        return Fail(state, AMGER_INIT_STAGE_APC, STATUS_INVALID_PARAMETER);
    }
    RtlZeroMemory(block, sizeof(block));
    *(uint64_t*)block = count;
    RtlCopyMemory(block + 8u, jobs, count * sizeof(AMGER_JOB));
    RtlZeroMemory(code, sizeof(code));
    EmitStub(code, state->DataPage, count);

    if (!UserWrite(state->Process, state->DataPage, block, sizeof(block)) ||
        !UserWrite(state->Process, state->CodePage, code, sizeof(code))) {
        return Fail(state, AMGER_INIT_STAGE_APC, STATUS_ACCESS_VIOLATION);
    }
    if (outStub != NULL) {
        *outStub = state->CodePage;
    }
    return STATUS_SUCCESS;
}

/* Single RW -> RX promotion. Called after every private stub is written and
 * before any detour or APC can make the page executable to other threads. */

static NTSTATUS PromoteCodePage(PAMGER_RUNTIME_STATE state) {
    KAPC_STATE apcState;
    SIZE_T pageSize = AMGER_PAGE_SIZE_4K;
    ULONG oldProtect = 0u;
    PVOID base = (PVOID)(uintptr_t)state->CodePage;
    NTSTATUS status;

    /* ZwProtectVirtualMemory writes the rounded base back through its input
     * pointer. Use a local so state->CodePage (and every stub address derived
     * from it earlier) cannot be altered by the call. */

    KeStackAttachProcess((PRKPROCESS)state->Process, &apcState);
    status = ZwProtectVirtualMemory(ZwCurrentProcess(),
        &base, &pageSize, PAGE_EXECUTE_READ, &oldProtect);
    KeUnstackDetachProcess(&apcState);
    if (!NT_SUCCESS(status)) {
        return Fail(state, AMGER_INIT_STAGE_APC, status);
    }
    return STATUS_SUCCESS;
}

/* The APC calls TLS callbacks inside the image. Until SectionsSeal runs the
 * whole mapping is RW, so those code pages are non-executable and the
 * callback would fault before writing the completion dword. Promote only
 * EXECUTE sections to RX now; SectionsSeal re-applies the same protection
 * later as a harmless no-op. */

#define AMGER_IMAGE_SCN_MEM_EXECUTE 0x20000000u
static NTSTATUS PromoteImageCode(PAMGER_RUNTIME_STATE state) {
    KAPC_STATE apcState;
    uint16_t index;

    KeStackAttachProcess((PRKPROCESS)state->Process, &apcState);
    for (index = 0u; index < state->Image->NumberOfSections; ++index) {
        const AMGER_PE_SECTION* section = &state->Image->Sections[index];
        PVOID base;
        SIZE_T size;
        ULONG old = 0u;
        NTSTATUS status;

        if ((section->Characteristics & AMGER_IMAGE_SCN_MEM_EXECUTE) == 0u ||
            section->VirtualSize == 0u) {
            continue;
        }
        base = (PVOID)(uintptr_t)Remote(state, section->VirtualAddress);
        size = section->VirtualSize;
        status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size,
                                        PAGE_EXECUTE_READ, &old);
        if (!NT_SUCCESS(status)) {
            KeUnstackDetachProcess(&apcState);
            return Fail(state, AMGER_INIT_STAGE_APC, status);
        }
    }
    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}

static NTSTATUS RunJobs(PAMGER_RUNTIME_STATE state) {
    PRKAPC apc;
    PETHREAD thread = NULL;
    NTSTATUS status;
    uint32_t attempt;
    uint32_t tail[2];
    uint32_t boosters = 0u;
    uint32_t completion = 0u;
    uint32_t started = 0u;
    uint32_t slot;

    tail[0] = 0u;
    tail[1] = 0u;

    /* Prefer a thread whose TEB TLS slot we actually populated: the TLS
     * callback dereferences ThreadLocalStoragePointer[index], so queueing to
     * an unpatched thread would fault in user mode and never write completion.
     * Fall back to the wakeability-ranked FindThread only if none resolve. */

    status = STATUS_NOT_FOUND;
    for (slot = 0u; slot < state->TlsBlockCount && !NT_SUCCESS(status); ++slot) {
        if (state->TlsThreadIds[slot] != NULL) {
            status = PsLookupThreadByThreadId(state->TlsThreadIds[slot], &thread);
        }
    }
    if (!NT_SUCCESS(status)) {
        status = FindThread(state, &thread);
    }
    if (!NT_SUCCESS(status)) {
        return Fail(state, AMGER_INIT_STAGE_APC, status);
    }

/* Ownership transfers to the APC kernel/rundown routines, which free it. */

#pragma warning(suppress : 4996 28197)
    apc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAPC), 'grmP');
    if (apc == NULL) {
        ObDereferenceObject(thread);
        return Fail(state, AMGER_INIT_STAGE_APC, STATUS_INSUFFICIENT_RESOURCES);
    }
    KeInitializeApc(apc, (PRKTHREAD)thread, AmgerOriginalApcEnvironment,
                    ApcKernelRoutine, ApcRundownRoutine,
                    (AMGER_NORMAL_ROUTINE)(uintptr_t)state->CodePage,
                    UserMode, (PVOID)(uintptr_t)state->DataPage);

    InterlockedIncrement((volatile long*)&state->PendingApcs);
    if (!KeInsertQueueApc(apc, NULL, NULL, 0)) {
        InterlockedDecrement((volatile long*)&state->PendingApcs);
        ExFreePoolWithTag(apc, 'grmP');
        ObDereferenceObject(thread);
        return Fail(state, AMGER_INIT_STAGE_APC, STATUS_UNSUCCESSFUL);
    }

    /* Kick delivery immediately, then re-kick every 250 ms while polling. Each
     * booster is a special kernel APC freed by its own kernel/rundown routine. */

    if (QueueAlertBooster(thread)) {
        ++boosters;
    }
    for (attempt = 0u; attempt < (AMGER_APC_WAIT_MS / 2u); ++attempt) {
        LARGE_INTEGER interval;
        interval.QuadPart = -20000LL; /* 2 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if ((attempt % 125u) == 124u) {
            if (QueueAlertBooster(thread)) {
                ++boosters;
            }
        }
        if (!UserRead(state->Process, state->DataPage + AMGER_COMPLETION_OFF,
                      tail, sizeof(tail))) {
            break;
        }
        completion = tail[0];
        started = tail[1];
        if (completion == 1u) {
            break;
        }
    }
    ObDereferenceObject(thread);

    state->Report->ApcStubStarted =
        (started == AMGER_STUB_STARTED_MARK) ? 1u : 0u;
    state->Report->ApcCompletionValue = completion;
    state->Report->ApcBoosters = boosters;

    if (completion != 1u) {
        ++state->ApcFailures;
        state->Report->ApcFailures = state->ApcFailures;
        /* The APC may still be delivered later. Keep its code page alive. */

        state->LeaveCodePage = TRUE;
        /* STATUS_TIMEOUT is 0x00000102, which NT_SUCCESS() treats as success.
         * Use a real error so the failure cannot be swallowed by callers. */

        return Fail(state, AMGER_INIT_STAGE_APC, STATUS_UNSUCCESSFUL);
    }
    /* PendingApcs is decremented by the APC kernel/rundown routine, not here:
     * a completed NormalRoutine does not mean the APC object has been reclaimed. */

    ++state->ApcRuns;
    state->Report->ApcRuns = state->ApcRuns;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* R23 - detour ntdll!RtlPcToFileHeader with validated prologue bytes    */
/* ------------------------------------------------------------------ */

/* Emits only the private stub and trampoline. Called while the code page is
 * still writable; the ntdll jump is not written until the page is RX, so no
 * thread can execute a DEP-faulting RW stub. */

static NTSTATUS EmitDetourStubs(PAMGER_RUNTIME_STATE state) {
    static const UCHAR expected[9] = {
        0x40u, 0x53u, 0x48u, 0x83u, 0xECu, 0x40u, 0x4Cu, 0x8Bu, 0x05u
    };
    UCHAR stub[128];
    UCHAR original[13];
    uint32_t used = 0u;
    uint32_t i;
    int32_t originalDisp;
    int32_t newDisp;
    int32_t relative;
    uint64_t absolute;
    uint64_t hookStub;
    uint64_t trampoline;

    if (state->HookFunction == 0u || state->CodePage == 0u) {
        return Fail(state, AMGER_INIT_STAGE_PC_DETOUR, STATUS_INVALID_PARAMETER);
    }
    if (!UserRead(state->Process, state->HookFunction, original, 13u)) {
        return Fail(state, AMGER_INIT_STAGE_PC_DETOUR,
                    STATUS_INVALID_PARAMETER);
    }
    for (i = 0u; i < 9u; ++i) {
        if (original[i] != expected[i]) {
            return Fail(state, AMGER_INIT_STAGE_PC_DETOUR, STATUS_NOT_SUPPORTED);
        }
    }
    RtlCopyMemory(state->Original, original, sizeof(state->Original));

    hookStub = state->CodePage + 0x400u;
    trampoline = state->CodePage + 0x500u;

    /* Replicate the overwritten prologue, check [base, base+SizeOfImage),
     * forward outside the range and otherwise return the private base. */

    stub[used++] = 0x40u; stub[used++] = 0x53u;
    stub[used++] = 0x48u; stub[used++] = 0x83u;
    stub[used++] = 0xECu; stub[used++] = 0x40u;
    stub[used++] = 0x49u; stub[used++] = 0xBBu;
    for (i = 0u; i < 8u; ++i) {
        stub[used++] = (UCHAR)(state->RemoteBase >> (i * 8u));
    }
    stub[used++] = 0x4Cu; stub[used++] = 0x39u; stub[used++] = 0xD9u;
    stub[used++] = 0x0Fu; stub[used++] = 0x82u;
    /* `used` now points at the 4-byte displacement field; the next
     * instruction begins after those 4 bytes, not after a further 6. */

    relative = (int32_t)((int64_t)trampoline -
                         (int64_t)(hookStub + used + 4u));
    for (i = 0u; i < 4u; ++i) {
        stub[used++] = (UCHAR)(((uint32_t)relative) >> (i * 8u));
    }
    stub[used++] = 0x49u; stub[used++] = 0xBBu;
    {
        uint64_t high = state->RemoteBase + state->Image->SizeOfImage;
        for (i = 0u; i < 8u; ++i) {
            stub[used++] = (UCHAR)(high >> (i * 8u));
        }
    }
    stub[used++] = 0x4Cu; stub[used++] = 0x39u; stub[used++] = 0xD9u;
    stub[used++] = 0x0Fu; stub[used++] = 0x83u;
    relative = (int32_t)((int64_t)trampoline -
                         (int64_t)(hookStub + used + 4u));
    for (i = 0u; i < 4u; ++i) {
        stub[used++] = (UCHAR)(((uint32_t)relative) >> (i * 8u));
    }
    stub[used++] = 0x48u; stub[used++] = 0xB8u;
    for (i = 0u; i < 8u; ++i) {
        stub[used++] = (UCHAR)(state->RemoteBase >> (i * 8u));
    }
    stub[used++] = 0x48u; stub[used++] = 0x89u; stub[used++] = 0x02u;
    stub[used++] = 0x48u; stub[used++] = 0x83u;
    stub[used++] = 0xC4u; stub[used++] = 0x40u;
    stub[used++] = 0x5Bu; stub[used++] = 0xC3u;

    if (!UserWrite(state->Process, hookStub, stub, used)) {
        return Fail(state, AMGER_INIT_STAGE_PC_DETOUR,
                    STATUS_INSUFFICIENT_RESOURCES);
    }

    /* Trampoline copies bytes 6..12, rebases the RIP-relative operand and
     * resumes at orig+13 without re-running the replicated prologue. */

    {
        UCHAR trampolineBytes[32];
        uint32_t t = 0u;
        uint32_t j;
        for (j = 6u; j < 13u; ++j) {
            trampolineBytes[t++] = original[j];
        }
        originalDisp = 0;
        for (j = 0u; j < 4u; ++j) {
            originalDisp |=
                (int32_t)((uint32_t)original[9u + j] << (j * 8u));
        }
        absolute = state->HookFunction + 13u +
                   (uint64_t)(int64_t)originalDisp;
        newDisp = (int32_t)(absolute - (trampoline + 7u));
        for (j = 0u; j < 4u; ++j) {
            trampolineBytes[3u + j] =
                (UCHAR)(((uint32_t)newDisp) >> (j * 8u));
        }
        trampolineBytes[t++] = 0x49u; trampolineBytes[t++] = 0xBBu;
        {
            uint64_t resume = state->HookFunction + 13u;
            for (j = 0u; j < 8u; ++j) {
                trampolineBytes[t++] = (UCHAR)(resume >> (j * 8u));
            }
        }
        trampolineBytes[t++] = 0x49u; /* REX.W: jmp r11, not jmp r11d */
        trampolineBytes[t++] = 0xFFu;
        trampolineBytes[t++] = 0xE3u;
        if (!UserWrite(state->Process, trampoline, trampolineBytes, t)) {
            return Fail(state, AMGER_INIT_STAGE_PC_DETOUR,
                        STATUS_UNSUCCESSFUL);
        }
    }

    state->HookStub = hookStub;
    state->HookTrampoline = trampoline;
    state->DetourStubsReady = TRUE;
    return STATUS_SUCCESS;
}

/* Writes a data or code page that MmCopyVirtualMemory cannot touch because it
 * is copy-on-write (ntdll image pages, PEB TLS bitmap). A temporary flip to
 * READWRITE goes through the memory manager so COW is honoured and a PRIVATE
 * page is created in the target; the original protection is then restored.
 * READWRITE has no EXECUTE bit, so this never creates an RWX window and W^X is
 * preserved. This is the single write path for the detour and the TLS bitmap:
 * an MDL alias would bypass COW and make the change visible in every process. */

static BOOLEAN WriteProtectedCode(PAMGER_RUNTIME_STATE state,
                                   uint64_t address, const VOID* data,
                                   SIZE_T length) {
    KAPC_STATE apcState;
    SIZE_T size = length;
    PVOID base = (PVOID)(uintptr_t)address;
    ULONG saved = 0u;
    ULONG restoreOld = 0u;
    NTSTATUS status;
    BOOLEAN written;

    if (address == 0u || data == NULL || length == 0u) {
        return FALSE;
    }

    KeStackAttachProcess((PRKPROCESS)state->Process, &apcState);
    status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size,
                                    PAGE_READWRITE, &saved);
    KeUnstackDetachProcess(&apcState);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    written = UserWrite(state->Process, address, data, length);

    KeStackAttachProcess((PRKPROCESS)state->Process, &apcState);
    base = (PVOID)(uintptr_t)address;
    size = length;
    status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size,
                                    saved, &restoreOld);
    KeUnstackDetachProcess(&apcState);
    return written && NT_SUCCESS(status);
}

/* Publishes the detour only after the private stub page is executable. */

static NTSTATUS ActivateDetour(PAMGER_RUNTIME_STATE state) {
    UCHAR jump[13];
    uint32_t j = 0u;
    uint32_t i;

    if (!state->DetourStubsReady || state->HookFunction == 0u) {
        return Fail(state, AMGER_INIT_STAGE_PC_DETOUR,
                    STATUS_INVALID_DEVICE_STATE);
    }
    jump[j++] = 0x49u; jump[j++] = 0xBAu;
    for (i = 0u; i < 8u; ++i) {
        jump[j++] = (UCHAR)(state->HookStub >> (i * 8u));
    }
    jump[j++] = 0x49u; /* REX.W: jmp r10, not jmp r10d */
    jump[j++] = 0xFFu; jump[j++] = 0xE2u;
    if (!WriteProtectedCode(state, state->HookFunction, jump, j)) {
        return Fail(state, AMGER_INIT_STAGE_PC_DETOUR,
                    STATUS_ACCESS_DENIED);
    }
    state->DetourInstalled = TRUE;
    state->Report->DetourBytes = j;
    state->Report->DetourAddress = state->HookStub;
    state->Report->Flags |= AMGER_INIT_FLAG_PC_DETOUR;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* R19 - retarget the image's CFG check pointer                        */
/* ------------------------------------------------------------------ */

/* The load-config field and the relocated global it points to are both
 * patched explicitly. A full-image scan for additional copies was removed:
 * it required a 4 KiB stack buffer inside an already deep call chain and
 * exhausted the kernel stack during an IPI (bugcheck 0x7f). */

static NTSTATUS RetargetCfg(PAMGER_RUNTIME_STATE state) {
    UCHAR chunk[256];
    uint64_t gadget;
    uint32_t rva;
    uint32_t offset;
    uint32_t limit;

    if (state->CfgCheckAddress == 0u ||
        (state->GuardFlags & 0x100u) == 0u) {
        /* Measured absence: this image is not CFG instrumented. */

        state->CfgCheckAfter = state->CfgCheckBefore;
        state->Report->CfgCheckAfter = state->CfgCheckAfter;
        state->Report->Flags |= AMGER_INIT_FLAG_CFG;
        return STATUS_SUCCESS;
    }
    if (state->NtdllBase == 0u || state->NtdllSize == 0u) {
        return Fail(state, AMGER_INIT_STAGE_CFG, STATUS_NOT_FOUND);
    }

    /* Find an INT3-padded `ret` inside ntdll's mapped image. The preceding
     * INT3 is a one-byte instruction, so the RET is a real instruction
     * boundary rather than an accidental byte pair inside another opcode. */

    gadget = 0u;
    limit = state->NtdllSize;
    if (limit > 0x200000u) {
        limit = 0x200000u;
    }
    /* The scan range is large but the stack buffer is only 256 bytes: the
     * earlier bugcheck came from a 4 KiB buffer on this deep call chain,
     * not from the number of bounded reads. */

    for (rva = 0x1000u; rva + 2u < limit; rva += (uint32_t)sizeof(chunk)) {
        uint32_t take = limit - rva;
        if (take > (uint32_t)sizeof(chunk)) {
            take = (uint32_t)sizeof(chunk);
        }
        if (!UserRead(state->Process, state->NtdllBase + rva, chunk, take)) {
            break;
        }
        for (offset = 0u; offset + 2u < take; ++offset) {
            if (chunk[offset] == 0xCCu && chunk[offset + 1u] == 0xC3u) {
                gadget = state->NtdllBase + rva + offset + 1u;
                break;
            }
        }
        if (gadget != 0u) {
            break;
        }
    }
    if (gadget == 0u) {
        return Fail(state, AMGER_INIT_STAGE_CFG, STATUS_NOT_FOUND);
    }
    state->RetGadget = gadget;

    if (!UserWrite(state->Process, state->CfgCheckAddress,
                   &gadget, sizeof(gadget))) {
        return Fail(state, AMGER_INIT_STAGE_CFG, STATUS_ACCESS_VIOLATION);
    }
    if (state->CfgCheckPointerAddress != 0u) {
        if (!UserWrite(state->Process, state->CfgCheckPointerAddress,
                       &gadget, sizeof(gadget))) {
            return Fail(state, AMGER_INIT_STAGE_CFG, STATUS_ACCESS_VIOLATION);
        }
        if (!UserRead(state->Process, state->CfgCheckPointerAddress,
                      &state->CfgCheckAfter, sizeof(gadget)) ||
            state->CfgCheckAfter != gadget) {
            return Fail(state, AMGER_INIT_STAGE_CFG, STATUS_UNSUCCESSFUL);
        }
    } else {
        state->CfgCheckAfter = gadget;
    }
    state->Report->CfgCheckAfter = state->CfgCheckAfter;
    state->Report->Flags |= AMGER_INIT_FLAG_CFG;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* R25 - durable thread TLS and new-thread callbacks                    */
/* ------------------------------------------------------------------ */

/* The durable part of thread TLS is PatchThreadSlots. New-thread callbacks
 * need lifecycle notification. The notify callback is deliberately tiny: it
 * can arrive at APC_LEVEL in the creating thread's loader lock, so it only
 * enqueues an event and arms a passive-level work item. Every user-memory
 * access, TLS-slot install and user-APC queue happens in that work item. This
 * removes the deep chain and large stack frames that caused the earlier 0x7f.
 * DETACH cannot be delivered to an exiting thread by a user APC; delete events
 * are counted only, never reported as callbacks fired. */

static VOID AmgerThreadNotify(HANDLE processId, HANDLE threadId,
                              BOOLEAN create) {
    long index;

    if (InterlockedCompareExchange(&g_r25.Enabled, 0L, 0L) == 0L ||
        processId != g_r25.ProcessId) {
        return;
    }
    index = InterlockedIncrement(&g_r25.Head) - 1L;
    if ((ULONG)(index - g_r25.Tail) >= AMGER_R25_RING) {
        (void)InterlockedIncrement(&g_r25.Dropped);
        return;
    }
    g_r25.Ring[(ULONG)index % AMGER_R25_RING].ProcessId = processId;
    g_r25.Ring[(ULONG)index % AMGER_R25_RING].ThreadId = threadId;
    g_r25.Ring[(ULONG)index % AMGER_R25_RING].Create = create;
    if (create) {
        (void)InterlockedIncrement(&g_r25.CreateSeen);
    } else {
        (void)InterlockedIncrement(&g_r25.DeleteSeen);
    }
    if (InterlockedCompareExchange(&g_r25.Gate, 1L, 0L) == 0L) {
        /* No device object is available in this phase; the work item is a
         * static, driver-lifetime structure, so ExQueueWorkItem is sufficient. */
#pragma warning(suppress : 28159)
        ExQueueWorkItem(&g_r25.WorkItem, DelayedWorkQueue);
    }
}

static VOID AmgerR25ApcKernelRoutine(struct _KAPC* apc,
                                     PVOID* normalRoutine,
                                     PVOID* normalContext,
                                     PVOID* argument1, PVOID* argument2) {
    UNREFERENCED_PARAMETER(normalRoutine);
    UNREFERENCED_PARAMETER(normalContext);
    UNREFERENCED_PARAMETER(argument1);
    UNREFERENCED_PARAMETER(argument2);
    (void)InterlockedDecrement(&g_r25.PendingApcs);
    ExFreePool(apc);
}

static VOID AmgerR25ApcRundownRoutine(struct _KAPC* apc) {
    (void)InterlockedDecrement(&g_r25.PendingApcs);
    ExFreePool(apc);
}

/* Installs a private TLS block in one new thread and queues the payload's
 * DLL_THREAD_ATTACH callbacks to it. Runs only from the passive work item. */

static BOOLEAN PromoteR25CodePage(PEPROCESS process, uint64_t page) {
    KAPC_STATE apc;
    PVOID base = (PVOID)(uintptr_t)page;
    SIZE_T size = AMGER_PAGE_SIZE_4K;
    ULONG old = 0u;
    NTSTATUS status;

    KeStackAttachProcess((PRKPROCESS)process, &apc);
    status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size,
                                    PAGE_EXECUTE_READ, &old);
    KeUnstackDetachProcess(&apc);
    return NT_SUCCESS(status);
}

static VOID AmgerR25AttachThread(HANDLE threadId) {
    AMGER_RUNTIME_STATE scratch;
    PETHREAD thread = NULL;
    PVOID teb = NULL;
    uint64_t array = 0u;
    uint64_t block = 0u;
    uint64_t codePage = 0u;
    uint64_t dataPage = 0u;
    uint64_t address;
    uint32_t count = 0u;
    uint32_t i;
    uint32_t zero = 0u;
    UCHAR code[AMGER_STUB_MAX];
    AMGER_JOB jobs[AMGER_MAX_JOBS];
    PRKAPC apc;
    KAPC_STATE apcState;

    if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &thread))) {
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
    if (PsGetThreadProcessId(thread) != g_r25.ProcessId) {
        ObDereferenceObject(thread);
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
    teb = PsGetThreadTeb(thread);
    if (teb == NULL || g_state.TlsIndexValue >= AMGER_TLS_MINIMUM) {
        ObDereferenceObject(thread);
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
    RtlZeroMemory(&scratch, sizeof(scratch));
    scratch.Process = g_r25.Process;
    if (!NT_SUCCESS(AllocatePrivatePage(&scratch, &block, PAGE_READWRITE)) ||
        !NT_SUCCESS(AllocatePrivatePage(&scratch, &codePage, PAGE_READWRITE)) ||
        !NT_SUCCESS(AllocatePrivatePage(&scratch, &dataPage, PAGE_READWRITE))) {
        ReleasePrivatePage(&scratch, &block);
        ReleasePrivatePage(&scratch, &codePage);
        ReleasePrivatePage(&scratch, &dataPage);
        ObDereferenceObject(thread);
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
    KeStackAttachProcess((PRKPROCESS)g_r25.Process, &apcState);
    array = 0u;
    (void)UserRead(g_r25.Process, (uint64_t)(uintptr_t)teb +
                   AMGER_TEB_TLS_POINTER, &array, sizeof(array));
    if (array != 0u && g_state.TlsTemplate != NULL &&
        UserWrite(g_r25.Process, block, g_state.TlsTemplate,
                  g_state.TlsRawBytes) &&
        UserWrite(g_r25.Process, array +
                  ((uint64_t)g_state.TlsIndexValue * 8u),
                  &block, sizeof(block))) {
        RtlZeroMemory(jobs, sizeof(jobs));
        for (i = 0u; i < g_state.TlsCallbackCount &&
                      count < AMGER_MAX_JOBS; ++i) {
            jobs[count].Function = g_state.TlsCallbacks[i];
            jobs[count].Arg1 = g_state.RemoteBase;
            jobs[count].Arg2 = 2u; /* DLL_THREAD_ATTACH */
            jobs[count].Arg3 = 0u;
            ++count;
        }
        if (count != 0u) {
            (void)UserWrite(g_r25.Process, dataPage, &count, sizeof(count));
            (void)UserWrite(g_r25.Process, dataPage + 8u, jobs,
                            count * sizeof(AMGER_JOB));
            address = dataPage + AMGER_COMPLETION_OFF;
            (void)UserWrite(g_r25.Process, address, &zero, sizeof(zero));
            EmitStub(code, dataPage, count);
            (void)UserWrite(g_r25.Process, codePage, code,
                            (uint32_t)(21u + (65u * count) + 22u));
        }
    } else {
        array = 0u;
    }
    KeUnstackDetachProcess(&apcState);

    if (array == 0u || count == 0u ||
        !PromoteR25CodePage(g_r25.Process, codePage)) {
        ReleasePrivatePage(&scratch, &block);
        ReleasePrivatePage(&scratch, &codePage);
        ReleasePrivatePage(&scratch, &dataPage);
        ObDereferenceObject(thread);
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
    if (g_r25.PageCount < AMGER_R25_MAX_PAGES) {
        g_r25.Codes[g_r25.PageCount] = codePage;
        g_r25.Datas[g_r25.PageCount] = dataPage;
        g_r25.Blocks[g_r25.PageCount] = block;
        g_r25.Arrays[g_r25.PageCount] = array;
        g_r25.Tebs[g_r25.PageCount] = (uint64_t)(uintptr_t)teb;
        g_r25.Tids[g_r25.PageCount] = threadId;
        ++g_r25.PageCount;
    } else {
        zero = 0u;
        (void)UserWrite(g_r25.Process, array +
                        ((uint64_t)g_state.TlsIndexValue * 8u),
                        &zero, sizeof(zero));
        ReleasePrivatePage(&scratch, &block);
        ReleasePrivatePage(&scratch, &codePage);
        ReleasePrivatePage(&scratch, &dataPage);
        ObDereferenceObject(thread);
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        return;
    }
#pragma warning(suppress : 4996 28197)
    apc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAPC), 'grmP');
    if (apc == NULL) {
        (void)InterlockedIncrement(&g_r25.AttachFailed);
        ObDereferenceObject(thread);
        return;
    }
    KeInitializeApc(apc, (PRKTHREAD)thread, AmgerOriginalApcEnvironment,
                    AmgerR25ApcKernelRoutine, AmgerR25ApcRundownRoutine,
                    (AMGER_NORMAL_ROUTINE)(uintptr_t)codePage,
                    UserMode, (PVOID)(uintptr_t)dataPage);
    (void)InterlockedIncrement(&g_r25.PendingApcs);
    if (KeInsertQueueApc(apc, NULL, NULL, 0)) {
        (void)QueueAlertBooster(thread);
        (void)InterlockedIncrement(&g_r25.AttachQueued);
    } else {
        (void)InterlockedDecrement(&g_r25.PendingApcs);
        ExFreePoolWithTag(apc, 'grmP');
        (void)InterlockedIncrement(&g_r25.AttachFailed);
    }
    ObDereferenceObject(thread);
}

WORKER_THREAD_ROUTINE AmgerTlsWorkItem;

VOID AmgerTlsWorkItem(PVOID context) {
    AMGER_R25_EVENT event;

    UNREFERENCED_PARAMETER(context);
    while (g_r25.Tail != g_r25.Head) {
        event = g_r25.Ring[(ULONG)g_r25.Tail % AMGER_R25_RING];
        (void)InterlockedIncrement(&g_r25.Tail);
        if (event.Create) {
            AmgerR25AttachThread(event.ThreadId);
        } else {
            (void)InterlockedIncrement(&g_r25.DetachObserved);
        }
    }
    (void)InterlockedExchange(&g_r25.Gate, 0L);
    if (g_r25.Tail != g_r25.Head &&
        InterlockedCompareExchange(&g_r25.Gate, 1L, 0L) == 0L) {
#pragma warning(suppress : 28159)
        ExQueueWorkItem(&g_r25.WorkItem, DelayedWorkQueue);
    }
}

static NTSTATUS RegisterThreadTlsNotify(PAMGER_RUNTIME_STATE state) {
    NTSTATUS status;

    RtlZeroMemory(&g_r25, sizeof(g_r25));
    g_r25.ProcessId = state->ProcessId;
    g_r25.Process = state->Process;
    ObReferenceObject(g_r25.Process);
    ExInitializeWorkItem(&g_r25.WorkItem, AmgerTlsWorkItem, NULL);
    g_r25.WorkItemReady = TRUE;
    status = PsSetCreateThreadNotifyRoutine(AmgerThreadNotify);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(g_r25.Process);
        g_r25.Process = NULL;
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, status);
    }
    (void)InterlockedExchange(&g_r25.Enabled, 1L);
    state->Report->ThreadNotifyStatus = (uint32_t)STATUS_SUCCESS;
    state->Report->Flags |= AMGER_INIT_FLAG_THREAD_NOTIFY;
    return STATUS_SUCCESS;
}

static VOID UnregisterThreadTlsNotify(VOID) {
    AMGER_RUNTIME_STATE scratch;
    LARGE_INTEGER interval;
    uint32_t i;
    uint64_t zero = 0u;

    if (g_r25.Enabled == 0L && g_r25.Process == NULL) {
        return;
    }
    (void)InterlockedExchange(&g_r25.Enabled, 0L);
    (void)PsRemoveCreateThreadNotifyRoutine(AmgerThreadNotify);
    interval.QuadPart = -10000LL;
    for (i = 0u; i < 200u && g_r25.Gate != 0L; ++i) {
        (void)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    if (g_r25.Gate != 0L) {
        /* A work item is still using the process, TLS template and pages.
         * Leave the references and allocations in place rather than freeing
         * memory it is about to touch. */
        return;
    }
    RtlZeroMemory(&scratch, sizeof(scratch));
    scratch.Process = g_r25.Process;
    for (i = 0u; i < g_r25.PageCount; ++i) {
        if (g_r25.Arrays[i] != 0u) {
            (void)UserWrite(g_r25.Process, g_r25.Arrays[i] +
                            ((uint64_t)g_state.TlsIndexValue * 8u),
                            &zero, sizeof(zero));
        }
        ReleasePrivatePage(&scratch, &g_r25.Blocks[i]);
        if (g_r25.PendingApcs == 0L) {
            ReleasePrivatePage(&scratch, &g_r25.Codes[i]);
            ReleasePrivatePage(&scratch, &g_r25.Datas[i]);
        }
    }
    ObDereferenceObject(g_r25.Process);
    RtlZeroMemory(&g_r25, sizeof(g_r25));
}

static NTSTATUS RegisterThreadTls(PAMGER_RUNTIME_STATE state) {
    NTSTATUS status;

    if (state->ThreadsPatched == 0u) {
        return Fail(state, AMGER_INIT_STAGE_THREAD_TLS, STATUS_NOT_FOUND);
    }
    status = RegisterThreadTlsNotify(state);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    state->Report->Flags |= AMGER_INIT_FLAG_THREAD_TLS;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Phase entry and rollback                                            */
/* ------------------------------------------------------------------ */

static NTSTATUS InitialiseUserPages(PAMGER_RUNTIME_STATE state) {
    NTSTATUS status;

    status = AllocatePrivatePage(state, &state->CodePage, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return Fail(state, AMGER_INIT_STAGE_APC, status);
    }
    status = AllocatePrivatePage(state, &state->DataPage, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return Fail(state, AMGER_INIT_STAGE_APC, status);
    }
    return STATUS_SUCCESS;
}

static VOID ReleasePrivatePage(PAMGER_RUNTIME_STATE state, uint64_t* page) {
    KAPC_STATE apc;
    PVOID base;
    SIZE_T size = 0u;

    if (*page == 0u) {
        return;
    }
    base = (PVOID)(uintptr_t)*page;
    KeStackAttachProcess((PRKPROCESS)state->Process, &apc);
    (void)ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
    KeUnstackDetachProcess(&apc);
    *page = 0u;
}

NTSTATUS InitializePhase(const AMGER_INIT_CONTEXT* context) {
    PAMGER_RUNTIME_STATE state = &g_state;
    AMGER_JOB jobs[AMGER_MAX_JOBS];
    uint32_t jobCount = 0u;
    uint32_t i;
    NTSTATUS status;

    if (context == NULL || context->Image == NULL ||
        context->Report == NULL || context->ProcessId == NULL) {
        if (context != NULL && context->Report != NULL) {
            context->Report->BuildId = AMGER_INIT_BUILD_ID;
            context->Report->Status = (uint32_t)STATUS_INVALID_PARAMETER;
            context->Report->FailureStage = AMGER_INIT_STAGE_PARAMETERS;
        }
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_initBusy, 1L, 0L) != 0L) {
        context->Report->BuildId = AMGER_INIT_BUILD_ID;
        context->Report->Status = (uint32_t)STATUS_DEVICE_BUSY;
        context->Report->FailureStage = AMGER_INIT_STAGE_PARAMETERS;
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(state, sizeof(*state));
    state->ProcessId = context->ProcessId;
    state->RemoteBase = context->RemoteBase;
    state->Image = context->Image;
    state->Report = context->Report;
    state->Report->BuildId = AMGER_INIT_BUILD_ID;
    state->Report->Status = 0u;
    state->Report->FailureStage = AMGER_INIT_STAGE_NONE;
    state->Report->Flags = 0u;
    state->Report->RemoteBase = context->RemoteBase;

    status = PsLookupProcessByProcessId(context->ProcessId, &state->Process);
    if (!NT_SUCCESS(status)) {
        (void)Fail(state, AMGER_INIT_STAGE_PROCESS, status);
        goto failure;
    }
    {
        uint64_t peb = (uint64_t)(uintptr_t)PsGetProcessPeb(state->Process);
        uint64_t ldr = 0u;
        uint64_t apiSet = 0u;
        if (peb == 0u ||
            !UserRead(state->Process, peb + 0x18u, &ldr, sizeof(ldr)) ||
            !UserRead(state->Process, peb + 0x68u, &apiSet, sizeof(apiSet))) {
            status = Fail(state, AMGER_INIT_STAGE_PROCESS,
                          STATUS_INVALID_DEVICE_STATE);
            goto failure;
        }
        state->Lookup.Peb = peb;
        state->Lookup.LdrHead = ldr;
        state->Lookup.ApiSetMap = apiSet;
    }

    status = ValidateLoadConfig(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = InitCookie(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = DetectActivation(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = InitTls(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = PatchThreadSlots(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = ResolveRoutines(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = InitialiseUserPages(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = RetargetCfg(state);
    if (!NT_SUCCESS(status)) goto failure;

    /* The single APC performs process-attach TLS callbacks and registers the
     * exception table before the entry point is ever called. */

    RtlZeroMemory(jobs, sizeof(jobs));
    for (i = 0u; i < state->TlsCallbackCount && jobCount < AMGER_MAX_JOBS; ++i) {
        jobs[jobCount].Function = state->TlsCallbacks[i];
        jobs[jobCount].Arg1 = context->RemoteBase;
        jobs[jobCount].Arg2 = 1u; /* DLL_PROCESS_ATTACH */
        jobs[jobCount].Arg3 = 0u;
        ++jobCount;
    }
    {
        AMGER_PE_DIRECTORY pdata =
            state->Image->Directories[AMGER_DIRECTORY_EXCEPTION];
        if (pdata.Rva != 0u && pdata.Size >= 12u && jobCount < AMGER_MAX_JOBS) {
            state->PdataRemote = Remote(state, pdata.Rva);
            state->PdataEntries = pdata.Size / 12u;
            state->PdataJobIndex = jobCount;
            state->PdataQueued = TRUE;
            jobs[jobCount].Function = state->RtlAddFunctionTable;
            jobs[jobCount].Arg1 = state->PdataRemote;
            jobs[jobCount].Arg2 = state->PdataEntries;
            jobs[jobCount].Arg3 = context->RemoteBase;
            ++jobCount;
        }
    }

    /* All private code is emitted while the page is RW. Promotion happens
     * once, then the detour is published and the APC is queued, so no thread
     * can ever execute a writable stub. */

    status = EmitDetourStubs(state);
    if (!NT_SUCCESS(status)) goto failure;
    if (jobCount != 0u) {
        status = PrepareApcStub(state, jobs, jobCount, NULL);
        if (!NT_SUCCESS(status)) goto failure;
    }
    status = PromoteCodePage(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = PromoteImageCode(state);
    if (!NT_SUCCESS(status)) goto failure;
    status = ActivateDetour(state);
    if (!NT_SUCCESS(status)) goto failure;

    if (jobCount != 0u) {
        status = RunJobs(state);
        if (!NT_SUCCESS(status)) goto failure;
    }
    if (state->PdataQueued) {
        /* RtlAddFunctionTable returns BOOLEAN in AL; the stub stores RAX at
         * Result@+32. Read the low byte only, since the upper RAX bits are
         * undefined for a BOOLEAN return. */
        uint8_t result = 0u;
        uint64_t address = state->DataPage + 8u +
                           (uint64_t)state->PdataJobIndex * sizeof(AMGER_JOB) +
                           32u;
        if (!UserRead(state->Process, address, &result, sizeof(result)) ||
            result == 0u) {
            status = Fail(state, AMGER_INIT_STAGE_PDATA, STATUS_UNSUCCESSFUL);
            goto failure;
        }
    }
    if (state->TlsCallbackCount != 0u) {
        state->Report->Flags |= AMGER_INIT_FLAG_TLS_CALLBACK;
    }
    if (state->PdataQueued) {
        state->Report->PdataTables = 1u;
        state->Report->PdataEntries = state->PdataEntries;
        state->Report->Flags |= AMGER_INIT_FLAG_PDATA;
    }

    status = RegisterThreadTls(state);
    if (!NT_SUCCESS(status)) goto failure;

    state->Report->ThreadCallbacksFired = state->ThreadCallbacks;
    state->Report->ThreadCreateSeen =
        (uint32_t)InterlockedCompareExchange(&g_r25.CreateSeen, 0L, 0L);
    state->Report->ThreadDeleteSeen =
        (uint32_t)InterlockedCompareExchange(&g_r25.DeleteSeen, 0L, 0L);
    state->Report->ThreadEventsDropped =
        (uint32_t)InterlockedCompareExchange(&g_r25.Dropped, 0L, 0L);
    state->Report->ThreadAttachQueued =
        (uint32_t)InterlockedCompareExchange(&g_r25.AttachQueued, 0L, 0L);
    state->Report->ThreadAttachFailed =
        (uint32_t)InterlockedCompareExchange(&g_r25.AttachFailed, 0L, 0L);
    state->Report->ThreadDetachObserved =
        (uint32_t)InterlockedCompareExchange(&g_r25.DetachObserved, 0L, 0L);
    state->Report->Status = (uint32_t)STATUS_SUCCESS;
    return STATUS_SUCCESS;

failure:
    (void)status;
    InitializeRevert(context);
    return state->Report->Status;
}

/* The deferred-phase rollback releases the entire private image VAD after
 * this revert, so image-internal mutations (cookie, TLS index variable, CFG
 * pointer and promoted EXEC protections) are discarded with the mapping. No
 * per-field image restore is needed on that path; the ntdll detour and PEB/TEB
 * structures are shared with the target and are restored explicitly below. */

VOID InitializeRevert(const AMGER_INIT_CONTEXT* context) {
    PAMGER_RUNTIME_STATE state = &g_state;
    uint32_t bits[AMGER_TLS_EXPANSION_MAX / 32u];

    UNREFERENCED_PARAMETER(context);
    if (state->Process == NULL) {
        InterlockedExchange(&g_initBusy, 0L);
        return;
    }

    if (state->DetourInstalled && state->HookFunction != 0u) {
        (void)WriteProtectedCode(state, state->HookFunction,
                                 state->Original, sizeof(state->Original));
    }
    UnregisterThreadTlsNotify();

    RtlZeroMemory(bits, sizeof(bits));
    if (state->TlsIndexAllocated && state->TlsBitsAddress != 0u &&
        state->TlsBitsSize != 0u &&
        UserRead(state->Process, state->TlsBitsAddress,
                 bits, state->TlsBitsSize)) {
        uint32_t bitPos = (state->TlsIndexValue >= AMGER_TLS_MINIMUM)
                        ? state->TlsIndexValue - AMGER_TLS_MINIMUM
                        : state->TlsIndexValue;
        bits[bitPos >> 5u] &= ~(1u << (bitPos & 31u));
        (void)WriteProtectedCode(state, state->TlsBitsAddress,
                                 bits, state->TlsBitsSize);
    }

    {
        uint32_t i;
        uint64_t zero = 0u;
        for (i = 0u; i < state->TlsBlockCount; ++i) {
            /* Restore the per-thread TLS slot pointer that PatchThreadSlots
             * changed, and release any array page it allocated. Leaving the
             * TEB pointing at a released page would be a dangling pointer. */

            if (state->TlsTebs[i] != 0u) {
                (void)UserWrite(state->Process,
                    state->TlsTebs[i] + AMGER_TEB_TLS_POINTER,
                    &state->OriginalArrays[i], sizeof(uint64_t));
            }
            if (state->TlsArrays[i] != 0u) {
                (void)UserWrite(state->Process,
                    state->TlsArrays[i] +
                        ((uint64_t)state->TlsIndexValue * 8u),
                    &zero, sizeof(zero));
            }
            ReleasePrivatePage(state, &state->TlsBlocks[i]);
            /* Free only the array page Phase 6 allocated (either because the
             * thread had none, or because the index needed a larger array). */

            if (state->TlsArrayReplaced[i]) {
                ReleasePrivatePage(state, &state->TlsArrays[i]);
            }
        }
        if (state->TlsTemplate != NULL) {
            ExFreePoolWithTag(state->TlsTemplate, 'grmD');
            state->TlsTemplate = NULL;
        }
    }
    /* A queued user APC may still run after a timeout. Its stub and job block
     * must outlive this revert; leaking the two pages is safer than freeing
     * memory a live APC is about to execute and read. */

    if (!state->LeaveCodePage &&
        InterlockedCompareExchange((volatile long*)&state->PendingApcs, 0L, 0L) == 0L) {
        ReleasePrivatePage(state, &state->CodePage);
        ReleasePrivatePage(state, &state->DataPage);
    } else {
        state->CodePage = 0u;
        state->DataPage = 0u;
    }

    ObDereferenceObject(state->Process);
    state->Process = NULL;
    state->Report->Flags |= AMGER_INIT_FLAG_REVERTED;
    InterlockedExchange(&g_initBusy, 0L);
}
