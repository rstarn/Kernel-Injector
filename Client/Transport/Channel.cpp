#include "Channel.hpp"

#include <algorithm>
#include <cstring>
#include <cwchar>

/* Same derivation as Bootstrap.c. Every externally visible identifier comes
 * from this hash; no product string appears in the device name. */
static uint64_t ReadMachineHash() {
    WCHAR guid[128] = { 0 };
    DWORD length = sizeof(guid);
    const LSTATUS status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid",
        RRF_RT_REG_SZ,
        nullptr,
        guid,
        &length);

    if (status == ERROR_SUCCESS && length >= sizeof(WCHAR)) {
        return AmgerMachineHash(guid, static_cast<size_t>(length / sizeof(WCHAR)));
    }
    return AmgerMachineHash(AMGER_FALLBACK_GUID,
                            wcslen(AMGER_FALLBACK_GUID));
}

static std::wstring BuildDevicePath(uint64_t hash) {
    WCHAR buffer[64] = { 0 };
    /* \\.\ prefix (4) + 16 hash digits + NUL must fit; asserted for both C and
     * C++ by the shared protocol header. */
    AMGER_ASSERT_NAME_BUFFER(64u, 4u);
    wcscpy_s(buffer, L"\\\\.\\");
    AmgerAppendName(buffer, 64u, hash);
    return buffer;
}

static ULONG DerivedIoctl(uint32_t functionBase, uint64_t hash) {
    return CTL_CODE(AMGER_DEVICE_TYPE,
                    AmgerIoctlFunction(functionBase, hash),
                    AMGER_IOCTL_METHOD, AMGER_IOCTL_ACCESS);
}

ChannelClient::ChannelClient()
    : deviceHandle(INVALID_HANDLE_VALUE),
      sharedRegion(nullptr),
      header(nullptr),
      regionSize(0u),
      lastLogSequence(0u),
      resultValue(0u),
      machineHash(ReadMachineHash()),
      devicePath(BuildDevicePath(machineHash)) {
}

ChannelClient::~ChannelClient() {
    Disconnect();
}

void ChannelClient::WriteCommand(volatile AMGER_COMMAND_HEADER* header,
                                 uint32_t magic,
                                 uint32_t command,
                                 uint64_t payloadVirtualAddress,
                                 uint64_t payloadSize,
                                 uint32_t targetProcessId,
                                 uint32_t options) {
    volatile AMGER_HEADER_CONTROL* control =
        reinterpret_cast<volatile AMGER_HEADER_CONTROL*>(&header->Reserved[0]);

    volatile long* sequenceAddress = reinterpret_cast<volatile long*>(&control->Sequence);
    uint32_t sequence = static_cast<uint32_t>(
        InterlockedCompareExchange(sequenceAddress, 0L, 0L));
    sequence = (sequence & 1u) ? sequence + 2u : sequence + 1u;
    InterlockedExchange(sequenceAddress, static_cast<long>(sequence));
    MemoryBarrier();

    header->Magic = magic;
    header->Version = AMGER_PROTOCOL_VERSION;
    header->Command = command;
    header->Status = AMGER_STATUS_PENDING;
    header->PayloadVirtualAddress = payloadVirtualAddress;
    header->PayloadSize = payloadSize;
    header->TargetProcessId = targetProcessId;
    header->Options = options;
    header->CompletionEventHandle = 0u;

    MemoryBarrier();
    InterlockedExchange(sequenceAddress, static_cast<long>(sequence + 1u));
}

uint32_t ChannelClient::ReadFinalStatus(volatile AMGER_COMMAND_HEADER* header) {
    MemoryBarrier();
    return header->Status;
}

bool ChannelClient::Connect(size_t requestedSize) {
    std::lock_guard<std::mutex> lock(operationMutex);
    return ConnectUnlocked(requestedSize);
}

bool ChannelClient::ConnectUnlocked(size_t requestedSize) {
    if (requestedSize < AMGER_MINIMUM_REGION_SIZE ||
        requestedSize > AMGER_SHARED_REGION_SIZE) {
        return false;
    }

    /* IRP_MJ_CLOSE is dispatched asynchronously. Reopening immediately after a
     * previous session can reach the driver while its region is still Closing,
     * so registration is retried briefly instead of failing on that race. */
    for (unsigned attempt = 0u; attempt < 8u; ++attempt) {
        DisconnectUnlocked();

        deviceHandle = CreateFileW(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0u,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (deviceHandle == INVALID_HANDLE_VALUE) {
            return false;
        }

        sharedRegion = VirtualAlloc(
            nullptr,
            requestedSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (sharedRegion == nullptr) {
            CloseHandle(deviceHandle);
            deviceHandle = INVALID_HANDLE_VALUE;
            return false;
        }
        std::memset(sharedRegion, 0, requestedSize);

        AMGER_SHARED_REGION_REQUEST request = {};
        request.VirtualAddress = reinterpret_cast<uint64_t>(sharedRegion);
        request.Size = static_cast<uint64_t>(requestedSize);

        DWORD bytesReturned = 0u;
        const BOOL ioctlOk = DeviceIoControl(
            deviceHandle,
            DerivedIoctl(AMGER_IOCTL_FUNCTION_REGISTER, machineHash),
            &request,
            sizeof(request),
            nullptr,
            0u,
            &bytesReturned,
            nullptr);
        if (ioctlOk) {
            regionSize = requestedSize;
            header = reinterpret_cast<volatile AMGER_COMMAND_HEADER*>(sharedRegion);
            return true;
        }

        DisconnectUnlocked();
        Sleep(25u);
    }

    return false;
}

bool ChannelClient::EnsureRegionUnlocked(size_t requestedSize) {
    if (header != nullptr && regionSize >= requestedSize) {
        return true;
    }
    /* The device is persistent, so re-registering on a fresh handle is safe. */
    return ConnectUnlocked(requestedSize);
}

bool ChannelClient::Connected() const {
    std::lock_guard<std::mutex> lock(operationMutex);
    return header != nullptr;
}

bool ChannelClient::ProbeDevice() const {
    /* Zero desired access is a pure existence probe: it asks the object
     * manager to resolve the derived name without requesting read or write
     * rights, and produces an IRP_MJ_CREATE/CLOSE pair that changes no driver
     * state. A stale cached header in Connected() cannot substitute for this. */
    HANDLE probe = CreateFileW(
        devicePath.c_str(),
        0u,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (probe == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(probe);
    return true;
}

bool ChannelClient::Ping() {
    std::lock_guard<std::mutex> lock(operationMutex);
    if (deviceHandle == INVALID_HANDLE_VALUE || sharedRegion == nullptr || header == nullptr) {
        return false;
    }

    WriteCommand(header, AmgerMagicValue(machineHash), AMGER_COMMAND_PING, 0u, 0u, 0u, 0u);

    DWORD bytesReturned = 0u;
    const BOOL kickOk = DeviceIoControl(
        deviceHandle,
        DerivedIoctl(AMGER_IOCTL_FUNCTION_KICK, machineHash),
        nullptr,
        0u,
        nullptr,
        0u,
        &bytesReturned,
        nullptr);

    const uint32_t status = ReadFinalStatus(header);

    /* No polling: the synchronous IOCTL is the completion boundary. */
    return kickOk != FALSE &&
           status != AMGER_STATUS_PENDING &&
           status == 0u; /* STATUS_SUCCESS is zero in both environments. */
}

uint32_t ChannelClient::LastFault() {
    std::lock_guard<std::mutex> lock(operationMutex);
    if (deviceHandle == INVALID_HANDLE_VALUE || sharedRegion == nullptr || header == nullptr) {
        return 0u;
    }

    /* Reset the result slot so a stale value from a prior Inject cannot be
     * mistaken for a fault. The driver publishes zero for STATUS when clean. */
    volatile AMGER_RESULT_CONTROL* result =
        reinterpret_cast<volatile AMGER_RESULT_CONTROL*>(&header->Reserved[0]);
    result->ResultValue = 0u;

    WriteCommand(header, AmgerMagicValue(machineHash), AMGER_COMMAND_STATUS,
                 0u, 0u, 0u, 0u);

    DWORD bytesReturned = 0u;
    const BOOL kickOk = DeviceIoControl(
        deviceHandle,
        DerivedIoctl(AMGER_IOCTL_FUNCTION_KICK, machineHash),
        nullptr, 0u, nullptr, 0u, &bytesReturned, nullptr);

    /* Only trust the result slot if the STATUS command actually completed.
     * Otherwise the slot is still the zero we wrote, which would be reported
     * as "no fault" and hide the fact that the query failed. */
    const uint32_t status = ReadFinalStatus(header);
    if (kickOk == FALSE || status == AMGER_STATUS_PENDING) {
        return AMGER_CLIENT_STATUS_QUERY_FAILED;
    }

    MemoryBarrier();
    resultValue = result->ResultValue;
    return static_cast<uint32_t>(resultValue);
}

uint32_t ChannelClient::Inject(uint32_t targetProcessId,
                               uint32_t options,
                               const void* payload,
                               size_t payloadSize) {
    std::lock_guard<std::mutex> lock(operationMutex);

    /* Clear any value left by a prior command so a failed inject cannot show a
     * stale remote base. Only a successful, non-PENDING completion overwrites it. */
    resultValue = 0u;

    if (payload == nullptr || payloadSize == 0u ||
        payloadSize > static_cast<size_t>(AMGER_MAXIMUM_PAYLOAD_SIZE) - AMGER_LOG_AREA_SIZE) {
        return AMGER_CLIENT_BAD_ARGUMENTS;
    }

    const size_t needed = static_cast<size_t>(AMGER_PAYLOAD_OFFSET) + payloadSize +
                          AMGER_LOG_AREA_SIZE;
    if (needed > AMGER_SHARED_REGION_SIZE || !EnsureRegionUnlocked(needed)) {
        return AMGER_CLIENT_REGION_FAILED;
    }

    PUCHAR payloadTarget = reinterpret_cast<PUCHAR>(sharedRegion) + AMGER_PAYLOAD_OFFSET;
    std::memcpy(payloadTarget, payload, payloadSize);

    WriteCommand(header,
                 AmgerMagicValue(machineHash),
                 AMGER_COMMAND_INJECT,
                 reinterpret_cast<uint64_t>(payloadTarget),
                 static_cast<uint64_t>(payloadSize),
                 targetProcessId,
                 options);

    DWORD bytesReturned = 0u;
    (void)DeviceIoControl(
        deviceHandle,
        DerivedIoctl(AMGER_IOCTL_FUNCTION_KICK, machineHash),
        nullptr,
        0u,
        nullptr,
        0u,
        &bytesReturned,
        nullptr);

    /* The driver publishes a final status on every path. A driver-side error
     * makes DeviceIoControl fail as well, so the shared header — not the BOOL
     * — is the authoritative result. PENDING means it never answered. */
    const uint32_t status = ReadFinalStatus(header);
    if (status == AMGER_STATUS_PENDING) {
        return AMGER_CLIENT_KICK_FAILED;
    }

    const volatile AMGER_RESULT_CONTROL* result =
        reinterpret_cast<volatile AMGER_RESULT_CONTROL*>(&header->Reserved[0]);
    resultValue = result->ResultValue;
    return status;
}

uint64_t ChannelClient::ResultValue() const {
    std::lock_guard<std::mutex> lock(operationMutex);
    return resultValue;
}

const std::wstring& ChannelClient::DevicePath() const {
    return devicePath;
}

std::vector<ChannelClient::LogRecord> ChannelClient::DrainLogs() {
    std::vector<LogRecord> records;
    std::lock_guard<std::mutex> lock(operationMutex);

    if (header == nullptr || sharedRegion == nullptr) {
        lastLogSequence = 0u;
        return records;
    }

    volatile AMGER_LOG_RING* ring = reinterpret_cast<volatile AMGER_LOG_RING*>(
        reinterpret_cast<PUCHAR>(sharedRegion) + regionSize - sizeof(AMGER_LOG_RING));

    for (unsigned attempt = 0u; attempt < 4u; ++attempt) {
        /* The log ring is NOT a seqlock. The driver writes every field of a
         * record first, issues a barrier, and only then publishes the final
         * sequence (LogStage in Bridge.c). It never marks a record with an odd
         * "writer active" value, so rejecting odd values here silently dropped
         * roughly half of all records, including one-record teardown logs.
         * The before/after double sample below is the real torn-read guard. */
        const uint32_t before = ring->Sequence;
        MemoryBarrier();

        records.clear();
        for (size_t index = 0u; index < AMGER_LOG_ENTRY_COUNT; ++index) {
            const volatile AMGER_LOG_ENTRY& entry = ring->Entries[index];
            if (entry.Sequence != 0u &&
                entry.Sequence > lastLogSequence &&
                entry.Sequence <= before) {
                records.push_back({entry.Sequence, entry.Id, entry.Status, entry.Detail});
            }
        }

        MemoryBarrier();
        if (ring->Sequence == before) {
            std::sort(records.begin(), records.end(),
                      [](const LogRecord& left, const LogRecord& right) {
                          return left.Sequence < right.Sequence;
                      });
            if (!records.empty()) {
                lastLogSequence = records.back().Sequence;
            }
            return records;
        }
    }

    records.clear();
    return records;
}

bool ChannelClient::Unload() {
    std::lock_guard<std::mutex> lock(operationMutex);
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesReturned = 0u;
    const BOOL unloadOk = DeviceIoControl(
        deviceHandle,
        DerivedIoctl(AMGER_IOCTL_FUNCTION_UNLOAD, machineHash),
        nullptr,
        0u,
        nullptr,
        0u,
        &bytesReturned,
        nullptr);
    return unloadOk != FALSE;
}

void ChannelClient::Disconnect() {
    std::lock_guard<std::mutex> lock(operationMutex);
    DisconnectUnlocked();
}

void ChannelClient::DisconnectUnlocked() {
    header = nullptr;

    if (deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(deviceHandle);
        deviceHandle = INVALID_HANDLE_VALUE;
    }

    if (sharedRegion != nullptr) {
        VirtualFree(sharedRegion, 0u, MEM_RELEASE);
        sharedRegion = nullptr;
    }
    regionSize = 0u;
    lastLogSequence = 0u;
    resultValue = 0u;
}
