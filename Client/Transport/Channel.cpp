#include "Channel.hpp"

#include <algorithm>
#include <cstring>

ChannelClient::ChannelClient()
    : deviceHandle(INVALID_HANDLE_VALUE),
      sharedRegion(nullptr),
      header(nullptr),
      regionSize(0u),
      lastLogSequence(0u),
      resultValue(0u) {
}

ChannelClient::~ChannelClient() {
    Disconnect();
}

void ChannelClient::WriteCommand(volatile AMGER_COMMAND_HEADER* header,
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

    header->Magic = AMGER_MAGIC_NUMBER;
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
    if (requestedSize < sizeof(AMGER_COMMAND_HEADER) ||
        requestedSize > AMGER_SHARED_REGION_SIZE) {
        return false;
    }

    /* IRP_MJ_CLOSE is dispatched asynchronously. Reopening immediately after a
     * previous session can reach the driver while its region is still Closing,
     * so registration is retried briefly instead of failing on that race. */
    for (unsigned attempt = 0u; attempt < 8u; ++attempt) {
        DisconnectUnlocked();

        deviceHandle = CreateFileW(
            AMGER_USER_DEVICE,
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
            AMGER_IOCTL_REGISTER_SHARED_REGION,
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

bool ChannelClient::Ping() {
    std::lock_guard<std::mutex> lock(operationMutex);
    if (deviceHandle == INVALID_HANDLE_VALUE || sharedRegion == nullptr || header == nullptr) {
        return false;
    }

    WriteCommand(header, AMGER_COMMAND_PING, 0u, 0u, 0u, 0u);

    DWORD bytesReturned = 0u;
    const BOOL kickOk = DeviceIoControl(
        deviceHandle,
        AMGER_IOCTL_KICK,
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

uint32_t ChannelClient::Inject(uint32_t targetProcessId,
                               uint32_t options,
                               const void* payload,
                               size_t payloadSize) {
    std::lock_guard<std::mutex> lock(operationMutex);

    if (payload == nullptr || payloadSize == 0u ||
        payloadSize > static_cast<size_t>(AMGER_MAXIMUM_PAYLOAD_SIZE) - AMGER_LOG_AREA_SIZE) {
        return AMGER_STATUS_PENDING;
    }

    const size_t needed = static_cast<size_t>(AMGER_PAYLOAD_OFFSET) + payloadSize +
                          AMGER_LOG_AREA_SIZE;
    if (needed > AMGER_SHARED_REGION_SIZE || !EnsureRegionUnlocked(needed)) {
        return AMGER_CLIENT_REGION_FAILED;
    }

    PUCHAR payloadTarget = reinterpret_cast<PUCHAR>(sharedRegion) + AMGER_PAYLOAD_OFFSET;
    std::memcpy(payloadTarget, payload, payloadSize);

    WriteCommand(header,
                 AMGER_COMMAND_INJECT,
                 reinterpret_cast<uint64_t>(payloadTarget),
                 static_cast<uint64_t>(payloadSize),
                 targetProcessId,
                 options);

    DWORD bytesReturned = 0u;
    (void)DeviceIoControl(
        deviceHandle,
        AMGER_IOCTL_KICK,
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

std::vector<ChannelClient::LogRecord> ChannelClient::DrainLogs() {
    std::vector<LogRecord> records;
    std::lock_guard<std::mutex> lock(operationMutex);

    if (header == nullptr || sharedRegion == nullptr) {
        lastLogSequence = 0u;
        return records;
    }

    volatile AMGER_LOG_RING* ring = reinterpret_cast<volatile AMGER_LOG_RING*>(
        reinterpret_cast<PUCHAR>(sharedRegion) + regionSize - sizeof(AMGER_LOG_RING));

    for (unsigned attempt = 0u; attempt < 2u; ++attempt) {
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
        AMGER_IOCTL_UNLOAD,
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
