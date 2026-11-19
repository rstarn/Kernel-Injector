#pragma once

/*
 * Channel.hpp - user-mode side of the shared-memory channel.
 *
 * Contract: owns the well-known device handle (see AMGER_USER_DEVICE in
 * Protocol.h) and the user allocation that the driver locks with an MDL.
 * The region is sized on demand: PING needs only the header, INJECT needs
 * the header plus its payload. Commands complete synchronously with their
 * IOCTL; no polling is performed.
 * Inputs: the fixed Protocol.h device name and the command fields.
 * Outputs: success/failure of Connect/Ping, and the final driver NTSTATUS
 * from Inject.
 * Failure modes: Connect fails on an unopenable device, allocation failure
 * or registration IOCTL failure. Ping fails on IOCTL failure, missing
 * completion or any non-success status.
 */

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>
#include <Windows.h>

#include "../../Shared/Protocol.h"

/* Client-only return sentinels for Inject. The driver never returns these. */
#define AMGER_CLIENT_REGION_FAILED 0xFFFFFFF0u
#define AMGER_CLIENT_KICK_FAILED   0xFFFFFFF1u

class ChannelClient {
public:
    struct LogRecord {
        uint32_t Sequence;
        uint16_t Id;
        uint32_t Status;
        uint32_t Detail;
    };

    ChannelClient();
    ~ChannelClient();

    bool Connect(size_t regionSize = AMGER_COMMAND_REGION_SIZE + AMGER_LOG_AREA_SIZE);
    bool Connected() const;
    bool Ping();
    uint32_t Inject(uint32_t targetProcessId, uint32_t options,
                    const void* payload, size_t payloadSize);
    bool Unload();
    void Disconnect();

    /* Returns dispatcher records newer than the last ones displayed. */
    std::vector<LogRecord> DrainLogs();

    ChannelClient(const ChannelClient&) = delete;
    ChannelClient& operator=(const ChannelClient&) = delete;

private:
    static void WriteCommand(volatile AMGER_COMMAND_HEADER* header,
                             uint32_t command,
                             uint64_t payloadVirtualAddress,
                             uint64_t payloadSize,
                             uint32_t targetProcessId,
                             uint32_t options);
    static uint32_t ReadFinalStatus(volatile AMGER_COMMAND_HEADER* header);
    bool ConnectUnlocked(size_t regionSize);
    bool EnsureRegionUnlocked(size_t regionSize);
    void DisconnectUnlocked();

    mutable std::mutex operationMutex;
    HANDLE deviceHandle;
    void* sharedRegion;
    volatile AMGER_COMMAND_HEADER* header;
    size_t regionSize;
    uint32_t lastLogSequence;
};
