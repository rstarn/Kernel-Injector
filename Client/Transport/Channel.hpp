#pragma once

/*
 * Channel.hpp - user-mode side of the shared-memory channel.
 *
 * Contract: owns the handle to the machine-derived device name and the user
 * allocation that the driver locks with an MDL.
 * The region is sized on demand: PING needs only the header, INJECT needs
 * the header plus its payload. Commands complete synchronously with their
 * IOCTL; no polling is performed.
 * Inputs: the machine-derived device path and the command fields.
 * Outputs: success/failure of Connect/Ping, and the final driver NTSTATUS
 * from Inject.
 * Failure modes: Connect fails on an unopenable device, allocation failure
 * or registration IOCTL failure. Ping fails on IOCTL failure, missing
 * completion or any non-success status.
 */

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <Windows.h>

#include "../../Shared/Protocol.h"

/* Client-only return sentinels. The driver never returns these. */
#define AMGER_CLIENT_REGION_FAILED      0xFFFFFFF0u
#define AMGER_CLIENT_KICK_FAILED        0xFFFFFFF1u
#define AMGER_CLIENT_STATUS_QUERY_FAILED 0xFFFFFFF2u
#define AMGER_CLIENT_BAD_ARGUMENTS      0xFFFFFFF3u

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

    /* Genuine object-manager probe: opens the derived device path with no
     * read/write access and closes it immediately. Unlike Connected(), which
     * only reports cached in-process state, this always asks the OS whether a
     * device currently exists under that name. */

    bool ProbeDevice() const;
    bool Ping();

    /* Issues the STATUS command and returns the first lifecycle teardown fault
     * recorded by the driver, or 0 when none has been recorded. This is the
     * client-side consumer of the driver's in-memory failure record, so a
     * teardown failure is visible rather than silent. */

    uint32_t LastFault();
    uint32_t Inject(uint32_t targetProcessId, uint32_t options,
                    const void* payload, size_t payloadSize);
    bool Unload();
    void Disconnect();

    uint64_t ResultValue() const;
    const std::wstring& DevicePath() const;

    /* Returns dispatcher records newer than the last ones displayed. */

    std::vector<LogRecord> DrainLogs();

    ChannelClient(const ChannelClient&) = delete;
    ChannelClient& operator=(const ChannelClient&) = delete;

private:
    static void WriteCommand(volatile AMGER_COMMAND_HEADER* header,
                             uint32_t magic,
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
    uint64_t resultValue;
    uint64_t machineHash;
    std::wstring devicePath;
};
