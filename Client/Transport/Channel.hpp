#pragma once

/*
 * Channel.hpp - user-mode side of the shared-memory channel.
 *
 * Contract: owns the bootstrap device handle and the user allocation that the
 * driver locks with an MDL. One Connect, one Ping, then Disconnect. Commands
 * complete synchronously with the KICK IOCTL; no polling is performed.
 * Inputs: bootstrap file path and the PING command.
 * Outputs: success/failure of each operation and the final driver NTSTATUS.
 * Failure modes: Connect fails on missing file, unopenable device, allocation
 * failure or registration IOCTL failure. Ping fails on IOCTL failure, missing
 * completion or any non-success status.
 */

#include <cstdint>
#include <mutex>
#include <string>
#include <Windows.h>

#include "../../Shared/Protocol.h"

class ChannelClient {
public:
    ChannelClient();
    ~ChannelClient();

    bool Connect(const std::wstring& bootstrapPath);
    bool Ping();
    void Disconnect();

    ChannelClient(const ChannelClient&) = delete;
    ChannelClient& operator=(const ChannelClient&) = delete;

private:
    static bool ReadBootstrapPath(const std::wstring& bootstrapPath, std::wstring& devicePath);
    static void WriteCommand(volatile AMGER_COMMAND_HEADER* header, uint32_t command);
    static uint32_t ReadFinalStatus(volatile AMGER_COMMAND_HEADER* header);
    void DisconnectUnlocked();

    std::mutex operationMutex;
    HANDLE deviceHandle;
    void* sharedRegion;
    volatile AMGER_COMMAND_HEADER* header;
};
