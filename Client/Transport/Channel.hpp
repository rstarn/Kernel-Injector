#pragma once

/*
 * Channel.hpp - user-mode side of the shared-memory channel.
 *
 * Contract: owns the well-known device handle (see AMGER_USER_DEVICE in
 * Protocol.h) and the user allocation that the driver locks with an MDL.
 * One Connect, then Ping / Unload, then Disconnect. Commands complete
 * synchronously with their IOCTL; no polling is performed.
 * Inputs: the fixed Protocol.h device name and the PING command.
 * Outputs: success/failure of each operation and the final driver NTSTATUS.
 * Failure modes: Connect fails on an unopenable device, allocation failure
 * or registration IOCTL failure. Ping fails on IOCTL failure, missing
 * completion or any non-success status.
 */

#include <cstdint>
#include <mutex>
#include <Windows.h>

#include "../../Shared/Protocol.h"

class ChannelClient {
public:
    ChannelClient();
    ~ChannelClient();

    bool Connect();
    bool Connected() const;
    bool Ping();
    bool Unload();
    void Disconnect();

    ChannelClient(const ChannelClient&) = delete;
    ChannelClient& operator=(const ChannelClient&) = delete;

private:
    static void WriteCommand(volatile AMGER_COMMAND_HEADER* header, uint32_t command);
    static uint32_t ReadFinalStatus(volatile AMGER_COMMAND_HEADER* header);
    void DisconnectUnlocked();

    mutable std::mutex operationMutex;
    HANDLE deviceHandle;
    void* sharedRegion;
    volatile AMGER_COMMAND_HEADER* header;
};
