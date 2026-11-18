#pragma once

/*
 * ChannelClient.hpp - user-mode side of the shared-memory channel.
 *
 * Contract: owns the bootstrap device handle and the user allocation that the
 * driver locks with an MDL. One Connect, zero or more Ping, then Disconnect.
 * Inputs: bootstrap file path, command identifier, timeout.
 * Outputs: success/failure of each operation; command Status read from shared
 * memory.
 * Failure modes: Connect fails when the bootstrap file is missing, the device
 * cannot be opened, allocation fails, or registration IOCTL fails. Ping fails
 * on timeout or a non-success Status. All failures leave the object safely
 * disconnectable.
 */

#include <cstdint>
#include <string>
#include <Windows.h>

#include "../../Shared/Protocol.h"

class ChannelClient {
public:
    /*
     * Contract: creates the disconnected state.
     * Inputs: none. Outputs: invalid handle and null region.
     * Failure modes: none.
     */
    ChannelClient();

    /*
     * Contract: releases the handle and allocation if still held.
     * Inputs: none. Outputs: disconnected object. Failure modes: none.
     */
    ~ChannelClient();

    /*
     * Contract: reads the bootstrap path, opens the GUID device, allocates
     * the shared region and registers it with the driver.
     * Inputs: wide path of the bootstrap file.
     * Outputs: true when the region is registered and the header is mapped.
     * Failure modes: false on missing file, unopenable device, allocation
     * failure, or registration IOCTL failure; all partial state is released.
     */
    bool Connect(const std::wstring& bootstrapPath);

    /*
     * Contract: writes one PING header, kicks the driver and waits for Status.
     * Inputs: timeout in milliseconds. Outputs: true on STATUS_SUCCESS.
     * Failure modes: false when not connected, on timeout, or on any
     * non-success status left in the header.
     */
    bool Ping(uint32_t timeoutMilliseconds);

    /*
     * Contract: idempotently releases all owned resources.
     * Inputs: none. Outputs: disconnected object. Failure modes: none.
     */
    void Disconnect();

    ChannelClient(const ChannelClient&) = delete;
    ChannelClient& operator=(const ChannelClient&) = delete;

private:
    static bool ReadBootstrapPath(const std::wstring& bootstrapPath, std::wstring& devicePath);

    HANDLE deviceHandle;
    void* sharedRegion;
    volatile AMGER_COMMAND_HEADER* header;
};
