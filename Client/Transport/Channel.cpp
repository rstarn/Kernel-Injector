#include "Channel.hpp"

#include <cstring>

ChannelClient::ChannelClient()
    : deviceHandle(INVALID_HANDLE_VALUE),
      sharedRegion(nullptr),
      header(nullptr) {
}

ChannelClient::~ChannelClient() {
    Disconnect();
}

bool ChannelClient::ReadBootstrapPath(
    const std::wstring& bootstrapPath, std::wstring& devicePath) {
    HANDLE file = CreateFileW(
        bootstrapPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    wchar_t buffer[512] = {};
    DWORD bytesRead = 0u;
    const BOOL readOk = ReadFile(file, buffer, sizeof(buffer) - sizeof(wchar_t),
                                 &bytesRead, nullptr);
    CloseHandle(file);

    if (!readOk || bytesRead == 0u || (bytesRead % sizeof(wchar_t)) != 0u) {
        return false;
    }

    const wchar_t* start = buffer;
    const wchar_t* end = buffer + (bytesRead / sizeof(wchar_t));
    const wchar_t* terminator = start;
    while (terminator != end && *terminator != L'\0') {
        ++terminator;
    }
    if (terminator == start) {
        return false;
    }

    devicePath.assign(start, terminator);
    return devicePath.rfind(L"\\\\.\\", 0u) == 0u;
}

void ChannelClient::WriteCommand(volatile AMGER_COMMAND_HEADER* header, uint32_t command) {
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
    header->PayloadVirtualAddress = 0u;
    header->PayloadSize = 0u;
    header->TargetProcessId = 0u;
    header->Options = 0u;
    header->CompletionEventHandle = 0u;

    MemoryBarrier();
    InterlockedExchange(sequenceAddress, static_cast<long>(sequence + 1u));
}

uint32_t ChannelClient::ReadFinalStatus(volatile AMGER_COMMAND_HEADER* header) {
    MemoryBarrier();
    return header->Status;
}

bool ChannelClient::Connect(const std::wstring& bootstrapPath) {
    Disconnect();

    std::wstring devicePath;
    if (!ReadBootstrapPath(bootstrapPath, devicePath)) {
        return false;
    }

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

    /* PING needs only the command header; the 64 MB maximum stays a protocol
     * capacity limit for future payloads. */
    sharedRegion = VirtualAlloc(
        nullptr,
        AMGER_COMMAND_REGION_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (sharedRegion == nullptr) {
        CloseHandle(deviceHandle);
        deviceHandle = INVALID_HANDLE_VALUE;
        return false;
    }
    std::memset(sharedRegion, 0, AMGER_COMMAND_REGION_SIZE);

    AMGER_SHARED_REGION_REQUEST request = {};
    request.VirtualAddress = reinterpret_cast<uint64_t>(sharedRegion);
    request.Size = static_cast<uint64_t>(AMGER_COMMAND_REGION_SIZE);

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
    if (!ioctlOk) {
        Disconnect();
        return false;
    }

    header = reinterpret_cast<volatile AMGER_COMMAND_HEADER*>(sharedRegion);
    return true;
}

bool ChannelClient::Ping() {
    if (deviceHandle == INVALID_HANDLE_VALUE || sharedRegion == nullptr || header == nullptr) {
        return false;
    }

    WriteCommand(header, AMGER_COMMAND_PING);

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

void ChannelClient::Disconnect() {
    header = nullptr;

    if (deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(deviceHandle);
        deviceHandle = INVALID_HANDLE_VALUE;
    }

    if (sharedRegion != nullptr) {
        VirtualFree(sharedRegion, 0u, MEM_RELEASE);
        sharedRegion = nullptr;
    }
}
