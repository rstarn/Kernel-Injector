#include "ChannelClient.hpp"

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

    sharedRegion = VirtualAlloc(
        nullptr,
        AMGER_SHARED_REGION_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (sharedRegion == nullptr) {
        CloseHandle(deviceHandle);
        deviceHandle = INVALID_HANDLE_VALUE;
        return false;
    }
    std::memset(sharedRegion, 0, AMGER_SHARED_REGION_SIZE);

    AMGER_SHARED_REGION_REQUEST request = {};
    request.VirtualAddress = reinterpret_cast<uint64_t>(sharedRegion);
    request.Size = static_cast<uint64_t>(AMGER_SHARED_REGION_SIZE);

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

bool ChannelClient::Ping(uint32_t timeoutMilliseconds) {
    if (deviceHandle == INVALID_HANDLE_VALUE || sharedRegion == nullptr || header == nullptr) {
        return false;
    }

    AMGER_COMMAND_HEADER command = {};
    command.Magic = AMGER_MAGIC_NUMBER;
    command.Version = AMGER_PROTOCOL_VERSION;
    command.Command = AMGER_COMMAND_PING;
    std::memcpy(const_cast<AMGER_COMMAND_HEADER*>(header), &command, sizeof(command));
    MemoryBarrier();

    DWORD bytesReturned = 0u;
    /* The device is deleted during registration; this IOCTL is the last use
     * of the handle. A failure here is tolerated when the shared Status was
     * nevertheless updated by the driver. */
    (void)DeviceIoControl(
        deviceHandle,
        AMGER_IOCTL_KICK,
        nullptr,
        0u,
        nullptr,
        0u,
        &bytesReturned,
        nullptr);

    const DWORD startTime = GetTickCount();
    uint32_t status = 0u;
    for (;;) {
        status = static_cast<uint32_t>(InterlockedCompareExchange(
            reinterpret_cast<volatile long*>(&header->Status), 0L, 0L));
        if (status != 0u) {
            break;
        }
        if ((GetTickCount() - startTime) >= timeoutMilliseconds) {
            break;
        }
        Sleep(1u);
    }

    return status == 0u;
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
