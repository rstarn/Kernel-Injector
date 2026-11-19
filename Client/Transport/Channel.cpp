#include "Channel.hpp"

#include <cstring>
#include <cwchar>

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
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    /* The bootstrap file is one fixed-format record: the AmgerGUID device
     * prefix, exactly 32 hexadecimal GUID digits, and one UTF-16 NUL.
     * Reject directories, reparse points, truncation, embedded NULs and
     * trailing data before opening any device. */
    FILE_ATTRIBUTE_TAG_INFO fileInfo = {};
    const BOOL infoOk = GetFileInformationByHandleEx(
        file, FileAttributeTagInfo, &fileInfo, sizeof(fileInfo));
    if (!infoOk ||
        (fileInfo.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0u) {
        CloseHandle(file);
        return false;
    }

    static const wchar_t prefix[] = AMGER_USER_DEVICE_PREFIX;
    constexpr size_t prefixLength = (sizeof(prefix) / sizeof(prefix[0])) - 1u;
    constexpr size_t expectedCharacters = prefixLength + AMGER_GUID_HEX_LENGTH;
    wchar_t buffer[expectedCharacters + 2u] = {};
    DWORD bytesRead = 0u;
    const DWORD expectedBytes =
        static_cast<DWORD>((expectedCharacters + 1u) * sizeof(wchar_t));
    const DWORD readCapacity = static_cast<DWORD>(sizeof(buffer));
    const BOOL readOk = ReadFile(file, buffer, readCapacity, &bytesRead, nullptr);
    CloseHandle(file);

    if (!readOk || bytesRead != expectedBytes ||
        buffer[expectedCharacters] != L'\0' ||
        wmemcmp(buffer, prefix, prefixLength) != 0) {
        return false;
    }

    for (size_t index = prefixLength; index < expectedCharacters; ++index) {
        const wchar_t character = buffer[index];
        const bool isHexDigit =
            (character >= L'0' && character <= L'9') ||
            (character >= L'A' && character <= L'F') ||
            (character >= L'a' && character <= L'f');
        if (!isHexDigit) {
            return false;
        }
    }

    devicePath.assign(buffer, expectedCharacters);
    return true;
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
    std::lock_guard<std::mutex> lock(operationMutex);
    DisconnectUnlocked();

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
        DisconnectUnlocked();
        return false;
    }

    header = reinterpret_cast<volatile AMGER_COMMAND_HEADER*>(sharedRegion);
    return true;
}

bool ChannelClient::Ping() {
    std::lock_guard<std::mutex> lock(operationMutex);
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
}
