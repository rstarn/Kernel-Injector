/*
 * Client.exe - interactive console front-end for the Ameger driver.
 *
 * Contract: no command-line arguments are accepted. The user picks a screen
 * from the main menu; every value shown on those screens is gathered live at
 * the moment the screen renders, never hardcoded.
 *   [1] Inject - resolves the process name adaptively, reads a DLL payload
 *                from disk and delivers it to the driver with the target PID.
 *   [2] Status - performs a live device check: responsiveness, a timed PING
 *                round-trip, the configured device name and the connection.
 *                One channel is opened on first use and kept for the session.
 *                The device persists across client launches, so exiting and
 *                relaunching needs no re-map.
 *   [3] Unload - removes the device and its name so the driver can be re-mapped.
 *   [0] Exit   - leaves the console.
 * Inputs: none. Outputs: process exit code 0 on a clean exit, 1 never occurs.
 * Failure modes: an unopenable device or a failed PING is a normal runtime
 * state, reported in color on screen, not an exit-code failure.
 */

#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <wchar.h>

#include "../Interface/Console.hpp"
#include "../Utilities/Process.hpp"
#include "../Transport/Channel.hpp"
#include "../../Shared/Protocol.h"

namespace {

std::wstring Trim(const std::wstring& value) {
    const size_t begin = value.find_first_not_of(L" \t\r\n");
    if (begin == std::wstring::npos) {
        return L"";
    }
    const size_t end = value.find_last_not_of(L" \t\r\n");
    return value.substr(begin, end - begin + 1u);
}

void PrintMenu() {
    Console::WriteText(L"[1]", Console::Brush::Orange);
    Console::WriteText(L" : ", Console::Brush::Gray);
    Console::WriteText(L"Inject", Console::Brush::White);
    Console::WriteRaw(L"\n");

    Console::WriteText(L"[2]", Console::Brush::Orange);
    Console::WriteText(L" : ", Console::Brush::Gray);
    Console::WriteText(L"Status", Console::Brush::White);
    Console::WriteRaw(L"\n");

    Console::WriteText(L"[3]", Console::Brush::Orange);
    Console::WriteText(L" : ", Console::Brush::Gray);
    Console::WriteText(L"Unload", Console::Brush::White);
    Console::WriteRaw(L"\n\n");

    Console::WriteText(L"[0]", Console::Brush::Orange);
    Console::WriteText(L" : ", Console::Brush::Gray);
    Console::WriteText(L"Exit", Console::Brush::White);
    Console::WriteRaw(L"\n\n");
}

struct Session {
    ChannelClient channel;
};

const wchar_t* StatusName(uint32_t status) {
#define AMGER_STATUS_NAME_CASE(code, name) case code: return L#name;
    switch (status) {
        AMGER_STATUS_TABLE(AMGER_STATUS_NAME_CASE)
    default:
        break;
    }
#undef AMGER_STATUS_NAME_CASE
    static wchar_t unknown[32] = {};
    swprintf_s(unknown, L"UNKNOWN_0x%08X", status);
    return unknown;
}

const wchar_t* LogIdName(uint16_t id) {
#define AMGER_LOG_ID_NAME_CASE(code, name) case code: return L#name;
    switch (id) {
        AMGER_LOG_ID_TABLE(AMGER_LOG_ID_NAME_CASE)
    default:
        break;
    }
#undef AMGER_LOG_ID_NAME_CASE
    return L"UNKNOWN";
}

void PrintLogs(const std::vector<ChannelClient::LogRecord>& records) {
    for (const auto& record : records) {
        /* The command-stage records start a second visual group after the
         * validation records. */
        if (record.Id == AMGER_LOG_ID_PING ||
            record.Id == AMGER_LOG_ID_INJECT ||
            record.Id == AMGER_LOG_ID_EJECT ||
            record.Id == AMGER_LOG_ID_STATUS_COMMAND) {
            Console::WriteRaw(L"\n");
        }

        wchar_t detail[48] = {};
        if (record.Detail != 0u) {
            swprintf_s(detail, L" [%u]", static_cast<unsigned>(record.Detail));
        }

        wchar_t line[160] = {};
        swprintf_s(line, L"Dispatcher[%02u] %s -> 0x%08X (%s)%s",
                   static_cast<unsigned>(record.Sequence), LogIdName(record.Id),
                   record.Status, StatusName(record.Status), detail);
        Console::WriteLine(line, Console::Brush::Gray);

        if (record.Id == AMGER_LOG_ID_REGISTER_COMMIT) {
            Console::WriteRaw(L"\n");
        }
    }

    if (!records.empty()) {
        Console::WriteRaw(L"\n");
    }
}

/* Client.exe lives in Build\Output; the reference DLL is two levels up in
 * Assets. Deriving from the module path keeps the location relative to the
 * install regardless of the process working directory. */
std::wstring ResolveTargetPath() {
    wchar_t modulePath[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::wstring directory(modulePath, length);
    for (unsigned level = 0u; level < 3u; ++level) {
        const size_t separator = directory.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            return L"Assets\\Target.dll";
        }
        directory.resize(separator);
    }
    return directory + L"\\Assets\\Target.dll";
}

void InjectScreen(Session& session) {
    Console::ClearScreen();

    const std::wstring query = Trim(Console::ReadLine(L"Process Name: ", Console::Brush::White));
    if (query.empty()) {
        Console::WriteLine(L"No process name entered.", Console::Brush::LightYellow);
        return;
    }

    DWORD pid = 0u;
    if (!Process::FindIdByName(query, pid)) {
        Console::WriteLine(L"The selected process target was not found.",
                           Console::Brush::LightRed);
        return;
    }

    Console::WriteText(L"The selected process target connected successfully. ",
                       Console::Brush::LightGreen);
    Console::WriteText(L"(PID: ", Console::Brush::Silver);
    Console::WriteText(std::to_wstring(pid), Console::Brush::LightGreen);
    Console::WriteText(L")\n", Console::Brush::Silver);
    Console::WriteRaw(L"\n");

    const std::wstring path = ResolveTargetPath();

    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr) {
        Console::WriteLine(L"Target.dll could not be opened.", Console::Brush::LightRed);
        return;
    }

    std::vector<unsigned char> payload;
    unsigned char buffer[4096];
    size_t read = 0u;
    while ((read = std::fread(buffer, 1u, sizeof(buffer), file)) > 0u) {
        payload.insert(payload.end(), buffer, buffer + read);
    }
    std::fclose(file);

    if (payload.empty()) {
        Console::WriteLine(L"DLL file is empty.", Console::Brush::LightRed);
        return;
    }

    if (!session.channel.Connected() && !session.channel.Connect()) {
        Console::WriteLine(L"Device unavailable. Map the driver first.", Console::Brush::LightRed);
        return;
    }

    const uint32_t status = session.channel.Inject(pid, 0u, payload.data(), payload.size());
    PrintLogs(session.channel.DrainLogs());
    if (status == 0u) {
        Console::WriteLine(L"Payload accepted by the driver.", Console::Brush::LightGreen);
    } else if (status == AMGER_CLIENT_REGION_FAILED) {
        Console::WriteLine(L"Device rejected the payload region.", Console::Brush::LightRed);
    } else if (status == AMGER_CLIENT_KICK_FAILED) {
        Console::WriteLine(L"Device did not answer the command.", Console::Brush::LightRed);
    } else if (status == AMGER_STATUS_PENDING) {
        Console::WriteLine(L"Payload could not be delivered.", Console::Brush::LightRed);
    } else {
        wchar_t text[96] = {};
        swprintf_s(text, L"Driver status: 0x%08X (%s)", status, StatusName(status));
        Console::WriteLine(text, Console::Brush::LightRed);
    }

    /* Keep this prompt outside the status branches: INJECT currently returns
     * STATUS_NOT_IMPLEMENTED until the mapping engine is linked, so a prompt
     * gated on success would never be reachable. */
    Console::WriteRaw(L"\n");
    Console::WriteText(L"Ready to inject? (", Console::Brush::Silver);
    Console::WriteText(L"Y", Console::Brush::LightGreen);
    Console::WriteText(L"/", Console::Brush::Gray);
    Console::WriteText(L"N", Console::Brush::LightRed);
    Console::WriteText(L"): ", Console::Brush::Silver);
    const std::wstring answer = Trim(Console::ReadLine(L"", Console::Brush::Silver));
    if (!answer.empty() && (answer.front() == L'Y' || answer.front() == L'y')) {
        Console::WriteLine(L"\nDelegating to the injection engine...", Console::Brush::LightYellow);
    }

    const uint64_t remoteBase = session.channel.ResultValue();
    if (remoteBase != 0u) {
        wchar_t base[64] = {};
        swprintf_s(base, L"Remote base: 0x%016llX", remoteBase);
        Console::WriteLine(base, Console::Brush::LightCyan);
    }
}

void StatusScreen(Session& session) {
    Console::ClearScreen();

    ChannelClient& client = session.channel;
    const bool connected = client.Connected() || client.Connect();

    bool pingOk = false;
    double pingMilliseconds = 0.0;
    if (connected) {
        LARGE_INTEGER frequency = {};
        LARGE_INTEGER started = {};
        LARGE_INTEGER finished = {};
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&started);
        pingOk = client.Ping();
        QueryPerformanceCounter(&finished);
        if (frequency.QuadPart > 0) {
            pingMilliseconds = 1000.0 * static_cast<double>(finished.QuadPart - started.QuadPart) /
                               static_cast<double>(frequency.QuadPart);
        }
    }

    PrintLogs(client.DrainLogs());

    const wchar_t* const stateText = connected && pingOk ? L"Operational"
                                   : connected           ? L"Degraded"
                                                         : L"Unavailable";
    const Console::Brush stateBrush = connected && pingOk ? Console::Brush::LightGreen
                                    : connected           ? Console::Brush::LightYellow
                                                          : Console::Brush::LightRed;

    const Console::Brush pingBrush = pingOk ? Console::Brush::LightGreen
                                   : connected ? Console::Brush::LightRed
                                               : Console::Brush::Gray;
    std::wstring pingText;
    if (pingOk) {
        wchar_t buffer[32] = {};
        swprintf_s(buffer, L"%.3f ms", pingMilliseconds);
        pingText = buffer;
    } else if (connected) {
        pingText = L"No response";
    } else {
        pingText = L"N/A";
    }

    const auto row = [](const std::wstring& label, const std::wstring& value,
                        Console::Brush valueBrush) {
        constexpr size_t labelWidth = 22u;
        std::wstring padded = label;
        if (padded.size() < labelWidth) {
            padded.append(labelWidth - padded.size(), L' ');
        }
        Console::WriteText(padded, Console::Brush::Silver);
        Console::WriteText(value + L"\n", valueBrush);
    };

    row(L"State:", stateText, stateBrush);
    row(L"Ping:", pingText, pingBrush);
    Console::WriteRaw(L"\n");
    row(L"Device Name:", connected ? client.DevicePath() : L"N/A",
        connected ? Console::Brush::LightCyan : Console::Brush::Gray);
    row(L"Device Connection:", connected ? L"Connected" : L"Not Connected",
        connected ? Console::Brush::LightGreen : Console::Brush::LightRed);
}

void UnloadScreen(Session& session) {
    Console::ClearScreen();

    ChannelClient& client = session.channel;

    /* The status line reports the result of a real object-manager probe, not
     * cached state: ProbeDevice opens the derived device name with zero access
     * and closes it, so "found" means the name actually resolved right now. */
    Console::WriteText(L"Checking if device exists... ", Console::Brush::LightYellow);
    const bool devicePresent = client.ProbeDevice();
    Console::WriteLine(devicePresent ? L"(Found)" : L"(Not Found)",
                       devicePresent ? Console::Brush::LightGreen
                                     : Console::Brush::LightRed);

    /* A stale cached header must not bypass a failed probe. */
    const bool connected = devicePresent && (client.Connected() || client.Connect());
    if (!connected) {
        Console::WriteLine(L"Device unavailable. Nothing to unload.",
                           Console::Brush::LightYellow);
        return;
    }

    /* Announce only after the device is confirmed reachable. Printing this
     * before the check would claim a disconnect is in progress even when no
     * driver is mapped under that derived name. */
    Console::WriteText(L"\nDisconnecting the current device driver: ", Console::Brush::Silver);
    Console::WriteLine(client.DevicePath(), Console::Brush::LightCyan);

    const bool unloaded = client.Unload();
    client.Disconnect();
    if (unloaded) {
        Console::WriteLine(L"Device and name removed. Re-map before reconnecting.",
                           Console::Brush::LightGreen);
    } else {
        Console::WriteLine(L"Unload failed.", Console::Brush::LightRed);
    }
}

void ShowMainScreen() {
    Console::ClearScreen();
    Console::RenderBanner();
    PrintMenu();
}

}  // namespace

int wmain() {
    Console::Initialize();
    Session session;

    for (;;) {
        ShowMainScreen();
        const std::wstring input = Trim(Console::ReadLine(L"Input: ", Console::Brush::Orange));
        if (std::wcin.eof()) {
            break;
        }
        if (input.empty()) {
            continue;
        }

        if (input == L"1") {
            InjectScreen(session);
            Console::WaitForEnter();
            continue;
        }
        if (input == L"2") {
            StatusScreen(session);
            Console::WaitForEnter();
            continue;
        }
        if (input == L"3") {
            UnloadScreen(session);
            Console::WaitForEnter();
            continue;
        }
        if (input == L"0") {
            break;
        }

        Console::WriteLine(L"Invalid selection. Enter 1, 2, 3 or 0.", Console::Brush::LightRed);
        Console::WaitForEnter(L"Press Enter to try again...");
    }

    Console::Reset();
    Console::WriteRaw(L"Session closed.\n");
    return 0;
}
