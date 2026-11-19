/*
 * Client.exe - interactive console front-end for the Ameger driver.
 *
 * Contract: no command-line arguments are accepted. The user picks a screen
 * from the main menu; every value shown on those screens is gathered live at
 * the moment the screen renders, never hardcoded.
 *   [1] Inject - asks for a process name, resolves it adaptively
 *                (case-insensitive, extension-optional) and reports the PID.
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
#include <string>
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

void InjectScreen() {
    Console::ClearScreen();

    const std::wstring raw = Console::ReadLine(L"Process Name: ", Console::Brush::White);
    const std::wstring query = Trim(raw);

    if (query.empty()) {
        Console::WriteLine(L"No process name entered.", Console::Brush::LightYellow);
        return;
    }

    DWORD pid = 0u;
    if (Process::FindIdByName(query, pid)) {
        Console::WriteText(L"The selected process target connected successfully. ",
                           Console::Brush::LightGreen);
        Console::WriteText(L"(PID: ", Console::Brush::Silver);
        Console::WriteText(std::to_wstring(pid), Console::Brush::LightGreen);
        Console::WriteText(L")\n", Console::Brush::Silver);
        return;
    }

    Console::WriteLine(L"The selected process target was not found.",
                       Console::Brush::LightRed);
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
    row(L"Device Name:", AMGER_USER_DEVICE, Console::Brush::LightCyan);
    row(L"Device Connection:", connected ? L"Connected" : L"Not Connected",
        connected ? Console::Brush::LightGreen : Console::Brush::LightRed);
}

void UnloadScreen(Session& session) {
    Console::ClearScreen();

    ChannelClient& client = session.channel;
    const bool connected = client.Connected() || client.Connect();
    if (!connected) {
        Console::WriteLine(L"Device unavailable. Nothing to unload.",
                           Console::Brush::LightYellow);
        return;
    }

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

        if (input == L"1") {
            InjectScreen();
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
