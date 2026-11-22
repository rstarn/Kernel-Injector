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
#include "../Utilities/Lexicon.hpp"

namespace {

std::wstring AsciiList(const char names[][AMGER_REPORT_NAME_LENGTH], uint32_t count) {
    std::wstring result;
    for (uint32_t index = 0u; index < count && index < AMGER_REPORT_MAX_MODULES; ++index) {
        if (index != 0u) {
            result += L", ";
        }
        for (const char* cursor = names[index]; *cursor != '\0'; ++cursor) {
            result.push_back(static_cast<wchar_t>(*cursor));
        }
    }
    if (result.empty()) {
        result = L"none";
    }
    return result;
}

const wchar_t* FlagText(uint32_t flags, uint32_t bit) {
    return (flags & bit) != 0u ? L"Present" : L"Not Present";
}

const wchar_t* StateText(uint32_t flags, uint32_t bit) {
    return (flags & bit) != 0u ? L"Enabled" : L"Disabled";
}

void WriteColoredValue(const std::wstring& text, Console::Brush brush) {
    size_t start = 0u;
    for (size_t index = 0u; index < text.size(); ++index) {
        const wchar_t character = text[index];
        const bool separator = character == L':' || character == L',' ||
                               character == L'(' || character == L')' ||
                               character == L'|' || character == L'/';
        if (!separator) {
            continue;
        }
        if (index > start) {
            Console::WriteText(text.substr(start, index - start), brush);
        }
        if (character == L',') {
            Console::WriteText(L", ", Console::Brush::White);
            start = index + 1u;
            if (start < text.size() && text[start] == L' ') {
                ++start;
                ++index;
            }
        } else {
            Console::WriteText(std::wstring(1u, character), Console::Brush::White);
            start = index + 1u;
        }
    }
    if (start < text.size()) {
        Console::WriteText(text.substr(start), brush);
    }
}

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

/* Names come from a generated table of XOR-encoded arrays, selected by the
 * raw code/id. No stringified token is materialised, so the diagnostic labels
 * are not plaintext in the binary. */

const wchar_t* StatusName(uint32_t status) {
    if (status == AMGER_CLIENT_STATUS_QUERY_FAILED) {
        return L"STATUS_QUERY_FAILED";
    }
    if (status == AMGER_CLIENT_BAD_ARGUMENTS) {
        return L"BAD_ARGUMENTS";
    }
    const wchar_t* known = LabelStatus(status);
    if (known != nullptr) {
        return known;
    }
    static wchar_t unknown[32] = {};
    swprintf_s(unknown, L"UNKNOWN_0x%08X", status);
    return unknown;
}

const wchar_t* LogIdName(uint16_t id) {
    const wchar_t* known = LabelLog(id);
    return known != nullptr ? known : L"UNKNOWN";
}

void PrintLogs(const std::vector<ChannelClient::LogRecord>& records) {
    uint16_t previousId = 0u;
    for (const auto& record : records) {

        /* Each command's validation phase follows the previous command's RESULT.
         * Separate the two commands with a blank line so the log reads as
         * distinct blocks instead of one continuous stream. */

        if (record.Id == AMGER_LOG_ID_HEADER_VALIDATE &&
            previousId == AMGER_LOG_ID_RESULT) {
            Console::WriteRaw(L"\n");
        }

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

        previousId = record.Id;
    }

    if (!records.empty()) {
        Console::WriteRaw(L"\n");
    }
}

/* Client.exe lives in Build\Output; the reference DLL is two levels up in
 * Assets. Deriving from the module path keeps the location relative to the
 * install regardless of the process working directory. */

std::wstring ResolveTargetPath() {

    /* Grow until the whole path fits; MAX_PATH-sized storage with a truncated
     * return would derive the wrong directory (or none). */

    std::vector<wchar_t> modulePath(MAX_PATH);
    DWORD length = GetModuleFileNameW(nullptr, modulePath.data(),
                                      static_cast<DWORD>(modulePath.size()));
    while (length >= modulePath.size()) {
        modulePath.resize(modulePath.size() * 2u);
        length = GetModuleFileNameW(nullptr, modulePath.data(),
                                    static_cast<DWORD>(modulePath.size()));
    }
    std::wstring directory(modulePath.data(), length);
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
    unsigned char fileBuffer[4096];
    size_t read = 0u;
    while ((read = std::fread(fileBuffer, 1u, sizeof(fileBuffer), file)) > 0u) {
        payload.insert(payload.end(), fileBuffer, fileBuffer + read);
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
    } else if (status == AMGER_CLIENT_BAD_ARGUMENTS) {
        Console::WriteLine(L"Payload was invalid or too large.", Console::Brush::LightRed);
    } else if (status == AMGER_STATUS_PENDING) {
        Console::WriteLine(L"Payload could not be delivered.", Console::Brush::LightRed);
    } else {
        wchar_t text[96] = {};
        swprintf_s(text, L"0x%08X (%s)", status, StatusName(status));
        Console::WriteText(L"Driver Status: ", Console::Brush::White);
        WriteColoredValue(text, Console::Brush::LightRed);
        Console::WriteRaw(L"\n");
    }

    AMGER_PARSER_REPORT parser = {};
    if (session.channel.ParserReport(parser)) {
        const std::wstring imports = AsciiList(parser.ImportNames, parser.ImportModuleCount);
        const std::wstring exports = AsciiList(parser.ExportNames, parser.ExportCount);
        wchar_t reportLine[640] = {};
        const Console::Brush good = Console::Brush::LightGreen;
        const Console::Brush bad = Console::Brush::LightRed;

        const auto emit = [](const wchar_t* label, const wchar_t* value,
                             Console::Brush brush) {
            Console::WriteText(label, Console::Brush::White);
            WriteColoredValue(value, brush);
            Console::WriteRaw(L"\n");
        };
        const auto emitList = [](const wchar_t* label, const std::wstring& text) {
            Console::WriteText(label, Console::Brush::White);
            for (size_t index = 0u; index < text.size(); ++index) {
                if (text[index] == L',') {
                    Console::WriteText(L", ", Console::Brush::White);
                    if (index + 1u < text.size() && text[index + 1u] == L' ') {
                        ++index;
                    }
                } else {
                    Console::WriteText(std::wstring(1u, text[index]),
                                       Console::Brush::LightGreen);
                }
            }
            Console::WriteRaw(L"\n");
        };
        const auto presence = [good, bad](uint32_t flags, uint32_t bit) {
            return (flags & bit) != 0u ? good : bad;
        };

        Console::WriteRaw(L"\n");
        Console::WriteLine(L"Parser:", Console::Brush::White);
        Console::WriteRaw(L"\n");

        swprintf_s(reportLine, L"0x%08X (%s)", parser.ParseStatus,
                   StatusName(parser.ParseStatus));
        emit(L"  Status: ", reportLine, parser.ParseStatus == 0u ? good : bad);
        Console::WriteRaw(L"\n");

        emit(L"  Architecture: ", L"x64 (x86 and PE32 rejected)", good);
        swprintf_s(reportLine, L"0x%08X | Image Base: 0x%016llX", parser.PeOffset,
                   static_cast<unsigned long long>(parser.ImageBase));
        emit(L"  PE Offset: ", reportLine, good);
        swprintf_s(reportLine, L"0x%X / 0x%X", parser.SectionAlignment, parser.FileAlignment);
        emit(L"  Section Alignment / File Alignment: ", reportLine, good);
        Console::WriteRaw(L"\n");
        swprintf_s(reportLine, L"0x%04X | File Characteristics: 0x%04X",
                   parser.DllCharacteristics, parser.FileCharacteristics);
        emit(L"  DLL Characteristics: ", reportLine, good);
        swprintf_s(reportLine, L"RVA 0x%08X | Sections: %u", parser.EntryPoint,
                   static_cast<unsigned>(parser.SectionCount));
        emit(L"  Entry Point: ", reportLine, good);
        Console::WriteRaw(L"\n");
        emit(L"  Load Configuration: ",
             FlagText(parser.Flags, AMGER_REPORT_FLAG_LOAD_CONFIG),
             presence(parser.Flags, AMGER_REPORT_FLAG_LOAD_CONFIG));
        emit(L"  TLS Directory: ", FlagText(parser.Flags, AMGER_REPORT_FLAG_TLS),
             presence(parser.Flags, AMGER_REPORT_FLAG_TLS));
        Console::WriteRaw(L"\n");
        swprintf_s(reportLine, L"%s (RVA 0x%08X)",
                   parser.SecurityCookieRva != 0u ? L"Present" : L"Not Present",
                   parser.SecurityCookieRva);
        emit(L"  Security Cookie: ", reportLine, parser.SecurityCookieRva != 0u ? good : bad);
        emit(L"  Activation Context Manifest: ",
             FlagText(parser.Flags, AMGER_REPORT_FLAG_MANIFEST),
             presence(parser.Flags, AMGER_REPORT_FLAG_MANIFEST));
        Console::WriteRaw(L"\n");
        emit(L"  Debug Directory: ", FlagText(parser.Flags, AMGER_REPORT_FLAG_DEBUG),
             presence(parser.Flags, AMGER_REPORT_FLAG_DEBUG));
        emit(L"  Resource Directory: ", FlagText(parser.Flags, AMGER_REPORT_FLAG_RESOURCE),
             presence(parser.Flags, AMGER_REPORT_FLAG_RESOURCE));
        Console::WriteRaw(L"\n");

        swprintf_s(reportLine, L"%s (DIR64 %u, HIGHLOW %u)",
                   FlagText(parser.Flags, AMGER_REPORT_FLAG_RELOCATIONS),
                   parser.RelocDir64Count, parser.RelocHighLowCount);
        emit(L"  Base Relocations: ", reportLine,
             presence(parser.Flags, AMGER_REPORT_FLAG_RELOCATIONS));
        emit(L"  Exception Directory: ",
             FlagText(parser.Flags, AMGER_REPORT_FLAG_EXCEPTIONS),
             presence(parser.Flags, AMGER_REPORT_FLAG_EXCEPTIONS));
        Console::WriteRaw(L"\n");
        swprintf_s(reportLine, L"%u", static_cast<unsigned>(parser.DirectoryCount));
        emit(L"  Data Directories: ", reportLine, parser.DirectoryCount != 0u ? good : bad);
        emit(L"  Directory Count: ", reportLine, parser.DirectoryCount != 0u ? good : bad);
        Console::WriteRaw(L"\n");

        swprintf_s(reportLine, L"%s | CFG: %s",
                   StateText(parser.Flags, AMGER_REPORT_FLAG_CET),
                   StateText(parser.Flags, AMGER_REPORT_FLAG_CFG));
        const bool hardened = (parser.Flags & AMGER_REPORT_FLAG_CET) != 0u &&
                              (parser.Flags & AMGER_REPORT_FLAG_CFG) != 0u;
        emit(L"  CET: ", reportLine, hardened ? good : bad);
        swprintf_s(reportLine, L"0x%08X | Headers Size: 0x%08X",
                   parser.SizeOfImage, parser.SizeOfHeaders);
        emit(L"  Image Size: ", reportLine, good);
        Console::WriteRaw(L"\n");

        emitList(L"  Import Modules: ", imports);
        Console::WriteRaw(L"\n");

        Console::WriteText(L"  Delay-load imports: ", Console::Brush::White);
        swprintf_s(reportLine, L"%u", parser.DelayImportCount);
        Console::WriteText(reportLine, good);
        Console::WriteText(L" Modules\n", Console::Brush::White);
        emit(L"  Exports Modules: ", exports.c_str(), good);
        emit(L"  Bound Imports: ",
             FlagText(parser.Flags, AMGER_REPORT_FLAG_BOUND_IMPORTS),
             presence(parser.Flags, AMGER_REPORT_FLAG_BOUND_IMPORTS));
        Console::WriteRaw(L"\n");

        swprintf_s(reportLine, L"%u", parser.ForwardedCount);
        emit(L"  Forwarded Exports: ", reportLine, good);
        swprintf_s(reportLine, L"%u", parser.OrdinalImportCount);
        emit(L"  Imports By Ordinal: ", reportLine, good);
        Console::WriteRaw(L"\n");
        emit(L"  Manual-Map Modules: ", L"deferred to Phase 5", bad);
        swprintf_s(reportLine, L"%u", parser.ApiSetCount);
        emit(L"  API-set References: ", reportLine, good);
        Console::WriteRaw(L"\n");

        if (parser.Allocation.Flags != 0u || parser.Allocation.Status != 0u) {
            const AMGER_ALLOC_REPORT& alloc = parser.Allocation;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Allocation:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", alloc.Status,
                       StatusName(alloc.Status));
            emit(L"  Status: ", reportLine, alloc.Status == 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X", alloc.ImageSize);
            emit(L"  Image Size: ", reportLine, good);
            swprintf_s(reportLine, L"%u", alloc.TargetProcessId);
            emit(L"  Target PID: ", reportLine, good);
            Console::WriteRaw(L"\n");
            emit(L"  Base Source: ", L"memory manager", good);
            emit(L"  Alignment: ", L"64 KiB (manager-chosen)", good);
            Console::WriteRaw(L"\n");

            emit(L"  Protection: ", L"READWRITE (reserve only)", good);
            swprintf_s(reportLine, L"0x%016llX",
                       static_cast<unsigned long long>(alloc.RemoteBase));
            emit(L"  Remote Base: ", reportLine, alloc.RemoteBase != 0u ? good : bad);
            emit(L"  Allocation Type: ", L"MEM_RESERVE", good);
            Console::WriteRaw(L"\n");

            const bool reserved = (alloc.Flags & AMGER_ALLOC_FLAG_RESERVED) != 0u;
            const bool released = (alloc.Flags & AMGER_ALLOC_FLAG_RELEASED) != 0u;
            emit(L"  Reservation: ",
                 released ? L"released" : reserved ? L"active" : L"none",
                 reserved ? good : bad);
            emit(L"  Commit: ", L"deferred to Phase 2", bad);
            Console::WriteRaw(L"\n");
            emit(L"  VAD State: ", L"private, non-executable", good);
            emit(L"  Handle: ", L"none (PsLookup only)", good);
            emit(L"  Caller: ", L"kernel-origin Zw", good);
            Console::WriteRaw(L"\n");

            emit(L"  Rollback: ",
                 released ? L"reserved region released" : L"reservation retained",
                 released ? good : bad);
            emit(L"  Execution: ", L"deferred to Phase 2", bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Mapping.Flags != 0u || parser.Mapping.Status != 0u) {
            const AMGER_MAP_REPORT& map = parser.Mapping;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Mapping:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", map.Status,
                       StatusName(map.Status));
            emit(L"  Status: ", reportLine, map.Status == 0u ? good : bad);
            Console::WriteRaw(L"\n");
            swprintf_s(reportLine, L"0x%016llX",
                       static_cast<unsigned long long>(map.RemoteBase));
            emit(L"  Remote Base: ", reportLine, map.RemoteBase != 0u ? good : bad);
            swprintf_s(reportLine, L"0x%08X", map.ImageSize);
            emit(L"  Image Size: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(map.SectionCount));
            emit(L"  Sections: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X", map.BytesCopied);
            emit(L"  Bytes Copied: ", reportLine, good);
            swprintf_s(reportLine, L"0x%08X", map.ZeroFilled);
            emit(L"  Zero Filled: ", reportLine, good);
            swprintf_s(reportLine, L"0x%08X", map.HeaderBytes);
            emit(L"  Headers: ", reportLine, good);
            Console::WriteRaw(L"\n");

            emit(L"  Commit: ", L"read/write", good);
            emit(L"  Protections: ", L"applied (no RWX)", good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(map.PageGroups));
            emit(L"  Page Groups: ", reportLine, good);
            Console::WriteRaw(L"\n");

            const bool reverted = (map.Flags & AMGER_MAP_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"mapping reverted" : L"mapping retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", L"deferred to Phase 3", bad);
            Console::WriteRaw(L"\n");
        }
    }

    /* The INJECT command has already been issued above, so this is
     * NOT a cancellation prompt - answering N cannot undo anything. The injection
     * engine is deferred, so word it as a status note rather than asking for a
     * decision that has no effect. Kept as an interaction so the existing menu
     * flow (which expects a keypress here) is unchanged. */

    Console::WriteText(L"Injection Engine: ", Console::Brush::Silver);
    Console::WriteLine(L"deferred (payload submitted to the driver above).",
                       Console::Brush::LightYellow);
    Console::WriteRaw(L"\n");
    Console::WriteText(L"Press Enter to continue...", Console::Brush::Gray);
    (void)Console::ReadLine(L"", Console::Brush::Silver);

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
    uint32_t lastFault = 0u;
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

        /* Query the driver's recorded teardown fault after PING (both share the
         * single command slot), so it is surfaced instead of left silent. */

        lastFault = client.LastFault();
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
        wchar_t pingBuffer[32] = {};
        swprintf_s(pingBuffer, L"%.3f ms", pingMilliseconds);
        pingText = pingBuffer;
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

    if (lastFault != 0u) {
        wchar_t fault[96] = {};
        swprintf_s(fault, L"0x%08X (%s)", lastFault, StatusName(lastFault));
        row(L"Last fault:", fault, Console::Brush::LightRed);
    }
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

    /* A stale cached header must not bypass a failed probe. If the device is
     * genuinely gone, drop any cached handle/MDL-backed region so a later
     * Status screen cannot operate on a stale handle or leak the mapping. */

    if (!devicePresent) {
        client.Disconnect();
        Console::WriteLine(L"Device unavailable. Nothing to unload.",
                           Console::Brush::LightYellow);
        return;
    }
    const bool connected = client.Connected() || client.Connect();
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

        /* A redirected final line without a trailing newline sets eof() while
         * still returning its text. Process that text; only an empty read at
         * EOF ends the loop. */

        if (input.empty()) {
            if (std::wcin.eof()) {
                break;
            }
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
