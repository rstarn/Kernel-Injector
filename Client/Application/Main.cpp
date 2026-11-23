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
                               character == L'|' || character == L'/' ||
                               character == L'[' || character == L']' ||
                               character == L'-' || character == L'>' ||
                               character == L'@' || character == L'=';
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

/* Stage codes travel with the phase reports, so a failed inject explains
 * which kernel pass rejected it instead of showing a bare NTSTATUS. */

const wchar_t* MapStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_MAP_STAGE_NONE: return L"none";
    case AMGER_MAP_STAGE_PARAMETERS: return L"parameters";
    case AMGER_MAP_STAGE_PROCESS: return L"process lookup";
    case AMGER_MAP_STAGE_COMMIT: return L"commit";
    case AMGER_MAP_STAGE_MDL: return L"MDL lock";
    case AMGER_MAP_STAGE_COPY: return L"section copy";
    case AMGER_MAP_STAGE_PROTECT: return L"protection seal";
    default: return L"unknown";
    }
}

const wchar_t* RelocStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_RELOC_STAGE_NONE: return L"none";
    case AMGER_RELOC_STAGE_PARAMETERS: return L"parameters";
    case AMGER_RELOC_STAGE_PROCESS: return L"process lookup";
    case AMGER_RELOC_STAGE_MDL: return L"MDL lock";
    case AMGER_RELOC_STAGE_DIRECTORY: return L"reloc directory";
    case AMGER_RELOC_STAGE_BLOCK: return L"reloc block";
    case AMGER_RELOC_STAGE_ENTRY: return L"reloc entry";
    default: return L"unknown";
    }
}

const wchar_t* ImportStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_IMPORT_STAGE_NONE: return L"none";
    case AMGER_IMPORT_STAGE_PARAMETERS: return L"parameters";
    case AMGER_IMPORT_STAGE_PEB: return L"PEB / process";
    case AMGER_IMPORT_STAGE_APISET: return L"ApiSet schema";
    case AMGER_IMPORT_STAGE_MDL: return L"MDL lock";
    case AMGER_IMPORT_STAGE_DESCRIPTOR: return L"import descriptor";
    case AMGER_IMPORT_STAGE_MODULE: return L"module lookup";
    case AMGER_IMPORT_STAGE_EXPORT: return L"export table";
    case AMGER_IMPORT_STAGE_FORWARD: return L"forwarded export";
    case AMGER_IMPORT_STAGE_IAT: return L"IAT write";
    case AMGER_IMPORT_STAGE_DELAY: return L"delay import";
    case AMGER_IMPORT_STAGE_BOUND: return L"bound import clear";
    default: return L"unknown";
    }
}

const wchar_t* DepStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_DEP_STAGE_NONE: return L"none";
    case AMGER_DEP_STAGE_PARAMETERS: return L"parameters";
    case AMGER_DEP_STAGE_FILE: return L"kernel file read";
    case AMGER_DEP_STAGE_PARSE: return L"dependency PE parse";
    case AMGER_DEP_STAGE_ALLOCATE: return L"dependency reserve";
    case AMGER_DEP_STAGE_MAP: return L"dependency map";
    case AMGER_DEP_STAGE_RELOCATE: return L"dependency relocations";
    case AMGER_DEP_STAGE_REGISTER: return L"dependency register";
    case AMGER_DEP_STAGE_IMPORT: return L"dependency imports";
    case AMGER_DEP_STAGE_ROUND: return L"round limit";
    default: return L"unknown";
    }
}

const wchar_t* EntryStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_ENTRY_STAGE_NONE: return L"none";
    case AMGER_ENTRY_STAGE_PARAMETERS: return L"parameters";
    case AMGER_ENTRY_STAGE_PROCESS: return L"process lookup";
    case AMGER_ENTRY_STAGE_ENTRY_RVA: return L"entry RVA";
    case AMGER_ENTRY_STAGE_EXPORT: return L"export lookup";
    case AMGER_ENTRY_STAGE_FORWARD: return L"forwarder";
    case AMGER_ENTRY_STAGE_CALL: return L"CRT entry call";
    case AMGER_ENTRY_STAGE_WIPE: return L"header erase";
    case AMGER_ENTRY_STAGE_VERIFY: return L"erase verification";
    default: return L"unknown";
    }
}

const wchar_t* InitStageName(uint32_t stage) {
    switch (stage) {
    case AMGER_INIT_STAGE_NONE: return L"none";
    case AMGER_INIT_STAGE_PARAMETERS: return L"parameters";
    case AMGER_INIT_STAGE_PROCESS: return L"process lookup";
    case AMGER_INIT_STAGE_LOAD_CONFIG: return L"load config";
    case AMGER_INIT_STAGE_COOKIE: return L"security cookie";
    case AMGER_INIT_STAGE_ACTIVATION: return L"activation context";
    case AMGER_INIT_STAGE_TLS_INDEX: return L"TLS index";
    case AMGER_INIT_STAGE_TLS_CALLBACK: return L"TLS callbacks";
    case AMGER_INIT_STAGE_THREAD_TLS: return L"thread TLS";
    case AMGER_INIT_STAGE_ROUTINES: return L"routine resolution";
    case AMGER_INIT_STAGE_PC_DETOUR: return L"PC-to-file detour";
    case AMGER_INIT_STAGE_PDATA: return L"exception table";
    case AMGER_INIT_STAGE_CFG: return L"CFG retarget";
    case AMGER_INIT_STAGE_APC: return L"user APC";
    default: return L"unknown";
    }
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
    } else {
        wchar_t text[96] = {};
        swprintf_s(text, L"0x%08X (%s)", status, StatusName(status));
        Console::WriteText(L"Driver Status: ", Console::Brush::White);
        WriteColoredValue(text, Console::Brush::LightRed);
        Console::WriteRaw(L"\n");
    }

    /* A client-side rejection never issued an IOCTL, so any report still in
     * the shared area belongs to an earlier injection and must not be shown. */
    const bool clientRejected =
        status == AMGER_CLIENT_BAD_ARGUMENTS ||
        status == AMGER_CLIENT_REGION_FAILED ||
        status == AMGER_CLIENT_KICK_FAILED;

    AMGER_PARSER_REPORT parser = {};
    if (!clientRejected && session.channel.ParserReport(parser)) {
        const std::wstring importList = AsciiList(parser.ImportNames, parser.ImportModuleCount);
        const std::wstring exports = AsciiList(parser.ExportNames, parser.ExportCount);
        wchar_t reportLine[640] = {};
        const Console::Brush good = Console::Brush::LightGreen;
        const Console::Brush bad = Console::Brush::LightRed;
        /* Phase 7 now runs the CRT entry even though Phase 8 is deferred, so
         * the execution row must reflect the measured entry state, not the
         * top-level status. */
        const bool entryCalled =
            (parser.Entry.Flags & AMGER_ENTRY_FLAG_CALLED) != 0u;
        const wchar_t* executionText =
            entryCalled ? L"entry called; phase 8 pending" : L"not reached";

        /* Read the dependency module count once from the local report copy
         * and use it in both blocks, so the two rendered lines cannot disagree. */

        const unsigned manualMapModules =
            static_cast<unsigned>(parser.Dependencies.ModulesMapped);

        const auto emit = [](const wchar_t* label, const wchar_t* value,
                             Console::Brush brush) {
            Console::WriteText(label, Console::Brush::White);
            WriteColoredValue(value, brush);
            Console::WriteRaw(L"\n");
        };
        const auto emitList = [](const wchar_t* label, const std::wstring& text) {
            /* "none" is the empty-list fallback from AsciiList, not a measured
             * name. Paint it neutrally so it is not mistaken for a real value. */
            const Console::Brush brush = text == L"none" ? Console::Brush::Gray
                                                        : Console::Brush::LightGreen;
            Console::WriteText(label, Console::Brush::White);
            for (size_t index = 0u; index < text.size(); ++index) {
                if (text[index] == L',') {
                    Console::WriteText(L", ", Console::Brush::White);
                    if (index + 1u < text.size() && text[index + 1u] == L' ') {
                        ++index;
                    }
                } else {
                    Console::WriteText(std::wstring(1u, text[index]), brush);
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

        /* Parse success implies AMD64/PE32+: the parser rejects other machine
         * types and PE32. A failed or empty parse cannot support that claim. */
        const bool architectureVerified =
            parser.ParseStatus == 0u && parser.SectionCount != 0u;
        emit(L"  Architecture: ",
             architectureVerified ? L"x64 (PE32+, AMD64 only)" : L"unverified",
             architectureVerified ? good : bad);
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
        Console::WriteRaw(L"\n");

        /* The CET flag describes the image's PE-declared CET compatibility,
         * not a measured process mitigation state. */
        swprintf_s(reportLine, L"%s | CFG: %s",
                   StateText(parser.Flags, AMGER_REPORT_FLAG_CET_COMPAT),
                   StateText(parser.Flags, AMGER_REPORT_FLAG_CFG));
        const bool hardened = (parser.Flags & AMGER_REPORT_FLAG_CET_COMPAT) != 0u &&
                              (parser.Flags & AMGER_REPORT_FLAG_CFG) != 0u;
        emit(L"  CET Compat: ", reportLine, hardened ? good : bad);
        swprintf_s(reportLine, L"0x%08X | Headers Size: 0x%08X",
                   parser.SizeOfImage, parser.SizeOfHeaders);
        emit(L"  Image Size: ", reportLine, good);
        Console::WriteRaw(L"\n");

        emitList(L"  Import Modules: ", importList);
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
        swprintf_s(reportLine, L"%u", manualMapModules);
        emit(L"  Manual-Map Modules: ", reportLine, good);
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
            const bool aligned = alloc.RemoteBase != 0u &&
                                 (alloc.RemoteBase & 0xFFFFu) == 0u;
            swprintf_s(reportLine, aligned ? L"64 KiB" : L"unaligned");
            emit(L"  Alignment: ", reportLine, aligned ? good : bad);
            swprintf_s(reportLine, L"0x%016llX",
                       static_cast<unsigned long long>(alloc.RemoteBase));
            emit(L"  Remote Base: ", reportLine, alloc.RemoteBase != 0u ? good : bad);
            Console::WriteRaw(L"\n");

            const bool reserved = (alloc.Flags & AMGER_ALLOC_FLAG_RESERVED) != 0u;
            const bool released = (alloc.Flags & AMGER_ALLOC_FLAG_RELEASED) != 0u;
            const bool committed =
                (parser.Mapping.Flags & AMGER_MAP_FLAG_COMMITTED) != 0u;
            emit(L"  Reservation: ",
                 released ? L"released" : reserved ? L"active" : L"none",
                 reserved ? good : bad);
            emit(L"  Commit: ", committed ? L"read/write" : L"not committed",
                 committed ? good : bad);
            Console::WriteRaw(L"\n");

            emit(L"  Rollback: ",
                 released ? L"reserved region released" : L"reservation retained",
                 released ? good : bad);
            emit(L"  Execution: ", executionText, bad);
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
            if (map.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", map.FailureStage,
                           MapStageName(map.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
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

            const bool committed = (map.Flags & AMGER_MAP_FLAG_COMMITTED) != 0u;
            const bool sealed = (map.Flags & AMGER_MAP_FLAG_PROTECTED) != 0u;
            emit(L"  Commit: ", committed ? L"read/write" : L"not committed",
                 committed ? good : bad);
            /* Flag-derived state only: no rendered field measures the actual
             * page protections. PageGroups is reported separately below. */
            emit(L"  Protections: ", sealed ? L"applied" : L"pending",
                 sealed ? good : bad);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(map.PageGroups));
            emit(L"  Page Groups: ", reportLine, sealed ? good : bad);
            Console::WriteRaw(L"\n");

            const bool reverted = (map.Flags & AMGER_MAP_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"mapping reverted" : L"mapping retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", executionText, bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Relocation.Flags != 0u || parser.Relocation.Status != 0u) {
            const AMGER_RELOC_REPORT& reloc = parser.Relocation;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Relocations:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", reloc.Status,
                       StatusName(reloc.Status));
            emit(L"  Status: ", reportLine, reloc.Status == 0u ? good : bad);
            if (reloc.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", reloc.FailureStage,
                           RelocStageName(reloc.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X", reloc.RelocRva);
            emit(L"  Directory RVA: ", reportLine, good);
            swprintf_s(reportLine, L"0x%08X", reloc.RelocSize);
            emit(L"  Directory Size: ", reportLine, good);
            swprintf_s(reportLine, L"0x%016llX",
                       static_cast<unsigned long long>(reloc.Delta));
            emit(L"  Base Delta: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(reloc.BlockCount));
            emit(L"  Blocks: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(reloc.FixupCount));
            emit(L"  Fixups: ", reportLine, good);
            Console::WriteRaw(L"\n");
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(reloc.HighLowCount));
            emit(L"  HIGHLOW: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(reloc.Dir64Count));
            emit(L"  DIR64: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(reloc.SkippedCount));
            emit(L"  Skipped (ABSOLUTE): ", reportLine, good);
            Console::WriteRaw(L"\n");

            const bool sealed = (parser.Mapping.Flags & AMGER_MAP_FLAG_PROTECTED) != 0u;
            emit(L"  Seal State: ", sealed ? L"applied" : L"pending",
                 sealed ? good : bad);
            Console::WriteRaw(L"\n");

            const bool reverted =
                (reloc.Flags & AMGER_RELOC_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"mapping reverted" : L"mapping retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", executionText, bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Imports.Flags != 0u || parser.Imports.Status != 0u) {
            const AMGER_IMPORT_REPORT& imports = parser.Imports;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Imports:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", imports.Status,
                       StatusName(imports.Status));
            emit(L"  Status: ", reportLine, imports.Status == 0u ? good : bad);
            if (imports.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", imports.FailureStage,
                           ImportStageName(imports.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.ModuleCount));
            emit(L"  Modules: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.DelayModuleCount));
            emit(L"  Delayed Modules: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.FunctionsResolved));
            emit(L"  Functions Resolved: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.ByNameCount));
            emit(L"  By Name: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.ByOrdinalCount));
            emit(L"  By Ordinal: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.ForwardedCount));
            emit(L"  Forwarded: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.ApiSetRedirectCount));
            emit(L"  API-Set Redirects: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.UnresolvedCount));
            emit(L"  Unresolved: ", reportLine,
                 imports.UnresolvedCount == 0u ? good : bad);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.LookupErrors));
            emit(L"  Lookup Errors: ", reportLine,
                 imports.LookupErrors == 0u ? good : bad);
            if (imports.DeferredCount != 0u) {
                swprintf_s(reportLine, L"%S", imports.DeferredModule);
                emit(L"  Pending: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            const bool boundCleared =
                (imports.Flags & AMGER_IMPORT_FLAG_BOUND_CLEARED) != 0u;
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(imports.DeferredModuleCount));
            emit(L"  Pending Modules: ", reportLine,
                 imports.DeferredModuleCount == 0u ? good : bad);
            emit(L"  Bound Imports: ", boundCleared ? L"cleared" : L"not cleared",
                 boundCleared ? good : bad);
            Console::WriteRaw(L"\n");

            const bool reverted =
                (imports.Flags & AMGER_IMPORT_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"mapping reverted" : L"mapping retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", executionText, bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Dependencies.Flags != 0u || parser.Dependencies.Status != 0u) {
            const AMGER_DEP_REPORT& dep = parser.Dependencies;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Dependencies:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", dep.Status,
                       StatusName(dep.Status));
            emit(L"  Status: ", reportLine, dep.Status == 0u ? good : bad);
            if (dep.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", dep.FailureStage,
                           DepStageName(dep.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.DeferredBefore));
            emit(L"  Deferred Before: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.DeferredAfter));
            emit(L"  Deferred After: ", reportLine,
                 dep.DeferredAfter == 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.ReboundFunctions));
            emit(L"  Rebound Functions: ", reportLine, good);
            swprintf_s(reportLine, L"%u",
                       static_cast<unsigned>(dep.DependencyImportsResolved));
            emit(L"  Dependency Imports: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%016llX",
                       static_cast<unsigned long long>(dep.BytesRead));
            emit(L"  Bytes Read: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.FileOpens));
            emit(L"  File Opens: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", manualMapModules);
            emit(L"  Manually Mapped: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.ModulesRegistered));
            emit(L"  Modules Registered: ", reportLine, good);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.Rounds));
            emit(L"  Rounds: ", reportLine, good);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.Failures));
            emit(L"  Failures: ", reportLine,
                 dep.Failures == 0u ? good : bad);
            swprintf_s(reportLine, L"%u", static_cast<unsigned>(dep.Cycles));
            emit(L"  Cycles Skipped: ", reportLine,
                 dep.Cycles == 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u -> %u",
                       static_cast<unsigned>(dep.LoaderEntriesBefore),
                       static_cast<unsigned>(dep.LoaderEntriesAfter));
            emit(L"  Loader Entries: ", reportLine,
                 dep.LoaderEntriesBefore == dep.LoaderEntriesAfter ? good : bad);
            Console::WriteRaw(L"\n");

            if (dep.MappedNameCount != 0u) {
                Console::WriteText(L"  Mapped Modules:", Console::Brush::White);
                Console::WriteRaw(L"\n");
                Console::WriteRaw(L"\n");
                for (unsigned index = 0u;
                     index < dep.MappedNameCount &&
                     index < AMGER_DEP_REPORT_MAX_NAMES;
                     ++index) {
                    swprintf_s(reportLine, L"[%u] %hs @ 0x%016llX", index,
                               dep.MappedNames[index],
                               static_cast<unsigned long long>(
                                   dep.Bases[index]));
                    emit(L"    ", reportLine, good);
                }
                Console::WriteRaw(L"\n");
            }

            const bool reverted =
                (dep.Flags & AMGER_DEP_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"dependencies released" : L"dependencies retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", executionText, bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Initialization.Flags != 0u ||
            parser.Initialization.Status != 0u) {
            const AMGER_INIT_REPORT& init = parser.Initialization;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Initialization:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", init.Status,
                       StatusName(init.Status));
            emit(L"  Status: ", reportLine, init.Status == 0u ? good : bad);
            if (init.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", init.FailureStage,
                           InitStageName(init.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"RVA 0x%08X | 0x%08X bytes | struct 0x%08X",
                       init.LoadConfigRva, init.LoadConfigSize, init.StructSize);
            emit(L"  Load Config: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_LOAD_CONFIG) != 0u ? good : bad);
            swprintf_s(reportLine, L"0x%08X", init.GuardFlags);
            emit(L"  Guard Flags: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_LOAD_CONFIG) != 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"RVA 0x%08X | low 0x%08X",
                       init.CookieRva, init.CookieLow);
            emit(L"  Security Cookie: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_COOKIE) != 0u ? good : bad);
            /* STATUS_NOT_FOUND means no manifest; STATUS_NOT_SUPPORTED means a
             * manifest was measured but not activated: the mapper resolves
             * imports in Phase 4 and has no loader data entry for the loader's
             * LoadLibrary-time activation context. Only a malformed tree is an
             * error. */
            swprintf_s(reportLine,
                       L"0x%08X | State = %u / Id = %u | %u bytes | Hash = 0x%08X",
                       init.ActivationStatus, init.ManifestState,
                       init.ManifestId, init.ManifestBytes, init.ManifestHash);
            const bool activationOk =
                init.ActivationStatus == 0u ||
                init.ActivationStatus == 0xC0000225u ||
                init.ActivationStatus == 0xC00000BBu;
            emit(L"  Activation Context: ", reportLine,
                 activationOk ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", init.TlsCallbackCount);
            emit(L"  TLS Callbacks: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_TLS_CALLBACK) != 0u ? good : bad);
            swprintf_s(reportLine, L"%u | %u bytes", init.TlsIndex,
                       init.TlsRawBytes);
            emit(L"  TLS Index: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_TLS_INDEX) != 0u ? good : bad);
            swprintf_s(reportLine,
                       L"Size = %u / Buffer = 0x%016llX / Bits = %08X%08X%s",
                       init.TlsBitmapSize,
                       static_cast<unsigned long long>(init.TlsBitmapBuffer),
                       init.TlsBitmapBits0, init.TlsBitmapBits1,
                       init.TlsIndex >= 64u ? L" (expansion)" : L"");
            emit(L"  TLS Bitmap: ", reportLine,
                 init.TlsBitmapBuffer != 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u", init.ThreadsPatched);
            emit(L"  TEB Slots Set: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_THREAD_TLS) != 0u ? good : bad);
            if (init.ThreadsPatched == 0u) {
                swprintf_s(reportLine, L"Reasons = 0x%08X / Snapshot = %u",
                           init.TlsThreadSkipMask, init.TlsSnapshotCount);
                emit(L"  Thread Probe: ", reportLine, bad);
            }
            swprintf_s(reportLine,
                       L"0x%08X | Create = %u / Delete = %u / Dropped = %u",
                       init.ThreadNotifyStatus, init.ThreadCreateSeen,
                       init.ThreadDeleteSeen, init.ThreadEventsDropped);
            emit(L"  Thread Notify: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_THREAD_NOTIFY) != 0u ? good : bad);
            swprintf_s(reportLine,
                       L"Attach Queued = %u / Failed = %u | Detach Observed = %u",
                       init.ThreadAttachQueued, init.ThreadAttachFailed,
                       init.ThreadDetachObserved);
            emit(L"  Thread Callbacks: ", reportLine,
                 init.ThreadAttachFailed == 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u / %u", init.RoutinesResolved,
                       init.RoutineCount);
            emit(L"  Routines Resolved: ", reportLine,
                 init.RoutinesResolved == init.RoutineCount ? good : bad);
            swprintf_s(reportLine, L"%u / %u", init.ApcRuns, init.ApcFailures);
            emit(L"  User APC Runs/Failures: ", reportLine,
                 init.ApcFailures == 0u ? good : bad);
            swprintf_s(reportLine,
                       L"Started = %u / Completion = 0x%08X / Boosters = %u",
                       init.ApcStubStarted, init.ApcCompletionValue,
                       init.ApcBoosters);
            emit(L"  APC Diagnostics: ", reportLine,
                 init.ApcStubStarted != 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u tables / %u entries", init.PdataTables,
                       init.PdataEntries);
            emit(L"  Exception Tables: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_PDATA) != 0u ? good : bad);

            swprintf_s(reportLine, L"%u bytes @ 0x%016llX", init.DetourBytes,
                       static_cast<unsigned long long>(init.DetourAddress));
            emit(L"  PC-to-File Detour: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_PC_DETOUR) != 0u ? good : bad);

            swprintf_s(reportLine, L"0x%016llX -> 0x%016llX",
                       static_cast<unsigned long long>(init.CfgCheckBefore),
                       static_cast<unsigned long long>(init.CfgCheckAfter));
            emit(L"  CFG Check Pointer: ", reportLine,
                 (init.Flags & AMGER_INIT_FLAG_CFG) != 0u ? good : bad);
            Console::WriteRaw(L"\n");

            const bool reverted =
                (init.Flags & AMGER_INIT_FLAG_REVERTED) != 0u;
            emit(L"  Rollback: ",
                 reverted ? L"initialization reverted" : L"initialization retained",
                 reverted ? good : bad);
            emit(L"  Execution: ", executionText, bad);
            Console::WriteRaw(L"\n");
        }

        if (parser.Entry.Flags != 0u || parser.Entry.Status != 0u) {
            const AMGER_ENTRY_REPORT& entry = parser.Entry;

            Console::WriteRaw(L"\n");
            Console::WriteLine(L"Entry:", Console::Brush::White);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"0x%08X (%s)", entry.Status,
                       StatusName(entry.Status));
            emit(L"  Status: ", reportLine, entry.Status == 0u ? good : bad);
            if (entry.Status != 0u) {
                swprintf_s(reportLine, L"0x%08X (%s)", entry.FailureStage,
                           EntryStageName(entry.FailureStage));
                emit(L"  Failure Stage: ", reportLine, bad);
            }
            Console::WriteRaw(L"\n");

            const wchar_t* kind = L"unknown";
            if (entry.EntryKind == AMGER_ENTRY_KIND_PE_ENTRY) {
                kind = L"PE (CRT startup)";
            } else if (entry.EntryKind == AMGER_ENTRY_KIND_EXPORT_NAME) {
                kind = L"named export";
            } else if (entry.EntryKind == AMGER_ENTRY_KIND_ORDINAL) {
                kind = L"ordinal export";
            }
            emit(L"  Kind: ", kind,
                 entry.EntryKind <= AMGER_ENTRY_KIND_ORDINAL ? good : bad);
            swprintf_s(reportLine, L"RVA 0x%08X @ 0x%016llX", entry.EntryRva,
                       static_cast<unsigned long long>(entry.EntryAddress));
            emit(L"  Resolved Entry: ", reportLine,
                 (entry.Flags & AMGER_ENTRY_FLAG_RESOLVED) != 0u ? good : bad);
            if (entry.EntryKind == AMGER_ENTRY_KIND_EXPORT_NAME) {
                swprintf_s(reportLine, L"%S", entry.EntryName);
                emit(L"  Export Name: ", reportLine, good);
            } else if (entry.EntryKind == AMGER_ENTRY_KIND_ORDINAL) {
                swprintf_s(reportLine, L"%u", entry.EntryOrdinal);
                emit(L"  Export Ordinal: ", reportLine, good);
            }
            Console::WriteRaw(L"\n");

            /* A FALSE return is a measured payload result (flagged by the
             * driver), not a failed engine call. The brush tracks whether the
             * call itself completed and was measured. */
            const bool crtFalse =
                (entry.Flags & AMGER_ENTRY_FLAG_CRT_FALSE) != 0u;
            swprintf_s(reportLine, L"0x%08X%s", entry.EntryResult,
                       crtFalse ? L" (payload refused attach)" : L"");
            emit(L"  CRT Result: ", reportLine,
                 (entry.Flags & AMGER_ENTRY_FLAG_CALLED) != 0u ? good : bad);
            swprintf_s(reportLine,
                       L"%u / %u | Started = %u / Completion = 0x%08X",
                       entry.ApcRuns, entry.ApcFailures, entry.ApcStubStarted,
                       entry.ApcCompletionValue);
            emit(L"  APC: ", reportLine,
                 entry.ApcFailures == 0u ? good : bad);
            Console::WriteRaw(L"\n");

            swprintf_s(reportLine, L"%u bytes | Signature Zero = %u",
                       entry.BytesWiped, entry.HeaderSignatureZeroVerified);
            emit(L"  Header Erase: ", reportLine,
                 (entry.Flags & AMGER_ENTRY_FLAG_WIPED) != 0u ? good : bad);
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
    /* Surface dispatcher records for the unload IOCTL, as InjectScreen and
     * StatusScreen already do for their commands. */
    PrintLogs(client.DrainLogs());
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
