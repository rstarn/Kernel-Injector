#include "CommandLine.hpp"

#include <Windows.h>
#include <iostream>

bool CommandLine::Process(int argc, wchar_t** argv, Configuration& configuration) {
    if (!configuration.ParseFromCommandLine(argc, argv)) {
        std::wcerr << L"[-] Missing value for --bootstrap-path" << std::endl;
        return false;
    }

    for (int index = 1; index < argc; ++index) {
        const std::wstring argument(argv[index]);
        if (argument == L"--ping" || argument == L"/ping" ||
            argument == L"--connect-only" || argument == L"/connect-only") {
            continue;
        }
        if (argument == L"--bootstrap-path" || argument == L"/bootstrap-path") {
            ++index;
            continue;
        }
        std::wcout << L"[!] Unrecognized argument: " << argument << std::endl;
    }

    return true;
}

void CommandLine::PrintUsage() {
    std::wcout << L"Usage: Loader.exe [--ping] [--connect-only] "
                  L"[--bootstrap-path <path>]" << std::endl;
}
