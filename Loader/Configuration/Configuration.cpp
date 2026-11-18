#include "Configuration.hpp"

#include <Windows.h>
#include <fstream>
#include <sstream>

#include "../../Shared/Protocol.h"

Configuration::Configuration()
    : pingRequested(false),
      connectOnly(false),
      bootstrapPath(AMGER_BOOTSTRAP_PATH),
      timeoutMilliseconds(500u) {
}

bool Configuration::ParseFromCommandLine(int argc, wchar_t** argv) {
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument(argv[index]);

        if (argument == L"--ping" || argument == L"/ping") {
            pingRequested = true;
            continue;
        }

        if (argument == L"--connect-only" || argument == L"/connect-only") {
            connectOnly = true;
            continue;
        }

        if (argument == L"--bootstrap-path" || argument == L"/bootstrap-path") {
            if (index + 1 >= argc) {
                return false;
            }
            bootstrapPath = argv[++index];
            continue;
        }
    }

    return true;
}

bool Configuration::LoadFromFile(const std::wstring& path) {
    std::wifstream stream(path.c_str());
    if (!stream.is_open()) {
        return false;
    }

    std::wstring line;
    while (std::getline(stream, line)) {
        const std::wstring::size_type separator = line.find(L'=');
        if (separator == std::wstring::npos) {
            continue;
        }

        const std::wstring key = line.substr(0, separator);
        const std::wstring value = line.substr(separator + 1);

        if (key == L"Ping") {
            pingRequested = (value == L"1" || value == L"true");
        } else if (key == L"ConnectOnly") {
            connectOnly = (value == L"1" || value == L"true");
        } else if (key == L"BootstrapPath") {
            bootstrapPath = value;
        } else if (key == L"TimeoutMilliseconds") {
            try {
                timeoutMilliseconds = static_cast<uint32_t>(std::stoul(value));
            } catch (...) {
                return false;
            }
        }
    }

    return true;
}

std::wstring Configuration::ResolvedBootstrapPath() const {
    const DWORD required = ExpandEnvironmentStringsW(bootstrapPath.c_str(), nullptr, 0u);
    if (required == 0u) {
        return L"";
    }

    std::wstring expanded(required, L'\0');
    const DWORD written = ExpandEnvironmentStringsW(
        bootstrapPath.c_str(), &expanded[0], required);
    if (written == 0u || written > required) {
        return L"";
    }

    expanded.resize(written - 1u);
    return expanded;
}
