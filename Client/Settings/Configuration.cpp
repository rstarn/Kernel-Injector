#include "Configuration.hpp"

#include <Windows.h>

#include "../../Shared/Protocol.h"

Configuration::Configuration()
    : pingRequested(false),
      connectOnly(false),
      bootstrapPath(AMGER_BOOTSTRAP_PATH) {
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
