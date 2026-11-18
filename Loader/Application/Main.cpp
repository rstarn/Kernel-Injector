/*
 * Loader.exe entry point for Phase 1.
 *
 * Contract: parse options, locate the driver-written bootstrap file, connect
 * to the random GUID device, and optionally perform one PING round-trip.
 * Inputs: wmain argc/argv; Phase 1 flags --ping, --connect-only,
 * --bootstrap-path.
 * Outputs: process exit code 0 on success, 1 on any failure.
 * Failure modes: a missing bootstrap file, an unopenable device, or a PING
 * timeout each produce exit code 1 with a diagnostic on stdout.
 */

#include <Windows.h>
#include <iostream>
#include <string>

#include "CommandLine.hpp"
#include "../Configuration/Configuration.hpp"
#include "../Communication/ChannelClient.hpp"

namespace {

bool FileExists(const std::wstring& path) {
    return !path.empty() &&
           GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

/* The driver writes to the system temp directory because kernel mode cannot
 * expand %TEMP%. Try the configured path first, then that well-known fallback. */
std::wstring ResolveBootstrapFile(const Configuration& configuration) {
    std::wstring path = configuration.ResolvedBootstrapPath();
    if (FileExists(path)) {
        return path;
    }

    DWORD required = ExpandEnvironmentStringsW(
        L"%SystemRoot%\\Temp\\AmegerBootstrap.txt", nullptr, 0u);
    if (required != 0u) {
        std::wstring fallback(required, L'\0');
        const DWORD written = ExpandEnvironmentStringsW(
            L"%SystemRoot%\\Temp\\AmegerBootstrap.txt", &fallback[0], required);
        if (written != 0u && written <= required) {
            fallback.resize(written - 1u);
            if (FileExists(fallback)) {
                return fallback;
            }
        }
    }

    return path;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    Configuration configuration;
    if (!CommandLine::Process(argc, argv, configuration)) {
        return 1;
    }

    if (!configuration.pingRequested && !configuration.connectOnly) {
        CommandLine::PrintUsage();
        return 1;
    }

    const std::wstring bootstrapFile = ResolveBootstrapFile(configuration);
    if (bootstrapFile.empty() || !FileExists(bootstrapFile)) {
        std::wcerr << L"[-] Bootstrap file not found (STATUS_OBJECT_NAME_NOT_FOUND): "
                   << bootstrapFile << std::endl;
        return 1;
    }

    ChannelClient client;
    if (!client.Connect(bootstrapFile)) {
        std::wcerr << L"[-] Failed to connect to bootstrap device" << std::endl;
        return 1;
    }

    if (configuration.connectOnly) {
        std::wcout << L"[+] Connected; bootstrap device consumed" << std::endl;
        client.Disconnect();
        return 0;
    }

    const bool pingSucceeded = client.Ping(configuration.timeoutMilliseconds);
    client.Disconnect();

    if (!pingSucceeded) {
        std::wcerr << L"[-] PING failed or timed out" << std::endl;
        return 1;
    }

    std::wcout << L"[+] PING round-trip succeeded" << std::endl;
    return 0;
}
