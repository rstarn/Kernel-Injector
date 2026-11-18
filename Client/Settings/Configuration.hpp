#pragma once

/*
 * Configuration.hpp - user-mode injection settings.
 *
 * Contract: value object holding Phase 1 client options, with defaults drawn
 * from Protocol.h. No kernel headers are used.
 * Inputs: command line only.
 * Outputs: normalized bootstrap path via ResolvedBootstrapPath.
 * Failure modes: ParseFromCommandLine returns false on a missing value.
 */

#include <cstdint>
#include <string>

struct Configuration {
    bool pingRequested;
    bool connectOnly;
    std::wstring bootstrapPath;

    /*
     * Contract: installs Phase 1 defaults (no flags, system-temp bootstrap
     * path). Inputs: none. Outputs: initialized object.
     * Failure modes: none; allocation failure in std::wstring throws.
     */
    Configuration();

    /*
     * Contract: reads --ping, --connect-only and --bootstrap-path <value>.
     * Inputs: wmain argc/argv. Outputs: mutated configuration.
     * Failure modes: false when --bootstrap-path has no following value.
     */
    bool ParseFromCommandLine(int argc, wchar_t** argv);

    /*
     * Contract: expands %VARIABLE% references in bootstrapPath.
     * Inputs: none beyond object state. Outputs: expanded path, or L"".
     * Failure modes: L"" when ExpandEnvironmentStringsW fails.
     */
    std::wstring ResolvedBootstrapPath() const;
};
