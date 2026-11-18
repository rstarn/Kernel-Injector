#pragma once

/*
 * Command.hpp - argv translation for Client.exe.
 *
 * Contract: converts the Phase 1 command line into an Configuration.
 * Inputs: standard wmain argc/argv.
 * Outputs: populated configuration returned by reference.
 * Failure modes: returns false when a flag that requires a value is missing;
 * unknown arguments are ignored with a warning printed to stdout.
 */

#include "../Settings/Configuration.hpp"

class CommandLine {
public:
    /*
     * Contract: translates Phase 1 flags into the configuration object.
     * Inputs: wmain argc/argv and a configuration to populate.
     * Outputs: true when arguments are usable; configuration populated.
     * Failure modes: false when a value-taking flag is missing; unknown
     * arguments are ignored and reported on stdout.
     */
    static bool Process(int argc, wchar_t** argv, Configuration& configuration);

    /*
     * Contract: writes the accepted flag list to stdout.
     * Inputs: none. Outputs: one usage line. Failure modes: none.
     */
    static void PrintUsage();
};
