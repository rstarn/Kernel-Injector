#pragma once

/*
 * Process.hpp - adaptive process lookup by image name.
 *
 * Contract: resolves a user-typed process name to a process identifier for
 * the Inject flow. Matching is case-insensitive and extension-optional, so
 * "notepad", "NOTEPAD.EXE" and "notepad.exe" all resolve to the same image.
 * Whitespace around the query is ignored. Inputs: raw user text.
 * Outputs: true with the lowest matching PID written to outPid, or false when
 * no process matches. Failure modes: a failed snapshot yields false, never an
 * exception.
 */

#include <string>
#include <Windows.h>

namespace Process {

/* Returns true when the candidate image name satisfies the normalized query:
 * case-insensitive exact match, with or without a trailing ".exe" on either
 * side. Not a substring or fuzzy match; ambiguity is impossible by design. */
bool MatchesImageName(const std::wstring& normalizedQuery, const std::wstring& imageName);

/* Trims surrounding whitespace and lowercases the query; empty when the query
 * has no usable characters. */
std::wstring NormalizeQuery(const std::wstring& rawQuery);

/* Finds the lowest PID whose image name satisfies NormalizeQuery +
 * MatchesImageName at snapshot time. Returns false and leaves outPid untouched
 * when nothing matches or the snapshot cannot be taken. */
bool FindIdByName(const std::wstring& rawQuery, DWORD& outPid);

}  // namespace Process
