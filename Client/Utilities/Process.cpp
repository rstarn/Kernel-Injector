#include "Process.hpp"

#include <cwctype>
#include <tlhelp32.h>

namespace Process {

std::wstring NormalizeQuery(const std::wstring& rawQuery) {
    const size_t begin = rawQuery.find_first_not_of(L" \t\r\n\"'");
    if (begin == std::wstring::npos) {
        return L"";
    }
    size_t end = rawQuery.find_last_not_of(L" \t\r\n\"'");
    if (end == std::wstring::npos) {
        end = rawQuery.size() - 1u;
    }
    std::wstring result = rawQuery.substr(begin, end - begin + 1u);
    for (wchar_t& character : result) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return result;
}

namespace {

std::wstring LowerCopy(const wchar_t* text) {
    std::wstring result;
    if (text == nullptr) {
        return result;
    }
    for (const wchar_t* cursor = text; *cursor != L'\0'; ++cursor) {
        result.push_back(static_cast<wchar_t>(std::towlower(*cursor)));
    }
    return result;
}

bool EndsWithExe(const std::wstring& value) {
    static const wchar_t kExtension[] = L".exe";
    if (value.size() < 4u) {
        return false;
    }
    const size_t offset = value.size() - 4u;
    for (size_t index = 0u; index < 4u; ++index) {
        if (static_cast<wchar_t>(std::towlower(value[offset + index])) != kExtension[index]) {
            return false;
        }
    }
    return true;
}

std::wstring StripExe(const std::wstring& value) {
    return EndsWithExe(value) ? value.substr(0u, value.size() - 4u) : value;
}

}  // namespace

bool MatchesImageName(const std::wstring& normalizedQuery, const std::wstring& imageName) {
    if (normalizedQuery.empty()) {
        return false;
    }
    const std::wstring name = LowerCopy(imageName.c_str());
    if (name.empty()) {
        return false;
    }
    /* Direct match (with or without extension), extension-optional on the
     * query side, and extension-optional on both sides. */
    return normalizedQuery == name ||
           normalizedQuery == StripExe(name) ||
           normalizedQuery + L".exe" == name ||
           StripExe(normalizedQuery) == name ||
           StripExe(normalizedQuery) == StripExe(name);
}

bool FindIdByName(const std::wstring& rawQuery, DWORD& outPid) {
    const std::wstring query = NormalizeQuery(rawQuery);
    if (query.empty()) {
        return false;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0u);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD best = static_cast<DWORD>(-1);

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const std::wstring image = LowerCopy(entry.szExeFile);
            if (MatchesImageName(query, image) && entry.th32ProcessID < best) {
                best = entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (best == static_cast<DWORD>(-1)) {
        return false;
    }
    outPid = best;
    return true;
}

}  // namespace Process
