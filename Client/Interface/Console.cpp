/*
 * Console.cpp - terminal rendering for Client.exe.
 *
 * Dynamic output policy: no screen redraws happen here except on demand;
 * callers drive every value that is printed. The banner gradient is computed
 * from the widest art line so the blend always spans the full art width,
 * whatever edit is made to the art in the future.
 */

#include "Console.hpp"

#include <Windows.h>
#include <cwchar>
#include <iostream>
#include <string>

namespace Console {
namespace {

HANDLE StdOut() {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

bool g_isConsole = false;
bool g_vt = false;
CONSOLE_SCREEN_BUFFER_INFO g_defaultBufferInfo = {};
WORD g_defaultAttributes = 0x0007u;  // FOREGROUND_RED | GREEN | BLUE

/* Console path writes UTF-16 directly through WriteConsoleW; a codepage can
 * never corrupt the banner. Redirected output falls back to std::wcout. */
void Emit(const std::wstring& text) {
    if (g_isConsole) {
        DWORD written = 0u;
        WriteConsoleW(StdOut(), text.c_str(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    std::wcout << text;
}

struct Rgb {
    unsigned char r;
    unsigned char g;
    unsigned char b;
};

Rgb BrushRgb(Brush brush) {
    switch (brush) {
    case Brush::White:      return {255u, 255u, 255u};
    case Brush::Silver:     return {205u, 205u, 205u};
    case Brush::Gray:       return {128u, 128u, 128u};
    case Brush::LightGreen: return {152u, 251u, 152u};
    case Brush::LightRed:   return {255u, 128u, 128u};
    case Brush::LightYellow:return {255u, 255u, 153u};
    case Brush::LightCyan:  return {153u, 255u, 255u};
    case Brush::Orange:     return {255u, 140u,   0u};
    case Brush::Default:    return {205u, 205u, 205u};
    }
    return {205u, 205u, 205u};
}

WORD BrushAttributes(Brush brush) {
    switch (brush) {
    case Brush::White:
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Brush::Silver:
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    case Brush::Gray:
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    case Brush::LightGreen:
        return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Brush::LightRed:
        return FOREGROUND_RED | FOREGROUND_INTENSITY;
    case Brush::LightYellow:
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Brush::LightCyan:
        return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Brush::Orange:
        return FOREGROUND_RED | FOREGROUND_GREEN;
    case Brush::Default:
        return g_defaultAttributes;
    }
    return g_defaultAttributes;
}

Rgb Lerp(const Rgb from, const Rgb to, double t) {
    if (t < 0.0) {
        t = 0.0;
    } else if (t > 1.0) {
        t = 1.0;
    }
    const auto mix = [t](unsigned char a, unsigned char b) {
        return static_cast<unsigned char>(
            static_cast<double>(a) + (static_cast<double>(b) - static_cast<double>(a)) * t);
    };
    return {mix(from.r, to.r), mix(from.g, to.g), mix(from.b, to.b)};
}

void ApplyTrueColor(const Rgb color) {
    std::wstring sequence = L"\x1b[38;2;";
    sequence += std::to_wstring(color.r);
    sequence += L";";
    sequence += std::to_wstring(color.g);
    sequence += L";";
    sequence += std::to_wstring(color.b);
    sequence += L"m";
    Emit(sequence);
}

void ApplyBrush(Brush brush) {
    if (brush == Brush::Default) {
        Reset();
        return;
    }
    if (g_vt) {
        ApplyTrueColor(BrushRgb(brush));
        return;
    }
    if (g_isConsole) {
        SetConsoleTextAttribute(StdOut(), BrushAttributes(brush));
    }
}

/* Compact 5-row block wordmark for AMGER CLIENT. */

void PrintGradientLine(const std::wstring& line, size_t width) {
    const Rgb orange(BrushRgb(Brush::Orange));
    const Rgb white(BrushRgb(Brush::White));
    size_t index = 0u;

    if (g_vt) {
        for (const wchar_t character : line) {
            const double t = (width > 1u)
                ? static_cast<double>(index) / static_cast<double>(width - 1u)
                : 0.0;
            ApplyTrueColor(Lerp(orange, white, t));
            Emit(std::wstring(1, character));
            ++index;
        }
        Reset();
        Emit(L"\n");
        return;
    }
    if (g_isConsole) {
        Brush current = Brush::Orange;
        SetBrush(current);
        for (const wchar_t character : line) {
            const double t = (width > 1u)
                ? static_cast<double>(index) / static_cast<double>(width - 1u)
                : 0.0;
            const Brush wanted = t < 0.55 ? Brush::Orange : Brush::White;
            if (wanted != current) {
                current = wanted;
                SetBrush(current);
            }
            Emit(std::wstring(1, character));
            ++index;
        }
        Reset();
        Emit(L"\n");
        return;
    }
    Emit(line + L"\n");
}

size_t g_bannerWidth = 76u;

}  // namespace

void Initialize() {
    const HANDLE output = StdOut();
    DWORD mode = 0u;
    g_isConsole = output != INVALID_HANDLE_VALUE &&
                  GetConsoleMode(output, &mode) != FALSE;
    if (g_isConsole) {
        if (GetConsoleScreenBufferInfo(output, &g_defaultBufferInfo) != FALSE) {
            g_defaultAttributes = g_defaultBufferInfo.wAttributes;
        }
        /* The banner uses box-drawing and block glyphs; emit UTF-8 so a
         * legacy console code page cannot corrupt them. */
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        const DWORD wanted = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        g_vt = SetConsoleMode(output, wanted) != FALSE;
    }
}

void Reset() {
    if (g_vt) {
        Emit(L"\x1b[0m");
        return;
    }
    if (g_isConsole) {
        SetConsoleTextAttribute(StdOut(), g_defaultAttributes);
    }
}

void SetBrush(Brush brush) {
    ApplyBrush(brush);
}

void WriteRaw(const std::wstring& text) {
    Emit(text);
}

void WriteText(const std::wstring& text, Brush brush) {
    ApplyBrush(brush);
    Emit(text);
    Reset();
}

void WriteLine(const std::wstring& text, Brush brush) {
    WriteText(text + L"\n", brush);
}

void ClearScreen() {
    /* Clearing never depends on VT escape sequences: some hosts accept
     * ENABLE_VIRTUAL_TERMINAL_PROCESSING but swallow the bytes, which leaves
     * every redraw appended to the previous one. The buffer fill works on
     * every real console regardless of what VT honours. */
    const HANDLE output = StdOut();
    CONSOLE_SCREEN_BUFFER_INFO info = {};
    if (g_isConsole && GetConsoleScreenBufferInfo(output, &info) != FALSE) {
        COORD home = {0, 0};
        const DWORD cells = static_cast<DWORD>(info.dwSize.X) *
                            static_cast<DWORD>(info.dwSize.Y);
        DWORD written = 0u;
        FillConsoleOutputCharacterW(output, L' ', cells, home, &written);
        FillConsoleOutputAttribute(output, g_defaultAttributes, cells, home, &written);
        SetConsoleCursorPosition(output, home);
        return;
    }
    /* Redirected output: fall back to vertical whitespace. */
    Emit(std::wstring(40u, L'\n'));
}

void WriteDivider() {
    WriteText(std::wstring(g_bannerWidth, L'_') + L"\n", Brush::Gray);
}

void RenderBanner() {
    /* Thick ANSI-Shadow wordmark. Width derives from the widest line, never
     * hardcoded; the gradient spans exactly that width. */
    static const wchar_t* const kArt[] = {
        L" █████╗ ███╗   ███╗███████╗ ██████╗ ███████╗██████╗",
        L"██╔══██╗████╗ ████║██╔════╝██╔════╝ ██╔════╝██╔══██╗",
        L"███████║██╔████╔██║█████╗  ██║  ███╗█████╗  ██████╔╝",
        L"██╔══██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══╝  ██╔══██╗",
        L"██║  ██║██║ ╚═╝ ██║███████╗╚██████╔╝███████╗██║  ██║",
        L"╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
        L"",
        L"██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗",
        L"██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗",
        L"██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║   ██║██████╔╝",
        L"██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║   ██║██╔══██╗",
        L"██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║",
        L"╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝",
    };

    size_t width = 0u;
    for (const wchar_t* raw : kArt) {
        const size_t length = wcslen(raw);
        if (length > width) {
            width = length;
        }
    }
    g_bannerWidth = width;

    WriteDivider();
    Emit(L"\n");
    for (const wchar_t* raw : kArt) {
        PrintGradientLine(std::wstring(raw), width);
    }

    Emit(L"\n");
    WriteDivider();
    Emit(L"\n");
}

std::wstring ReadLine(const std::wstring& prompt, Brush promptBrush) {
    if (!prompt.empty()) {
        WriteText(prompt, promptBrush);
    }
    std::wstring line;
    std::getline(std::wcin, line);
    return line;
}

void WaitForEnter(const std::wstring& message) {
    Emit(L"\n");
    WriteText(message, Brush::Gray);
    std::wstring discarded;
    std::getline(std::wcin, discarded);
}

}  // namespace Console
