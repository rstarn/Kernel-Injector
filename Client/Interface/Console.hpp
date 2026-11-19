#pragma once

/*
 * Console.hpp - interactive console presentation for Client.exe.
 *
 * Contract: owns everything that reaches the terminal — clearing, colors,
 * the gradient banner, prompts and line input. All rendering goes through
 * this translation unit so the menu screens stay free of Win32 details.
 * Colors degrade to 16-color console attributes when virtual terminal
 * processing is unavailable, and to plain text when output is redirected.
 * Inputs: none beyond the calls below. Outputs: writes to stdout, reads one
 * line from stdin. Failure modes: none reported; callers always get a string.
 */

#include <string>

namespace Console {

/* Semantic colors. Orange anchors the banner gradient; the rest are used
 * for labels (Silver/Gray), values and state results. */
enum class Brush {
    Default,      // console default foreground
    White,        // bright white
    Silver,       // normal white
    Gray,         // dim gray
    LightGreen,   // good / connected / success
    LightRed,     // bad / not connected / failure
    LightYellow,  // degraded / warning
    LightCyan,    // informational values
    Orange,       // banner gradient anchor / menu accents
};

/* Best-effort startup: enables virtual terminal processing when the attached
 * console supports it. Must be called once before any other call. */
void Initialize();

void ClearScreen();
void Reset();
void SetBrush(Brush brush);

/* Writes text without changing colors. Same console/redirected path as the
 * colored writes; intended for raw spacing and plain notes. */
void WriteRaw(const std::wstring& text);

/* Writes text in the given brush and restores the default brush afterwards. */
void WriteText(const std::wstring& text, Brush brush);
void WriteLine(const std::wstring& text, Brush brush);

/* Gradient banner (orange -> white, left to right) followed by a divider. */
void RenderBanner();
void WriteDivider();

/* Prints the prompt in the given brush, then reads one line from stdin. */
std::wstring ReadLine(const std::wstring& prompt, Brush promptBrush = Brush::White);

/* Prints a dim message and waits for the user to press Enter. */
void WaitForEnter(const std::wstring& message = L"Press Enter to return to the menu...");

}  // namespace Console
