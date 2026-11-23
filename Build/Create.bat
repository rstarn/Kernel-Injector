@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem Ameger build driver.
rem Usage: Create.bat [BUILD | CLEAN | REBUILD]
rem This script is the single source of truth for compiler flags. The former
rem compile_commands.json is intentionally absent: its per-target commands are
rem the ones below, so nothing can drift from the build.
rem Outputs:
rem   Build\Output\Client.exe
rem   Build\Output\Driver.sys
rem CLEAN/REBUILD remove only these build outputs (plus Build\Output\Objects); every
rem other file in Build\Output (crash dumps, reports, analysis logs) is kept.
rem ===========================================================================

set "AMGER_ROOT=%~dp0.."
set "AMGER_OUTPUT=%AMGER_ROOT%\Build\Output"
set "AMGER_OBJECTS=%AMGER_ROOT%\Build\Output\Objects"
set "AMGER_ACTION=%~1"
if "%AMGER_ACTION%"=="" set "AMGER_ACTION=BUILD"

rem Exit code carried to :Finish, which pauses so a double-clicked window does
rem not vanish before the result (or an error) can be read.
set "AMGER_EXIT=0"

if /i "%AMGER_ACTION%"=="CLEAN" goto :Clean
if /i "%AMGER_ACTION%"=="REBUILD" goto :Rebuild
if /i "%AMGER_ACTION%"=="BUILD" goto :Build

echo Unknown action: %AMGER_ACTION%
echo Usage: Create.bat [BUILD ^| CLEAN ^| REBUILD]
set "AMGER_EXIT=1"
goto :Finish

:Clean
rem Build outputs only; Build\Output itself and any other files in it are kept.
if exist "%AMGER_OUTPUT%\Client.exe" del /q "%AMGER_OUTPUT%\Client.exe"
if exist "%AMGER_OUTPUT%\Driver.sys" del /q "%AMGER_OUTPUT%\Driver.sys"
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"
if exist "%AMGER_OBJECTS%" rmdir /s /q "%AMGER_OBJECTS%"
echo [Ameger] Clean complete.
goto :Finish

:Rebuild
if exist "%AMGER_OUTPUT%\Client.exe" del /q "%AMGER_OUTPUT%\Client.exe"
if exist "%AMGER_OUTPUT%\Driver.sys" del /q "%AMGER_OUTPUT%\Driver.sys"
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"
if exist "%AMGER_OBJECTS%" rmdir /s /q "%AMGER_OBJECTS%"

:Build
if not exist "%AMGER_OUTPUT%" mkdir "%AMGER_OUTPUT%"
if not exist "%AMGER_OBJECTS%" mkdir "%AMGER_OBJECTS%"

rem --- Regenerate obfuscated label header from Shared\Protocol.h -------------
rem Lexicon.hpp holds XOR-encoded diagnostic labels; regenerating it here keeps
rem it reproducible from the protocol tables instead of hand-maintained.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%AMGER_ROOT%\Build\Scripts\Lexicon.ps1" "%AMGER_ROOT%"
if errorlevel 1 (
    echo [Ameger] ERROR: Lexicon.ps1 failed.
    set "AMGER_EXIT=1"
    goto :Finish
)

rem --- Locate the Visual Studio x64 build environment -----------------------
set "AMGER_VCVARS="
for /d %%v in ("C:\Program Files\Microsoft Visual Studio\2022\*") do (
    if exist "%%~v\VC\Auxiliary\Build\vcvars64.bat" set "AMGER_VCVARS=%%~v\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined AMGER_VCVARS (
    for /d %%v in ("C:\Program Files (x86)\Microsoft Visual Studio\*") do (
        if exist "%%~v\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "AMGER_VCVARS=%%~v\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
        if exist "%%~v\Community\VC\Auxiliary\Build\vcvars64.bat" set "AMGER_VCVARS=%%~v\Community\VC\Auxiliary\Build\vcvars64.bat"
        if exist "%%~v\Professional\VC\Auxiliary\Build\vcvars64.bat" set "AMGER_VCVARS=%%~v\Professional\VC\Auxiliary\Build\vcvars64.bat"
        if exist "%%~v\Enterprise\VC\Auxiliary\Build\vcvars64.bat" set "AMGER_VCVARS=%%~v\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )
)
if not defined AMGER_VCVARS (
    echo [Ameger] ERROR: vcvars64.bat not found. Install Visual Studio 2022 with the C++ toolset.
    set "AMGER_EXIT=1"
    goto :Finish
)
call "%AMGER_VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [Ameger] ERROR: Visual Studio environment initialization failed.
    set "AMGER_EXIT=1"
    goto :Finish
)
where cl.exe >nul 2>&1
if errorlevel 1 goto :Failed
where link.exe >nul 2>&1
if errorlevel 1 goto :Failed
where mt.exe >nul 2>&1
if errorlevel 1 goto :Failed

rem --- Locate the newest installed WDK ---------------------------------------
set "AMGER_WDK_VERSION="
for /f "delims=" %%i in ('dir /b /ad /o-n "C:\Program Files (x86)\Windows Kits\10\Include" 2^>nul ^| findstr /r "^10\."') do (
    if not defined AMGER_WDK_VERSION set "AMGER_WDK_VERSION=%%i"
)
if not defined AMGER_WDK_VERSION (
    echo [Ameger] ERROR: WDK kernel headers not found.
    set "AMGER_EXIT=1"
    goto :Finish
)

set "AMGER_KM_INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include\%AMGER_WDK_VERSION%\km"
set "AMGER_SHARED_INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include\%AMGER_WDK_VERSION%\shared"
set "AMGER_UCRT_INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include\%AMGER_WDK_VERSION%\ucrt"
set "AMGER_KM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%AMGER_WDK_VERSION%\km\x64"

if not exist "%AMGER_KM_INCLUDE%\ntddk.h" goto :WdkMissing
if not exist "%AMGER_SHARED_INCLUDE%\ntdef.h" goto :WdkMissing
if not exist "%AMGER_UCRT_INCLUDE%\stdio.h" goto :WdkMissing
if not exist "%AMGER_KM_LIB%\ntoskrnl.lib" goto :WdkMissing

echo [Ameger] WDK %AMGER_WDK_VERSION%

rem --- Client.exe ------------------------------------------------------------
set "AMGER_CLIENT_FLAGS=/nologo /W4 /EHsc /std:c++17 /utf-8 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /I"%AMGER_ROOT%\Shared""

cl %AMGER_CLIENT_FLAGS% /c /Fo"%AMGER_OBJECTS%\Main.obj" "%AMGER_ROOT%\Client\Application\Main.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_CLIENT_FLAGS% /c /Fo"%AMGER_OBJECTS%\Console.obj" "%AMGER_ROOT%\Client\Interface\Console.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_CLIENT_FLAGS% /c /Fo"%AMGER_OBJECTS%\Process.obj" "%AMGER_ROOT%\Client\Utilities\Process.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_CLIENT_FLAGS% /c /Fo"%AMGER_OBJECTS%\Channel.obj" "%AMGER_ROOT%\Client\Transport\Channel.cpp"
if errorlevel 1 goto :Failed

rem Drop any stale binary first so a failed link cannot leave it looking fresh.
if exist "%AMGER_OUTPUT%\Client.exe" del /q "%AMGER_OUTPUT%\Client.exe"
rem Disable linker manifest generation so no sidecar is written to Build\Output.
link /nologo /subsystem:console /machine:x64 /manifest:no /out:"%AMGER_OUTPUT%\Client.exe" ^
    "%AMGER_OBJECTS%\Main.obj" ^
    "%AMGER_OBJECTS%\Console.obj" ^
    "%AMGER_OBJECTS%\Process.obj" ^
    "%AMGER_OBJECTS%\Channel.obj" ^
    kernel32.lib user32.lib advapi32.lib
if errorlevel 1 goto :Failed

rem Remove a sidecar left by an older build; Output must contain binaries only.
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"

rem Embed the source manifest with requireAdministrator so the client matches the device DACL.
mt.exe -nologo -manifest "%AMGER_ROOT%\Build\Project\Client.exe.manifest" "-outputresource:%AMGER_OUTPUT%\Client.exe;#1"
if errorlevel 1 goto :Failed

rem --- Driver.sys ----------------------------------------------------
set "AMGER_DRIVER_FLAGS=/nologo /W4 /TC /std:c17 /GS /kernel /D_AMD64_=1 /DAMD64=1 /D_WIN64=1 /DNTDDI_VERSION=0x0A000000 /I"%AMGER_ROOT%\Shared" /I"%AMGER_KM_INCLUDE%" /I"%AMGER_SHARED_INCLUDE%" /I"%AMGER_UCRT_INCLUDE%""

cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\DriverEntry.obj" "%AMGER_ROOT%\Driver\Initialization\Driver.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Bootstrap.obj" "%AMGER_ROOT%\Driver\Initialization\Startup\Bootstrap.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Bridge.obj" "%AMGER_ROOT%\Driver\Communication\Endpoint\Bridge.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Dispatcher.obj" "%AMGER_ROOT%\Driver\Communication\Routing\Dispatcher.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Injector.obj" "%AMGER_ROOT%\Driver\Execution\Injector.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Allocate.obj" "%AMGER_ROOT%\Driver\Execution\Reserve\Allocate.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Sections.obj" "%AMGER_ROOT%\Driver\Execution\Mapping\Sections.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Fixups.obj" "%AMGER_ROOT%\Driver\Execution\Relocate\Fixups.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Lookup.obj" "%AMGER_ROOT%\Driver\Execution\Imports\Lookup.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Resolve.obj" "%AMGER_ROOT%\Driver\Execution\Imports\Binding\Resolve.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Images.obj" "%AMGER_ROOT%\Driver\Execution\Dependencies\Images.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Graph.obj" "%AMGER_ROOT%\Driver\Execution\Dependencies\Table\Graph.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Runtime.obj" "%AMGER_ROOT%\Driver\Execution\Initialize\Runtime.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Format.obj" "%AMGER_ROOT%\Driver\Utilities\Parser\Format.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Guard.obj" "%AMGER_ROOT%\Driver\Utilities\Guard.c"
if errorlevel 1 goto :Failed

rem Drop any stale binary first so a failed link cannot leave it looking fresh.
if exist "%AMGER_OUTPUT%\Driver.sys" del /q "%AMGER_OUTPUT%\Driver.sys"
rem INIT holds the entry point and import descriptors; the mapper must map all sections.
link /nologo /driver /subsystem:native /machine:x64 /entry:GsDriverEntry /nodefaultlib /release ^
    /out:"%AMGER_OUTPUT%\Driver.sys" ^
    "%AMGER_OBJECTS%\DriverEntry.obj" ^
    "%AMGER_OBJECTS%\Bootstrap.obj" ^
    "%AMGER_OBJECTS%\Bridge.obj" ^
    "%AMGER_OBJECTS%\Dispatcher.obj" ^
    "%AMGER_OBJECTS%\Injector.obj" ^
    "%AMGER_OBJECTS%\Allocate.obj" ^
    "%AMGER_OBJECTS%\Sections.obj" ^
    "%AMGER_OBJECTS%\Fixups.obj" ^
    "%AMGER_OBJECTS%\Lookup.obj" ^
    "%AMGER_OBJECTS%\Resolve.obj" ^
    "%AMGER_OBJECTS%\Images.obj" ^
    "%AMGER_OBJECTS%\Graph.obj" ^
    "%AMGER_OBJECTS%\Runtime.obj" ^
    "%AMGER_OBJECTS%\Format.obj" ^
    "%AMGER_OBJECTS%\Guard.obj" ^
    /libpath:"%AMGER_KM_LIB%" ntoskrnl.lib hal.lib BufferOverflowK.lib
if errorlevel 1 goto :Failed

rem --- Verify the shipped binaries on every successful build ---------------
rem Verify.bat exits 0 on all-pass and 1 on any failed check. It has its own
rem setlocal, so call is required: a bare invocation would transfer control and
rem never return to this script. CLEAN never reaches this point (it jumps to
rem :Finish), so verification only runs on BUILD/REBUILD outputs that exist.
if not exist "%AMGER_ROOT%\Build\Scripts\Verify.bat" (
    echo [Ameger] ERROR: Verify.bat not found.
    set "AMGER_EXIT=1"
    goto :Finish
)
echo [Ameger] Verifying shipped binaries...
call "%AMGER_ROOT%\Build\Scripts\Verify.bat"
if errorlevel 1 (
    echo [Ameger] ERROR: static verification failed.
    set "AMGER_EXIT=1"
    goto :Finish
)

echo [Ameger] Build complete.
dir "%AMGER_OUTPUT%"
goto :Finish

:WdkMissing
echo [Ameger] ERROR: WDK %AMGER_WDK_VERSION% is incomplete (headers or x64 kernel libraries missing).
set "AMGER_EXIT=1"
goto :Finish

:Failed
echo [Ameger] BUILD FAILED.
set "AMGER_EXIT=1"
goto :Finish

:Finish
rem Keep the window open on double-click so the build result can be read.
rem Automation can set AMGER_NO_PAUSE=1 to skip the pause, which blocks scripts.
echo.
if /i "%AMGER_NO_PAUSE%"=="" pause
exit /b %AMGER_EXIT%
