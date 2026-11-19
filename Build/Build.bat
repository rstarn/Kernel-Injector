@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem Ameger Phase 1 build driver.
rem Usage: Build.bat [BUILD | CLEAN | REBUILD]
rem This script is the single source of truth for compiler flags. The former
rem compile_commands.json is intentionally absent: its per-target commands are
rem the ones below, so nothing can drift from the build.
rem Outputs:
rem   Build\Output\Client.exe
rem   Build\Output\Driver.sys
rem CLEAN/REBUILD remove only these build outputs (plus Build\Objects); every
rem other file in Build\Output (crash dumps, reports, analysis logs) is kept.
rem ===========================================================================

set "AMGER_ROOT=%~dp0.."
set "AMGER_OUTPUT=%AMGER_ROOT%\Build\Output"
set "AMGER_OBJECTS=%AMGER_ROOT%\Build\Objects"
set "AMGER_ACTION=%~1"
if "%AMGER_ACTION%"=="" set "AMGER_ACTION=BUILD"

if /i "%AMGER_ACTION%"=="CLEAN" goto :Clean
if /i "%AMGER_ACTION%"=="REBUILD" goto :Rebuild
if /i "%AMGER_ACTION%"=="BUILD" goto :Build

echo Unknown action: %AMGER_ACTION%
echo Usage: Build.bat [BUILD ^| CLEAN ^| REBUILD]
exit /b 1

:Clean
rem Build outputs only; Build\Output itself and any other files in it are kept.
if exist "%AMGER_OUTPUT%\Client.exe" del /q "%AMGER_OUTPUT%\Client.exe"
if exist "%AMGER_OUTPUT%\Driver.sys" del /q "%AMGER_OUTPUT%\Driver.sys"
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"
if exist "%AMGER_OBJECTS%" rmdir /s /q "%AMGER_OBJECTS%"
echo [Ameger] Clean complete.
exit /b 0

:Rebuild
if exist "%AMGER_OUTPUT%\Client.exe" del /q "%AMGER_OUTPUT%\Client.exe"
if exist "%AMGER_OUTPUT%\Driver.sys" del /q "%AMGER_OUTPUT%\Driver.sys"
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"
if exist "%AMGER_OBJECTS%" rmdir /s /q "%AMGER_OBJECTS%"

:Build
if not exist "%AMGER_OUTPUT%" mkdir "%AMGER_OUTPUT%"
if not exist "%AMGER_OBJECTS%" mkdir "%AMGER_OBJECTS%"

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
    echo [Ameger] ERROR: vcvars64.bat not found. Install Visual Studio Build Tools with the v145 C++ toolset.
    exit /b 1
)
call "%AMGER_VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [Ameger] ERROR: Visual Studio environment initialization failed.
    exit /b 1
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
    exit /b 1
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
    kernel32.lib user32.lib
if errorlevel 1 goto :Failed

rem Remove a sidecar left by an older build; Output must contain binaries only.
if exist "%AMGER_OUTPUT%\Client.exe.manifest" del /q "%AMGER_OUTPUT%\Client.exe.manifest"

rem Embed the source manifest with requireAdministrator so the client matches the device DACL.
mt.exe -nologo -manifest "%AMGER_ROOT%\Build\Client.exe.manifest" "-outputresource:%AMGER_OUTPUT%\Client.exe;#1"
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
    "%AMGER_OBJECTS%\Guard.obj" ^
    /libpath:"%AMGER_KM_LIB%" ntoskrnl.lib hal.lib BufferOverflowK.lib
if errorlevel 1 goto :Failed

echo [Ameger] Build complete.
dir "%AMGER_OUTPUT%"
exit /b 0

:WdkMissing
echo [Ameger] ERROR: WDK %AMGER_WDK_VERSION% is incomplete (headers or x64 kernel libraries missing).
exit /b 1

:Failed
echo [Ameger] BUILD FAILED.
exit /b 1
