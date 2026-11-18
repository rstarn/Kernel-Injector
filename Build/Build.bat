@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem Ameger Phase 1 build driver.
rem Usage: Build.bat [BUILD | CLEAN | REBUILD]
rem Outputs:
rem   Build\Output\Client.exe
rem   Build\Output\Driver.sys
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
if exist "%AMGER_OUTPUT%" rmdir /s /q "%AMGER_OUTPUT%"
if exist "%AMGER_OBJECTS%" rmdir /s /q "%AMGER_OBJECTS%"
echo [Ameger] Clean complete.
exit /b 0

:Rebuild
if exist "%AMGER_OUTPUT%" rmdir /s /q "%AMGER_OUTPUT%"
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
    echo [Ameger] ERROR: vcvars64.bat not found. Install Visual Studio 2022 Desktop C++ build tools.
    exit /b 1
)
call "%AMGER_VCVARS%" >nul 2>&1

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

echo [Ameger] WDK %AMGER_WDK_VERSION%

rem --- Client.exe ------------------------------------------------------------
set "AMGER_LOADER_FLAGS=/nologo /W4 /EHsc /std:c++17 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /I"%AMGER_ROOT%\Shared""

cl %AMGER_LOADER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Main.obj" "%AMGER_ROOT%\Loader\Application\Main.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_LOADER_FLAGS% /c /Fo"%AMGER_OBJECTS%\CommandLine.obj" "%AMGER_ROOT%\Loader\Application\CommandLine.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_LOADER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Configuration.obj" "%AMGER_ROOT%\Loader\Configuration\Configuration.cpp"
if errorlevel 1 goto :Failed
cl %AMGER_LOADER_FLAGS% /c /Fo"%AMGER_OBJECTS%\ChannelClient.obj" "%AMGER_ROOT%\Loader\Communication\ChannelClient.cpp"
if errorlevel 1 goto :Failed

link /nologo /subsystem:console /machine:x64 /out:"%AMGER_OUTPUT%\Client.exe" ^
    "%AMGER_OBJECTS%\Main.obj" ^
    "%AMGER_OBJECTS%\CommandLine.obj" ^
    "%AMGER_OBJECTS%\Configuration.obj" ^
    "%AMGER_OBJECTS%\ChannelClient.obj" ^
    kernel32.lib user32.lib
if errorlevel 1 goto :Failed

rem --- Driver.sys ----------------------------------------------------
set "AMGER_DRIVER_FLAGS=/nologo /W4 /TC /GS- /kernel /D_AMD64_=1 /DAMD64=1 /D_WIN64=1 /I"%AMGER_ROOT%\Shared" /I"%AMGER_KM_INCLUDE%" /I"%AMGER_SHARED_INCLUDE%" /I"%AMGER_UCRT_INCLUDE%""

cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\DriverEntry.obj" "%AMGER_ROOT%\Driver\Initialization\Driver.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Bootstrap.obj" "%AMGER_ROOT%\Driver\Initialization\Bootstrap.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Bridge.obj" "%AMGER_ROOT%\Driver\Communication\Bridge.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Dispatcher.obj" "%AMGER_ROOT%\Driver\Communication\Dispatcher.c"
if errorlevel 1 goto :Failed
cl %AMGER_DRIVER_FLAGS% /c /Fo"%AMGER_OBJECTS%\Guard.obj" "%AMGER_ROOT%\Driver\Utilities\Guard.c"
if errorlevel 1 goto :Failed

link /nologo /driver /subsystem:native /machine:x64 /entry:DriverEntry /nodefaultlib /release ^
    /out:"%AMGER_OUTPUT%\Driver.sys" ^
    "%AMGER_OBJECTS%\DriverEntry.obj" ^
    "%AMGER_OBJECTS%\Bootstrap.obj" ^
    "%AMGER_OBJECTS%\Bridge.obj" ^
    "%AMGER_OBJECTS%\Dispatcher.obj" ^
    "%AMGER_OBJECTS%\Guard.obj" ^
    /libpath:"%AMGER_KM_LIB%" ntoskrnl.lib hal.lib
if errorlevel 1 goto :Failed

echo [Ameger] Build complete.
dir "%AMGER_OUTPUT%"
exit /b 0

:Failed
echo [Ameger] BUILD FAILED.
exit /b 1
