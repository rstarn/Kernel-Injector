@echo off
setlocal enabledelayedexpansion
rem ===========================================================================
rem Verify.bat - static stealth/consistency checks on the shipped binaries.
rem Lives in Build\Scripts\.
rem Usage: Verify.bat
rem Checks: no product brand strings, no plaintext diagnostic labels in the
rem client, no Event Log API in the driver, and both binaries present.
rem Exits 0 on all-pass, 1 on any failure.
rem ===========================================================================

set "AMGER_ROOT=%~dp0..\.."
set "OUT=%AMGER_ROOT%\Build\Output"
set "DRIVER=%OUT%\Driver.sys"
set "CLIENT=%OUT%\Client.exe"
set "FAILED=0"

echo [Verify] Static stealth checks
echo.

if not exist "%DRIVER%" (
    echo   [FAIL] Driver.sys missing
    set "FAILED=1"
) else echo   [OK] Driver.sys present
if not exist "%CLIENT%" (
    echo   [FAIL] Client.exe missing
    set "FAILED=1"
) else echo   [OK] Client.exe present
echo.

rem brand strings in both binaries (ASCII + UTF-16)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "$files=@('%DRIVER%','%CLIENT%'); $bad=0; foreach($f in $files){$b=[IO.File]::ReadAllBytes($f); $s=[Text.Encoding]::ASCII.GetString($b)+[Text.Encoding]::Unicode.GetString($b); $n=([regex]::Matches($s,'Amger|amger|AMGR','IgnoreCase')).Count; if($n -gt 0){Write-Host ('  [FAIL] '+(Split-Path $f -Leaf)+': '+$n+' brand hits'); $bad=1}else{Write-Host ('  [OK] '+(Split-Path $f -Leaf)+': brand-free')}}; exit $bad"
if errorlevel 1 set "FAILED=1"

rem plaintext diagnostic labels in the client
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "$b=[IO.File]::ReadAllBytes('%CLIENT%'); $s=[Text.Encoding]::ASCII.GetString($b)+[Text.Encoding]::Unicode.GetString($b); $n=([regex]::Matches($s,'INJECT|UNLOAD_OWNER|STATUS_NOT_IMPLEMENTED|REGISTER_MDL|CLEANUP_DRAIN|STATUS_QUERY_FAILED|BAD_ARGUMENTS|UNKNOWN_0x')).Count; if($n -gt 0){Write-Host ('  [FAIL] client plaintext labels: '+$n); exit 1}else{Write-Host '  [OK] client diagnostic labels obfuscated'; exit 0}"
if errorlevel 1 set "FAILED=1"

rem Event Log API must not be imported by the driver
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "$b=[IO.File]::ReadAllBytes('%DRIVER%'); $s=[Text.Encoding]::ASCII.GetString($b)+[Text.Encoding]::Unicode.GetString($b); $n=([regex]::Matches($s,'IoWriteErrorLogEntry|Driver detected an internal error','IgnoreCase')).Count; if($n -gt 0){Write-Host ('  [FAIL] driver Event Log references: '+$n); exit 1}else{Write-Host '  [OK] driver has no Event Log artifact'; exit 0}"
if errorlevel 1 set "FAILED=1"

echo.
if "%FAILED%"=="1" (
    echo [Verify] FAILED
    exit /b 1
)
echo [Verify] ALL CHECKS PASSED
exit /b 0
