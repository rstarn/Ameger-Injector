@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"

set "C_RESET="
set "C_GREEN="
set "C_RED="
set "C_YELLOW="
if /i not "%AMEGER_NO_COLOR%"=="1" for /f %%A in ('echo prompt $E ^| cmd') do set "ESC=%%A"
if defined ESC (
    set "C_RESET=%ESC%[0m"
    set "C_GREEN=%ESC%[92m"
    set "C_RED=%ESC%[91m"
    set "C_YELLOW=%ESC%[93m"
)

for %%I in ("%~dp0..\..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "DLL_DIR=%OUT_ROOT%\DLLs"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "WORK_DIR=%RELEASE_CACHE%\Protect"
set "ASSET_TPL=%ROOT%\Assets\Template"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "BUILD_VMP_SCRIPT=%SCRIPTS_DIR%\BuildVMP.ps1"
set "STRIP_SCRIPT=%SCRIPTS_DIR%\StripExportDirs.ps1"
set "STATE_FILE=%RELEASE_CACHE%\Protect.payload.state"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "DEPLOYED_CONFIG="
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "PAYLOAD_ORIGINAL_NAME=Jlov.dll"
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
set "VMP_PROJECT="
set "TARGET_NAME="
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect Console...
echo.
call :find_vmp_con
if errorlevel 2 goto :vmp_wrapper
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console = %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving Payload Target...
echo.
call :read_names_state
if errorlevel 1 goto :names_missing
if defined DLLDIR_NAME (
  set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%"
) else (
  set "DLL_DIR=%OUT_ROOT%\DLLs"
)
if defined CONFIG_NAME (
  set "DEPLOYED_CONFIG=%OUT_ROOT%\%CONFIG_NAME%.ini"
) else (
  set "DEPLOYED_CONFIG=%OUT_ROOT%\Configuration.ini"
)
if not exist "%DLL_DIR%" (
  echo   %C_RED%Error: Release DLL Folder Not Found: %DLL_DIR%%C_RESET%
  goto :failure
)
set "TARGET="
set "DLL_CANDIDATES=0"
for %%F in ("%DLL_DIR%\*.dll") do call :consider_dll "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
if not "%DLL_CANDIDATES%"=="1" goto :target_ambiguous
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
echo   %C_GREEN%[+]%C_RESET% Target      = %C_GREEN%%TARGET%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Skipped     = %C_YELLOW%%RUNTIME_NAME% (Manual-Mapped)%C_RESET%
echo.
call :check_already_protected
if defined VMP_PRESENT (
  if /i not "%AMEGER_FORCE_VMP%"=="1" (
    echo   %C_GREEN%[+]%C_RESET% Already Protected ^(segment %C_YELLOW%%VMP_PRESENT%%C_RESET%^); Skipping.
    echo   %C_YELLOW%       Set AMEGER_FORCE_VMP=1 To Virtualize Anyway.%C_RESET%
    goto :already_protected
  )
)
if not defined VMP_PROBE_OK if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_RED%Error: Could Not Probe The Payload For Existing VMProtect Sections.%C_RESET%
  echo   %C_RED%       Refusing To Re-Virtualize A Possibly-Protected Binary; Set AMEGER_FORCE_VMP=1 To Proceed.%C_RESET%
  goto :failure
)
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Resolving VMProtect Project...
echo.
call :find_project
if errorlevel 1 goto :project_missing
echo   %C_GREEN%[+]%C_RESET% Project      = %C_GREEN%%VMP_PROJECT%%C_RESET%
echo.
call :check_project_input
if errorlevel 1 goto :project_mismatch
call :vmp_settings
echo.
call :read_state
echo.
if /i "%STATE_MATCH%"=="output" (
  echo   %C_GREEN%[+]%C_RESET% Already Protected; Nothing To Do.
  goto :already_done
)
if /i "%STATE_MATCH%"=="unknown" (
  echo   %C_YELLOW%[+]%C_RESET% No Prior State Recorded; Protecting Now.
) else (
  echo   %C_GREEN%[+]%C_RESET% Source Matches Recorded Build; Protecting.
)
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing Payload...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256 = %C_GREEN%%SRC_SHA%%C_RESET%
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment Name = %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(Randomized Per Build)%C_RESET%
call :run_vmp
if errorlevel 1 goto :pack_only_fallback
goto :vmp_done
:pack_only_fallback
echo   %C_YELLOW%[!]%C_RESET% Function virtualization failed; falling back to packing-only.
call :tail_log
call :prepare_project -PackOnly
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment Name = %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(Pack-Only, Refreshed)%C_RESET%
call :run_vmp
if errorlevel 1 (
  echo   %C_RED%Error: VMProtect Reported A Failure; See The Log Tail Below.%C_RESET%
  call :tail_log
  goto :failure
)
:vmp_done
call :validate_output
if errorlevel 2 goto :fc_error
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected Output Validated.
call :verify_segment "%WORK_DIR%\out.dll"
if errorlevel 1 goto :segment_error
echo   %C_GREEN%[+]%C_RESET% VM Segment = %C_GREEN%%VM_SEG%%C_RESET% (Verified)
call :strip_exports "%WORK_DIR%\out.dll"
if errorlevel 1 goto :strip_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Re-pinning Payload Hash...
echo.
copy /y "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
if not defined OUT_SHA goto :hash_error
set "PIN_SRC=%WORK_DIR%\pin.ini"
set "PINGEN_TMP=%TEMP%\amg_pingen_%RANDOM%%RANDOM%"
set "PINGEN_B64=%PINGEN_TMP%.b64"
set "PINGEN_PS1=%PINGEN_TMP%.ps1"
set "PINGEN_RC=1"
>"%PINGEN_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PINGEN_B64%" echo cGFyYW0oW3N0cmluZ10kQ29uZmlnTWFzdGVyLCBbc3RyaW5nXSRPdXRTaGEsIFtzdHJpbmddJFBpblNyYykNCiRjID0gW0lPLkZpbGVdOjpSZWFkQWxsVGV4dCgkQ29uZmlnTWFzdGVyKQ0KJGMgPSBbcmVnZXhdOjpSZXBsYWNlKCRjLCAnKD9tKV5QYXlsb2FkU2hhMjU2XHMqPS4qJCcsICdQYXlsb2FkU2hhMjU2ID0gJyArICgkT3V0U2hhKSkNCltJTy5GaWxlXTo6V3JpdGVBbGxUZXh0KCRQaW5TcmMsICRjLCBbVGV4dC5FbmNvZGluZ106OkFTQ0lJKQ0K
>>"%PINGEN_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PINGEN_B64%" "%PINGEN_PS1%" >nul 2>&1
if errorlevel 1 goto :pingen_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PINGEN_PS1%" -ConfigMaster "%CONFIG_MASTER%" -OutSha "%OUT_SHA%" -PinSrc "%PIN_SRC%"
set "PINGEN_RC=%ERRORLEVEL%"
:pingen_cleanup
if exist "%PINGEN_PS1%" del /f /q "%PINGEN_PS1%" >nul 2>&1
if exist "%PINGEN_B64%" del /f /q "%PINGEN_B64%" >nul 2>&1
if not "%PINGEN_RC%"=="0" goto :pin_error
if not exist "%PIN_SRC%" goto :pin_error
echo   %C_GREEN%[+]%C_RESET% PayloadSha256 = %C_GREEN%%OUT_SHA%%C_RESET%
if not exist "%CONFIG_SCRIPT%" goto :pin_error
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_RED%Error: AMEGER_ENCRYPT_CONFIG=0 Is Refused; The Launcher Rejects Plaintext Configs.%C_RESET%
  goto :pin_error
)
if not exist "%DEPLOYED_CONFIG%" goto :pin_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%PIN_SRC%" -Destination "%DEPLOYED_CONFIG%"
if errorlevel 1 goto :pin_error
echo   %C_GREEN%[+]%C_RESET% Config re-encrypted = %C_GREEN%%DEPLOYED_CONFIG%%C_RESET%
goto :pin_done

:pin_done
call :assert_master_pin
if errorlevel 1 goto :pin_error
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload Protection Completed.
echo   Payload    = %C_GREEN%%TARGET%%C_RESET%
echo.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:already_protected
echo.
echo Payload Is Already VMProtect-Protected; Release Unchanged.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:check_already_protected
set "VMP_PRESENT="
set "VMP_PROBE_OK="
set "BASELINE="
if exist "%RELEASE_CACHE%\pe-sections.txt" for /f "usebackq tokens=1,* delims=:" %%A in ("%RELEASE_CACHE%\pe-sections.txt") do if /i "%%A"=="%TARGET_NAME%" set "BASELINE=%%B"
if not defined BASELINE (
  echo   %C_RED%Warning: No Section Baseline Recorded For %TARGET_NAME%.%C_RESET%
  echo   %C_RED%         Refusing To Guess Whether The Payload Is Already Protected.%C_RESET%
  goto :vmp_check_cleanup
)
REM The VMProtect probe is a PowerShell script carried as base64 so that batch never has to parse a
REM stray parenthesis from the PowerShell grammar. certutil decodes it to a unique temp .ps1, which is
REM run and then removed. The probe reads the target's PE section table and reports any section absent
REM from the recorded baseline as a VMP_PRESENT line. VMP_PROBE_OK is set only when the probe ran and
REM produced a readable result; callers must treat an unset VMP_PROBE_OK as "unknown", never as
REM "not protected", or a broken probe would silently re-virtualize an already-protected binary.
set "VMP_CHK=%TEMP%\amg_vmpchk_%RANDOM%%RANDOM%"
set "VMP_CHK_B64=%VMP_CHK%.b64"
set "VMP_CHK_PS1=%VMP_CHK%.ps1"
set "VMP_CHK_OUT=%VMP_CHK%.out"
>"%VMP_CHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMP_CHK_B64%" echo cGFyYW0oDQogICAgW3N0cmluZ10kQmFzZWxpbmUgPSAnQG5vbmVAJywNCiAgICBbc3RyaW5nXSRUYXJnZXQNCikNCiRiYXNlPSgkQmFzZWxpbmUpLlNwbGl0KCcsJykNCiRiPVtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRUYXJnZXQpDQokZT1bQml0Q29udmVydGVyXTo6VG9JbnQzMigkYiwweDNDKQ0KJGM9JGUrNA0KJG49W0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCRjKzIpDQokej1bQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsJGMrMTYpDQokcz0kYysyMCskeg0KZm9yKCRpPTA7JGkgLWx0ICRuOyRpKyspew0KICAgICRvPSRzKzQwKiRpDQogICAgJG5tPVtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRiLCRvLDgpLlRyaW0oW2NoYXJdMCkNCiAgICAkeD1bQml0Q29udmVydGVyXTo6VG9VSW50MzIoJGIsJG8rMzYpDQogICAgaWYoJHggLWJhbmQgMHgyMDAwMDAwMCl7ICR0YWc9JG5tKycrWCcgfSBlbHNlIHsgJHRhZz0kbm0gfQ0KICAgIGlmKCRiYXNlIC1ub3Rjb250YWlucyAkdGFnKXsgV3JpdGUtT3V0cHV0ICgnVk1QX1BSRVNFTlQ9JyArICRubSkgfQ0KfQ0K
>>"%VMP_CHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMP_CHK_B64%" "%VMP_CHK_PS1%" >nul 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_PS1%" goto :vmp_check_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_CHK_PS1%" -Baseline "%BASELINE%" -Target "%TARGET%" >"%VMP_CHK_OUT%" 2>&1
if errorlevel 1 goto :vmp_check_cleanup
if not exist "%VMP_CHK_OUT%" goto :vmp_check_cleanup
set "VMP_PROBE_OK=1"
for /f "usebackq tokens=1,* delims==" %%A in ("%VMP_CHK_OUT%") do if /i "%%A"=="VMP_PRESENT" set "VMP_PRESENT=%%B"
:vmp_check_cleanup
if exist "%VMP_CHK_PS1%" del /f /q "%VMP_CHK_PS1%" >nul 2>&1
if exist "%VMP_CHK_B64%" del /f /q "%VMP_CHK_B64%" >nul 2>&1
if exist "%VMP_CHK_OUT%" del /f /q "%VMP_CHK_OUT%" >nul 2>&1
exit /b 0

:already_done
echo.
echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Protection Artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%DLL_DIR%%C_RESET%.
echo.
echo Payload Already Protected; Release Unchanged.
echo.
if defined VMSEG echo VM Segment = %C_GREEN%%VMSEG%%C_RESET% (Recorded)
echo Payload = %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:consider_dll
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
if /i "%~nx1"=="%RUNTIME_NAME%" exit /b 0
set /a "DLL_CANDIDATES+=1"
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
exit /b 0

:prepare_project
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
set "VMP_DROP="
set "VMP_KEEP="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%" -Target "%TARGET%" %~1`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
if defined VMP_DROP (
  echo   %C_YELLOW%[!]%C_RESET% .vmp Procedure^(s^) Absent From Payload, Dropped: %C_YELLOW%%VMP_DROP%%C_RESET%
  echo   %C_YELLOW%      Virtualizing Only What The Payload Exposes: %VMP_KEEP%%C_RESET%
)
exit /b 0

:run_vmp
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.dll" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
exit /b %ERRORLEVEL%

:strip_exports
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%STRIP_SCRIPT%" -Path "%~1"
exit /b %ERRORLEVEL%

:find_vmp_con
if defined AMEGER_VMP_CON if exist "%AMEGER_VMP_CON%" (
  set "VMP_CON=%AMEGER_VMP_CON%"
  goto :vmp_con_bat_check
)
call :scan_vmp_dirs "%ProgramFiles%"
call :scan_vmp_dirs "%ProgramW6432%"
call :scan_vmp_dirs "%ProgramFiles(x86)%"
call :scan_vmp_dirs "%LOCALAPPDATA%"
call :scan_vmp_dirs "%ALLUSERSPROFILE%"
if not defined VMP_CON for /f "delims=" %%E in ('where VMProtect_Con.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON for /f "delims=" %%E in ('where vmpconsole.exe 2^>nul') do if not defined VMP_CON set "VMP_CON=%%E"
if not defined VMP_CON exit /b 1
:vmp_con_bat_check
set "VMP_CON=%VMP_CON:"=%"
if not exist "%VMP_CON%" exit /b 1
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".bat" exit /b 2
for %%X in ("%VMP_CON%") do if /i "%%~xX"==".cmd" exit /b 2
exit /b 0

:scan_vmp_dirs
for /d %%D in ("%~1\VMProtect*") do if not defined VMP_CON for %%E in ("%%~fD\VMProtect_Con.exe" "%%~fD\VMProtect_Console.exe" "%%~fD\vmpconsole.exe") do if not defined VMP_CON if exist "%%E" set "VMP_CON=%%E"
exit /b 0

:find_project
if defined AMEGER_VMP_PROJECT_DLL if exist "%AMEGER_VMP_PROJECT_DLL%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_DLL%"
  exit /b 0
)
if exist "%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%PAYLOAD_ORIGINAL_NAME%.vmp"
  exit /b 0
)
for %%F in ("%ASSET_TPL%\*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
for %%F in ("%~dp0*.vmp") do if not defined VMP_PROJECT set "VMP_PROJECT=%%~fF"
if defined VMP_PROJECT if exist "%VMP_PROJECT%" exit /b 0
set "VMP_PROJECT="
exit /b 1

:check_project_input
set "PROJIN_TMP=%TEMP%\amg_projin_%RANDOM%%RANDOM%"
set "PROJIN_B64=%PROJIN_TMP%.b64"
set "PROJIN_PS1=%PROJIN_TMP%.ps1"
set "PROJIN_RC=1"
>"%PROJIN_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PROJIN_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCwgW3N0cmluZ10kRXhwZWN0ZWROYW1lKQ0KJHggPSBbeG1sXVtJTy5GaWxlXTo6UmVhZEFsbFRleHQoJFZtcFByb2plY3QpDQokaSA9IFtzdHJpbmddJHguRG9jdW1lbnQuUHJvdGVjdGlvbi5JbnB1dEZpbGVOYW1lDQppZiAoJGkgLWVxICRFeHBlY3RlZE5hbWUpIHsgZXhpdCAwIH0NCldyaXRlLUhvc3QgKCcgICAgcHJvamVjdCB0YXJnZXRzOiAnICsgJGkpDQpleGl0IDENCg==
>>"%PROJIN_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PROJIN_B64%" "%PROJIN_PS1%" >nul 2>&1
if errorlevel 1 goto :projin_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PROJIN_PS1%" -VmpProject "%VMP_PROJECT%" -ExpectedName "%PAYLOAD_ORIGINAL_NAME%"
set "PROJIN_RC=%ERRORLEVEL%"
:projin_cleanup
if exist "%PROJIN_PS1%" del /f /q "%PROJIN_PS1%" >nul 2>&1
if exist "%PROJIN_B64%" del /f /q "%PROJIN_B64%" >nul 2>&1
exit /b %PROJIN_RC%

:vmp_settings
set "VMPSET_TMP=%TEMP%\amg_vmpset_%RANDOM%%RANDOM%"
set "VMPSET_B64=%VMPSET_TMP%.b64"
set "VMPSET_PS1=%VMPSET_TMP%.ps1"
>"%VMPSET_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMPSET_B64%" echo cGFyYW0oW3N0cmluZ10kVm1wUHJvamVjdCkNCiR4ID0gW3htbF1bSU8uRmlsZV06OlJlYWRBbGxUZXh0KCRWbXBQcm9qZWN0KQ0KJHAgPSAkeC5Eb2N1bWVudC5Qcm90ZWN0aW9uDQpXcml0ZS1Ib3N0ICgnICAgIElucHV0ICAgICAgICAgOiAnICsgJHAuSW5wdXRGaWxlTmFtZSkNCldyaXRlLUhvc3QgKCcgICAgVk0gY29tcGxleGl0eSA6ICcgKyAkcC5WTUNvbXBsZXhpdHkpDQpXcml0ZS1Ib3N0ICgnICAgIFZNIGluc3RhbmNlcyAgOiAnICsgJHAuVk1JbnN0YW5jZXMpDQpXcml0ZS1Ib3N0ICgnICAgIE9wdGlvbnMgICAgICAgOiAnICsgJHAuT3B0aW9ucykNCldyaXRlLUhvc3QgJyAgICBQcm9jZWR1cmVzICAgIDonDQpmb3JlYWNoICgkcSBpbiAkcC5Qcm9jZWR1cmVzLlByb2NlZHVyZSkgew0KICAgIFdyaXRlLUhvc3QgKCcgICAgICAtICcgKyAkcS5NYXBBZGRyZXNzICsgJyAgQ29tcGlsYXRpb25UeXBlPScgKyAkcS5Db21waWxhdGlvblR5cGUgKyAnICBDb21wbGV4aXR5PScgKyAkcS5Db21wbGV4aXR5KQ0KfQ0K
>>"%VMPSET_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMPSET_B64%" "%VMPSET_PS1%" >nul 2>&1
if errorlevel 1 goto :vmpset_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMPSET_PS1%" -VmpProject "%VMP_PROJECT%"
:vmpset_cleanup
if exist "%VMPSET_PS1%" del /f /q "%VMPSET_PS1%" >nul 2>&1
if exist "%VMPSET_B64%" del /f /q "%VMPSET_B64%" >nul 2>&1
exit /b 0

:read_state
set "STATE_MATCH=unknown"
if not exist "%STATE_FILE%" exit /b 0
set "SRC="
set "OUT="
for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do set "%%A=%%B"
if not defined OUT exit /b 0
call :sha256_of "%TARGET%" CUR
if errorlevel 1 exit /b 0
if /i "%CUR%"=="%OUT%" (
  set "STATE_MATCH=output"
  exit /b 0
)
if defined SRC if /i "%CUR%"=="%SRC%" (
  set "STATE_MATCH=source"
  exit /b 0
)
exit /b 0

:sha256_of
set "SHA256="
if not exist "%~1" exit /b 1
set "SHATMP_TMP=%TEMP%\amg_sha_%RANDOM%%RANDOM%"
set "SHATMP_B64=%SHATMP_TMP%.b64"
set "SHATMP_PS1=%SHATMP_TMP%.ps1"
set "SHATMP_OUT=%SHATMP_TMP%.out"
>"%SHATMP_B64%" echo -----BEGIN CERTIFICATE-----
>>"%SHATMP_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1NIQTI1Nj0nICsgJGgpDQo=
>>"%SHATMP_B64%" echo -----END CERTIFICATE-----
certutil -decode "%SHATMP_B64%" "%SHATMP_PS1%" >nul 2>&1
if errorlevel 1 goto :sha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SHATMP_PS1%" -Path "%~1" >"%SHATMP_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%SHATMP_OUT%") do set "%%A=%%B"
:sha_cleanup
if exist "%SHATMP_PS1%" del /f /q "%SHATMP_PS1%" >nul 2>&1
if exist "%SHATMP_B64%" del /f /q "%SHATMP_B64%" >nul 2>&1
if exist "%SHATMP_OUT%" del /f /q "%SHATMP_OUT%" >nul 2>&1
if not defined SHA256 exit /b 1
set "%~2=%SHA256%"
set "SHA256="
exit /b 0

:validate_output
if not exist "%WORK_DIR%\out.dll" exit /b 1
set "VALOUT_TMP=%TEMP%\amg_valout_%RANDOM%%RANDOM%"
set "VALOUT_B64=%VALOUT_TMP%.b64"
set "VALOUT_PS1=%VALOUT_TMP%.ps1"
set "VALOUT_RC=1"
>"%VALOUT_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VALOUT_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQppZiAoJGIuTGVuZ3RoIC1sdCAyKSB7IGV4aXQgMSB9DQppZiAoJGJbMF0gLW5lIDB4NEQgLW9yICRiWzFdIC1uZSAweDVBKSB7IGV4aXQgMSB9DQpleGl0IDANCg==
>>"%VALOUT_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VALOUT_B64%" "%VALOUT_PS1%" >nul 2>&1
if errorlevel 1 goto :valout_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VALOUT_PS1%" -Path "%WORK_DIR%\out.dll"
set "VALOUT_RC=%ERRORLEVEL%"
:valout_cleanup
if exist "%VALOUT_PS1%" del /f /q "%VALOUT_PS1%" >nul 2>&1
if exist "%VALOUT_B64%" del /f /q "%VALOUT_B64%" >nul 2>&1
if not "%VALOUT_RC%"=="0" exit /b 1
fc /b "%WORK_DIR%\out.dll" "%TARGET%" > nul
if errorlevel 2 exit /b 2
if not errorlevel 1 exit /b 1
exit /b 0

:verify_segment
set "VM_SEG="
set "VM_SEG_STATUS="
set "VMSEG_TMP=%TEMP%\amg_vmseg_%RANDOM%%RANDOM%"
set "VMSEG_B64=%VMSEG_TMP%.b64"
set "VMSEG_PS1=%VMSEG_TMP%.ps1"
set "VMSEG_OUT=%VMSEG_TMP%.out"
>"%VMSEG_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMSEG_B64%" echo cGFyYW0oW3N0cmluZ10kU2VnbWVudCwgW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQokZSA9IFtCaXRDb252ZXJ0ZXJdOjpUb0ludDMyKCRiLCAweDNDKQ0KJGMgPSAkZSArIDQNCiRuID0gW0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCAkYyArIDIpDQokeiA9IFtCaXRDb252ZXJ0ZXJdOjpUb1VJbnQxNigkYiwgJGMgKyAxNikNCiRzID0gJGMgKyAyMCArICR6DQokZm91bmQgPSAkbnVsbA0KZm9yICgkaSA9IDA7ICRpIC1sdCAkbjsgJGkrKykgew0KICAgICRvID0gJHMgKyA0MCAqICRpDQogICAgJG5tID0gW1RleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJGIsICRvLCA4KS5UcmltKFtjaGFyXTApDQogICAgaWYgKCRubS5TdGFydHNXaXRoKCRTZWdtZW50KSkgeyAkZm91bmQgPSAkbm07IGJyZWFrIH0NCn0NCmlmICgkbnVsbCAtZXEgJGZvdW5kKSB7DQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUdfU1RBVFVTPW1pc3NpbmcnDQogICAgV3JpdGUtT3V0cHV0ICdWTV9TRUc9Jw0KICAgIGV4aXQgMA0KfQ0KV3JpdGUtT3V0cHV0ICgnVk1fU0VHPScgKyAkZm91bmQpDQppZiAoJGZvdW5kIC1tYXRjaCAoJ14nICsgW3JlZ2V4XTo6RXNjYXBlKCRTZWdtZW50KSArICdbMC05XSokJykpIHsNCiAgICBXcml0ZS1PdXRwdXQgJ1ZNX1NFR19TVEFUVVM9b2snDQp9IGVsc2Ugew0KICAgIFdyaXRlLU91dHB1dCAnVk1fU0VHX1NUQVRVUz1taXNtYXRjaCcNCn0NCmV4aXQgMA0K
>>"%VMSEG_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMSEG_B64%" "%VMSEG_PS1%" >nul 2>&1
if errorlevel 1 goto :vmseg_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMSEG_PS1%" -Segment "%SEG_NAME%" -Path "%~1" >"%VMSEG_OUT%" 2>&1
for /f "usebackq tokens=1,* delims==" %%A in ("%VMSEG_OUT%") do set "%%A=%%B"
:vmseg_cleanup
if exist "%VMSEG_PS1%" del /f /q "%VMSEG_PS1%" >nul 2>&1
if exist "%VMSEG_B64%" del /f /q "%VMSEG_B64%" >nul 2>&1
if exist "%VMSEG_OUT%" del /f /q "%VMSEG_OUT%" >nul 2>&1
if /i "%VM_SEG_STATUS%"=="ok" exit /b 0
if /i "%VM_SEG_STATUS%"=="missing" (
  echo   %C_RED%Error: No VMProtect Segment Found In The Protected Output.%C_RESET%
) else (
  echo   %C_RED%Error: VMProtect Segment Name Mismatch In The Protected Output.%C_RESET%
)
echo   %C_RED%       Expected = %SEG_NAME% (Optionally Followed By Digits)%C_RESET%
echo   %C_RED%       Observed = %VM_SEG%%C_RESET%
exit /b 1

:assert_master_pin
if not exist "%PAYLOAD_ASSET%" exit /b 1
call :sha256_of "%PAYLOAD_ASSET%" ASSET_SHA
if errorlevel 1 exit /b 1
if not defined ASSET_SHA exit /b 1
set "PINCHK_TMP=%TEMP%\amg_pinchk_%RANDOM%%RANDOM%"
set "PINCHK_B64=%PINCHK_TMP%.b64"
set "PINCHK_PS1=%PINCHK_TMP%.ps1"
set "PINCHK_RC=1"
>"%PINCHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%PINCHK_B64%" echo cGFyYW0oW3N0cmluZ10kQ29uZmlnTWFzdGVyLCBbc3RyaW5nXSRBc3NldFNoYSkNCiRjID0gW0lPLkZpbGVdOjpSZWFkQWxsVGV4dCgkQ29uZmlnTWFzdGVyKQ0KJG0gPSBbcmVnZXhdOjpNYXRjaCgkYywgJyg/bSleUGF5bG9hZFNoYTI1NlxzKj1ccyooWzAtOUEtRmEtZl17NjR9KScpDQppZiAoLW5vdCAkbS5TdWNjZXNzKSB7IGV4aXQgMSB9DQppZiAoJG0uR3JvdXBzWzFdLlZhbHVlIC1uZSAkQXNzZXRTaGEpIHsNCiAgICBXcml0ZS1Ib3N0ICgnICAgIG1hc3RlciBwaW5zIDogJyArICRtLkdyb3Vwc1sxXS5WYWx1ZSkNCiAgICBXcml0ZS1Ib3N0ICgnICAgIGFzc2V0IGlzICAgIDogJyArICRBc3NldFNoYSkNCiAgICBleGl0IDENCn0NCmV4aXQgMA0K
>>"%PINCHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%PINCHK_B64%" "%PINCHK_PS1%" >nul 2>&1
if errorlevel 1 goto :pinchk_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PINCHK_PS1%" -ConfigMaster "%CONFIG_MASTER%" -AssetSha "%ASSET_SHA%"
set "PINCHK_RC=%ERRORLEVEL%"
:pinchk_cleanup
if exist "%PINCHK_PS1%" del /f /q "%PINCHK_PS1%" >nul 2>&1
if exist "%PINCHK_B64%" del /f /q "%PINCHK_B64%" >nul 2>&1
exit /b %PINCHK_RC%

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
>>"%STATE_FILE%" echo VMSEG=%VM_SEG%
exit /b 0

:read_names_state
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
if not exist "%NAMES_STATE%" exit /b 1
for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do set "%%A=%%B"
if not defined PAYLOAD_NAME exit /b 1
if not defined RUNTIME_NAME exit /b 1
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
set "LOG_NAME="
if exist "%NAMES_STATE%" for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do if /i "%%A"=="LOG_NAME" set "LOG_NAME=%%B"
if not defined LOG_NAME for %%I in ("%OUT_ROOT%\*.ini") do if not defined LOG_NAME set "LOG_NAME=%%~nI.log"
for %%F in ("%DLL_DIR%\*.vmp" "%DLL_DIR%\*.log" "%DLL_DIR%\*.bak" "%DLL_DIR%\*.tmp") do if /i not "%%~nxF"=="Result.log" if /i not "%%~nxF"=="%LOG_NAME%" if exist "%%~F" (
  echo   %C_RED%Error: Protection Artifact Left In The Release Folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_wrapper
echo   %C_RED%Error: AMEGER_VMP_CON Points At A Batch/CMD Wrapper: %VMP_CON%%C_RESET%
echo   %C_RED%       A Wrapper Transfers Control And Never Returns; Use The Real Console.%C_RESET%
goto :failure

:vmp_missing
echo   %C_RED%Error: VMProtect Console Not Found.%C_RESET%
echo   %C_YELLOW%       Searched:%C_RESET%
echo         %PROGRAMFILES%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMW6432%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMFILES(X86)%\VMProtect*\VMProtect_Con.exe
echo         %LOCALAPPDATA%\VMProtect*\VMProtect_Con.exe
echo         PATH ^(VMProtect_Con.exe, vmpconsole.exe^)
echo   %C_YELLOW%       Fix: Set AMEGER_VMP_CON to the full path, with no surrounding quotes,%C_RESET%
echo   %C_YELLOW%             e.g. set AMEGER_VMP_CON=C:\Program Files\VMProtect Ultimate\VMProtect_Con.exe%C_RESET%
echo   %C_YELLOW%       Leaving It Unset Is Fine If VMProtect Is Installed Normally.%C_RESET%
echo   %C_YELLOW%       Note: The Console Build Is Not Included In The Lite Edition.%C_RESET%
goto :failure

:names_missing
echo   %C_RED%Error: Per-Build Name State Not Found Or Incomplete: %NAMES_STATE%%C_RESET%
echo   %C_RED%       Run Create.bat First; The Deployed Payload And Runtime DLL Cannot Be Resolved.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%Error: No Virtualizable Payload DLL Found In The Release Folder.%C_RESET%
goto :failure

:target_ambiguous
echo   %C_RED%Error: Expected Exactly One Virtualizable Payload DLL In %DLL_DIR%, found %DLL_CANDIDATES%.%C_RESET%
echo   %C_RED%       Refusing To Guess Which DLL To Protect.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%Error: No .vmp Project Found; Set AMEGER_VMP_PROJECT_DLL.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%Error: The Project Does Not Target This Binary.%C_RESET%
echo   %C_RED%       Refusing To Protect With A Crossed Project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%Error: Unable To Prepare The Protection Staging Directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%Error: Unable To Calculate The Payload SHA-256.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%Error: VMProtect Output Failed Validation; Release Left Untouched.%C_RESET%
goto :failure

:segment_error
echo   %C_RED%Error: The Protected Payload Does Not Carry The Generated VMProtect Segment.%C_RESET%
echo   %C_RED%       Release Left Untouched; The Output Was Not Deployed.%C_RESET%
goto :failure

:fc_error
echo   %C_RED%Error: Unable To Compare The Protected Output Against The Source.%C_RESET%
echo   %C_RED%       fc Failed; The Output Is Unverified And Will Not Ship.%C_RESET%
goto :failure

:project_error
echo   %C_RED%Error: Unable To Prepare The Randomized Project Copy.%C_RESET%
goto :failure

:strip_error
echo   %C_RED%Error: Unable To Strip The Payload Export Directory.%C_RESET%
echo   %C_RED%       The release payload would ship its only named symbol.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%Error: Unable To Deploy The Protected Payload.%C_RESET%
goto :failure

:pin_error
echo   %C_RED%Error: Unable To Re-Pin The Release Config Or Re-Encrypt It.%C_RESET%
echo   %C_RED%       The release payload and its shipped pin now disagree.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%Error: Unable To Remove Generated Protection Artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
