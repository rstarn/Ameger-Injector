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
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "WORK_DIR=%RELEASE_CACHE%\Protect"
set "ASSET_TPL=%ROOT%\Assets\Template"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "BUILD_VMP_SCRIPT=%SCRIPTS_DIR%\BuildVMP.ps1"
set "STATE_FILE=%RELEASE_CACHE%\Protect.exe.state"
set "VERIFY_SCRIPT=%BUILD_DIR%\Scripts\VerifyEmbedMagic.ps1"
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "RUNTIME_NAME="
set "EXE_ORIGINAL_NAME=Host - x64.exe"
set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
set "VMP_CON="

echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Locating VMProtect console...
echo.
call :find_vmp_con
if errorlevel 2 goto :vmp_wrapper
if errorlevel 1 goto :vmp_missing
echo   %C_GREEN%[+]%C_RESET% Console: %C_GREEN%%VMP_CON%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Resolving launcher target...
echo.
if not exist "%OUT_ROOT%" (
  echo   %C_RED%ERROR: release folder not found: %OUT_ROOT%%C_RESET%
  goto :failure
)
set "TARGET="
set "RUNTIME_DLL="
set "EXE_CANDIDATES=0"
for %%F in ("%OUT_ROOT%\*.exe") do call :consider_exe "%%~fF"
if not defined TARGET goto :target_missing
if not exist "%TARGET%" goto :target_missing
if not "%EXE_CANDIDATES%"=="1" goto :target_ambiguous
for %%N in ("%TARGET%") do set "TARGET_NAME=%%~nxN"
call :read_runtime_name
if defined DLLDIR_NAME (set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%") else (set "DLL_DIR=%OUT_ROOT%\DLLs")
if defined RUNTIME_NAME if exist "%DLL_DIR%\%RUNTIME_NAME%" set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_NAME%"
echo   %C_GREEN%[+]%C_RESET% Target:  %C_GREEN%%TARGET%%C_RESET%
if defined RUNTIME_DLL (
  echo   %C_GREEN%[+]%C_RESET% Runtime: %C_GREEN%%RUNTIME_DLL%%C_RESET% ^(left unvirtualized^)
) else (
  echo   %C_YELLOW%[+]%C_RESET% Runtime DLL not found; embedded-hash verification will fail closed unless AMEGER_ALLOW_SKIP_EMBED=1.
)
call :check_already_protected
if defined VMP_PRESENT if /i not "%AMEGER_FORCE_VMP%"=="1" (
  echo   %C_GREEN%[+]%C_RESET% Already protected ^(segment %C_YELLOW%%VMP_PRESENT%%C_RESET%^); skipping.
  echo   %C_YELLOW%       Set AMEGER_FORCE_VMP=1 to virtualize anyway.%C_RESET%
  goto :already_protected
)
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Resolving VMProtect project...
echo.
call :find_project
if errorlevel 1 goto :project_missing
echo   %C_GREEN%[+]%C_RESET% Project: %C_GREEN%%VMP_PROJECT%%C_RESET%
echo.
call :check_project_input
if errorlevel 1 goto :project_mismatch
call :vmp_settings
echo.
call :read_state
echo.
if /i "%STATE_MATCH%"=="output" (
  echo   %C_GREEN%[+]%C_RESET% Already protected; nothing to do.
  goto :already_done
)
if /i "%STATE_MATCH%"=="unknown" (
  echo   %C_YELLOW%[+]%C_RESET% No prior state recorded; protecting now.
) else (
  echo   %C_GREEN%[+]%C_RESET% Source matches recorded build; protecting.
)
echo.
echo.

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Virtualizing launcher...
echo.
call :clean_work
if errorlevel 1 goto :work_error
if not exist "%WORK_DIR%" mkdir "%WORK_DIR%"
if not exist "%WORK_DIR%" goto :work_error
call :sha256_of "%TARGET%" SRC_SHA
if errorlevel 1 goto :hash_error
if not defined SRC_SHA goto :hash_error
echo   Source SHA-256: %C_GREEN%%SRC_SHA%%C_RESET%
call :prepare_project
if errorlevel 1 goto :project_error
echo   %C_GREEN%[+]%C_RESET% Segment name: %C_GREEN%%SEG_NAME%%C_RESET% %C_YELLOW%(randomized per build)%C_RESET%
"%VMP_CON%" "%TARGET%" "%WORK_DIR%\out.exe" -pf "%PROJ_WORK%" -we > "%WORK_DIR%\vmp.log" 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: VMProtect reported a failure; see the log tail below.%C_RESET%
  call :tail_log
  goto :failure
)
call :validate_output
if errorlevel 2 goto :fc_error
if errorlevel 1 goto :output_invalid
echo.
echo   %C_GREEN%OK%C_RESET% Protected output validated.
call :verify_segment "%WORK_DIR%\out.exe"
if errorlevel 1 goto :segment_error
echo   %C_GREEN%[+]%C_RESET% VM segment: %C_GREEN%%VM_SEG%%C_RESET% (verified)
echo.
copy /y "%WORK_DIR%\out.exe" "%TARGET%" > nul
if errorlevel 1 goto :deploy_error
call :sha256_of "%TARGET%" OUT_SHA
if errorlevel 1 goto :hash_error
echo   %C_GREEN%[+]%C_RESET% Output SHA-256: %C_GREEN%%OUT_SHA%%C_RESET%
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Verifying embedded runtime hash...
echo.
if not defined RUNTIME_DLL goto :embed_unavailable
if not exist "%VERIFY_SCRIPT%" goto :embed_unavailable
call :runtime_hash_words
if errorlevel 1 goto :embed_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%TARGET%" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
if errorlevel 1 goto :embed_error
echo   %C_GREEN%[+]%C_RESET% Embedded runtime hash intact after virtualization.
goto :embed_ok

:embed_unavailable
echo   %C_RED%ERROR: cannot verify the embedded runtime hash after virtualization.%C_RESET%
echo   %C_RED%       The runtime DLL or %VERIFY_SCRIPT% was not found; refusing to ship an unverified launcher.%C_RESET%
goto :failure

:embed_ok
call :write_state
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping protection artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher protection completed.
echo.
echo Interface x64: %C_GREEN%%TARGET%%C_RESET%
if "%NO_PAUSE%"=="0" pause
exit /b 0

:already_protected
echo.
echo Launcher is already VMProtect-protected; release unchanged.
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:check_already_protected
set "VMP_PRESENT="
set "BASELINE="
if exist "%RELEASE_CACHE%\pe-sections.txt" for /f "usebackq tokens=1,* delims=:" %%A in ("%RELEASE_CACHE%\pe-sections.txt") do if /i "%%A"=="%TARGET_NAME%" set "BASELINE=%%B"
if not defined BASELINE set "BASELINE=@none@"
REM The VMProtect probe is a PowerShell script carried as base64 so that batch never has to parse a
REM stray parenthesis from the PowerShell grammar. certutil decodes it to a unique temp .ps1, which is
REM run and then removed. The probe reads the target's PE section table and reports any section absent
REM from the recorded baseline as a VMP_PRESENT line. VMP_PRESENT is left unset if the probe cannot
REM run, exactly as the previous inline command behaved.
set "VMP_CHK=%TEMP%\amg_vmpchk_%RANDOM%%RANDOM%"
set "VMP_CHK_B64=%VMP_CHK%.b64"
set "VMP_CHK_PS1=%VMP_CHK%.ps1"
set "VMP_CHK_OUT=%VMP_CHK%.out"
>"%VMP_CHK_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VMP_CHK_B64%" echo cGFyYW0oDQogICAgW3N0cmluZ10kQmFzZWxpbmUgPSAnQG5vbmVAJywNCiAgICBbc3RyaW5nXSRUYXJnZXQNCikNCiRiYXNlPSgkQmFzZWxpbmUpLlNwbGl0KCcsJykNCiRiPVtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRUYXJnZXQpDQokZT1bQml0Q29udmVydGVyXTo6VG9JbnQzMigkYiwweDNDKQ0KJGM9JGUrNA0KJG49W0JpdENvbnZlcnRlcl06OlRvVUludDE2KCRiLCRjKzIpDQokej1bQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsJGMrMTYpDQokcz0kYysyMCskeg0KZm9yKCRpPTA7JGkgLWx0ICRuOyRpKyspew0KICAgICRvPSRzKzQwKiRpDQogICAgJG5tPVtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRiLCRvLDgpLlRyaW0oW2NoYXJdMCkNCiAgICAkeD1bQml0Q29udmVydGVyXTo6VG9VSW50MzIoJGIsJG8rMzYpDQogICAgaWYoJHggLWJhbmQgMHgyMDAwMDAwMCl7ICR0YWc9JG5tKycrWCcgfSBlbHNlIHsgJHRhZz0kbm0gfQ0KICAgIGlmKCRiYXNlIC1ub3Rjb250YWlucyAkdGFnKXsgV3JpdGUtT3V0cHV0ICgnVk1QX1BSRVNFTlQ9JyArICRubSkgfQ0KfQ0K
>>"%VMP_CHK_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VMP_CHK_B64%" "%VMP_CHK_PS1%" >nul 2>&1
if errorlevel 1 goto :vmp_check_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VMP_CHK_PS1%" -Baseline "%BASELINE%" -Target "%TARGET%" >"%VMP_CHK_OUT%" 2>&1
for /f "usebackq tokens=1,* delims==" %%A in ("%VMP_CHK_OUT%") do set "%%A=%%B"
:vmp_check_cleanup
if exist "%VMP_CHK_PS1%" del /f /q "%VMP_CHK_PS1%" >nul 2>&1
if exist "%VMP_CHK_B64%" del /f /q "%VMP_CHK_B64%" >nul 2>&1
if exist "%VMP_CHK_OUT%" del /f /q "%VMP_CHK_OUT%" >nul 2>&1
exit /b 0

:already_done
echo.
echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping protection artifacts...
echo.
call :clean_work
if errorlevel 1 goto :cleanup_error
call :assert_clean
if errorlevel 1 goto :cleanup_error
echo   %C_GREEN%[+]%C_RESET% No VMProtect traces in %C_GREEN%%OUT_ROOT%%C_RESET%.
echo.
echo Launcher already protected; release unchanged.
echo.
if defined VMSEG echo VM segment: %C_GREEN%%VMSEG%%C_RESET% (recorded)
echo Interface x64: %C_GREEN%%TARGET%%C_RESET%
echo.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:consider_exe
set "CANDIDATE=%~1"
if not defined CANDIDATE exit /b 0
set /a "EXE_CANDIDATES+=1"
if defined TARGET exit /b 0
set "TARGET=%CANDIDATE%"
exit /b 0

:prepare_project
set "PROJ_WORK=%WORK_DIR%\project.vmp"
set "SEG_NAME="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BUILD_VMP_SCRIPT%" -Project "%VMP_PROJECT%" -Out "%PROJ_WORK%"`) do set "%%A=%%B"
if not exist "%PROJ_WORK%" exit /b 1
if not defined SEG_NAME exit /b 1
exit /b 0

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
if defined AMEGER_VMP_PROJECT_EXE if exist "%AMEGER_VMP_PROJECT_EXE%" (
  set "VMP_PROJECT=%AMEGER_VMP_PROJECT_EXE%"
  exit /b 0
)
if exist "%ASSET_TPL%\%EXE_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%ASSET_TPL%\%EXE_ORIGINAL_NAME%.vmp"
  exit /b 0
)
if exist "%~dp0%EXE_ORIGINAL_NAME%.vmp" (
  set "VMP_PROJECT=%~dp0%EXE_ORIGINAL_NAME%.vmp"
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
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PROJIN_PS1%" -VmpProject "%VMP_PROJECT%" -ExpectedName "%EXE_ORIGINAL_NAME%"
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

:read_runtime_name
set "RUNTIME_NAME="
if not exist "%NAMES_STATE%" exit /b 0
for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do set "%%A=%%B"
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

:runtime_hash_words
set "H0="
set "H1="
set "H2="
set "H3="
set "H4="
set "H5="
set "H6="
set "H7="
set "HASH8_TMP=%TEMP%\amg_hash8_%RANDOM%%RANDOM%"
set "HASH8_B64=%HASH8_TMP%.b64"
set "HASH8_PS1=%HASH8_TMP%.ps1"
set "HASH8_OUT=%HASH8_TMP%.out"
>"%HASH8_B64%" echo -----BEGIN CERTIFICATE-----
>>"%HASH8_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCjAuLjcgfCBGb3JFYWNoLU9iamVjdCB7IFdyaXRlLU91dHB1dCAoJ0gnICsgJF8gKyAnPTB4JyArICRoLlN1YnN0cmluZygkXyo4LDgpKSB9DQo=
>>"%HASH8_B64%" echo -----END CERTIFICATE-----
certutil -decode "%HASH8_B64%" "%HASH8_PS1%" >nul 2>&1
if errorlevel 1 goto :hash8_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%HASH8_PS1%" -Path "%RUNTIME_DLL%" >"%HASH8_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%HASH8_OUT%") do set "%%A=%%B"
:hash8_cleanup
if exist "%HASH8_PS1%" del /f /q "%HASH8_PS1%" >nul 2>&1
if exist "%HASH8_B64%" del /f /q "%HASH8_B64%" >nul 2>&1
if exist "%HASH8_OUT%" del /f /q "%HASH8_OUT%" >nul 2>&1
if not defined H0 exit /b 1
if not defined H7 exit /b 1
exit /b 0

:validate_output
if not exist "%WORK_DIR%\out.exe" exit /b 1
set "VALOUT_TMP=%TEMP%\amg_valout_%RANDOM%%RANDOM%"
set "VALOUT_B64=%VALOUT_TMP%.b64"
set "VALOUT_PS1=%VALOUT_TMP%.ps1"
set "VALOUT_RC=1"
>"%VALOUT_B64%" echo -----BEGIN CERTIFICATE-----
>>"%VALOUT_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRiID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJFBhdGgpDQppZiAoJGIuTGVuZ3RoIC1sdCAyKSB7IGV4aXQgMSB9DQppZiAoJGJbMF0gLW5lIDB4NEQgLW9yICRiWzFdIC1uZSAweDVBKSB7IGV4aXQgMSB9DQpleGl0IDANCg==
>>"%VALOUT_B64%" echo -----END CERTIFICATE-----
certutil -decode "%VALOUT_B64%" "%VALOUT_PS1%" >nul 2>&1
if errorlevel 1 goto :valout_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VALOUT_PS1%" -Path "%WORK_DIR%\out.exe"
set "VALOUT_RC=%ERRORLEVEL%"
:valout_cleanup
if exist "%VALOUT_PS1%" del /f /q "%VALOUT_PS1%" >nul 2>&1
if exist "%VALOUT_B64%" del /f /q "%VALOUT_B64%" >nul 2>&1
if not "%VALOUT_RC%"=="0" exit /b 1
fc /b "%WORK_DIR%\out.exe" "%TARGET%" > nul
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
  echo   %C_RED%ERROR: no VMProtect segment found in the protected output.%C_RESET%
) else (
  echo   %C_RED%ERROR: VMProtect segment name mismatch in the protected output.%C_RESET%
)
echo   %C_RED%       expected: %SEG_NAME% (optionally followed by digits)%C_RESET%
echo   %C_RED%       observed: %VM_SEG%%C_RESET%
exit /b 1

:write_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
>"%STATE_FILE%" echo SRC=%SRC_SHA%
>>"%STATE_FILE%" echo OUT=%OUT_SHA%
>>"%STATE_FILE%" echo VMSEG=%VM_SEG%
exit /b 0

:tail_log
if exist "%WORK_DIR%\vmp.log" for /f "usebackq delims=" %%L in ("%WORK_DIR%\vmp.log") do echo     %%L
exit /b 0

:clean_work
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" exit /b 1
exit /b 0

:assert_clean
for %%F in ("%OUT_ROOT%\*.vmp" "%OUT_ROOT%\*.log" "%OUT_ROOT%\*.bak" "%OUT_ROOT%\*.tmp") do if exist "%%~F" (
  echo   %C_RED%ERROR: protection artifact left in the release folder: %%~nxF%C_RESET%
  exit /b 1
)
exit /b 0

:vmp_wrapper
echo   %C_RED%ERROR: AMEGER_VMP_CON points at a batch/cmd wrapper: %VMP_CON%%C_RESET%
echo   %C_RED%       A wrapper transfers control and never returns; use the real console.%C_RESET%
goto :failure

:vmp_missing
echo   %C_RED%ERROR: VMProtect console not found.%C_RESET%
echo   %C_YELLOW%       Searched:%C_RESET%
echo         %PROGRAMFILES%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMW6432%\VMProtect*\VMProtect_Con.exe
echo         %PROGRAMFILES(X86)%\VMProtect*\VMProtect_Con.exe
echo         %LOCALAPPDATA%\VMProtect*\VMProtect_Con.exe
echo         PATH ^(VMProtect_Con.exe, vmpconsole.exe^)
echo   %C_YELLOW%       Fix: set AMEGER_VMP_CON to the full path, with no surrounding quotes,%C_RESET%
echo   %C_YELLOW%             e.g. set AMEGER_VMP_CON=C:\Program Files\VMProtect Ultimate\VMProtect_Con.exe%C_RESET%
echo   %C_YELLOW%       Leaving it unset is fine if VMProtect is installed normally.%C_RESET%
echo   %C_YELLOW%       Note: the console build is not included in the Lite edition.%C_RESET%
goto :failure

:target_missing
echo   %C_RED%ERROR: no launcher EXE found in the release folder.%C_RESET%
goto :failure

:target_ambiguous
echo   %C_RED%ERROR: expected exactly one launcher EXE in %OUT_ROOT%, found %EXE_CANDIDATES%.%C_RESET%
echo   %C_RED%       Refusing to guess which EXE to protect.%C_RESET%
goto :failure

:project_missing
echo   %C_RED%ERROR: no .vmp project found; set AMEGER_VMP_PROJECT_EXE.%C_RESET%
goto :failure

:project_mismatch
echo   %C_RED%ERROR: the project does not target this binary.%C_RESET%
echo   %C_RED%       Refusing to protect with a crossed project.%C_RESET%
goto :failure

:work_error
echo   %C_RED%ERROR: unable to prepare the protection staging directory.%C_RESET%
goto :failure

:hash_error
echo   %C_RED%ERROR: unable to calculate a SHA-256 for the target or runtime.%C_RESET%
goto :failure

:output_invalid
echo   %C_RED%ERROR: VMProtect output failed validation; release left untouched.%C_RESET%
goto :failure

:segment_error
echo   %C_RED%ERROR: the protected launcher does not carry the generated VMProtect segment.%C_RESET%
echo   %C_RED%       Release left untouched; the output was not deployed.%C_RESET%
goto :failure

:fc_error
echo   %C_RED%ERROR: unable to compare the protected output against the source.%C_RESET%
echo   %C_RED%       fc failed; the output is unverified and will not ship.%C_RESET%
goto :failure

:project_error
echo   %C_RED%ERROR: unable to prepare the randomized project copy.%C_RESET%
goto :failure

:deploy_error
echo   %C_RED%ERROR: unable to deploy the protected launcher.%C_RESET%
goto :failure

:embed_error
echo   %C_RED%ERROR: embedded runtime hash no longer matches the runtime DLL.%C_RESET%
echo   %C_RED%       The launcher would refuse to start; rebuild without protection.%C_RESET%
goto :failure

:cleanup_error
echo   %C_RED%ERROR: unable to remove generated protection artifacts.%C_RESET%
goto :failure

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
