@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
for %%A in (%*) do if /i "%%A"=="/nopause" set "NO_PAUSE=1"

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

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "BUILD_DIR=%ROOT%\Build"
set "OUT_ROOT=%BUILD_DIR%\Release"
set "STAGE_DIR=%BUILD_DIR%\Executors\Protection"
set "PROTECT_DLL=%STAGE_DIR%\ProtectDLL.bat"
set "PROTECT_EXE=%STAGE_DIR%\ProtectEXE.bat"
set "NAMES_STATE=%OUT_ROOT%\Cache\BuildNames.state"
set "PAYLOAD_NAME="
set "EXE_NAME="

set "STAGE=%~1"
if /i "%STAGE%"=="/nopause" set "STAGE="
if defined STAGE (
  if /i not "%STAGE%"=="dll" if /i not "%STAGE%"=="exe" (
    echo %C_RED%ERROR: unknown stage "%STAGE%"; use dll or exe.%C_RESET%
    goto :usage_error
  )
)

set "DLL_DIR_NAME="
set "PAYLOAD_DEST="

if not exist "%OUT_ROOT%" (
  echo   %C_RED%ERROR: release folder not found: %OUT_ROOT%%C_RESET%
  echo   %C_RED%       Run Create.bat before protecting anything.%C_RESET%
  goto :failure
)
if not exist "%PROTECT_DLL%" (
  echo   %C_RED%ERROR: missing stage script: %PROTECT_DLL%%C_RESET%
  goto :failure
)
if not exist "%PROTECT_EXE%" (
  echo   %C_RED%ERROR: missing stage script: %PROTECT_EXE%%C_RESET%
  goto :failure
)

echo [%C_GREEN%1%C_RESET%/%C_GREEN%3%C_RESET%] Preparing...
echo.
echo   %C_GREEN%[+]%C_RESET% Release:   %C_GREEN%%OUT_ROOT%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Stages:    %STAGE_DIR%
echo   %C_GREEN%[+]%C_RESET% Runtime:   %C_YELLOW%skipped by design (manual-mapped)%C_RESET%
echo.
echo.

set "DLL_RESULT=skipped"
set "EXE_RESULT=skipped"

if defined STAGE if /i "%STAGE%"=="exe" goto :run_exe

echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting payload...
echo.
call "%PROTECT_DLL%" /nopause
if errorlevel 1 (
  set "DLL_RESULT=failed"
  goto :summarize
)
set "DLL_RESULT=ok"

:run_exe
if defined STAGE if /i "%STAGE%"=="dll" goto :summarize
echo [%C_GREEN%2%C_RESET%/%C_GREEN%3%C_RESET%] Protecting launcher...
echo.
call "%PROTECT_EXE%" /nopause
if errorlevel 1 (
  set "EXE_RESULT=failed"
  goto :summarize
)
set "EXE_RESULT=ok"

:summarize
if exist "%NAMES_STATE%" for /f "usebackq tokens=1,* delims==" %%A in ("%NAMES_STATE%") do (
  if /i "%%A"=="PAYLOAD_NAME" if not defined PAYLOAD_NAME set "PAYLOAD_NAME=%%B"
  if /i "%%A"=="EXE_NAME" if not defined EXE_NAME set "EXE_NAME=%%B"
  if /i "%%A"=="DLLDIR_NAME" if not defined DLL_DIR_NAME set "DLL_DIR_NAME=%%B"
)
if defined DLL_DIR_NAME if exist "%OUT_ROOT%\%DLL_DIR_NAME%\%PAYLOAD_NAME%" set "PAYLOAD_DEST=%OUT_ROOT%\%DLL_DIR_NAME%\"
if not defined PAYLOAD_DEST if defined PAYLOAD_NAME for /f "delims=" %%F in ('dir /b /s /a-d "%OUT_ROOT%\%PAYLOAD_NAME%" 2^>nul') do if not defined PAYLOAD_DEST set "PAYLOAD_DEST=%%~dpF"
echo.
echo [%C_GREEN%3%C_RESET%/%C_GREEN%3%C_RESET%] Summary...
echo.
call :report "Payload" "%DLL_RESULT%"
call :report "Launcher" "%EXE_RESULT%"
echo.
if /i "%DLL_RESULT%"=="failed" goto :stage_failed
if /i "%EXE_RESULT%"=="failed" goto :stage_failed
echo Protection completed successfully.
echo.
if defined PAYLOAD_DEST (
  echo   Payload      = %C_GREEN%%PAYLOAD_DEST%%PAYLOAD_NAME%%C_RESET%
) else if defined PAYLOAD_NAME (
  echo   Payload      = %C_GREEN%%OUT_ROOT%\%PAYLOAD_NAME%%C_RESET%
) else (
  echo   Payload      = %C_YELLOW%deployed name state unavailable; see the payload stage above%C_RESET%
)
if defined EXE_NAME (
  echo   Interface x64 = %C_GREEN%%OUT_ROOT%\%EXE_NAME%.exe%C_RESET%
) else (
  echo   Interface x64 = %C_GREEN%%OUT_ROOT%\*.exe%C_RESET%
)
echo.
if not defined STAGE if exist "%NAMES_STATE%" del /f /q "%NAMES_STATE%" >nul 2>&1
if "%NO_PAUSE%"=="0" pause
exit /b 0

:report
if /i "%~2"=="ok" (
  echo   %C_GREEN%OK%C_RESET%    %~1
  exit /b 0
)
if /i "%~2"=="skipped" (
  echo   %C_YELLOW%-  %C_RESET%   %~1 ^(skipped^)
  exit /b 0
)
echo   %C_RED%FAIL%C_RESET%  %~1
exit /b 0

:stage_failed
echo.
echo %C_RED%Protection failed; the release is not shippable.%C_RESET%
goto :failure

:usage_error
if "%NO_PAUSE%"=="0" pause
exit /b 1

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
