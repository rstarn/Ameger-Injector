@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "NO_PAUSE=0"
if defined CREATE_NO_PAUSE set "NO_PAUSE=%CREATE_NO_PAUSE%"
if /i "%~1"=="/nopause" set "NO_PAUSE=1"
set "REPIN=0"
if /i "%~1"=="repin" set "REPIN=1"
if /i "%~1"=="/repin" set "REPIN=1"

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
set "OUT_ROOT=%ROOT%\Build\Release"
set "DEPS_RELEASE=%OUT_ROOT%"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "CACHE_RUNTIME=%RELEASE_CACHE%\Runtime"
set "CACHE_INTERFACE=%RELEASE_CACHE%\Injector"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "MUTATE_SCRIPT=%SCRIPTS_DIR%\BuildPE.ps1"
set "SEED_SCRIPT=%SCRIPTS_DIR%\CreateSeeds.ps1"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "VERIFY_SCRIPT=%SCRIPTS_DIR%\VerifyEmbedMagic.ps1"
set "VERIFY_SYSCALL_SCRIPT=%SCRIPTS_DIR%\VerifySyscallsLayer.ps1"
set "NAMES_SCRIPT=%SCRIPTS_DIR%\ShuffleNaming.ps1"
set "RENAME_SCRIPT=%SCRIPTS_DIR%\ShuffleExports.ps1"
set "EXPORTS_SCRIPT=%SCRIPTS_DIR%\VerifyExportsName.ps1"
set "REPIN_SCRIPT=%SCRIPTS_DIR%\RepinPayload.ps1"
set "NAMES_STATE=%RELEASE_CACHE%\BuildNames.state"
set "CONFIG_MASTER=%BUILD_DIR%\Configuration.ini"
set "PAYLOAD_ASSET=%ROOT%\Assets\DLL\Jlov.dll"
set "PAYLOAD_PROTECTED=%ROOT%\Assets\DLL\Jlov.protected.dll"
set "PAYLOAD_DEST="
set "RUNTIME_STOCK_DLL=%DEPS_RELEASE%\Ameger Injector - x64.dll"
set "LIBRARY_PROJ=%ROOT%\Interface\Template\AmegerInjector.vcxproj"
set "INTERFACE_PROJ=%ROOT%\Interface\Template\AmegerInjectorInterface.vcxproj"
set "OUT64=%OUT_ROOT%"
set "LIBRARY64_OBJ=%CACHE_RUNTIME%"
set "INTERFACE64_OBJ=%CACHE_INTERFACE%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="

if "%REPIN%"=="1" goto :repin_payload
echo [%C_GREEN%1%C_RESET%/%C_GREEN%6%C_RESET%] Checking MSBuild...
echo.
call :find_msbuild
if errorlevel 1 goto :msbuild_error
if not defined AMEGER_PLATFORM_TOOLSET call :select_toolset
set "TOOLSET_ARG="
if defined AMEGER_PLATFORM_TOOLSET set "TOOLSET_ARG=/p:PlatformToolset=%AMEGER_PLATFORM_TOOLSET%"
set "SDK_ARG="
if defined AMEGER_WINDOWS_SDK_VERSION set "SDK_ARG=/p:WindowsTargetPlatformVersion=%AMEGER_WINDOWS_SDK_VERSION%"
echo   %C_GREEN%[+]%C_RESET% MSBuild: %C_GREEN%%MSBUILD%%C_RESET%
if defined AMEGER_PLATFORM_TOOLSET echo   %C_GREEN%[+]%C_RESET% Platform toolset: %C_GREEN%%AMEGER_PLATFORM_TOOLSET%%C_RESET%
if defined AMEGER_WINDOWS_SDK_VERSION echo   %C_GREEN%[+]%C_RESET% Windows SDK: %C_GREEN%%AMEGER_WINDOWS_SDK_VERSION%%C_RESET%
echo.
echo.

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Checking Projects...
echo.
if not exist "%LIBRARY_PROJ%" goto :source_error
if not exist "%INTERFACE_PROJ%" goto :source_error
echo   %C_GREEN%[+]%C_RESET% Runtime And Interface Projects Present.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Cleaning Release And Cache...
echo.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%BUILD_DIR%\obj"
if errorlevel 1 goto :clean_error
call :prepare_cache
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean Layout Prepared In %C_GREEN%%RELEASE_CACHE%%C_RESET%.
echo.
echo.
call :generate_names
if errorlevel 1 goto :names_error
set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
if not exist "%DLL_DIR%" (
  echo   %C_RED%Error: Unable To Create The Per-Build DLL Folder; Refusing To Deploy Stable Names.%C_RESET%
  goto :clean_error
)
set "DEPLOYED_CONFIG=%OUT_ROOT%\%CONFIG_NAME%.ini"
set "PAYLOAD_DEST=%DLL_DIR%\%PAYLOAD_NAME%"
set "INTERFACE_EXE=%OUT64%\%EXE_NAME%.exe"
echo   %C_GREEN%[+]%C_RESET% Deployed Payload Name = %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Runtime Name = %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed Launcher Name = %C_GREEN%%EXE_NAME%.exe%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed DLL Folder = %C_GREEN%%DLLDIR_NAME%%C_RESET%
echo.
echo.

call :maybe_adopt_payload
if errorlevel 1 goto :payload_error

echo [%C_GREEN%4%C_RESET%/%C_GREEN%6%C_RESET%] Building Injector...
set "MUTATE_ARGS="
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :seeds_ready
where powershell.exe >nul 2>&1
if errorlevel 1 goto :seeds_missing
if not exist "%SEED_SCRIPT%" goto :seeds_missing
set "AmegerMmapSentinel="
set "AmegerStringSeed="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SEED_SCRIPT%"`) do set "%%A=%%B"
if not defined AmegerMmapSentinel goto :seeds_missing
if not defined AmegerStringSeed goto :seeds_missing
set /a "AmegerStubSeed=(%AmegerMmapSentinel%) & 0x7FFFFFFF"
if not defined AmegerStubSeed goto :seeds_missing
if "%AmegerStubSeed%"=="0" goto :seeds_missing
    set "MUTATE_ARGS=/p:AmegerMmapSentinel=%AmegerMmapSentinel% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerStubSeed=%AmegerStubSeed%"
echo.
echo   %C_GREEN%[+]%C_RESET% Per-Build Sentinel = %C_GREEN%%AmegerMmapSentinel%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Per-Build String Seed = %C_GREEN%%AmegerStringSeed%%C_RESET%
echo.
goto :seeds_ready

:seeds_missing
echo.
echo   %C_RED%Error: Per-Build Seed Generation Failed; Refusing To Build With Fixed Seeds.%C_RESET%
goto :failure

:seeds_ready
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error

REM The remote mapping shell is staged into the target as one contiguous span sized from
REM (MMAP_SEC_END - ManualMapping_Shell), which is only correct if the linker merged every
REM .code$NN part into a single section. That has to be checked on the raw linker output:
REM BuildPE.ps1 randomises every section name a few lines below, so by the end of the build the
REM section is no longer called .code and the check could not find it. This is the one content
REM check that cannot be a byte scan, because an unmerged link still passes every pattern scan.
call :verify_mmap_sections "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :verify_error
echo.
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_RED%Error: BuildPE.ps1 Was Not Found; Refusing To Continue With An Unmutated Runtime DLL.%C_RESET%
goto :failure

:runtime_mutate_ready
call :rename_exports
if errorlevel 1 goto :rename_export_error
call :write_names_state
if errorlevel 1 goto :names_state_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
set "RTSHA_TMP=%TEMP%\amg_rtsha_%RANDOM%%RANDOM%"
set "RTSHA_B64=%RTSHA_TMP%.b64"
set "RTSHA_PS1=%RTSHA_TMP%.ps1"
set "RTSHA_OUT=%RTSHA_TMP%.out"
>"%RTSHA_B64%" echo -----BEGIN CERTIFICATE-----
>>"%RTSHA_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ1JVTlRJTUVfU0hBMjU2PScgKyAkaCkNCldyaXRlLU91dHB1dCAoJ0gwPTB4JyArICRoLlN1YnN0cmluZygwLDgpKQ0KV3JpdGUtT3V0cHV0ICgnSDE9MHgnICsgJGguU3Vic3RyaW5nKDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMj0weCcgKyAkaC5TdWJzdHJpbmcoMTYsOCkpDQpXcml0ZS1PdXRwdXQgKCdIMz0weCcgKyAkaC5TdWJzdHJpbmcoMjQsOCkpDQpXcml0ZS1PdXRwdXQgKCdIND0weCcgKyAkaC5TdWJzdHJpbmcoMzIsOCkpDQpXcml0ZS1PdXRwdXQgKCdINT0weCcgKyAkaC5TdWJzdHJpbmcoNDAsOCkpDQpXcml0ZS1PdXRwdXQgKCdINj0weCcgKyAkaC5TdWJzdHJpbmcoNDgsOCkpDQpXcml0ZS1PdXRwdXQgKCdINz0weCcgKyAkaC5TdWJzdHJpbmcoNTYsOCkpDQo=
>>"%RTSHA_B64%" echo -----END CERTIFICATE-----
certutil -decode "%RTSHA_B64%" "%RTSHA_PS1%" >nul 2>&1
if errorlevel 1 goto :rtsha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RTSHA_PS1%" -Path "%RUNTIME_STOCK_DLL%" >"%RTSHA_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%RTSHA_OUT%") do set "%%A=%%B"
:rtsha_cleanup
if exist "%RTSHA_PS1%" del /f /q "%RTSHA_PS1%" >nul 2>&1
if exist "%RTSHA_B64%" del /f /q "%RTSHA_B64%" >nul 2>&1
if exist "%RTSHA_OUT%" del /f /q "%RTSHA_OUT%" >nul 2>&1
if not defined RUNTIME_SHA256 goto :hash_error
if not defined H0 goto :hash_error
if not defined H1 goto :hash_error
if not defined H2 goto :hash_error
if not defined H3 goto :hash_error
if not defined H4 goto :hash_error
if not defined H5 goto :hash_error
if not defined H6 goto :hash_error
if not defined H7 goto :hash_error
set "RUNTIME_HASH_ARGS=/p:AmegerRuntimeHash0=%H0% /p:AmegerRuntimeHash1=%H1% /p:AmegerRuntimeHash2=%H2% /p:AmegerRuntimeHash3=%H3% /p:AmegerRuntimeHash4=%H4% /p:AmegerRuntimeHash5=%H5% /p:AmegerRuntimeHash6=%H6% /p:AmegerRuntimeHash7=%H7% /p:AmegerStringSeed=%AmegerStringSeed% /p:AmegerExeName=%EXE_NAME% /p:AmegerConfigMagic=%CONFIG_MAGIC%"
set "RUNTIME_DLL_NAME=%RUNTIME_NAME%"
set "RUNTIME_DLL=%DLL_DIR%\%RUNTIME_DLL_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
move /y "%RUNTIME_STOCK_DLL%" "%RUNTIME_DLL%" >nul
if not exist "%RUNTIME_DLL%" goto :runtime_rename_error
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256 = %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying Release Binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime Binaries Are In %C_GREEN%%OUT_ROOT%%C_RESET%.
call :deploy_payload
if errorlevel 1 goto :payload_error
call :protect_config
if errorlevel 1 goto :config_error
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping Intermediates Into Cache And Verifying...
echo.
set "EXE_COUNT=0"
for %%F in ("%OUT64%\*.exe") do set /a "EXE_COUNT+=1"
if not "%EXE_COUNT%"=="1" (
  echo   %C_RED%Error: Expected Exactly One Launcher EXE In %OUT64%, Found %EXE_COUNT%.%C_RESET%
  goto :verify_error
)
if not exist "%INTERFACE_EXE%" (
  echo   %C_RED%Error: Expected Launcher Missing: %INTERFACE_EXE%%C_RESET%
  goto :verify_error
)
call :verify "%INTERFACE_EXE%" "x64 Interface"
if errorlevel 1 goto :verify_error
call :verify_embed
if errorlevel 1 goto :verify_content_error
call :verify_config_magic
if errorlevel 1 goto :verify_content_error
call :verify_deployed_pin
if errorlevel 1 goto :verify_content_error
call :verify_config_keys
if errorlevel 1 goto :verify_content_error
call :verify "%RUNTIME_DLL%" "x64 runtime"
if errorlevel 1 goto :verify_error
call :verify_syscall_stub
if errorlevel 1 goto :verify_content_error
call :verify_syscall_payload
if errorlevel 1 goto :verify_content_error
call :verify_syscall_stealth
if errorlevel 1 goto :verify_content_error
call :verify_export_names "%RUNTIME_DLL%"
if errorlevel 1 goto :verify_content_error
echo.
echo   %C_GREEN%[+]%C_RESET% SyscallStub         = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallPayload      = %C_GREEN%OK%C_RESET%
echo   %C_GREEN%[+]%C_RESET% SyscallStealth      = %C_GREEN%OK%C_RESET%
echo.
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :remove_import_artifacts "%DLL_DIR%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache Groups = Runtime, Injector.
echo.
echo.

if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :refuse_unmutated
if not exist "%MUTATE_SCRIPT%" goto :mutate_exe_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :mutate_exe_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%INTERFACE_EXE%"
if errorlevel 1 goto :mutate_exe_error
call :verify_embed
if errorlevel 1 goto :verify_content_error

call :write_section_manifest
if errorlevel 1 goto :manifest_error
echo.
echo Build Completed Successfully.
echo.
echo Cache = %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Payload = %C_GREEN%%PAYLOAD_DEST%%C_RESET%
echo Interface x64 = %C_GREEN%%INTERFACE_EXE%%C_RESET%
echo Runtime DLL = %C_GREEN%%RUNTIME_DLL%%C_RESET%

echo.
call :scrub_build_cache
if errorlevel 1 goto :scrub_error
if "%NO_PAUSE%"=="0" pause
exit /b 0

:find_msbuild
if exist "%VSWHERE%" for /f "usebackq delims=" %%M in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2^>nul`) do if not defined MSBUILD if exist "%%M" set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if defined MSBUILD exit /b 0
for /f "delims=" %%M in ('where msbuild.exe 2^>nul') do if not defined MSBUILD set "MSBUILD=%%M"
if defined MSBUILD exit /b 0
exit /b 1

:select_toolset
if defined AMEGER_PLATFORM_TOOLSET exit /b 0
if not exist "%VSWHERE%" exit /b 0
set "VS_VERSION="
for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -property installationVersion 2^>nul`) do if not defined VS_VERSION set "VS_VERSION=%%V"
if not defined VS_VERSION exit /b 0
for /f "tokens=1 delims=." %%V in ("%VS_VERSION%") do set "VS_MAJOR=%%V"
if "%VS_MAJOR%"=="18" set "AMEGER_PLATFORM_TOOLSET=v145"
if "%VS_MAJOR%"=="17" set "AMEGER_PLATFORM_TOOLSET=v143"
exit /b 0

:clean_directory
if exist "%~1" rmdir /s /q "%~1"
if exist "%~1" exit /b 1
exit /b 0

:prepare_cache
if not exist "%DEPS_RELEASE%" mkdir "%DEPS_RELEASE%"
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%CACHE_RUNTIME%" mkdir "%CACHE_RUNTIME%"
if not exist "%CACHE_INTERFACE%" mkdir "%CACHE_INTERFACE%"
if not exist "%CACHE_RUNTIME%" exit /b 1
if not exist "%CACHE_INTERFACE%" exit /b 1
exit /b 0

:generate_names
if not exist "%NAMES_SCRIPT%" (
  echo   %C_RED%Error: ShuffleNaming.ps1 Not Found; Refusing To Deploy Stable Names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Deploy Stable Names.%C_RESET%
  exit /b 1
)
set "PAYLOAD_NAME="
set "RUNTIME_NAME="
set "EXE_NAME="
set "DLLDIR_NAME="
set "CONFIG_NAME="
set "CONFIG_MAGIC="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%NAMES_SCRIPT%"`) do set "%%A=%%B"
if not defined PAYLOAD_NAME exit /b 1
if not defined RUNTIME_NAME exit /b 1
if not defined EXE_NAME exit /b 1
if not defined DLLDIR_NAME exit /b 1
if not defined CONFIG_NAME exit /b 1
if not defined CONFIG_MAGIC exit /b 1
if /i "%PAYLOAD_NAME%"=="%RUNTIME_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%EXE_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%PAYLOAD_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%EXE_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%RUNTIME_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%EXE_NAME%"=="%DLLDIR_NAME%" exit /b 1
if /i "%EXE_NAME%"=="%CONFIG_NAME%" exit /b 1
if /i "%DLLDIR_NAME%"=="%CONFIG_NAME%" exit /b 1
echo   %C_GREEN%[+]%C_RESET% PayloadName = %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% RuntimeName = %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ExeName     = %C_GREEN%%EXE_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% DllDirName  = %C_GREEN%%DLLDIR_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ConfigName  = %C_GREEN%%CONFIG_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% LogName     = %C_GREEN%%CONFIG_NAME%.log%C_RESET%
echo   %C_GREEN%[+]%C_RESET% ConfigMagic = %C_GREEN%%CONFIG_MAGIC%%C_RESET%
echo.
exit /b 0

:rename_exports
if not exist "%RENAME_SCRIPT%" (
  echo   %C_RED%Error: ShuffleExports.ps1 Not Found; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
set "RENAME_STATUS="
set "EXPORT_MAP="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RENAME_SCRIPT%" -Path "%RUNTIME_STOCK_DLL%"`) do set "%%A=%%B"
if /i not "%RENAME_STATUS%"=="ok" (
  echo   %C_RED%Error: Runtime Export Rename Failed; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%Error: Runtime Export Rename Produced No Map; Refusing To Ship Stable Export Names.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Runtime Exports Renamed (Map Captured).
exit /b 0

:write_names_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%NAMES_STATE%" echo PAYLOAD_NAME=%PAYLOAD_NAME%
>>"%NAMES_STATE%" echo RUNTIME_NAME=%RUNTIME_NAME%
>>"%NAMES_STATE%" echo EXE_NAME=%EXE_NAME%
>>"%NAMES_STATE%" echo DLLDIR_NAME=%DLLDIR_NAME%
>>"%NAMES_STATE%" echo CONFIG_NAME=%CONFIG_NAME%
>>"%NAMES_STATE%" echo LOG_NAME=%CONFIG_NAME%.log
>>"%NAMES_STATE%" echo CONFIG_MAGIC=%CONFIG_MAGIC%
>>"%NAMES_STATE%" echo EXPORT_MAP=%EXPORT_MAP%
if not exist "%NAMES_STATE%" exit /b 1
exit /b 0

:build_project
set "PROJECT=%~1"
set "ARCH=%~2"
set "PROJECT_OUT=%~3"
set "PROJECT_INT=%~4"
if not exist "%PROJECT%" exit /b 2
if not exist "%PROJECT_OUT%" mkdir "%PROJECT_OUT%"
if not exist "%PROJECT_OUT%" exit /b 2
if not exist "%PROJECT_INT%" mkdir "%PROJECT_INT%"
if not exist "%PROJECT_INT%" exit /b 2
echo   %C_GREEN%Building%C_RESET% %PROJECT% %C_RED%(%ARCH%)%C_RESET%
"%MSBUILD%" "%PROJECT%" /nologo /m /nodeReuse:false /v:minimal /t:Build /p:Configuration=Release /p:Platform=%~2 "/p:OutDir=%~3\\" "/p:IntDir=%~4\\" %~5 %~6 %~7
exit /b %ERRORLEVEL%

:verify
if not exist "%~1" exit /b 1
echo   %C_GREEN%OK%C_RESET% %~2 = %C_GREEN%"%~1"%C_RESET%
exit /b 0

:verify_embed
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Embed -Path "%INTERFACE_EXE%" -Words "%H0%,%H1%,%H2%,%H3%,%H4%,%H5%,%H6%,%H7%"
exit /b %ERRORLEVEL%

:verify_config_magic
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check Magic -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%"
exit /b %ERRORLEVEL%

:verify_deployed_pin
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check DeployedPin -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%" -ExpectPin "%DEPLOYED_SHA%"
exit /b %ERRORLEVEL%

:verify_config_keys
if not defined CONFIG_MAGIC exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check ConfigKeys -Path "%DEPLOYED_CONFIG%" -Magic "%CONFIG_MAGIC%"
exit /b %ERRORLEVEL%

REM Confirms the stealth critical plumbing is actually compiled into the shipped runtime. These are
REM static checks on the built image; the live behaviour is covered by the runtime verify tool.
:verify_syscall_stub
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Stub -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

:verify_syscall_payload
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Payload -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

:verify_syscall_stealth
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check Stealth -Path "%RUNTIME_DLL%"
exit /b %ERRORLEVEL%

REM Confirms the remote mapping shell is still one contiguous, execute-read block. Takes the image
REM path as an argument because it runs on the pre-mutation linker output, before BuildPE.ps1 has
REM randomised the section names.
:verify_mmap_sections
if not exist "%VERIFY_SYSCALL_SCRIPT%" exit /b 1
set "MMAP_VERIFY_PATH=%~1"
if not defined MMAP_VERIFY_PATH set "MMAP_VERIFY_PATH=%RUNTIME_DLL%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SYSCALL_SCRIPT%" -Check MmapSections -Path "%MMAP_VERIFY_PATH%"
exit /b %ERRORLEVEL%

REM Refuses to ship a runtime whose export table still carries a stable, greppable entrypoint
REM name. ShuffleExports.ps1 renames them per build; this is the gate that proves it happened.
:verify_export_names
if not exist "%EXPORTS_SCRIPT%" exit /b 1
where powershell.exe >nul 2>&1
if errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%EXPORTS_SCRIPT%" -Path "%~1"
exit /b %ERRORLEVEL%

:remove_import_artifacts
for %%F in ("%~1\*.lib" "%~1\*.exp") do if exist "%%~F" (
  del /f /q "%%~F"
  if exist "%%~F" exit /b 1
)
exit /b 0

:sweep_artifacts
for %%F in ("%DEPS_RELEASE%\Ameger Injector - *.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_RUNTIME%\" >nul
  if exist "%%~F" exit /b 1
)
for %%F in ("%OUT64%\*.pdb") do if exist "%%~F" (
  move "%%~F" "%CACHE_INTERFACE%\" >nul
  if exist "%%~F" exit /b 1
)
exit /b 0

:protect_config
if not defined DEPLOYED_SHA (
  echo   %C_RED%Error: Deployed Payload SHA-256 Unavailable; Refusing To Ship An Unpinned Config.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_NAME (
  echo   %C_RED%Error: Deployed Payload Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined RUNTIME_NAME (
  echo   %C_RED%Error: Deployed Runtime Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined DLLDIR_NAME (
  echo   %C_RED%Error: Deployed DLL Folder Name Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%Error: Runtime Export Map Unavailable; Refusing To Ship An Unstamped Config.%C_RESET%
  exit /b 1
)
if not defined CONFIG_MAGIC (
  echo   %C_RED%Error: Per-Build Config Magic Unavailable; Refusing To Ship A Static-Magic Config.%C_RESET%
  exit /b 1
)
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_RED%Error: AMEGER_ENCRYPT_CONFIG=0 Is Refused; The Launcher Rejects Plaintext Configs, So This Would Ship An Unloadable Release.%C_RESET%
  echo   %C_RED%Rebuild without the opt-out to ship the encrypted config.%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%Error: Master Config Not Found: %CONFIG_MASTER%%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_SCRIPT%" (
  echo   %C_RED%Error: ProtectConfig.ps1 Not Found; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%CONFIG_MASTER%" -Destination "%DEPLOYED_CONFIG%" -PinPayload "%PAYLOAD_DEST%" -PayloadName "%PAYLOAD_NAME%" -RuntimeName "%RUNTIME_NAME%" -ExportMap "%EXPORT_MAP%" -DllDir "%DLLDIR_NAME%" -ConfigMagic "%CONFIG_MAGIC%"
if errorlevel 1 (
  echo   %C_RED%Error: Config Encryption Failed; Refusing To Ship A Plaintext Config.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Config Encrypted = %C_GREEN%%DEPLOYED_CONFIG%%C_RESET%
exit /b 0

:deploy_payload
set "PAYLOAD_SRC=%PAYLOAD_ASSET%"
set "PAYLOAD_IS_PREPARED="
if defined AMEGER_PAYLOAD (
  set "PAYLOAD_SRC=%AMEGER_PAYLOAD%"
  set "PAYLOAD_IS_PREPARED=1"
) else if exist "%PAYLOAD_PROTECTED%" (
  set "PAYLOAD_SRC=%PAYLOAD_PROTECTED%"
  set "PAYLOAD_IS_PREPARED=1"
)
if not exist "%PAYLOAD_SRC%" (
  echo   %C_RED%Error: Payload Asset Not Found: %PAYLOAD_SRC%%C_RESET%
  exit /b 1
)
if defined PAYLOAD_IS_PREPARED echo   %C_YELLOW%[+]%C_RESET% Prepared payload: %C_YELLOW%%PAYLOAD_SRC%%C_RESET%
copy /y "%PAYLOAD_SRC%" "%PAYLOAD_DEST%" >nul
if errorlevel 1 (
  echo   %C_RED%Error: Failed To Copy Payload To %PAYLOAD_DEST%%C_RESET%
  exit /b 1
)
set "DEPLOYED_SHA="
set "DSHA_TMP=%TEMP%\amg_dsha_%RANDOM%%RANDOM%"
set "DSHA_B64=%DSHA_TMP%.b64"
set "DSHA_PS1=%DSHA_TMP%.ps1"
set "DSHA_OUT=%DSHA_TMP%.out"
>"%DSHA_B64%" echo -----BEGIN CERTIFICATE-----
>>"%DSHA_B64%" echo cGFyYW0oW3N0cmluZ10kUGF0aCkNCiRoID0gKFtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl06OkNyZWF0ZSgpLkNvbXB1dGVIYXNoKFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRQYXRoKSkpIC1yZXBsYWNlICctJywnJykNCldyaXRlLU91dHB1dCAoJ0RFUExPWUVEX1NIQT0nICsgJGgpDQo=
>>"%DSHA_B64%" echo -----END CERTIFICATE-----
certutil -decode "%DSHA_B64%" "%DSHA_PS1%" >nul 2>&1
if errorlevel 1 goto :dsha_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%DSHA_PS1%" -Path "%PAYLOAD_DEST%" >"%DSHA_OUT%" 2>&1
for /f "usebackq tokens=1,2 delims==" %%A in ("%DSHA_OUT%") do set "%%A=%%B"
:dsha_cleanup
if exist "%DSHA_PS1%" del /f /q "%DSHA_PS1%" >nul 2>&1
if exist "%DSHA_B64%" del /f /q "%DSHA_B64%" >nul 2>&1
if exist "%DSHA_OUT%" del /f /q "%DSHA_OUT%" >nul 2>&1
if not defined DEPLOYED_SHA (
  echo   %C_RED%Error: Unable To Hash The Deployed Payload.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_IS_PREPARED (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_DEST%" -Config "%CONFIG_MASTER%"
  if errorlevel 1 (
    echo   %C_RED%Error: Deployed Payload Failed Hash Verification.%C_RESET%
    echo     The pristine asset %PAYLOAD_ASSET% does not match the master PayloadSha256 pin.
    echo     If you intentionally swapped the payload, refresh the pin and rebuild:
    echo         Create.bat repin
    echo     Or ship the changed DLL without touching the master pristine pin:
    echo         set AMEGER_PAYLOAD=path\to.dll  and rerun Create.bat
    echo         or copy it to "%PAYLOAD_PROTECTED%"
    exit /b 1
  )
) else (
  echo   %C_YELLOW%[+]%C_RESET% Prepared payload deployed; master pin left pristine.%C_RESET%
)
echo   %C_GREEN%[+]%C_RESET% Payload deployed: %C_GREEN%%PAYLOAD_DEST%%C_RESET%
exit /b 0

:write_section_manifest
set "MANIFEST=%RELEASE_CACHE%\pe-sections.txt"
set "MANIF_TMP=%TEMP%\amg_manif_%RANDOM%%RANDOM%"
set "MANIF_B64=%MANIF_TMP%.b64"
set "MANIF_PS1=%MANIF_TMP%.ps1"
set "MANIF_RC=1"
>"%MANIF_B64%" echo -----BEGIN CERTIFICATE-----
>>"%MANIF_B64%" echo cGFyYW0oW3N0cmluZ10kSW50ZXJmYWNlRXhlLCBbc3RyaW5nXSRQYXlsb2FkLCBbc3RyaW5nXSRNYW5pZmVzdCkNCiRvdXQgPSBAKCkNCmZvcmVhY2ggKCRwIGluIEAoJEludGVyZmFjZUV4ZSwgJFBheWxvYWQpKSB7DQogICAgaWYgKC1ub3QgKFRlc3QtUGF0aCAtTGl0ZXJhbFBhdGggJHApKSB7IGV4aXQgMSB9DQogICAgJGIgPSBbSU8uRmlsZV06OlJlYWRBbGxCeXRlcygkcCkNCiAgICAkZSA9IFtCaXRDb252ZXJ0ZXJdOjpUb0ludDMyKCRiLCAweDNDKQ0KICAgICRjID0gJGUgKyA0DQogICAgJG4gPSBbQml0Q29udmVydGVyXTo6VG9VSW50MTYoJGIsICRjICsgMikNCiAgICAkeiA9IFtCaXRDb252ZXJ0ZXJdOjpUb1VJbnQxNigkYiwgJGMgKyAxNikNCiAgICAkcyA9ICRjICsgMjAgKyAkeg0KICAgICRuYW1lcyA9IEAoKQ0KICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJG47ICRpKyspIHsNCiAgICAgICAgJG8gPSAkcyArIDQwICogJGkNCiAgICAgICAgJG5tID0gW1RleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJGIsICRvLCA4KS5UcmltKFtjaGFyXTApDQogICAgICAgICR4ID0gW0JpdENvbnZlcnRlcl06OlRvVUludDMyKCRiLCAkbyArIDM2KQ0KICAgICAgICBpZiAoJHggLWJhbmQgMHgyMDAwMDAwMCkgeyAkbmFtZXMgKz0gKCRubSArICcrWCcpIH0gZWxzZSB7ICRuYW1lcyArPSAkbm0gfQ0KICAgIH0NCiAgICAkb3V0ICs9IChbSU8uUGF0aF06OkdldEZpbGVOYW1lKCRwKSArICc6JyArICgkbmFtZXMgLWpvaW4gJywnKSkNCn0NCltJTy5GaWxlXTo6V3JpdGVBbGxMaW5lcygkTWFuaWZlc3QsICRvdXQpDQo=
>>"%MANIF_B64%" echo -----END CERTIFICATE-----
certutil -decode "%MANIF_B64%" "%MANIF_PS1%" >nul 2>&1
if errorlevel 1 goto :manif_cleanup
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MANIF_PS1%" -InterfaceExe "%INTERFACE_EXE%" -Payload "%PAYLOAD_DEST%" -Manifest "%MANIFEST%"
set "MANIF_RC=%ERRORLEVEL%"
:manif_cleanup
if exist "%MANIF_PS1%" del /f /q "%MANIF_PS1%" >nul 2>&1
if exist "%MANIF_B64%" del /f /q "%MANIF_B64%" >nul 2>&1
if not "%MANIF_RC%"=="0" exit /b 1
if not exist "%MANIFEST%" exit /b 1
exit /b 0

:scrub_build_cache
if /i "%AMEGER_KEEP_BUILD_CACHE%"=="1" (
  echo   %C_YELLOW%[!]%C_RESET% Build-cache scrub skipped ^(AMEGER_KEEP_BUILD_CACHE=1^); residue retained.
  exit /b 0
)
if not exist "%RELEASE_CACHE%" exit /b 0
set "SCRUB_FAILED="
for /f "delims=" %%F in ('dir /b /a "%RELEASE_CACHE%" 2^>nul') do call :scrub_entry "%%F"
if defined SCRUB_FAILED exit /b 1
echo   %C_GREEN%[+]%C_RESET% Build cache scrubbed; kept pe-sections.txt and Protect state.
echo.
exit /b 0

:scrub_entry
call :scrub_preserved "%~1"
if not errorlevel 1 exit /b 0
rmdir /s /q "%RELEASE_CACHE%\%~1" 2>nul
del /f /q "%RELEASE_CACHE%\%~1" 2>nul
if exist "%RELEASE_CACHE%\%~1" (
  echo   %C_RED%Error: Unable To Remove Build Residue: %RELEASE_CACHE%\%~1%C_RESET%
  set "SCRUB_FAILED=1"
)
exit /b 0

:scrub_preserved
if /i "%~1"=="pe-sections.txt" exit /b 0
if /i "%~1"=="Protect.payload.state" exit /b 0
if /i "%~1"=="Protect.exe.state" exit /b 0
if /i "%~1"=="BuildNames.state" exit /b 0
exit /b 1

:manifest_error
echo   %C_RED%Error: Unable To Record The PE Section Baseline Manifest.%C_RESET%
goto :failure

:scrub_error
echo   %C_RED%Error: Post-Success Build-Cache Scrub Failed; Residue May Remain In %RELEASE_CACHE%.%C_RESET%
goto :failure

:msbuild_error
echo %C_RED%Error: MSBuild Was Not Found.%C_RESET%
goto :failure

:source_error
echo %C_RED%Error: One Or More Required Project Files Are Missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%Error: Unable To Prepare The Release Or Cache Directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%Error: A Project Build Failed.%C_RESET%
goto :failure

:hash_error
echo %C_RED%Error: Unable To Calculate The Runtime DLL SHA-256.%C_RESET%
goto :failure

:runtime_rename_error
echo %C_RED%Error: Unable To Rename The Runtime DLL To Its Per-Build Name.%C_RESET%
goto :failure

:names_error
echo %C_RED%Error: Unable To Generate The Per-Build Deployed File Names.%C_RESET%
goto :failure

:rename_export_error
echo %C_RED%Error: Unable To Rename The Runtime DLL Exports.%C_RESET%
goto :failure

:names_state_error
echo %C_RED%Error: Unable To Record The Per-Build Name State.%C_RESET%
goto :failure

:verify_error
echo %C_RED%Error: One Or More Expected Binaries Are Missing.%C_RESET%
goto :failure

:verify_content_error
echo %C_RED%Error: Content Verification Failed (Embedded Runtime Hash, Config Magic, Deployed Pin, Per-Build Config Key, Syscall/Stealth Layer, Or Mmap Section Merge).%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%Error: Unable To Remove Generated Import Artifacts.%C_RESET%
goto :failure

:config_error
echo %C_RED%Error: Unable To Deploy An Encrypted Configuration.%C_RESET%
goto :failure

:payload_error
echo %C_RED%Error: Unable To Deploy The Target Payload.%C_RESET%
goto :failure

:mutate_fatal
echo %C_RED%Error: Unable To Mutate The Runtime DLL; Refusing To Continue With An Inconsistent Build.%C_RESET%
goto :failure

:mutate_exe_error
echo %C_RED%Error: Interface PE Mutation Failed Or BuildPE.ps1 Was Not Found; Refusing To Continue With An Inconsistent Build.%C_RESET%
goto :failure

:refuse_unmutated
echo.
echo %C_RED%Error: AMEGER_REFUSE_UNMUTATED=1 Would Ship Unmutated Binaries (Stable Timestamps, MSVC Rich Fingerprint, Standard Section Names, PDB Debug Directory). Refusing: Rebuild Without The Bypass For Any Shipped Build.%C_RESET%
goto :failure

:maybe_adopt_payload
if not exist "%PAYLOAD_ASSET%" exit /b 0
if not exist "%CONFIG_MASTER%" exit /b 0
if not exist "%VERIFY_SCRIPT%" exit /b 0
where powershell.exe >nul 2>&1
if errorlevel 1 exit /b 0

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_ASSET%" -Config "%CONFIG_MASTER%" >nul 2>&1
if not errorlevel 1 exit /b 0

echo.
echo   %C_YELLOW%[!]%C_RESET% The Payload Asset Does Not Match The Master PayloadSha256 Pin:
echo       Asset  = %C_YELLOW%%PAYLOAD_ASSET%%C_RESET%
echo       Config = %C_YELLOW%%CONFIG_MASTER%%C_RESET%
if /i not "%AMEGER_AUTO_REPIN%"=="1" (
  echo.
  echo   %C_RED%Refusing To Continue With A Payload The Master Config Does Not Describe.%C_RESET%
  echo   The Deployed Pin Would Describe A DLL That Is Not The One Being Shipped, And
  echo   The Only Thing That Would Hide The Mismatch Is Rewriting The Master Pin.
  echo.
  echo   If The Asset Was Replaced Intentionally, Adopt It Explicitly:
  echo       Create.bat repin
  echo   Or Ship A One-Off DLL Without Touching The Master Pin:
  echo       set AMEGER_PAYLOAD=path\to\dll  and rerun Create.bat
  echo   To Restore The Previous Behaviour Of Adopting The Asset Automatically:
  echo       set AMEGER_AUTO_REPIN=1  and rerun Create.bat
  exit /b 1
)
if not exist "%REPIN_SCRIPT%" (
  echo   %C_RED%Error: AMEGER_AUTO_REPIN=1 But RepinPayload.ps1 Was Not Found.%C_RESET%
  exit /b 1
)
echo   %C_YELLOW%[!]%C_RESET% AMEGER_AUTO_REPIN=1: Re-Pinning The Master Config To The Current Asset.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPIN_SCRIPT%" -Config "%CONFIG_MASTER%" -Payload "%PAYLOAD_ASSET%" -Quiet
if errorlevel 1 (
  echo   %C_RED%Error: Could Not Re-Pin The Master To The Current Payload Asset.%C_RESET%
  exit /b 1
)
exit /b 0

:repin_payload
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%Error: Master Config Not Found: %CONFIG_MASTER%%C_RESET%
  goto :failure
)
if not exist "%REPIN_SCRIPT%" (
  echo   %C_RED%Error: RepinPayload.ps1 Not Found; Refusing To Re-Pin.%C_RESET%
  goto :failure
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%Error: PowerShell Unavailable; Cannot Re-Pin.%C_RESET%
  goto :failure
)
set "REPIN_SRC=%PAYLOAD_ASSET%"
if defined AMEGER_PAYLOAD set "REPIN_SRC=%AMEGER_PAYLOAD%"
if not exist "%REPIN_SRC%" (
  echo   %C_RED%Error: Payload Asset Not Found: %REPIN_SRC%%C_RESET%
  goto :failure
)
echo   Repinning master pin for: %C_YELLOW%%REPIN_SRC%%C_RESET%
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPIN_SCRIPT%" -Config "%CONFIG_MASTER%" -Payload "%REPIN_SRC%"
if errorlevel 1 goto :failure
goto :repin_success

:repin_success
echo.
echo   %C_GREEN%[+]%C_RESET% Master Configuration.ini re-pinned. Re-run Create.bat to deploy the new payload.
if "%NO_PAUSE%"=="0" pause
exit /b 0

:failure
if "%NO_PAUSE%"=="0" pause
exit /b 1
