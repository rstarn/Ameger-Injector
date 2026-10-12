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
set "DLL_DIR="
set "DEPS_RELEASE=%OUT_ROOT%"
set "RELEASE_CACHE=%OUT_ROOT%\Cache"
set "CACHE_RUNTIME=%RELEASE_CACHE%\Runtime"
set "CACHE_INTERFACE=%RELEASE_CACHE%\Injector"
set "SCRIPTS_DIR=%BUILD_DIR%\Scripts"
set "TIMESTAMP_SCRIPT=%SCRIPTS_DIR%\AddPE.ps1"
set "MUTATE_SCRIPT=%SCRIPTS_DIR%\BuildPE.ps1"
set "SEED_SCRIPT=%SCRIPTS_DIR%\CreateSeeds.ps1"
set "CONFIG_SCRIPT=%SCRIPTS_DIR%\ProtectConfig.ps1"
set "VERIFY_SCRIPT=%SCRIPTS_DIR%\VerifyEmbedMagic.ps1"
set "NAMES_SCRIPT=%SCRIPTS_DIR%\ShuffleNaming.ps1"
set "RENAME_SCRIPT=%SCRIPTS_DIR%\ShuffleExports.ps1"
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

echo [%C_GREEN%2%C_RESET%/%C_GREEN%6%C_RESET%] Checking projects...
echo.
if not exist "%LIBRARY_PROJ%" goto :source_error
if not exist "%INTERFACE_PROJ%" goto :source_error
echo   %C_GREEN%[+]%C_RESET% Runtime and Interface projects present.
echo.
echo.

echo [%C_GREEN%3%C_RESET%/%C_GREEN%6%C_RESET%] Cleaning Release and Cache...
echo.
call :clean_directory "%OUT_ROOT%"
if errorlevel 1 goto :clean_error
call :clean_directory "%BUILD_DIR%\obj"
if errorlevel 1 goto :clean_error
call :prepare_cache
if errorlevel 1 goto :clean_error
echo   %C_GREEN%[+]%C_RESET% Clean layout prepared in %C_GREEN%%RELEASE_CACHE%%C_RESET%.
echo.
echo.
call :generate_names
if errorlevel 1 goto :names_error
set "DLL_DIR=%OUT_ROOT%\%DLLDIR_NAME%"
if not exist "%DLL_DIR%" mkdir "%DLL_DIR%"
if not exist "%DLL_DIR%" (
  echo   %C_RED%ERROR: unable to create the per-build DLL folder; refusing to deploy stable names.%C_RESET%
  goto :clean_error
)
set "DEPLOYED_CONFIG=%OUT_ROOT%\%CONFIG_NAME%.ini"
set "PAYLOAD_DEST=%DLL_DIR%\%PAYLOAD_NAME%"
set "INTERFACE_EXE=%OUT64%\%EXE_NAME%.exe"
echo   %C_GREEN%[+]%C_RESET% Deployed payload name: %C_GREEN%%PAYLOAD_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed runtime name: %C_GREEN%%RUNTIME_NAME%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed launcher name: %C_GREEN%%EXE_NAME%.exe%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Deployed DLL folder: %C_GREEN%%DLLDIR_NAME%%C_RESET%
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
echo   %C_GREEN%[+]%C_RESET% Per-build sentinel: %C_GREEN%%AmegerMmapSentinel%%C_RESET%
echo   %C_GREEN%[+]%C_RESET% Per-build string seed: %C_GREEN%%AmegerStringSeed%%C_RESET%
echo.
goto :seeds_ready

:seeds_missing
echo.
echo   %C_RED%ERROR: per-build seed generation failed; refusing to build with fixed seeds.%C_RESET%
goto :failure

:seeds_ready
call :build_project "%LIBRARY_PROJ%" x64 "%DEPS_RELEASE%" "%LIBRARY64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%MUTATE_ARGS%"
if errorlevel 1 goto :build_error
echo.
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :runtime_timestamp_ready
if not exist "%TIMESTAMP_SCRIPT%" goto :runtime_timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :timestamp_fatal
goto :runtime_timestamp_ready

:runtime_timestamp_missing
echo   %C_RED%ERROR: AddPE.ps1 was not found; refusing to continue with an untimestamped runtime DLL.%C_RESET%
goto :failure

:runtime_timestamp_ready
if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :runtime_mutate_ready
if not exist "%MUTATE_SCRIPT%" goto :runtime_mutate_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%RUNTIME_STOCK_DLL%"
if errorlevel 1 goto :mutate_fatal
goto :runtime_mutate_ready

:runtime_mutate_missing
echo   %C_RED%ERROR: BuildPE.ps1 was not found; refusing to continue with an unmutated runtime DLL.%C_RESET%
goto :failure

:runtime_mutate_ready
call :rename_exports
if errorlevel 1 goto :rename_export_error
call :write_names_state
if errorlevel 1 goto :names_state_error
where powershell.exe >nul 2>&1
if errorlevel 1 goto :hash_error
set "RUNTIME_SHA256="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%RUNTIME_STOCK_DLL%'))) -replace '-',''); Write-Output ('RUNTIME_SHA256=' + $h); Write-Output ('H0=0x' + $h.Substring(0,8)); Write-Output ('H1=0x' + $h.Substring(8,8)); Write-Output ('H2=0x' + $h.Substring(16,8)); Write-Output ('H3=0x' + $h.Substring(24,8)); Write-Output ('H4=0x' + $h.Substring(32,8)); Write-Output ('H5=0x' + $h.Substring(40,8)); Write-Output ('H6=0x' + $h.Substring(48,8)); Write-Output ('H7=0x' + $h.Substring(56,8))"`) do set "%%A=%%B"
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
echo   %C_GREEN%[+]%C_RESET% Runtime SHA-256:        %RUNTIME_SHA256%
echo.
call :build_project "%INTERFACE_PROJ%" x64 "%OUT64%" "%INTERFACE64_OBJ%" "%TOOLSET_ARG%" "%SDK_ARG%" "%RUNTIME_HASH_ARGS%"
if errorlevel 1 goto :build_error
echo.
echo.

echo [%C_GREEN%5%C_RESET%/%C_GREEN%6%C_RESET%] Deploying release binaries...
echo.
echo   %C_GREEN%[+]%C_RESET% Runtime binaries are in %C_GREEN%%OUT_ROOT%%C_RESET%.
call :deploy_payload
if errorlevel 1 goto :payload_error
call :protect_config
if errorlevel 1 goto :config_error
echo.
echo.

echo [%C_GREEN%6%C_RESET%/%C_GREEN%6%C_RESET%] Sweeping intermediates into Cache and verifying...
echo.
set "EXE_COUNT=0"
for %%F in ("%OUT64%\*.exe") do set /a "EXE_COUNT+=1"
if not "%EXE_COUNT%"=="1" (
  echo   %C_RED%ERROR: expected exactly one launcher EXE in %OUT64%, found %EXE_COUNT%.%C_RESET%
  goto :verify_error
)
if not exist "%INTERFACE_EXE%" (
  echo   %C_RED%ERROR: expected launcher missing: %INTERFACE_EXE%%C_RESET%
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
call :remove_import_artifacts "%DEPS_RELEASE%"
if errorlevel 1 goto :cleanup_error
call :remove_import_artifacts "%DLL_DIR%"
if errorlevel 1 goto :cleanup_error
call :sweep_artifacts
if errorlevel 1 goto :cleanup_error
echo.
echo   %C_GREEN%[+]%C_RESET% Cache groups: Runtime, Injector.
echo.
echo.

if /i "%AMEGER_REFUSE_UNMUTATED%"=="1" goto :refuse_unmutated
if not exist "%TIMESTAMP_SCRIPT%" goto :timestamp_missing
where powershell.exe >nul 2>&1
if errorlevel 1 goto :timestamp_missing
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TIMESTAMP_SCRIPT%" "%INTERFACE_EXE%"
if errorlevel 1 goto :timestamp_error
if not exist "%MUTATE_SCRIPT%" goto :mutate_exe_error
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%MUTATE_SCRIPT%" "%INTERFACE_EXE%"
if errorlevel 1 goto :mutate_exe_error
call :verify_embed
if errorlevel 1 goto :verify_content_error

call :write_section_manifest
if errorlevel 1 goto :manifest_error
echo.
echo Build completed successfully.
echo.
echo Cache:   %C_GREEN%%RELEASE_CACHE%%C_RESET%
echo Payload:     %C_GREEN%%PAYLOAD_DEST%%C_RESET%
echo Interface x64: %C_GREEN%%INTERFACE_EXE%%C_RESET%
echo Runtime DLL: %C_GREEN%%RUNTIME_DLL%%C_RESET%

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
  echo   %C_RED%ERROR: ShuffleNaming.ps1 not found; refusing to deploy stable names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: PowerShell unavailable; refusing to deploy stable names.%C_RESET%
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
exit /b 0

:rename_exports
if not exist "%RENAME_SCRIPT%" (
  echo   %C_RED%ERROR: ShuffleExports.ps1 not found; refusing to ship stable export names.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: PowerShell unavailable; refusing to ship stable export names.%C_RESET%
  exit /b 1
)
set "RENAME_STATUS="
set "EXPORT_MAP="
for /f "usebackq tokens=1,* delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RENAME_SCRIPT%" -Path "%RUNTIME_STOCK_DLL%"`) do set "%%A=%%B"
if /i not "%RENAME_STATUS%"=="ok" (
  echo   %C_RED%ERROR: runtime export rename failed; refusing to ship stable export names.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%ERROR: runtime export rename produced no map; refusing to ship stable export names.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Runtime exports renamed (map captured).
exit /b 0

:write_names_state
if not exist "%RELEASE_CACHE%" mkdir "%RELEASE_CACHE%"
if not exist "%RELEASE_CACHE%" exit /b 1
>"%NAMES_STATE%" echo PAYLOAD_NAME=%PAYLOAD_NAME%
>>"%NAMES_STATE%" echo RUNTIME_NAME=%RUNTIME_NAME%
>>"%NAMES_STATE%" echo EXE_NAME=%EXE_NAME%
>>"%NAMES_STATE%" echo DLLDIR_NAME=%DLLDIR_NAME%
>>"%NAMES_STATE%" echo CONFIG_NAME=%CONFIG_NAME%
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
echo   %C_GREEN%OK%C_RESET% %~2: %C_GREEN%"%~1"%C_RESET%
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
  echo   %C_RED%ERROR: deployed payload SHA-256 unavailable; refusing to ship an unpinned config.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_NAME (
  echo   %C_RED%ERROR: deployed payload name unavailable; refusing to ship an unstamped config.%C_RESET%
  exit /b 1
)
if not defined RUNTIME_NAME (
  echo   %C_RED%ERROR: deployed runtime name unavailable; refusing to ship an unstamped config.%C_RESET%
  exit /b 1
)
if not defined DLLDIR_NAME (
  echo   %C_RED%ERROR: deployed DLL folder name unavailable; refusing to ship an unstamped config.%C_RESET%
  exit /b 1
)
if not defined EXPORT_MAP (
  echo   %C_RED%ERROR: runtime export map unavailable; refusing to ship an unstamped config.%C_RESET%
  exit /b 1
)
if not defined CONFIG_MAGIC (
  echo   %C_RED%ERROR: per-build config magic unavailable; refusing to ship a static-magic config.%C_RESET%
  exit /b 1
)
if /i "%AMEGER_ENCRYPT_CONFIG%"=="0" (
  echo   %C_RED%ERROR: AMEGER_ENCRYPT_CONFIG=0 is refused; the launcher rejects plaintext configs, so this would ship an unloadable release.%C_RESET%
  echo   %C_RED%Rebuild without the opt-out to ship the encrypted config.%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%ERROR: master config not found: %CONFIG_MASTER%%C_RESET%
  exit /b 1
)
if not exist "%CONFIG_SCRIPT%" (
  echo   %C_RED%ERROR: ProtectConfig.ps1 not found; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: PowerShell unavailable; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONFIG_SCRIPT%" -Source "%CONFIG_MASTER%" -Destination "%DEPLOYED_CONFIG%" -PinPayload "%PAYLOAD_DEST%" -PayloadName "%PAYLOAD_NAME%" -RuntimeName "%RUNTIME_NAME%" -ExportMap "%EXPORT_MAP%" -DllDir "%DLLDIR_NAME%" -ConfigMagic "%CONFIG_MAGIC%"
if errorlevel 1 (
  echo   %C_RED%ERROR: config encryption failed; refusing to ship a plaintext config.%C_RESET%
  exit /b 1
)
echo   %C_GREEN%[+]%C_RESET% Configuration encrypted for deployment.
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
  echo   %C_RED%ERROR: payload asset not found: %PAYLOAD_SRC%%C_RESET%
  exit /b 1
)
if defined PAYLOAD_IS_PREPARED echo   %C_YELLOW%[+]%C_RESET% Prepared payload: %C_YELLOW%%PAYLOAD_SRC%%C_RESET%
copy /y "%PAYLOAD_SRC%" "%PAYLOAD_DEST%" >nul
if errorlevel 1 (
  echo   %C_RED%ERROR: failed to copy payload to %PAYLOAD_DEST%%C_RESET%
  exit /b 1
)
set "DEPLOYED_SHA="
for /f "usebackq tokens=1,2 delims==" %%A in (`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$h=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes('%PAYLOAD_DEST%'))) -replace '-',''); Write-Output ('DEPLOYED_SHA=' + $h)"`) do set "%%A=%%B"
if not defined DEPLOYED_SHA (
  echo   %C_RED%ERROR: unable to hash the deployed payload.%C_RESET%
  exit /b 1
)
if not defined PAYLOAD_IS_PREPARED (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%VERIFY_SCRIPT%" -Check PayloadHash -Path "%PAYLOAD_DEST%" -Config "%CONFIG_MASTER%"
  if errorlevel 1 (
    echo   %C_RED%ERROR: deployed payload failed hash verification.%C_RESET%
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
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$out=@(); foreach($p in @('%INTERFACE_EXE%','%PAYLOAD_DEST%')){ if(-not (Test-Path -LiteralPath $p)){exit 1}; $b=[IO.File]::ReadAllBytes($p); $e=[BitConverter]::ToInt32($b,0x3C); $c=$e+4; $n=[BitConverter]::ToUInt16($b,$c+2); $z=[BitConverter]::ToUInt16($b,$c+16); $s=$c+20+$z; $names=@(); for($i=0;$i -lt $n;$i++){ $o=$s+40*$i; $nm=[Text.Encoding]::ASCII.GetString($b,$o,8).Trim([char]0); $x=[BitConverter]::ToUInt32($b,$o+36); if($x -band 0x20000000){ $names += ($nm + '+X') } else { $names += $nm } }; $out += ([IO.Path]::GetFileName($p) + ':' + ($names -join ',')) }; [IO.File]::WriteAllLines('%MANIFEST%',$out)"
if errorlevel 1 exit /b 1
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
  echo   %C_RED%ERROR: unable to remove build residue: %RELEASE_CACHE%\%~1%C_RESET%
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
echo   %C_RED%ERROR: unable to record the PE section baseline manifest.%C_RESET%
goto :failure

:scrub_error
echo   %C_RED%ERROR: post-success build-cache scrub failed; residue may remain in %RELEASE_CACHE%.%C_RESET%
goto :failure

:msbuild_error
echo %C_RED%ERROR: MSBuild was not found.%C_RESET%
goto :failure

:source_error
echo %C_RED%ERROR: one or more required project files are missing.%C_RESET%
goto :failure

:clean_error
echo %C_RED%ERROR: unable to prepare the Release or Cache directory.%C_RESET%
goto :failure

:build_error
echo %C_RED%ERROR: a project build failed.%C_RESET%
goto :failure

:hash_error
echo %C_RED%ERROR: unable to calculate the runtime DLL SHA-256.%C_RESET%
goto :failure

:runtime_rename_error
echo %C_RED%ERROR: unable to rename the runtime DLL to its per-build name.%C_RESET%
goto :failure

:names_error
echo %C_RED%ERROR: unable to generate the per-build deployed file names.%C_RESET%
goto :failure

:rename_export_error
echo %C_RED%ERROR: unable to rename the runtime DLL exports.%C_RESET%
goto :failure

:names_state_error
echo %C_RED%ERROR: unable to record the per-build name state.%C_RESET%
goto :failure

:verify_error
echo %C_RED%ERROR: one or more expected binaries are missing.%C_RESET%
goto :failure

:verify_content_error
echo %C_RED%ERROR: embedded runtime hash, config magic, deployed pin or per-build config key verification failed.%C_RESET%
goto :failure

:cleanup_error
echo %C_RED%ERROR: unable to remove generated import artifacts.%C_RESET%
goto :failure

:config_error
echo %C_RED%ERROR: unable to deploy an encrypted configuration.%C_RESET%
goto :failure

:payload_error
echo %C_RED%ERROR: unable to deploy the target payload.%C_RESET%
goto :failure

:timestamp_missing
echo %C_RED%ERROR: AddPE.ps1 or PowerShell was not found; refusing to continue with an untimestamped build.%C_RESET%
goto :failure

:timestamp_fatal
echo %C_RED%ERROR: unable to retimestamp the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:mutate_fatal
echo %C_RED%ERROR: unable to mutate the runtime DLL; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:mutate_exe_error
echo %C_RED%ERROR: interface PE mutation failed or BuildPE.ps1 was not found; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:timestamp_error
echo %C_RED%ERROR: retimestamping the interface EXE failed; refusing to continue with an inconsistent build.%C_RESET%
goto :failure

:refuse_unmutated
echo.
echo %C_RED%ERROR: AMEGER_REFUSE_UNMUTATED=1 would ship unmutated binaries (stable timestamps, MSVC Rich fingerprint, standard section names, PDB debug directory). Refusing: rebuild without the bypass for any shipped build.%C_RESET%
goto :failure

:maybe_adopt_payload
if /i "%AMEGER_STRICT_PAYLOAD%"=="1" exit /b 0
where powershell.exe >nul 2>&1
if errorlevel 1 exit /b 0
if not exist "%REPIN_SCRIPT%" exit /b 0
if not exist "%PAYLOAD_ASSET%" exit /b 0
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%REPIN_SCRIPT%" -Config "%CONFIG_MASTER%" -Payload "%PAYLOAD_ASSET%" -Quiet
if errorlevel 1 (
  echo   %C_RED%ERROR: could not re-pin the master to the current payload asset.%C_RESET%
  exit /b 1
)
exit /b 0

:repin_payload
if not exist "%CONFIG_MASTER%" (
  echo   %C_RED%ERROR: master config not found: %CONFIG_MASTER%%C_RESET%
  goto :failure
)
if not exist "%REPIN_SCRIPT%" (
  echo   %C_RED%ERROR: RepinPayload.ps1 not found; refusing to re-pin.%C_RESET%
  goto :failure
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo   %C_RED%ERROR: PowerShell unavailable; cannot re-pin.%C_RESET%
  goto :failure
)
set "REPIN_SRC=%PAYLOAD_ASSET%"
if defined AMEGER_PAYLOAD set "REPIN_SRC=%AMEGER_PAYLOAD%"
if not exist "%REPIN_SRC%" (
  echo   %C_RED%ERROR: payload asset not found: %REPIN_SRC%%C_RESET%
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
