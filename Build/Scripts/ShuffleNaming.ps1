# Emits the per-build deployed file names for the payload DLL, the runtime
# DLL (V-02/V-03), and the launcher EXE (V-04).
#
# Create.bat deploys the payload to <DllDir>\<PayloadName> and the runtime DLL
# to <DllDir>\<RuntimeName>, and links the launcher as <ExeName>.exe, so a
# shipped release folder never exposes the stable Jlov.dll / rtdll_* /
# "Host - x64.exe" on-disk names (or a stable "DLLs" folder) that identified
# every previous build. The launcher name matters because it is the process
# image name a process enumeration (Warden's NtQuerySystemInformation) sees; a
# fixed "Host - x64.exe" is a stable signature no matter how random the DLL
# names are.
#
# DllDir itself is drawn here (V-05) and recorded in Cache\BuildNames.state
# alongside the names, which is the only place any consumer should read it from
# - the folder is per-build, so hardcoding it anywhere prints paths that do
# not exist.
#
# Each name is 8..12 ASCII alphanumeric characters (the first a letter). DLL
# names carry ".dll"; the EXE, folder and config names are bare basenames
# (MSBuild appends ".exe" via TargetName; the folder/config gain their fixed
# extensions at deploy time). All five are drawn from the OS CSPRNG and
# guaranteed pairwise distinct within a build.
#
# Output is five KEY=VALUE lines consumed by Create.bat:
#   PAYLOAD_NAME=<name>.dll
#   RUNTIME_NAME=<name>.dll
#   EXE_NAME=<name>
#   DLLDIR_NAME=<name>
#   CONFIG_NAME=<name>
#
# Strict Windows PowerShell 5.1. Exit code 0 = names produced, 1 = failure
# (fatal: the caller refuses to deploy a stable or missing name).

param()

$ErrorActionPreference = "Stop"

$script:Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$script:Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

function New-DeployedName($Rng) {
    # Length 8..12, then a random letter, then alphanumerics. One reusable byte
    # buffer keeps the CSPRNG draw simple and PS5.1-safe.
    $buf = New-Object byte[] 1
    $Rng.GetBytes($buf)
    $length = 8 + ($buf[0] % 5)

    $chars = New-Object 'char[]' $length
    $Rng.GetBytes($buf)
    $chars[0] = $script:Letters[$buf[0] % $script:Letters.Length]
    for ($i = 1; $i -lt $length; $i++) {
        $Rng.GetBytes($buf)
        $chars[$i] = $script:Alnum[$buf[0] % $script:Alnum.Length]
    }
    return (-join $chars)
}

try {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
} catch {
    Write-Host ("  [x] ERROR: name generation failed (RNG unavailable): " + $_.Exception.Message)
    exit 1
}

try {
    $payload = New-DeployedName $rng
    do { $runtime = New-DeployedName $rng } while ($runtime -eq $payload)
    do { $exe = New-DeployedName $rng } while ($exe -eq $payload -or $exe -eq $runtime)
    do { $dildir = New-DeployedName $rng } while ($dildir -eq $payload -or $dildir -eq $runtime -or $dildir -eq $exe)
    do { $config = New-DeployedName $rng } while ($config -eq $payload -or $config -eq $runtime -or $config -eq $exe -or $config -eq $dildir)
} finally {
    $rng.Dispose()
}

# Fail closed on any shape violation rather than emit a name the fixed contract
# does not allow.
foreach ($n in @($payload, $runtime, $exe, $dildir, $config)) {
    if ($n.Length -lt 8 -or $n.Length -gt 12) {
        Write-Host "  [x] ERROR: generated name has invalid length"
        exit 1
    }
    if ($n -notmatch '^[A-Za-z][A-Za-z0-9]+$') {
        Write-Host "  [x] ERROR: generated name has invalid characters"
        exit 1
    }
}
$all = @($payload, $runtime, $exe, $dildir, $config)
for ($i = 0; $i -lt $all.Count; $i++) {
    for ($j = $i + 1; $j -lt $all.Count; $j++) {
        if ($all[$i] -eq $all[$j]) {
            Write-Host "  [x] ERROR: generated names collide"
            exit 1
        }
    }
}

Write-Output ("PAYLOAD_NAME=" + $payload + ".dll")
Write-Output ("RUNTIME_NAME=" + $runtime + ".dll")
Write-Output ("EXE_NAME=" + $exe)
Write-Output ("DLLDIR_NAME=" + $dildir)
Write-Output ("CONFIG_NAME=" + $config)
exit 0
