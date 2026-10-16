param()

$ErrorActionPreference = "Stop"

$script:Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$script:Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

function New-DeployedName($Rng) {

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
    Write-Host ("  [x] Error: Name Generation Failed (RNG Unavailable): " + $_.Exception.Message)
    exit 1
}

try {
    $payload = New-DeployedName $rng
    do { $runtime = New-DeployedName $rng } while ($runtime -eq $payload)
    do { $exe = New-DeployedName $rng } while ($exe -eq $payload -or $exe -eq $runtime)
    do { $dildir = New-DeployedName $rng } while ($dildir -eq $payload -or $dildir -eq $runtime -or $dildir -eq $exe)
    do { $config = New-DeployedName $rng } while ($config -eq $payload -or $config -eq $runtime -or $config -eq $exe -or $config -eq $dildir)
    do { $wndclass = New-DeployedName $rng } while ($wndclass -eq $payload -or $wndclass -eq $runtime -or $wndclass -eq $exe -or $wndclass -eq $dildir -or $wndclass -eq $config)
    $mb = New-Object byte[] 8
    $rng.GetBytes($mb)
    $mc = New-Object 'char[]' 8
    $mc[0] = $script:Letters[$mb[0] % $script:Letters.Length]
    for ($k = 1; $k -lt 8; $k++) {
        $mc[$k] = $script:Alnum[$mb[$k] % $script:Alnum.Length]
    }
    $magic = (-join $mc)
} finally {
    $rng.Dispose()
}
if ($magic.Length -ne 8 -or $magic -notmatch '^[A-Za-z][A-Za-z0-9]{7}$') {
    Write-Host "  [x] Error: Generated Config Magic Has Invalid Shape"
    exit 1
}

foreach ($n in @($payload, $runtime, $exe, $dildir, $config, $magic, $wndclass)) {
    if ($n.Length -lt 8 -or $n.Length -gt 12) {
        Write-Host "  [x] Error: Generated Name Has Invalid Length"
        exit 1
    }
    if ($n -notmatch '^[A-Za-z][A-Za-z0-9]+$') {
        Write-Host "  [x] Error: Generated Name Has Invalid Characters"
        exit 1
    }
}
$all = @($payload, $runtime, $exe, $dildir, $config, $magic, $wndclass)
for ($i = 0; $i -lt $all.Count; $i++) {
    for ($j = $i + 1; $j -lt $all.Count; $j++) {
        if ($all[$i] -eq $all[$j]) {
            Write-Host "  [x] Error: Generated Names Collide"
            exit 1
        }
    }
}

Write-Output ("PAYLOAD_NAME=" + $payload + ".dll")
Write-Output ("RUNTIME_NAME=" + $runtime + ".dll")
Write-Output ("EXE_NAME=" + $exe)
Write-Output ("DLLDIR_NAME=" + $dildir)
Write-Output ("CONFIG_NAME=" + $config)
Write-Output ("CONFIG_MAGIC=" + $magic)
Write-Output ("WINDOW_CLASS=" + $wndclass)
exit 0
