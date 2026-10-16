param()

$ErrorActionPreference = "Stop"

try {
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 4
    $rng.GetBytes($buf)
    $mmap = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
    $rng.GetBytes($buf)
    $str = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
}
catch {
    Write-Host ("  [x] Error: Seed Generation Failed (RNG Unavailable): " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
finally {
    if ($null -ne $rng) { $rng.Dispose() }
}

if ($buf.Length -ne 4) {
    Write-Host "  [x] Error: RNG Returned A Short Buffer; Refusing To Build With A Fixed Sentinel." -ForegroundColor Red
    exit 1
}

Write-Output ("AmegerMmapSentinel=0x{0:X8}" -f $mmap)
Write-Output ("AmegerStringSeed=0x{0:X8}" -f $str)
exit 0
