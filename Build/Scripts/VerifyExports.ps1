param(
    [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Path)) { Write-Host "MISSING"; exit 1 }
$bytes = [IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($bytes, 0x3C)
$magic = [BitConverter]::ToUInt16($bytes, $e + 24)
$optOff = $e + 24
$numSections = [BitConverter]::ToUInt16($bytes, $e + 6)
$secOff = $e + 24 + (0xF0, 0xE0)[$magic -ne 0x20B]
function RvaToOff($rva) {
    for ($i = 0; $i -lt $numSections; $i++) {
        $o = $secOff + $i * 40
        $va = [BitConverter]::ToUInt32($bytes, $o + 12)
        $vs = [BitConverter]::ToUInt32($bytes, $o + 8)
        $rp = [BitConverter]::ToUInt32($bytes, $o + 20)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) { return $rp + ($rva - $va) }
    }
    return $null
}
$exportRva = [BitConverter]::ToUInt32($bytes, $optOff + 0x70)
$off = RvaToOff $exportRva
$numNames = [BitConverter]::ToUInt32($bytes, $off + 24)
$namesRva = [BitConverter]::ToUInt32($bytes, $off + 32)
$namesOff = RvaToOff $namesRva
$bad = @("CoreExecute","CoreStart","CoreStop","CoreFetch","CoreSetTrace","CoreLastError","CoreClearLastError","CoreExecStats","CoreSymbolState","CoreImportState","CoreAcqStats","CoreLoadStats","CoreExecTelemetry","CoreStrStats")
$found = @()
for ($i = 0; $i -lt $numNames; $i++) {
    $nrva = [BitConverter]::ToUInt32($bytes, $namesOff + $i * 4)
    $noff = RvaToOff $nrva
    $end = $noff
    while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
    $name = [Text.Encoding]::ASCII.GetString($bytes, $noff, $end - $noff)
    if ($bad -contains $name) { $found += $name }
}
if ($found.Count -gt 0) {
    Write-Host "FAIL: stable export names present: $($found -join ', ')"
    exit 1
}
Write-Host "OK: $numNames exports, no stable Core* names"
exit 0