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
$exportSize = [BitConverter]::ToUInt32($bytes, $optOff + 0x74)



if ($exportRva -eq 0 -or $exportSize -eq 0) {
    Write-Host "OK: no export directory present (0 named exports)"
    exit 0
}

$off = RvaToOff $exportRva
if ($null -eq $off) {
    Write-Host "FAIL: export directory RVA 0x$($exportRva.ToString('X')) is outside every section"
    exit 1
}
$numNames = [BitConverter]::ToUInt32($bytes, $off + 24)
$namesRva = [BitConverter]::ToUInt32($bytes, $off + 32)
$namesOff = RvaToOff $namesRva
if ($numNames -gt 0 -and $null -eq $namesOff) {
    Write-Host "FAIL: export name table RVA 0x$($namesRva.ToString('X')) is outside every section"
    exit 1
}
$bad = @("CoreExecute","CoreStart","CoreStop","CoreFetch","CoreSetTrace","CoreLastError","CoreClearLastError","CoreExecStats","CoreSymbolState","CoreImportState","CoreAcqStats","CoreLoadStats","CoreExecTelemetry","CoreStrStats")
$found = @()
for ($i = 0; $i -lt $numNames; $i++) {
    $nrva = [BitConverter]::ToUInt32($bytes, $namesOff + $i * 4)
    $noff = RvaToOff $nrva
    if ($null -eq $noff) {
        Write-Host "FAIL: export name RVA 0x$($nrva.ToString('X')) is outside every section"
        exit 1
    }
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
