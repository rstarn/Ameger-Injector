param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Out,

    [string]$Target,

    [switch]$PackOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Project)) { Write-Host "  [!] project not found: $Project"; exit 1 }

$text = [IO.File]::ReadAllText($Project)

$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$name = '.' + (-join (1..4 | ForEach-Object { $alphabet[[int](Get-Random -Maximum $alphabet.Length)] }))

if ($text -notmatch 'VMCodeSectionName="[^"]*"') {
    Write-Host "  [!] no VMCodeSectionName attribute in $Project"
    exit 1
}

$rewritten = [regex]::Replace($text, 'VMCodeSectionName="[^"]*"', 'VMCodeSectionName="' + $name + '"')

$before = ([regex]::Match($text, 'InputFileName="([^"]+)"')).Groups[1].Value
$after = ([regex]::Match($rewritten, 'InputFileName="([^"]+)"')).Groups[1].Value
if ($before -ne $after) { Write-Host '  [!] InputFileName changed during rewrite'; exit 1 }

if ($PackOnly) {
    if ($rewritten -match '(?s)<Procedures>.*?</Procedures>') {
        $rewritten = [regex]::Replace($rewritten, '(?s)<Procedures>.*?</Procedures>', '<Procedures />', 1)
    } elseif ($rewritten -notmatch '<Procedures\s*/>') {
        $rewritten = [regex]::Replace($rewritten, '(<Protection\b[^>]*>)', ('$1' + "`r`n        <Procedures />"), 1)
    }
    Write-Host 'KEPT='
    Write-Host 'DROPPED='
}

elseif ($Target -and (Test-Path -LiteralPath $Target)) {
    try {
        $b = [IO.File]::ReadAllBytes($Target)
        if ($b.Length -lt 64 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw 'not MZ' }
        $e = [BitConverter]::ToInt32($b, 0x3C)
        if ($e -lt 0 -or ($e + 24) -gt $b.Length) { throw 'bad e_lfanew' }
        if ([BitConverter]::ToUInt32($b, $e) -ne 0x00004550) { throw 'not PE' }
        $coff = $e + 4
        $nsec = [BitConverter]::ToUInt16($b, $coff + 2)
        $optSize = [BitConverter]::ToUInt16($b, $coff + 16)
        $opt = $e + 24
        $magic = [BitConverter]::ToUInt16($b, $opt)
        $dd = if ($magic -eq 0x20B) { $opt + 112 } elseif ($magic -eq 0x10B) { $opt + 96 } else { throw 'not PE32/PE32+' }
        $secBase = $opt + $optSize
        $sizeOfImage = [BitConverter]::ToUInt32($b, $opt + 56)
        $expRva = [BitConverter]::ToUInt32($b, $dd + 0)

        $r2o = {
            param($rva)
            for ($i = 0; $i -lt $nsec; $i++) {
                $o = $secBase + 40 * $i
                $va = [BitConverter]::ToUInt32($b, $o + 12)
                $vs = [BitConverter]::ToUInt32($b, $o + 8)
                $ptr = [BitConverter]::ToUInt32($b, $o + 20)
                $sz = [BitConverter]::ToUInt32($b, $o + 16)
                $sp = [Math]::Max($vs, $sz)
                if ($rva -ge $va -and $rva -lt ($va + $sp)) { return ($rva - $va) + $ptr }
            }
            return -1
        }

        $names = New-Object System.Collections.Generic.HashSet[string]
        if ($expRva -ne 0) {
            $eo = & $r2o $expRva
            if ($eo -ge 0) {
                $nNames = [BitConverter]::ToUInt32($b, $eo + 24)
                $anRva = [BitConverter]::ToUInt32($b, $eo + 32)
                $anOff = & $r2o $anRva
                if ($anOff -ge 0) {
                    for ($i = 0; $i -lt $nNames; $i++) {
                        $nr = [BitConverter]::ToUInt32($b, $anOff + 4 * $i)
                        $no = & $r2o $nr
                        if ($no -ge 0) {
                            $len = 0
                            while (($no + $len) -lt $b.Length -and $b[$no + $len] -ne 0) { $len++ }
                            [void]$names.Add([Text.Encoding]::ASCII.GetString($b, $no, $len).ToLowerInvariant())
                        }
                    }
                }
            }
        }

        $procRx = '(?s)<Procedure\b[^>]*\bMapAddress="([^"]*)"[^>]*/>'
        $elems = [regex]::Matches($rewritten, $procRx)
        if ($elems.Count -gt 0) {
            $keepElems = New-Object System.Collections.Generic.List[string]
            $keepNames = New-Object System.Collections.Generic.List[string]
            $dropNames = New-Object System.Collections.Generic.List[string]
            foreach ($m in $elems) {
                $full = $m.Value
                $addr = $m.Groups[1].Value
                $isEntry = ($addr -ieq 'EntryPoint')
                $isExport = $names.Contains($addr.ToLowerInvariant())
                $resolved = $isEntry -or $isExport
                if (-not $resolved -and $addr -match '^(0[xX])?[0-9A-Fa-f]+$') {

                    $v = 0
                    if ($addr -match '^0[xX]') { [void][int]::TryParse($addr.Substring(2), [Globalization.NumberStyles]::HexNumber, $null, [ref]$v) }
                    else { [void][int]::TryParse($addr, [Globalization.NumberStyles]::Integer, $null, [ref]$v) }
                    if ($v -gt 0 -and $sizeOfImage -gt 0 -and $v -lt $sizeOfImage) { $resolved = $true }
                }
                if ($resolved) { $keepElems.Add($full); $keepNames.Add($addr) }
                else { $dropNames.Add($addr) }
            }
            if ($keepElems.Count -eq 0) {
                $inject = ($elems[0].Value) -replace 'MapAddress="[^"]*"', 'MapAddress="EntryPoint"'
                $keepElems.Add($inject)
                $keepNames.Add('EntryPoint')
            }
            $block = "<Procedures>`r`n            " + ($keepElems -join "`r`n            ") + "`r`n        </Procedures>"
            $rewritten = [regex]::Replace($rewritten, '(?s)<Procedures>.*?</Procedures>',
                [System.Text.RegularExpressions.MatchEvaluator]{ param($mm) $block }, 1)
            if ($dropNames.Count -gt 0) { Write-Host ("DROPPED=" + ($dropNames -join ',')) }
            Write-Host ("KEPT=" + ($keepNames -join ','))
        }
    }
    catch {

        Write-Host ("  [!] procedure reconciliation skipped (target parse failed): " + $_.Exception.Message)
    }
}

[IO.File]::WriteAllText($Out, $rewritten, (New-Object Text.UTF8Encoding($false)))
if (-not (Test-Path -LiteralPath $Out)) { Write-Host '  [!] failed to write rewritten project'; exit 1 }

Write-Host ("SEG_NAME={0}" -f $name)
exit 0
