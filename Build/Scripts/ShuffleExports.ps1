param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = "Stop"

function Write-Diag([string]$Text) {
    [Console]::Error.WriteLine($Text)
}

function Fail([string]$Reason) {
    Write-Output "RENAME_STATUS=failed"
    Write-Diag ("  [x] Export Rename: " + $Reason)
    exit 1
}

if (-not (Test-Path -LiteralPath $Path)) { Fail ("File Not Found: " + $Path) }

$bytes = $null
$read = $false
for ($attempt = 1; $attempt -le 20 -and -not $read; $attempt++) {
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $read = $true
    } catch {
        $chain = $_.Exception
        while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
        if ($chain -and $attempt -lt 20) {
            Start-Sleep -Milliseconds 500
        } else {
            Fail ("Read Failed: " + $_.Exception.Message)
        }
    }
}
if (-not $read) { Fail "Read Failed" }

if ($bytes.Length -lt 64 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90) { Fail "Not MZ" }
$e = [BitConverter]::ToInt32($bytes, 0x3C)
if ($e -le 0 -or ($e + 24) -gt $bytes.Length) { Fail "Bad e_lfanew" }
if ([BitConverter]::ToUInt32($bytes, $e) -ne 0x00004550) { Fail "Not PE" }

$coff = $e + 4
$nsec = [BitConverter]::ToUInt16($bytes, $coff + 2)
if ($nsec -le 0 -or $nsec -gt 96) { Fail "Bad Section Count" }
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $e + 24
$magic = [BitConverter]::ToUInt16($bytes, $opt)
if ($magic -eq 0x20B) {
    $dd = $opt + 112
} elseif ($magic -eq 0x10B) {
    $dd = $opt + 96
} else {
    Fail "Not PE32/PE32+"
}
$secBase = $opt + $optSize

function Convert-RvaToOffset([byte[]]$Data, [int]$SectionBase, [int]$Count, [uint32]$Rva) {
    for ($i = 0; $i -lt $Count; $i++) {
        $o = $SectionBase + 40 * $i
        $va = [BitConverter]::ToUInt32($Data, $o + 12)
        $vs = [BitConverter]::ToUInt32($Data, $o + 8)
        $ptr = [BitConverter]::ToUInt32($Data, $o + 20)
        $sz = [BitConverter]::ToUInt32($Data, $o + 16)
        $span = [Math]::Max($vs, $sz)
        if ($Rva -ge $va -and $Rva -lt ($va + $span)) { return [int](($Rva - $va) + $ptr) }
    }
    return -1
}

$expRva = [BitConverter]::ToUInt32($bytes, $dd + 0)
$expSz = [BitConverter]::ToUInt32($bytes, $dd + 4)

if ($expRva -eq 0 -or $expSz -lt 40) {
    Write-Output "EXPORT_MAP="
    Write-Output "RENAME_STATUS=ok"
    exit 0
}

$eo = Convert-RvaToOffset $bytes $secBase $nsec $expRva
if ($eo -lt 0 -or ($eo + 40) -gt $bytes.Length) { Fail "Export Directory RVA Unresolved" }

$nFunc = [BitConverter]::ToUInt32($bytes, $eo + 20)
$nNames = [BitConverter]::ToUInt32($bytes, $eo + 24)
$afRva = [BitConverter]::ToUInt32($bytes, $eo + 28)
$anRva = [BitConverter]::ToUInt32($bytes, $eo + 32)
$aoRva = [BitConverter]::ToUInt32($bytes, $eo + 36)

if ($nNames -eq 0) {
    Write-Output "EXPORT_MAP="
    Write-Output "RENAME_STATUS=ok"
    exit 0
}
if ($nNames -gt 4096) { Fail "Implausible Export Name Count" }

$afOff = Convert-RvaToOffset $bytes $secBase $nsec $afRva
$anOff = Convert-RvaToOffset $bytes $secBase $nsec $anRva
$aoOff = Convert-RvaToOffset $bytes $secBase $nsec $aoRva
if ($afOff -lt 0 -or $anOff -lt 0 -or $aoOff -lt 0) { Fail "Export Table RVA Unresolved" }

$entries = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $nNames; $i++) {
    $nr = [BitConverter]::ToUInt32($bytes, $anOff + 4 * $i)
    $no = Convert-RvaToOffset $bytes $secBase $nsec $nr
    if ($no -lt 0 -or $no -ge $bytes.Length) { Fail "Export Name RVA Unresolved" }
    $len = 0
    while (($no + $len) -lt $bytes.Length -and $bytes[$no + $len] -ne 0) { $len++ }
    if ($len -lt 1) { Fail "Empty Export Name" }
    if (($no + $len) -ge $bytes.Length) { Fail "Unterminated Export Name" }
    $old = [Text.Encoding]::ASCII.GetString($bytes, $no, $len)
    $ord = [BitConverter]::ToUInt16($bytes, $aoOff + 2 * $i)
    [void]$entries.Add([pscustomobject]@{
        Index   = $i
        Offset  = $no
        Length  = $len
        Old     = $old
        Ordinal = $ord
    })
}

$letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
if ($entries.Count -gt $letters.Length) { Fail "Too Many Exports For The Ordering Scheme" }

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {

    $chosen = New-Object System.Collections.Generic.List[int]
    $oneByte = New-Object byte[] 1
    while ($chosen.Count -lt $entries.Count) {
        $rng.GetBytes($oneByte)
        $idx = [int]($oneByte[0] % $letters.Length)
        if (-not $chosen.Contains($idx)) { [void]$chosen.Add($idx) }
    }
    $sortedIdx = @($chosen | Sort-Object)

    $originals = @{}
    foreach ($ent in $entries) { $originals[$ent.Old.ToLowerInvariant()] = $true }

    $newNames = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $ent = $entries[$i]
        $first = [char]$letters[$sortedIdx[$i]]
        $tailLen = $ent.Length - 1
        $cand = $null
        for ($attempt = 0; $attempt -lt 256; $attempt++) {
            $tail = New-Object 'char[]' $tailLen
            for ($k = 0; $k -lt $tailLen; $k++) {
                $rng.GetBytes($oneByte)
                $tail[$k] = $alnum[$oneByte[0] % $alnum.Length]
            }
            $try = ([string]$first) + (-join $tail)

            if ($try.ToLowerInvariant().StartsWith("core")) { continue }
            if ($originals.ContainsKey($try.ToLowerInvariant())) { continue }
            $cand = $try
            break
        }
        if ($null -eq $cand) { Fail ("Could Not Synthesize A Replacement For " + $ent.Old) }
        [void]$newNames.Add($cand)
    }

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $ent = $entries[$i]
        $nn = $newNames[$i]
        if ($nn.Length -ne $ent.Length) { Fail "Internal Length Mismatch" }
        $enc = [Text.Encoding]::ASCII.GetBytes($nn)
        [Array]::Copy($enc, 0, $bytes, $ent.Offset, $enc.Length)
        $bytes[$ent.Offset + $ent.Length] = 0
    }
} finally {
    $rng.Dispose()
}

$written = $false
for ($attempt = 1; $attempt -le 20 -and -not $written; $attempt++) {
    try {
        [IO.File]::WriteAllBytes($Path, $bytes)
        $written = $true
    } catch {
        $chain = $_.Exception
        while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
        if ($chain -and $attempt -lt 20) {
            Start-Sleep -Milliseconds 500
        } else {
            Fail ("Write Failed: " + $_.Exception.Message)
        }
    }
}
if (-not $written) { Fail "Write Failed" }

$v = [IO.File]::ReadAllBytes($Path)
$ve = [BitConverter]::ToInt32($v, 0x3C)
if ($v.Length -lt 64 -or $v[0] -ne 77 -or $v[1] -ne 90 -or [BitConverter]::ToUInt32($v, $ve) -ne 0x00004550) {
    Fail "Re-Parse: Not A PE After Write"
}
$vcoff = $ve + 4
$vnsec = [BitConverter]::ToUInt16($v, $vcoff + 2)
$voptSize = [BitConverter]::ToUInt16($v, $vcoff + 16)
$vopt = $ve + 24
$vmagic = [BitConverter]::ToUInt16($v, $vopt)
if ($vmagic -eq 0x20B) { $vdd = $vopt + 112 } elseif ($vmagic -eq 0x10B) { $vdd = $vopt + 96 } else { Fail "Re-Parse: Bad Magic" }
$vsecBase = $vopt + $voptSize
$vexpRva = [BitConverter]::ToUInt32($v, $vdd + 0)
$veo = Convert-RvaToOffset $v $vsecBase $vnsec $vexpRva
if ($veo -lt 0) { Fail "Re-Parse: Export Directory RVA Unresolved" }
$vafRva = [BitConverter]::ToUInt32($v, $veo + 28)
$vanRva = [BitConverter]::ToUInt32($v, $veo + 32)
$vaoRva = [BitConverter]::ToUInt32($v, $veo + 36)
$vafOff = Convert-RvaToOffset $v $vsecBase $vnsec $vafRva
$vanOff = Convert-RvaToOffset $v $vsecBase $vnsec $vanRva
$vaoOff = Convert-RvaToOffset $v $vsecBase $vnsec $vaoRva
if ($vafOff -lt 0 -or $vanOff -lt 0 -or $vaoOff -lt 0) { Fail "Re-Parse: Export Table RVA Unresolved" }

$prev = $null
for ($i = 0; $i -lt $entries.Count; $i++) {
    $ent = $entries[$i]
    $nr = [BitConverter]::ToUInt32($v, $vanOff + 4 * $i)
    $no = Convert-RvaToOffset $v $vsecBase $vnsec $nr
    if ($no -lt 0 -or $no -ge $v.Length) { Fail "Re-Parse: Name RVA Unresolved" }
    $len = 0
    while (($no + $len) -lt $v.Length -and $v[$no + $len] -ne 0) { $len++ }
    $got = [Text.Encoding]::ASCII.GetString($v, $no, $len)

    if ($got.ToLowerInvariant().StartsWith("core")) { Fail ("Original-Style Export Name Still Present: " + $got) }
    if ($originals.ContainsKey($got.ToLowerInvariant())) { Fail ("An Original Export Name Survived: " + $got) }

    if ($got -ne $newNames[$i]) { Fail ("Slot " + $i + " Is " + $got + ", Expected " + $newNames[$i]) }

    $vord = [BitConverter]::ToUInt16($v, $vaoOff + 2 * $i)
    if ($vord -ne $ent.Ordinal) { Fail ("Ordinal Index Changed At Slot " + $i) }
    $funcIdx = [int]$vord
    if ($funcIdx -lt 0 -or $funcIdx -ge $nFunc) { Fail ("Ordinal Index " + $vord + " Outside The Function Table") }
    $funcRva = [BitConverter]::ToUInt32($v, $vafOff + 4 * $funcIdx)
    if ($funcRva -eq 0) { Fail ("Name " + $got + " Resolves To A Null Function RVA") }
    if ((Convert-RvaToOffset $v $vsecBase $vnsec $funcRva) -lt 0) { Fail ("Name " + $got + " Resolves Outside Every Section") }

    if ($null -ne $prev -and [string]::CompareOrdinal($prev, $got) -ge 0) {
        Fail ("Name Table Order Broken At Slot " + $i)
    }
    $prev = $got
}

$pairs = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $entries.Count; $i++) {
    [void]$pairs.Add($entries[$i].Old + "=" + $newNames[$i])
}
Write-Output ("EXPORT_MAP=" + ($pairs -join ','))
Write-Output "RENAME_STATUS=ok"
exit 0
