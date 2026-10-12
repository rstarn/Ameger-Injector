param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Embed", "Magic", "PayloadHash", "DeployedPin", "ConfigKeys")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Words,

    [string]$Magic,

    [string]$Config,

    [string]$ExpectPin
)

$ErrorActionPreference = "Stop"

$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

if ($Check -eq "Embed") {
    $wordList = @()
    if (-not [string]::IsNullOrWhiteSpace($Words)) { $wordList = $Words -split ',' }
    if ($wordList.Count -ne 8) {
        Write-Fail ("Expected 8 runtime hash words, got " + $wordList.Count)
        exit 1
    }

    $pos = 0
    $last = $data.Length - 4
    for ($i = 0; $i -lt $wordList.Count; $i++) {
        $w = [string]$wordList[$i]
        if ($w.StartsWith("0x") -or $w.StartsWith("0X")) { $w = $w.Substring(2) }
        $val = [Convert]::ToUInt32($w, 16)
        $b = [BitConverter]::GetBytes([uint32]$val)

        $found = -1
        for ($j = $pos; $j -le $last; $j++) {
            if ($data[$j] -eq $b[0] -and $data[$j + 1] -eq $b[1] -and
                $data[$j + 2] -eq $b[2] -and $data[$j + 3] -eq $b[3]) {
                $found = $j
                break
            }
        }
        if ($found -lt 0) {
            Write-Fail ("Runtime hash word " + $i + " not found in order: " + (Get-Painted $script:C_Dim $Path))
            exit 1
        }
        $pos = $found + 4
    }

    Write-Ok ("Embedded runtime hash: " + (Get-Painted $script:C_Green "8") + "/" + (Get-Painted $script:C_Green "8") + " dwords in order (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "PayloadHash") {
    if ([string]::IsNullOrEmpty($Config)) {
        Write-Fail "Expected a master config path"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $Config)) {
        Write-Fail ("Master config not found: " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $pin = $null
    foreach ($line in [IO.File]::ReadAllLines($Config)) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("PayloadSha256 pin missing in " + (Get-Painted $script:C_Dim $Config))
        exit 1
    }

    $actual = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($data)) -replace "-", "")
    if ($actual -ine $pin) {
        Write-Fail ("Payload hash mismatch: expected " + $pin + ", got " + $actual + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Payload SHA-256: " + (Get-Painted $script:C_Green $actual) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "DeployedPin") {
    if ([string]::IsNullOrEmpty($ExpectPin)) {
        Write-Fail "Expected a payload SHA-256"
        exit 1
    }
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected a config magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI decrypt failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $pin = $null
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq "PayloadSha256") {
            $pin = $trimmed.Substring($eq + 1).Trim()
            break
        }
    }
    if ([string]::IsNullOrEmpty($pin)) {
        Write-Fail ("Deployed config pins no PayloadSha256 (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    if ($pin -ine $ExpectPin) {
        Write-Fail ("Deployed config pin mismatch: config pins " + $pin + ", deployed payload is " + $ExpectPin + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Deployed config pin: " + (Get-Painted $script:C_Green $pin) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "ConfigKeys") {
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected a config magic"
        exit 1
    }

    $magicBytes = [Text.Encoding]::ASCII.GetBytes($Magic)
    $isEncrypted = $false
    if ($data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($data.Length - $magicBytes.Length)
            [Array]::Copy($data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            Write-Fail ("DPAPI decrypt failed: " + $_.Exception.Message)
            exit 1
        }
        $text = [Text.Encoding]::UTF8.GetString($plainBytes)
    } else {
        $text = [Text.Encoding]::UTF8.GetString($data)
    }

    $present = @{}
    foreach ($line in ($text -split "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        $k = $trimmed.Substring(0, $eq).Trim()
        $v = $trimmed.Substring($eq + 1).Trim()
        if ($k -ieq "PayloadName" -or $k -ieq "RuntimeName" -or $k -ieq "ExportMap" -or $k -ieq "DllDir") { $present[$k] = $v }
    }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap", "DllDir")) {
        if (-not $present.ContainsKey($k) -or [string]::IsNullOrEmpty($present[$k])) {
            Write-Fail ("Deployed config is missing required key: " + $k + " (" + (Get-Painted $script:C_Dim $Path) + ")")
            exit 1
        }
    }
    Write-Ok ("Deployed config carries per-build keys: PayloadName, RuntimeName, ExportMap, DllDir (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ([string]::IsNullOrEmpty($Magic)) {
    Write-Fail "Expected a config magic string"
    exit 1
}
$expected = [Text.Encoding]::ASCII.GetBytes($Magic)
if ($data.Length -lt $expected.Length) {
    Write-Fail ("Encrypted config magic '" + $Magic + "' missing: " + (Get-Painted $script:C_Dim $Path))
    exit 1
}
for ($i = 0; $i -lt $expected.Length; $i++) {
    if ($data[$i] -ne $expected[$i]) {
        Write-Fail ("Encrypted config magic '" + $Magic + "' missing: " + (Get-Painted $script:C_Dim $Path))
        exit 1
    }
}
Write-Ok ("Encrypted config magic: " + (Get-Painted $script:C_Green $Magic) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
exit 0
