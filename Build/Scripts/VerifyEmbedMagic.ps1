param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Embed", "Magic", "DeployedPin", "ConfigKeys", "ConfigParity")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Words,

    [string]$Magic,

    [string]$ExpectPin,

    [string]$MasterPath
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

function Get-ConfigPlainText([byte[]]$Data, [string]$ConfigMagic) {
    $magicBytes = [Text.Encoding]::ASCII.GetBytes($ConfigMagic)
    $isEncrypted = $false
    if ($Data.Length -gt $magicBytes.Length) {
        $isEncrypted = $true
        for ($i = 0; $i -lt $magicBytes.Length; $i++) {
            if ($Data[$i] -ne $magicBytes[$i]) { $isEncrypted = $false; break }
        }
    }
    if ($isEncrypted) {
        Add-Type -AssemblyName System.Security | Out-Null
        try {
            $blob = New-Object byte[] ($Data.Length - $magicBytes.Length)
            [Array]::Copy($Data, $magicBytes.Length, $blob, 0, $blob.Length)
            $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            return $null
        }
        return [Text.Encoding]::UTF8.GetString($plainBytes)
    }
    return [Text.Encoding]::UTF8.GetString($Data)
}

function Get-ConfigKeyMap([string]$Text) {
    $map = @{}
    if ($null -eq $Text) { return $map }
    $section = ""
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        if ($trimmed.StartsWith("[") -and $trimmed.EndsWith("]")) {
            $section = $trimmed.Substring(1, $trimmed.Length - 2).Trim().ToLowerInvariant()
            continue
        }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        $key = $trimmed.Substring(0, $eq).Trim().ToLowerInvariant()
        if ($key.Length -eq 0) { continue }
        $value = $trimmed.Substring($eq + 1).Trim()
        if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $map[$section + "::" + $key] = $value
    }
    return $map
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not Found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

if ($Check -eq "Embed") {
    $wordList = @()
    if (-not [string]::IsNullOrWhiteSpace($Words)) { $wordList = $Words -split ',' }
    if ($wordList.Count -ne 8) {
        Write-Fail ("Expected 8 Runtime Hash Words, Got " + $wordList.Count)
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
            Write-Fail ("Runtime Hash Word " + $i + " Not Found In Order: " + (Get-Painted $script:C_Dim $Path))
            exit 1
        }
        $pos = $found + 4
    }

    Write-Ok ("Embedded Runtime Hash: " + (Get-Painted $script:C_Green "8") + "/" + (Get-Painted $script:C_Green "8") + " Dwords In Order (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "DeployedPin") {
    if ([string]::IsNullOrEmpty($ExpectPin)) {
        Write-Fail "Expected A Payload SHA-256"
        exit 1
    }
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
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
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
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
        Write-Fail ("Deployed Config Pins No PayloadSha256 (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    if ($pin -ine $ExpectPin) {
        Write-Fail ("Deployed Config Pin Mismatch: Config Pins " + $pin + ", Deployed Payload Is " + $ExpectPin + " (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    Write-Ok ("Deployed Config Pin = " + (Get-Painted $script:C_Green $pin) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "ConfigParity") {
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
        exit 1
    }
    if ([string]::IsNullOrEmpty($MasterPath)) {
        Write-Fail "Expected A Master Config Path"
        exit 1
    }
    if (-not (Test-Path -LiteralPath $MasterPath)) {
        Write-Fail ("Master Config Not Found: " + $MasterPath)
        exit 1
    }

    $deployedText = Get-ConfigPlainText $data $Magic
    if ($null -eq $deployedText) {
        Write-Fail ("DPAPI Decrypt Failed For The Deployed Config (" + (Get-Painted $script:C_Dim $Path) + ")")
        exit 1
    }
    $masterText = Get-ConfigPlainText ([IO.File]::ReadAllBytes($MasterPath)) $Magic
    if ($null -eq $masterText) {
        Write-Fail ("Master Config Could Not Be Read: " + (Get-Painted $script:C_Dim $MasterPath))
        exit 1
    }

    $master = Get-ConfigKeyMap $masterText
    $deployed = Get-ConfigKeyMap $deployedText
    if ($master.Count -eq 0) {
        Write-Fail ("Master Config Carries No Keys (" + (Get-Painted $script:C_Dim $MasterPath) + ")")
        exit 1
    }

    $rewritten = @("payloadsha256", "payloadname", "runtimename", "exportmap", "dlldir")
    $lost = 0
    $diverged = 0
    foreach ($key in $master.Keys) {
        if (-not $deployed.ContainsKey($key)) {
            Write-Fail ("Master Key Was Lost On The Way To The Deployed Config: " + $key + " (" + (Get-Painted $script:C_Dim $Path) + ")")
            $lost++
            continue
        }
        $bare = $key.Substring($key.IndexOf("::") + 2)
        if ($rewritten -contains $bare) { continue }
        if ($deployed[$key] -ne $master[$key]) {
            Write-Fail ("Deployed Config Diverged From The Master On: " + $key + " (Master '" + $master[$key] + "', Deployed '" + $deployed[$key] + "')")
            $diverged++
        }
    }
    if ($lost -gt 0 -or $diverged -gt 0) {
        Write-Fail ("Master/Deployed Config Parity Failed: " + $lost + " Lost, " + $diverged + " Diverged")
        exit 1
    }
    Write-Ok ("Deployed Config Carries Every Master Key: " + (Get-Painted $script:C_Green (([string]$master.Count) + "/" + ([string]$master.Count))) + " Keys, No Divergence (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ($Check -eq "ConfigKeys") {
    if ([string]::IsNullOrEmpty($Magic)) {
        Write-Fail "Expected A Config Magic"
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
            Write-Fail ("DPAPI Decrypt Failed: " + $_.Exception.Message)
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
            Write-Fail ("Deployed Config Is Missing Required Key: " + $k + " (" + (Get-Painted $script:C_Dim $Path) + ")")
            exit 1
        }
    }
    Write-Ok ("Deployed Config Carries Per-Build Keys: PayloadName, RuntimeName, ExportMap, DllDir (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

if ([string]::IsNullOrEmpty($Magic)) {
    Write-Fail "Expected A Config Magic String"
    exit 1
}
$expected = [Text.Encoding]::ASCII.GetBytes($Magic)
if ($data.Length -lt $expected.Length) {
    Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
    exit 1
}
for ($i = 0; $i -lt $expected.Length; $i++) {
    if ($data[$i] -ne $expected[$i]) {
        Write-Fail ("Encrypted Config Magic '" + $Magic + "' Missing: " + (Get-Painted $script:C_Dim $Path))
        exit 1
    }
}
Write-Ok ("Encrypted Config Magic = " + (Get-Painted $script:C_Green $Magic) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
exit 0
