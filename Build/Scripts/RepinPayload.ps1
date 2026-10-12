param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Payload,

    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Config)) {
    Write-Host ("RepinPayload: config not found: " + $Config)
    exit 1
}
if (-not (Test-Path -LiteralPath $Payload)) {
    Write-Host ("RepinPayload: payload asset not found: " + $Payload)
    exit 1
}

$hash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($Payload))) -replace "-", "")
if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64 -or $hash -notmatch '^[0-9A-Fa-f]{64}$') {
    Write-Host "RepinPayload: Payload did not yield a 64-hex SHA-256 digest"
    exit 1
}

$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Config))

$rx = '(?m)^([ \t]*PayloadSha256[ \t]=).*$'
$count = [regex]::Matches($text, $rx).Count

if ($count -gt 1) {
    Write-Host ("RepinPayload: found " + $count + " PayloadSha256 lines; refusing an ambiguous re-pin")
    exit 1
}

$old = $null
if ($count -eq 1) {
    $line = ([regex]::Match($text, $rx)).Value
    $eq = $line.IndexOf("=")
    $old = $line.Substring($eq + 1).Trim()
    if ($old -ieq $hash) {
        if (-not $Quiet) { Write-Host ("RepinPayload: pin already current (" + $hash + "); no change") }
        exit 0
    }
    $text = [regex]::Replace($text, $rx, ('$1 ' + $hash), 1)
}
else {

    $lines = [regex]::Split($text, "\r?\n")
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -ieq "[General]") { $idx = $i; break }
    }
    if ($idx -lt 0) {
        Write-Host "RepinPayload: no [General] section and no PayloadSha256 line; refusing to guess placement"
        exit 1
    }
    $new = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $new.Add($lines[$i])
        if ($i -eq $idx) { $new.Add("PayloadSha256 = " + $hash) }
    }
    $text = ($new -join "`r`n")
}

[IO.File]::WriteAllText($Config, $text, (New-Object Text.UTF8Encoding($false)))
Write-Host ("RepinPayload: PayloadSha256 " + $(if ($old) { $old } else { "<absent>" }) + " -> " + $hash)
Write-Host ("RepinPayload: config pinned to " + $Payload)
exit 0
