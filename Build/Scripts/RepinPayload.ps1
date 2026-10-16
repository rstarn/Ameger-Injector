param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Payload,

    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Config)) {
    Write-Host ("RepinPayload: Config Not Found: " + $Config)
    exit 1
}
if (-not (Test-Path -LiteralPath $Payload)) {
    Write-Host ("RepinPayload: Payload Asset Not Found: " + $Payload)
    exit 1
}

$hash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($Payload))) -replace "-", "")
if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64 -or $hash -notmatch '^[0-9A-Fa-f]{64}$') {
    Write-Host "RepinPayload: Payload Did Not Yield A 64-Hex SHA-256 Digest"
    exit 1
}

$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Config))

$rx = '(?m)^([ \t]*PayloadSha256[ \t]=).*$'
$count = [regex]::Matches($text, $rx).Count

if ($count -gt 1) {
    Write-Host ("RepinPayload: Found " + $count + " PayloadSha256 Lines; Refusing An Ambiguous Re-Pin")
    exit 1
}

$old = $null
if ($count -eq 1) {
    $line = ([regex]::Match($text, $rx)).Value
    $eq = $line.IndexOf("=")
    $old = $line.Substring($eq + 1).Trim()
    if ($old -ieq $hash) {
        if (-not $Quiet) { Write-Host ("RepinPayload: Pin Already Current (" + $hash + "); No Change") }
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
        Write-Host "RepinPayload: No [General] Section And No PayloadSha256 Line; Refusing To Guess Placement"
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
Write-Host ("RepinPayload: Config Pinned To " + $Payload)
exit 0
