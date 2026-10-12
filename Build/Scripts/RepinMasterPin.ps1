# Re-pin the plaintext master PayloadSha256 to the current payload asset.
#
# The master Build\Configuration.ini carries PayloadSha256 = <SHA-256 of the
# pristine Assets\DLL\Jlov.dll>. Create.bat's :deploy_payload verifies the
# deployed copy against this pin whenever the pristine asset itself is shipped,
# so replacing that DLL with a different payload makes the build fail closed on
# the stale pin. Sanctioning the refresh here (instead of forbidding hand-edits)
# makes "swap the payload" a real workflow: the pin is re-established to the new
# asset, and :deploy_payload STILL verifies the shipped DLL against whatever pin
# the master now holds, so a later substitution still fails the build.
#
# To ship a changed payload WITHOUT touching the master pristine pin, use the
# prepared-payload path instead: AMEGER_PAYLOAD=<path>\x.dll, or dropping it at
# Assets\DLL\Jlov.protected.dll. That re-pins only the shipped config.
#
# Only the PayloadSha256 value is rewritten; every other line (comments, section
# layout, indentation, BOM) is preserved. Rewrites are CRLF-normalized exactly
# like the sibling ProtectConfig.ps1.
#
# Usage:
#   RepinMasterPin.ps1 -Config <Configuration.ini> -Payload <payload.dll>
# Exit codes: 0 = pin updated (or already current, file untouched), 1 = fatal
# (file unchanged).

param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Payload,
    # Suppress the "already current" no-op message. The build adopts the current
    # asset on every run, so it needs the no-op silent while still reporting a
    # real change; the interactive "Create.bat repin" leaves this off.
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Config)) {
    Write-Host ("RepinMasterPin: master config not found: " + $Config)
    exit 1
}
if (-not (Test-Path -LiteralPath $Payload)) {
    Write-Host ("RepinMasterPin: payload asset not found: " + $Payload)
    exit 1
}

$hash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($Payload))) -replace "-", "")
if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -ne 64 -or $hash -notmatch '^[0-9A-Fa-f]{64}$') {
    Write-Host "RepinMasterPin: Payload did not yield a 64-hex SHA-256 digest"
    exit 1
}

# Preserve any BOM: UTF8.GetString leaves a leading U+FEFF intact, and writing
# with UTF8Encoding($false) re-emits it byte-for-byte, so a BOM'd master stays
# BOM'd and a BOM-less one stays BOM-less.
$text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Config))

# Anchored, single-space-tolerant match on a real key line only. [ \t] (not \s)
# so a blank/whitespace line cannot bleed across a newline into the match, and a
# ;/ comment line can never match because it does not start with the key name.
$rx = '(?m)^([ \t]*PayloadSha256[ \t]=).*$'
$count = [regex]::Matches($text, $rx).Count

if ($count -gt 1) {
    Write-Host ("RepinMasterPin: found " + $count + " PayloadSha256 lines; refusing an ambiguous re-pin")
    exit 1
}

$old = $null
if ($count -eq 1) {
    $line = ([regex]::Match($text, $rx)).Value
    $eq = $line.IndexOf("=")
    $old = $line.Substring($eq + 1).Trim()
    if ($old -ieq $hash) {
        if (-not $Quiet) { Write-Host ("RepinMasterPin: pin already current (" + $hash + "); no change") }
        exit 0
    }
    $text = [regex]::Replace($text, $rx, ('$1 ' + $hash), 1)
}
else {
    # No PayloadSha256 line: inject one at the top of [General] so the master is
    # never left unpinned (a missing pin fails closed downstream on both the
    # deploy gate and the launcher).
    $lines = [regex]::Split($text, "\r?\n")
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -ieq "[General]") { $idx = $i; break }
    }
    if ($idx -lt 0) {
        Write-Host "RepinMasterPin: no [General] section and no PayloadSha256 line; refusing to guess placement"
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
Write-Host ("RepinMasterPin: PayloadSha256 " + $(if ($old) { $old } else { "<absent>" }) + " -> " + $hash)
Write-Host ("RepinMasterPin: master pinned to " + $Payload)
exit 0
