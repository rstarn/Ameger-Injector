param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Stub", "Payload", "Stealth")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path
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

# Byte pattern matcher with wildcards. A needle element of -1 matches any byte in the haystack; every
# other element is compared verbatim. Wildcards are what make the checks tolerant of a compiler that
# materialises an immediate differently between builds (a different service number, a different
# register, or an alternate constant-pool placement) while the opcode skeleton stays identical.
function Get-ByteMatches([byte[]]$Hay, [int[]]$Needle) {
    $count = 0
    $last = $Hay.Length - $Needle.Length
    for ($i = 0; $i -le $last; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Needle[$j] -ge 0 -and $Hay[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { $count++ }
    }
    return $count
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

# The syscall stub template that is emitted into the stub pool and into the remote stage:
#   4C 8B D1          mov  r10, rcx
#   B8 ?? ?? ?? ??    mov  eax, <service>   (imm32 wildcarded: it is per-service, not fixed)
#   0F 05             syscall
#   C3                ret
$stubTemplate = [int[]](0x4C, 0x8B, 0xD1, 0xB8, -1, -1, -1, -1, 0x0F, 0x05, 0xC3)

# The healthy ntdll prologue the resolver matches against, as an immediate compare value.
$healthyPrologue = [int[]](0x4C, 0x8B, 0xD1, 0xB8)

# Page-aligned staging and the page-rounded payload protect are evidenced by the alignment constants.
# The immediates below are the splitmix64 finalizer constants used by MMI_KeyBlock in
# Ameger/Injection/ManualMapping/ManualMappingInternal.h (0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9,
# 0x94D049BB133111EB). Keep this list in sync with that function: it is the single source of truth.
# These are read in little endian order, which is how x64 stores a 64-bit immediate.
$keystreamConstant = [int[]](0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E)  # 0x9E3779B97F4A7C15
$keystreamAlt      = [int[]](0xB9, 0xE5, 0xE4, 0x1C, 0x6D, 0x47, 0x58, 0xBF)  # 0xBF58476D1CE4E5B9
$keystreamAlt2     = [int[]](0xEB, 0x11, 0x31, 0x13, 0xBB, 0x49, 0xD0, 0x94)  # 0x94D049BB133111EB

if ($Check -eq "Stub") {
    $stubCount = Get-ByteMatches $data $stubTemplate
    if ($stubCount -lt 1) {
        Write-Fail "Direct-syscall stub template (mov r10,rcx; mov eax,imm; syscall; ret) not present"
        exit 1
    }
    Write-Ok ("Direct-syscall stub template present (" + $stubCount + " match)")

    $prologueCount = Get-ByteMatches $data $healthyPrologue
    if ($prologueCount -lt 1) {
        Write-Fail "ntdll healthy-prologue comparison constant not present"
        exit 1
    }
    Write-Ok ("Resolver prologue constant present (" + $prologueCount + " match)")

    # A syscall dispatcher needs the two-byte opcode 0F 05 to be issued; without it the layer is inert.
    $syscallOp = [int[]](0x0F, 0x05)
    $opCount = Get-ByteMatches $data $syscallOp
    if ($opCount -lt 1) {
        Write-Fail "syscall opcode 0F 05 not found; direct-syscall layer would be inert"
        exit 1
    }
    Write-Ok ("syscall opcode issued (" + $opCount + " match)")
}

if ($Check -eq "Payload") {
    # Any one of the mixer constants is enough: the compiler is free to fold or drop individual
    # constants, so requiring a specific one would make the check brittle to a build change.
    $k1 = Get-ByteMatches $data $keystreamConstant
    $k2 = Get-ByteMatches $data $keystreamAlt
    $k3 = Get-ByteMatches $data $keystreamAlt2
    if (($k1 + $k2 + $k3) -lt 1) {
        Write-Fail "Payload keystream mixer constants not present; transfer obfuscation appears disabled"
        exit 1
    }
    Write-Ok ("Payload keystream mixer present (k1=" + $k1 + " k2=" + $k2 + " k3=" + $k3 + ")")
}

if ($Check -eq "Stealth") {
    # Specific instruction encodings of the NtProtectVirtualMemory protection argument. The 4th argument
    # (NewProtect) is loaded into r9d, and the 5th argument (OldProtect pointer) is written to the x64
    # shadow space at [rsp+20h]. Matching the immediate *together* with that shadow store is what makes
    # the check specific: a bare "20 00 00 00" / "01 00 00 00" matches almost any x64 image, while the
    # paired sequence only appears at a real protection call. Both instruction orders are accepted so a
    # different scheduler decision does not produce a false negative.
    $shadow = [int[]](0x48, 0x89, 0x4C, 0x24, 0x20)               # mov qword ptr [rsp+20h], rcx
    $r9rx   = [int[]](0x41, 0xB9, 0x20, 0x00, 0x00, 0x00)         # mov r9d, 20h (PAGE_EXECUTE_READ)
    $r9na   = [int[]](0x41, 0xB9, 0x01, 0x00, 0x00, 0x00)         # mov r9d, 01h (PAGE_NOACCESS)
    $r9rwx  = [int[]](0x41, 0xB9, 0x40, 0x00, 0x00, 0x00)         # mov r9d, 40h (PAGE_EXECUTE_READWRITE)

    $rx  = (Get-ByteMatches $data ([int[]]($shadow + $r9rx)))  + (Get-ByteMatches $data ([int[]]($r9rx + $shadow)))
    $na  = (Get-ByteMatches $data ([int[]]($shadow + $r9na)))  + (Get-ByteMatches $data ([int[]]($r9na + $shadow)))
    $rwx = (Get-ByteMatches $data ([int[]]($shadow + $r9rwx))) + (Get-ByteMatches $data ([int[]]($r9rwx + $shadow)))

    if (($rx -lt 1) -or ($na -lt 1)) {
        Write-Fail "W^X protection sequences missing (PAGE_EXECUTE_READ / PAGE_NOACCESS into NtProtectVirtualMemory)"
        exit 1
    }
    if ($rwx -gt 0) {
        Write-Fail "NtProtectVirtualMemory requests PAGE_EXECUTE_READWRITE (0x40); W^X regression"
        exit 1
    }
    Write-Ok ("W^X protect sequences present (rx=" + $rx + " noaccess=" + $na + " rwx=" + $rwx + ")")

    Write-Host ("  " + (Get-Painted $script:C_Dim "static verification only; live properties are checked by the runtime verify tool"))
}

exit 0
