param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Stub", "Payload", "Stealth", "MmapSections")]
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
    Write-Fail ("Not Found: " + $Path)
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
        Write-Fail "Direct-Syscall Stub Template (mov r10,rcx; mov eax,imm; syscall; ret) Not Present"
        exit 1
    }
    Write-Ok ("Direct-Syscall Stub Template Present (" + $stubCount + " Match)")

    $prologueCount = Get-ByteMatches $data $healthyPrologue
    if ($prologueCount -lt 1) {
        Write-Fail "ntdll Healthy-Prologue Comparison Constant Not Present"
        exit 1
    }
    Write-Ok ("Resolver Prologue Constant Present (" + $prologueCount + " Match)")

    # A syscall dispatcher needs the two-byte opcode 0F 05 to be issued; without it the layer is inert.
    $syscallOp = [int[]](0x0F, 0x05)
    $opCount = Get-ByteMatches $data $syscallOp
    if ($opCount -lt 1) {
        Write-Fail "Syscall Opcode 0F 05 Not Found; Direct-Syscall Layer Would Be Inert"
        exit 1
    }
    Write-Ok ("Syscall Opcode Issued (" + $opCount + " Match)")
}

if ($Check -eq "Payload") {
    # Any one of the mixer constants is enough: the compiler is free to fold or drop individual
    # constants, so requiring a specific one would make the check brittle to a build change.
    $k1 = Get-ByteMatches $data $keystreamConstant
    $k2 = Get-ByteMatches $data $keystreamAlt
    $k3 = Get-ByteMatches $data $keystreamAlt2
    if (($k1 + $k2 + $k3) -lt 1) {
        Write-Fail "Payload Keystream Mixer Constants Not Present; Transfer Obfuscation Appears Disabled"
        exit 1
    }
    Write-Ok ("Payload Keystream Mixer Present (K1 = " + $k1 + " | K2 = " + $k2 + " | K3 = " + $k3 + ")")
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
        Write-Fail "W^X Protection Sequences Missing (PAGE_EXECUTE_READ / PAGE_NOACCESS Into NtProtectVirtualMemory)"
        exit 1
    }
    if ($rwx -gt 0) {
        Write-Fail "NtProtectVirtualMemory Requests PAGE_EXECUTE_READWRITE (0x40); W^X Regression"
        exit 1
    }
    Write-Ok ("W^X Protect Sequences Present (RX = " + $rx + " | NOACCESS = " + $na + " | RWX = " + $rwx + ")")

    Write-Host ("  " + (Get-Painted $script:C_Dim "Static Verification Only; Live Properties Are Checked By The Runtime Verify Tool"))
}

if ($Check -eq "MmapSections") {
    # The remote mapping shell lives in code_seg(".mmap_sec$01" .. ".mmap_sec$14"). The C++ side
    # computes ShellSize as (MMAP_SEC_END - ManualMapping_Shell) and copies that whole span into the
    # target in one WriteProcessMemory, which is only correct when the linker has merged every "$"
    # suffixed part of the section into ONE contiguous block. If it emitted them separately, the span
    # would span padding (or an unrelated section) and the staged image would contain whatever the
    # linker placed between the parts - which still passes every byte-pattern check below.
    #
    # So this check reads the section table directly: it requires exactly one section whose name is the
    # ".mmap_sec" base, which is what a successful merge leaves behind. Any leftover per-part sections
    # ("$01", "$02", ... appear verbatim in the name field) mean the merge did not happen.
    if ($data.Length -lt 64 -or $data[0] -ne 0x4D -or $data[1] -ne 0x5A) {
        Write-Fail "Not An MZ Image"
        exit 1
    }

    $e = [BitConverter]::ToInt32($data, 0x3C)
    if ($e -le 0 -or ($e + 24) -gt $data.Length) { Write-Fail "Bad e_lfanew"; exit 1 }
    if ([BitConverter]::ToUInt32($data, $e) -ne 0x00004550) { Write-Fail "Not PE"; exit 1 }

    $coff = $e + 4
    $nsec = [BitConverter]::ToUInt16($data, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($data, $coff + 16)
    $opt = $e + 24
    if ($nsec -le 0 -or $nsec -gt 96) { Write-Fail "Bad Section Count"; exit 1 }
    if ([BitConverter]::ToUInt16($data, $opt) -ne 0x20B) { Write-Fail "Not PE32+"; exit 1 }

    $secBase = $opt + $optSize
    $names = New-Object System.Collections.ArrayList
    $chars = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $secBase + (40 * $i)
        $name = ""
        for ($k = 0; $k -lt 8; $k++) {
            $c = $data[$o + $k]
            if ($c -eq 0) { break }
            $name += [char]$c
        }
        [void]$names.Add($name)
        [void]$chars.Add([PSCustomObject]@{ Index = $i; Name = $name; Offset = $o })
    }

    # The PE name field is exactly 8 bytes with no terminator, so a merged ".mmap_sec$NN" family shows
    # up as the truncated 8-char name ".mmap_se". A successful merge therefore leaves exactly one
    # section whose name is a prefix of ".mmap_sec"; if the linker had emitted the "$NN" parts
    # separately, their names would still carry the "$" and the "$NN" suffix and be caught here.
    $mmapExact = @($chars | Where-Object { $_.Name -eq ".mmap_sec" })
    $mmapTrunc = @($chars | Where-Object { $_.Name -eq ".mmap_se" })

    # Per-part leftovers: any name that still contains the "$NN" discriminator means the merge did not
    # fully collapse. In practice the linker truncates, so this is the belt-and-braces path.
    $dollarParts = @($chars | Where-Object { $_.Name -match "\`$" })

    if ($mmapExact.Count -eq 0 -and $mmapTrunc.Count -eq 0) {
        Write-Fail "No .mmap_sec Section Present At All; The Remote Shell Was Not Emitted"
        Write-Host ("      Sections: " + ($names -join ", "))
        exit 1
    }

    $mergedCount = $mmapExact.Count + $mmapTrunc.Count
    if ($mergedCount -ne 1) {
        Write-Fail ("Expected Exactly One Merged .mmap_sec Section, Found " + $mergedCount)
        exit 1
    }

    if ($dollarParts.Count -ne 0) {
        Write-Fail ("Per-Part code_seg Sections With A `$ Discriminator Survived The Link (" + $dollarParts.Count + ")")
        Write-Host ("      Found: " + (($dollarParts | ForEach-Object { $_.Name }) -join ", "))
        exit 1
    }

    Write-Ok ("Remote Mapping Shell Is A Single Merged Section (" + ($mmapExact + $mmapTrunc)[0].Name + ")")

    # The merged block must be executable and non writable: the shell is staged RW, written, then
    # promoted to RX, and the dispatch table that points into it is what the trampoline calls through.
    $entry = ($mmapExact + $mmapTrunc)[0]
    $characteristics = [BitConverter]::ToUInt32($data, $entry.Offset + 36)
    if (($characteristics -band 0x20000000) -eq 0) {
        Write-Fail "Merged .mmap_sec Section Is Not Executable"
        exit 1
    }
    if (($characteristics -band 0x80000000) -ne 0) {
        Write-Fail "Merged .mmap_sec Section Is Writable; W^X Regression In The Staged Image"
        exit 1
    }
    Write-Ok ("Merged Shell Section Is Execute+Read (Characteristics 0x" + $characteristics.ToString("X8") + ")")
}

exit 0
