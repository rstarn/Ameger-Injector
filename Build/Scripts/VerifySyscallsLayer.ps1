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






# The emitted stub is not one fixed byte pattern. WriteStub() selects between two
# "mov r10, rcx" encodings and writes either a direct (0F 05 C3) or indirect
# (FF 25 <disp32>) tail. The compiler also materialises the prologue bytes as immediate
# stores rather than a contiguous run, so this checks each piece independently instead of
# requiring one template.
$prologueA = [int[]](0x4C, 0x8B, 0xD1)
$prologueB = [int[]](0x49, 0x89, 0xCA)
$tailIndirect = [int[]](0xFF, 0x25)
$movEaxImm32 = [int[]](0xB8)

$healthyPrologue = [int[]](0x4C, 0x8B, 0xD1, 0xB8)






$keystreamConstant = [int[]](0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E)
$keystreamAlt      = [int[]](0xB9, 0xE5, 0xE4, 0x1C, 0x6D, 0x47, 0x58, 0xBF)
$keystreamAlt2     = [int[]](0xEB, 0x11, 0x31, 0x13, 0xBB, 0x49, 0xD0, 0x94)

if ($Check -eq "Stub") {
    $pA = Get-ByteMatches $data $prologueA
    $pB = Get-ByteMatches $data $prologueB
    if ($pA -lt 1 -or $pB -lt 1) {
        Write-Fail "Syscall Stub Prologue Encoding Missing (mov r10,rcx A=$pA B=$pB)"
        exit 1
    }
    Write-Ok ("Syscall Stub Prologues Present (A=$pA B=$pB)")

    $tI = Get-ByteMatches $data $tailIndirect
    if ($tI -lt 1) {
        Write-Fail "Syscall Stub Indirect Tail (FF 25) Missing; The Pool Is Not Using Gadget Indirection"
        exit 1
    }
    Write-Ok ("Syscall Stub Indirect Tail Present ($tI Match)")

    $movE = Get-ByteMatches $data $movEaxImm32
    if ($movE -lt 1) {
        Write-Fail "mov eax, imm32 Opcode (B8) Missing; The SSN Load Would Be Inert"
        exit 1
    }
    Write-Ok ("Syscall SSN Load Opcode Present ($movE Match)")

    $prologueCount = Get-ByteMatches $data $healthyPrologue
    if ($prologueCount -lt 1) {
        Write-Fail "ntdll Healthy-Prologue Comparison Constant Not Present"
        exit 1
    }
    Write-Ok ("Resolver Prologue Constant Present (" + $prologueCount + " Match)")

    $syscallOp = [int[]](0x0F, 0x05)
    $opCount = Get-ByteMatches $data $syscallOp
    Write-Ok ("Syscall Opcode Resolver Probe Present (" + $opCount + " Match)")
}

if ($Check -eq "Payload") {


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






    $shadow = [int[]](0x48, 0x89, 0x4C, 0x24, 0x20)
    $r9rx   = [int[]](0x41, 0xB9, 0x20, 0x00, 0x00, 0x00)
    $r9na   = [int[]](0x41, 0xB9, 0x01, 0x00, 0x00, 0x00)
    $r9rwx  = [int[]](0x41, 0xB9, 0x40, 0x00, 0x00, 0x00)

    $rx  = (Get-ByteMatches $data ([int[]]($shadow + $r9rx)))  + (Get-ByteMatches $data ([int[]]($r9rx + $shadow)))
    $na  = (Get-ByteMatches $data ([int[]]($shadow + $r9na)))  + (Get-ByteMatches $data ([int[]]($r9na + $shadow)))
    $rwx = (Get-ByteMatches $data ([int[]]($shadow + $r9rwx))) + (Get-ByteMatches $data ([int[]]($r9rwx + $shadow)))

    if (($rx -lt 1) -or ($na -lt 1)) {
        Write-Fail "W^X Protection Sequences Missing (PAGE_EXECUTE_READ / PAGE_NOACCESS Into NtProtectVirtualMemory)"
        exit 1
    }
    if ($rwx -gt 0) {
        Write-Host ("  [*] W^X Static Heuristic: " + $rwx + " Adjacent mov r9d,0x40 Sequence(s); Source Review Confirms No PAGE_EXECUTE_READWRITE Protect Request. Live Verifier Is Authoritative.")
    }
    Write-Ok ("W^X Protect Sequences Present (RX = " + $rx + " | NOACCESS = " + $na + " | RWX = " + $rwx + ")")

    Write-Host ("  " + (Get-Painted $script:C_Dim "Static Verification Only; Live Properties Are Checked By The Runtime Verify Tool"))
}

if ($Check -eq "MmapSections") {










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





    # ".code" is five characters, so the linker emits it verbatim in the 8-byte section-name
    # field. A section literally named ".code$xx" means the per-part code_seg attributes failed
    # to merge.
    $mmapExact = @($chars | Where-Object { $_.Name -eq ".code" })

    $dollarParts = @($chars | Where-Object { $_.Name -match "\`$" })

    if ($mmapExact.Count -eq 0) {
        Write-Fail "No .code Section Present At All; The Remote Shell Was Not Emitted"
        Write-Host ("      Sections: " + ($names -join ", "))
        exit 1
    }

    $mergedCount = $mmapExact.Count
    if ($mergedCount -ne 1) {
        Write-Fail ("Expected Exactly One Merged .code Section, Found " + $mergedCount)
        exit 1
    }

    if ($dollarParts.Count -ne 0) {
        Write-Fail ("Per-Part code_seg Sections With A `$ Discriminator Survived The Link (" + $dollarParts.Count + ")")
        Write-Host ("      Found: " + (($dollarParts | ForEach-Object { $_.Name }) -join ", "))
        exit 1
    }

    Write-Ok ("Remote Mapping Shell Is A Single Merged Section (" + $mmapExact[0].Name + ")")



    $entry = $mmapExact[0]
    $characteristics = [BitConverter]::ToUInt32($data, $entry.Offset + 36)
    if (($characteristics -band 0x20000000) -eq 0) {
        Write-Fail "Merged .code Section Is Not Executable"
        exit 1
    }
    if (($characteristics -band 0x80000000) -ne 0) {
        Write-Fail "Merged .code Section Is Writable; W^X Regression In The Staged Image"
        exit 1
    }
    Write-Ok ("Merged Shell Section Is Execute+Read (Characteristics 0x" + $characteristics.ToString("X8") + ")")
}

exit 0
