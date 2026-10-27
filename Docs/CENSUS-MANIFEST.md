> **Census reflects TASK-001 state. Mapper has moved since.**
>
> Hashes below were recorded at commit 6d20e98 (baseline-001-post).
> Ameger-Mapper has advanced past cce43c1 ("Improve logging output
> formatting and consistency"), which modified Provider.hpp and
> Driver.cpp. Hash comparisons against those two Mapper rows will
> diverge for benign reasons. Injector-side rows remain accurate as
> of baseline-003-post (65d591d) unless Injector has moved again.
>
> Current Mapper truth lives in
> `git -C D:\Ameger\Mapper\Mapper log` and in
> `Docs/RISK-REGISTER.md`.

# TASK-001 Census Manifest

One row per file. sha12 = first 12 hex of SHA-256.

| path | lang | bytes | sha12 | lines | role |
|---|---|---:|---|---|---|
| .analysis | markdown | 149752 | 40E520FE1C8E | 2036 | repository or Mapper support file |
| .asm-lsp.toml | toml | 402 | BE3B50C08A8C | 18 | repository or Mapper support file |
| .clangd | json | 2603 | 3F3939A49E24 | 64 | repository or Mapper support file |
| .gitignore | gitignore | 139 | C0C709F0B1FE | 10 | repository or Mapper support file |
| .zed/settings.json | text | 278 | 6DD2654451A1 | 17 | repository or Mapper support file |
| Ameger/Core/Foundation/Error.h | c-header | 5251 | 7D0753895C9F | 118 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Main.cpp | cpp | 9191 | CD66D40B2D29 | 282 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/InjectionTypes.h | c-header | 8600 | 9D55695D5260 | 200 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/Core/DomainKey.h | c-header | 548 | EB98AB8418C1 | 23 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/Core/KcStrSuite.h | c-header | 1544 | 0696274DDD07 | 68 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h | c-header | 3336 | B9CB997A1547 | 69 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/KcLayered.h | c-header | 11077 | 3346819E5E71 | 260 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/KcNarrow.h | c-header | 2258 | 72727F92E115 | 70 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/KcStack.h | c-header | 1409 | 78819760DA15 | 36 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/KcStrings/KcWide.h | c-header | 2487 | 38EA37F0EFFD | 72 | Ameger runtime/injection library source or header |
| Ameger/Core/Foundation/Primitives/ResourceGuard.h | c-header | 3077 | 13FB1520F4E2 | 139 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Binary/DynamicAPI.h | c-header | 5209 | A74330BF5BF1 | 150 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Binary/PEImage.h | c-header | 18149 | EC6177344BB7 | 463 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Header/PrecompiledHeader.cpp | cpp | 2443 | D28F8BD58CC4 | 101 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Header/PrecompiledHeader.h | c-header | 1991 | 5CF575B2F544 | 57 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Tools/Tools.cpp | cpp | 23187 | 36F69D54FFE4 | 778 | Ameger runtime/injection library source or header |
| Ameger/Core/Utility/Tools/Tools.h | c-header | 3880 | 837B410932B8 | 104 | Ameger runtime/injection library source or header |
| Ameger/Execution/Routine/StartRoutine.cpp | cpp | 631 | 796DB400E91C | 11 | Ameger runtime/injection library source or header |
| Ameger/Execution/Routine/StartRoutine.h | c-header | 4634 | 768C25690292 | 92 | Ameger runtime/injection library source or header |
| Ameger/Execution/Stub/RemoteShell.inc | c-header | 3593 | 51F1E34C3CC4 | 70 | Ameger runtime/injection library source or header |
| Ameger/Execution/Stub/RemoteThreadHijack.asm | asm | 7545 | 2402A8D5FEC0 | 220 | Ameger runtime/injection library source or header |
| Ameger/Execution/ThreadHijacking.cpp | cpp | 67273 | 92BA584D1A15 | 1801 | Ameger runtime/injection library source or header |
| Ameger/Injection.h | c-header | 2997 | 21E350645366 | 72 | Ameger runtime/injection library source or header |
| Ameger/Injection/Injection.cpp | cpp | 13041 | 0CD8011A2F06 | 378 | Ameger runtime/injection library source or header |
| Ameger/Injection/Injection.h | c-header | 633 | 40A75CDAACF2 | 22 | Ameger runtime/injection library source or header |
| Ameger/Injection/ManualMapping/ManualMapping.cpp | cpp | 118754 | F291521ABB59 | 2991 | Ameger runtime/injection library source or header |
| Ameger/Injection/ManualMapping/ManualMappingCore.h | c-header | 420 | 7841749611E1 | 9 | Ameger runtime/injection library source or header |
| Ameger/Injection/ManualMapping/ManualMappingInternal.h | c-header | 17495 | F2BF1F045487 | 399 | Ameger runtime/injection library source or header |
| Ameger/NT/NTDefinitions.h | c-header | 14126 | 477BBF7F2A89 | 452 | Ameger runtime/injection library source or header |
| Ameger/NT/NTFunctions.h | c-header | 4793 | 11D5FE826EAF | 188 | Ameger runtime/injection library source or header |
| Ameger/NT/Windows11.h | c-header | 3154 | F7C2B1EC0F0F | 96 | Ameger runtime/injection library source or header |
| Ameger/Native/Syscall.cpp | cpp | 34598 | 3E1FDCA71E8F | 1008 | Ameger runtime/injection library source or header |
| Ameger/Native/Syscall.h | c-header | 17997 | 49D3A696DDFB | 503 | Ameger runtime/injection library source or header |
| Ameger/System/Download/Manager.cpp | cpp | 3285 | EC2A4EF7789C | 127 | Ameger runtime/injection library source or header |
| Ameger/System/Download/Manager.h | c-header | 817 | 200BAFD572B6 | 24 | Ameger runtime/injection library source or header |
| Ameger/System/Handle/HandleHijack.cpp | cpp | 35452 | B0F12A23083C | 1105 | Ameger runtime/injection library source or header |
| Ameger/System/Handle/HandleHijack.h | c-header | 760 | 8EC923F98ABD | 10 | Ameger runtime/injection library source or header |
| Ameger/System/Import/ImportHandler.cpp | cpp | 10839 | E56458893DB7 | 256 | Ameger runtime/injection library source or header |
| Ameger/System/Import/ImportHandler.h | c-header | 1802 | B2359F7B1E10 | 51 | Ameger runtime/injection library source or header |
| Ameger/System/Information/ProcessInformation.cpp | cpp | 8674 | 57297FA3A5D7 | 277 | Ameger runtime/injection library source or header |
| Ameger/System/Information/ProcessInformation.h | c-header | 1303 | C38827ABFAEB | 32 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Loader/SymbolLoader.cpp | cpp | 30358 | AE0D4A085B95 | 828 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Loader/SymbolLoader.h | c-header | 1840 | D88F1463A4A8 | 70 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Offsets/DynamicOffsets.cpp | cpp | 10689 | 9B87191051A4 | 249 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Offsets/DynamicOffsets.h | c-header | 1365 | ADCBAB471DE9 | 38 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Parser/SymbolParser.cpp | cpp | 12963 | 74C9D074A46F | 417 | Ameger runtime/injection library source or header |
| Ameger/System/Symbol/Parser/SymbolParser.h | c-header | 1302 | 692B0DB5D1BE | 28 | Ameger runtime/injection library source or header |
| Assets/DLL/Jlov.dll | text | 12791808 | 551F794BA6C3 | binary | bundled runtime payload or VMProtect template |
| Assets/Template/Host - x64.exe.vmp | text | 523 | 4AC1B7F57FAA | binary | bundled runtime payload or VMProtect template |
| Assets/Template/Jlov.dll.vmp | text | 618 | D81A521ACBF0 | binary | bundled runtime payload or VMProtect template |
| Build/Configuration.ini | ini | 626 | C8500EE8C452 | 29 | build/protection pipeline file |
| Build/Executors/Create.bat | bat | 37384 | 4205B0A8E29C | 746 | build/protection pipeline file |
| Build/Executors/Protect.bat | bat | 4469 | 612D92A9A964 | 131 | build/protection pipeline file |
| Build/Executors/Protection/ProtectDLL.bat | bat | 27792 | 5F91DCF0762B | 574 | build/protection pipeline file |
| Build/Executors/Protection/ProtectEXE.bat | bat | 24968 | 29E3EEF95697 | 514 | build/protection pipeline file |
| Build/Scripts/BuildPE.ps1 | powershell | 21249 | 432F647E6F16 | 472 | build/protection pipeline file |
| Build/Scripts/BuildVMP.ps1 | powershell | 6271 | E5D5EF1927DF | 118 | build/protection pipeline file |
| Build/Scripts/CreateSeeds.ps1 | powershell | 837 | E7AD65F87CE3 | 24 | build/protection pipeline file |
| Build/Scripts/ProtectConfig.ps1 | powershell | 8285 | E0006EE85F42 | 211 | build/protection pipeline file |
| Build/Scripts/RepinPayload.ps1 | powershell | 2328 | 13AA426574F3 | 58 | build/protection pipeline file |
| Build/Scripts/ShuffleExports.ps1 | powershell | 9755 | 699BBAAE2622 | 219 | build/protection pipeline file |
| Build/Scripts/ShuffleNaming.ps1 | powershell | 2734 | 625A97DBECAB | 70 | build/protection pipeline file |
| Build/Scripts/StripExportDirs.ps1 | powershell | 3487 | F60C701EA6FC | 79 | build/protection pipeline file |
| Build/Scripts/VerifyEmbedMagic.ps1 | powershell | 8819 | 4947B8467484 | 212 | build/protection pipeline file |
| Build/Scripts/VerifyExportsName.ps1 | powershell | 2657 | 79E8E00AFC19 | 61 | build/protection pipeline file |
| Build/Scripts/VerifySyscallsLayer.ps1 | powershell | 9427 | 5C1EC6B8E301 | 191 | build/protection pipeline file |
| Interface/Source/Interface/Interface.cpp | cpp | 9777 | 76A0AA6AD5FC | 326 | launcher/injection frontend source or project template |
| Interface/Source/Interface/Process.cpp | cpp | 16886 | D8CDEE4A64B7 | 371 | launcher/injection frontend source or project template |
| Interface/Source/Interface/Stealth.cpp | cpp | 207235 | EDD923E79F8C | 4033 | launcher/injection frontend source or project template |
| Interface/Source/Launcher.h | c-header | 18471 | ACBE655867DA | 420 | launcher/injection frontend source or project template |
| Interface/Source/Main.cpp | cpp | 223940 | 12F00221FBD6 | 5083 | launcher/injection frontend source or project template |
| Interface/Source/PCH/PCH.cpp | cpp | 18 | 1CE37CEB4D40 | 1 | launcher/injection frontend source or project template |
| Interface/Source/PCH/PCH.h | c-header | 576 | DCD31A7B924A | 29 | launcher/injection frontend source or project template |
| Interface/Template/AmegerInjector.vcxproj | xml | 9889 | C9C30F88BE3E | 146 | launcher/injection frontend source or project template |
| Interface/Template/AmegerInjector.vcxproj.filters | text | 9850 | 13DE0FA72ED1 | binary | launcher/injection frontend source or project template |
| Interface/Template/AmegerInjectorInterface.vcxproj | xml | 4928 | D76C13D21447 | 83 | launcher/injection frontend source or project template |
| Interface/Template/Solution/AmegerInjector.sln | visual-studio-sln | 1191 | 5CBB60589732 | 24 | launcher/injection frontend source or project template |
| D:\Ameger\Mapper\.clangd | json | 2137 | 174E319B6B7F | 39 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\.gitignore | gitignore | 934 | 55FEDC82E6DC | 17 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\HelloWorld.sys | text | 3072 | 4F7F5D4CF540 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Releasemapper_debug.log | log | 294 | 82D6A06D38FA | 4 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Executors\Create.bat | bat | 26370 | ADE78EA2F334 | 486 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\Mapper.exe | text | 351232 | 1DE0C125DCA4 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\Mapper.exe.bak | text | 356352 | 3AA6C8545FAE | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\mapper_debug.log | log | 5499 | 1B65541ABAB6 | 61 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\Offsets.ini | ini | 665 | 2D6978CBBF40 | 24 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\SymbolTool.exe | text | 143360 | F5C1B4075D4D | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\write_test.txt | text | 11 | 34924D30A7D8 | 1 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\DLLs\dbghelp.dll | text | 2254392 | 2ED18FDB0BFE | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Release\DLLs\symsrv.dll | text | 423480 | FEA493309D3D | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ci.pdb | text | 765952 | 0708AFC41F80 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ntkrnlmp.pdb | text | 11522048 | F4F5C5D8DBAF | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\pingme.txt | text | 0 | E3B0C44298FC | 0 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ACPI.sys\B9C5FA56d6000\ACPI.sys | text | 873984 | E08A3597C683 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\acpiex.sys\FFB0E9152a000\acpiex.sys | text | 181760 | BA4BBED308C7 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\amdwps.sys\3DC3FE93e000\amdwps.sys | text | 67144 | E84CCD1521E0 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\BasicDisplay.sys\B0DDBE8B1a000\BasicDisplay.sys | text | 106496 | 75AB8FD5C899 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Beep.SYS\59390532a000\Beep.SYS | text | 40960 | 98CDBD998CF1 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\BOOTVID.dll\6E4A77D6d000\BOOTVID.dll | text | 62880 | 3E641691C4D0 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\cdrom.sys\731C7A1939000\cdrom.sys | text | 233472 | D9200F7C9D0B | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\CEA.sys\B769334218000\CEA.sys | text | 108016 | C82628CC7E76 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\CI.dll\4A10CEF711a000\CI.dll | text | 1170872 | C7D23814F320 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\CLASSPNP.SYS\08C8D62D7b000\CLASSPNP.SYS | text | 513496 | 16CF1FD7AED6 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\CLFS.SYS\9F1FB9DC8c000\CLFS.SYS | text | 570848 | 3BC0C50AE802 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\cmimcext.sys\A419E7AB12000\cmimcext.sys | text | 83432 | 2913F378DC2E | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\cng.sys\4E806F3Ce9000\cng.sys | text | 964288 | 06091EFF0AF7 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\crashdmp.sys\363B806D28000\crashdmp.sys | text | 161272 | 25698C7ADCBB | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\disk.sys\0757DD5C20000\disk.sys | text | 140776 | 007DB5A388DB | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\dxgkrnl.sys\A0F677D550d000\dxgkrnl.sys | text | 5293592 | AB420F667230 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\EhStorClass.sys\E478B89428000\EhStorClass.sys | text | 169432 | 10F3328824C2 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\filecrypt.sys\C6C0A88B17000\filecrypt.sys | text | 94208 | 48F8408987EC | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\fileinfo.sys\E7D4AA871d000\fileinfo.sys | text | 128432 | 56B772AC1184 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\FLTMGR.SYS\54AD72BC9a000\FLTMGR.SYS | text | 632288 | 33FE4804A039 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Fs_Rec.sys\1671DC59f000\Fs_Rec.sys | text | 71072 | 799C95DEC781 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\fvevol.sys\9A24DF20f1000\fvevol.sys | text | 996848 | BFA677BFFC77 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\fwpkclnt.sys\93E8A9FC8b000\fwpkclnt.sys | text | 579048 | E846C63A88A1 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\globmerger.sys\5EA3F06D20000\globmerger.sys | text | 140760 | 7D28D8B78FFF | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\hal.dll\EB9DEAA96000\hal.dll | text | 30000 | 6F8EC8F2FBA2 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\intelpep.sys\ACCCA7DA9f000\intelpep.sys | text | 657880 | 81D0892C1B71 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\IntelPMT.sys\9C2CA21713000\IntelPMT.sys | text | 88520 | A05600E18B15 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\iorate.sys\9A1CFEC214000\iorate.sys | text | 91624 | F35E1F621E16 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Kerb3961Kernel.sys\1D31A52D24000\Kerb3961Kernel.sys | text | 157144 | D180185B1FF5 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ksecdd.sys\F9B59C2436000\ksecdd.sys | text | 230904 | 3BB62B2EAF11 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ksecpkg.sys\62C0729038000\ksecpkg.sys | text | 230872 | 21D772CC4FEA | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\mountmgr.sys\862D9EFB23000\mountmgr.sys | text | 153064 | 8C7F26EFCA85 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\msisadrv.sys\C0CACEA5c000\msisadrv.sys | text | 58672 | DF2BF42C5CD3 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\msrpc.sys\8CFD115D65000\msrpc.sys | text | 423376 | 4DC103137769 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\mup.sys\E75A3C1C2b000\mup.sys | text | 185840 | 9A6CF0E6BF89 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ndis.sys\21D1FBEC1ca000\ndis.sys | text | 1877472 | 052AF5C0C624 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\NETIO.SYS\14053F28b7000\NETIO.SYS | text | 751096 | C92B8430E371 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Ntfs.sys\489F48C437d000\Ntfs.sys | text | 3634640 | 64835FA4BD4A | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ntkrnlmp.exe\FDA9ED741450000\ntkrnlmp.exe | text | 13104632 | D90C69CFA925 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\ntosext.sys\33F8A971d000\ntosext.sys | text | 62896 | A0D65E80D109 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Null.SYS\B4E46DA9d000\Null.SYS | text | 53248 | E56F9025A414 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\nvmedisk.sys\8698A9EE1d000\nvmedisk.sys | text | 128488 | ED789955358F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\partmgr.sys\DCDAFB9236000\partmgr.sys | text | 230896 | 6B5AD1739135 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\pci.sys\B0FBB7FD92000\pci.sys | text | 603640 | 09FB387886E9 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\pcw.sys\5BE4BC2F17000\pcw.sys | text | 103896 | B6C09B56EA59 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\pdc.sys\DD07B48435000\pdc.sys | text | 214520 | 7594E8AD88AE | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\PRM.sys\514FAA80f000\PRM.sys | text | 71072 | CEF2B58655B4 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\PSHED.dll\D52402051d000\PSHED.dll | text | 124416 | 9D28A344A681 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\rdyboost.sys\506BCD444e000\rdyboost.sys | text | 316896 | E93F329054F7 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\spaceport.sys\77E96B88f8000\spaceport.sys | text | 1025488 | 41ADBE9DB03D | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\stornvme.sys\66394A2A4f000\stornvme.sys | text | 333280 | 977432C9738D | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\storport.sys\C6628551281000\storport.sys | text | 2631128 | 4A9C1154C586 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\symcryptk.dll\98293ECDd000\symcryptk.dll | text | 62936 | 6C96C39BA155 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\tbs.sys\1BF929E1f000\tbs.sys | text | 71128 | A7758026D7E7 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\tcpip.sys\7636B763359000\tcpip.sys | text | 3479016 | 4E6435DBC435 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\tm.sys\60FD2AE02a000\tm.sys | text | 181720 | 453D4A71A68F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\tpm.sys\EB6923BB5a000\tpm.sys | text | 374224 | 2BEF98B8653C | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\uiomap.sys\CE52CC6611000\uiomap.sys | text | 69632 | 23B28B085482 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\vdrvroot.sys\87DB08091c000\vdrvroot.sys | text | 124216 | 0029FA9FE4F3 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\volmgr.sys\63943C2B1e000\volmgr.sys | text | 132600 | ADCCC9F19C6F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\volmgrx.sys\A127AA2266000\volmgrx.sys | text | 427504 | CF0683DE0279 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\volsnap.sys\232F319A84000\volsnap.sys | text | 550376 | 0BED9A1DD577 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\volume.sys\B2729186b000\volume.sys | text | 54672 | 42E63746060E | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\watchdog.sys\F3C582F020000\watchdog.sys | text | 140792 | 934992FF53C0 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WdBoot.sys\6CB508649000\WdBoot.sys | text | 20880 | FAE9E12E8F5D | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Wdf01000.sys\E27E5F8Cf0000\Wdf01000.sys | text | 988648 | 8FC84407CA0F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WDFLDR.SYS\962D91C317000\WDFLDR.SYS | text | 103928 | AD04EF498606 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\werkernel.sys\A6EDF41C17000\werkernel.sys | text | 103896 | 0E5937808C7F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\wfplwfs.sys\8C1645E13b000\wfplwfs.sys | text | 247272 | CD17B1A4D71C | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\win32k.sys\1058DE7Bc7000\win32k.sys | text | 812496 | BB6A6B989455 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\winaccel.sys\FF85D40115000\winaccel.sys | text | 95536 | 0534B9038F46 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WindowsTrustedRT.sys\7847E5AF18000\WindowsTrustedRT.sys | text | 109000 | F09A1537E4ED | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WindowsTrustedRTProxy.sys\7DDA7461c000\WindowsTrustedRTProxy.sys | text | 59800 | FA8336A782B6 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WMILIB.SYS\BF8195C9d000\WMILIB.SYS | text | 62792 | 24EF49436964 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\Wof.sys\4BE7C7E346000\Wof.sys | text | 288232 | CF54507B523F | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Build\Symbols\WppRecorder.sys\E3C6511C13000\WppRecorder.sys | text | 87528 | 6CEE95240506 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\App\AmgSharedApp.h | c-header | 1724 | 867284FBC20D | 75 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\App\Hypervisor.h | c-header | 10570 | 57826E012218 | 271 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\App\Main.cpp | cpp | 49659 | 2944EF0F09EA | 1092 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\App\NT.hpp | c-header | 7086 | 5E2DB74E13D3 | 178 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Mapper\Mapper.cpp | cpp | 34626 | 46A075CD014A | 733 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Mapper\Mapper.hpp | c-header | 5283 | B9FA08D3E167 | 96 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\PE\PE.cpp | cpp | 18456 | 110F7209C660 | 327 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\PE\PE.hpp | c-header | 5404 | 85839C21FDB5 | 108 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Provider\Driver.cpp | cpp | 149550 | 1187AB4C6485 | 3052 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Provider\Driver.hpp | c-header | 21185 | 6BC7A532A0C2 | 421 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Provider\Provider.hpp | c-header | 2524 | 7BCE6C108182 | 63 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Provider\Resource.hpp | c-header | 183401 | 81C8B65DA8FB | 763 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Service\Service.cpp | cpp | 8414 | E8156A35D11F | 168 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Service\Service.hpp | c-header | 1129 | 6702B8B965E6 | 29 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Symbols\Main.cpp | cpp | 16203 | 65F05A91DA8A | 340 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Symbols\Engine\SymbolEngine.cpp | cpp | 22549 | FE40B76E5316 | 529 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Symbols\Engine\SymbolEngine.hpp | c-header | 3671 | 163E5DE399F8 | 76 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Symbols\Handler\SymbolsHandler.cpp | cpp | 20770 | 23D1F2EC97F8 | 469 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Symbols\Handler\SymbolsHandler.hpp | c-header | 4057 | 520EA19A9162 | 86 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Template\Mapper.sln | visual-studio-sln | 1313 | F15C459D4B93 | 25 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Template\Mapper\Mapper.vcxproj | xml | 5549 | 970F4DDB19B2 | 110 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Template\Mapper\Mapper.vcxproj.filters | text | 2884 | 8F019D0C89E6 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Template\Symbols\SymbolTool.vcxproj | xml | 3547 | 7FD6E1C5BA2D | 68 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Template\Symbols\SymbolTool.vcxproj.filters | text | 1062 | 4A4B8B019A96 | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Utilities\Console.hpp | c-header | 12257 | 006031AA10FA | 305 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Utilities\Utilities.cpp | cpp | 7649 | E2EA921D0743 | 177 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Utilities\Utilities.hpp | c-header | 1595 | 3094B36DCF69 | 34 | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Utilities\DLLs\dbghelp.dll | text | 2254392 | 2ED18FDB0BFE | binary | Ameger runtime/injection library source or header |
| D:\Ameger\Mapper\Mapper\Utilities\DLLs\symsrv.dll | text | 423480 | FEA493309D3D | binary | Ameger runtime/injection library source or header |

FILES_TRACKED_REPO: 82
FILES_READ_REPO: 82
FILES_READ_FAILED_REPO: none
FILES_READ_MAPPER: 121
FILES_READ_FAILED_MAPPER: none
