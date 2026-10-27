# TASK-001 Risk Register

| ID | severity | file:line | description | evidence |
|---|---|---|---|---|
| R1 | P0 | D:\Ameger\Mapper\Mapper\Provider\Provider.hpp:42 | Provider driver memcpy IOCTL does not validate source/destination pointers, giving unchecked kernel read/write. | Provider.hpp:37-58; Driver.cpp:1336 |
| R2 | P1 | Ameger/Execution/ThreadHijacking.cpp:371 | Handle probe fallback loop can stop at `kMaxHandleProbes` and return a fallback that may be unstable or wrong. | ThreadHijacking.cpp:371-446 |
| R3 | P1 | Ameger/Injection/ManualMapping/ManualMapping.cpp:697 | Manual mapping intentionally leaks staging or image memory in some inverted-table paths; leakage is tracked but may leave forensic residue. | ManualMapping.cpp:697-947, :3333 |
| R4 | P1 | Ameger/NT/Windows11.h:104 | Fixed Windows 11 LDR offsets are fragile against future OS layout changes. | Windows11.h:104-113 |
| R5 | P1 | Interface/Source/Main.cpp:3430 | Missing `PayloadSha256` refuses load, but a mismatched payload pin is security-critical and depends on exact digest. | Main.cpp:2310, :3430 |
| R6 | P1 | Build/Executors/Create.bat:140 | Build verification order is load-bearing; reordering `BuildPE.ps1` before `:verify_mmap_sections` breaks the `.code` section check. | Create.bat:140-147 |
| R7 | P2 | Ameger/Core/Utility/Tools/Tools.cpp:241 | Scratch alphabet size invariant; changing it breaks scratch path layout. | Tools.cpp:241 |
| R8 | P2 | Build/Scripts/CreateSeeds.ps1 | Per-build seeds make builds nondeterministic unless seeds are recorded/reused. | Create.bat:118-124 |
| R9 | P2 | Ameger/Native/Syscall.cpp:572 | Syscall resolution scans ntdll exports; if ntdll is hooked or renamed, service numbers may be unresolved. | Syscall.cpp:572-610 |
| R10 | P2 | Interface/Source/Main.cpp:4314 | Target selection may choose a broker/incorrect same-named process unless operator target is screened. | Main.cpp:4314-4329; .analysis F4e |
