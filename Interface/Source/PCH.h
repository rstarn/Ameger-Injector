#pragma once

// Precompiled header for the launcher (Host) build.
// What: the stable system/CRT/STL headers every launcher translation unit
//   needs, compiled once instead of per TU. Why PCH: Main.cpp is a ~6000-line
//   TU whose dominant compile cost is re-parsing Windows.h and the STL, not
//   its own code. How: PCH.cpp includes this to generate the .pch; every other
//   launcher TU includes it FIRST. Only stable, third-party headers live here -
//   the repo-local headers (Injection.h, PEImage.h, ...) stay in Main.cpp so
//   editing them does not invalidate the PCH.
// x64 + Unicode only, matching the interface project settings.
#ifndef _WIN64
#error This build is x64-only.
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <conio.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <climits>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <memory>
#include <array>
