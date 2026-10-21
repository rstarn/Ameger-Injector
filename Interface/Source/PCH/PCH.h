#pragma once

#ifndef _WIN64
#error This build is x64-only.
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <conio.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
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
