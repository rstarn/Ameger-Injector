// PCH anchor TU for the launcher build. Includes only PCH.h so the compiler
// emits the precompiled header that Main.cpp consumes. No code lives here;
// the vcxproj marks this file PrecompiledHeader=Create.
#include "PCH.h"
