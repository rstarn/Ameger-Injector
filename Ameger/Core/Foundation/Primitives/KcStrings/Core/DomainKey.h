#pragma once

#include <cstddef>
#include <cstdint>
#include <intrin.h>

namespace kc_strings
{
namespace detail
{

#ifndef AMEGER_STRING_SEED
#define AMEGER_STRING_SEED (__LINE__ * 0x5A827999u + 0x6ED9EBA1u)
#endif
inline constexpr std::uint32_t kStringSeed = static_cast<std::uint32_t>(AMEGER_STRING_SEED);

template <typename CharT, std::size_t N>
__forceinline void Wipe(CharT * p) noexcept
{
    volatile CharT * v = p;
    for (std::size_t i = 0; i < N; ++i)
    {
        v[i] = static_cast<CharT>(0);
    }
}
}
}
