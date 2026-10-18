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

__forceinline std::uint8_t DomainByte(std::uint32_t key, std::size_t idx) noexcept
{

    return static_cast<std::uint8_t>((key >> ((idx % 4) * 8)) ^ (idx * 0xC2B2AE35u));
}

class DomainMask
{
    volatile std::uint32_t m_key;

    __forceinline std::uint32_t Compute() noexcept
    {

        const std::uint64_t ticks = __rdtsc();

        std::uint32_t k = static_cast<std::uint32_t>(ticks ^ (ticks >> 32));
        k ^= static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&ticks));
        k *= 0x85EBCA6Bu;
        k ^= k >> 13;
        return k;
    }

public:
    __forceinline DomainMask() noexcept : m_key(Compute()) {}

    __forceinline std::uint8_t Byte(std::size_t idx) const noexcept
    {
        return DomainByte(m_key, idx);
    }
};

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
