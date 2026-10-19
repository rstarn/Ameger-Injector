#pragma once

#include <cstddef>
#include <cstdint>

#include "Core/DomainKey.h"

namespace kc_strings
{

template <typename CharT, CharT C, std::uint32_t Key, std::size_t Idx>
struct KcObfuscatedChar
{
	static constexpr CharT KeyByte() noexcept
	{
		return static_cast<CharT>((Key >> ((Idx % 4) * 8)) ^ (Idx * 0x27D4EB2Du));
	}

	static constexpr CharT Encrypted = static_cast<CharT>(C ^ KeyByte());

	__forceinline static CharT Decode() noexcept
	{
		volatile CharT enc = Encrypted;
		return static_cast<CharT>(static_cast<int>(enc) ^ static_cast<int>(KeyByte()));
	}
};
}

#define KC_STACK_KEY_ (static_cast<std::uint32_t>((__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u ^ 0xDEADBEEFu ^ ::kc_strings::detail::kStringSeed))

namespace kc_strings
{

template <std::size_t Idx, typename CharT, std::size_t N>
__forceinline void KcStore(CharT (&buf)[N], CharT value) noexcept
{
	static_assert(N > 0, "KcStack destination buffer must not be empty");
	static_assert(Idx < N, "KcStack index exceeds the destination buffer");

	buf[Idx] = value;
}
}

#define KC_SC_(name, key, idx, c) ::kc_strings::KcStore<idx>(name, ::kc_strings::KcObfuscatedChar<char, c, key, idx>::Decode())

#define KC_SC_1(n, k, c0) KC_SC_(n,k,0,c0)
#define KC_SC_2(n, k, c0, c1) KC_SC_1(n,k,c0); KC_SC_(n,k,1,c1)
#define KC_SC_3(n, k, c0, c1, c2) KC_SC_2(n,k,c0,c1); KC_SC_(n,k,2,c2)
