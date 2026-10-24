#pragma once

#include <cstddef>
#include <utility>

#include "DomainKey.h"

namespace xor_string
{

	constexpr unsigned kGolden = 0x9E3779B1u;

	constexpr unsigned kBaseKey = 0xA53A5A5Du ^ static_cast<unsigned>(::kc_strings::detail::kStringSeed);

	template <typename CharT, size_t N, unsigned Key>
	struct XorEncrypted
	{
		static_assert(N > 1, "Empty string");

		CharT Data[N]{};

		static constexpr CharT EncryptByte(CharT c, std::size_t idx) noexcept
		{
			const unsigned ks = Key + static_cast<unsigned>(idx) * kGolden;
			return static_cast<CharT>(c ^ static_cast<CharT>(ks));
		}

		template <size_t... Is>
		constexpr XorEncrypted(const CharT(&s)[N], std::index_sequence<Is...>) noexcept
			: Data{ EncryptByte(s[Is], Is)... }
		{
		}
	};

	template <typename CharT, size_t N, unsigned Key>
	class XorDecrypted
	{
		CharT Buf[N];

		XorDecrypted(const XorDecrypted &) = delete;
		XorDecrypted & operator=(const XorDecrypted &) = delete;

	public:
		__declspec(noinline) explicit XorDecrypted(const XorEncrypted<CharT, N, Key> & enc) noexcept
		{
			for (size_t i = 0; i < N; ++i)
			{
				const unsigned ks = Key + static_cast<unsigned>(i) * kGolden;
				Buf[i] = static_cast<CharT>(enc.Data[i] ^ static_cast<CharT>(ks));
			}
		}

		~XorDecrypted() noexcept
		{
			volatile CharT * p = Buf;
			for (size_t i = 0; i < N; ++i)
			{
				p[i] = static_cast<CharT>(0);
			}
		}

		__forceinline const CharT * get() const noexcept
		{
			return Buf;
		}
	};
}

#define XOR_STR_A_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<char, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_A(s) XOR_STR_A_IMPL(s, __COUNTER__)

#define XOR_STR_W_IMPL(s, c)                                                                                          \
	::xor_string::XorDecrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))>( \
		[]() -> const ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> & { \
			static constexpr ::xor_string::XorEncrypted<wchar_t, (sizeof(s) / sizeof((s)[0])), (::xor_string::kBaseKey ^ (static_cast<unsigned>(c) * ::xor_string::kGolden))> kc_enc( \
				s, std::make_index_sequence<(sizeof(s) / sizeof((s)[0]))> {});                                              \
			return kc_enc;                                                                                             \
		}())
#define XOR_STR_W(s) XOR_STR_W_IMPL(s, __COUNTER__)
