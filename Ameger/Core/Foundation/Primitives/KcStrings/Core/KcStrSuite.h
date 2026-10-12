#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "../KcNarrow.h"
#include "../KcWide.h"
#include "../KcStack.h"
#include "../KcLayered.h"

namespace kc_strings
{

inline constexpr unsigned KcTierCount = 5;

__forceinline constexpr unsigned KcTiersPassed(unsigned self_test_result) noexcept
{
	return self_test_result == 0 ? KcTierCount : self_test_result - 1;
}

inline unsigned KcStringsSelfTest() noexcept
{
	{
		auto probe = KC_STR("Kc");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != 0)
		{
			return 1;
		}
	}

	{
		auto probe = KC_WSTR(L"Kc");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != 0)
		{
			return 2;
		}
	}

	{

		char buf[3];
		const char ref[3] = { 'K', 'c', 0 };
		constexpr auto stack_key = KC_STACK_KEY_;
		KC_SC_3(buf, stack_key, 'K', 'c', '\0');
		if (std::memcmp(buf, ref, sizeof(buf)) != 0)
		{
			return 3;
		}
		volatile char * wipe = buf;
		for (std::size_t i = 0; i < sizeof(buf); ++i)
		{
			wipe[i] = 0;
		}
	}

	{
		auto probe = KC_STR_LAYERED("Kc9");
		const char * text = probe.c_str();
		if (text[0] != 'K' || text[1] != 'c' || text[2] != '9' || text[3] != 0)
		{
			return 4;
		}
	}

	{
		auto probe = KC_WSTR_LAYERED(L"Kc9");
		const wchar_t * text = probe.c_str();
		if (text[0] != L'K' || text[1] != L'c' || text[2] != L'9' || text[3] != 0)
		{
			return 5;
		}
	}

	return 0;
}
}
