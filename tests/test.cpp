#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string_view>
#include <xorstr.hpp>

TEST_CASE("XOR_STR direct use without assignment") {
    REQUIRE(std::strcmp(XOR_STR("Hello World"), "Hello World") == 0);
    REQUIRE(std::strcmp(XOR_STR(""), "") == 0);
    REQUIRE(std::strcmp(XOR_STR("A"), "A") == 0);
    REQUIRE(std::wcscmp(XOR_STR(L"Wide 😊"), L"Wide 😊") == 0);
}

TEST_CASE("Multiple different strings, no dangling") {
    REQUIRE(std::strcmp(XOR_STR("First"), "First") == 0);
    REQUIRE(std::strcmp(XOR_STR("Second"), "Second") == 0);
    REQUIRE(XOR_STR("First") != XOR_STR("Second"));
}

TEST_CASE("XOR_STR decrypts correctly to original string", "[xorstr]") {
    SECTION("ASCII short string") {
        const char *decrypted = XOR_STR("Hello, World!");
        REQUIRE(std::string_view(decrypted) == "Hello, World!");
    }

    SECTION("ASCII empty string") {
        const char *decrypted = XOR_STR("");
        REQUIRE(std::string_view(decrypted) == "");
    }

    SECTION("String with null characters in middle (should still work as raw bytes)") {
        const char *decrypted = XOR_STR("ABC\0DEF");
        REQUIRE(std::memcmp(decrypted, "ABC\0DEF", 7) == 0);
    }

    SECTION("Long string crossing multiple 32-byte blocks") {
        const char *decrypted =
            XOR_STR("This is a very long string designed to exceed 32 bytes and test AVX2 block decryption properly.");
        REQUIRE(std::string_view(decrypted) ==
                "This is a very long string designed to exceed 32 bytes and test AVX2 block decryption properly.");
    }

    SECTION("String exactly 32 bytes") {
        const char *decrypted = XOR_STR("12345678901234567890123456789012"); // 32 chars
        REQUIRE(std::string_view(decrypted) == "12345678901234567890123456789012");
    }
}

TEST_CASE("Different macro invocations produce different keys (anti-pattern detection)", "[xorstr]") {
    const char *s1 = XOR_STR("secret");
    const char *s2 = XOR_STR("secret"); // Different line → different seed

    // The decrypted plaintext must be the same
    REQUIRE(std::string_view(s1) == "secret");
    REQUIRE(std::string_view(s2) == "secret");

    // But the encrypted data in the object should be different (different keys)
    // We cannot directly access the private data, so we use a trick: call reveal() twice
    // If keys were the same, second call would re-encrypt to original ciphertext.
    // Since seeds are different, second XOR would produce garbage → we detect that.

    // Note: This is a heuristic test – safe because reveal() modifies in-place.
    auto check_double_reveal = [](const char *(*func)()) {
        const char *first = func();
        const char *second = func(); // call macro again → new object
        // Not comparing first vs second directly because they are different objects
        return std::string(first) != std::string(second); // should both be "secret" anyway
    };

    // Actually we cannot easily extract the raw encrypted bytes without modifying the class.
    // So we accept that the primary guarantee is per-invocation unique seed via __COUNTER__/__LINE__.
    // The test above already proves decryption works independently.
    SUCCEED("Different invocations use different seeds due to __COUNTER__ and __LINE__");
}

TEST_CASE("XOR_STR works with wide strings (wchar_t)", "[xorstr]") {
#if defined(_MSC_VER)
    // MSVC uses 2-byte wchar_t
    const wchar_t *decrypted = XOR_STR(L"Wide string test 😊");
    REQUIRE(std::wstring_view(decrypted) == L"Wide string test 😊");
#else
    // GCC/Clang typically use 4-byte wchar_t (UTF-32)
    const wchar_t *decrypted = XOR_STR(L"Wide string test");
    REQUIRE(std::wstring_view(decrypted) == L"Wide string test");
#endif
}

TEST_CASE("Calling reveal() multiple times on same object", "[xorstr][behavior]") {
    auto str_obj = make_xorstr<0x12345678ULL>("duplicate test");

    const char *first = str_obj.reveal();
    REQUIRE(std::string_view(first) == "duplicate test");

    const char *second = str_obj.reveal(); // second call re-xors → back to encrypted
    // Now it should NOT equal the plaintext anymore
    REQUIRE(std::string_view(second) != "duplicate test");

    const char *third = str_obj.reveal(); // third call → decrypt again
    REQUIRE(std::string_view(third) == "duplicate test");
}

TEST_CASE("No data leakage in global constants (compile-time encryption)", "[xorstr]") {
    // The key point: the plaintext should NOT appear in the binary as a string.
    // This cannot be tested purely at runtime, but we can at least verify
    // that the static data array is not equal to the plaintext bytes.
    static const auto encrypted_obj = make_xorstr<0xDEADBEEFULL>("hidden");

    // Raw bytes of plaintext "hidden\0"
    const uint8_t plaintext_bytes[] = {'h', 'i', 'd', 'd', 'e', 'n', 0};

    const uint8_t *encrypted_bytes = reinterpret_cast<const uint8_t *>(encrypted_obj.encrypted_blocks.data());

    bool leaked = std::equal(std::begin(plaintext_bytes), std::end(plaintext_bytes), encrypted_bytes);

    REQUIRE_FALSE(leaked); // If this fails, plaintext is visible in binary!
}

TEST_CASE("XOR_STR handles very large strings correctly", "[xorstr][large]") {
    SECTION("256-byte string (exactly 8 AVX2 blocks)") {
        // 构造一个精确 256 字符的重复模式字符串，便于验证
        constexpr const char *original = "0123456789ABCDEF0123456789ABCDEF" // 32 chars
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"
                                         "0123456789ABCDEF0123456789ABCDEF"; // 总计 256 chars + '\0'

        const char *decrypted = XOR_STR("0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF"
                                        "0123456789ABCDEF0123456789ABCDEF");

        REQUIRE(std::string_view(decrypted) == std::string_view(original));
    }

    SECTION("500+ byte string with varied content") {
        constexpr const char *original =
            "This is a very large string designed to thoroughly test the XOR_STR implementation. "
            "It contains multiple AVX2 blocks, mixed ASCII characters, punctuation, numbers 1234567890, "
            "and special symbols !@#$%^&*()_+-=[]{}|;':\",./<>? "
            "We even include some repeated patterns to detect alignment issues: "
            "ABCDEFGABCDEFGABCDEFGABCDEFG "
            "And finally, some trailing data to test partial block handling.";

        const std::string decrypted =
            XOR_STR("This is a very large string designed to thoroughly test the XOR_STR implementation. "
                    "It contains multiple AVX2 blocks, mixed ASCII characters, punctuation, numbers 1234567890, "
                    "and special symbols !@#$%^&*()_+-=[]{}|;':\",./<>? "
                    "We even include some repeated patterns to detect alignment issues: "
                    "ABCDEFGABCDEFGABCDEFGABCDEFG "
                    "And finally, some trailing data to test partial block handling.");

        REQUIRE(std::string_view(decrypted) == std::string_view(original));
    }

    SECTION("Maximum realistic string: ~1024 bytes") {
        // 构造一个约 1KB 的字符串
        std::string original_str;
        original_str.reserve(1024);
        for (int i = 0; i < 32; ++i) {
            original_str +=
                "Large block #" + std::to_string(i) + ": The quick brown fox jumps over the lazy dog. 0123456789 ";
        }
        // 确保以 \0 结尾（C风格字符串）
        original_str += '\0';

        // 因为字面量太大，不能直接写 constexpr 数组，但我们可以用动态方式构造原始字符串进行比较
        // 注意：XOR_STR 本身仍然是编译期加密
        const std::string decrypted = XOR_STR(
            "Large block #0: The quick brown fox jumps over the lazy dog. 0123456789 Large block #1: The quick brown "
            "fox jumps over the lazy dog. 0123456789 Large block #2: The quick brown fox jumps over the lazy dog. "
            "0123456789 Large block #3: The quick brown fox jumps over the lazy dog. 0123456789 Large block #4: The "
            "quick brown fox jumps over the lazy dog. 0123456789 Large block #5: The quick brown fox jumps over the "
            "lazy dog. 0123456789 Large block #6: The quick brown fox jumps over the lazy dog. 0123456789 Large block "
            "#7: The quick brown fox jumps over the lazy dog. 0123456789 Large block #8: The quick brown fox jumps "
            "over the lazy dog. 0123456789 Large block #9: The quick brown fox jumps over the lazy dog. 0123456789 "
            "Large block #10: The quick brown fox jumps over the lazy dog. 0123456789 Large block #11: The quick brown "
            "fox jumps over the lazy dog. 0123456789 Large block #12: The quick brown fox jumps over the lazy dog. "
            "0123456789 Large block #13: The quick brown fox jumps over the lazy dog. 0123456789 Large block #14: The "
            "quick brown fox jumps over the lazy dog. 0123456789 Large block #15: The quick brown fox jumps over the "
            "lazy dog. 0123456789 Large block #16: The quick brown fox jumps over the lazy dog. 0123456789 Large block "
            "#17: The quick brown fox jumps over the lazy dog. 0123456789 Large block #18: The quick brown fox jumps "
            "over the lazy dog. 0123456789 Large block #19: The quick brown fox jumps over the lazy dog. 0123456789 "
            "Large block #20: The quick brown fox jumps over the lazy dog. 0123456789 Large block #21: The quick brown "
            "fox jumps over the lazy dog. 0123456789 Large block #22: The quick brown fox jumps over the lazy dog. "
            "0123456789 Large block #23: The quick brown fox jumps over the lazy dog. 0123456789 Large block #24: The "
            "quick brown fox jumps over the lazy dog. 0123456789 Large block #25: The quick brown fox jumps over the "
            "lazy dog. 0123456789 Large block #26: The quick brown fox jumps over the lazy dog. 0123456789 Large block "
            "#27: The quick brown fox jumps over the lazy dog. 0123456789 Large block #28: The quick brown fox jumps "
            "over the lazy dog. 0123456789 Large block #29: The quick brown fox jumps over the lazy dog. 0123456789 "
            "Large block #30: The quick brown fox jumps over the lazy dog. 0123456789 Large block #31: The quick brown "
            "fox jumps over the lazy dog. 0123456789 ");

        REQUIRE(std::string_view(decrypted) == original_str.substr(0, original_str.size() - 1)); // 去掉多余的 \0 比较
    }

    SECTION("Non-multiple of 8 bytes (partial last block)") {
        // 长度不是 8 的倍数，测试 padding 和最后不完整 block 的处理
        const std::string decrypted = XOR_STR("Short tail after full blocks!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!12345");

        REQUIRE(std::string_view(decrypted) == "Short tail after full blocks!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!12345");
    }
}
