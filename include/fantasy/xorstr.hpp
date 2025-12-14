#pragma once
#include <immintrin.h>
#include <cstddef>
#include <array>
#include <utility>
namespace fantasy {
    /**
     * @brief 编译期索引哈希函数 (Optimized for constexpr)
     * @param seed 初始的 64 位种子。
     * @param index 序列中的位置 (0, 1, 2, ...)。
     * @return uint64_t 对应索引的唯一密钥。
     */
    constexpr uint64_t indexed_key_gen(uint64_t seed, std::size_t index) {
        // 1. 将种子和索引混合
        uint64_t z = seed + index;

        // 2. 混合常量 (Magic Numbers from SplitMix64 or similar)
        // 确保 z 状态被充分打乱
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z = (z ^ (z >> 31));

        // 3. 进一步混合以引入更高的分散度
        // 引入另一个常量进行异或和乘法
        z ^= 0xAAAAAAAAAAAAAAAALL;
        z *= 0xC6FD031E56F1449DULL;

        return z;
    }

    [[nodiscard]] constexpr std::size_t align_up(std::size_t value, std::size_t alignment) noexcept {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    template <typename CharT, size_t N>
    constexpr uint64_t xor_block(const CharT (&str)[N], uint32_t block_index, uint64_t key) {
        constexpr size_t total_bytes = sizeof(CharT) * N;
        uint64_t value{0};
        size_t offset = block_index * sizeof(uint64_t) / sizeof(CharT);

        for (size_t i = 0; i < sizeof(uint64_t) / sizeof(CharT); i += 1) {
            size_t idx = offset + i;
            if (idx < total_bytes) {
                // i * sizeof(CharT)为了支持char和wchar
                value |= static_cast<uint64_t>(str[idx]) << (i * sizeof(CharT) * 8); // little-endian
            }
        }

        return value ^ key;
    }

    template <typename CharT, size_t N, uint64_t... Keys> struct xorstr {
        template <size_t... Is>
        constexpr xorstr(const CharT (&str)[N], std::index_sequence<Is...>)
            : encrypted_blocks{xor_block<CharT, N>(str, Is, Keys)...} {}

        [[nodiscard]] inline const CharT *reveal() {
            alignas(32) constexpr uint64_t key_blocks[align_up(sizeof(CharT) * N, 32) / sizeof(uint64_t)] = {
                Keys...,
            };
            std::size_t block = align_up(sizeof(CharT) * N, 32) / 32;
            for (size_t i = 0; i < block; i++) {
                const __m256i encrypted_data = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(
                    reinterpret_cast<const uint8_t *>(encrypted_blocks.data()) + i * 32));
                const __m256i key_mask = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i *>(reinterpret_cast<const uint8_t *>(key_blocks) + i * 32));
                const __m256i decrypted_data = _mm256_xor_si256(encrypted_data, key_mask);
                _mm256_storeu_si256(
                    reinterpret_cast<__m256i *>(reinterpret_cast<uint8_t *>(encrypted_blocks.data()) + i * 32),
                    decrypted_data);
            }
            return reinterpret_cast<const CharT *>(encrypted_blocks.data());
        }
        alignas(32) std::array<uint64_t, align_up(sizeof(CharT) * N, 32) / sizeof(uint64_t)> encrypted_blocks{0};
    };

    template <uint64_t Seed, typename CharT, size_t N> constexpr auto make_xorstr(const CharT (&str)[N]) {
        static constexpr uint64_t INITIAL_SEED = Seed;
        return [&]<std::size_t... Is>(std::index_sequence<Is...>) {
            return xorstr<CharT, N, indexed_key_gen(INITIAL_SEED, Is)...>(
                str, std::make_index_sequence<align_up(sizeof(CharT) * N, sizeof(uint64_t)) / sizeof(uint64_t)>());
        }(std::make_index_sequence<align_up(sizeof(CharT) * N, sizeof(uint64_t)) / sizeof(uint64_t)>{});
    }
} // namespace fantasy
// 高熵编译期种子，确保每个调用点不同
#define COMPILETIME_SEED (__COUNTER__ * __LINE__ * 0xCBF29CE484222325ULL + __TIME__[0] + __TIME__[4])

// 确保每次调用的初始种子都不一样
#define XOR_STR(s) fantasy::make_xorstr<COMPILETIME_SEED>(s).reveal()
