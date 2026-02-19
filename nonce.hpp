#ifndef NONCE_HPP
#define NONCE_HPP

#include <array>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ============================================================================
// NonceCalculator
// ----------------------------------------------------------------------------
// В этом классе собраны утилиты, которые нужны именно для проверки PoW:
// 1) Расчёт двойного SHA-256 (SHA256d) от 80-байтного заголовка.
// 2) Преобразование compact-формата nBits (как в Bitcoin header) в 256-битный target.
// 3) Преобразование фиксированной сложности (difficulty) в 256-битный target.
// 4) Байт-ориентированное сравнение hash <= target (строго по правилам Bitcoin).
// ============================================================================
class NonceCalculator {
public:
    // Константы SHA-256 (K[0..63]) согласно FIPS 180-4.
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // ------------------------------------------------------------------------
    // dsha256 (подробная версия)
    // ------------------------------------------------------------------------
    // По требованию: выполняем расчёт SHA256d максимально пошагово с логированием:
    // 1) SHA256(data)
    // 2) SHA256(hash1)
    // На каждом раунде каждого блока печатаются значения регистров a..h.
    // ------------------------------------------------------------------------
    static std::vector<unsigned char> dsha256(const std::vector<unsigned char>& data) {
        std::cout << "\n================ SHA256d: НАЧАЛО ================\n";
        std::cout << "[SHA256d] Входные данные (" << data.size() << " байт): " << bytes_to_hex(data) << "\n";

        std::vector<unsigned char> hash1 = sha256_verbose(data, "SHA256#1");
        std::vector<unsigned char> hash2 = sha256_verbose(hash1, "SHA256#2");

        std::cout << "[SHA256d] Итоговый hash2 (BE): " << bytes_to_hex(hash2) << "\n";
        std::cout << "================ SHA256d: КОНЕЦ =================\n\n";
        return hash2;
    }

    static std::array<unsigned char, 32> target_from_compact(const std::string& nbits_hex) {
        if (nbits_hex.size() != 8) {
            throw std::runtime_error("nbits must be exactly 4 bytes (8 hex chars)");
        }

        uint32_t compact = static_cast<uint32_t>(std::stoul(nbits_hex, nullptr, 16));
        uint32_t exponent = compact >> 24;
        uint32_t mantissa = compact & 0x007fffff;

        if (compact & 0x00800000) {
            throw std::runtime_error("Negative compact target is invalid");
        }

        using boost::multiprecision::cpp_int;
        cpp_int target = mantissa;

        if (exponent > 3) {
            target <<= (8 * (exponent - 3));
        } else {
            target >>= (8 * (3 - exponent));
        }

        return cpp_int_to_32bytes_be(target);
    }

    static std::array<unsigned char, 32> target_from_difficulty(double difficulty) {
        if (difficulty <= 0.0) {
            throw std::runtime_error("Difficulty must be positive");
        }

        using boost::multiprecision::cpp_dec_float_100;
        using boost::multiprecision::cpp_int;

        const cpp_int diff1_target = (cpp_int(0x00ffff) << (8 * (0x1d - 3)));

        cpp_dec_float_100 diff = cpp_dec_float_100(difficulty);
        cpp_dec_float_100 scaled = cpp_dec_float_100(diff1_target) / diff;
        cpp_int target = static_cast<cpp_int>(scaled);

        return cpp_int_to_32bytes_be(target);
    }

    static bool hash_meets_target(const std::vector<unsigned char>& hash_be,
                                  const std::array<unsigned char, 32>& target_be) {
        if (hash_be.size() != 32) {
            throw std::runtime_error("Hash must be 32 bytes");
        }

        for (size_t i = 0; i < 32; ++i) {
            if (hash_be[i] < target_be[i]) return true;
            if (hash_be[i] > target_be[i]) return false;
        }
        return true;
    }

    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
        std::stringstream ss;
        for (unsigned char b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }

    static std::string bytes_to_hex(const std::array<unsigned char, 32>& bytes) {
        std::stringstream ss;
        for (unsigned char b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }

private:
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t big_sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t big_sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t small_sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t small_sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    static std::vector<unsigned char> sha256_verbose(const std::vector<unsigned char>& data,
                                                     const std::string& stage_name) {
        std::cout << "[" << stage_name << "] Вход (" << data.size() << " байт): " << bytes_to_hex(data) << "\n";

        std::vector<unsigned char> padded = data;
        const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;

        padded.push_back(0x80);
        while ((padded.size() % 64) != 56) {
            padded.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            padded.push_back(static_cast<unsigned char>((bit_len >> (i * 8)) & 0xff));
        }

        std::cout << "[" << stage_name << "] После паддинга (" << padded.size() << " байт): "
                  << bytes_to_hex(padded) << "\n";

        uint32_t h0 = 0x6a09e667;
        uint32_t h1 = 0xbb67ae85;
        uint32_t h2 = 0x3c6ef372;
        uint32_t h3 = 0xa54ff53a;
        uint32_t h4 = 0x510e527f;
        uint32_t h5 = 0x9b05688c;
        uint32_t h6 = 0x1f83d9ab;
        uint32_t h7 = 0x5be0cd19;

        for (size_t block_index = 0; block_index < padded.size() / 64; ++block_index) {
            uint32_t w[64] = {0};
            const size_t offset = block_index * 64;

            std::vector<unsigned char> block_bytes(padded.begin() + offset, padded.begin() + offset + 64);
            std::cout << "[" << stage_name << "] Блок #" << block_index << " (64 байта): "
                      << bytes_to_hex(block_bytes) << "\n";

            for (int i = 0; i < 16; ++i) {
                w[i] = (static_cast<uint32_t>(padded[offset + i * 4]) << 24) |
                       (static_cast<uint32_t>(padded[offset + i * 4 + 1]) << 16) |
                       (static_cast<uint32_t>(padded[offset + i * 4 + 2]) << 8) |
                       static_cast<uint32_t>(padded[offset + i * 4 + 3]);
            }

            for (int i = 16; i < 64; ++i) {
                w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
            }

            std::cout << "[" << stage_name << "] W[0..63]:\n";
            for (int i = 0; i < 64; ++i) {
                std::cout << "  W[" << std::setw(2) << std::setfill('0') << i << "]="
                          << std::hex << std::setw(8) << std::setfill('0') << w[i] << std::dec;
                if ((i + 1) % 4 == 0)
                    std::cout << "\n";
                else
                    std::cout << "  ";
            }

            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;

            std::cout << "[" << stage_name << "] Старт регистров блока #" << block_index << ": "
                      << regs_to_string(a, b, c, d, e, f, g, h) << "\n";

            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
                uint32_t t2 = big_sigma0(a) + maj(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;

                std::cout << "[" << stage_name << "] Блок #" << block_index << ", раунд "
                          << std::setw(2) << std::setfill('0') << i
                          << " | T1=" << std::hex << std::setw(8) << std::setfill('0') << t1
                          << " T2=" << std::setw(8) << t2 << std::dec
                          << " | " << regs_to_string(a, b, c, d, e, f, g, h) << "\n";
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;

            std::cout << "[" << stage_name << "] После блока #" << block_index << ": "
                      << regs_to_string(h0, h1, h2, h3, h4, h5, h6, h7) << "\n";
        }

        std::vector<unsigned char> digest(32);
        write_u32_be(digest, 0, h0);
        write_u32_be(digest, 4, h1);
        write_u32_be(digest, 8, h2);
        write_u32_be(digest, 12, h3);
        write_u32_be(digest, 16, h4);
        write_u32_be(digest, 20, h5);
        write_u32_be(digest, 24, h6);
        write_u32_be(digest, 28, h7);

        std::cout << "[" << stage_name << "] Итоговый digest (BE): " << bytes_to_hex(digest) << "\n";
        return digest;
    }

    static void write_u32_be(std::vector<unsigned char>& out, size_t offset, uint32_t v) {
        out[offset] = static_cast<unsigned char>((v >> 24) & 0xff);
        out[offset + 1] = static_cast<unsigned char>((v >> 16) & 0xff);
        out[offset + 2] = static_cast<unsigned char>((v >> 8) & 0xff);
        out[offset + 3] = static_cast<unsigned char>(v & 0xff);
    }

    static std::string regs_to_string(uint32_t a,
                                      uint32_t b,
                                      uint32_t c,
                                      uint32_t d,
                                      uint32_t e,
                                      uint32_t f,
                                      uint32_t g,
                                      uint32_t h) {
        std::ostringstream ss;
        ss << "a=" << to_hex32(a) << " b=" << to_hex32(b) << " c=" << to_hex32(c) << " d=" << to_hex32(d)
           << " e=" << to_hex32(e) << " f=" << to_hex32(f) << " g=" << to_hex32(g) << " h=" << to_hex32(h);
        return ss.str();
    }

    static std::string to_hex32(uint32_t v) {
        std::ostringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << v;
        return ss.str();
    }

    static std::array<unsigned char, 32> cpp_int_to_32bytes_be(boost::multiprecision::cpp_int value) {
        if (value < 0) {
            throw std::runtime_error("Target cannot be negative");
        }
        return ss.str();
    }

        std::array<unsigned char, 32> out{};
        for (int i = 31; i >= 0 && value > 0; --i) {
            out[i] = static_cast<unsigned char>(value & 0xff);
            value >>= 8;
        }
        return out;
    }
};

#endif // NONCE_HPP
