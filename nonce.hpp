#ifndef NONCE_HPP
#define NONCE_HPP

#include <array>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <iomanip>
#include <openssl/sha.h>
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
    // ------------------------------------------------------------------------
    // dsha256
    // ------------------------------------------------------------------------
    // Выполняет стандартный Bitcoin-хэш: SHA256(SHA256(data)).
    // На входе: произвольный набор байтов (для блока это обычно 80 байт заголовка).
    // На выходе: 32 байта хэша в «сырых» байтах (big-endian представление числа).
    // ------------------------------------------------------------------------
    static std::vector<unsigned char> dsha256(const std::vector<unsigned char>& data) {
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];

        SHA256(data.data(), data.size(), hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        return std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
    }

    // ------------------------------------------------------------------------
    // target_from_compact
    // ------------------------------------------------------------------------
    // Преобразует compact nBits из заголовка блока в полный 256-битный target.
    // Формат nBits:
    //   - старший байт: exponent
    //   - младшие 3 байта: mantissa
    // Формула (Bitcoin): target = mantissa * 2^(8*(exponent-3)).
    // ------------------------------------------------------------------------
    static std::array<unsigned char, 32> target_from_compact(const std::string& nbits_hex) {
        if (nbits_hex.size() != 8) {
            throw std::runtime_error("nbits must be exactly 4 bytes (8 hex chars)");
        }

        uint32_t compact = static_cast<uint32_t>(std::stoul(nbits_hex, nullptr, 16));
        uint32_t exponent = compact >> 24;
        uint32_t mantissa = compact & 0x007fffff;

        // В Bitcoin знак у target быть не может. Если sign-бит выставлен — значение невалидно.
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

    // ------------------------------------------------------------------------
    // target_from_difficulty
    // ------------------------------------------------------------------------
    // Преобразует фиксированную difficulty в target по классическому соотношению:
    //   target = diff1_target / difficulty
    // где diff1_target соответствует 0x1d00ffff (Bitcoin difficulty-1 baseline).
    // ------------------------------------------------------------------------
    static std::array<unsigned char, 32> target_from_difficulty(double difficulty) {
        if (difficulty <= 0.0) {
            throw std::runtime_error("Difficulty must be positive");
        }

        using boost::multiprecision::cpp_dec_float_100;
        using boost::multiprecision::cpp_int;

        const cpp_int diff1_target = (cpp_int(0x00ffff) << (8 * (0x1d - 3)));

        cpp_dec_float_100 diff = cpp_dec_float_100(difficulty);
        cpp_dec_float_100 scaled = cpp_dec_float_100(diff1_target) / diff;

        // Усечение в меньшую сторону безопасно для target (не делает его «легче», чем положено).
        cpp_int target = static_cast<cpp_int>(scaled);
        return cpp_int_to_32bytes_be(target);
    }

    // ------------------------------------------------------------------------
    // hash_meets_target
    // ------------------------------------------------------------------------
    // Сравнение выполняется как сравнение 256-битных целых чисел в big-endian:
    // hash валиден тогда и только тогда, когда hash <= target.
    // ------------------------------------------------------------------------
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

    // Утилиты форматирования в hex для максимально подробного логирования.
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
    static std::array<unsigned char, 32> cpp_int_to_32bytes_be(boost::multiprecision::cpp_int value) {
        if (value < 0) {
            throw std::runtime_error("Target cannot be negative");
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
