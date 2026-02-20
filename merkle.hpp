#ifndef MERKLE_HPP
#define MERKLE_HPP

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/sha.h>

class MerkleCalculator {
public:
    // ---------------------------------------------------------------------------------
    // hex_to_bytes
    // ---------------------------------------------------------------------------------
    // Очень подробно валидируем входную hex-строку, потому что ошибка на этом этапе
    // приводит к полностью неверному корню Меркла, и дальше диагностика становится сложной.
    // ---------------------------------------------------------------------------------
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
        if (hex.size() % 2 != 0) {
            throw std::runtime_error("HEX-строка должна содержать чётное количество символов");
        }

        for (char ch : hex) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) {
                throw std::runtime_error("HEX-строка содержит недопустимые символы");
            }
        }

        std::vector<unsigned char> bytes;
        bytes.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.length(); i += 2) {
            const std::string byte_string = hex.substr(i, 2);
            const unsigned long value = std::strtoul(byte_string.c_str(), nullptr, 16);
            bytes.push_back(static_cast<unsigned char>(value));
        }

        return bytes;
    }

    // Преобразование массива байтов в hex-строку для логирования и отладки.
    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
        std::stringstream ss;
        for (unsigned char b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }

    // Выполнение Double SHA256 (SHA256(SHA256(data))).
    // Здесь используется OpenSSL: это компактно и надёжно.
    static std::vector<unsigned char> dsha256(const std::vector<unsigned char>& data) {
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];

        SHA256(data.data(), data.size(), hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        return std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
    }

    // Вычисление корня Меркла для Stratum mining.notify.
    //
    // ВАЖНО ПО ENDIAN:
    // 1) Stratum поля передаются в hex-представлении.
    // 2) Для вычисления hash через SHA256 важен байтовый поток, а не "числовое" значение.
    // 3) Поэтому мы НЕ меняем порядок байтов внутри веток arbitrarily: берём байты ровно так,
    //    как они даны в hex, и конкатенируем current_hash || branch_hash.
    // 4) Результат возвращается в том же внутреннем порядке байтов (internal order), пригодном
    //    для сборки заголовка блока (как это уже делает main.cpp).
    static std::string calculate_root(const std::string& coinb1,
                                      const std::string& extranonce1,
                                      const std::string& extranonce2,
                                      const std::string& coinb2,
                                      const std::vector<std::string>& merkle_branch) {
        std::cout << "\n[MERKLE] ===== НАЧАЛО РАСЧЁТА КОРНЯ МЕРКЛА =====\n";

        // 1) Формируем coinbase-транзакцию из частей, как определено в Stratum.
        const std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
        std::cout << "[MERKLE] coinb1: " << coinb1 << "\n";
        std::cout << "[MERKLE] extranonce1: " << extranonce1 << "\n";
        std::cout << "[MERKLE] extranonce2: " << extranonce2 << "\n";
        std::cout << "[MERKLE] coinb2: " << coinb2 << "\n";
        std::cout << "[MERKLE] Полный coinbase hex: " << coinbase_hex << "\n";

        const std::vector<unsigned char> coinbase_bytes = hex_to_bytes(coinbase_hex);
        std::cout << "[MERKLE] Coinbase длина: " << coinbase_bytes.size() << " байт\n";

        // 2) Первый лист дерева: double SHA256(coinbase).
        std::vector<unsigned char> current_hash = dsha256(coinbase_bytes);
        std::cout << "[MERKLE] Шаг 0: hash(coinbase) = " << bytes_to_hex(current_hash) << "\n";

        // 3) Последовательно "поднимаемся" по ветке merkle_branch.
        for (size_t i = 0; i < merkle_branch.size(); ++i) {
            const std::string& branch_hex = merkle_branch[i];
            const std::vector<unsigned char> branch_hash = hex_to_bytes(branch_hex);

            if (branch_hash.size() != SHA256_DIGEST_LENGTH) {
                throw std::runtime_error("Элемент merkle_branch должен быть ровно 32 байта");
            }

            // В Stratum обычно текущий хеш (coinbase-path) является левым узлом.
            // Поэтому concat = current_hash || branch_hash.
            std::vector<unsigned char> combined;
            combined.reserve(current_hash.size() + branch_hash.size());
            combined.insert(combined.end(), current_hash.begin(), current_hash.end());
            combined.insert(combined.end(), branch_hash.begin(), branch_hash.end());

            std::cout << "[MERKLE] Шаг " << (i + 1) << ": branch = " << branch_hex << "\n";
            std::cout << "[MERKLE] Шаг " << (i + 1) << ": concat(current||branch) = "
                      << bytes_to_hex(combined) << "\n";

            current_hash = dsha256(combined);
            std::cout << "[MERKLE] Шаг " << (i + 1) << ": новый current_hash = "
                      << bytes_to_hex(current_hash) << "\n";
        }

        const std::string merkle_root = bytes_to_hex(current_hash);
        std::cout << "[MERKLE] Итоговый merkle root (internal byte order): " << merkle_root << "\n";
        std::cout << "[MERKLE] ===== КОНЕЦ РАСЧЁТА КОРНЯ МЕРКЛА =====\n\n";

        return merkle_root;
    }

    // Генерация значения extranonce2 из нулей (размер в байтах).
    static std::string generate_default_extranonce2(int size) {
        if (size < 0) {
            throw std::runtime_error("Размер extranonce2 не может быть отрицательным");
        }

        std::stringstream ss;
        for (int i = 0; i < size; ++i) {
            ss << "00";
        }
        return ss.str();
    }
};

#endif // MERKLE_HPP
