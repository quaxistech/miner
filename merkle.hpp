#ifndef MERKLE_HPP
#define MERKLE_HPP

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <algorithm>

class MerkleCalculator {
public:
    // Помощник: Преобразование hex-строки в вектор байтов
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Помощник: Преобразование вектора байтов в hex-строку
    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
        std::stringstream ss;
        for (unsigned char b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }

    // Выполнение Double SHA256 (SHA256(SHA256(data)))
    static std::vector<unsigned char> dsha256(const std::vector<unsigned char>& data) {
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];

        SHA256(data.data(), data.size(), hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        return std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
    }

    // Вычисление Корня Меркла (Merkle Root)
    // coinb1: Начальная часть coinbase-транзакции
    // extranonce1: Nonce, предоставленный сервером
    // extranonce2: Nonce, сгенерированный майнером
    // coinb2: Конечная часть coinbase-транзакции
    // merkle_branch: Список хэшей-партнеров от сервера
    static std::string calculate_root(const std::string& coinb1, 
                                    const std::string& extranonce1, 
                                    const std::string& extranonce2, 
                                    const std::string& coinb2, 
                                    const std::vector<std::string>& merkle_branch) {
        
        // 1. Создание Coinbase-транзакции
        // Coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
        std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
        std::vector<unsigned char> coinbase_bytes = hex_to_bytes(coinbase_hex);

        // 2. Хэширование Coinbase (Лист Меркла 0)
        std::vector<unsigned char> current_hash = dsha256(coinbase_bytes);

        // Отладочная информация
        // std::cout << "Coinbase Hex: " << coinbase_hex << std::endl;
        // std::cout << "Coinbase Hash: " << bytes_to_hex(current_hash) << std::endl;

        // 3. Итерация по ветке
        for (const auto& branch_hex : merkle_branch) {
            std::vector<unsigned char> branch_hash = hex_to_bytes(branch_hex);
            
            // Конкатенация: current_hash + branch_hash
            // Stratum V1 предполагает, что задание майнера всегда является левым листом в паре, 
            // потому что мы ищем блок для *этой* coinbase.
            // Примечание: Стандартное вычисление Меркла в Bitcoin включает обработку 80-байтовых заголовков в little-endian, 
            // но обычно хэши `merkle_branch` в Stratum передаются как 32-байтовые hex-строки. 
            // Являются ли они big или little endian, зависит от пула, но конкатенация обычно происходит побайтово.
            
            std::vector<unsigned char> combined;
            combined.insert(combined.end(), current_hash.begin(), current_hash.end());
            combined.insert(combined.end(), branch_hash.begin(), branch_hash.end());

            current_hash = dsha256(combined);
        }

        return bytes_to_hex(current_hash);
    }
    
    // Генерация дефолтного ExtraNonce2 (заполненного нулями) заданного размера
    static std::string generate_default_extranonce2(int size) {
        std::stringstream ss;
        for(int i=0; i<size; ++i) ss << "00";
        return ss.str();
    }
};

#endif // MERKLE_HPP
