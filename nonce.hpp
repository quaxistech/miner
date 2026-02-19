#ifndef NONCE_HPP
#define NONCE_HPP

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include "midstate.hpp"

// Определение структуры для хранения 8 регистров состояния
struct StateRegs {
    uint32_t A, B, C, D, E, F, G, H;
    
    void print(const std::string& step_name) const {
        std::cout << "[Шаг: " << step_name << "] "
                  << "A:" << std::hex << std::setw(8) << std::setfill('0') << A << " "
                  << "B:" << std::hex << std::setw(8) << std::setfill('0') << B << " "
                  << "C:" << std::hex << std::setw(8) << std::setfill('0') << C << " "
                  << "D:" << std::hex << std::setw(8) << std::setfill('0') << D << " "
                  << "E:" << std::hex << std::setw(8) << std::setfill('0') << E << " "
                  << "F:" << std::hex << std::setw(8) << std::setfill('0') << F << " "
                  << "G:" << std::hex << std::setw(8) << std::setfill('0') << G << " "
                  << "H:" << std::hex << std::setw(8) << std::setfill('0') << H << std::dec << std::endl;
    }
};

class NonceCalculator {
public:
    // Константы (те же, что и в midstate)
    static constexpr uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    // Макро-подобная inline-функция для одного шага раунда
    static void step(int i, uint32_t w_i, StateRegs& s) {
        uint32_t s1 = rotr(s.E, 6) ^ rotr(s.E, 11) ^ rotr(s.E, 25);
        uint32_t ch = (s.E & s.F) ^ (~s.E & s.G);
        uint32_t temp1 = s.H + s1 + ch + k[i] + w_i;
        uint32_t s0 = rotr(s.A, 2) ^ rotr(s.A, 13) ^ rotr(s.A, 22);
        uint32_t maj = (s.A & s.B) ^ (s.A & s.C) ^ (s.B & s.C);
        uint32_t temp2 = s0 + maj;

        s.H = s.G;
        s.G = s.F;
        s.F = s.E;
        s.E = s.D + temp1;
        s.D = s.C;
        s.C = s.B;
        s.B = s.A;
        s.A = temp1 + temp2;
        
        s.print(std::to_string(i));
    }

    // Помощник для вычисления цели (target) из сложности
    static std::string calculate_target(double difficulty) {
        return "Цель для сложности " + std::to_string(difficulty); 
    }

    // Основная функция для проверки одного nonce
    static void check_nonce(const MidstateCalculator::SHA256State& midstate, 
                           const std::vector<unsigned char>& block_tail_12bytes,
                           double network_difficulty) {
        
        std::cout << "\n=== РУЧНАЯ ПРОВЕРКА NONCE (SHA-256 Пошагово) ===\n";
        
        if (block_tail_12bytes.size() != 12) {
             std::cout << "Ошибка: Хвост должен быть 12 байт (nTime, nBits, Nonce)\n";
             return;
        }

        // Подготовка расписания сообщений W[0..63] для Фрагмента 2
        // Фрагмент 2 требует последние 4 байта корня Меркла.
        // Я буду использовать обновленную check_nonce_step_by_step.
    }
    
    // Обновленная сигнатура для приема merkle tail
    static void check_nonce_step_by_step(
        const MidstateCalculator::SHA256State& midstate, 
        const std::vector<unsigned char>& merkle_tail_4bytes,
        const std::vector<unsigned char>& block_tail_12bytes, // nTime, nBits, Nonce
        double network_difficulty
    ) {
        if (merkle_tail_4bytes.size() != 4 || block_tail_12bytes.size() != 12) {
            std::cout << "Ошибка: Неверные размеры хвоста.\n";
            return;
        }

        // 1. Создание Фрагмента 2 (64 байта)
        unsigned char chunk2[64];
        std::memset(chunk2, 0, 64);
        
        // Копирование Merkle Tail [0..3]
        std::memcpy(chunk2, merkle_tail_4bytes.data(), 4);
        
        // Копирование Block Tail [4..15]
        std::memcpy(chunk2 + 4, block_tail_12bytes.data(), 12);
        
        // Заполнение (Padding)
        chunk2[16] = 0x80;
        
        // Длина (Big Endian) в конце. 80 байт = 640 бит.
        // 640 = 0x280.
        chunk2[62] = 0x02;
        chunk2[63] = 0x80;

        std::cout << "Фрагмент 2 (Hex): ";
        for(int i=0; i<64; ++i) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)chunk2[i];
        std::cout << std::dec << "\n\n";

        // 2. Подготовка W (Расписание сообщений)
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t)chunk2[i * 4] << 24 |
                   (uint32_t)chunk2[i * 4 + 1] << 16 |
                   (uint32_t)chunk2[i * 4 + 2] << 8 |
                   (uint32_t)chunk2[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // 3. Инициализация состояния из Midstate
        StateRegs s;
        s.A = midstate.h[0]; s.B = midstate.h[1]; s.C = midstate.h[2]; s.D = midstate.h[3];
        s.E = midstate.h[4]; s.F = midstate.h[5]; s.G = midstate.h[6]; s.H = midstate.h[7];
        
        std::cout << "Начальное состояние (Midstate):\n";
        s.print("Init");

        // 4. Выполнение 64 шагов
        step(0, w[0], s);
        step(1, w[1], s);
        step(2, w[2], s); step(3, w[3], s); step(4, w[4], s); step(5, w[5], s);
        step(6, w[6], s); step(7, w[7], s); step(8, w[8], s); step(9, w[9], s);
        step(10, w[10], s); step(11, w[11], s); step(12, w[12], s); step(13, w[13], s);
        step(14, w[14], s); step(15, w[15], s); step(16, w[16], s); step(17, w[17], s);
        step(18, w[18], s); step(19, w[19], s); step(20, w[20], s); step(21, w[21], s);
        step(22, w[22], s); step(23, w[23], s); step(24, w[24], s); step(25, w[25], s);
        step(26, w[26], s); step(27, w[27], s); step(28, w[28], s); step(29, w[29], s);
        step(30, w[30], s); step(31, w[31], s); step(32, w[32], s); step(33, w[33], s);
        step(34, w[34], s); step(35, w[35], s); step(36, w[36], s); step(37, w[37], s);
        step(38, w[38], s); step(39, w[39], s); step(40, w[40], s); step(41, w[41], s);
        step(42, w[42], s); step(43, w[43], s); step(44, w[44], s); step(45, w[45], s);
        step(46, w[46], s); step(47, w[47], s); step(48, w[48], s); step(49, w[49], s);
        step(50, w[50], s); step(51, w[51], s); step(52, w[52], s); step(53, w[53], s);
        step(54, w[54], s); step(55, w[55], s); step(56, w[56], s); step(57, w[57], s);
        step(58, w[58], s); step(59, w[59], s); step(60, w[60], s); step(61, w[61], s);
        step(62, w[62], s); step(63, w[63], s);

        // 5. Финализация состояния
        s.A += midstate.h[0]; s.B += midstate.h[1]; s.C += midstate.h[2]; s.D += midstate.h[3];
        s.E += midstate.h[4]; s.F += midstate.h[5]; s.G += midstate.h[6]; s.H += midstate.h[7];
        
        std::cout << "--- Конец первого прохода хэширования ---\n";
        std::cout << "Результат первого хэша (Big Endian): " 
                  << std::hex << std::setw(8) << std::setfill('0') << s.A
                  << std::setw(8) << s.B << std::setw(8) << s.C << std::setw(8) << s.D
                  << std::setw(8) << s.E << std::setw(8) << s.F << std::setw(8) << s.G << std::setw(8) << s.H << "\n\n";

        // ВТОРОЙ ПРОХОД (SHA256(Hash1))
        unsigned char final_chunk[64];
        std::memset(final_chunk, 0, 64);
        
        auto write_be = [&](uint32_t val, int off) {
            final_chunk[off] = (val >> 24) & 0xFF;
            final_chunk[off+1] = (val >> 16) & 0xFF;
            final_chunk[off+2] = (val >> 8) & 0xFF;
            final_chunk[off+3] = val & 0xFF;
        };
        
        write_be(s.A, 0); write_be(s.B, 4); write_be(s.C, 8); write_be(s.D, 12);
        write_be(s.E, 16); write_be(s.F, 20); write_be(s.G, 24); write_be(s.H, 28);
        
        final_chunk[32] = 0x80;
        final_chunk[62] = 0x01; final_chunk[63] = 0x00;

        StateRegs s2;
        s2.A = 0x6a09e667; s2.B = 0xbb67ae85; s2.C = 0x3c6ef372; s2.D = 0xa54ff53a;
        s2.E = 0x510e527f; s2.F = 0x9b05688c; s2.G = 0x1f83d9ab; s2.H = 0x5be0cd19;

        uint32_t w2[64];
        for (int i = 0; i < 16; ++i) {
            w2[i] = (uint32_t)final_chunk[i * 4] << 24 | (uint32_t)final_chunk[i * 4 + 1] << 16 | (uint32_t)final_chunk[i * 4 + 2] << 8 | (uint32_t)final_chunk[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w2[i - 15], 7) ^ rotr(w2[i - 15], 18) ^ (w2[i - 15] >> 3);
            uint32_t s1 = rotr(w2[i - 2], 17) ^ rotr(w2[i - 2], 19) ^ (w2[i - 2] >> 10);
            w2[i] = w2[i - 16] + s0 + w2[i - 7] + s1;
        }

        step(0, w2[0], s2); step(1, w2[1], s2);
        step(2, w2[2], s2); step(3, w2[3], s2); step(4, w2[4], s2); step(5, w2[5], s2);
        step(6, w2[6], s2); step(7, w2[7], s2); step(8, w2[8], s2); step(9, w2[9], s2);
        step(10, w2[10], s2); step(11, w2[11], s2); step(12, w2[12], s2); step(13, w2[13], s2);
        step(14, w2[14], s2); step(15, w2[15], s2); step(16, w2[16], s2); step(17, w2[17], s2);
        step(18, w2[18], s2); step(19, w2[19], s2); step(20, w2[20], s2); step(21, w2[21], s2);
        step(22, w2[22], s2); step(23, w2[23], s2); step(24, w2[24], s2); step(25, w2[25], s2);
        step(26, w2[26], s2); step(27, w2[27], s2); step(28, w2[28], s2); step(29, w2[29], s2);
        step(30, w2[30], s2); step(31, w2[31], s2); step(32, w2[32], s2); step(33, w2[33], s2);
        step(34, w2[34], s2); step(35, w2[35], s2); step(36, w2[36], s2); step(37, w2[37], s2);
        step(38, w2[38], s2); step(39, w2[39], s2); step(40, w2[40], s2); step(41, w2[41], s2);
        step(42, w2[42], s2); step(43, w2[43], s2); step(44, w2[44], s2); step(45, w2[45], s2);
        step(46, w2[46], s2); step(47, w2[47], s2); step(48, w2[48], s2); step(49, w2[49], s2);
        step(50, w2[50], s2); step(51, w2[51], s2); step(52, w2[52], s2); step(53, w2[53], s2);
        step(54, w2[54], s2); step(55, w2[55], s2); step(56, w2[56], s2); step(57, w2[57], s2);
        step(58, w2[58], s2); step(59, w2[59], s2); step(60, w2[60], s2); step(61, w2[61], s2);
        step(62, w2[62], s2); step(63, w2[63], s2);

        s2.A += 0x6a09e667; s2.B += 0xbb67ae85; s2.C += 0x3c6ef372; s2.D += 0xa54ff53a;
        s2.E += 0x510e527f; s2.F += 0x9b05688c; s2.G += 0x1f83d9ab; s2.H += 0x5be0cd19;

        std::cout << "\n=== ФИНАЛЬНЫЙ ХЭШ БЛОКА ===\n";
        
        std::vector<unsigned char> hash_bytes;
        auto push_be = [&](uint32_t v) {
            hash_bytes.push_back((v >> 24) & 0xFF); hash_bytes.push_back((v >> 16) & 0xFF);
            hash_bytes.push_back((v >> 8) & 0xFF); hash_bytes.push_back(v & 0xFF);
        };
        push_be(s2.A); push_be(s2.B); push_be(s2.C); push_be(s2.D);
        push_be(s2.E); push_be(s2.F); push_be(s2.G); push_be(s2.H);
        
        std::cout << "Raw SHA256d (Big Endian): ";
        for(auto b : hash_bytes) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "\n";
        
        std::vector<unsigned char> hash_le = hash_bytes;
        std::reverse(hash_le.begin(), hash_le.end());
        
        std::cout << "Block Hash (Little Endian): ";
        for(auto b : hash_le) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "\n";
        
        std::cout << "\nСравнение:\n";
        std::cout << "Значение: ";
        for(auto b : hash_le) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "\n";
        
        std::cout << "Цель (Приблиз.): " << std::dec << network_difficulty << " (очень большое число, цель маленькая)\n";
        
        bool success = (hash_le[0] == 0 && hash_le[1] == 0 && hash_le[2] == 0); 
        std::cout << "Результат: " << (success ? "НИЗКИЙ ХЭШ (Возможно валидный?)" : "ВЫСОКИЙ ХЭШ (Невалидный)") << "\n";
        std::cout << "==========================\n";
    }
};

#endif // NONCE_HPP
