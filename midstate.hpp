#ifndef MIDSTATE_HPP
#define MIDSTATE_HPP

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <iostream>

class MidstateCalculator {
public:
    struct SHA256State {
        uint32_t h[8];
        
        std::string to_hex() const {
            std::stringstream ss;
            for (int i = 0; i < 8; ++i) {
                // Форматирование как Big Endian слов, типично для отладки midstate
                // Некоторое оборудование ожидает слова Little Endian. Мы будем придерживаться стандартного вывода BE для читаемости.
                ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
            }
            return ss.str();
        }
    };

    // Вычисление midstate для первых 64 байт заголовка блока
    static SHA256State calculate_midstate(const std::vector<unsigned char>& data_64_bytes) {
        if (data_64_bytes.size() != 64) {
             throw std::runtime_error("Для вычисления Midstate требуется ровно 64 байта");
        }

        // Начальные значения хэша SHA-256 (Первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        // Константы (Первые 32 бита дробных частей кубических корней первых 64 простых чисел)
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Подготовка информации
        // 1. Подготовка расписания сообщений (Message Schedule) W[0..63]
        uint32_t w[64];
        
        // Копирование первых 16 слов (64 байта) из данных
        // Данные обычно строго Big Endian в определении SHA256, 
        // но заголовки Bitcoin - это структуры полей Little Endian. 
        // Когда мы передаем 64-байтовый блок, мы ДОЛЖНЫ передавать его точно так, как он находится в памяти.
        // Алгоритм SHA256 обрабатывает входные данные как поток байтов.
        // Однако операция "block" читает 32-битные слова в BIG ENDIAN из потока байтов.
        
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t)data_64_bytes[i * 4] << 24 |
                   (uint32_t)data_64_bytes[i * 4 + 1] << 16 |
                   (uint32_t)data_64_bytes[i * 4 + 2] << 8 |
                   (uint32_t)data_64_bytes[i * 4 + 3];
        }

        // Расширение первых 16 слов в оставшиеся 48 слов w[16..63]
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Инициализация рабочих переменных текущим значением хэша
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_var = h[7];

        // Основной цикл функции сжатия
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h_var + s1 + ch + k[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;

            h_var = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Добавление сжатого фрагмента к текущему значению хэша
        SHA256State state;
        state.h[0] = h[0] + a;
        state.h[1] = h[1] + b;
        state.h[2] = h[2] + c;
        state.h[3] = h[3] + d;
        state.h[4] = h[4] + e;
        state.h[5] = h[5] + f;
        state.h[6] = h[6] + g;
        state.h[7] = h[7] + h_var;

        return state;
    }

private:
    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
};

#endif // MIDSTATE_HPP
