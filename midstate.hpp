#ifndef MIDSTATE_HPP
#define MIDSTATE_HPP

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class MidstateCalculator {
public:
    struct SHA256State {
        uint32_t h[8];

        // Вывод состояния в формате 8 слов по 32 бита (Big Endian текстовое представление).
        std::string to_hex() const {
            std::stringstream ss;
            for (int i = 0; i < 8; ++i) {
                ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
            }
            return ss.str();
        }
    };

    // ---------------------------------------------------------------------------------
    // calculate_midstate
    // ---------------------------------------------------------------------------------
    // Midstate для Bitcoin-майнинга — это состояние SHA-256 после обработки ПЕРВЫХ 64 байт
    // 80-байтного заголовка блока. Это ровно один блок SHA-256 без финального padding.
    //
    // Ключевой момент по endian:
    // - Заголовок Bitcoin состоит из полей LE (version, prevhash, merkle root, time, bits, nonce).
    // - Но SHA-256 читает входной поток байтов по 32-битным словам как BIG ENDIAN.
    // - Значит, нам нужно просто подать байты в правильном порядке заголовка (как собраны в main),
    //   а внутри SHA-256 слова W[i] формируются как big-endian unpack из этих байтов.
    // ---------------------------------------------------------------------------------
    static SHA256State calculate_midstate(const std::vector<unsigned char>& data_64_bytes) {
        if (data_64_bytes.size() != 64) {
            throw std::runtime_error("Для вычисления Midstate требуется ровно 64 байта");
        }

        std::cout << "\n[MIDSTATE] ===== НАЧАЛО РАСЧЁТА MIDSTATE =====\n";
        std::cout << "[MIDSTATE] Входные 64 байта: " << bytes_to_hex(data_64_bytes) << "\n";

        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        static constexpr uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        uint32_t w[64]{};

        // W[0..15] читаем как big-endian слова из байтового потока.
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(data_64_bytes[i * 4]) << 24) |
                   (static_cast<uint32_t>(data_64_bytes[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(data_64_bytes[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(data_64_bytes[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::cout << "[MIDSTATE] Message schedule W[0..63]:\n";
        for (int i = 0; i < 64; ++i) {
            std::cout << "  W[" << std::setw(2) << std::setfill('0') << i << "]="
                      << std::hex << std::setw(8) << std::setfill('0') << w[i] << std::dec;
            if ((i + 1) % 4 == 0) {
                std::cout << "\n";
            } else {
                std::cout << "  ";
            }
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        std::cout << "[MIDSTATE] Начальные регистры: " << regs_to_string(a, b, c, d, e, f, g, h) << "\n";

        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;

            std::cout << "[MIDSTATE] Раунд " << std::setw(2) << std::setfill('0') << i
                      << " | T1=" << std::hex << std::setw(8) << std::setfill('0') << temp1
                      << " T2=" << std::setw(8) << temp2 << std::dec
                      << " | " << regs_to_string(a, b, c, d, e, f, g, h) << "\n";
        }


        std::cout << "[MIDSTATE] После раунда 63 (рабочие a..h до feed-forward): "
                  << regs_to_string(a, b, c, d, e, f, g, h) << "\n";
        std::cout << "[MIDSTATE] ВАЖНО: итог SHA-256 блока = (начальное state) + (рабочие a..h) по mod 2^32,\n"
                  << "           поэтому значения после раунда 63 обычно НЕ равны итоговому состоянию.\n";

        SHA256State out{};
        out.h[0] = state[0] + a;
        out.h[1] = state[1] + b;
        out.h[2] = state[2] + c;
        out.h[3] = state[3] + d;
        out.h[4] = state[4] + e;
        out.h[5] = state[5] + f;
        out.h[6] = state[6] + g;
        out.h[7] = state[7] + h;

        std::cout << "[MIDSTATE] Feed-forward по словам:\n";
        std::cout << "  H0=" << hex32(state[0]) << " + " << hex32(a) << " = " << hex32(out.h[0]) << "\n";
        std::cout << "  H1=" << hex32(state[1]) << " + " << hex32(b) << " = " << hex32(out.h[1]) << "\n";
        std::cout << "  H2=" << hex32(state[2]) << " + " << hex32(c) << " = " << hex32(out.h[2]) << "\n";
        std::cout << "  H3=" << hex32(state[3]) << " + " << hex32(d) << " = " << hex32(out.h[3]) << "\n";
        std::cout << "  H4=" << hex32(state[4]) << " + " << hex32(e) << " = " << hex32(out.h[4]) << "\n";
        std::cout << "  H5=" << hex32(state[5]) << " + " << hex32(f) << " = " << hex32(out.h[5]) << "\n";
        std::cout << "  H6=" << hex32(state[6]) << " + " << hex32(g) << " = " << hex32(out.h[6]) << "\n";
        std::cout << "  H7=" << hex32(state[7]) << " + " << hex32(h) << " = " << hex32(out.h[7]) << "\n";
        std::cout << "[MIDSTATE] Итоговое состояние (BE words): " << out.to_hex() << "\n";
        std::cout << "[MIDSTATE] ===== КОНЕЦ РАСЧЁТА MIDSTATE =====\n\n";

        return out;
    }

private:
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
        std::ostringstream ss;
        for (unsigned char b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }

    static std::string hex32(uint32_t v) {
        std::ostringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << v;
        return ss.str();
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
        ss << "a=" << hex32(a) << " b=" << hex32(b) << " c=" << hex32(c) << " d=" << hex32(d)
           << " e=" << hex32(e) << " f=" << hex32(f) << " g=" << hex32(g) << " h=" << hex32(h);
        return ss.str();
    }
};

#endif // MIDSTATE_HPP
