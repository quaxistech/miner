#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "json.hpp"
#include "merkle.hpp"
#include "midstate.hpp"
#include "nonce.hpp"

using json = nlohmann::json;
using boost::asio::ip::tcp;

class StratumClient {
public:
    StratumClient(boost::asio::io_context& io_context, const std::string& host, const std::string& port)
        : io_context_(io_context), socket_(io_context), resolver_(io_context), extranonce2_size_(4) {
        auto endpoints = resolver_.resolve(host, port);
        boost::asio::connect(socket_, endpoints);
        std::cout << "[ИНФО] Соединение установлено с " << host << ":" << port << std::endl;
    }

    void run() {
        // Стандартный старт Stratum-сессии: подписка, затем чтение входящих сообщений.
        send_request("mining.subscribe", {"miner/1.0.0"});
        while (true) {
            read_response();
        }
    }

private:
    // ------------------------------------------------------------------------
    // ВАЖНО: по требованию оставляем жёстко заданные параметры
    // ------------------------------------------------------------------------
    // FIXED_BLOCK_VERSION_DEC:
    //   Жёстко заданная версия блока (десятичная форма), которая будет использоваться
    //   вместо поля version из mining.notify.
    // FIXED_NETWORK_DIFFICULTY:
    //   Жёстко заданная сложность сети для дополнительной проверки hash<=target.
    // ------------------------------------------------------------------------
    static constexpr uint32_t FIXED_BLOCK_VERSION_DEC = 1073733632;
    static constexpr double FIXED_NETWORK_DIFFICULTY = 146470000000000000.0;

    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    tcp::resolver resolver_;

    // Данные Stratum-сессии.
    std::string extranonce1_;
    int extranonce2_size_;

    // Чтобы не терять контекст пула, всё равно запоминаем присланную сложность,
    // но в целевой проверке используем фиксированную сложность согласно требованию.
    double last_pool_difficulty_ = 0.0;

    // ------------------------------------------------------------------------
    // parse_hex_field_le
    // ------------------------------------------------------------------------
    // Stratum обычно передаёт числовые поля в hex-строке в «читаемом» big-endian,
    // тогда как в заголовке Bitcoin многие поля хранятся little-endian.
    // Эта функция переводит hex-строку в байты и разворачивает порядок байтов.
    // ------------------------------------------------------------------------
    static std::vector<unsigned char> parse_hex_field_le(const std::string& hex) {
        auto bytes = MerkleCalculator::hex_to_bytes(hex);
        std::reverse(bytes.begin(), bytes.end());
        return bytes;
    }

    // Утилита печати байтов в HEX-форме для максимально подробного вывода.
    static void print_hex_bytes(const std::string& label, const std::vector<unsigned char>& bytes) {
        std::cout << label << " (" << bytes.size() << " байт): ";
        std::cout << NonceCalculator::bytes_to_hex(bytes) << std::endl;
    }

    void send_request(const std::string& method, const json& params) {
        static int id_counter = 1;
        json request = {{"id", id_counter++}, {"method", method}, {"params", params}};

        std::string request_str = request.dump() + "\n";
        boost::asio::write(socket_, boost::asio::buffer(request_str));
        std::cout << "[ОТПРАВЛЕНО] -> " << request_str;
    }

    void read_response() {
        boost::asio::streambuf response_buffer;
        boost::asio::read_until(socket_, response_buffer, "\n");
        std::istream is(&response_buffer);
        std::string line;
        std::getline(is, line);

        if (line.empty()) return;

        std::cout << "[ПОЛУЧЕНО] <- " << line << std::endl;

        auto response = json::parse(line);
        explain_message(response);
    }

    void explain_message(const json& msg) {
        std::cout << "\n--- [РАЗБОР ДАННЫХ] ---\n";

        if (msg.contains("error") && !msg["error"].is_null()) {
            std::cout << "ОШИБКА ОТ ПУЛА: " << msg["error"] << std::endl;
            return;
        }

        if (msg.contains("method") && !msg["method"].is_null()) {
            std::string method = msg["method"];
            std::cout << "Метод: " << method << std::endl;

            if (method == "mining.notify") {
                explain_mining_notify(msg["params"]);
            } else if (method == "mining.set_difficulty") {
                explain_set_difficulty(msg["params"]);
            } else if (method == "client.show_message") {
                std::cout << "Сообщение от пула: " << msg["params"][0] << std::endl;
            } else {
                std::cout << "Неизвестный метод уведомления." << std::endl;
            }
        } else if (msg.contains("result") && !msg["result"].is_null()) {
            if (msg["result"].is_array() && msg["result"].size() >= 3 && msg["result"][0].is_array()) {
                explain_subscribe_response(msg["result"]);
                send_request("mining.authorize", {"user", "password"});
            } else if (msg["result"].is_boolean()) {
                std::cout << "Авторизация: " << (msg["result"].get<bool>() ? "УСПЕШНО" : "ОТКЛОНЕНО") << std::endl;
            } else {
                std::cout << "Получен результат на запрос ID " << msg["id"] << ": " << msg["result"] << std::endl;
            }
        }

        std::cout << "-----------------------\n\n";
    }

    void explain_subscribe_response(const json& result) {
        extranonce1_ = result[1];
        extranonce2_size_ = result[2];

        std::cout << "Тип: Ответ на mining.subscribe" << std::endl;
        std::cout << "Extranonce1: " << extranonce1_ << std::endl;
        std::cout << "Extranonce2_size: " << extranonce2_size_ << " байт" << std::endl;
    }

    void explain_set_difficulty(const json& params) {
        last_pool_difficulty_ = params[0].get<double>();
        std::cout << "Тип: mining.set_difficulty" << std::endl;
        std::cout << "Сложность от пула (для информации): " << last_pool_difficulty_ << std::endl;
        std::cout << "Сложность, используемая в расчёте (жёстко): " << FIXED_NETWORK_DIFFICULTY << std::endl;
    }

    void explain_mining_notify(const json& params) {
        if (params.size() < 9) {
            std::cout << "Некорректный формат mining.notify" << std::endl;
            return;
        }

        const std::string job_id = params[0];
        const std::string prevhash = params[1];
        const std::string coinb1 = params[2];
        const std::string coinb2 = params[3];
        const json merkle_branch_json = params[4];
        const std::string version_from_pool = params[5];
        const std::string nbits = params[6];
        const std::string ntime = params[7];
        const bool clean_jobs = params[8];

        std::cout << "Тип: mining.notify, Job ID: " << job_id << std::endl;
        std::cout << "prevhash: " << prevhash << std::endl;
        std::cout << "version от пула (игнорируется по требованию): " << version_from_pool << std::endl;
        std::cout << "nbits: " << nbits << std::endl;
        std::cout << "ntime: " << ntime << std::endl;
        std::cout << "clean_jobs: " << (clean_jobs ? "true" : "false") << std::endl;

        if (extranonce1_.empty()) {
            std::cout << "Невозможно рассчитать header/hash: отсутствует extranonce1" << std::endl;
            return;
        }

        // Шаг 1. Построение Merkle Root по правилам Stratum V1.
        std::vector<std::string> branch;
        for (const auto& item : merkle_branch_json) {
            branch.push_back(item.get<std::string>());
        }

        const std::string extranonce2 = MerkleCalculator::generate_default_extranonce2(extranonce2_size_);
        const std::string merkle_root =
            MerkleCalculator::calculate_root(coinb1, extranonce1_, extranonce2, coinb2, branch);

        std::cout << "[COINBASE] extranonce1: " << extranonce1_ << std::endl;
        std::cout << "[COINBASE] extranonce2 (фиксировано нулями): " << extranonce2 << std::endl;
        std::cout << "[MERKLE] root (внутренний порядок байтов): " << merkle_root << std::endl;

        // Шаг 2. Сборка 80-байтного заголовка Bitcoin (с жёсткой версией).
        std::vector<unsigned char> header;
        header.reserve(80);

        // Версия: именно фиксированное число, little-endian в заголовке.
        std::vector<unsigned char> version_le = {
            static_cast<unsigned char>((FIXED_BLOCK_VERSION_DEC >> 0) & 0xff),
            static_cast<unsigned char>((FIXED_BLOCK_VERSION_DEC >> 8) & 0xff),
            static_cast<unsigned char>((FIXED_BLOCK_VERSION_DEC >> 16) & 0xff),
            static_cast<unsigned char>((FIXED_BLOCK_VERSION_DEC >> 24) & 0xff)};

        // prevhash приходит как «читаемый» hex, для заголовка нужен little-endian порядок.
        auto prevhash_le = parse_hex_field_le(prevhash);

        // merkle_root уже возвращается как внутренний (подходящий для заголовка) порядок байтов.
        auto merkle_root_internal = MerkleCalculator::hex_to_bytes(merkle_root);

        // ntime/nbits в заголовок тоже кладём little-endian.
        auto ntime_le = parse_hex_field_le(ntime);
        auto nbits_le = parse_hex_field_le(nbits);

        header.insert(header.end(), version_le.begin(), version_le.end());
        header.insert(header.end(), prevhash_le.begin(), prevhash_le.end());
        header.insert(header.end(), merkle_root_internal.begin(), merkle_root_internal.end());
        header.insert(header.end(), ntime_le.begin(), ntime_le.end());
        header.insert(header.end(), nbits_le.begin(), nbits_le.end());

        // Nonce для демонстрационной проверки оставляем 0 (LE).
        const uint32_t nonce = 0;
        header.push_back(static_cast<unsigned char>((nonce >> 0) & 0xff));
        header.push_back(static_cast<unsigned char>((nonce >> 8) & 0xff));
        header.push_back(static_cast<unsigned char>((nonce >> 16) & 0xff));
        header.push_back(static_cast<unsigned char>((nonce >> 24) & 0xff));

        if (header.size() != 80) {
            std::cout << "Ошибка: ожидается 80 байт заголовка, получено " << header.size() << std::endl;
            return;
        }

        // Максимально подробный вывод всех промежуточных полей.
        print_hex_bytes("[HEADER] version_le", version_le);
        print_hex_bytes("[HEADER] prevhash_le", prevhash_le);
        print_hex_bytes("[HEADER] merkle_root_internal", merkle_root_internal);
        print_hex_bytes("[HEADER] ntime_le", ntime_le);
        print_hex_bytes("[HEADER] nbits_le", nbits_le);
        print_hex_bytes("[HEADER] full_80_bytes", header);

        // Шаг 3. Midstate (первые 64 байта), как обычно используют майнеры/ASIC pipeline.
        std::vector<unsigned char> first_chunk(header.begin(), header.begin() + 64);
        auto midstate = MidstateCalculator::calculate_midstate(first_chunk);

        // Шаг 4. Полный SHA256d заголовка.
        auto hash_be = NonceCalculator::dsha256(header);
        std::vector<unsigned char> hash_le = hash_be;
        std::reverse(hash_le.begin(), hash_le.end());

        // Шаг 5а. Эталонный target из nBits (канонически для блока).
        auto target_from_nbits = NonceCalculator::target_from_compact(nbits);
        bool valid_vs_nbits = NonceCalculator::hash_meets_target(hash_be, target_from_nbits);

        // Шаг 5б. Дополнительный target из жёстко заданной сложности (по вашему требованию).
        auto target_from_fixed_diff = NonceCalculator::target_from_difficulty(FIXED_NETWORK_DIFFICULTY);
        bool valid_vs_fixed_diff = NonceCalculator::hash_meets_target(hash_be, target_from_fixed_diff);

        // Подробнейший финальный отчёт.
        std::cout << "[MIDSTATE] " << midstate.to_hex() << std::endl;
        std::cout << "[HASH big-endian] " << NonceCalculator::bytes_to_hex(hash_be) << std::endl;
        std::cout << "[HASH little-endian/display] " << NonceCalculator::bytes_to_hex(hash_le) << std::endl;
        std::cout << "[TARGET from nBits] " << NonceCalculator::bytes_to_hex(target_from_nbits) << std::endl;
        std::cout << "[TARGET CHECK nBits] "
                  << (valid_vs_nbits ? "PASS (hash <= target)" : "FAIL (hash > target)") << std::endl;
        std::cout << "[COMPARE nBits] hash=" << NonceCalculator::bytes_to_hex(hash_be)
                  << " VS target=" << NonceCalculator::bytes_to_hex(target_from_nbits) << std::endl;

        std::cout << "[FIXED VERSION DEC] " << FIXED_BLOCK_VERSION_DEC << std::endl;
        std::cout << "[FIXED DIFFICULTY] " << std::fixed << std::setprecision(0) << FIXED_NETWORK_DIFFICULTY
                  << std::defaultfloat << std::endl;
        std::cout << "[TARGET from fixed difficulty] " << NonceCalculator::bytes_to_hex(target_from_fixed_diff)
                  << std::endl;
        std::cout << "[TARGET CHECK fixed difficulty] "
                  << (valid_vs_fixed_diff ? "PASS (hash <= target)" : "FAIL (hash > target)") << std::endl;
        std::cout << "[COMPARE fixed difficulty] hash=" << NonceCalculator::bytes_to_hex(hash_be)
                  << " VS target=" << NonceCalculator::bytes_to_hex(target_from_fixed_diff) << std::endl;
    }
};

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    std::string port = "3333";

    if (argc > 1) host = argv[1];
    if (argc > 2) port = argv[2];

    try {
        boost::asio::io_context io_context;
        StratumClient client(io_context, host, port);
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
