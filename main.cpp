#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include "json.hpp" // Использование скачанного заголовка
#include "merkle.hpp" // Включение логики Меркла
#include "midstate.hpp" // Включение логики Midstate
#include "nonce.hpp" // Включение логики Nonce

using json = nlohmann::json;
using boost::asio::ip::tcp;

class StratumClient {
public:
    StratumClient(boost::asio::io_context& io_context, const std::string& host, const std::string& port)
        : io_context_(io_context), socket_(io_context), resolver_(io_context), extranonce2_size_(4) {
        
        try {
            auto endpoints = resolver_.resolve(host, port);
            boost::asio::connect(socket_, endpoints);
            std::cout << "[ИНФО] Соединение установлено с " << host << ":" << port << std::endl;
        } catch (std::exception& e) {
            std::cerr << "[ОШИБКА] Не удалось подключиться: " << e.what() << std::endl;
            exit(1);
        }
    }

    void run() {
        // 1. Отправка mining.subscribe
        send_request("mining.subscribe", { "miner/1.0.0" }); // user agent
        
        // Чтение и обработка ответов
        try {
            while (true) {
                read_response();
            }
        } catch (std::exception& e) {
            std::cerr << "[ОШИБКА] Ошибка при чтении: " << e.what() << std::endl;
        }
    }

private:
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    tcp::resolver resolver_;
    std::string buffer_;
    
    // Данные сессии
    std::string extranonce1_;
    int extranonce2_size_;

    void send_request(const std::string& method, const json& params) {
        static int id_counter = 1;
        json request = {
            {"id", id_counter++},
            {"method", method},
            {"params", params}
        };

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
        
        try {
            json response = json::parse(line);
            explain_message(response);
        } catch (json::parse_error& e) {
            std::cerr << "[ОШИБКА] Ошибка парсинга JSON: " << e.what() << std::endl;
        }
    }

    void explain_message(const json& msg) {
        std::cout << "\n--- [РАЗБОР ДАННЫХ] ---\n";
        
        // 1. Обработка ошибок
        if (msg.contains("error") && !msg["error"].is_null()) {
            std::cout << "ОШИБКА ОТ ПУЛА: " << msg["error"] << std::endl;
            return;
        }

        // 2. Обработка уведомлений (notifications)
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
        } 
        // 3. Обработка ответов на запросы (responses)
        else if (msg.contains("result") && !msg["result"].is_null()) {
             // Ответ на mining.subscribe
             if (msg["result"].is_array() && msg["result"].size() >= 3 && msg["result"][0].is_array()) {
                 explain_subscribe_response(msg["result"]);
                 
                 // После успешной подписки, отправляем авторизацию
                 send_request("mining.authorize", { "user", "password" }); 
             }
             // Ответ на mining.authorize (true/false)
             else if (msg["result"].is_boolean()) {
                 bool authorized = msg["result"];
                 std::cout << "Авторизация: " << (authorized ? "УСПЕШНО" : "ОТКЛОНЕНО") << std::endl;
             }
             else {
                 std::cout << "Получен результат на запрос ID " << msg["id"] << ": " << msg["result"] << std::endl;
             }
        }
        std::cout << "-----------------------\n\n";
    }

    void explain_subscribe_response(const json& result) {
        std::cout << "Тип: Ответ на mining.subscribe (Подписка)" << std::endl;
        
        const auto& subscriptions = result[0];
        extranonce1_ = result[1];
        extranonce2_size_ = result[2];

        std::cout << "1. Subscriptions (Подписки):" << std::endl;
        for (const auto& sub : subscriptions) {
            std::cout << "   - " << sub[0] << " (ID сессии: " << sub[1] << ")" << std::endl;
        }
        
        std::cout << "2. Extranonce1: " << extranonce1_ << std::endl;
        std::cout << "   -> Первая часть уникального идентификатора nonce, выданная пулом." << std::endl;
        
        std::cout << "3. Extranonce2_size: " << extranonce2_size_ << std::endl;
        std::cout << "   -> Размер второй части nonce (в байтах)." << std::endl;
    }

    void explain_set_difficulty(const json& params) {
        double difficulty = params[0];
        std::cout << "Тип: Установка сложности (mining.set_difficulty)" << std::endl;
        std::cout << "Новая сложность: " << difficulty << std::endl;
    }

    void explain_mining_notify(const json& params) {
        if (params.size() < 9) {
            std::cout << "Некорректный формат mining.notify" << std::endl;
            return;
        }

        std::string job_id = params[0];
        std::string prevhash = params[1];
        std::string coinb1 = params[2];
        std::string coinb2 = params[3];
        json merkle_branch_json = params[4];
        std::string version = params[5];
        std::string nbits = params[6];
        std::string ntime = params[7];
        bool clean_jobs = params[8];

        std::cout << "Тип: Новое задание (mining.notify)" << std::endl;
        std::cout << "1. Job ID: " << job_id << std::endl;
        std::cout << "2. Previous Hash: " << prevhash << std::endl;
        std::cout << "3. Coinb1: " << coinb1 << std::endl;
        std::cout << "4. Coinb2: " << coinb2 << std::endl;
        std::cout << "5. Merkle Branch: [" << merkle_branch_json.size() << " элементов]" << std::endl;
        std::cout << "6. Version: " << version << std::endl;
        std::cout << "7. nBits: " << nbits << std::endl;
        std::cout << "8. nTime: " << ntime << std::endl;
        std::cout << "9. Clean Jobs: " << (clean_jobs ? "DA" : "NET") << std::endl;

        // Вычисление Корня Меркла
        if (!extranonce1_.empty()) {
            std::vector<std::string> branch;
            for (const auto& item : merkle_branch_json) {
                branch.push_back(item.get<std::string>());
            }
            
            // Генерация произвольного Extranonce2
            // Поскольку Extranonce2_size обычно в байтах, нам нужны символы hex (2 на байт)
            // extranonce2_size_ в байтах. длина строки = size * 2.
            std::string extranonce2 = "";
            for (int i = 0; i < extranonce2_size_; ++i) extranonce2 += "00"; 
            
            std::string root = MerkleCalculator::calculate_root(
                coinb1, extranonce1_, extranonce2, coinb2, branch
            );
            
            std::cout << "\n[ВЫЧИСЛЕНИЕ MERKLE]" << std::endl;
            std::cout << "   -> Extranonce1 (использован): " << extranonce1_ << std::endl;
            std::cout << "   -> Extranonce2 (сгенерирован): " << extranonce2 << std::endl;
            std::cout << "   -> Вычисленный Merkle Root: " << root << std::endl;

            // --- Вычисление Midstate ---
            // Требование: Version = 1073733632 (Десятичное)
            // Создание первых 64 байт заголовка блока
            std::vector<unsigned char> header64;

            // 1. Версия (4 байта, Little Endian)
            uint32_t version_val = 1073733632; 
            header64.push_back((version_val >> 0) & 0xFF);
            header64.push_back((version_val >> 8) & 0xFF);
            header64.push_back((version_val >> 16) & 0xFF);
            header64.push_back((version_val >> 24) & 0xFF);

            // 2. Предыдущий хэш (32 байта, Little Endian)
            // Stratum предоставляет текст как Big Endian (формат RPC). Преобразовать в байты и перевернуть.
            std::vector<unsigned char> prev_bytes = MerkleCalculator::hex_to_bytes(prevhash);
            std::reverse(prev_bytes.begin(), prev_bytes.end());
            header64.insert(header64.end(), prev_bytes.begin(), prev_bytes.end());

            // 3. Корень Меркла (32 байта, Little Endian / Внутренний порядок байтов)
            // Наш calculate_root возвращает внутренний порядок байтов. Просто добавить.
            std::vector<unsigned char> root_bytes = MerkleCalculator::hex_to_bytes(root);
            header64.insert(header64.end(), root_bytes.begin(), root_bytes.end());

            // Убедитесь, что у нас есть как минимум 64 байта (Version 4 + Prev 32 + Root 32 = 68).
            // Нам нужны только первые 64 байта для midstate.
            if (header64.size() >= 64) {
                std::vector<unsigned char> first_chunk(header64.begin(), header64.begin() + 64);
                
                try {
                    auto midstate = MidstateCalculator::calculate_midstate(first_chunk);
                    std::cout << "   -> Midstate (Hex): " << midstate.to_hex() << std::endl;

                    // --- Ручная проверка Nonce ---
                    // Нам нужна оставшаяся часть заголовка для второго фрагмента.
                    // Заголовок всего 80 байт.
                    // Обработано 64 байта. Осталось 16 байт.
                    // Оставшиеся 16 байт это:
                    // [64..67] Последние 4 байта корня Меркла
                    // [68..71] nTime
                    // [72..75] nBits
                    // [76..79] Nonce

                    // Извлечение Merkle Tail (последние 4 байта root_bytes)
                    // root_bytes равно 32 байта.
                    std::vector<unsigned char> merkle_tail(root_bytes.end() - 4, root_bytes.end());

                    // Создание хвоста блока (nTime, nBits, Nonce)
                    std::vector<unsigned char> block_tail;
                    
                    // nTime (4 байта Little Endian)
                    // Stratum ntime - это hex-строка
                    // Пример: "69977a90".
                    // Давайте декодируем hex в байты.
                    std::vector<unsigned char> ntime_bytes = MerkleCalculator::hex_to_bytes(ntime);
                    // Standard stratum is Big Endian for all fields EXCEPT clean_jobs etc.
                    // Поэтому мы должны перевернуть, чтобы получить Little Endian для хэширования.
                    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
                    block_tail.insert(block_tail.end(), ntime_bytes.begin(), ntime_bytes.end());

                    // nBits (4 байта Little Endian)
                    std::vector<unsigned char> nbits_bytes = MerkleCalculator::hex_to_bytes(nbits);
                    std::reverse(nbits_bytes.begin(), nbits_bytes.end());
                    block_tail.insert(block_tail.end(), nbits_bytes.begin(), nbits_bytes.end());

                    // Nonce (4 байта Little Endian)
                    // Мы не нашли nonce! Мы просто проверяем ОДИН nonce, как было запрошено.
                    // Используем Nonce = 0.
                    uint32_t nonce_val = 0; 
                    block_tail.push_back((nonce_val >> 0) & 0xFF);
                    block_tail.push_back((nonce_val >> 8) & 0xFF);
                    block_tail.push_back((nonce_val >> 16) & 0xFF);
                    block_tail.push_back((nonce_val >> 24) & 0xFF);
                    
                    // Сложность сети
                    // Мы используем значение, предоставленное пользователем: 146 470 000 000 000 000
                    double current_diff = 146470000000000000.0;
                    
                    NonceCalculator::check_nonce_step_by_step(midstate, merkle_tail, block_tail, current_diff);

                } catch (const std::exception& e) {
                     std::cout << "   -> Ошибка Midstate/Nonce: " << e.what() << std::endl;
                }
            } else {
                std::cout << "   -> Ошибка Midstate: Недостаточно данных заголовка." << std::endl;
            }

        } else {
             std::cout << "\n[ВЫЧИСЛЕНИЕ MERKLE] Невозможно рассчитать: нет Extranonce1." << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    // ... основная функция остается прежней
    std::string host = "127.0.0.1";
    std::string port = "3333";

    if (argc > 1) host = argv[1];
    if (argc > 2) port = argv[2];

    try {
        boost::asio::io_context io_context;
        StratumClient client(io_context, host, port);
        client.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
