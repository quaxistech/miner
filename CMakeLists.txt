cmake_minimum_required(VERSION 3.14)
project(stratum_client CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Проверка наличия Boost (Asio)
find_package(Boost REQUIRED)

# FetchContent удален, так как json.hpp есть локально
# include(FetchContent)
# FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp)
# FetchContent_MakeAvailable(json)


# Если FetchContent плохо работает для header-only библиотек без сложной настройки, 
# мы можем просто скачать один заголовочный файл напрямую через скрипт или команду.
# Для простоты, попробуем предположить, что nlohmann_json доступен или скачаем его через вспомогательный скрипт, если потребуется.
# На самом деле, FetchContent для одного заголовочного файла сложен. Я скачаю его вручную при настройке.

add_executable(stratum_client main.cpp)

# Подключение директорий при необходимости
find_package(OpenSSL REQUIRED)
target_include_directories(stratum_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(stratum_client PRIVATE Boost::boost OpenSSL::SSL OpenSSL::Crypto)
