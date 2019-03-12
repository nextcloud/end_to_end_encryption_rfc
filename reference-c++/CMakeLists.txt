cmake_minimum_required(VERSION 3.0.0)

project(nextcloud-e2ee-reference VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl@1.1/1.1.1b")

find_package(OpenSSL REQUIRED)
find_package(Qt5Core)
find_package(ZLIB REQUIRED)

add_executable(${PROJECT_NAME} "main.cpp")

target_link_libraries(
    ${PROJECT_NAME}
    Qt5::Core
    OpenSSL::Crypto
    OpenSSL::SSL
    ${ZLIB_LIBRARIES})
