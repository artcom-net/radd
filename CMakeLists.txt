cmake_minimum_required(VERSION 3.1)

set(CMAKE_C_COMPILER /usr/bin/cc)
set(CMAKE_CXX_COMPILER /usr/bin/c++)

project(radius)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_FLAGS "-Wall")

include_directories(include)
file(GLOB SOURCES "src/*.c")

find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
#FIND_LIBRARY(SQLITE3_LIBRARY NAMES sqlite3)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} sqlite3)
