cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/build/conan_toolchain.cmake)

set(PROJECT_NAME "WireguardVPNServer")
project(${PROJECT_NAME})

find_package(onnxruntime REQUIRED)
find_package(PcapPlusPlus REQUIRED)

add_executable(server_app main.cpp)

target_include_directories(server_app PRIVATE ${PcapPlusPlus_INCLUDE_DIRS})

target_link_libraries(server_app PRIVATE onnxruntime::onnxruntime PcapPlusPlus::PcapPlusPlus)
