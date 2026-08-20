#!/bin/bash
export CC=clang-17
export CXX=clang++-17

conan install . --output-folder=build --build=missing -pr=clang
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build