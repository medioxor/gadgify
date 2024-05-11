cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 20)

project(gadgify)

option(CAPSTONE_ARM_SUPPORT "" ON)
option(CAPSTONE_AARCH64_SUPPORT "" ON)
option(CAPSTONE_X86_SUPPORT "" ON)
add_subdirectory(deps/capstone)
add_subdirectory(deps/argparse)

include_directories(
        deps/capstone/include
        deps/argparse/include/argparse
)

add_executable(gadgify
        src/main.cpp
        src/File.cpp
        src/File.h
        src/PEFile.cpp
        src/PEFile.h
        src/Gadgify.cpp
        src/Gadgify.h
        src/ExecutableBinary.cpp
        src/ExecutableBinary.h
)

install(TARGETS gadgify)

target_link_options(gadgify PRIVATE --static)

target_compile_options(capstone PRIVATE -w)

target_link_libraries(gadgify PRIVATE capstone)
