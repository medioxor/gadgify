cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 20)

project(gadgify)
set(CAPSTONE_ARCHITECTURE_DEFAULT ON)
set(CAPSTONE_X86_SUPPORT ON)
set(CAPSTONE_ARM_SUPPORT ON)
set(CAPSTONE_AARCH64_SUPPORT ON)
add_subdirectory(deps/capstone)

target_compile_options(capstone PUBLIC
        -w
)

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
        src/ThreadPool.cpp
        src/ThreadPool.h
        src/ThreadPool.h
)
install(TARGETS gadgify)
target_link_options(gadgify PRIVATE --static)
target_link_libraries(gadgify PRIVATE capstone)
