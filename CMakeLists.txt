cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 20)
project(gadgify)

add_subdirectory(deps/argparse)

include_directories(
        deps/capstone/include
        deps/argparse/include/argparse
)

add_compile_definitions(CAPSTONE_USE_SYS_DYN_MEM CAPSTONE_HAS_X86, CAPSTONE_HAS_ARM, CAPSTONE_HAS_AARCH64, CAPSTONE_HAS_MIPS)
file(GLOB
        capstoneSource
        deps/capstone/*.h
        deps/capstone/arch/X86/*.h
        deps/capstone/arch/ARM/*.h
        deps/capstone/arch/AArch64/*.h
        deps/capstone/arch/Mips/*.h
        deps/capstone/*.c
        deps/capstone/arch/X86/*.c
        deps/capstone/arch/ARM/*.c
        deps/capstone/arch/AArch64/*.c
        deps/capstone/arch/Mips/*.c
)
add_library(capstone ${capstoneSource})
target_compile_options(capstone PRIVATE -w)

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
)
install(TARGETS gadgify)
target_link_libraries(gadgify PRIVATE capstone)
target_link_options(gadgify PRIVATE --static)
