cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 17)

project(gadgify)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(deps/zydis)
add_subdirectory(deps/argparse)

include_directories(
        deps/phnt
        deps/zydis/include
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
)

target_link_options(gadgify PRIVATE --static)

target_link_libraries(gadgify PRIVATE "Zydis")
