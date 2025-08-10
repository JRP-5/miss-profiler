cmake_minimum_required(VERSION 3.15)
project(mem_profiler LANGUAGES C CXX)

# Output locations
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Set build type to Debug to enable -g
set(CMAKE_BUILD_TYPE Debug)

# Compiler flags for debug builds
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0 -fno-omit-frame-pointer -fno-inline")
set(CMAKE_C_FLAGS_DEBUG   "-g3 -O0 -fno-omit-frame-pointer -fno-inline")

# Optional: enable all warnings
add_compile_options(-Wall -Wextra -Wno-unused)

# Executable
add_executable(vector
    examples/vector.cpp
)

# Shared library
add_library(hook SHARED
    src/hook.cpp
    src/symboliser.cpp
    src/symboliser.h
)

# Link dependencies
target_link_libraries(hook
    dl 
    unwind
    dw
    elf
)
