cmake_minimum_required(VERSION 3.15)
project(mem_profiler LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)

# Output locations
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Set build type to Debug to enable -g
set(CMAKE_BUILD_TYPE Debug)

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
