cmake_minimum_required(VERSION 3.15)
project(mem_profiler LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)

# Output locations
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Set build type to Debug to enable -g
set(CMAKE_BUILD_TYPE Debug)

# Executable
add_executable(
    main 
    src/main.cpp
    src/symboliser.cpp
    src/symboliser.h
)
add_executable(
    vector examples/vector.cpp
)
add_executable(
    multithread examples/multithread.cpp
)

target_link_libraries(main
    dl 
    unwind
    dw
    elf
)
