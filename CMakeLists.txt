cmake_minimum_required(VERSION 3.15)
project(mem_profiler LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)

# Output locations
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Set build type to Debug to enable -g
set(CMAKE_BUILD_TYPE Debug)

include(FetchContent)
# Fetch moodycamel concurrentqueue
FetchContent_Declare(
    concurrentqueue
    GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
    GIT_TAG        master 
)
FetchContent_MakeAvailable(concurrentqueue)

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

target_include_directories(main PRIVATE
    ${concurrentqueue_SOURCE_DIR}
)

target_link_libraries(main
    dl 
    unwind
    dw
    elf
)
