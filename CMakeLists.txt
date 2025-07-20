cmake_minimum_required(VERSION 3.15)
project(mem_profiler LANGUAGES C CXX)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_executable(vector_test
    examples/vector.cpp
)

add_library(hook SHARED
    src/hook.cpp
)

target_link_libraries(hook
    dl 
    unwind
)

