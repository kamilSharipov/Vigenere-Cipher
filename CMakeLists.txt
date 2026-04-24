cmake_minimum_required(VERSION 3.14)
project(vigenere_cipher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0 -Wall -Wextra -Werror)
    else()
        add_compile_options(-O2 -DNDEBUG -Wall -Wextra -Werror -march=native)
    endif()
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

find_package(Boost REQUIRED COMPONENTS program_options)

add_library(vigenere_lib STATIC src/vigenere.cpp)
target_include_directories(vigenere_lib PUBLIC include)

add_executable(vigenere_app src/main.cpp)
target_link_libraries(vigenere_app PRIVATE vigenere_lib Boost::program_options)

enable_testing()
add_executable(test_vigenere tests/test_vigenere.cpp)
target_link_libraries(test_vigenere PRIVATE vigenere_lib GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(test_vigenere)
