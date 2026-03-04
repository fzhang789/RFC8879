cmake_minimum_required(VERSION 3.16)
project(rfc8879_poc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(hitls_cert_compress STATIC
    src/hitls_cert_compress.c
)

target_include_directories(hitls_cert_compress PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(hitls_cert_compress PRIVATE /W4)
else()
    target_compile_options(hitls_cert_compress PRIVATE -Wall -Wextra)
endif()

add_executable(test_rfc8879
    tests/test_hitls_cert_compress.c
)

target_link_libraries(test_rfc8879 PRIVATE hitls_cert_compress)

if(MSVC)
    target_compile_options(test_rfc8879 PRIVATE /W4)
else()
    target_compile_options(test_rfc8879 PRIVATE -Wall -Wextra)
endif()
