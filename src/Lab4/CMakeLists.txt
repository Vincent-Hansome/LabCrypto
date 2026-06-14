# Lab 4: Hashing & PKI
find_package(cryptopp CONFIG REQUIRED)

add_executable(hashtool main.cpp hash_core.cpp)

target_link_libraries(hashtool PRIVATE cryptopp::cryptopp)

if(MSVC)
    target_compile_options(hashtool PRIVATE /W4)
else()
    target_compile_options(hashtool PRIVATE -Wall -Wextra)
endif()