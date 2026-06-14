# Lab 5: Chu ky so ECDSA va RSA-PSS
find_package(cryptopp CONFIG REQUIRED)

add_executable(sigtool main.cpp sig_core.cpp)

target_link_libraries(sigtool PRIVATE cryptopp::cryptopp)

if(MSVC)
    target_compile_options(sigtool PRIVATE /W4)
else()
    target_compile_options(sigtool PRIVATE -Wall -Wextra)
endif()