# Lab 3: Sử dụng lại Crypto++ và nlohmann_json
find_package(cryptopp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED) 

add_executable(rsatool main.cpp rsa_core.cpp)

target_link_libraries(rsatool PRIVATE cryptopp::cryptopp nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(rsatool PRIVATE /W4)
else()
    target_compile_options(rsatool PRIVATE -Wall -Wextra)
endif()