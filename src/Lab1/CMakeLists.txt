# Tìm các thư viện trong hệ thống vcpkg
find_package(cryptopp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED) 

# Khai báo file chạy (Chỉ dùng MỘT lệnh duy nhất)
add_executable(aestool main.cpp aes128.cpp ctr_mode.cpp)

# Liên kết (Link) cả 2 thư viện vào file chạy aestool
target_link_libraries(aestool PRIVATE cryptopp::cryptopp)
target_link_libraries(aestool PRIVATE nlohmann_json::nlohmann_json) 

# Áp dụng cờ cảnh báo tùy theo trình biên dịch
if(MSVC)
    target_compile_options(aestool PRIVATE /W4)
else()
    target_compile_options(aestool PRIVATE -Wall -Wextra)
endif()