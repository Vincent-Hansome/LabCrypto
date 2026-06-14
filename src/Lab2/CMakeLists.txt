# Khai báo tìm thư viện JSON
find_package(nlohmann_json CONFIG REQUIRED) 

add_executable(lab2_aestool 
    main.cpp 
    aes128.cpp 
    ctr_mode.cpp
)

# Liên kết thư viện JSON vào dự án (VẪN CẤM DÙNG Crypto++)
target_link_libraries(lab2_aestool PRIVATE nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(lab2_aestool PRIVATE /W4)
else()
    target_compile_options(lab2_aestool PRIVATE -Wall -Wextra)
endif()