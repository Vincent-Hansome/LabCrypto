# Lab 6: Post-Quantum Cryptography
find_package(liboqs CONFIG REQUIRED)

add_executable(pqtool main.cpp pq_core.cpp)

# Target chính xác theo cấu hình chuẩn của vcpkg
target_link_libraries(pqtool PRIVATE OQS::oqs)

if(MSVC)
    target_compile_options(pqtool PRIVATE /W4)
else()
    target_compile_options(pqtool PRIVATE -Wall -Wextra)
endif()