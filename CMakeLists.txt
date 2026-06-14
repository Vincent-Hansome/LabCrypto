cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0135 NEW)
project(CryptoLabs VERSION 1.0.0 LANGUAGES CXX)

# Bắt buộc sử dụng C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tìm các thư viện cần thiết (OpenSSL)
find_package(OpenSSL REQUIRED)

# Tuỳ chọn tự động tải Google Test qua FetchContent
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

# Cấu hình thư mục con (bạn sẽ tạo CMakeLists.txt riêng trong src/Lab1)
add_subdirectory(src/Lab1)
add_subdirectory(src/Lab2)
add_subdirectory(src/Lab3)
add_subdirectory(src/Lab4)
add_subdirectory(src/Lab5)
add_subdirectory(src/Lab6)
# add_subdirectory(tests)