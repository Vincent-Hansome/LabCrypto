#ifndef CTR_MODE_H
#define CTR_MODE_H

#include "aes128.h"
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <iostream>

// Lớp xử lý chế độ Counter (CTR) tuân thủ NIST SP 800-38A
class CTRMode {
private:
    AES128 aes;              // Lõi mã hóa AES-128
    uint8_t counterBlock[16]; // Khối 16 byte chứa (Nonce + Counter)

    // Hàm tăng bộ đếm (Increment) an toàn cho block tiếp theo
    // Sử dụng chuẩn Big-Endian: Tăng từ byte cuối cùng (byte thứ 15) ngược lên
    void IncrementCounter();

public:
    // Khởi tạo CTR với Khóa (16 bytes) và IV/Nonce (16 bytes)
    CTRMode(const uint8_t* key, const uint8_t* iv);

    // Hàm xử lý dữ liệu luồng (Dùng chung cho cả Mã hóa và Giải mã)
    // In/Out là dữ liệu gốc, length là kích thước file (tính bằng byte)
    void ProcessData(const uint8_t* in, uint8_t* out, size_t length);
};

#endif // CTR_MODE_H