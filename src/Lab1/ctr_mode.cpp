#include "ctr_mode.h"

// Khởi tạo CTR [cite: 462]
CTRMode::CTRMode(const uint8_t* key, const uint8_t* iv) : aes(key) {
    if (!iv) {
        throw std::invalid_argument("[-] Loi: IV/Nonce khong duoc de trong!");
    }
    // Copy IV 16-byte vào khối đếm (counter block)
    for (int i = 0; i < 16; i++) {
        counterBlock[i] = iv[i];
    }
}

// Tăng bộ đếm (Big-Endian) [cite: 463, 465]
void CTRMode::IncrementCounter() {
    // Duyệt từ byte cuối cùng (byte 15) lên byte 0
    for (int i = 15; i >= 0; i--) {
        counterBlock[i]++;
        // Nếu không bị tràn (overflow) ở byte hiện tại (nghĩa là < 256 hay khác 0) thì dừng tăng
        if (counterBlock[i] != 0) {
            break;
        }
    }
}

// Hàm cốt lõi biến AES thành Stream Cipher [cite: 453-454, 467-468]
// Lưu ý: Trong CTR, quá trình Mã hóa và Giải mã là MỘT (đều là phép XOR với Keystream)
void CTRMode::ProcessData(const uint8_t* in, uint8_t* out, size_t length) {
    uint8_t keystreamBlock[16];
    size_t offset = 0;

    // Xử lý từng block 16 byte
    while (offset < length) {
        // 1. Mã hóa khối Counter hiện tại bằng AES để tạo Keystream [cite: 453]
        aes.EncryptBlock(counterBlock, keystreamBlock);

        // 2. Tính số byte còn lại cần xử lý (Xử lý mượt mà khối cuối cùng dù không đủ 16 byte) [cite: 468]
        size_t bytesToProcess = (length - offset) < 16 ? (length - offset) : 16;

        // 3. XOR Keystream với Plaintext (hoặc Ciphertext) [cite: 454, 460]
        for (size_t i = 0; i < bytesToProcess; i++) {
            out[offset + i] = in[offset + i] ^ keystreamBlock[i];
        }

        // 4. Tăng bộ đếm cho block tiếp theo [cite: 463]
        IncrementCounter();

        // 5. Chuyển sang block dữ liệu tiếp theo
        offset += bytesToProcess;
    }
}