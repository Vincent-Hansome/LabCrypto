#ifndef AES128_H
#define AES128_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>

// Class AES-128 tuân thủ chuẩn FIPS-197 (Chỉ mã hóa, không cần giải mã cho CTR)
class AES128 {
private:
    static const int Nk = 4;
    static const int Nr = 10;

    uint8_t RoundKey[176];
    static const uint8_t sbox[256];
    static const uint8_t Rcon[11];

    void KeyExpansion(const uint8_t* key);
    void AddRoundKey(uint8_t round, uint8_t* state);
    void SubBytes(uint8_t* state);
    void ShiftRows(uint8_t* state);
    void MixColumns(uint8_t* state);

    uint8_t galois_mul(uint8_t a, uint8_t b);

public:
    AES128(const uint8_t* key);
    void EncryptBlock(const uint8_t* in, uint8_t* out);
};

#endif // AES128_H