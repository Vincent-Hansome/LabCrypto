#ifndef RSA_CORE_H
#define RSA_CORE_H

#include <string>

class RSACore {
public:
    // Sinh khóa
    static void GenerateKeys(int keySize, const std::string& pubFile, const std::string& privFile);

    // Mã hóa thuần RSA-OAEP
    static void Encrypt(const std::string& pubFile, const std::string& inFile, const std::string& outFile);

    // Giải mã thuần RSA-OAEP
    static void Decrypt(const std::string& privFile, const std::string& inFile, const std::string& outFile);
    // Mã hóa Lai (Hybrid) kết hợp AES-GCM và RSA
    static void EncryptHybrid(const std::string& pubFile, const std::string& inFile, const std::string& outFile);

    // Giải mã Lai (Hybrid) 
    static void DecryptHybrid(const std::string& privFile, const std::string& inFile, const std::string& outFile);
};

#endif