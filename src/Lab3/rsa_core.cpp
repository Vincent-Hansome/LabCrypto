#include "rsa_core.h"
#include <iostream>
#include <fstream>
#include <chrono>

// Thư viện Crypto++
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
// Đã xóa cryptopp/pem.h vì vcpkg không tích hợp sẵn

// Thư viện JSON
#include <nlohmann/json.hpp>

using namespace CryptoPP;
using namespace std;
using json = nlohmann::json;

void RSACore::GenerateKeys(int keySize, const string& pubFile, const string& privFile) {
    AutoSeededRandomPool rng;

    cout << "[*] Dang sinh cap khoa RSA " << keySize << "-bit (Vui long doi)...\n";

    // 1. Khởi tạo khóa Private
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, keySize);
    RSA::PrivateKey privateKey(parameters);

    // 2. Trích xuất khóa Public từ Private
    RSA::PublicKey publicKey(parameters);

    // 3. Lưu khóa Private ra file (Định dạng DER chuẩn của Crypto++)
    FileSink privFileSink(privFile.c_str(), true);
    privateKey.Save(privFileSink);

    // 4. Lưu khóa Public ra file (Định dạng DER chuẩn của Crypto++)
    FileSink pubFileSink(pubFile.c_str(), true);
    publicKey.Save(pubFileSink);

    // 5. Lưu Metadata JSON
    json metadata;
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    string timeStr = ctime(&now_time);
    timeStr.pop_back(); // Xóa ký tự xuống dòng

    metadata["creation_time"] = timeStr;
    metadata["modulus_bits"] = keySize;
    metadata["hash"] = "SHA-256";
    metadata["format"] = "DER"; // Đánh dấu metadata là định dạng Binary

    ofstream metaFile(pubFile + ".meta.json");
    metaFile << metadata.dump(4);
    metaFile.close();

    cout << "[+] Da luu Public Key (DER) tai:  " << pubFile << "\n";
    cout << "[+] Da luu Private Key (DER) tai: " << privFile << "\n";
    cout << "[+] Da luu Metadata tai:          " << pubFile << ".meta.json\n";
}
// --- Hàm Mã hóa RSA-OAEP ---
void RSACore::Encrypt(const string& pubFile, const string& inFile, const string& outFile) {
    AutoSeededRandomPool rng;

    // 1. Load Public Key từ file DER
    RSA::PublicKey publicKey;
    FileSource pubFileSrc(pubFile.c_str(), true);
    publicKey.Load(pubFileSrc);

    // 2. Khởi tạo thuật toán RSA-OAEP với SHA-256
    RSAES<OAEP<SHA256>>::Encryptor encryptor(publicKey);

    // 3. Thực hiện mã hóa File-to-File
    cout << "[*] Dang ma hoa file: " << inFile << " bang RSA-OAEP...\n";
    FileSource(inFile.c_str(), true,
        new PK_EncryptorFilter(rng, encryptor,
            new FileSink(outFile.c_str())
        )
    );
    cout << "[+] Ma hoa thanh cong! File ket qua: " << outFile << "\n";
}

// --- Hàm Giải mã RSA-OAEP ---
void RSACore::Decrypt(const string& privFile, const string& inFile, const string& outFile) {
    AutoSeededRandomPool rng;

    // 1. Load Private Key từ file DER
    RSA::PrivateKey privateKey;
    FileSource privFileSrc(privFile.c_str(), true);
    privateKey.Load(privFileSrc);

    // 2. Khởi tạo thuật toán RSA-OAEP với SHA-256
    RSAES<OAEP<SHA256>>::Decryptor decryptor(privateKey);

    // 3. Thực hiện giải mã File-to-File
    cout << "[*] Dang giai ma file: " << inFile << " bang RSA-OAEP...\n";
    FileSource(inFile.c_str(), true,
        new PK_DecryptorFilter(rng, decryptor,
            new FileSink(outFile.c_str())
        )
    );
    cout << "[+] Giai ma thanh cong! File ket qua: " << outFile << "\n";
}
// --- Hàm Mã hóa Lai (Hybrid Envelope) ---
void RSACore::EncryptHybrid(const string& pubFile, const string& inFile, const string& outFile) {
    AutoSeededRandomPool rng;

    // 1. Sinh khóa Session AES-256 và IV ngẫu nhiên
    SecByteBlock aesKey(AES::MAX_KEYLENGTH); // 32 bytes
    rng.GenerateBlock(aesKey, aesKey.size());
    SecByteBlock iv(12); // 12 bytes chuẩn cho GCM
    rng.GenerateBlock(iv, iv.size());

    // 2. Load Public Key và Mã hóa Khóa Session bằng RSA-OAEP
    RSA::PublicKey publicKey;
    FileSource pubFileSrc(pubFile.c_str(), true);
    publicKey.Load(pubFileSrc);
    RSAES<OAEP<SHA256>>::Encryptor rsaEncryptor(publicKey);

    string keyIvData((const char*)aesKey.data(), aesKey.size());
    keyIvData.append((const char*)iv.data(), iv.size());

    string encryptedKeyIv;
    StringSource(keyIvData, true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedKeyIv)
        )
    );

    // 3. Ghi Header Phong bì (Gồm: Kích thước khối khóa RSA + Khối khóa RSA)
    ofstream out(outFile, ios::binary);
    uint32_t keyIvLen = encryptedKeyIv.size();
    out.write((const char*)&keyIvLen, sizeof(keyIvLen));
    out.write(encryptedKeyIv.data(), encryptedKeyIv.size());

    // 4. Mã hóa luồng dữ liệu file gốc bằng AES-GCM và nối trực tiếp vào file xuất
    GCM<AES>::Encryption aesEncryptor;
    aesEncryptor.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());

    cout << "[*] Dang boc file vao Phong bi so Hybrid...\n";
    FileSource(inFile.c_str(), true,
        new AuthenticatedEncryptionFilter(aesEncryptor,
            new FileSink(out)
        )
    );
    out.close();
    cout << "[+] Hoan tat! File Hybrid Envelope: " << outFile << "\n";
}

// --- Hàm Giải mã Lai (Hybrid Envelope) ---
void RSACore::DecryptHybrid(const string& privFile, const string& inFile, const string& outFile) {
    AutoSeededRandomPool rng;

    // 1. Đọc Header Phong bì từ file mã hóa
    ifstream in(inFile, ios::binary);
    uint32_t keyIvLen;
    in.read((char*)&keyIvLen, sizeof(keyIvLen));

    string encryptedKeyIv(keyIvLen, '\0');
    in.read(&encryptedKeyIv[0], keyIvLen);

    // 2. Giải mã Khóa Session bằng RSA Private Key
    RSA::PrivateKey privateKey;
    FileSource privFileSrc(privFile.c_str(), true);
    privateKey.Load(privFileSrc);
    RSAES<OAEP<SHA256>>::Decryptor rsaDecryptor(privateKey);

    string keyIvData;
    StringSource(encryptedKeyIv, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(keyIvData)
        )
    );

    SecByteBlock aesKey((const CryptoPP::byte*)keyIvData.data(), AES::MAX_KEYLENGTH);
    SecByteBlock iv((const CryptoPP::byte*)keyIvData.data() + AES::MAX_KEYLENGTH, 12);

    // 3. Dùng Khóa Session vừa lấy được để giải mã phần dữ liệu còn lại bằng AES-GCM
    GCM<AES>::Decryption aesDecryptor;
    aesDecryptor.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());

    cout << "[*] Dang mo Phong bi so Hybrid...\n";
    FileSource(in, true,
        new AuthenticatedDecryptionFilter(aesDecryptor,
            new FileSink(outFile.c_str())
        )
    );
    cout << "[+] Hoan tat! File goc: " << outFile << "\n";
}