#include "sig_core.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <iomanip>

#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>

using namespace CryptoPP;
using namespace std;

// --- 1. SINH KHÓA ---
void SigCore::GenerateKeys(const string& algo, const string& pubFile, const string& privFile) {
    AutoSeededRandomPool rng;
    try {
        if (algo == "ecdsa-p256") {
            cout << "[*] Dang sinh cap khoa ECDSA (P-256)...\n";
            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            privateKey.Initialize(rng, ASN1::secp256r1()); // Chuẩn curve P-256
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            privateKey.MakePublicKey(publicKey);

            FileSink privSink(privFile.c_str(), true); privateKey.Save(privSink);
            FileSink pubSink(pubFile.c_str(), true); publicKey.Save(pubSink);
        }
        else if (algo == "rsa-pss-3072") {
            cout << "[*] Dang sinh cap khoa RSA-PSS (3072-bit)...\n";
            InvertibleRSAFunction params;
            params.GenerateRandomWithKeySize(rng, 3072);
            RSA::PrivateKey privateKey(params);
            RSA::PublicKey publicKey(params);

            FileSink privSink(privFile.c_str(), true); privateKey.Save(privSink);
            FileSink pubSink(pubFile.c_str(), true); publicKey.Save(pubSink);
        }
        else {
            cerr << "[-] Thuat toan khong hop le!\n"; return;
        }
        cout << "[+] Luu PublicKey tai:  " << pubFile << "\n";
        cout << "[+] Luu PrivateKey tai: " << privFile << "\n";
    }
    catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; }
}

// --- 2. KÝ FILE (DETACHED SIGNATURE) ---
void SigCore::SignFile(const string& algo, const string& privFile, const string& inFile, const string& sigFile) {
    AutoSeededRandomPool rng;
    try {
        if (algo == "ecdsa-p256") {
            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            FileSource privSource(privFile.c_str(), true); privateKey.Load(privSource);

            ECDSA<ECP, SHA256>::Signer signer(privateKey);
            FileSource(inFile.c_str(), true, new SignerFilter(rng, signer, new FileSink(sigFile.c_str())));
        }
        else if (algo == "rsa-pss-3072") {
            RSA::PrivateKey privateKey;
            FileSource privSource(privFile.c_str(), true); privateKey.Load(privSource);

            RSASS<PSS, SHA256>::Signer signer(privateKey); // Chuẩn RSA-PSS
            FileSource(inFile.c_str(), true, new SignerFilter(rng, signer, new FileSink(sigFile.c_str())));
        }
        else { cerr << "[-] Thuat toan khong hop le!\n"; return; }
        cout << "[+] Ky thanh cong! Chu ky luu tai: " << sigFile << "\n";
    }
    catch (const exception& e) { cerr << "[-] Loi khi ky: " << e.what() << "\n"; }
}

// --- 3. XÁC MINH CHỮ KÝ ---
void SigCore::VerifySignature(const string& algo, const string& pubFile, const string& inFile, const string& sigFile) {
    try {
        bool result = false;
        string signature, message;
        FileSource(sigFile.c_str(), true, new StringSink(signature));
        FileSource(inFile.c_str(), true, new StringSink(message));

        // Tách riêng bước ép kiểu sang con trỏ uint8_t để MSVC không bị bối rối
        const uint8_t* msgPtr = reinterpret_cast<const uint8_t*>(message.data());
        const uint8_t* sigPtr = reinterpret_cast<const uint8_t*>(signature.data());

        if (algo == "ecdsa-p256") {
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            FileSource pubSource(pubFile.c_str(), true); publicKey.Load(pubSource);

            ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
            result = verifier.VerifyMessage(msgPtr, message.size(), sigPtr, signature.size());
        }
        else if (algo == "rsa-pss-3072") {
            RSA::PublicKey publicKey;
            FileSource pubSource(pubFile.c_str(), true); publicKey.Load(pubSource);

            RSASS<PSS, SHA256>::Verifier verifier(publicKey);
            result = verifier.VerifyMessage(msgPtr, message.size(), sigPtr, signature.size());
        }

        if (result) {
            cout << "[+] XAC MINH THANH CONG: Chu ky HOP LE!\n";
        }
        else {
            cout << "[-] XAC MINH THAT BAI: Du lieu bi thay doi hoac chu ky gia mao!\n";
        }
    }
    catch (const exception& e) { cerr << "[-] Loi xac minh: " << e.what() << "\n"; }
}
// --- 4. BENCHMARK HIỆU NĂNG ---
void SigCore::Benchmark(const string& algo) {
    cout << "=========================================================\n";
    cout << "[*] BENCHMARK THUAT TOAN: " << algo << "\n";
    cout << "=========================================================\n";

    AutoSeededRandomPool rng;
    // Các mốc dung lượng theo yêu cầu bài Lab: 1KB, 16KB, 1MB, 8MB
    vector<size_t> sizes = { 1024, 16384, 1048576, 8388608 };
    vector<string> sizeNames = { "1 KiB", "16 KiB", "1 MiB", "8 MiB" };

    // Sinh khóa trên RAM để test
    ECDSA<ECP, SHA256>::PrivateKey ecPriv;
    ECDSA<ECP, SHA256>::PublicKey ecPub;
    RSA::PrivateKey rsaPriv;
    RSA::PublicKey rsaPub;

    if (algo == "ecdsa-p256") {
        ecPriv.Initialize(rng, ASN1::secp256r1());
        ecPriv.MakePublicKey(ecPub);
    }
    else if (algo == "rsa-pss-3072") {
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 3072);
        rsaPriv = RSA::PrivateKey(params);
        rsaPub = RSA::PublicKey(params);
    }
    else {
        cerr << "[-] Thuat toan khong ho tro!\n"; return;
    }

    for (size_t i = 0; i < sizes.size(); i++) {
        string message(sizes[i], 'A'); // Tạo payload giả
        string signature;

        int iterations = (sizes[i] >= 1048576) ? 5 : 50; // Payload lớn thì test ít lại để đỡ chờ lâu

        // Bấm giờ Ký (Sign)
        auto startSign = chrono::high_resolution_clock::now();
        for (int j = 0; j < iterations; j++) {
            signature.clear();
            if (algo == "ecdsa-p256") {
                ECDSA<ECP, SHA256>::Signer signer(ecPriv);
                StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));
            }
            else {
                RSASS<PSS, SHA256>::Signer signer(rsaPriv);
                StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));
            }
        }
        auto endSign = chrono::high_resolution_clock::now();
        double timeSignMs = chrono::duration<double, std::milli>(endSign - startSign).count() / iterations;

        // Bấm giờ Xác minh (Verify)
        auto startVerify = chrono::high_resolution_clock::now();
        for (int j = 0; j < iterations; j++) {
            bool result = false;
            const uint8_t* msgPtr = reinterpret_cast<const uint8_t*>(message.data());
            const uint8_t* sigPtr = reinterpret_cast<const uint8_t*>(signature.data());

            if (algo == "ecdsa-p256") {
                ECDSA<ECP, SHA256>::Verifier verifier(ecPub);
                result = verifier.VerifyMessage(msgPtr, message.size(), sigPtr, signature.size());
            }
            else {
                RSASS<PSS, SHA256>::Verifier verifier(rsaPub);
                result = verifier.VerifyMessage(msgPtr, message.size(), sigPtr, signature.size());
            }
        }
        auto endVerify = chrono::high_resolution_clock::now();
        double timeVerifyMs = chrono::duration<double, std::milli>(endVerify - startVerify).count() / iterations;

        cout << "[+] Kich thuoc: " << sizeNames[i] << "\n";
        cout << "    - Latency (Sign):   " << fixed << setprecision(3) << timeSignMs << " ms/op\n";
        cout << "    - Latency (Verify): " << fixed << setprecision(3) << timeVerifyMs << " ms/op\n";
        cout << "---------------------------------------------------------\n";
    }
}