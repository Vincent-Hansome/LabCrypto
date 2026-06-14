#include "pq_core.h"
#include <oqs/oqs.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>

#include <chrono>
#include <iomanip>

using namespace std;

// Hàm tiện ích đọc/ghi file nhị phân
static vector<uint8_t> ReadFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) throw runtime_error("Khong the mo file: " + filename);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<uint8_t> buffer(size);
    if (file.read((char*)buffer.data(), size)) return buffer;
    throw runtime_error("Loi doc file");
}

static void WriteFile(const string& filename, const uint8_t* data, size_t len) {
    ofstream file(filename, ios::binary);
    if (!file) throw runtime_error("Khong the ghi file: " + filename);
    file.write((const char*)data, len);
}

// 1. SINH KHÓA (ML-DSA hoặc ML-KEM)
void PQCore::GenerateKey(const string& algo, const string& pubFile, const string& privFile) {
    if (algo == "mldsa-44") {
        OQS_SIG* sig = OQS_SIG_new("ML-DSA-44");
        if (!sig) sig = OQS_SIG_new("Dilithium2"); // Fallback cho version cũ của liboqs
        if (!sig) throw runtime_error("Thu vien khong ho tro ML-DSA-44");

        vector<uint8_t> pubKey(sig->length_public_key);
        vector<uint8_t> privKey(sig->length_secret_key);

        if (OQS_SIG_keypair(sig, pubKey.data(), privKey.data()) != OQS_SUCCESS) {
            OQS_SIG_free(sig); throw runtime_error("Loi sinh khoa ML-DSA");
        }
        WriteFile(pubFile, pubKey.data(), pubKey.size());
        WriteFile(privFile, privKey.data(), privKey.size());
        OQS_SIG_free(sig);
        cout << "[+] Da sinh cap khoa Chu ky hau luong tu (ML-DSA-44) thanh cong!\n";
    }
    else if (algo == "mlkem-512") {
        OQS_KEM* kem = OQS_KEM_new("ML-KEM-512");
        if (!kem) kem = OQS_KEM_new("Kyber512");
        if (!kem) throw runtime_error("Thu vien khong ho tro ML-KEM-512");

        vector<uint8_t> pubKey(kem->length_public_key);
        vector<uint8_t> privKey(kem->length_secret_key);

        if (OQS_KEM_keypair(kem, pubKey.data(), privKey.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem); throw runtime_error("Loi sinh khoa ML-KEM");
        }
        WriteFile(pubFile, pubKey.data(), pubKey.size());
        WriteFile(privFile, privKey.data(), privKey.size());
        OQS_KEM_free(kem);
        cout << "[+] Da sinh cap khoa Dong goi KEM (ML-KEM-512) thanh cong!\n";
    }
    else {
        cerr << "[-] Thuat toan khong hop le (Dung mldsa-44 hoac mlkem-512)\n";
    }
}

// 2. KÝ TÊN (SIGN)
void PQCore::Sign(const string& algo, const string& privFile, const string& inFile, const string& sigFile) {
    if (algo != "mldsa-44") { cerr << "[-] Chi ho tro mldsa-44 de ky!\n"; return; }
    OQS_SIG* sig = OQS_SIG_new("ML-DSA-44");
    if (!sig) sig = OQS_SIG_new("Dilithium2");

    vector<uint8_t> privKey = ReadFile(privFile);
    vector<uint8_t> message = ReadFile(inFile);
    vector<uint8_t> signature(sig->length_signature);
    size_t sigLen = 0;

    if (OQS_SIG_sign(sig, signature.data(), &sigLen, message.data(), message.size(), privKey.data()) == OQS_SUCCESS) {
        WriteFile(sigFile, signature.data(), sigLen);
        cout << "[+] Ky thanh cong! Chu ky luu tai: " << sigFile << "\n";
    }
    else {
        cerr << "[-] Loi khi ky chu ky ML-DSA!\n";
    }
    OQS_SIG_free(sig);
}

// 3. XÁC MINH (VERIFY)
void PQCore::Verify(const string& algo, const string& pubFile, const string& inFile, const string& sigFile) {
    if (algo != "mldsa-44") return;
    OQS_SIG* sig = OQS_SIG_new("ML-DSA-44");
    if (!sig) sig = OQS_SIG_new("Dilithium2");

    vector<uint8_t> pubKey = ReadFile(pubFile);
    vector<uint8_t> message = ReadFile(inFile);
    vector<uint8_t> signature = ReadFile(sigFile);

    if (OQS_SIG_verify(sig, message.data(), message.size(), signature.data(), signature.size(), pubKey.data()) == OQS_SUCCESS) {
        cout << "[+] XAC MINH THANH CONG: Chu ky PQC HOP LE!\n";
    }
    else {
        cout << "[-] XAC MINH THAT BAI: Du lieu bi thay doi hoac chu ky gia mao!\n";
    }
    OQS_SIG_free(sig);
}

// 4. ENCAPSULATE (Đóng gói khóa KEM)
void PQCore::Encapsulate(const string& algo, const string& pubFile, const string& ctFile, const string& ssFile) {
    if (algo != "mlkem-512") return;
    OQS_KEM* kem = OQS_KEM_new("ML-KEM-512");
    if (!kem) kem = OQS_KEM_new("Kyber512");

    vector<uint8_t> pubKey = ReadFile(pubFile);
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    vector<uint8_t> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), pubKey.data()) == OQS_SUCCESS) {
        WriteFile(ctFile, ciphertext.data(), ciphertext.size());
        WriteFile(ssFile, sharedSecret.data(), sharedSecret.size());
        cout << "[+] Encapsulate thanh cong! (Da sinh Ciphertext va Shared Secret)\n";
    }
    else {
        cerr << "[-] Loi Encapsulate ML-KEM!\n";
    }
    OQS_KEM_free(kem);
}

// 5. DECAPSULATE (Mở gói khóa KEM)
void PQCore::Decapsulate(const string& algo, const string& privFile, const string& ctFile, const string& ssFile) {
    if (algo != "mlkem-512") return;
    OQS_KEM* kem = OQS_KEM_new("ML-KEM-512");
    if (!kem) kem = OQS_KEM_new("Kyber512");

    vector<uint8_t> privKey = ReadFile(privFile);
    vector<uint8_t> ciphertext = ReadFile(ctFile);
    vector<uint8_t> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, sharedSecret.data(), ciphertext.data(), privKey.data()) == OQS_SUCCESS) {
        WriteFile(ssFile, sharedSecret.data(), sharedSecret.size());
        cout << "[+] Decapsulate thanh cong! (Da khoi phuc Shared Secret tu Ciphertext)\n";
    }
    else {
        cerr << "[-] Loi Decapsulate ML-KEM!\n";
    }
    OQS_KEM_free(kem);
}

// --- 6. BENCHMARK HIỆU NĂNG LƯỢNG TỬ ---
void PQCore::Benchmark(const string& algo) {
    cout << "=========================================================\n";
    cout << "[*] BENCHMARK THUAT TOAN PQC: " << algo << "\n";
    cout << "=========================================================\n";

    int iterations = 100; // Chạy 100 vòng lặp để lấy trung bình
    vector<uint8_t> message(1024, 'A'); // Payload 1KB giả lập

    if (algo == "mldsa-44") {
        OQS_SIG* sig = OQS_SIG_new("ML-DSA-44");
        if (!sig) sig = OQS_SIG_new("Dilithium2");

        vector<uint8_t> pubKey(sig->length_public_key);
        vector<uint8_t> privKey(sig->length_secret_key);
        vector<uint8_t> signature(sig->length_signature);
        size_t sigLen;

        auto start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_SIG_keypair(sig, pubKey.data(), privKey.data());
        auto end = chrono::high_resolution_clock::now();
        cout << " - Latency (KeyGen): " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_SIG_sign(sig, signature.data(), &sigLen, message.data(), message.size(), privKey.data());
        end = chrono::high_resolution_clock::now();
        cout << " - Latency (Sign):   " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_SIG_verify(sig, message.data(), message.size(), signature.data(), sigLen, pubKey.data());
        end = chrono::high_resolution_clock::now();
        cout << " - Latency (Verify): " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        OQS_SIG_free(sig);
    }
    else if (algo == "mlkem-512") {
        OQS_KEM* kem = OQS_KEM_new("ML-KEM-512");
        if (!kem) kem = OQS_KEM_new("Kyber512");

        vector<uint8_t> pubKey(kem->length_public_key);
        vector<uint8_t> privKey(kem->length_secret_key);
        vector<uint8_t> ciphertext(kem->length_ciphertext);
        vector<uint8_t> sharedSecret(kem->length_shared_secret);

        auto start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_KEM_keypair(kem, pubKey.data(), privKey.data());
        auto end = chrono::high_resolution_clock::now();
        cout << " - Latency (KeyGen): " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), pubKey.data());
        end = chrono::high_resolution_clock::now();
        cout << " - Latency (Encaps): " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) OQS_KEM_decaps(kem, sharedSecret.data(), ciphertext.data(), privKey.data());
        end = chrono::high_resolution_clock::now();
        cout << " - Latency (Decaps): " << fixed << setprecision(3) << chrono::duration<double, std::milli>(end - start).count() / iterations << " ms/op\n";

        OQS_KEM_free(kem);
    }
}