#include <iostream>
#include <string>
#include <map>
#include <chrono>
#include <vector>
#include <fstream>
#include "rsa_core.h"

using namespace std;

// === MODULE BENCHMARK TỰ ĐỘNG CHO LAB 3 ===
void runBenchmark() {
    cout << "\n=========================================================\n";
    cout << "[*] BENCHMARK HYBRID ENCRYPTION (RSA-3072 + AES-256-GCM)\n";
    cout << "=========================================================\n";

    // 1. Tạo cặp khóa dùng một lần cho quá trình test
    string pub = "bench_pub.der";
    string priv = "bench_priv.der";
    cout << "[*] Dang tao khoa RSA 3072-bit cho Benchmark (Vui long doi)...\n";
    RSACore::GenerateKeys(3072, pub, priv);

    // Test với 1 MiB và 100 MiB
    vector<size_t> fileSizes = { 1, 100 };

    for (size_t sizeMB : fileSizes) {
        size_t bytes = sizeMB * 1024 * 1024;
        string inFile = "bench_" + to_string(sizeMB) + "MB.dat";
        string encFile = inFile + ".enc";

        // 2. Tạo file rác ảo trên ổ cứng để test thực tế
        vector<uint8_t> dummyData(bytes, 0x41); // Ghi toàn chữ 'A'
        ofstream out(inFile, ios::binary);
        out.write(reinterpret_cast<const char*>(dummyData.data()), bytes);
        out.close();

        // 3. Bấm giờ quá trình Mã hóa Lai (Hybrid)
        auto start = chrono::high_resolution_clock::now();
        RSACore::EncryptHybrid(pub, inFile, encFile);
        auto end = chrono::high_resolution_clock::now();

        // Tính toán
        chrono::duration<double, std::milli> duration_ms = end - start;
        double throughput = sizeMB / (duration_ms.count() / 1000.0);

        cout << " ---> [File " << sizeMB << " MiB] Latency: " << duration_ms.count()
            << " ms | Throughput: " << throughput << " MB/s\n\n";
    }
    cout << "=========================================================\n";
    cout << "[+] Da hoan tat Benchmark! Ban co the lay so lieu dien vao bao cao.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "[-] Loi: Vui long nhap lenh (keygen, encrypt, decrypt, encrypt-hybrid, decrypt-hybrid, benchmark).\n";
        return 1;
    }

    string command = argv[1];

    // Lệnh Benchmark
    if (command == "benchmark") {
        try { runBenchmark(); }
        catch (const exception& e) { cerr << "[-] Loi Benchmark: " << e.what() << "\n"; return 1; }
        return 0;
    }

    map<string, string> args;
    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];
        if (i + 1 < argc && arg.rfind("--", 0) == 0) {
            args[arg] = argv[++i];
        }
    }

    // Lệnh Sinh Khóa
    if (command == "keygen") {
        int bits = 3072;
        if (args.count("--bits")) bits = stoi(args["--bits"]);
        string pubFile = args.count("--pub") ? args["--pub"] : "pub.pem";
        string privFile = args.count("--priv") ? args["--priv"] : "priv.pem";
        try { RSACore::GenerateKeys(bits, pubFile, privFile); }
        catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; return 1; }
    }
    // Lệnh Mã hóa RSA thuần
    else if (command == "encrypt") {
        if (!args.count("--pub") || !args.count("--in") || !args.count("--out")) return 1;
        try { RSACore::Encrypt(args["--pub"], args["--in"], args["--out"]); }
        catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; return 1; }
    }
    // Lệnh Giải mã RSA thuần
    else if (command == "decrypt") {
        if (!args.count("--priv") || !args.count("--in") || !args.count("--out")) return 1;
        try { RSACore::Decrypt(args["--priv"], args["--in"], args["--out"]); }
        catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; return 1; }
    }
    // Lệnh Mã hóa Hybrid
    else if (command == "encrypt-hybrid") {
        if (!args.count("--pub") || !args.count("--in") || !args.count("--out")) return 1;
        try { RSACore::EncryptHybrid(args["--pub"], args["--in"], args["--out"]); }
        catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; return 1; }
    }
    // Lệnh Giải mã Hybrid
    else if (command == "decrypt-hybrid") {
        if (!args.count("--priv") || !args.count("--in") || !args.count("--out")) return 1;
        try { RSACore::DecryptHybrid(args["--priv"], args["--in"], args["--out"]); }
        catch (const exception& e) { cerr << "[-] Loi: " << e.what() << "\n"; return 1; }
    }
    else {
        cerr << "[-] Lenh khong hop le.\n";
        return 1;
    }

    return 0;
}