#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <iomanip>
#include <sstream>              // Thêm thư viện này để dùng stringstream
#include <nlohmann/json.hpp>    // Thêm thư viện này để dùng JSON
#include "ctr_mode.h"
#include <chrono>

using namespace std;
using json = nlohmann::json;

// Hàm tự động dịch chuỗi Hex sang mảng Byte (Pure C++)
vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Hàm thực thi Known Answer Tests (KATs) cho chế độ CTR
void runKAT(const string& filename) {
    try {
        ifstream f(filename);
        if (!f.is_open()) {
            cerr << "[-] Loi: Khong the mo file KAT " << filename << "\n";
            return;
        }
        json data = json::parse(f);
        cout << "[*] Dang chay Known Answer Tests (KAT) tu file: " << filename << " ...\n";

        int passed = 0, failed = 0;

        if (data.contains("AES-128-CTR")) {
            for (const auto& test : data["AES-128-CTR"]) {
                string desc = test.value("description", "Unknown Test");
                string keyHex = test["key"];
                string ivHex = test["iv"];
                string ptHex = test["plaintext"];
                string expectedCtHex = test["ciphertext"];

                vector<uint8_t> key = hexToBytes(keyHex);
                vector<uint8_t> iv = hexToBytes(ivHex);
                vector<uint8_t> pt = hexToBytes(ptHex);
                vector<uint8_t> actualCt(pt.size());

                // Khởi tạo CTR Mode
                CTRMode ctr(key.data(), iv.data());

                // Xử lý dữ liệu
                ctr.ProcessData(pt.data(), actualCt.data(), pt.size());

                // Chuyển kết quả về Hex
                stringstream ss;
                ss << hex << setfill('0');
                for (int i = 0; i < actualCt.size(); ++i) {
                    ss << setw(2) << static_cast<int>(actualCt[i]);
                }
                string actualCtHex = ss.str();

                if (actualCtHex == expectedCtHex) {
                    cout << "[+] PASS: " << desc << "\n";
                    passed++;
                }
                else {
                    cout << "[-] FAIL: " << desc << "\n";
                    cout << "    Expected: " << expectedCtHex << "\n";
                    cout << "    Actual:   " << actualCtHex << "\n";
                    failed++;
                }
            }
        }
        cout << "------------------------------------------\n";
        cout << "[*] Ket qua KAT: PASS " << passed << " | FAIL " << failed << "\n";
    }
    catch (const json::parse_error& e) {
        cerr << "[-] Loi cu phap JSON: " << e.what() << "\n";
    }
    catch (const exception& e) {
        cerr << "[-] Loi KAT: " << e.what() << "\n";
    }
}

// Hàm tự động đo lường hiệu năng (Benchmark) cho C++ thuần
void runBenchmark() {
    const string keyHex = "00112233445566778899AABBCCDDEEFF";
    const string ivHex = "00000000000000000000000000000000";
    vector<uint8_t> key = hexToBytes(keyHex);
    vector<uint8_t> iv = hexToBytes(ivHex);

    // Test với 1 MiB và 100 MiB [cite: 517-518]
    vector<size_t> fileSizes = { 1, 100 };

    cout << "\n=========================================================\n";
    cout << "[*] BENCHMARK PURE C++ (AES-128-CTR)\n";
    cout << "=========================================================\n";

    for (size_t sizeMB : fileSizes) {
        size_t bytes = sizeMB * 1024 * 1024;
        // Tạo mảng dữ liệu ảo trên RAM
        vector<uint8_t> dummyData(bytes, 0x41);
        vector<uint8_t> outData(bytes);

        // Khởi tạo CTR Mode
        CTRMode ctr(key.data(), iv.data());

        // Bắt đầu bấm giờ
        auto start = chrono::high_resolution_clock::now();
        ctr.ProcessData(dummyData.data(), outData.data(), bytes);
        auto end = chrono::high_resolution_clock::now();

        // Tính toán kết quả
        chrono::duration<double, std::milli> duration_ms = end - start;
        double throughput = sizeMB / (duration_ms.count() / 1000.0);

        cout << " ---> [File " << sizeMB << " MiB] Latency: " << duration_ms.count()
            << " ms | Throughput: " << throughput << " MB/s\n";
    }
    cout << "=========================================================\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "[-] Loi: Vui long nhap lenh (encrypt, decrypt hoac --kat).\n";
        return 1;
    }

    string command = argv[1];

    // Bắt lệnh chạy KAT
    if (command == "--kat") {
        if (argc >= 3) {
            runKAT(argv[2]);
            return 0;
        }
        else {
            cerr << "[-] Loi: Thieu ten file JSON. Vi du: aestool --kat vectors.json\n";
            return 1;
        }
    }
    // === THÊM ĐOẠN NÀY ĐỂ CHẠY BENCHMARK ===
    if (command == "benchmark") {
        runBenchmark();
        return 0;
    }

    map<string, string> args;
    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];
        if (i + 1 < argc && arg.rfind("--", 0) == 0) {
            args[arg] = argv[++i];
        }
    }

    // Chốt chặn xác thực đầu vào
    if (command == "encrypt" || command == "decrypt") {
        if (!args.count("--mode") || args["--mode"] != "ctr") {
            cerr << "[-] Loi: Lab 2 chi ho tro che do --mode ctr\n";
            return 1;
        }
        if (!args.count("--key-hex") || !args.count("--iv") || !args.count("--in") || !args.count("--out")) {
            cerr << "[-] Loi: Thieu tham so. Cu phap chuan:\n";
            cerr << "    aestool encrypt --mode ctr --key-hex <16-byte-hex> --iv <16-byte-hex> --in <file> --out <file>\n";
            return 1;
        }

        vector<uint8_t> key = hexToBytes(args["--key-hex"]);
        vector<uint8_t> iv = hexToBytes(args["--iv"]);

        if (key.size() != 16) {
            cerr << "[-] LOI BAO MAT: Key phai co do dai dung 16 bytes (32 ky tu hex).\n";
            return 1;
        }
        if (iv.size() != 16) {
            cerr << "[-] LOI BAO MAT: IV (Nonce) phai co do dai dung 16 bytes (32 ky tu hex).\n";
            return 1;
        }

        try {
            CTRMode ctr(key.data(), iv.data());
            ifstream inFile(args["--in"], ios::binary);
            if (!inFile) {
                cerr << "[-] Loi: Khong the mo file dau vao: " << args["--in"] << "\n";
                return 1;
            }

            ofstream outFile(args["--out"], ios::binary);
            if (!outFile) {
                cerr << "[-] Loi: Khong the tao file dau ra: " << args["--out"] << "\n";
                return 1;
            }

            const size_t CHUNK_SIZE = 4096;
            vector<uint8_t> bufferIn(CHUNK_SIZE);
            vector<uint8_t> bufferOut(CHUNK_SIZE);

            cout << "[*] Dang xu ly du lieu (Che do CTR - Pure C++)...\n";

            while (inFile.read(reinterpret_cast<char*>(bufferIn.data()), CHUNK_SIZE) || inFile.gcount() > 0) {
                size_t bytesRead = inFile.gcount();
                ctr.ProcessData(bufferIn.data(), bufferOut.data(), bytesRead);
                outFile.write(reinterpret_cast<const char*>(bufferOut.data()), bytesRead);
            }

            inFile.close();
            outFile.close();

            cout << "[+] Thanh cong! File ket qua duoc luu tai: " << args["--out"] << "\n";

        }
        catch (const exception& ex) {
            cerr << "[-] LOI HE THONG (Fail Closed): " << ex.what() << "\n";
            return 1;
        }
    }
    else {
        cerr << "[-] Loi: Lenh khong hop le.\n";
        return 1;
    }

    return 0;
}