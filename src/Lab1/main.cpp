#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <chrono>

// Nhúng thư viện Crypto++ (Nếu môi trường lỗi, dòng này sẽ báo gạch đỏ)
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/gcm.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;
using namespace CryptoPP;

// Hàm in hướng dẫn sử dụng chuẩn theo tài liệu
void printHelp() {
    cout << "Usage: aestool <command> [options]\n"
        << "Commands:\n"
        << "  encrypt\n"
        << "  decrypt\n"
        << "Options:\n"
        << "  --mode <ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm>\n"
        << "  --in <INFILE> | --text \"...\"\n"
        << "  --out <OUTFILE>\n"
        << "  --key <KEYFILE> | --key-hex <HEX>\n"
        << "  --iv <IVFILE>\n"
        << "  --aead\n"
        << "  --encode <hex|base64|raw>\n";
}

// Hàm mã hóa AES-CBC
void encrypt_AES_CBC(const string& keyHex, const string& inputFile, const string& outputFile) {
    AutoSeededRandomPool prng;

    // 1. Chuyển Key từ dạng Hex string sang byte array
    string keyString;
    StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
    SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());

    // 2. Tự động sinh IV ngẫu nhiên an toàn (Yêu cầu bắt buộc)
    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // In IV ra màn hình để người dùng biết (Lưu ý: Thực tế nên xuất ra file header JSON)
    string ivHex;
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));
    cout << "[+] Tự động sinh IV (Hex): " << ivHex << "\n";

    try {
        // 3. Khởi tạo thuật toán AES chế độ CBC
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // 4. Đọc file -> Mã hóa (tự động Padding) -> Ghi ra file
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(e,
                new FileSink(outputFile.c_str())
            )
        );
        cout << "[+] Ma hoa thanh cong! File luu tai: " << outputFile << "\n";
    }
    catch (const Exception& ex) {
        // Yêu cầu: Fail closed (Đóng an toàn khi có lỗi)
        cerr << "[-] Loi ma hoa: " << ex.what() << "\n";
        exit(1);
    }
}

// Hàm giải mã AES-CBC
void decrypt_AES_CBC(const string& keyHex, const string& ivHex, const string& inputFile, const string& outputFile) {
    try {
        // 1. Chuyển Key và IV từ Hex sang byte array
        string keyString, ivString;
        StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
        StringSource(ivHex, true, new HexDecoder(new StringSink(ivString)));

        SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());
        SecByteBlock iv((const CryptoPP::byte*)ivString.data(), ivString.size());

        // 2. Khởi tạo thuật toán AES chế độ CBC để Giải mã
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // 3. Đọc file -> Giải mã (tự động gỡ Padding) -> Ghi ra file
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(d,
                new FileSink(outputFile.c_str())
            )
        );
        cout << "[+] Giai ma thanh cong! File luu tai: " << outputFile << "\n";
    }
    catch (const CryptoPP::Exception& ex) {
        // Bắt lỗi và Fail closed (Ví dụ: Sai padding do sai key/IV, hoặc file hỏng)
        cerr << "[-] Loi GIAI MA (Fail Closed): " << ex.what() << "\n";
        exit(1);
    }
}

void encrypt_AES_GCM(const string& keyHex, const string& inputFile, const string& outputFile) {
    AutoSeededRandomPool prng;

    // 1. Khởi tạo Key
    string keyString;
    StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
    SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());

    // 2. Tự động sinh IV (Nonce) ngẫu nhiên (AES-GCM thường dùng IV dài 12 bytes = 96 bits)
    const int GCM_IV_SIZE = 12;
    CryptoPP::byte iv[GCM_IV_SIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string ivHex;
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));
    cout << "[+] Tu dong sinh IV (Hex): " << ivHex << "\n";

    try {
        // 3. Khởi tạo thuật toán AES-GCM mã hóa
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

        // 4. Mã hóa và sinh Tag
        // GCM yêu cầu xử lý Tag, độ dài Tag chuẩn là 16 bytes
        const int TAG_SIZE = 16;

        string cipherTextWithTag; // Biến tạm để lưu dữ liệu mã hóa + Tag

        FileSource fs(inputFile.c_str(), true,
            new AuthenticatedEncryptionFilter(e,
                new StringSink(cipherTextWithTag), false, TAG_SIZE
            )
        );

        // 5. Trích xuất Tag ra khỏi chuỗi (Tag thường được đính vào cuối ciphertext)
        string tag = cipherTextWithTag.substr(cipherTextWithTag.length() - TAG_SIZE);
        string cipherText = cipherTextWithTag.substr(0, cipherTextWithTag.length() - TAG_SIZE);

        // In Tag ra màn hình (Hex)
        string tagHex;
        StringSource((const CryptoPP::byte*)tag.data(), tag.size(), true, new HexEncoder(new StringSink(tagHex)));
        cout << "[+] The xac thuc TAG sinh ra (Hex): " << tagHex << "\n";

        // Ghi Ciphertext ra file
        StringSource(cipherText, true, new FileSink(outputFile.c_str()));

        cout << "[+] Ma hoa GCM thanh cong! File luu tai: " << outputFile << "\n";
    }
    catch (const Exception& ex) {
        cerr << "[-] Loi ma hoa GCM: " << ex.what() << "\n";
        exit(1);
    }
}

// Hàm giải mã AES-GCM có kiểm tra Thẻ xác thực (TAG)
void decrypt_AES_GCM(const string& keyHex, const string& ivHex, const string& tagHex, const string& inputFile, const string& outputFile) {
    try {
        // 1. Giải mã Hex cho Key, IV và TAG
        string keyString, ivString, tagString;
        StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
        StringSource(ivHex, true, new HexDecoder(new StringSink(ivString)));
        StringSource(tagHex, true, new HexDecoder(new StringSink(tagString)));

        SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());
        SecByteBlock iv((const CryptoPP::byte*)ivString.data(), ivString.size());

        // 2. Khởi tạo GCM giải mã
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        const int TAG_SIZE = 16;

        // 3. Đọc file mã hóa
        string cipherText;
        FileSource fs(inputFile.c_str(), true, new StringSink(cipherText));

        // Nối Tag vào cuối Ciphertext (Vì Filter của Crypto++ yêu cầu Tag nằm ở cuối)
        string cipherTextWithTag = cipherText + tagString;

        // 4. Đưa qua bộ lọc Giải mã có Xác thực (Authenticated Decryption)
        StringSource ss(cipherTextWithTag, true,
            new AuthenticatedDecryptionFilter(d,
                new FileSink(outputFile.c_str()),
                AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                TAG_SIZE
            )
        );

        cout << "[+] Giai ma GCM thanh cong! Du lieu an toan va nguyen ven.\n";
    }
    catch (const HashVerificationFilter::HashVerificationFailed& ex) {
        // Lỗi này văng ra khi TAG không khớp (File bị sửa lén hoặc sai khóa)
        cerr << "[-] CANH BAO BAO MAT: Xac thuc TAG that bai! Du lieu da bi thay doi hoac sai chia khoa.\n";
        cerr << "[-] Fail Closed: Tu choi giai ma.\n";
        exit(1);
    }
    catch (const Exception& ex) {
        cerr << "[-] Loi he thong GCM: " << ex.what() << "\n";
        exit(1);
    }
}

// Hàm mã hóa AES-ECB (KHÔNG dùng IV)
void encrypt_AES_ECB(const string& keyHex, const string& inputFile, const string& outputFile) {
    try {
        // 1. Chỉ chuyển đổi Key (Không có IV)
        string keyString;
        StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
        SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());

        // 2. Khởi tạo thuật toán AES chế độ ECB
        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, key.size()); // Hàm SetKey thay vì SetKeyWithIV

        // 3. Đọc file -> Mã hóa -> Ghi file
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(e,
                new FileSink(outputFile.c_str())
            )
        );
        cout << "[+] Ma hoa ECB thanh cong! File luu tai: " << outputFile << "\n";
    }
    catch (const CryptoPP::Exception& ex) {
        cerr << "[-] Loi ma hoa ECB: " << ex.what() << "\n";
        exit(1);
    }
}

// Hàm giải mã AES-ECB (KHÔNG dùng IV)
void decrypt_AES_ECB(const string& keyHex, const string& inputFile, const string& outputFile) {
    try {
        string keyString;
        StringSource(keyHex, true, new HexDecoder(new StringSink(keyString)));
        SecByteBlock key((const CryptoPP::byte*)keyString.data(), keyString.size());

        // 2. Khởi tạo giải mã ECB
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, key.size());

        // 3. Đọc file -> Giải mã -> Ghi file
        FileSource fs(inputFile.c_str(), true,
            new StreamTransformationFilter(d,
                new FileSink(outputFile.c_str())
            )
        );
        cout << "[+] Giai ma ECB thanh cong! File luu tai: " << outputFile << "\n";
    }
    catch (const CryptoPP::Exception& ex) {
        cerr << "[-] Loi GIAI MA ECB (Fail Closed): " << ex.what() << "\n";
        exit(1);
    }
}

// Hàm tự động đọc file JSON và chạy KAT (Known Answer Tests)
void run_KAT(const string& jsonFile) {
    try {
        std::ifstream f(jsonFile);
        if (!f.is_open()) {
            cerr << "[-] Loi: Khong the mo file " << jsonFile << "\n";
            exit(1);
        }
        json data = json::parse(f);
        cout << "[*] Dang chay Known Answer Tests (KAT) tu file: " << jsonFile << " ...\n";

        int passed = 0, failed = 0;

        // Xử lý các test case cho AES-CBC
        if (data.contains("AES-CBC")) {
            for (const auto& test : data["AES-CBC"]) {
                string desc = test.value("description", "Unknown Test");
                string keyHex = test["key"];
                string ivHex = test["iv"];
                string ptHex = test["plaintext"];
                string expectedCtHex = test["ciphertext"];

                // 1. Chuyển đổi Hex sang byte
                string keyStr, ivStr, ptStr;
                StringSource(keyHex, true, new HexDecoder(new StringSink(keyStr)));
                StringSource(ivHex, true, new HexDecoder(new StringSink(ivStr)));
                StringSource(ptHex, true, new HexDecoder(new StringSink(ptStr)));

                SecByteBlock key((const CryptoPP::byte*)keyStr.data(), keyStr.size());
                SecByteBlock iv((const CryptoPP::byte*)ivStr.data(), ivStr.size());

                // 2. Chạy mã hóa ngay trong RAM (Memory) để test
                string actualCtStr;
                try {
                    CBC_Mode<AES>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), iv);

                    // Lưu ý: Các Test Vector của NIST thường KHÔNG dùng Padding (NO_PADDING)
                    StringSource(ptStr, true,
                        new StreamTransformationFilter(e,
                            new StringSink(actualCtStr),
                            StreamTransformationFilter::NO_PADDING
                        )
                    );

                    // 3. Chuyển kết quả ra Hex và đối chiếu
                    string actualCtHex;
                    StringSource((const CryptoPP::byte*)actualCtStr.data(), actualCtStr.size(), true,
                        new HexEncoder(new StringSink(actualCtHex)));

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
                catch (const Exception& ex) {
                    cout << "[-] FAIL: " << desc << " (Ngoai le: " << ex.what() << ")\n";
                    failed++;
                }
            }
        }
        cout << "[*] Ket qua KAT -> PASS: " << passed << " | FAIL: " << failed << "\n";
    }
    catch (const json::parse_error& e) {
        cerr << "[-] Loi cu phap JSON: " << e.what() << "\n";
        exit(1);
    }
}

// Hàm tự động đo lường hiệu năng (Benchmark)
void run_benchmark() {
    const double FILE_SIZE_MB = 50.0;
    const string testFile = "bench_in.txt";
    const string outFile = "bench_out.bin";
    const string keyHex = "00112233445566778899AABBCCDDEEFF"; // Dùng tạm key 16 byte

    cout << "[*] Dang tao file du lieu ao " << FILE_SIZE_MB << " MB de test (Vui long doi)...\n";
    std::ofstream ofs(testFile, std::ios::binary);
    if (!ofs) { cerr << "[-] Loi tao file test!\n"; return; }

    // Ghi 50 lần, mỗi lần 1MB ký tự 'A'
    std::string dummyData(1024 * 1024, 'A');
    for (int i = 0; i < FILE_SIZE_MB; ++i) {
        ofs << dummyData;
    }
    ofs.close();

    cout << "\n=========================================================\n";
    cout << "[*] KET QUA BENCHMARK (Kich thuoc file: " << FILE_SIZE_MB << " MB)\n";
    cout << "=========================================================\n";

    // --- 1. Đo chế độ ECB ---
    // (Lưu ý: Gọi thẳng hàm encrypt_AES_ECB ở đây sẽ lách được chốt chặn 16KB ở main)
    auto start = std::chrono::high_resolution_clock::now();
    encrypt_AES_ECB(keyHex, testFile, outFile);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> ecb_ms = end - start;
    cout << " ---> [KET QUA ECB] Latency: " << ecb_ms.count() << " ms | Throughput: "
        << (FILE_SIZE_MB / (ecb_ms.count() / 1000.0)) << " MB/s\n\n";

    // --- 2. Đo chế độ CBC ---
    start = std::chrono::high_resolution_clock::now();
    encrypt_AES_CBC(keyHex, testFile, outFile);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> cbc_ms = end - start;
    cout << " ---> [KET QUA CBC] Latency: " << cbc_ms.count() << " ms | Throughput: "
        << (FILE_SIZE_MB / (cbc_ms.count() / 1000.0)) << " MB/s\n\n";

    // --- 3. Đo chế độ GCM ---
    start = std::chrono::high_resolution_clock::now();
    encrypt_AES_GCM(keyHex, testFile, outFile);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> gcm_ms = end - start;
    cout << " ---> [KET QUA GCM] Latency: " << gcm_ms.count() << " ms | Throughput: "
        << (FILE_SIZE_MB / (gcm_ms.count() / 1000.0)) << " MB/s\n";

    cout << "=========================================================\n";
    cout << "[*] Hoan tat! Hay copy cac so lieu nay vao bang trong Báo cáo.\n";
}

int main(int argc, char* argv[]) {
    // Yêu cầu: Fail closed nếu đầu vào không hợp lệ
    if (argc < 2) {
        cerr << "Error: Missing command.\n";
        printHelp();
        return 1;
    }

    string command = argv[1];

    // === THÊM ĐOẠN NÀY ĐỂ BẮT LỆNH --kat ===
    if (command == "--kat") {
        if (argc >= 3) {
            run_KAT(argv[2]); // argv[2] chính là tên file vectors.json
            return 0;         // Chạy xong chấm điểm thì thoát luôn
        }
        else {
            cerr << "[-] Loi: Thieu ten file JSON. Vi du: aestool --kat vectors.json\n";
            return 1;
        }
    }
    // =======================================
    // === THÊM NHÁNH NÀY CHO BENCHMARK ===
    if (command == "benchmark") {
        run_benchmark();
        return 0;
    }
    // ====================================

    map<string, string> args;

    // Phân tích đối số dòng lệnh (CLI Parser)
    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];

        // CẬP NHẬT Ở ĐÂY: Dạy cho parser biết --allow-ecb là một cờ hợp lệ
        if (arg == "--aead" || arg == "--allow-ecb") {
            args[arg] = "true";
        }
        else if (i + 1 < argc && arg.rfind("--", 0) == 0) {
            args[arg] = argv[++i];
        }
    }

    if (command == "encrypt") {
        cout << "[*] Bat dau qua trinh MA HOA...\n";
        if (args.count("--mode")) cout << "[-] Che do (Mode): " << args["--mode"] << "\n";

        // === CHỐT CHẶN BẢO MẬT: MISUSE PREVENTION (ECB) ===
        if (args["--mode"] == "ecb") {
            if (args.count("--key-hex") && args.count("--in") && args.count("--out")) {

                // 1. KIỂM TRA DUNG LƯỢNG FILE TRƯỚC
                std::ifstream inFile(args["--in"], std::ios::binary | std::ios::ate);
                if (inFile.is_open()) {
                    std::streamsize fileSize = inFile.tellg();
                    inFile.close();
                    const int MAX_ECB_SIZE = 16 * 1024; // Giới hạn 16 KB

                    if (fileSize > MAX_ECB_SIZE) {
                        if (args.count("--allow-ecb")) {
                            cout << "[!] CANH BAO BAO MAT: Ban dang co tinh dung ECB de ma hoa file lon (" << fileSize << " bytes). Dieu nay cuc ky nguy hiem!\n";
                        }
                        else {
                            cerr << "[-] LOI BAO MAT (Fail Closed): Che do ECB khong an toan cho file > 16KB.\n";
                            cerr << "    Giai phap: Hay chuyen sang dung CBC hoac GCM.\n";
                            cerr << "    De ep buoc chay, hay them tham so: --allow-ecb\n";
                            exit(1); // Chặn đứng chương trình ngay tại đây!
                        }
                    }
                    else {
                        cout << "[!] CANH BAO: Che do ECB la che do kem an toan nhat. Khuyen nghi dung CBC/GCM.\n";
                    }
                }

                // 2. NẾU QUA ĐƯỢC CHỐT CHẶN THÌ MỚI GỌI HÀM MÃ HÓA
                encrypt_AES_ECB(args["--key-hex"], args["--in"], args["--out"]);
            }
            else {
                cerr << "[-] Loi: Thieu tham so cho qua trinh ma hoa ECB.\n";
            }
        }
        else if (args["--mode"] == "gcm") {
            if (args.count("--key-hex") && args.count("--in") && args.count("--out")) {
                encrypt_AES_GCM(args["--key-hex"], args["--in"], args["--out"]);
            }
            else {
                cerr << "[-] Loi: Thieu tham so cho qua trinh ma hoa GCM.\n";
            }
        }

    }
    else if (command == "decrypt") {
        cout << "[*] Bat dau qua trinh GIAI MA...\n";
        if (args.count("--mode")) cout << "[-] Che do (Mode): " << args["--mode"] << "\n";

        if (args["--mode"] == "cbc") {
            // Giải mã thì bắt buộc phải có thêm IV
            if (args.count("--key-hex") && args.count("--iv") && args.count("--in") && args.count("--out")) {
                decrypt_AES_CBC(args["--key-hex"], args["--iv"], args["--in"], args["--out"]);
            }
            else {
                cerr << "[-] Loi: Thieu tham so cho qua trinh giai ma CBC (Kiem tra lai Key hoac IV).\n";
            }
        }
        else if (args["--mode"] == "ecb") {
            // Không yêu cầu --iv
            if (args.count("--key-hex") && args.count("--in") && args.count("--out")) {
                decrypt_AES_ECB(args["--key-hex"], args["--in"], args["--out"]);
            }
            else {
                cerr << "[-] Loi: Thieu tham so cho qua trinh giai ma ECB.\n";
            }
        }
        // Nhánh xử lý giải mã GCM
        else if (args["--mode"] == "gcm") {
            // Giả sử dùng cờ --encode để truyền TAG vào (hoặc bạn có thể đổi thành --tag tùy ý)
            if (args.count("--key-hex") && args.count("--iv") && args.count("--encode") && args.count("--in") && args.count("--out")) {
                decrypt_AES_GCM(args["--key-hex"], args["--iv"], args["--encode"], args["--in"], args["--out"]);
            }
            else {
                cerr << "[-] Loi: Thieu tham so cho GCM (Can co --key-hex, --iv, --encode de truyen TAG, --in, --out).\n";
            }
        }

    }
    
    else {
        cerr << "Error: Unknown command '" << command << "'\n";
        printHelp();
        return 1;
    }

    return 0;
}