#include "hash_core.h"
#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h> // Thêm thư viện hỗ trợ SHAKE
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;
using namespace std;

void HashCore::ComputeHash(const string& algo, const string& inFile, int outLen) {
    string digest;
    cout << "[*] Dang tinh bam file: " << inFile << " bang thuat toan " << algo << "...\n";

    try {
        // Hàm Lambda tối ưu hóa việc đọc file theo luồng (Streaming Mode)
        auto hashFile = [&](HashTransformation& hash) {
            FileSource(inFile.c_str(), true,
                new HashFilter(hash, new HexEncoder(new StringSink(digest)))
            );
            };

        // Hàm Lambda riêng cho SHAKE vì nó cần độ dài đầu ra (XOF)
        auto hashShake = [&](HashTransformation& hash) {
            if (outLen <= 0) {
                throw runtime_error("Thuat toan SHAKE bat buoc phai co tham so --outlen (vi du: --outlen 64)");
            }
            FileSource(inFile.c_str(), true,
                new HashFilter(hash, new HexEncoder(new StringSink(digest)), false, outLen)
            );
            };

        // Phân nhánh các thuật toán 
        if (algo == "sha224") { SHA224 hash;   hashFile(hash); }
        else if (algo == "sha256") { SHA256 hash;   hashFile(hash); }
        else if (algo == "sha384") { SHA384 hash;   hashFile(hash); }
        else if (algo == "sha512") { SHA512 hash;   hashFile(hash); }
        else if (algo == "sha3-224") { SHA3_224 hash; hashFile(hash); }
        else if (algo == "sha3-256") { SHA3_256 hash; hashFile(hash); }
        else if (algo == "sha3-384") { SHA3_384 hash; hashFile(hash); }
        else if (algo == "sha3-512") { SHA3_512 hash; hashFile(hash); }
        else if (algo == "shake128") { SHAKE128 hash; hashShake(hash); }
        else if (algo == "shake256") { SHAKE256 hash; hashShake(hash); }
        else {
            cerr << "[-] Loi: Thuat toan " << algo << " hien chua duoc ho tro!\n";
            return;
        }

        cout << "[+] Hash (" << algo << "): " << digest << "\n";
    }
    catch (const exception& e) {
        cerr << "[-] Loi khi bam file: " << e.what() << "\n";
    }
}