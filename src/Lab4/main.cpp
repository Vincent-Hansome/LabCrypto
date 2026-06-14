#include <iostream>
#include <string>
#include <map>
#include "hash_core.h"

using namespace std;

int main(int argc, char* argv[]) {
    map<string, string> args;

    // Quét các tham số CLI
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (i + 1 < argc && arg.rfind("--", 0) == 0) {
            args[arg] = argv[++i];
        }
        // Bắt cờ không có giá trị đi kèm (như --stream)
        else if (arg == "--stream") {
            args["--stream"] = "true";
        }
    }

    // Bắt lệnh băm dữ liệu
    if (args.count("--algo") && args.count("--in")) {
        int outLen = args.count("--outlen") ? stoi(args["--outlen"]) : 0;

        if (args.count("--stream")) {
            cout << "[*] Che do Streaming Mode da duoc bat (Ho tro file dung luong lon).\n";
        }

        HashCore::ComputeHash(args["--algo"], args["--in"], outLen);
    }
    else {
        cerr << "[-] Cu phap chuan: hashtool --algo <thuat_toan> --in <file> [--outlen <byte>] [--stream]\n";
        cerr << "[-] Ho tro: sha224, sha256, sha384, sha512, sha3-256, sha3-512, shake128, shake256\n";
        return 1;
    }

    return 0;
}