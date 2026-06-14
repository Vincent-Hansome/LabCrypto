#include <iostream>
#include <string>
#include <map>
#include "sig_core.h"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "[-] Cu phap: sigtool <keygen|sign|verify> [cac tham so...]\n";
        return 1;
    }
    string command = argv[1];
    map<string, string> args;

    for (int i = 2; i < argc; ++i) {
        string arg = argv[i];
        if (i + 1 < argc && arg.rfind("--", 0) == 0) {
            args[arg] = argv[++i];
        }
    }

    string algo = args.count("--algo") ? args["--algo"] : "ecdsa-p256";
    string pubFile = args.count("--pub") ? args["--pub"] : "pub.pem";
    string privFile = args.count("--priv") ? args["--priv"] : "priv.pem";

    if (command == "keygen") {
        SigCore::GenerateKeys(algo, pubFile, privFile);
    }
    else if (command == "sign") {
        if (!args.count("--in") || !args.count("--out")) {
            cerr << "[-] Cu phap: sigtool sign --algo <thuat_toan> --in <file> --out <file_chu_ky>\n";
            return 1;
        }
        SigCore::SignFile(algo, privFile, args["--in"], args["--out"]);
    }
    else if (command == "verify") {
        if (!args.count("--in") || !args.count("--sig")) {
            cerr << "[-] Cu phap: sigtool verify --algo <thuat_toan> --in <file> --sig <file_chu_ky>\n";
            return 1;
        }
        SigCore::VerifySignature(algo, pubFile, args["--in"], args["--sig"]);
    }
    else if (command == "benchmark") {
        SigCore::Benchmark(algo);
    }
    else {
        cerr << "[-] Lenh khong hop le!\n";
        return 1;
    }
    return 0;
}