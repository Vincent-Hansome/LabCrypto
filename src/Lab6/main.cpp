#include <iostream>
#include <string>
#include <map>
#include "pq_core.h"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "[-] Cu phap: pqtool <keygen|sign|verify|encaps|decaps> [tham so...]\n";
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

    string algo = args.count("--algo") ? args["--algo"] : "";
    string pubFile = args.count("--pub") ? args["--pub"] : "pub.bin";
    string privFile = args.count("--priv") ? args["--priv"] : "priv.bin";
    string inFile = args.count("--in") ? args["--in"] : "";
    string sigFile = args.count("--sig") ? args["--sig"] : "";
    string outFile = args.count("--out") ? args["--out"] : "";
    string ctFile = args.count("--ct") ? args["--ct"] : "";
    string ssFile = args.count("--ss") ? args["--ss"] : "";

    try {
        if (command == "keygen") PQCore::GenerateKey(algo, pubFile, privFile);
        else if (command == "sign") PQCore::Sign(algo, privFile, inFile, outFile);
        else if (command == "verify") PQCore::Verify(algo, pubFile, inFile, sigFile);
        else if (command == "encaps") PQCore::Encapsulate(algo, pubFile, ctFile, ssFile);
        else if (command == "decaps") PQCore::Decapsulate(algo, privFile, ctFile, ssFile);
        // Thêm dòng này vào
        else if (command == "benchmark") PQCore::Benchmark(algo);
        else cerr << "[-] Lenh khong hop le!\n";
    }
    catch (const exception& e) {
        cerr << "[-] Exception: " << e.what() << "\n";
    }
    return 0;
}