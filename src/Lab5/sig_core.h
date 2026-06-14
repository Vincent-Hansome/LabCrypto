#ifndef SIG_CORE_H
#define SIG_CORE_H

#include <string>

class SigCore {
public:
    // 1. Sinh cap khoa bat doi xung
    static void GenerateKeys(const std::string& algo, const std::string& pubFile, const std::string& privFile);

    // 2. Ky file du lieu (Detached Signature)
    static void SignFile(const std::string& algo, const std::string& privFile, const std::string& inFile, const std::string& sigFile);

    // 3. Xac minh chu ky
    static void VerifySignature(const std::string& algo, const std::string& pubFile, const std::string& inFile, const std::string& sigFile);

    static void Benchmark(const std::string& algo);
};

#endif