#ifndef PQ_CORE_H
#define PQ_CORE_H

#include <string>

class PQCore {
public:
    static void GenerateKey(const std::string& algo, const std::string& pubFile, const std::string& privFile);
    static void Sign(const std::string& algo, const std::string& privFile, const std::string& inFile, const std::string& sigFile);
    static void Verify(const std::string& algo, const std::string& pubFile, const std::string& inFile, const std::string& sigFile);
    static void Encapsulate(const std::string& algo, const std::string& pubFile, const std::string& ctFile, const std::string& ssFile);
    static void Decapsulate(const std::string& algo, const std::string& privFile, const std::string& ctFile, const std::string& ssFile);

    static void Benchmark(const std::string& algo);
};

#endif