#ifndef HASH_CORE_H
#define HASH_CORE_H

#include <string>

class HashCore {
public:
    // Hàm băm hỗ trợ SHA-2, SHA-3 và đọc file theo luồng (Stream)
    static void ComputeHash(const std::string& algo, const std::string& inFile, int outLen = 0);
};

#endif