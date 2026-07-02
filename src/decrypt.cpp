#include "decrypt.h"
#include "math_utils.h"

#include <iostream>

using namespace operations::math;

namespace core::decryptor {
std::string decrypt(keyPair& keyPair, const ByteArray& ciphertext)  {
    std::string plaintext;

    const size_t blockSize = keyPair.getPrivateKey().n.getBytes().size();
    if (blockSize == 0 || ciphertext.size() % blockSize != 0) {
        std::cerr << "Decryption error: Invalid ciphertext block size alignment." << std::endl;
        return plaintext;
    }

    // Process the ciphertext block-by-block using the fixed block size
    for (size_t i = 0; i < ciphertext.size(); i += blockSize) {
        // 1. Extract a single block chunk
        std::vector chunk(ciphertext.begin() + i, ciphertext.begin() + i + blockSize);

        // 2. Construct a Base256 representation from the extracted block chunk
        const operations::Base256 c_num(chunk);

        // 3. Perform RSA mathematical operation: M = C^d mod n
        operations::Base256 m_num = modPow(c_num, keyPair.getPrivateKey().d, keyPair.getPrivateKey().n);

        // 4. Retrieve the decrypted byte value and convert it back to a character
        const auto& m_bytes = m_num.getBytes();
        if (!m_bytes.empty()) {
            plaintext.push_back(static_cast<char>(m_bytes[0]));
        } else {
            plaintext.push_back('\0');  // Fallback for a zero-value block
        }
    }

    return plaintext;
}
}
