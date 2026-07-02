#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string>
#include <vector>

#include "keyPair.h"

namespace core {
namespace encryptor {
    // Performs RSA encryption on a plaintext string
    [[nodiscard]] ByteArray encrypt(keyPair& keyPair, const std::string& plaintext) ;
};
}  // namespace core

#endif