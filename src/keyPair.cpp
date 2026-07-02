#include "keyPair.h"

#include <filesystem>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#endif

#include "math_utils.h"


namespace {
    constexpr size_t PRIME_SIZE_WORDS = 32;

    ByteArray getSecureRandomBytes(size_t word_count) {
        ByteArray buffer(word_count);
        size_t byte_size = word_count * sizeof(uint64_t); // 32 * 8 = 256 Bytes

    #if defined(_WIN32)
        BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(byte_size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    #else
        #if defined(__GLIBC__) && ((__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
        if (getentropy(buffer.data(), byte_size) == 0) {
            return buffer;
        }
        #endif
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (urandom.is_open()) {
            urandom.read(reinterpret_cast<char*>(buffer.data()), byte_size);
        }
    #endif
        return buffer;
    }

    ByteArray generateCandidateBytes() {
        ByteArray candidate = getSecureRandomBytes(PRIME_SIZE_WORDS);

        candidate[PRIME_SIZE_WORDS - 1] |= 0x8000'0000'0000'0000ULL;

        candidate[0] |= 0x01;

        return candidate;
    }

    operations::Base256 generateSecurePrime() {
        ByteArray candidateBytes = generateCandidateBytes();
        operations::Base256 candidate(candidateBytes);

        while (!operations::math::isPrime(candidate)) {
            candidate += operations::Base256(2);
        }
        return candidate;
    }
}

// Default Constructor: Generates a new secure 4096-bit RSA keypair
keyPair::keyPair() {
    const operations::Base256 p = generateSecurePrime();
    operations::Base256 q = generateSecurePrime();

    // Ensure p and q are not identical
    while (p == q) {
        q = generateSecurePrime();
    }

    operations::Base256 phi = (p - operations::Base256(1)) * (q - operations::Base256(1));
    const operations::Base256 e(65537);

    // Ensure e and phi are coprime
    while (operations::math::gcd(e, phi) != operations::Base256(1)) {
        q = generateSecurePrime();
        while (p == q) {
            q = generateSecurePrime();
        }
        phi = (p - operations::Base256(1)) * (q - operations::Base256(1));
    }

    const operations::Base256 n = p * q;
    const operations::Base256 d = operations::math::modInverse(e, phi);

    public_key.n = n;
    public_key.e = e;

    private_key.n = n;
    private_key.d = d;
}

// Import Constructor: Imports keys from Base64 encoded serialized strings
keyPair::keyPair(const std::string& publicKey, const std::string& privateKey) {
    const ByteArray pubBytes = base64Decode(publicKey);
    s_deserialize(pubBytes, public_key.n, public_key.e);

    const ByteArray privBytes = base64Decode(privateKey);
    s_deserialize(privBytes, private_key.n, private_key.d);
}

ByteArray PublicKey::serialize() const {
    return keyPair::s_serialize(n, e);
}

ByteArray PrivateKey::serialize() const {
    return keyPair::s_serialize(n, d);
}

// Serializes two 4 bytes Byte Arrays with Big endian
ByteArray keyPair::s_serialize(const operations::Base256 &first,
                                          const operations::Base256 &second) {
    ByteArray serialized;
    const auto &firstBytes = first.getBytes();
    const auto &secondBytes = second.getBytes();

    uint32_t firstSize = firstBytes.size();
    uint32_t secondSize = secondBytes.size();

    serialized.push_back((firstSize >> 24) & 0xFF);
    serialized.push_back((firstSize >> 16) & 0xFF);
    serialized.push_back((firstSize >> 8) & 0xFF);
    serialized.push_back(firstSize & 0xFF);

    serialized.insert(serialized.end(), firstBytes.begin(), firstBytes.end());

    serialized.push_back((secondSize >> 24) & 0xFF);
    serialized.push_back((secondSize >> 16) & 0xFF);
    serialized.push_back((secondSize >> 8) & 0xFF);
    serialized.push_back(secondSize & 0xFF);

    serialized.insert(serialized.end(), secondBytes.begin(), secondBytes.end());

    return serialized;
}

// Deserializes two 4 bytes Byte Arrays with Big endian
bool keyPair::s_deserialize(const ByteArray &data, operations::Base256 &outFirst,
                            operations::Base256 &outSecond) {
    if (data.size() < 8) return false;

    size_t index = 0;

    uint32_t firstSize =
        (data[index] << 24) | (data[index + 1] << 16) | (data[index + 2] << 8) | data[index + 3];
    index += 4;

    if (index + firstSize > data.size()) return false;
    const auto firstBegin =
        data.begin() + static_cast<ByteArray::difference_type>(index);
    const auto firstEnd =
        firstBegin + static_cast<ByteArray::difference_type>(firstSize);
    ByteArray firstBytes(firstBegin, firstEnd);
    index += firstSize;

    if (index + 4 > data.size()) return false;

    const uint32_t secondSize =
        (data[index] << 24) | (data[index + 1] << 16) | (data[index + 2] << 8) | data[index + 3];
    index += 4;

    if (index + secondSize > data.size()) return false;
    const auto secondBegin =
        data.begin() + static_cast<ByteArray::difference_type>(index);
    const auto secondEnd =
        secondBegin + static_cast<ByteArray::difference_type>(secondSize);
    ByteArray secondBytes(secondBegin, secondEnd);

    outFirst = operations::Base256(firstBytes);
    outSecond = operations::Base256(secondBytes);

    return true;
}

std::string keyPair::base64Encode(const ByteArray &data) {
    ByteArray result;
    size_t index = 0;

    while (index < data.size()) {
        uint32_t dataSegment = 0;
        for (int i = 2; i >= 0; i--) {
            if (index >= data.size()) break;
            const uint8_t number = data.at(index++);
            dataSegment += number << (i * 8);
        }

        for (int j = 0; j < 4; j++) {
            dataSegment <<= 6;
            result.push_back(static_cast<uint8_t>((dataSegment & (0b00111111 << 24)) >> 24));
        }
    }

    std::string outString;
    for (auto c : result) {
        outString += base64Chars[c];
    }
    return outString;
}

ByteArray keyPair::base64Decode(std::string data) {
    ByteArray result;

    while (!data.empty()) {
        if (data.length() < 4) break;
        std::string letterSegment = data.substr(0, 4);
        data.erase(0, 4);

        uint32_t dataSegment = 0;
        for (int i = 3; i >= 0; i--) {
            if (static_cast<size_t>(3 - i) >= letterSegment.length()) continue;
            const uint8_t number = getBase64Index(letterSegment.at(3 - i));
            if (number > 0b111111) {
                std::cerr << "Invalid char: " << letterSegment.at(3 - i) << std::endl;
                continue;
            }
            dataSegment += number << (i * 6);
        }

        for (int j = 0; j < 3; j++) {
            dataSegment <<= 8;
            result.push_back((dataSegment & (0xFF << 24)) >> 24);
        }
    }
    return result;
}

uint8_t keyPair::getBase64Index(char letter) {
    for (int i = 0; base64Chars[i] != '\0'; i++) {
        if (base64Chars[i] == letter) {
            return i;
        }
    }
    return 0;
}
