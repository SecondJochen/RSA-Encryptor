#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "encrypt.h"
#include "decrypt.h"
#include "keyPair.h"

using core::encryptor::encrypt;
using core::decryptor::decrypt;

TEST_CASE("RSA Core: Basic Encryption and Decryption Roundtrip") {
    static keyPair pair;

    SECTION("Decrypting encrypted normal string recovers the original text") {
        std::string plaintext = "Hello, C++ World!";

        ByteArray ciphertext = encrypt(pair, plaintext);

        REQUIRE_FALSE(ciphertext.empty());

        std::string recovered = decrypt(pair, ciphertext);

        REQUIRE(recovered == plaintext);
    }

    SECTION("Decrypting encrypted empty string recovers empty string") {
        std::string plaintext = "";

        ByteArray ciphertext = encrypt(pair, plaintext);
        std::string recovered = decrypt(pair, ciphertext);

        REQUIRE(recovered == plaintext);
    }

    SECTION("Correct handling of spaces, numbers, and special symbols") {
        std::string plaintext = "RSA_4096_Test! @#$%^&*()_+ 12345";

        ByteArray ciphertext = encrypt(pair, plaintext);
        std::string recovered = decrypt(pair, ciphertext);

        REQUIRE(recovered == plaintext);
    }
}

TEST_CASE("RSA Core: Security and Key Isolation") {
    static keyPair pairA;
    static keyPair pairB;

    std::string plaintext = "Highly Confidential Cryptographic Data";

    ByteArray ciphertext = encrypt(pairA, plaintext);

    SECTION("Decrypting with the incorrect keypair must not recover the plaintext") {
        std::string recovered = decrypt(pairB, ciphertext);

        REQUIRE(recovered != plaintext);
    }
}

TEST_CASE("RSA Core: Key Serialization and Base64 Import/Export") {
    static keyPair originalPair;

    std::string pubBase64 = keyPair::base64Encode(originalPair.getPublicKey().serialize());
    std::string privBase64 = keyPair::base64Encode(originalPair.getPrivateKey().serialize());

    REQUIRE_FALSE(pubBase64.empty());
    REQUIRE_FALSE(privBase64.empty());

    keyPair importedPair(pubBase64, privBase64);

    std::string plaintext = "Verification of Imported Keys";
    ByteArray ciphertext = encrypt(importedPair, plaintext);
    std::string recovered = decrypt(importedPair, ciphertext);

    REQUIRE(recovered == plaintext);
}