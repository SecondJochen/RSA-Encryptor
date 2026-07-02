#ifndef KEY_PAIR_H
#define KEY_PAIR_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "base256.h"
#include "key_fwd.h"

#define KEY_FOLDER "rsa-keys"

enum { NONE, PUBLIC, PRIVATE, BOTH };

struct PublicKey {
    operations::Base256 n;
    operations::Base256 e;

    [[nodiscard]] ByteArray serialize() const;
};

struct PrivateKey {
    operations::Base256 n;
    operations::Base256 d;

    [[nodiscard]] ByteArray serialize() const;
};

class keyPair {
   private:
    PublicKey public_key;
    PrivateKey private_key;

    static constexpr char base64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


   public:
    keyPair();

    keyPair(const std::string& publicKey, const std::string& privateKey);

    PublicKey getPublicKey() { return public_key; }
    PrivateKey getPrivateKey() { return private_key; }

    static ByteArray s_serialize(const operations::Base256 &first,
                                        const operations::Base256 &second);
    static bool s_deserialize(const ByteArray
        &data, operations::Base256 &outFirst,
                              operations::Base256 &outSecond);

    // Base64 helper functions
    static std::string base64Encode(const ByteArray &data);
    static ByteArray base64Decode(std::string data);
    static uint8_t getBase64Index(char letter);
};

#endif