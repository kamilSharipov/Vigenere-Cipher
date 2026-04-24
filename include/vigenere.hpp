#pragma once

#include <string>

namespace vigenere {

enum class GammaMode {
    RepeatKey,
    AutokeyPlaintext,
    AutokeyCiphertext
};

std::string encrypt(const std::string& plaintext,
                    const std::string& key,
                    GammaMode mode);

std::string decrypt(const std::string& ciphertext,
                    const std::string& key,
                    GammaMode mode);

} // namespace vigenere
