#include "vigenere.hpp"

#include <cctype>
#include <string>
#include <stdexcept>

namespace vigenere {

constexpr std::size_t ALPHABET_SIZE = 26;

int char_to_int(const char c) { 
    return std::toupper(static_cast<unsigned char>(c)) - 'A';
}

char int_to_char(const int v) {
    return 'A' + (v % ALPHABET_SIZE);
}

std::string normalize(const std::string& input) {
    std::string res;
    res.reserve(input.size());

    for (char c : input) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            res += std::toupper(static_cast<unsigned char>(c));
        }
    }

    return res;
}

std::string encrypt(const std::string& plaintext,
                    const std::string& key,
                    GammaMode mode) {
    std::string pt = normalize(plaintext);
    std::string k  = normalize(key);

    if (k.empty()) {
        throw std::invalid_argument{"Key cannot be empty"};
    }

    std::string ct;
    ct.reserve(pt.size());

    for (std::size_t i = 0; i < ct.size(); ++i) {
        int p = char_to_int(pt[i]);
        int g = 0;

        switch (mode) {
            case GammaMode::RepeatKey:
                g = char_to_int(k[i % k.size()]);
                break;
            case GammaMode::AutokeyPlaintext:
                g = (i == 0) ? char_to_int(k[0]) : char_to_int(pt[i - 1]);
                break;
            case GammaMode::AutokeyCiphertext:
                g = (i == 0) ? char_to_int(k[0]) : char_to_int(ct[i - 1]);
                break;
            default:
                throw std::invalid_argument{
                    "Mode must be RepeatKey, AutokeyPlaintext or AutokeyCiphertext"
                };
                break;
        }

        ct += int_to_char((p + g) % ALPHABET_SIZE);
    }

    return ct;
}

std::string decrypt(const std::string& ciphertext,
                    const std::string& key,
                    GammaMode mode) {
    std::string ct = normalize(ciphertext);
    std::string k  = normalize(key);

    if (k.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }

    std::string pt;
    pt.reserve(ct.size());

    for (size_t i = 0; i < ct.size(); ++i) {
        int c = char_to_int(ct[i]);
        int g = 0;

        switch (mode) {
            case GammaMode::RepeatKey:
                g = char_to_int(k[i % k.size()]);
                break;
            case GammaMode::AutokeyPlaintext:
                g = (i == 0) ? char_to_int(k[0]) : char_to_int(pt[i - 1]);
                break;
            case GammaMode::AutokeyCiphertext:
                g = (i == 0) ? char_to_int(k[0]) : char_to_int(ct[i - 1]);
                break;
            default:
                throw std::invalid_argument{
                    "Mode must be RepeatKey, AutokeyPlaintext or AutokeyCiphertext"
                };
                break;
        }

        int p = (c - g + ALPHABET_SIZE) % ALPHABET_SIZE;
        pt += int_to_char(p);
    }

    return pt;
}

} // namespace vigenere
