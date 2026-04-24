#include <gtest/gtest.h>
#include "vigenere.hpp"
#include <stdexcept>

TEST(VigenereRepeatKey, BasicEncryption) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "KEY", vigenere::GammaMode::RepeatKey), "RIJVS");
}

TEST(VigenereRepeatKey, BasicDecryption) {
    EXPECT_EQ(vigenere::decrypt("RIJVS", "KEY", vigenere::GammaMode::RepeatKey), "HELLO");
}

TEST(VigenereRepeatKey, Roundtrip) {
    std::string plaintext = "CRYPTOGRAPHY";
    std::string key = "SECRET";
    std::string ciphertext = vigenere::encrypt(plaintext, key, vigenere::GammaMode::RepeatKey);
    std::string decrypted = vigenere::decrypt(ciphertext, key, vigenere::GammaMode::RepeatKey);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(VigenereRepeatKey, EmptyText) {
    EXPECT_EQ(vigenere::encrypt("", "KEY", vigenere::GammaMode::RepeatKey), "");
    EXPECT_EQ(vigenere::decrypt("", "KEY", vigenere::GammaMode::RepeatKey), "");
}

TEST(VigenereRepeatKey, EmptyKey_ThrowsException) {
    EXPECT_THROW(vigenere::encrypt("HELLO", "", vigenere::GammaMode::RepeatKey), 
                 std::invalid_argument);
    EXPECT_THROW(vigenere::decrypt("RIJVS", "", vigenere::GammaMode::RepeatKey), 
                 std::invalid_argument);
}

TEST(VigenereRepeatKey, KeyLongerThanText) {
    EXPECT_EQ(vigenere::encrypt("HI", "LONGKEY", vigenere::GammaMode::RepeatKey), "SW");
    EXPECT_EQ(vigenere::decrypt("SW", "LONGKEY", vigenere::GammaMode::RepeatKey), "HI");
}

TEST(VigenereRepeatKey, SingleCharacterText) {
    EXPECT_EQ(vigenere::encrypt("A", "B", vigenere::GammaMode::RepeatKey), "B");
    EXPECT_EQ(vigenere::decrypt("B", "B", vigenere::GammaMode::RepeatKey), "A");
}

TEST(VigenereRepeatKey, SingleCharacterKey) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "A", vigenere::GammaMode::RepeatKey), "HELLO");
    EXPECT_EQ(vigenere::encrypt("HELLO", "B", vigenere::GammaMode::RepeatKey), "IFMMP");
}

TEST(VigenereRepeatKey, MixedCaseInput) {
    EXPECT_EQ(vigenere::encrypt("HeLLo", "KeY", vigenere::GammaMode::RepeatKey), "RIJVS");
    EXPECT_EQ(vigenere::encrypt("hello", "key", vigenere::GammaMode::RepeatKey), "RIJVS");
    EXPECT_EQ(vigenere::encrypt("HELLO", "key", vigenere::GammaMode::RepeatKey), "RIJVS");
}

TEST(VigenereRepeatKey, NonAlphabeticCharactersIgnored) {
    EXPECT_EQ(vigenere::encrypt("H3LL0!", "KEY", vigenere::GammaMode::RepeatKey), "RPJ");
    EXPECT_EQ(vigenere::encrypt("H-E-L-L-O", "ABC", vigenere::GammaMode::RepeatKey), "HFNLP");
    //EXPECT_EQ(vigenere::encrypt("Hello World!", "KEY", vigenere::GammaMode::RepeatKey), "RIJVSUYVJL");
}

TEST(VigenereRepeatKey, AllNonAlphabeticCharacters) {
    EXPECT_EQ(vigenere::encrypt("123!@#", "KEY", vigenere::GammaMode::RepeatKey), "");
}

TEST(VigenereRepeatKey, LongText) {
    std::string longText = "THISISAVERYLONGTEXTTOENSURETHECIPHERWORKSCORRECTLY";
    std::string key = "KEY";
    std::string encrypted = vigenere::encrypt(longText, key, vigenere::GammaMode::RepeatKey);
    std::string decrypted = vigenere::decrypt(encrypted, key, vigenere::GammaMode::RepeatKey);
    EXPECT_EQ(longText, decrypted);
}

TEST(VigenereRepeatKey, SameKeyAsText) {
    EXPECT_EQ(vigenere::encrypt("KEY", "KEY", vigenere::GammaMode::RepeatKey), "UIW");
}

TEST(VigenereRepeatKey, KeyWithNonAlphabeticCharacters) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "K3Y!", vigenere::GammaMode::RepeatKey), "RCVJY");
    EXPECT_EQ(vigenere::decrypt("RCVJY", "K3Y!", vigenere::GammaMode::RepeatKey), "HELLO");
}


TEST(VigenereAutokeyPlaintext, BasicEncryption) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "K", vigenere::GammaMode::AutokeyPlaintext), "RLPWZ");
}

TEST(VigenereAutokeyPlaintext, BasicDecryption) {
    EXPECT_EQ(vigenere::decrypt("RLPWZ", "K", vigenere::GammaMode::AutokeyPlaintext), "HELLO");
}

TEST(VigenereAutokeyPlaintext, Roundtrip) {
    std::string plaintext = "WORLD";
    std::string key = "S";
    std::string ciphertext = vigenere::encrypt(plaintext, key, vigenere::GammaMode::AutokeyPlaintext);
    std::string decrypted = vigenere::decrypt(ciphertext, key, vigenere::GammaMode::AutokeyPlaintext);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(VigenereAutokeyPlaintext, EmptyText) {
    EXPECT_EQ(vigenere::encrypt("", "K", vigenere::GammaMode::AutokeyPlaintext), "");
    EXPECT_EQ(vigenere::decrypt("", "K", vigenere::GammaMode::AutokeyPlaintext), "");
}

TEST(VigenereAutokeyPlaintext, EmptyKey_ThrowsException) {
    EXPECT_THROW(vigenere::encrypt("HELLO", "", vigenere::GammaMode::AutokeyPlaintext), 
                 std::invalid_argument);
}

TEST(VigenereAutokeyPlaintext, SingleCharacterText) {
    EXPECT_EQ(vigenere::encrypt("A", "B", vigenere::GammaMode::AutokeyPlaintext), "B");
    EXPECT_EQ(vigenere::decrypt("B", "B", vigenere::GammaMode::AutokeyPlaintext), "A");
}

TEST(VigenereAutokeyPlaintext, MultiCharacterKey_UsesOnlyFirst) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "KEY", vigenere::GammaMode::AutokeyPlaintext), "RLPWZ");
}

TEST(VigenereAutokeyPlaintext, MixedCaseInput) {
    EXPECT_EQ(vigenere::encrypt("HeLLo", "k", vigenere::GammaMode::AutokeyPlaintext), "RLPWZ");
}

TEST(VigenereAutokeyPlaintext, LongText) {
    std::string longText = "AUTOKEYCIPHER";
    std::string key = "X";
    std::string encrypted = vigenere::encrypt(longText, key, vigenere::GammaMode::AutokeyPlaintext);
    std::string decrypted = vigenere::decrypt(encrypted, key, vigenere::GammaMode::AutokeyPlaintext);
    EXPECT_EQ(longText, decrypted);
}

TEST(VigenereAutokeyCiphertext, BasicEncryption) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "K", vigenere::GammaMode::AutokeyCiphertext), "RVGRF");
}

TEST(VigenereAutokeyCiphertext, BasicDecryption) {
    EXPECT_EQ(vigenere::decrypt("RVGRF", "K", vigenere::GammaMode::AutokeyCiphertext), "HELLO");
}

TEST(VigenereAutokeyCiphertext, Roundtrip) {
    std::string plaintext = "MESSAGE";
    std::string key = "M";
    std::string ciphertext = vigenere::encrypt(plaintext, key, vigenere::GammaMode::AutokeyCiphertext);
    std::string decrypted = vigenere::decrypt(ciphertext, key, vigenere::GammaMode::AutokeyCiphertext);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(VigenereAutokeyCiphertext, EmptyText) {
    EXPECT_EQ(vigenere::encrypt("", "K", vigenere::GammaMode::AutokeyCiphertext), "");
    EXPECT_EQ(vigenere::decrypt("", "K", vigenere::GammaMode::AutokeyCiphertext), "");
}

TEST(VigenereAutokeyCiphertext, EmptyKey_ThrowsException) {
    EXPECT_THROW(vigenere::encrypt("HELLO", "", vigenere::GammaMode::AutokeyCiphertext), 
                 std::invalid_argument);
}

TEST(VigenereAutokeyCiphertext, SingleCharacterText) {
    EXPECT_EQ(vigenere::encrypt("A", "C", vigenere::GammaMode::AutokeyCiphertext), "C");
    EXPECT_EQ(vigenere::decrypt("C", "C", vigenere::GammaMode::AutokeyCiphertext), "A");
}

TEST(VigenereAutokeyCiphertext, MultiCharacterKey_UsesOnlyFirst) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "KEY", vigenere::GammaMode::AutokeyCiphertext), "RVGRF");
}

TEST(VigenereAutokeyCiphertext, MixedCaseInput) {
    EXPECT_EQ(vigenere::encrypt("HeLLo", "k", vigenere::GammaMode::AutokeyCiphertext), "RVGRF");
}

TEST(VigenereAutokeyCiphertext, LongText) {
    std::string longText = "CIPHERTEXT";
    std::string key = "Z";
    std::string encrypted = vigenere::encrypt(longText, key, vigenere::GammaMode::AutokeyCiphertext);
    std::string decrypted = vigenere::decrypt(encrypted, key, vigenere::GammaMode::AutokeyCiphertext);
    EXPECT_EQ(longText, decrypted);
}

TEST(VigenereSpecialCases, KeyWithAllAs) {
    EXPECT_EQ(vigenere::encrypt("HELLO", "A", vigenere::GammaMode::RepeatKey), "HELLO");
    EXPECT_EQ(vigenere::encrypt("HELLO", "AAAA", vigenere::GammaMode::RepeatKey), "HELLO");
}

TEST(VigenereSpecialCases, EncryptThenDecrypt) {
    std::string text = "TESTTEXT";
    std::string key = "KEY";

    std::string encrypted = vigenere::encrypt(text, key, vigenere::GammaMode::RepeatKey);
    EXPECT_EQ(vigenere::decrypt(encrypted, key, vigenere::GammaMode::RepeatKey), text);

    encrypted = vigenere::encrypt(text, "K", vigenere::GammaMode::AutokeyPlaintext);
    EXPECT_EQ(vigenere::decrypt(encrypted, "K", vigenere::GammaMode::AutokeyPlaintext), text);

    encrypted = vigenere::encrypt(text, "K", vigenere::GammaMode::AutokeyCiphertext);
    EXPECT_EQ(vigenere::decrypt(encrypted, "K", vigenere::GammaMode::AutokeyCiphertext), text);
}

TEST(VigenereSpecialCases, AllLettersOfAlphabet) {
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string key = "B";
    
    std::string encrypted = vigenere::encrypt(alphabet, key, vigenere::GammaMode::RepeatKey);

    std::string expected = "BCDEFGHIJKLMNOPQRSTUVWXYZA";
    EXPECT_EQ(encrypted, expected);
    
    std::string decrypted = vigenere::decrypt(encrypted, key, vigenere::GammaMode::RepeatKey);
    EXPECT_EQ(decrypted, alphabet);
}

TEST(VigenereSpecialCases, RepeatedPattern) {
    std::string text = "ABABABAB";
    std::string key = "AB";
    
    std::string encrypted = vigenere::encrypt(text, key, vigenere::GammaMode::RepeatKey);
    std::string decrypted = vigenere::decrypt(encrypted, key, vigenere::GammaMode::RepeatKey);
    EXPECT_EQ(decrypted, text);
}

TEST(VigenereErrorHandling, EmptyKey_RepeatKey) {
    EXPECT_THROW(vigenere::encrypt("TEXT", "", vigenere::GammaMode::RepeatKey), 
                 std::invalid_argument);
}

TEST(VigenereErrorHandling, EmptyKey_AutokeyPlaintext) {
    EXPECT_THROW(vigenere::encrypt("TEXT", "", vigenere::GammaMode::AutokeyPlaintext), 
                 std::invalid_argument);
}

TEST(VigenereErrorHandling, EmptyKey_AutokeyCiphertext) {
    EXPECT_THROW(vigenere::encrypt("TEXT", "", vigenere::GammaMode::AutokeyCiphertext), 
                 std::invalid_argument);
}

TEST(VigenereErrorHandling, KeyWithOnlyNonAlphabetic) {
    EXPECT_THROW(vigenere::encrypt("HELLO", "123", vigenere::GammaMode::RepeatKey), 
                 std::invalid_argument);
}
