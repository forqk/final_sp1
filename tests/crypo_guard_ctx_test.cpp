
#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <sstream>
#include <stdexcept>
#include <string>

using namespace CryptoGuard;

// Тесты писал чатжпт, авторам лень писать тесты, мне тоже

// 1. Шифрование обычной строки
TEST(CryptoGuardEncrypt, EncryptSuccess) {
    CryptoGuardCtx ctx;

    std::stringstream input("Hello OpenSSL!");
    std::stringstream encrypted;

    ctx.EncryptFile(input, encrypted, "1234");

    ASSERT_FALSE(encrypted.str().empty());
    ASSERT_NE(encrypted.str(), "Hello OpenSSL!");
}

// 2. Шифрование пустой строки
TEST(CryptoGuardEncrypt, EncryptEmptyString) {
    CryptoGuardCtx ctx;

    std::stringstream input;
    std::stringstream encrypted;

    ctx.EncryptFile(input, encrypted, "1234");

    // AES-CBC с padding создаёт один блок из 16 байт
    ASSERT_EQ(encrypted.str().size(), 16u);
}

// 3. Шифрование с пустым паролем
TEST(CryptoGuardEncrypt, EncryptEmptyPassword) {
    CryptoGuardCtx ctx;

    std::stringstream input("Hello OpenSSL!");
    std::stringstream encrypted;

    ASSERT_THROW(ctx.EncryptFile(input, encrypted, ""), std::invalid_argument);
}

// 4. Расшифровка обычной строки
TEST(CryptoGuardDecrypt, DecryptSuccess) {
    CryptoGuardCtx ctx;

    std::stringstream input("Hello OpenSSL!");
    std::stringstream encrypted;
    std::stringstream decrypted;

    ctx.EncryptFile(input, encrypted, "1234");

    ctx.DecryptFile(encrypted, decrypted, "1234");

    ASSERT_EQ(decrypted.str(), "Hello OpenSSL!");
}

// 5. Расшифровка строки из нескольких блоков
TEST(CryptoGuardDecrypt, DecryptMultipleBlocks) {
    CryptoGuardCtx ctx;

    const std::string original(1000, 'A');

    std::stringstream input(original);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ctx.EncryptFile(input, encrypted, "1234");
    ctx.DecryptFile(encrypted, decrypted, "1234");

    ASSERT_EQ(decrypted.str(), original);
}

// 6. Расшифровка с пустым паролем
TEST(CryptoGuardDecrypt, DecryptEmptyPassword) {
    CryptoGuardCtx ctx;

    std::stringstream input("Encrypted data");
    std::stringstream decrypted;

    ASSERT_THROW(ctx.DecryptFile(input, decrypted, ""), std::invalid_argument);
}

// Проверка SHA-256 для обычной строки
TEST(CryptoGuardChecksum, ChecksumSuccess) {
    CryptoGuardCtx ctx;

    std::stringstream input("abc");

    const std::string result = ctx.CalculateChecksum(input);

    ASSERT_EQ(result, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// Проверка SHA-256 для пустой строки
TEST(CryptoGuardChecksum, ChecksumEmptyInput) {
    CryptoGuardCtx ctx;

    std::stringstream input;

    const std::string result = ctx.CalculateChecksum(input);

    ASSERT_EQ(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}