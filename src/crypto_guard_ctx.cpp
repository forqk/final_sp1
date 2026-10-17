#include "crypto_guard_ctx.h"
#include <exception>
#include <istream>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ValidateStreams(inStream, outStream, password);

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        EVP_CipherInit_ex(ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        size_t buff_size = 16;
        std::vector<unsigned char> outBuf(buff_size + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(buff_size);
        int outLen;

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            auto bytesReaden = inStream.gcount();

            if (bytesReaden == 0) {
                break;
            }

            EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesReaden));

            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        }

        EVP_CipherFinal_ex(ctx_.get(), outBuf.data(), &outLen);
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ValidateStreams(inStream, outStream, password);
    }

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    void ValidateStreams(const std::ios &inStream, const std::ios &outStream, std::string_view password) const {
        if (!inStream) {
            throw std::runtime_error("bad iStream");
        }
        if (!outStream) {
            throw std::runtime_error("bad Ostream");
        }
        if (password.empty()) {
            throw std::invalid_argument("passwd cannot be empty");
        }
    }

    using UniquePtrCtx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    UniquePtrCtx ctx_{EVP_CIPHER_CTX_new()};
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inp, std::iostream &out, std::string_view passwd) {
    pImpl_->EncryptFile(inp, out, passwd);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inp, std::iostream &out, std::string_view passwd) {
    pImpl_->DecryptFile(inp, out, passwd);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inp) { return pImpl_->CalculateChecksum(inp); }
}  // namespace CryptoGuard