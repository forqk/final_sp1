#include "crypto_guard_ctx.h"
#include <exception>
#include <istream>
#include <memory>
#include <openssl/evp.h>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <iomanip>
#include <sstream>

#include <openssl/err.h>

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

    void CryptFunc(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {
        EVP_CipherInit_ex(ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(buff_size_ + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(buff_size_);
        int outLen;

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            auto bytesRead = inStream.gcount();

            if (bytesRead == 0) {
                break;
            }

            if (!EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
                ThrowOpenSSLError("EVP_CipherUpdate failed");
            }

            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        }

        if (!EVP_CipherFinal_ex(ctx_.get(), outBuf.data(), &outLen)) {
            ThrowOpenSSLError("EVP_CipherFinal_ex failed");
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ValidateInput(inStream, outStream, password);
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        CryptFunc(inStream, outStream, params);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ValidateInput(inStream, outStream, password);
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        CryptFunc(inStream, outStream, params);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream) {
            throw std::runtime_error("bad iStream");
        }

        using UniquePtrmdCtx = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *mdCtx) { EVP_MD_CTX_free(mdCtx); })>;
        UniquePtrmdCtx mdctx{EVP_MD_CTX_new()};

        const EVP_MD *md = EVP_get_digestbyname("SHA256");

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        if (!EVP_DigestInit_ex2(mdctx.get(), md, NULL)) {
            ThrowOpenSSLError("Message digest initialization failed.\n");
        }

        std::vector<unsigned char> inBuf(buff_size_);

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            auto bytesRead = inStream.gcount();

            if (bytesRead == 0) {
                break;
            }

            if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), bytesRead)) {
                ThrowOpenSSLError("Message digest update failed.\n");
            }
        }

        if (!EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len)) {
            ThrowOpenSSLError("Message digest finalization failed.\n");
        }

        std::stringstream ss;

        for (unsigned int i = 0; i < md_len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
        }

        return ss.str();
    }

private:
    void ValidateInput(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream) {
            throw std::runtime_error("bad iStream");
        }
        if (!outStream) {
            throw std::runtime_error("bad oStream");
        }
        if (password.empty()) {
            throw std::invalid_argument("passwd cannot be empty");
        }
    }

    void ThrowOpenSSLError(const std::string &message) {
        unsigned long err = ERR_get_error();

        char errorBuffer[256];
        ERR_error_string_n(err, errorBuffer, sizeof(errorBuffer));

        throw std::runtime_error(message + ": " + errorBuffer);
    }

    using UniquePtrCtx =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    UniquePtrCtx ctx_{EVP_CIPHER_CTX_new()};

    size_t buff_size_ = 16;
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