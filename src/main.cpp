#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <istream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

#include <fstream>

struct FileStreams {
    std::fstream input;
    std::fstream output;
};

FileStreams OpenFiles(const std::string &inputPath, const std::string &outputPath) {
    if (std::filesystem::exists(outputPath) && std::filesystem::equivalent(inputPath, outputPath)) {
        throw std::runtime_error("Input and output files must be different");
    }

    FileStreams files{std::fstream(inputPath, std::ios::in | std::ios::binary),
                      std::fstream(outputPath, std::ios::out | std::ios::binary | std::ios::trunc)};

    if (!files.input.is_open() || !files.output.is_open()) {
        throw std::runtime_error("Failed to open files");
    }

    return files;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        if (!options.Parse(argc, argv)) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        switch (options.GetCommand()) {

        case COMMAND_TYPE::ENCRYPT: {
            auto files = OpenFiles(options.GetInputFile(), options.GetOutputFile());

            cryptoCtx.EncryptFile(files.input, files.output, options.GetPassword());
            std::print("File encrypted successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto files = OpenFiles(options.GetInputFile(), options.GetOutputFile());

            cryptoCtx.DecryptFile(files.input, files.output, options.GetPassword());
            std::print("File decrypted successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            std::fstream input(options.GetInputFile(), std::ios::in | std::ios::binary);

            if (!input.is_open()) {
                throw std::runtime_error("Cannot open input file");
            }

            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(input));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}