
#include "cmd_options.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

// Тесты писал чатжпт, авторам лень писать тесты, мне тоже.

namespace {

namespace fs = std::filesystem;
using CryptoGuard::ProgramOptions;

// Создаёт входной файл перед тестом и удаляет после него.
class ProgramOptionsTest : public ::testing::Test {
protected:
    const fs::path inputPath = "cryptoguard_test_input.txt";
    const fs::path outputPath = "cryptoguard_test_output.txt";

    void SetUp() override {
        std::ofstream file(inputPath);
        file << "Hello CryptoGuard!";
    }

    void TearDown() override {
        fs::remove(inputPath);
        fs::remove(outputPath);
    }
};

// Позволяет удобно передавать аргументы в Parse().
bool ParseArgs(ProgramOptions &options, std::vector<std::string> args) {
    std::vector<char *> argv;

    for (auto &arg : args) {
        argv.push_back(arg.data());
    }

    return options.Parse(static_cast<int>(argv.size()), argv.data());
}

}  // namespace

// 1. Проверка --help
TEST(ProgramOptions, Help) {
    ProgramOptions options;

    EXPECT_FALSE(ParseArgs(options, {"CryptoGuard", "--help"}));
}

// 2. Корректный checksum
TEST_F(ProgramOptionsTest, ValidChecksum) {
    ProgramOptions options;

    EXPECT_TRUE(ParseArgs(options, {"CryptoGuard", "--command", "checksum", "--input", inputPath.string()}));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

// 3. Корректный encrypt
TEST_F(ProgramOptionsTest, ValidEncrypt) {
    ProgramOptions options;

    EXPECT_TRUE(ParseArgs(options, {"CryptoGuard", "--command", "encrypt", "-i", inputPath.string(), "-o",
                                    outputPath.string(), "-p", "1234"}));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

// 4. Корректный decrypt
TEST_F(ProgramOptionsTest, ValidDecrypt) {
    ProgramOptions options;

    EXPECT_TRUE(ParseArgs(options, {"CryptoGuard", "--command", "decrypt", "-i", inputPath.string(), "-o",
                                    outputPath.string(), "-p", "1234"}));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

// 5. Отсутствует input
TEST(ProgramOptions, MissingInput) {
    ProgramOptions options;

    EXPECT_THROW(ParseArgs(options, {"CryptoGuard", "--command", "checksum"}), std::invalid_argument);
}

// 6. Отсутствует command
TEST_F(ProgramOptionsTest, MissingCommand) {
    ProgramOptions options;

    EXPECT_THROW(ParseArgs(options, {"CryptoGuard", "-i", inputPath.string()}), std::invalid_argument);
}

// 7. Неизвестная команда
TEST_F(ProgramOptionsTest, UnknownCommand) {
    ProgramOptions options;

    EXPECT_THROW(ParseArgs(options, {"CryptoGuard", "--command", "unknown", "-i", inputPath.string()}),
                 std::invalid_argument);
}

// 8. Отсутствует password
TEST_F(ProgramOptionsTest, MissingPassword) {
    ProgramOptions options;

    EXPECT_THROW(ParseArgs(options, {"CryptoGuard", "--command", "encrypt", "-i", inputPath.string(), "-o",
                                     outputPath.string()}),
                 std::invalid_argument);
}

// 9. Отсутствует output
TEST_F(ProgramOptionsTest, MissingOutput) {
    ProgramOptions options;

    EXPECT_THROW(ParseArgs(options, {"CryptoGuard", "--command", "decrypt", "-i", inputPath.string(), "-p", "1234"}),
                 std::invalid_argument);
}
