#include "cmd_options.h"
#include <boost/program_options/options_description.hpp>
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // если не вырубить всё уплывает
    // clang-format off
    desc_.add_options()
        ("help", "produce help message")
        ("command", po::value<std::string>(), "encrypt, decrypt, checksum")
        ("input,i", po::value<std::string>(), "input")
        ("output,o", po::value<std::string>(), "output")
        ("password,p", po::value<std::string>(), "password");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char **argv) {
    namespace fs = std::filesystem;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    // Help
    if (vm.count("help")) {
        std::cout << desc_ << "\n"
                  << "Examples:\n"
                  << "  CryptoGuard -i input.txt -o encrypted.txt -p 1234 --command encrypt\n"
                  << "  CryptoGuard -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt\n"
                  << "  CryptoGuard -i input.txt --command checksum\n";
        return false;
    }

    if (!vm.count("input") || !vm.count("command")) {
        throw std::invalid_argument("Input and command are required");
    }

    const auto &commandName = vm["command"].as<std::string>();
    const auto it = commandMapping_.find(commandName);

    if (it == commandMapping_.end()) {
        throw std::invalid_argument("Unknown command: " + commandName);
    }

    const auto command = it->second;

    const auto &input = vm["input"].as<std::string>();

    if (!fs::is_regular_file(input)) {
        throw std::invalid_argument("Input file does not exist or is not a regular file: " + input);
    }

    std::string output;
    std::string password;

    if (command != COMMAND_TYPE::CHECKSUM) {
        if (!vm.count("output") || !vm.count("password")) {
            throw std::invalid_argument("Output and password are required");
        }

        output = vm["output"].as<std::string>();
        password = vm["password"].as<std::string>();

        if (output.empty() || password.empty()) {
            throw std::invalid_argument("Output and password cannot be empty");
        }

        if (fs::exists(output) && !fs::is_regular_file(output)) {
            throw std::invalid_argument("Output path is not a regular file: " + output);
        }

        if (fs::exists(output) && fs::equivalent(input, output)) {
            throw std::invalid_argument("Input and output files must be different");
        }
    }

    inputFile_ = input;
    command_ = command;
    outputFile_ = output;
    password_ = password;

    return true;
}

}  // namespace CryptoGuard
