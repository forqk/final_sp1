#include "cmd_options.h"
#include <boost/program_options/options_description.hpp>
#include <iostream>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    // clang-format off
    desc_.add_options()
        ("help", "produce help message")
        ("command", po::value<std::string>(), "encrypt, decrypt, checksum")
        ("input,i", po::value<std::string>(), "input file")("output,o", po::value<std::string>(), "output file")
        ("password,p", po::value<std::string>(), "password");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);
    } catch (const po::error &error) {
        std::cout << "Error: " << error.what() << '\n' << "Use --help to see available options.\n";
        return;
    }

    if (vm.count("help")) {
        std::cout << desc_ << "\n"
                  << "Examples:\n"
                  << "  CryptoGuard -i input.txt -o encrypted.txt -p 1234 --command encrypt\n"
                  << "  CryptoGuard -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt\n"
                  << "  CryptoGuard -i input.txt --command checksum\n";
        return;
    }

    if (!vm.count("input")) {
        std::cout << "Error: input file is required. --help to see available options.\n";
        return;
    }

    if (!vm.count("command")) {
        std::cout << "Error: --command is required.--help to see available options.\n";
        return;
    }

    std::string str_command = vm["command"].as<std::string>();
    if (!commandMapping_.count(str_command)) {
        std::cout << "Error: --command parameters. --help to see available options.\n";
        return;
    }

    command_ = commandMapping_.at(str_command);
    if (command_ != ProgramOptions::COMMAND_TYPE::CHECKSUM && (!vm.count("output") || !vm.count("password"))) {
        std::cout << "Error: --command parameters. --help to see available options.\n";
        return;
    }
}

}  // namespace CryptoGuard
