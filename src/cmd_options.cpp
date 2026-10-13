#include "cmd_options.h"
#include <boost/program_options/options_description.hpp>
#include <iostream>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
    ("help", "produce help message")
    ("command", po::value<std::string>(),"encrypt, decrypt, checksum")
    ("input,i", po::value<std::string>(), "input file")
    ("output,o", po::value<std::string>(), "output file")
    ("password,p", po::value<std::string>(), "password");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        return;
    }

    if (vm.count())
}

}  // namespace CryptoGuard
