#include <iostream>
#include <argparse.hpp>
#include <iomanip>
#include "Gadgify.h"

int main(int argc, char *argv[]) {
    argparse::ArgumentParser program("Gadgify");
    uint32_t gap = 0;
    program.add_argument("-g", "--gap")
            .help("The gap between instructions specified in the pattern e.g. searching for the pattern"
                  "'mov r*, r1*;call r*;sub *' with a gap of '3' will result in gadgets that can have up to 3"
                  "instructions that do not match the pattern between each instruction in the pattern provided.")
            .scan<'u', uint32_t>()
            .default_value(gap);

    program.add_argument("-p", "--pattern")
            .required()
            .help("The pattern to search for.");

    program.add_argument("-r", "--raw")
            .help("Treat the binary as raw executable code and not as a PE.")
            .default_value(false)
            .implicit_value(true);

    program.add_argument("binaryPath")
            .required()
            .help("Path of the file to search for gadgets. e.g. C:\\Windows\\System32\\ntdll.dll");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    bool isRaw = program.get<bool>("--raw");
    std::stringstream results;

    if (isRaw)
    {
        FileContents file = File::Read(program.get<std::string>("binaryPath"));
        Gadgify::GetGadgets([&results](uint64_t offset, const std::string &gadget)
            {
                results << "0x" << std::hex << std::setfill('0') << std::setw(8) << offset << ": " << gadget << std::endl;
            },
            std::vector<char>(file.contents, file.contents+file.size),
            program.get<std::string>("--pattern"),
            program.get<uint32_t>("--gap")
        );
    }
    else
    {
        Gadgify::GetGadgets([&results](uint64_t offset, const std::string &gadget)
            {
                results << "0x" << std::hex << std::setfill('0') << std::setw(8) << offset << ": " << gadget << std::endl;
            },
            program.get<std::string>("binaryPath"),
            program.get<std::string>("--pattern"),
            program.get<uint32_t>("--gap")
        );
    }

    std::cout << results.str() << std::endl;

    return 0;
}
