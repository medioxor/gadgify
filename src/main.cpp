#include <iostream>
#include <argparse.hpp>
#include <iomanip>
#include "Gadgify.h"
#include "ExecutableBinary.h"

int main(int argc, char *argv[]) {
    argparse::ArgumentParser program("Gadgify");
    uint32_t gap = 3;
    std::stringstream results;
    std::mutex stringStreamMutex;

    program.add_argument("-nc", "--no-cet")
            .default_value(false)
            .implicit_value(true)
            .help("Only search for gadgets in executable code that is NOT compatible with Intel CET.");
    program.add_argument("-g", "--gap")
            .help("The gap between instructions specified in the pattern e.g. searching for the "
                  "'mov r*, r1*;call r*;sub *' pattern with a gap of '3' will result in gadgets that can have up to 3 "
                  "instructions that do not match the pattern between each instruction in the pattern provided.")
            .scan<'u', uint32_t>()
            .default_value(gap);
    program.add_argument("-p", "--pattern")
            .required()
            .help("The pattern to search for.");

    argparse::ArgumentParser directory_command("dir");
    directory_command.add_description("Search for gadgets in every binary found within a given directory.");
    directory_command.add_argument("path")
            .required()
            .help("Path to a directory containing executable binaries e.g. C:\\Windows\\System32");

    argparse::ArgumentParser binary_command("bin");
    binary_command.add_description("Search for gadgets in a binary file e.g. PE, ELF, MACHO.");
    binary_command.add_argument("path")
            .required()
            .help("Path to an executable binary e.g. C:\\Windows\\System32\\ntdll.dll");

    argparse::ArgumentParser raw_command("raw");
    raw_command.add_description("Search for gadgets in raw executable code e.g. a dumped .text section.");
    raw_command.add_argument("-a", "--arch")
            .required()
            .help("Define the instruction set architecture. Supported: x64, x86, arm32, arm64");
    raw_command.add_argument("-e", "--endianness")
            .required()
            .help("Define if the executable code should be treated as little or big endian.");
    raw_command.add_argument("-t", "--isThumb")
            .help("Assume the executable code contains ARM Thumb instructions.")
            .default_value(false)
            .implicit_value(true);
    raw_command.add_argument("path")
            .required()
            .help("Path of the file to search for gadgets. e.g. C:\\test.bin");

    program.add_subparser(directory_command);
    program.add_subparser(binary_command);
    program.add_subparser(raw_command);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    if (program.is_subcommand_used("raw"))
    {
        std::vector<char> fileContents(File::Read(raw_command.get<std::string>("path")));
        Gadgify::GetGadgets([&results](uint64_t offset, const std::string &gadget) {
                                results << "0x" << std::hex << std::setfill('0') << std::setw(8) << offset << ": " << gadget << std::endl;
                            },
                            fileContents,
                            program.get<std::string>("--pattern"),
                            program.get<uint32_t>("--gap"),
                            raw_command.get<std::string>("--arch"),
                            raw_command.get<std::string>("--endianness"),
                            raw_command.get<bool>("--isThumb"));

        if (results.str().empty())
        {
            std::cout << "No gadgets found that matched your query." << std::endl;
        }
        else
        {
            std::cout << results.str() << std::endl;
        }
    }
    if (program.is_subcommand_used("bin"))
    {
        std::filesystem::path path = binary_command.get<std::string>("path");
        std::cout << "Searching for gadgets in " << path.string() << std::endl;
        Gadgify::GetGadgets([&results, &stringStreamMutex, &path](uint64_t offset, const std::string &gadget) {
                                std::lock_guard<std::mutex> streamLock(stringStreamMutex);
                                results << path.filename().string() << "+" << "0x" << std::hex << std::setfill('0') << std::setw(8) << offset << ": " << gadget << std::endl;
                            },
                            path.string(),
                            program.get<std::string>("--pattern"),
                            gap, !program.get<bool>("--no-cet"));
        if (results.str().empty())
        {
            std::cout << "No gadgets found that matched your query." << std::endl;
        }
        else
        {
            std::cout << results.str() << std::endl;
        }
    }
    if (program.is_subcommand_used("dir"))
    {
        const std::filesystem::path binaryDirectory{directory_command.get<std::string>("path")};
        for (auto const& dir_entry : std::filesystem::directory_iterator{binaryDirectory})
            if (!dir_entry.is_directory())
            {
                std::cout << "Searching for gadgets in " << dir_entry.path().filename().string() << std::endl;
                Gadgify::GetGadgets([&dir_entry, &results, &stringStreamMutex](uint64_t offset, const std::string &gadget) {
                                        std::lock_guard<std::mutex> streamLock(stringStreamMutex);
                                        results << dir_entry.path().filename().string() << "+" "0x" << std::hex << std::setfill('0') << std::setw(8) << offset << ": " << gadget
                                                << std::endl;
                                    },
                                    dir_entry.path().string(),
                                    program.get<std::string>("--pattern"),
                                    gap, !program.get<bool>("--no-cet"));
                if (!results.str().empty())
                {
                    std::cout << results.str() << std::endl;
                    results.clear();
                }
            }
    }



    return 0;
}
