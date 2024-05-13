#ifndef GADGIFY_GADGIFY_H
#define GADGIFY_GADGIFY_H

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <map>
#include <iostream>
#include <regex>
#include <execution>
#include <capstone/capstone.h>
#include "ThreadPool.h"
#include "PEFile.h"

class Gadgify {
public:
    static std::optional<Gadgify> Create(std::string filePath, BINARYTYPE type);
    static std::optional<Gadgify> Create(std::vector<char> binaryContents, BINARYTYPE type);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::string peFile,
               const std::string &pattern, uint32_t gapSize, BINARYTYPE type);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::vector<char> bytes,
               const std::string &pattern, uint32_t gapSize, BINARYTYPE type);
    void SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, std::vector<std::regex> regexes,
                       uint32_t gapSize, const std::vector<Instruction> &instructions, uint64_t virtualAddress);
private:
    bool Disassemble(const std::function<void(std::vector<Instruction>, uint64_t)> &callback, cs_arch arch, cs_mode mode);
    Gadgify(std::vector<char> binaryContents, BINARYTYPE type);
    static std::vector<std::regex> ConstructRegexes(const std::string& pattern);
    std::vector<Section> sections_;
    std::vector<std::string> controlFlowMnemonics_{};
    std::string returnMnemonic_{};
    cs_arch arch_{};
    cs_mode mode_{};
};


#endif //GADGIFY_GADGIFY_H
