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
    static std::optional<Gadgify> Create(std::string filePath, bool allowCet);
    static std::optional<Gadgify> Create(std::vector<char> binaryContents, bool allowCet);
    static std::optional<Gadgify> Create(const std::vector<char>& binaryContents, std::string arch, const std::string& endianness, bool isThumb);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::string filePath,
               const std::string &pattern, uint32_t gapSize, bool allowCet);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::vector<char> bytes,
               const std::string &pattern, uint32_t gapSize, bool allowCet);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
               const std::vector<char>& bytes, const std::string &pattern, uint32_t gapSize, const std::string &arch,
               const std::string &endianness, bool isThumb);
    void SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, std::vector<std::regex> regexes,
                       uint32_t gapSize, const std::vector<Instruction> &instructions, uint64_t virtualAddress);
private:
    static BINARYTYPE DetermineBinaryType(const std::vector<char>& binaryContents);
    bool Disassemble(const std::function<void(std::vector<Instruction>, uint64_t)> &callback, cs_arch arch, cs_mode mode);
    explicit Gadgify(std::vector<char> binaryContents, bool allowCet);
    Gadgify(const std::vector<char> &binaryContents, cs_arch arch, cs_mode mode);
    static std::vector<std::regex> ConstructRegexes(const std::string& pattern);
    std::vector<Section> sections_;
    std::vector<std::string> controlFlowMnemonics_{};
    std::string returnMnemonic_{};
    cs_arch arch_{};
    cs_mode mode_{};
};


#endif //GADGIFY_GADGIFY_H
