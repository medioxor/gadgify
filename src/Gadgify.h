#ifndef GADGIFY_GADGIFY_H
#define GADGIFY_GADGIFY_H

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <map>
#include <regex>
#include <Zydis/Zydis.h>
#include "PEFile.h"

struct Bytecode
{
    uint32_t virtualAddress;
    std::vector<char> bytes;
};

class Gadgify {
public:
    Gadgify(std::string peFile);
    Gadgify(std::vector<char> bytes);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::string peFile,
               const std::string &pattern, uint32_t gapSize);
    static void
    GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::vector<char> bytes,
               const std::string &pattern, uint32_t gapSize);
    bool SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, const std::string &pattern,
                       uint32_t gapSize);
private:
    static std::vector<std::regex> ConstructRegexes(const std::string& pattern);
    std::vector<Bytecode> bytecodes_;
};


#endif //GADGIFY_GADGIFY_H
