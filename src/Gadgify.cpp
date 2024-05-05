#include "Gadgify.h"

#include <utility>

Gadgify::Gadgify(std::string peFile) {
    PEFile::GetSections([&](IMAGE_SECTION_HEADER sectionHeader, const std::vector<char>& sectionContents)
    {
        if (sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            bytecodes_.push_back(
                    {
                        .virtualAddress = reinterpret_cast<uint32_t>(sectionHeader.VirtualAddress),
                        .bytes = sectionContents
                    }
            );
        }
    }, std::move(peFile));
}

Gadgify::Gadgify(std::vector<char> bytes) {
    bytecodes_.push_back(
            {
                    .virtualAddress = 0,
                    .bytes = std::move(bytes)
            }
    );
}

void
Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::string peFile,
                    const std::string &pattern, uint32_t gapSize) {
    Gadgify gadgify(std::move(peFile));

    gadgify.SearchGadgets([&](uint64_t offset, const std::string &gadget) {
        callback(offset, gadget);
    }, pattern, gapSize);
}

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         std::vector<char> bytes,
                         const std::string &pattern, uint32_t gapSize) {
    Gadgify gadgify(std::move(bytes));

    gadgify.SearchGadgets([&](uint64_t offset, const std::string &gadget) {
        callback(offset, gadget);
    }, pattern, gapSize);
}

bool Gadgify::SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, const std::string &pattern,
                            uint32_t gapSize) {
    std::vector<std::regex> regexes = ConstructRegexes(pattern);
    if (regexes.empty())
    {
        return false;
    }

    for (Bytecode bytecode : bytecodes_)
    {
        uint64_t firstOffset = 0;
        std::vector<std::string> gadget;
        uint32_t gapCounter = 0;
        uint32_t matches = 0;

        ZyanU64 runtime_address = 0x007FFFFFFF400000;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                runtime_address,
                reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(bytecode.bytes.data()) + offset),
                bytecode.bytes.size() - offset,
                &instruction
        )))
        {
            if (matches > regexes.size())
            {
                return false;
            }
            bool isMatch = std::regex_match(instruction.text, regexes[matches]);
            if (isMatch)
            {
                matches++;
                gadget.emplace_back(instruction.text);
            }
            else if (gapCounter < gapSize)
            {
                if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_RET ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JB ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JBE ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JCXZ ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JECXZ ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JKNZD ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JKZD ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JL ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JLE ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNB ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNBE ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNL ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNLE ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNO ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNP ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNS ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JNZ ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JO ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JP ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JRCXZ ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JS ||
                    instruction.info.mnemonic == ZYDIS_MNEMONIC_JZ
                        )
                {
                    gapCounter = 0;
                    matches = 0;
                    gadget.clear();
                    firstOffset = 0;
                }
                else
                {
                    gadget.emplace_back(instruction.text);
                    gapCounter++;
                }
            }
            else
            {
                gapCounter = 0;
                matches = 0;
                gadget.clear();
                firstOffset = 0;
            }
            if (gadget.size() == 1)
            {
                firstOffset = offset;
            }
            if (regexes.size() == matches)
            {
                std::string gadgetString;
                for (const std::string& i : gadget)
                {
                    gadgetString.append(i);
                    gadgetString.append("; ");
                }
                callback(firstOffset + bytecode.virtualAddress, gadgetString);
                gapCounter = 0;
                matches = 0;
                gadget.clear();
                firstOffset = 0;
            }
            offset += instruction.info.length;
            runtime_address += instruction.info.length;
        }
    }

    return true;
}

std::vector<std::regex> Gadgify::ConstructRegexes(const std::string& pattern) {
    std::vector<std::regex> regexes;
    std::string currentRegex;
    for (char i : pattern)
    {
        if (i == ' ' && currentRegex.empty())
        {
            continue;
        }
        if (i == ';')
        {
            regexes.emplace_back(currentRegex);
            currentRegex = "";
            continue;
        }
        if (i == '*')
        {
            currentRegex.push_back('.');
            currentRegex.push_back('*');
            continue;
        }
        if (i == '[' || i == ']')
        {
            currentRegex.push_back('\\');
            currentRegex.push_back(i);
            continue;
        }

        currentRegex.push_back(i);
    }
    return regexes;
}
