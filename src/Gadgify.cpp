#include "Gadgify.h"

#include <utility>

Gadgify::Gadgify(std::vector<char> binaryContents, BINARYTYPE type) {
    switch (type)
    {
        case PE:
            std::optional<PEFile> pe = PEFile::Create(std::move(binaryContents));
            if (pe.has_value())
            {
                controlFlowMnemonics_ = pe->GetControlFlowMnemonics();
                for (const Section& section : pe->GetSections())
                {
                    if (section.isExecutable_)
                    {
                        sections_.push_back(section);
                    }
                }
            }
            break;
    }
}

void
Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback, std::string peFile,
                    const std::string &pattern, uint32_t gapSize, BINARYTYPE type) {
    std::optional<Gadgify> gadgify = Gadgify::Create(std::move(peFile), type);
    if (gadgify.has_value())
    {
        gadgify->SearchGadgets([&](uint64_t offset, const std::string &gadget) {
            callback(offset, gadget);
        }, pattern, gapSize);
    }
}

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         std::vector<char> bytes,
                         const std::string &pattern, uint32_t gapSize, BINARYTYPE type) {
    std::optional<Gadgify> gadgify = Gadgify::Create(std::move(bytes), type);
    if (gadgify.has_value())
    {
        gadgify->SearchGadgets([&](uint64_t offset, const std::string &gadget) {
            callback(offset, gadget);
        }, pattern, gapSize);
    }
}

bool Gadgify::SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, const std::string &pattern,
                            uint32_t gapSize) {
    std::vector<std::regex> regexes = ConstructRegexes(pattern);
    if (regexes.empty()) {
        return false;
    }
    for (const Section &section: sections_) {
        for (const std::vector<Instruction>& chunk: section.instructionChunks_)
        {
            uint64_t firstOffset = 0;
            std::vector<std::string> gadget;
            uint32_t gapCounter = 0;
            uint32_t matches = 0;
            for (const Instruction& instruction : chunk)
            {
                if (matches > regexes.size())
                {
                    return false;
                }
                bool isMatch = std::regex_match(instruction.instruction_, regexes[matches]);
                if (isMatch) {
                    matches++;
                    gadget.emplace_back(instruction.instruction_);
                }
                else if (gapCounter < gapSize)
                {
                    if (std::find(controlFlowMnemonics_.begin(), controlFlowMnemonics_.end(), instruction.mnemonic_) != controlFlowMnemonics_.end())
                    {
                        gapCounter = 0;
                        matches = 0;
                        gadget.clear();
                    }
                    else
                    {
                        gadget.emplace_back(instruction.instruction_);
                        gapCounter++;
                    }
                }
                else
                {
                    gapCounter = 0;
                    matches = 0;
                    gadget.clear();
                }
                if (gadget.size() == 1)
                {
                    firstOffset = instruction.offset_;
                }
                if (regexes.size() == matches)
                {
                    std::string gadgetString;
                    for (const std::string &i: gadget)
                    {
                        gadgetString.append(i);
                        gadgetString.append("; ");
                    }
                    callback(firstOffset + section.virtualAddress_, gadgetString);
                    gapCounter = 0;
                    matches = 0;
                    gadget.clear();
                }
            }
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

    if (regexes.empty() || !currentRegex.empty())
    {
        std::cout << "Failed to construct query. Ensure each instruction always ends with a semi-colon e.g. "
                     "\"-p 'mov r1*; sub *; ret;'\" NOT \"-p 'ret' etc" << std::endl;
        regexes.clear();
    }
    return regexes;
}

std::optional<Gadgify> Gadgify::Create(std::string filePath, BINARYTYPE type) {
    return Gadgify::Create(File::Read(std::move(filePath)), type);
}

std::optional<Gadgify> Gadgify::Create(std::vector<char> binaryContents, BINARYTYPE type) {
    Gadgify gadgify(std::move(binaryContents), type);
    if (gadgify.sections_.empty())
    {
        return std::nullopt;
    }
    else
    {
        return gadgify;
    }
}
