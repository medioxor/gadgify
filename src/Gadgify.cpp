#include "Gadgify.h"

#include <utility>

Gadgify::Gadgify(std::vector<char> binaryContents, BINARYTYPE type) {
    switch (type)
    {
        case PE:
            std::optional<PEFile> pe = PEFile::Create(std::move(binaryContents));
            if (pe.has_value())
            {
                arch_ = pe->GetArch();
                mode_ = pe->GetMode();
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
        std::vector<std::regex> regexes = ConstructRegexes(pattern);
        gadgify->Disassemble([&](const std::vector<Instruction>& instructions, uint64_t virtualAddress) {
            gadgify->SearchGadgets([&](uint64_t offset, const std::string &gadget) {
                callback(offset, gadget);
            }, regexes, gapSize, instructions, virtualAddress);
        }, gadgify->arch_, gadgify->mode_);
    }
}

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         std::vector<char> bytes,
                         const std::string &pattern, uint32_t gapSize, BINARYTYPE type) {
    std::optional<Gadgify> gadgify = Gadgify::Create(std::move(bytes), type);
    std::vector<std::regex> regexes = ConstructRegexes(pattern);
    if (gadgify.has_value())
    {
        gadgify->Disassemble([&](const std::vector<Instruction>& instructions, uint64_t virtualAddress) {
            gadgify->SearchGadgets([&](uint64_t offset, const std::string &gadget) {
                callback(offset, gadget);
            }, regexes, gapSize, instructions, virtualAddress);
        }, gadgify->arch_, gadgify->mode_);
    }
}

bool Gadgify::Disassemble(const std::function<void(std::vector<Instruction>, uint64_t)> &callback, cs_arch arch, cs_mode mode) {
    ThreadPool pool(4);
    switch (arch)
    {
        case CS_ARCH_X86:
            controlFlowMnemonics_ = {
                    "call",
                    "ret",
                    "syscall",
                    "int3",
                    "int",
                    "je",
                    "jae",
                    "jb",
                    "jbe",
                    "jcxz",
                    "jecxz",
                    "jknzd",
                    "jkzd",
                    "jl",
                    "jle",
                    "jmp",
                    "jnb",
                    "jnbe",
                    "jnl",
                    "jne",
                    "jnle",
                    "jno",
                    "jnp",
                    "jns",
                    "jnz",
                    "jo",
                    "jp",
                    "jrcxz",
                    "js",
                    "jz"
            };
            returnMnemonic_ = "ret";
            break;
        case CS_ARCH_ARM:
            returnMnemonic_ = "bx";
            break;
        case CS_ARCH_AARCH64:
            returnMnemonic_ = "ret";
            break;
    }
    std::sort(controlFlowMnemonics_.begin(), controlFlowMnemonics_.end());
    csh handle{0};
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
        return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);
    for (Section& section : sections_)
    {
        if (section.isExecutable_)
        {
            uint64_t totalDisassembled = 0;
            std::vector<Instruction> instructionChunk;

            while (totalDisassembled < section.contents_.size())
            {
                size_t codeSize = section.contents_.size() - totalDisassembled;
                size_t currentOffset = totalDisassembled;
                const auto* code = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(section.contents_.data()) + totalDisassembled);
                while(cs_disasm_iter(handle, &code, &codeSize, &currentOffset, insn)) {
                    instructionChunk.emplace_back(
                                insn->mnemonic,
                                insn->op_str,
                                insn->address
                    );
                    if (strcmp(insn->mnemonic, returnMnemonic_.data()) == 0)
                    {
                        pool.Enqueue([instructionChunk, section, callback]() {
                            callback(instructionChunk, section.virtualAddress_);
                        });
                        instructionChunk.clear();
                    }
                    totalDisassembled += insn->size;
                }
                totalDisassembled += 1;
            }
        }
    }
    cs_free(insn, 1);
    cs_close(&handle);
    pool.Wait();
    return true;
}

void Gadgify::SearchGadgets(const std::function<void(uint64_t, std::string)> &callback, std::vector<std::regex> regexes,
                            uint32_t gapSize, const std::vector<Instruction> &instructions, uint64_t virtualAddress) {
    if (regexes.empty()) {
        return;
    }
    uint64_t firstOffset = 0;
    std::vector<std::string> gadget;
    std::vector<std::string> gap;
    std::vector<uint64_t> gapOffsets;
    uint32_t matches = 0;
    for (const Instruction& instruction : instructions)
    {
        if (matches > regexes.size())
        {
            matches = 0;
            gadget.clear();
            continue;
        }
        bool isMatch = std::regex_match(instruction.instruction_, regexes[matches]);
        if (isMatch) {
            matches++;
            if (!gap.empty())
            {
                firstOffset = gapOffsets[0];
                for (const auto & i : gap)
                {
                    gadget.push_back(i);
                }
                gap.clear();
                gapOffsets.clear();
            }
            else
            {
                firstOffset = instruction.offset_;
            }
            gadget.emplace_back(instruction.instruction_);
        }
        else
        {
            if (std::binary_search(controlFlowMnemonics_.begin(), controlFlowMnemonics_.end(), instruction.mnemonic_))
            {
                matches = 0;
                gap.clear();
                gapOffsets.clear();
                gadget.clear();
            }
            else
            {
                if (gap.size() == gapSize)
                {
                    gap.erase(gap.begin());
                    gapOffsets.erase(gapOffsets.begin());
                }
                gap.emplace_back(instruction.instruction_);
                gapOffsets.push_back(instruction.offset_);
            }
        }
        if (regexes.size() == matches)
        {
            std::string gadgetString;
            for (const std::string &i: gadget)
            {
                gadgetString.append(i);
                gadgetString.append("; ");
            }
            callback(firstOffset + virtualAddress, gadgetString);
            matches = 0;
            gap.clear();
            gapOffsets.clear();
            gadget.clear();
        }
    }
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
