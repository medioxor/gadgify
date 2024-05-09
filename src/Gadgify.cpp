#include "Gadgify.h"

Gadgify::Gadgify(std::string peFile) {
    PEFile::GetSections([&](IMAGE_SECTION_HEADER sectionHeader, const std::vector<char>& sectionContents)
    {
        if (sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            bytecodes_.push_back(
                    {
                        .virtualAddress = sectionHeader.VirtualAddress,
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

        csh handle;
        cs_insn *insn;
        size_t count;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        {
            return false;
        }
        count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(bytecode.bytes.data()), bytecode.bytes.size(), 0x0, 0, &insn);
        if (count == 0)
        {
            std::cout << "Failed to disassemble binary" << std::endl;
            return false;
        }
        size_t j;
        std::string instruction;
        for (j = 0; j < count; j++) {
            if (insn[j].op_str[0] == '\0')
            {
                instruction = std::string(insn[j].mnemonic);
            }
            else
            {
                instruction = std::string(insn[j].mnemonic) + " " + insn[j].op_str;
            }
            if (matches > regexes.size())
            {
                cs_free(insn, count);
                cs_close(&handle);
                return false;
            }
            bool isMatch = std::regex_match(instruction, regexes[matches]);
            if (isMatch)
            {
                matches++;
                gadget.emplace_back(instruction);
            }
            else if (gapCounter < gapSize)
            {
                if (strcmp(insn[j].mnemonic, "call") == 0 ||
                        strcmp(insn[j].mnemonic, "ret") == 0 ||
                        strcmp(insn[j].mnemonic, "syscall") == 0 ||
                        strcmp(insn[j].mnemonic, "jb") == 0 ||
                        strcmp(insn[j].mnemonic, "jbe") == 0 ||
                        strcmp(insn[j].mnemonic, "jcxz") == 0 ||
                        strcmp(insn[j].mnemonic, "jecxz") == 0 ||
                        strcmp(insn[j].mnemonic, "jknzd") == 0 ||
                        strcmp(insn[j].mnemonic, "jkzd") == 0 ||
                        strcmp(insn[j].mnemonic, "jl") == 0 ||
                        strcmp(insn[j].mnemonic, "jle") == 0 ||
                        strcmp(insn[j].mnemonic, "jmp") == 0 ||
                        strcmp(insn[j].mnemonic, "jnb") == 0 ||
                        strcmp(insn[j].mnemonic, "jnbe") == 0 ||
                        strcmp(insn[j].mnemonic, "jnl") == 0 ||
                        strcmp(insn[j].mnemonic, "jnle") == 0 ||
                        strcmp(insn[j].mnemonic, "jno") == 0 ||
                        strcmp(insn[j].mnemonic, "jnp") == 0 ||
                        strcmp(insn[j].mnemonic, "jns") == 0 ||
                        strcmp(insn[j].mnemonic, "jnz") == 0 ||
                        strcmp(insn[j].mnemonic, "jo") == 0 ||
                        strcmp(insn[j].mnemonic, "jp") == 0 ||
                        strcmp(insn[j].mnemonic, "jrcxz") == 0 ||
                        strcmp(insn[j].mnemonic, "js") == 0 ||
                        strcmp(insn[j].mnemonic, "jz") == 0
                )
                {
                    gapCounter = 0;
                    matches = 0;
                    gadget.clear();
                }
                else
                {
                    gadget.emplace_back(instruction);
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
                firstOffset = insn[j].address;
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
            }
        }
        cs_free(insn, count);
        cs_close(&handle);
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
