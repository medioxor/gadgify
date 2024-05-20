#include "Gadgify.h"

#include <utility>

Gadgify::Gadgify(const std::vector<char> &binaryContents, cs_arch arch, cs_mode mode)
{
    arch_ = arch;
    mode_ = mode;
    sections_.emplace_back(
        binaryContents,
        true,
        0
    );
}

Gadgify::Gadgify(std::vector<char> binaryContents, bool allowCet)
{
    BINARYTYPE type = DetermineBinaryType(binaryContents);
    if (type == BINARYTYPE::PE)
    {
        std::optional<PEFile> pe = PEFile::Create(std::move(binaryContents));
        if (pe.has_value())
        {
            if (!allowCet && pe->isCetCompat())
            {
                //std::cout << "Binary is compatible with Intel CET, not going to search for gadgets." << std::endl;
                return;
            }
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
    }
    if (type == UNKNOWN)
    {
        //std::cout << "Binary is not a valid PE, ELF, or MACH-O" << std::endl;
    }
}

std::optional<Gadgify> Gadgify::Create(std::string filePath, bool allowCet)
{
    return Gadgify::Create(File::Read(std::move(filePath)), allowCet);
}

std::optional<Gadgify> Gadgify::Create(std::vector<char> binaryContents, bool allowCet)
{
    Gadgify gadgify(std::move(binaryContents), allowCet);
    if (gadgify.sections_.empty())
    {
        return std::nullopt;
    }
    else
    {
        return gadgify;
    }
}

std::optional<Gadgify> Gadgify::Create(
        const std::vector<char>& binaryContents,
        std::string arch,
        const std::string& endianness,
        bool isThumb
)
{
    auto mode = static_cast<cs_mode>(0);
    if (endianness == "little")
    {
        mode = static_cast<cs_mode>(mode + CS_MODE_LITTLE_ENDIAN);
    }
    else if (endianness == "big")
    {
        mode = static_cast<cs_mode>(mode + CS_MODE_BIG_ENDIAN);
    }
    else
    {
        std::cout << "Unknown endianness: " << endianness << std::endl;
        return std::nullopt;
    }
    if (isThumb)
    {
        mode = static_cast<cs_mode>(mode + CS_MODE_THUMB);
    }
    cs_arch architecture{};

    if (arch == "x64")
    {
        architecture = CS_ARCH_X86;
        mode = static_cast<cs_mode>(mode + CS_MODE_64);
    }
    if (arch == "x86")
    {
        architecture = CS_ARCH_X86;
        mode = static_cast<cs_mode>(mode + CS_MODE_32);
    }
    if (arch == "arm32")
    {
        architecture = CS_ARCH_ARM;
        if (!isThumb)
        {
            mode = static_cast<cs_mode>(mode + CS_MODE_ARM);
        }
    }
    if (arch == "arm64")
    {
        architecture = CS_ARCH_AARCH64;
        mode = static_cast<cs_mode>(mode + CS_MODE_ARM);
    }

    Gadgify gadgify(binaryContents, architecture, mode);
    if (gadgify.sections_.empty())
    {
        return std::nullopt;
    }
    else
    {
        return gadgify;
    }
}

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         const std::vector<char>& bytes, const std::string &pattern, uint32_t gapSize,
                         const std::string &arch, const std::string &endianness, bool isThumb)
{
    std::optional<Gadgify> gadgify = Gadgify::Create(bytes, arch, endianness, isThumb);

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

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         std::string filePath,
                         const std::string &pattern, uint32_t gapSize, bool allowCet)
{
    GetGadgets(callback, File::Read(std::move(filePath)), pattern, gapSize, allowCet);
}

void Gadgify::GetGadgets(const std::function<void(uint64_t offset, const std::string &gadget)> &callback,
                         std::vector<char> bytes,
                         const std::string &pattern, uint32_t gapSize, bool allowCet)
{
    std::optional<Gadgify> gadgify = Gadgify::Create(std::move(bytes), allowCet);
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

bool Gadgify::Disassemble(
        const std::function<void(std::vector<Instruction>, uint64_t)> &callback,
        cs_arch arch,
        cs_mode mode
)
{
    ThreadPool pool;
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
    uint32_t returnCounter = 0;
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
                    totalDisassembled += insn->size;
                    if (strcmp(insn->mnemonic, returnMnemonic_.data()) == 0)
                    {
                        returnCounter++;
                    }
                    if (returnCounter == 40)
                    {
                        pool.Enqueue([chunk = std::move(instructionChunk), virtualAddress = section.virtualAddress_, callback]() {
                            callback(chunk, virtualAddress);
                        });
                        returnCounter = 0;
                    }
                    totalDisassembled += insn->size;
                }
                if (!instructionChunk.empty())
                {
                    pool.Enqueue([chunk = std::move(instructionChunk), virtualAddress = section.virtualAddress_, callback]() {
                        callback(chunk, virtualAddress);
                    });
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

void Gadgify::SearchGadgets(
        const std::function<void(uint64_t, std::string)> &callback,
        std::vector<std::regex> regexes,
        uint32_t gapSize,
        const std::vector<Instruction> &instructions,
        uint64_t virtualAddress
)
{
    if (regexes.empty())
    {
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
        if (isMatch)
        {
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

BINARYTYPE Gadgify::DetermineBinaryType(const std::vector<char>& binaryContents) {
    std::vector<std::tuple<BINARYTYPE, std::vector<uint8_t>>> types = {
            {BINARYTYPE::PE, {0x4D, 0x5A}},
            {BINARYTYPE::ELF, {0x7F, 0x45, 0x4C, 0x46}},
            {BINARYTYPE::MACH, {0xFE, 0xED, 0xFA, 0xCE}},
            {BINARYTYPE::MACH, {0xFE, 0xED, 0xFA, 0xCF}},
            {BINARYTYPE::MACH, {0xCE, 0xFA, 0xED, 0xFE}}
    };
    if (binaryContents.size() < 4)
    {
        return UNKNOWN;
    }
    for (const auto& [ binaryType, magicBytes ] : types)
    {
        if (memcmp(binaryContents.data(), magicBytes.data(), magicBytes.size()) == 0)
        {
            return binaryType;
        }
    }
    return UNKNOWN;
}
