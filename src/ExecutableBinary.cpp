#include "ExecutableBinary.h"

#include <utility>

ExecutableBinary::ExecutableBinary(std::string filePath)
{
    binaryContents_ = File::Read(std::move(filePath));
    binarySize_ = binaryContents_.size();
    binaryBufferAddr_ = reinterpret_cast<uintptr_t>(binaryContents_.data());
}

ExecutableBinary::ExecutableBinary(std::vector<char> binaryContents)
{
    binaryContents_ = std::move(binaryContents);
    binarySize_ = binaryContents_.size();
    binaryBufferAddr_ = reinterpret_cast<uintptr_t>(binaryContents_.data());
}

ExecutableBinary::ExecutableBinary(char *binaryContentsBuffer, size_t bufferSize)
{
    binarySize_ = bufferSize;
    char* peContentsBufferEnd = reinterpret_cast<char*>(
            reinterpret_cast<std::uintptr_t>(binaryContentsBuffer) + bufferSize);
    binaryContents_ = std::vector(binaryContentsBuffer, peContentsBufferEnd);
    binaryBufferAddr_ = reinterpret_cast<uintptr_t>(binaryContents_.data());
}

bool ExecutableBinary::ValidatePtr(uintptr_t address, size_t typeSize) const
{
    if ((address + typeSize) > (binaryBufferAddr_ + binarySize_) || address < binaryBufferAddr_)
    {
        return false;
    }
    return true;
}

bool ExecutableBinary::IsValid() const
{
    return isValid_;
}

size_t ExecutableBinary::GetNumberOfSections() const
{
    return numberOfSections_;
}

size_t ExecutableBinary::GetSize()
{
    return binaryContents_.size();
}

bool ExecutableBinary::Disassemble(cs_arch arch, cs_mode mode) {
    switch (arch)
    {
        case CS_ARCH_X86:
            controlFlowMnemonics_ = {
                    "call",
                    "ret",
                    "syscall",
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
        case CS_ARCH_AARCH64:
            returnMnemonic_ = "ret";
            break;
    }
    csh handle{0};
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
        return false;
    }
    for (Section& section : sections_)
    {
        if (section.isExecutable_)
        {
            cs_insn* instructions;
            size_t instructionCount = cs_disasm(handle, reinterpret_cast<const uint8_t*>(section.contents_.data()), section.contents_.size(), 0x0, 0, &instructions);
            size_t currentChunk = 0;
            section.instructionChunks_.emplace_back();
            for (int i = 0; i < instructionCount; i++) {
                std::string instruction;
                if (instructions[i].op_str[0] == '\0')
                {
                    instruction = std::string(instructions[i].mnemonic);
                }
                else
                {
                    instruction = std::string(instructions[i].mnemonic) + " " + instructions[i].op_str;
                }
                if (strcmp(instructions[i].mnemonic, returnMnemonic_.data()) == 0)
                {
                    section.instructionChunks_[currentChunk].emplace_back(
                            instruction,
                            instructions[i].mnemonic,
                            instructions[i].address
                    );
                    section.instructionChunks_.emplace_back();
                    currentChunk++;
                }
                section.instructionChunks_[currentChunk].emplace_back(
                        instruction,
                        instructions[i].mnemonic,
                        instructions[i].address
                );
            }
            cs_free(instructions, instructionCount);
        }
    }
    cs_close(&handle);

    return true;
}

std::vector<Section> ExecutableBinary::GetSections() {
    return sections_;
}

const std::vector<std::string> &ExecutableBinary::GetControlFlowMnemonics() const {
    return controlFlowMnemonics_;
}

Section::Section(const std::vector<char> &contents, bool isExecutable, uint64_t virtualAddress) :
    contents_(contents),
    isExecutable_(isExecutable),
    virtualAddress_(virtualAddress){}

Instruction::Instruction(std::string instruction, std::string mnemonic, uint64_t offset) :
    instruction_(std::move(instruction)),
    mnemonic_(std::move(mnemonic)),
    offset_(offset){}
