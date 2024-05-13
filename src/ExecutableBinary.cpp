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

std::vector<Section> ExecutableBinary::GetSections() {
    return sections_;
}

cs_arch ExecutableBinary::GetArch() const {
    return arch_;
}

cs_mode ExecutableBinary::GetMode() const {
    return mode_;
}

Section::Section(const std::vector<char> &contents, bool isExecutable, uint64_t virtualAddress) :
    contents_(contents),
    isExecutable_(isExecutable),
    virtualAddress_(virtualAddress){}

Instruction::Instruction(char* mnemonic, char* op_str, uint64_t offset) : offset_(offset)
{
    size_t mnemonicLen = strlen(mnemonic);
    size_t op_strLen = strlen(op_str);
    if (mnemonicLen + op_strLen + 2 < sizeof(instruction_))
    {
        if (op_strLen > 0)
        {
            memcpy(instruction_, mnemonic, mnemonicLen);
            instruction_[mnemonicLen] = ' ';
            memcpy(instruction_ + mnemonicLen + 1 , op_str, op_strLen);
            instruction_[mnemonicLen + op_strLen + 1] = '\0';
        }
        else
        {
            memcpy(instruction_, mnemonic, mnemonicLen);
            instruction_[mnemonicLen] = '\0';
        }
    }
    if (mnemonicLen < (sizeof(mnemonic_) + 1))
    {
        memcpy(mnemonic_, mnemonic, mnemonicLen);
    }
}
