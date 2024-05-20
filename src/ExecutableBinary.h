#ifndef GADGIFY_EXECUTABLEBINARY_H
#define GADGIFY_EXECUTABLEBINARY_H

#include <vector>
#include <string>
#include <capstone/capstone.h>
#include <iostream>
#include <map>
#include "File.h"

enum BINARYTYPE
{   PE = 0,
    ELF = 1,
    MACH = 2,
    RAW = 3,
    UNKNOWN = 4
};

class Instruction {
public:
    Instruction(char* mnemonic, char* op_str, uint64_t offset);
    char instruction_[200]{};
    char mnemonic_[32]{};
    uint64_t offset_;
};

class Section {
public:
    Section(const std::vector<char> &contents, bool isExecutable, uint64_t virtualAddress);
    std::vector<char> contents_;
    std::vector<std::vector<Instruction>> instructionChunks_;
    bool isExecutable_;
    uint64_t virtualAddress_;
};

class ExecutableBinary {
public:
    size_t GetSize();
    size_t GetNumberOfSections() const;
    cs_arch GetArch() const;
    cs_mode GetMode() const;
    std::vector<Section> GetSections();
    [[nodiscard]] bool IsValid() const;
protected:
    explicit ExecutableBinary(std::string filePath);
    explicit ExecutableBinary(std::vector<char> binaryContents);
    explicit ExecutableBinary(char* binaryContentsBuffer, size_t bufferSize);
    [[nodiscard]] bool ValidatePtr(uintptr_t address, size_t typeSize) const;
    bool isValid_{false};
    std::vector<Section> sections_;
    size_t numberOfSections_{0};
    std::vector<char> binaryContents_;
    size_t binarySize_;
    uintptr_t binaryBufferAddr_{0};
    cs_arch arch_{};
    cs_mode mode_{};
};

#endif //GADGIFY_EXECUTABLEBINARY_H
