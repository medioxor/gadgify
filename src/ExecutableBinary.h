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
    RAW = 3
};

class Instruction {
public:
    Instruction(std::string instruction, std::string mnemonic, uint64_t offset);
    std::string instruction_;
    std::string mnemonic_;
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
    std::vector<Section> GetSections();
    const std::vector<std::string> &GetControlFlowMnemonics() const;
    [[nodiscard]] bool IsValid() const;
protected:
    explicit ExecutableBinary(std::string filePath);
    explicit ExecutableBinary(std::vector<char> binaryContents);
    explicit ExecutableBinary(char* binaryContentsBuffer, size_t bufferSize);
    bool Disassemble(cs_arch arch, cs_mode mode);
    [[nodiscard]] bool ValidatePtr(uintptr_t address, size_t typeSize) const;
    bool isValid_{false};
    std::vector<Section> sections_;
    size_t numberOfSections_{0};
    std::vector<char> binaryContents_;
    size_t binarySize_;
    uintptr_t binaryBufferAddr_{0};
    std::string returnMnemonic_{};
    std::vector<std::string> controlFlowMnemonics_{};
    cs_arch arch_{};
    cs_mode mode_{};
};

#endif //GADGIFY_EXECUTABLEBINARY_H
