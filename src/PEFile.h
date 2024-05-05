#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <cstring>
#include "File.h"
#include "WindowsTypes.h"

#ifndef GADGIFY_PEFILE_H
#define GADGIFY_PEFILE_H

class PEFile {
public:
    explicit PEFile(std::string filePath);
    explicit PEFile(std::vector<char> peContents);
    explicit PEFile(char* peContentsBuffer, size_t bufferSize);
    static PEFile Parse(std::string path);
    size_t GetSize();
    size_t GetNumberOfSections() const;
    [[nodiscard]] bool IsValid() const;
    static bool GetSections(
            const std::function<void(IMAGE_SECTION_HEADER sectionHeader, std::vector<char> sectionContents)>& callback,
            std::string filePath);
private:
    IMAGE_SECTION_HEADER GetSectionHeader(int index);
    IMAGE_SECTION_HEADER GetSectionHeader(const std::string& sectionName);
    std::vector<char> GetSectionContents(int index);
    std::vector<char> GetSectionContents(const std::string& sectionName);
    void ParseHeadersAndValidate();
    [[nodiscard]] bool ValidatePtr(uintptr_t address, size_t typeSize) const;
    std::vector<char> peContents_;
    size_t peSize_;
    bool isValid_ = true;
    IMAGE_DOS_HEADER* dosHeader_{};
    IMAGE_NT_HEADERS64* ntHeaders_{};
    IMAGE_SECTION_HEADER* firstSection_{};
    size_t numberOfSections_{};
    uintptr_t peBufferAddr_{};
};


#endif //GADGIFY_PEFILE_H
