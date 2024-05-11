#ifndef GADGIFY_PEFILE_H
#define GADGIFY_PEFILE_H

#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <cstring>
#include <iostream>
#include <optional>
#include "File.h"
#include "WindowsTypes.h"
#include "ExecutableBinary.h"

class PEFile : public ExecutableBinary {
    using ExecutableBinary::ExecutableBinary;
public:
    static std::optional<PEFile> Create(std::string filePath);
    static std::optional<PEFile> Create(std::vector<char> binaryContents);
    static std::optional<PEFile> Create(char* binaryContentsBuffer, size_t bufferSize);
private:
    [[nodiscard]] bool Parse();
    bool ParseHeaders();
    bool ParseSections();
    std::vector<char> GetSectionContents(int index);
    IMAGE_DOS_HEADER* dosHeader_{};
    IMAGE_NT_HEADERS64* ntHeaders_{};
    IMAGE_SECTION_HEADER* firstSection_{};
};

#endif //GADGIFY_PEFILE_H
