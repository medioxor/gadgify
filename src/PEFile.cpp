#include "PEFile.h"

#include <utility>

bool PEFile::ParseHeaders()
{
    if (binaryContents_.size() < sizeof(IMAGE_DOS_HEADER))
    {
        isValid_ = false;
        return false;
    }

    dosHeader_ = reinterpret_cast<IMAGE_DOS_HEADER*>(binaryContents_.data());
    if (dosHeader_->e_magic != IMAGE_DOS_SIGNATURE)
    {
        isValid_ = false;
        return false;
    }

    uint32_t ntHeadersRva = dosHeader_->e_lfanew;
    ntHeaders_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(binaryBufferAddr_ + ntHeadersRva);
    if (!ValidatePtr(reinterpret_cast<uintptr_t>(ntHeaders_), sizeof(IMAGE_NT_HEADERS64)))
    {
        isValid_ = false;
        return false;
    }

    switch (ntHeaders_->FileHeader.Machine)
    {
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_IA64:
            arch_ = CS_ARCH_X86;
            mode_ = CS_MODE_64;
            break;
        case IMAGE_FILE_MACHINE_I386:
            arch_ = CS_ARCH_X86;
            mode_ = CS_MODE_32;
            break;
        case IMAGE_FILE_MACHINE_ARM:
            arch_ = CS_ARCH_ARM;
            mode_ = CS_MODE_ARM;
            break;
        case IMAGE_FILE_MACHINE_ARMNT:
            arch_ = CS_ARCH_ARM;
            mode_ = CS_MODE_THUMB;
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            arch_ = CS_ARCH_AARCH64;
            mode_ = CS_MODE_ARM;
            break;
        default:
            isValid_ = false;
            return false;
    }

    if (ntHeaders_->Signature != IMAGE_NT_SIGNATURE)
    {
        isValid_ = false;
        return false;
    }

    firstSection_ = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<uintptr_t>(ntHeaders_) +
            FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders_->FileHeader.SizeOfOptionalHeader);

    if (!ValidatePtr(reinterpret_cast<uintptr_t>(firstSection_), sizeof(IMAGE_SECTION_HEADER)))
    {
        firstSection_ = nullptr;
        isValid_ = false;
        return false;
    }

    numberOfSections_ = ntHeaders_->FileHeader.NumberOfSections;

    IMAGE_DATA_DIRECTORY* debugDataDirectory = &ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (ValidatePtr(reinterpret_cast<uintptr_t>(debugDataDirectory), sizeof(IMAGE_DATA_DIRECTORY)))
    {
        IMAGE_SECTION_HEADER* sectionHeader = firstSection_;
        int currentSection = 0;
        while (ValidatePtr(reinterpret_cast<uintptr_t>(sectionHeader), sizeof(IMAGE_SECTION_HEADER )) && currentSection < numberOfSections_)
        {
            if ((debugDataDirectory->VirtualAddress >= sectionHeader->VirtualAddress) && (debugDataDirectory->VirtualAddress < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)))
            {
                uintptr_t sectionData = binaryBufferAddr_ + sectionHeader->PointerToRawData;
                DWORD relativeOffset = (debugDataDirectory->VirtualAddress - sectionHeader->VirtualAddress);
                size_t debugDirectoryCount = debugDataDirectory->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
                int currentEntry = 0;
                auto debugDirectory = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(sectionData + relativeOffset);
                while (ValidatePtr(reinterpret_cast<uintptr_t>(debugDirectory), sizeof(IMAGE_DEBUG_DIRECTORY)) && currentEntry < debugDirectoryCount)
                {
                    if (debugDirectory->Type == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS)
                    {
                        auto* characteristics = reinterpret_cast<uint32_t*>(binaryBufferAddr_ + debugDirectory->PointerToRawData);
                        if (ValidatePtr(reinterpret_cast<uintptr_t>(characteristics), sizeof(uint32_t)))
                        {
                            if (*characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
                            {
                                cetCompat_ = true;
                            }
                            if (*characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE)
                            {
                                cetCompatStrict_ = true;
                            }
                            if (*characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE)
                            {
                                cetIpValidation_ = true;
                            }
                            if (*characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC)
                            {
                                cetAllowDynamicApi_ = true;
                            }
                        }
                    }
                    currentEntry++;
                    debugDirectory += sizeof(IMAGE_DEBUG_DIRECTORY);
                }
            }
            currentSection++;
            sectionHeader += sizeof(IMAGE_SECTION_HEADER);
        }
    }

    isValid_ = true;
    return true;
}

bool PEFile::ParseSections()
{
    if (numberOfSections_ == 0)
    {
        return false;
    }
    IMAGE_SECTION_HEADER* sectionHeader = firstSection_;
    int currentSection = 0;
    while (ValidatePtr(reinterpret_cast<uintptr_t>(sectionHeader), sizeof(IMAGE_SECTION_HEADER )) && currentSection < numberOfSections_)
    {
        std::vector<char> sectionContents = GetSectionContents(currentSection);
        bool isExecutable = sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE;
        if (!sectionContents.empty())
        {
            sections_.emplace_back(sectionContents, isExecutable, sectionHeader->VirtualAddress);
        }
        currentSection++;
        sectionHeader += sizeof(IMAGE_SECTION_HEADER);
    }
    return true;
}

std::vector<char> PEFile::GetSectionContents(int index)
{
    IMAGE_SECTION_HEADER sectionHeader = firstSection_[index];
    if (sectionHeader.SizeOfRawData < 1)
    {
        return {};
    }
    char* sectionContents = reinterpret_cast<char*>(binaryBufferAddr_ + sectionHeader.PointerToRawData);
    if (!ValidatePtr(reinterpret_cast<std::uintptr_t>(sectionContents), sectionHeader.SizeOfRawData))
    {
        return {};
    }
    char* sectionContentsEnd = reinterpret_cast<char*>(
            reinterpret_cast<std::uintptr_t>(sectionContents) + sectionHeader.SizeOfRawData);

    return {sectionContents, sectionContentsEnd};
}

std::optional<PEFile> PEFile::Create(std::string filePath) {
    PEFile pe(std::move(filePath));
    if (pe.Parse())
    {
        return pe;
    }
    return std::nullopt;
}

std::optional<PEFile> PEFile::Create(std::vector<char> binaryContents) {
    PEFile pe(std::move(binaryContents));
    if (pe.Parse())
    {
        return pe;
    }
    return std::nullopt;
}

std::optional<PEFile> PEFile::Create(char *binaryContentsBuffer, size_t bufferSize) {
    PEFile pe(binaryContentsBuffer, bufferSize);
    if (pe.Parse())
    {
        return pe;
    }
    return std::nullopt;
}

bool PEFile::Parse() {
    if (!ParseHeaders())
    {
        return false;
    }
    if (!ParseSections())
    {
        return false;
    }
    return true;
}

bool PEFile::isCetCompat() const {
    return cetAllowDynamicApi_ || cetCompatStrict_ || cetCompat_ || cetIpValidation_;
}
