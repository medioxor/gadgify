#include "PEFile.h"

PEFile::PEFile(std::string filePath)
{
    FileContents file = File::Read(std::move(filePath));
    peContents_ = std::vector<char>(file.size);
    memcpy(peContents_.data(), file.contents, file.size);
    free(file.contents);
    peSize_ = file.size;
    peBufferAddr_ = reinterpret_cast<uintptr_t>(peContents_.data());
    ParseHeadersAndValidate();
}

PEFile::PEFile(std::vector<char> peContents) :
    peContents_(std::move(peContents)),
    peSize_(peContents.size()),
    peBufferAddr_(reinterpret_cast<uintptr_t>(peContents_.data()))
{
    ParseHeadersAndValidate();
}

PEFile::PEFile(char *peContentsBuffer, size_t bufferSize) :
    peSize_(bufferSize)
{
    char* peContentsBufferEnd = reinterpret_cast<char*>(
            reinterpret_cast<std::uintptr_t>(peContentsBuffer) + bufferSize);
    peContents_ = std::vector(peContentsBuffer, peContentsBufferEnd);
    peBufferAddr_ = reinterpret_cast<uintptr_t>(peContents_.data());
    ParseHeadersAndValidate();
}

PEFile PEFile::Parse(std::string path)
{
    return PEFile(std::move(path));
}

size_t PEFile::GetSize()
{
    return peContents_.size();
}

void PEFile::ParseHeadersAndValidate()
{
    if (peContents_.size() < sizeof(IMAGE_DOS_HEADER))
    {
        isValid_ = false;
        return;
    }

    dosHeader_ = reinterpret_cast<IMAGE_DOS_HEADER*>(peContents_.data());
    if (dosHeader_->e_magic != IMAGE_DOS_SIGNATURE)
    {
        isValid_ = false;
        return;
    }

    uint32_t ntHeadersRva = dosHeader_->e_lfanew;
    ntHeaders_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(peBufferAddr_ + ntHeadersRva);
    if (!ValidatePtr(reinterpret_cast<uintptr_t>(ntHeaders_), sizeof(IMAGE_NT_HEADERS64)))
    {
        isValid_ = false;
        return;
    }
    if (ntHeaders_->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 && ntHeaders_->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        isValid_ = false;
        return;
    }

    if (ntHeaders_->Signature != IMAGE_NT_SIGNATURE)
    {
        isValid_ = false;
        return;
    }

    firstSection_ = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<uintptr_t>(ntHeaders_) +
            FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders_->FileHeader.SizeOfOptionalHeader);

    if (!ValidatePtr(reinterpret_cast<uintptr_t>(firstSection_), sizeof(IMAGE_SECTION_HEADER)))
    {
        firstSection_ = nullptr;
        isValid_ = false;
        return;
    }

    numberOfSections_ = ntHeaders_->FileHeader.NumberOfSections;

    isValid_ = true;
}

bool PEFile::ValidatePtr(uintptr_t address, size_t typeSize) const
{
    if ((address + typeSize) > (peBufferAddr_ + peSize_) || address < peBufferAddr_)
    {
        return false;
    }
    return true;
}

bool PEFile::IsValid() const
{
    return isValid_;
}

bool PEFile::GetSections(const std::function<void(IMAGE_SECTION_HEADER sectionHeader, std::vector<char> sectionContents)> &callback, std::string filePath)
{
    PEFile pe(std::move(filePath));

    if (!pe.IsValid())
    {
        std::cout << "The file provided is not a valid Portable Executable (PE)." << std::endl;
        return false;
    }

    for (int i = 0; i < pe.GetNumberOfSections(); i++)
    {
        IMAGE_SECTION_HEADER sectionHeader = pe.GetSectionHeader(i);
        std::vector<char> sectionContents = pe.GetSectionContents(i);
        if (!sectionContents.empty())
        {
            callback(sectionHeader, sectionContents);
        }
    }

    return true;
}

IMAGE_SECTION_HEADER PEFile::GetSectionHeader(int index)
{
    if (index < numberOfSections_)
    {
        return firstSection_[index];
    }
    else
    {
        return {0};
    }
}

IMAGE_SECTION_HEADER PEFile::GetSectionHeader(const std::string& sectionName)
{
    for (int i = 0; i < numberOfSections_; i++)
    {
        IMAGE_SECTION_HEADER section = firstSection_[i];
        std::string currentSectionName(reinterpret_cast<const char *const>(section.Name));
        if (currentSectionName == sectionName)
        {
            return section;
        }
    }

    return {0};
}

size_t PEFile::GetNumberOfSections() const
{
    return numberOfSections_;
}

std::vector<char> PEFile::GetSectionContents(int index)
{
    IMAGE_SECTION_HEADER sectionHeader = GetSectionHeader(index);
    std::string sectionName(reinterpret_cast<const char *const>(sectionHeader.Name));
    return GetSectionContents(sectionName);
}

std::vector<char> PEFile::GetSectionContents(const std::string &sectionName)
{
    IMAGE_SECTION_HEADER sectionHeader = GetSectionHeader(sectionName);
    if (sectionHeader.SizeOfRawData < 1)
    {
        return {};
    }
    char* sectionContents = reinterpret_cast<char*>(peBufferAddr_ + sectionHeader.PointerToRawData);
    if (!ValidatePtr(reinterpret_cast<std::uintptr_t>(sectionContents), sectionHeader.SizeOfRawData))
    {
        return {};
    }
    char* sectionContentsEnd = reinterpret_cast<char*>(
            reinterpret_cast<std::uintptr_t>(sectionContents) + sectionHeader.SizeOfRawData);

    return {sectionContents, sectionContentsEnd};
}
