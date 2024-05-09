#include "File.h"

File::File(std::string filePath) : filePath_(std::move(filePath)) {
    if (std::filesystem::exists(filePath_))
    {
        fileStream_.open(filePath_, std::ios::in | std::ios::binary);
    }
}

File::File(std::string filePath, std::ios_base::openmode openMode) : filePath_(std::move(filePath)) {
    if (std::filesystem::exists(filePath_))
    {
        fileStream_.open(filePath_, openMode);
    }
}

bool File::Delete(std::string filePath) {
    File file(std::move(filePath));
    return file.Delete();
}

File::~File() {
    if (fileStream_.is_open())
    {
        fileStream_.close();
    }
}

bool File::Delete() {
    if (fileStream_.is_open())
    {
        fileStream_.close();
    }
    std::filesystem::path path(filePath_);
    std::filesystem::remove(path);
    return std::filesystem::remove(path);
}

size_t File::GetSize() {
    if (fileStream_.is_open())
    {
        fileStream_.seekg(0, std::ios::end);
        size_t size = fileStream_.tellg();
        fileStream_.seekg(0, std::ios::beg);
        return size;
    }
    else
    {
        return 0;
    }
}

size_t File::GetSize(std::string filePath) {
    File file(std::move(filePath));
    return file.GetSize();
}

std::vector<char> File::Read(std::string filePath) {
    File file(std::move(filePath));
    return file.Read();
}

std::vector<char> File::Read() {
    std::vector<char> fileContents(GetSize());

    fileStream_.read(fileContents.data(), static_cast<long long>(fileContents.size()));

    return fileContents;
}
