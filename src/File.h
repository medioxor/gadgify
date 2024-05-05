#include <filesystem>
#include <fstream>
#include <vector>

#ifndef GADGIFY_FILE_H
#define GADGIFY_FILE_H

struct FileContents
{
    size_t size;
    char* contents;
};

class File {
public:
    explicit File(std::string filePath);
    explicit File(std::string filePath, std::ios_base::openmode openMode);
    virtual ~File();
    static FileContents Read(std::string filePath);
    FileContents Read();
    static bool Delete(std::string filePath);
    static size_t GetSize(std::string filePath);
    bool Delete();
    size_t GetSize();
private:
    std::string filePath_;
    std::ifstream fileStream_;
};


#endif //GADGIFY_FILE_H
