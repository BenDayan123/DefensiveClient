#ifndef ENCRYPTEDFILE_H
#define ENCRYPTEDFILE_H

#include <string>
#include <vector>
#include <cstdint>

// crctab for linkage across translation units
extern const uint_fast32_t crctab[8][256];

/**
 * @brief Holds encrypted file contents and transfer metadata.
 */
struct EncryptedFileData {
    std::string fileName;
    uint32_t origFileSize{ 0 };
    uint32_t crc{ 0 };
    std::vector<uint8_t> encryptedContent;
};

namespace EncryptedFile {
    std::optional<EncryptedFileData> createEncryptedFile(
        const std::string& filePath,
        const std::vector<uint8_t>& aesKey
    );
}

#endif