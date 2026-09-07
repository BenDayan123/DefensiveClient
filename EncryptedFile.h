#ifndef ENCRYPTEDFILE_H
#define ENCRYPTEDFILE_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Holds encrypted file contents and transfer metadata.
 */
struct EncryptedFileData {
    std::string fileName;
    uint32_t origFileSize{ 0 };
    uint32_t crc{ 0 };
    std::vector<uint8_t> encryptedContent;
};

#endif