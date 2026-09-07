#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <vector>

#include "EncryptedFile.h"
#include "CryptoHelper.h"

/**
 * @brief Reads a local file, computes its POSIX CRC, and encrypts it with AES-256-CBC.
 * @param filePath Path to the target file.
 * @param aesKey 32-byte symmetric AES key.
 * @return Populated EncryptedFileData on success, or std::nullopt on failure.
 */
std::optional<EncryptedFileData> createEncryptedFile(
    const std::string& filePath,
    const std::vector<uint8_t>& aesKey) {

    // Verify file existence
    if (!std::filesystem::exists(filePath)) {
        std::cerr << "[-] Error: File not found: " << filePath << std::endl;
        return std::nullopt;
    }

    // Open and read file into memory
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Could not open file: " << filePath << std::endl;
        return std::nullopt;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> rawBuffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(rawBuffer.data()), fileSize)) {
        std::cerr << "[-] Error: Failed to read file data: " << filePath << std::endl;
        return std::nullopt;
    }

    EncryptedFileData result;
    result.origFileSize = static_cast<uint32_t>(rawBuffer.size());
    result.fileName = std::filesystem::path(filePath).filename().string();

    // Compute POSIX CRC checksum on the raw, unencrypted bytes
    result.crc = CryptoHelper::calculateCksum(rawBuffer);

    // Encrypt file data using AES-256-CBC
    result.encryptedContent = CryptoHelper::encryptAesCbc(aesKey, rawBuffer);
    if (result.encryptedContent.empty() && result.origFileSize > 0) {
        std::cerr << "[-] Error: AES encryption failed." << std::endl;
        return std::nullopt;
    }

    return result;
}