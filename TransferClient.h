#ifndef TRANSFER_CLIENT_H
#define TRANSFER_CLIENT_H

#include <string>
#include <vector>
#include <array>

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "CryptoHelper.h"
#include "EncryptedFile.h"
#include "Protocol.h"

/**
 * @brief Manages the client connection, authentication, and encrypted file transfer.
 */
class TransferClient {
private:
    std::string targetFilePath;
    ConfigManager config;
    NetworkClient client;
    CryptoHelper crypto;

    std::array<uint8_t, Protocol::UUID_SIZE> clientId{};
    std::vector<uint8_t> decryptedAesKey;

    /**
     * @brief Attempts to reconnect using saved credentials (Code 827).
     * @param clientName The client username.
     * @param needsRegistration Output flag set to true if reconnect is rejected or credentials are bad.
     * @return True if reconnection and AES key retrieval succeeded, false otherwise.
     */
    bool tryReconnect(const std::string& clientName, bool& needsRegistration);

    /**
     * @brief Registers as a new client (Code 825) and exchanges RSA public key (Code 826).
     * @param clientName The client username.
     * @return True if registration and key exchange succeeded, false otherwise.
     */
    bool registerAndExchangeKeys(const std::string& clientName);

    /**
     * @brief Handles the full authentication flow: tries reconnect first, falls back to registration.
     * @param clientName The client username.
     * @return True if the client is authenticated and has an AES key, false otherwise.
     */
    bool authenticate(const std::string& clientName);

    /**
     * @brief Sends the encrypted file (Code 828) and handles CRC confirmation attempts (Codes 900/901/902).
     * @param fileData Struct containing file metadata, encrypted content, and local CRC.
     * @return True if server verified the CRC successfully, false if all attempts failed.
     */
    bool transferAndVerify(const EncryptedFileData& fileData);

public:
    /**
     * @brief Creates a TransferClient instance.
     * @param targetFilePath Path to the file that will be encrypted and sent.
     */
    TransferClient(std::string targetFilePath = "test.jfif");

    ~TransferClient() = default;

    TransferClient(const TransferClient&) = delete;
    TransferClient& operator=(const TransferClient&) = delete;

    /**
     * @brief Runs the complete client flow: connects, authenticates, encrypts, and sends the file.
     * @return True if the transfer completed successfully, false on any error.
     */
    bool run();
};

#endif