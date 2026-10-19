#ifndef TRANSFER_CLIENT_H
#define TRANSFER_CLIENT_H

#include <string>
#include <vector>
#include <array>
#include <optional>
#include <initializer_list>

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
    ConfigManager config;
    NetworkClient client;
    CryptoHelper crypto;

    std::array<uint8_t, Protocol::UUID_SIZE> clientId{};
    std::vector<uint8_t> decryptedAesKey;

    /**
     * @brief Receives one server response and validates it before use.
     * Checks the payload size against the protocol before reading it, then checks
     * the response code, the server version and the echoed client ID.
     * @param acceptedCodes Response codes that count as success for the current step.
     * @return The validated response, or std::nullopt (error already printed).
     */
    std::optional<Protocol::ServerResponse> receiveResponse(
        std::initializer_list<Protocol::ResponseCode> acceptedCodes);

    /**
     * @brief Attempts to reconnect using saved credentials (Code 827).
     * Uses the name and UUID from me.info and the private key from priv.key
     * (falling back to me.info line 3).
     * @param needsRegistration Output flag set to true if reconnect is rejected or credentials are bad.
     * @return True if reconnection and AES key retrieval succeeded, false otherwise.
     */
    bool tryReconnect(bool& needsRegistration);

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

    /**
     * @brief Encrypts and transmits a single file by path.
     * @param filePath Path to the file.
     * @return True if transfer and verification succeeded, false otherwise.
     */
    bool sendSingleFile(const std::string& filePath);

public:
    TransferClient() = default;

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