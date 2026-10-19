#define _WIN32_WINNT 0x0A00

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <array>
#include <optional>
#include <algorithm>

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "CryptoHelper.h"
#include "EncryptedFile.h"
#include "Protocol.h"
#include "TransferClient.h"

static const std::string SERVER_ERROR_MSG = "server responded with an error";

// Receives and validates a single server response
std::optional<Protocol::ServerResponse> TransferClient::receiveResponse(
    std::initializer_list<Protocol::ResponseCode> acceptedCodes) {

    auto header = Protocol::PacketParser::parseHeader(client.receiveExact(Protocol::RESPONSE_HEADER_SIZE));
    if (!header.has_value()) {
        std::cerr << SERVER_ERROR_MSG << " (no valid response header)" << std::endl;
        return std::nullopt;
    }
    const auto code = static_cast<uint16_t>(header->code);

    if (header->version != Protocol::SERVER_VERSION) {
        std::cerr << "[!] Warning: unexpected server version " << static_cast<int>(header->version) << std::endl;
    }

    // Never trust the size sent by the server: validate it before allocating anything
    const auto expectedSize = Protocol::PacketParser::expectedPayloadSize(header->code);
    if (!expectedSize.has_value() || header->payloadSize != *expectedSize) {
        std::cerr << SERVER_ERROR_MSG << " (code " << code
            << ", invalid payload size " << header->payloadSize << ")" << std::endl;
        client.disconnect();  // the stream is out of sync and can't be trusted anymore
        return std::nullopt;
    }

    Protocol::ServerResponse response{ *header, client.receiveExact(header->payloadSize) };
    if (response.payload.size() != header->payloadSize) {
        std::cerr << SERVER_ERROR_MSG << " (connection lost while reading the payload)" << std::endl;
        return std::nullopt;
    }

    if (std::find(acceptedCodes.begin(), acceptedCodes.end(), header->code) == acceptedCodes.end()) {
        std::cerr << SERVER_ERROR_MSG << " (unexpected response code " << code << ")" << std::endl;
        return std::nullopt;
    }

    // Every accepted response except 1600 (assigns a new ID) and 1606 (rejection) must echo our ID
    const bool echoesClientId = header->code != Protocol::ResponseCode::RegistrationSuccess &&
        header->code != Protocol::ResponseCode::ReconnectRejected;
    if (echoesClientId && !std::equal(clientId.begin(), clientId.end(), response.payload.begin())) {
        std::cerr << SERVER_ERROR_MSG << " (client ID mismatch in response code " << code << ")" << std::endl;
        return std::nullopt;
    }

    return response;
}

// Handles registration and RSA key exchange (Codes 825 & 826)
bool TransferClient::registerAndExchangeKeys(const std::string& clientName) {
    std::cout << "[*] Sending registration request (Code 825)..." << std::endl;

    // Send registration request (Code 825)
    auto packet = Protocol::PacketBuilder::buildRegistration(clientName);
    if (!client.send(packet)) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    // Receive registration response (Code 1600)
    auto registrationResponse = receiveResponse({ Protocol::ResponseCode::RegistrationSuccess });
    if (!registrationResponse.has_value()) {
        return false;
    }

    auto assignedUuidOpt = Protocol::PacketParser::parseClientIdPayload(registrationResponse->payload);
    if (!assignedUuidOpt.has_value()) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }
    clientId = *assignedUuidOpt;

    std::cout << "[+] Registered successfully (Code 1600)." << std::endl;

    // Generate RSA-1024 key pair and must have credentials
    crypto.generateRsaKeys();
    if (!config.saveClientInfo(clientName, clientId, crypto.getPrivateKeyBase64())) {
        std::cerr << "Error: failed to save client credentials (me.info / priv.key)." << std::endl;
        return false;
    }

    // Send public key (Code 826)
    std::cout << "[*] Sending RSA public key (Code 826)..." << std::endl;
    auto pubKeyPacket = Protocol::PacketBuilder::buildPublicKeyExchange(
        clientId,
        clientName,
        crypto.getPublicKeyDER()
    );
    if (!client.send(pubKeyPacket)) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    // Receive encrypted AES key (Code 1602)
    auto aesResponse = receiveResponse({ Protocol::ResponseCode::AesKeyReceived });
    if (!aesResponse.has_value()) {
        return false;
    }

    auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(aesResponse->payload);
    if (!aesOpt.has_value()) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    decryptedAesKey = crypto.decryptAesKey(aesOpt->encryptedAesKey);
    std::cout << "[+] Received and decrypted symmetric AES key (Code 1602)." << std::endl;
    return true;
}

// Handles reconnection attempt (Code 827)
bool TransferClient::tryReconnect(bool& needsRegistration) {
    // priv.key is the source of truth for the private key; me.info line 3 is a fallback
    const auto privKeyOpt = config.loadPrivateKey();
    const bool credentialsLoaded = config.loadClientInfo() &&
        crypto.loadPrivateKeyBase64(privKeyOpt.value_or(config.getClientInfo().privateKeyBase64));

    if (!credentialsLoaded) {
        std::cerr << "[!] Stored credentials are invalid. Falling back to new registration." << std::endl;
        config.removeClientInfo();
        needsRegistration = true;
        return false;
    }

    // Reconnect with the identity stored in me.info, not the name from transfer.json
    const ClientInfo& storedInfo = config.getClientInfo();
    clientId = storedInfo.uuid;
    std::cout << "[*] Existing credentials found. Sending reconnect request (Code 827)..." << std::endl;

    // Send Reconnect request (Code 827)
    auto reconnectPacket = Protocol::PacketBuilder::buildReconnect(clientId, storedInfo.name);
    if (!client.send(reconnectPacket)) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    // Receive reconnect response (Code 1605 or 1606)
    auto reconnectResponse = receiveResponse({
        Protocol::ResponseCode::ReconnectApproved,
        Protocol::ResponseCode::ReconnectRejected });
    if (!reconnectResponse.has_value()) {
        return false;
    }

    // Handle server rejection (Code 1606)
    if (reconnectResponse->header.code == Protocol::ResponseCode::ReconnectRejected) {
        std::cout << "[!] Server rejected reconnect (Code 1606). Registering as a new client..." << std::endl;
        config.removeClientInfo();
        needsRegistration = true;
        return false;
    }

    // Reconnect approved (Code 1605): extract AES key
    auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(reconnectResponse->payload);
    if (!aesOpt.has_value()) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    decryptedAesKey = crypto.decryptAesKey(aesOpt->encryptedAesKey);
    std::cout << "[+] Reconnected successfully (Code 1605)." << std::endl;
    return true;
}

// Coordinates authentication flow
bool TransferClient::authenticate(const std::string& clientName) {
    bool needsRegistration = !config.hasClientInfo();

    if (!needsRegistration) {
        if (tryReconnect(needsRegistration))
            return true;
    }

    return needsRegistration && registerAndExchangeKeys(clientName);
}

// Handles file upload and CRC verification attempts
bool TransferClient::transferAndVerify(const EncryptedFileData& fileData) {
        for (int attempt = 1; attempt <= Protocol::MAX_CRC_ATTEMPTS; ++attempt) {
            std::cout << "\n[*] Transmission Attempt " << attempt << " / " << Protocol::MAX_CRC_ATTEMPTS << std::endl;

            // Send encrypted file (Code 828)
            auto filePacket = Protocol::PacketBuilder::buildSendFile(
                clientId,
                fileData.origFileSize,
                1,
                1,
                fileData.fileName,
                fileData.encryptedContent
            );

            if (!client.send(filePacket)) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
                return false;
            }

            // Receive CRC response from server (Code 1603)
            auto crcResponse = receiveResponse({ Protocol::ResponseCode::FileReceivedWithCrc });
            if (!crcResponse.has_value()) {
                return false;
            }

            auto crcResponseOpt = Protocol::PacketParser::parseFileCrcPayload(crcResponse->payload);
            if (!crcResponseOpt.has_value()) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
                return false;
            }

            // The server must report the same encrypted size that was sent
            if (crcResponseOpt->contentSize != fileData.encryptedContent.size()) {
                std::cerr << SERVER_ERROR_MSG << " (content size mismatch: sent "
                    << fileData.encryptedContent.size() << ", server reported "
                    << crcResponseOpt->contentSize << ")" << std::endl;
                return false;
            }

            // Check if CRC matches
            if (crcResponseOpt->cksum == fileData.crc) {
                std::cout << "[+] CRC verified successfully! Sending CRC confirmation (Code 900)..." << std::endl;

                // Send CRC confirmation (Code 900)
                auto confirmPacket = Protocol::PacketBuilder::buildCrcStatus(
                    clientId,
                    Protocol::RequestCode::CrcValid,
                    fileData.fileName
                );
                if (!client.send(confirmPacket)) {
                    std::cerr << SERVER_ERROR_MSG << std::endl;
                    return false;
                }

                // Receive final acknowledgment (Code 1604)
                if (!receiveResponse({ Protocol::ResponseCode::MessageConfirmed }).has_value()) {
                    return false;
                }

                std::cout << "[SUCCESS] File transfer and verification completed successfully!" << std::endl;
                return true;
            }

            // CRC mismatch
            std::cerr << "[!] Warning: CRC mismatch on attempt " << attempt
                << " (Local: " << fileData.crc << " != Server: " << crcResponseOpt->cksum << ")" << std::endl;

            if (attempt < Protocol::MAX_CRC_ATTEMPTS) {
                // Request retry (Code 901)
                std::cout << "[*] Sending CRC retry request (Code 901)..." << std::endl;
                auto retryPacket = Protocol::PacketBuilder::buildCrcStatus(
                    clientId,
                    Protocol::RequestCode::CrcInvalidRetry,
                    fileData.fileName
                );
                if (!client.send(retryPacket)) {
                    std::cerr << SERVER_ERROR_MSG << std::endl;
                    return false;
                }
            }
            else {
                // Final abort after 4 attempts (Code 902)
                std::cerr << "[-] Max CRC retry limit reached. Sending abort notification (Code 902)..." << std::endl;
                auto failPacket = Protocol::PacketBuilder::buildCrcStatus(
                    clientId,
                    Protocol::RequestCode::CrcInvalidAbort,
                    fileData.fileName
                );
                if (!client.send(failPacket)) {
                    std::cerr << SERVER_ERROR_MSG << std::endl;
                    return false;
                }

                // Receive acknowledgment of the abort (Code 1604)
                if (!receiveResponse({ Protocol::ResponseCode::MessageConfirmed }).has_value()) {
                    return false;
                }

                std::cerr << SERVER_ERROR_MSG << std::endl;
                return false;
            }
        }

        return false;
    }

bool TransferClient::sendSingleFile(const std::string& filePath) {
    if (!std::filesystem::exists(filePath)) {
        std::cerr << "[-] File does not exist on disk: " << filePath << std::endl;
        return false;
    }

    auto fileDataOpt = EncryptedFile::createEncryptedFile(filePath, decryptedAesKey);
    if (!fileDataOpt.has_value()) {
        std::cerr << "[-] Error preparing encrypted file: " << filePath << std::endl;
        return false;
    }

    const auto& fileData = *fileDataOpt;
    std::cout << "[*] File prepared: '" << fileData.fileName << "'" << std::endl;
    std::cout << "    Original Size: " << fileData.origFileSize << " bytes" << std::endl;
    std::cout << "    Encrypted Size: " << fileData.encryptedContent.size() << " bytes" << std::endl;
    std::cout << "    Local POSIX Checksum: " << fileData.crc << std::endl;

    return transferAndVerify(fileData);
}

// Executes the client workflow
bool TransferClient::run() {
    if (!config.loadTransferInfo())
        return false;

    const auto& serverConfig = config.getTransferInfo();
    const std::string ip = serverConfig.getIP();
    const auto port = serverConfig.getPort();
    const std::string clientName = serverConfig.getClientName();
    const auto& filesToSend = serverConfig.getFiles();

    // Connect to server
    if (!client.connect(ip, port)) {
        std::cerr << "[-] Unable to connect to " << ip << ":" << port << std::endl;
        return false;
    }

    // Authenticate session
    if (!authenticate(clientName)) {
        return false;
    }

    // Validate AES key size
    if (decryptedAesKey.size() != 32) {
        std::cerr << "[-] Decrypted AES key size is invalid." << std::endl;
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    bool allSuccess = true;
    for (const auto& filePath : filesToSend) {
        if (!sendSingleFile(filePath)) {
            allSuccess = false;
            break;
        }
    }

    client.disconnect();
    return allSuccess;
}