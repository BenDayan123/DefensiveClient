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

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "CryptoHelper.h"
#include "EncryptedFile.h"
#include "Protocol.h"
#include "TransferClient.h"

static const std::string SERVER_ERROR_MSG = "server responded with an error";

TransferClient::TransferClient(std::string targetFilePath)
    : targetFilePath(std::move(targetFilePath)) {}

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
    auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
    auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

    if (!responseHeader.has_value() ||
        responseHeader->code != Protocol::ResponseCode::RegistrationSuccess) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    auto payloadBytes = client.receiveExact(responseHeader->payloadSize);
    auto assignedUuidOpt = Protocol::PacketParser::parseClientIdPayload(payloadBytes);
    if (!assignedUuidOpt.has_value()) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }
    clientId = *assignedUuidOpt;

    std::cout << "[+] Registered successfully (Code 1600)." << std::endl;

    // Generate RSA-1024 key pair and persist credentials
    crypto.generateRsaKeys();
    config.saveClientInfo(clientName, clientId, crypto.getPrivateKeyBase64());

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
    headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
    responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

    if (!responseHeader.has_value() ||
        responseHeader->code != Protocol::ResponseCode::AesKeyReceived) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    auto aesPayload = client.receiveExact(responseHeader->payloadSize);
    auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(aesPayload);
    if (!aesOpt.has_value()) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    decryptedAesKey = crypto.decryptAesKey(aesOpt->encryptedAesKey);
    std::cout << "[+] Received and decrypted symmetric AES key (Code 1602)." << std::endl;
    return true;
}

// Handles reconnection attempt (Code 827)
bool TransferClient::tryReconnect(const std::string& clientName, bool& needsRegistration) {
    if (!config.loadClientInfo() ||
        !crypto.loadPrivateKeyBase64(config.getClientInfo().privateKeyBase64)) {
        std::cerr << "[!] Stored credentials are invalid. Falling back to new registration." << std::endl;
        config.removeClientInfo();
        needsRegistration = true;
        return false;
    }

    clientId = config.getClientInfo().uuid;
    std::cout << "[*] Existing credentials found. Sending reconnect request (Code 827)..." << std::endl;

    // Send Reconnect request (Code 827)
    auto reconnectPacket = Protocol::PacketBuilder::buildReconnect(clientId, clientName);
    if (!client.send(reconnectPacket)) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    // Receive response header
    auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
    auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

    if (!responseHeader.has_value() ||
        (responseHeader->code != Protocol::ResponseCode::ReconnectApproved &&
            responseHeader->code != Protocol::ResponseCode::ReconnectRejected)) {
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return false;
    }

    // Handle server rejection (Code 1606)
    if (responseHeader->code == Protocol::ResponseCode::ReconnectRejected) {
        std::cout << "[!] Server rejected reconnect (Code 1606). Registering as a new client..." << std::endl;
        client.receiveExact(responseHeader->payloadSize);
        config.removeClientInfo();
        needsRegistration = true;
        return false;
    }

    // Reconnect approved (Code 1605): extract AES key
    auto payloadBytes = client.receiveExact(responseHeader->payloadSize);
    auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(payloadBytes);
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
        if (tryReconnect(clientName, needsRegistration))
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
            auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

            if (!responseHeader.has_value() ||
                responseHeader->code != Protocol::ResponseCode::FileReceivedWithCrc) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
                return false;
            }

            auto crcPayload = client.receiveExact(responseHeader->payloadSize);
            auto crcResponseOpt = Protocol::PacketParser::parseFileCrcPayload(crcPayload);
            if (!crcResponseOpt.has_value()) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
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
                client.send(confirmPacket);

                // Receive final acknowledgment (Code 1604)
                headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
                responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
                if (responseHeader.has_value()) {
                    client.receiveExact(responseHeader->payloadSize);
                }

                std::cout << "\n=======================================================" << std::endl;
                std::cout << "[SUCCESS] File transfer and verification completed successfully!" << std::endl;
                std::cout << "=======================================================\n" << std::endl;
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
                client.send(retryPacket);
            }
            else {
                // Final abort after 4 attempts (Code 902)
                std::cerr << "[-] Max CRC retry limit reached. Sending abort notification (Code 902)..." << std::endl;
                auto failPacket = Protocol::PacketBuilder::buildCrcStatus(
                    clientId,
                    Protocol::RequestCode::CrcInvalidAbort,
                    fileData.fileName
                );
                client.send(failPacket);

                headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
                responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
                if (responseHeader.has_value()) {
                    client.receiveExact(responseHeader->payloadSize);
                }

                std::cerr << SERVER_ERROR_MSG << std::endl;
                return false;
            }
        }

        return false;
    }

// Executes the client workflow
bool TransferClient::run() {
    if (!config.loadTransferInfo())
        return false;

    const auto& serverConfig = config.getTransferInfo();
    const std::string ip = serverConfig.getIP();
    const auto port = serverConfig.getPort();
    const std::string clientName = serverConfig.getClientName();

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

    // Prepare test file
    if (!std::filesystem::exists(targetFilePath)) {
        std::ofstream dummyFile(targetFilePath, std::ios::binary);
        dummyFile << "Encrypted file transfer test content with POSIX checksum validation.";
        dummyFile.close();
    }

    // Encrypt target file
    auto fileDataOpt = EncryptedFile::createEncryptedFile(targetFilePath, decryptedAesKey);
    if (!fileDataOpt.has_value()) {
        std::cerr << "[-] Error preparing encrypted file." << std::endl;
        return false;
    }
    const auto& fileData = *fileDataOpt;

    std::cout << "[*] File prepared: '" << fileData.fileName << "'" << std::endl;
    std::cout << "    Original Size: " << fileData.origFileSize << " bytes" << std::endl;
    std::cout << "    Encrypted Size: " << fileData.encryptedContent.size() << " bytes" << std::endl;
    std::cout << "    Local POSIX Checksum: " << fileData.crc << std::endl;

    // Transmit and verify
    bool success = transferAndVerify(fileData);
    client.disconnect();
    return success;
}