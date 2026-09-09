#define _WIN32_WINNT 0x0A00

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include <string>
#include <iostream>

// Specific modular Boost.Asio headers (avoids broken monolithic macro templates)
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include "ConfigManager.h"
#include "NetworkClient.h"
#include "CryptoHelper.h"
#include "EncryptedFile.h"
#include "Protocol.h"

using boost::asio::ip::tcp;

static const std::string SERVER_ERROR_MSG = "server responded with an error";

int main() {
    // Initialize and load configuration from transfer.json
    ConfigManager config;
    NetworkClient client;

    if (!config.loadTransferInfo())
        return 1;

    const auto& serverConfig = config.getTransferInfo();
    const std::string ip = serverConfig.getIP();
    const auto port = serverConfig.getPort();
    const std::string clientName = serverConfig.getClientName();

    // ---------------------------------------------------------------------
    // Connect to the server
    // ---------------------------------------------------------------------
    if (!client.connect(ip, port)) {
        std::cerr << "[-] Unable to connect to " << ip << ":" << port << std::endl;
        return 1;
    }

    CryptoHelper crypto;
    std::array<uint8_t, Protocol::UUID_SIZE> clientId{};
    std::vector<uint8_t> decryptedAesKey;

    // Determine whether this client needs to register or reconnect
    bool needsRegistration = !config.hasClientInfo();

    // ---------------------------------------------------------------------
    // Reconnection Flow (Code 827)
    // Used if me.info already exists on disk
    // ---------------------------------------------------------------------
    if (!needsRegistration) {
        // Load saved identity and private key
        if (!config.loadClientInfo() ||
            !crypto.loadPrivateKeyBase64(config.getClientInfo().privateKeyBase64)) {
            std::cerr << "[!] Stored credentials are invalid. Falling back to new registration." << std::endl;
            config.removeClientInfo();
            needsRegistration = true;
        }
        else {
            clientId = config.getClientInfo().uuid;
            std::cout << "[*] Existing credentials found. Sending reconnect request (Code 827)..." << std::endl;

            // Send Reconnect request (Code 827)
            auto reconnectPacket = Protocol::PacketBuilder::buildReconnect(clientId, clientName);
            if (!client.send(reconnectPacket)) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
                return 1;
            }

            // Receive response header
            auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

            if (!responseHeader.has_value() ||
                (responseHeader->code != Protocol::ResponseCode::ReconnectApproved &&
                    responseHeader->code != Protocol::ResponseCode::ReconnectRejected)) {
                std::cerr << SERVER_ERROR_MSG << std::endl;
                return 1;
            }

            // If reconnect is rejected (Code 1606), clear files and re-register
            if (responseHeader->code == Protocol::ResponseCode::ReconnectRejected) {
                std::cout << "[!] Server rejected reconnect (Code 1606). Registering as a new client..." << std::endl;
                client.receiveExact(responseHeader->payloadSize); // Flush payload
                config.removeClientInfo();
                needsRegistration = true;
            }
            else {
                // Reconnect accepted (Code 1605): parse encrypted AES key
                auto payloadBytes = client.receiveExact(responseHeader->payloadSize);
                auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(payloadBytes);
                if (!aesOpt.has_value()) {
                    std::cerr << SERVER_ERROR_MSG << std::endl;
                    return 1;
                }
                decryptedAesKey = crypto.decryptAesKey(aesOpt->encryptedAesKey);
                std::cout << "[+] Reconnected successfully (Code 1605)." << std::endl;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Registration & Key Exchange Flow (Codes 825 & 826)
    // Used for first-time clients or after reconnect failure
    // ---------------------------------------------------------------------
    if (needsRegistration) {
        std::cout << "[*] Sending registration request (Code 825)..." << std::endl;

        // Send Registration packet (Code 825)
        auto packet = Protocol::PacketBuilder::buildRegistration(clientName);
        if (!client.send(packet)) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Receive response header
        auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
        auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

        if (!responseHeader.has_value() ||
            responseHeader->code != Protocol::ResponseCode::RegistrationSuccess) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Read assigned 16-byte UUID from server (Code 1600)
        auto payloadBytes = client.receiveExact(responseHeader->payloadSize);
        auto assignedUuidOpt = Protocol::PacketParser::parseClientIdPayload(payloadBytes);
        if (!assignedUuidOpt.has_value()) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }
        clientId = *assignedUuidOpt;

        std::cout << "[+] Registered successfully (Code 1600)." << std::endl;

        // Generate RSA-1024 key pair
        crypto.generateRsaKeys();

        // Save client credentials to me.info and priv.key
        config.saveClientInfo(clientName, clientId, crypto.getPrivateKeyBase64());

        // Send RSA Public Key to server (Code 826)
        std::cout << "[*] Sending RSA public key (Code 826)..." << std::endl;
        auto pubKeyPacket = Protocol::PacketBuilder::buildPublicKeyExchange(
            clientId,
            clientName,
            crypto.getPublicKeyDER()
        );
        if (!client.send(pubKeyPacket)) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Receive encrypted AES key response (Code 1602)
        headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
        responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

        if (!responseHeader.has_value() ||
            responseHeader->code != Protocol::ResponseCode::AesKeyReceived) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        auto aesPayload = client.receiveExact(responseHeader->payloadSize);
        auto aesOpt = Protocol::PacketParser::parseAesKeyPayload(aesPayload);
        if (!aesOpt.has_value()) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Decrypt AES key with local RSA private key
        decryptedAesKey = crypto.decryptAesKey(aesOpt->encryptedAesKey);
        std::cout << "[+] Received and decrypted symmetric AES key (Code 1602)." << std::endl;
    }

    // Ensure AES key length is exactly 32 bytes (256 bits)
    if (decryptedAesKey.size() != 32) {
        std::cerr << "[-] Decrypted AES key size is invalid." << std::endl;
        std::cerr << SERVER_ERROR_MSG << std::endl;
        return 1;
    }

    // ---------------------------------------------------------------------
    // File Preparation & Encryption
    // ---------------------------------------------------------------------
    const std::string targetFilePath = "test.jfif";

    // Create a sample test file if it does not exist
    if (!std::filesystem::exists(targetFilePath)) {
        std::ofstream dummyFile(targetFilePath, std::ios::binary);
        dummyFile << "Encrypted file transfer test content with POSIX checksum validation.";
        dummyFile.close();
    }

    // Read target file, calculate POSIX CRC, and encrypt with AES-CBC
    auto fileDataOpt = EncryptedFile::createEncryptedFile(targetFilePath, decryptedAesKey);
    if (!fileDataOpt.has_value()) {
        std::cerr << "[-] Error preparing encrypted file." << std::endl;
        return 1;
    }
    const auto& fileData = *fileDataOpt;

    std::cout << "[*] File prepared: '" << fileData.fileName << "'" << std::endl;
    std::cout << "    Original Size: " << fileData.origFileSize << " bytes" << std::endl;
    std::cout << "    Encrypted Size: " << fileData.encryptedContent.size() << " bytes" << std::endl;
    std::cout << "    Local POSIX Checksum: " << fileData.crc << std::endl;

    // ---------------------------------------------------------------------
    // File Transmission & Checksum Verification Loop (Codes 828, 900, 901, 902)
    // ---------------------------------------------------------------------
    for (int attempt = 1; attempt <= Protocol::MAX_CRC_ATTEMPTS; ++attempt) {
        std::cout << "\n[*] Transmission Attempt " << attempt << " / " << Protocol::MAX_CRC_ATTEMPTS << std::endl;

        // Build and send File Packet (Code 828)
        auto filePacket = Protocol::PacketBuilder::buildSendFile(
            clientId,
            fileData.origFileSize,
            1, // Current packet number
            1, // Total packets
            fileData.fileName,
            fileData.encryptedContent
        );

        if (!client.send(filePacket)) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Receive server CRC response (Code 1603)
        auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
        auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

        if (!responseHeader.has_value() ||
            responseHeader->code != Protocol::ResponseCode::FileReceivedWithCrc) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        auto crcPayload = client.receiveExact(responseHeader->payloadSize);
        auto crcResponseOpt = Protocol::PacketParser::parseFileCrcPayload(crcPayload);
        if (!crcResponseOpt.has_value()) {
            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }

        // Check if server CRC matches client local CRC
        if (crcResponseOpt->cksum == fileData.crc) {
            std::cout << "[+] CRC verified successfully! Sending CRC confirmation (Code 900)..." << std::endl;

            // Send CRC valid message (Code 900)
            auto confirmPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcValid,
                fileData.fileName
            );
            client.send(confirmPacket);

            // Receive final confirmation (Code 1604)
            headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
            if (responseHeader.has_value()) {
                client.receiveExact(responseHeader->payloadSize);
            }

            std::cout << "\n=======================================================" << std::endl;
            std::cout << "[SUCCESS] File transfer and verification completed successfully!" << std::endl;
            std::cout << "=======================================================\n" << std::endl;
            break;
        }

        // CRC mismatch handling
        std::cerr << "[!] Warning: CRC mismatch on attempt " << attempt
            << " (Local: " << fileData.crc << " != Server: " << crcResponseOpt->cksum << ")" << std::endl;

        if (attempt < Protocol::MAX_CRC_ATTEMPTS) {
            // Send retry message (Code 901)
            std::cout << "[*] Sending CRC retry request (Code 901)..." << std::endl;
            auto retryPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcInvalidRetry,
                fileData.fileName
            );
            client.send(retryPacket);
        }
        else {
            // 4th failure: send abort message (Code 902)
            std::cerr << "[-] Max CRC retry limit reached. Sending abort notification (Code 902)..." << std::endl;
            auto failPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcInvalidAbort,
                fileData.fileName
            );
            client.send(failPacket);

            // Receive final acknowledgment (Code 1604)
            headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
            if (responseHeader.has_value()) {
                client.receiveExact(responseHeader->payloadSize);
            }

            std::cerr << SERVER_ERROR_MSG << std::endl;
            return 1;
        }
    }

    client.disconnect();
    return 0;
}