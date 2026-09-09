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

    // ---------------------------------------------------------------------
    // Send Registration Request (Code 825)
    // ---------------------------------------------------------------------
    std::vector<uint8_t> packet = Protocol::PacketBuilder::buildRegistration(clientName);

    if (!client.send(packet)) {
        std::cerr << "[-] Error: Failed to transmit registration packet." << std::endl;
        return 1;
    }
    auto headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
    if (headerBytes.empty()) {
        std::cerr << "[-] Failed to receive response header from server." << std::endl;
        return 1;
    }
    auto responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
    if (!responseHeader.has_value()) {
        std::cerr << "[-] Corrupted response header received." << std::endl;
        return 1;
    }

    std::cout << "[+] Received response code: " << static_cast<uint16_t>(responseHeader->code)
        << " | Payload size: " << responseHeader->payloadSize << " bytes" << std::endl;

    if (responseHeader->code == Protocol::ResponseCode::RegistrationFailed) {
        std::cerr << "[-] Server responded with 1601: Registration rejected (Name already registered)." << std::endl;
        return 1;
    }

    if (responseHeader->code != Protocol::ResponseCode::RegistrationSuccess) {
        std::cerr << "[-] Unexpected response code received: "
            << static_cast<uint16_t>(responseHeader->code) << std::endl;
        return 1;
    }
    std::vector<uint8_t> payloadBytes = client.receiveExact(responseHeader->payloadSize);
    if (payloadBytes.size() != Protocol::UUID_SIZE) {
        std::cerr << "[-] Expected 16-byte UUID payload, received " << payloadBytes.size() << " bytes." << std::endl;
        return 1;
    }

    auto assignedUuidOpt = Protocol::PacketParser::parseClientIdPayload(payloadBytes);
    if (!assignedUuidOpt.has_value()) {
        std::cerr << "[-] Failed to parse UUID from payload." << std::endl;
        return 1;
    }

    std::array<uint8_t, Protocol::UUID_SIZE> clientId = *assignedUuidOpt;
    std::cout << "[+] Success (Code 1600), Assigned UUID: ";
    for (uint8_t b : clientId) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;

    // ---------------------------------------------------------------------
    // Generate RSA keys and persist credentials to me.info & priv.key
    // ---------------------------------------------------------------------
    CryptoHelper crypto;
    crypto.generateRsaKeys();
    std::vector<uint8_t> publicKeyDER = crypto.getPublicKeyDER();
    std::string privateKeyBase64 = crypto.getPrivateKeyBase64();

    std::cout << "[+] Public Key generated (" << publicKeyDER.size() << " bytes)." << std::endl;

    // Save identity files via ConfigManager
    if (config.saveClientInfo(clientName, clientId, privateKeyBase64))
        std::cout << "[+] Credentials successfully saved to me.info and priv.key." << std::endl;
    else std::cerr << "[!] Warning: Failed to persist credentials to disk." << std::endl;
    
    // ---------------------------------------------------------------------
    // Send Public Key Exchange Request (Code 826)
    // ---------------------------------------------------------------------
    std::vector<uint8_t> pubKeyPacket = Protocol::PacketBuilder::buildPublicKeyExchange(
        clientId,
        clientName,
        publicKeyDER
    );

    if (!client.send(pubKeyPacket)) {
        std::cerr << "[-] Fatal: Failed to transmit public key packet." << std::endl;
        return 1;
    }

    // ---------------------------------------------------------------------
    // Receive AES Key from Server (Code 1602)
    // ---------------------------------------------------------------------
    headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
    responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
        
    if (!responseHeader.has_value() || responseHeader->code != Protocol::ResponseCode::AesKeyReceived) {
        std::cerr << "[-] Error: Expected Code 1602, got: "
            << (responseHeader ? static_cast<uint16_t>(responseHeader->code) : 0) << std::endl;
        return 1;
    }

    // Read payload: 16B Client ID + 128B Encrypted AES Key
    std::vector<uint8_t> aesPayload = client.receiveExact(responseHeader->payloadSize);
    auto aesResponseOpt = Protocol::PacketParser::parseAesKeyPayload(aesPayload);
    if (!aesResponseOpt.has_value()) {
        std::cerr << "[-] Fatal: Failed to unpack encrypted AES payload." << std::endl;
        return 1;
    }
    std::cout << "[+] Received Encrypted AES Key Response (Code 1602)!, length: " << aesResponseOpt->encryptedAesKey.size() << " bytes." << std::endl;

    // ---------------------------------------------------------------------
    // Decrypt the symmetric AES-256 key using local RSA Private Key
    // ---------------------------------------------------------------------
    std::vector<uint8_t> decryptedAesKey = crypto.decryptAesKey(aesResponseOpt->encryptedAesKey);
    if (decryptedAesKey.size() != 32) {
        std::cerr << "[-] Fatal: AES key decryption failed (invalid size: "
            << decryptedAesKey.size() << ")." << std::endl;
        return 1;
    }

    std::cout << "\n=======================================================\nAES Key (Hex): ";
    for (uint8_t b : decryptedAesKey)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);

    // ---------------------------------------------------------------------
       // 8. Prepare, Checksum, and Encrypt File via createEncryptedFile
       // ---------------------------------------------------------------------
    const std::string targetFilePath = "test.txt";

    // Ensure the test file exists locally
    if (!std::filesystem::exists(targetFilePath)) {
        std::ofstream dummyFile(targetFilePath, std::ios::binary);
        dummyFile << "Encrypted file transfer test content with POSIX checksum validation.";
        dummyFile.close();
    }

    // Reads file, calculates POSIX CRC via memcrc, and encrypts with AES-256-CBC
    auto fileDataOpt = EncryptedFile::createEncryptedFile(targetFilePath, decryptedAesKey);
    if (!fileDataOpt.has_value()) {
        std::cerr << "[-] Fatal: Failed to read, hash, or encrypt target file." << std::endl;
        return 1;
    }

    const EncryptedFileData& fileData = *fileDataOpt;

    std::cout << "[*] Target file prepared: '" << fileData.fileName << "'" << std::endl;
    std::cout << "    Original Size: " << fileData.origFileSize << " bytes" << std::endl;
    std::cout << "    Encrypted Size: " << fileData.encryptedContent.size() << " bytes" << std::endl;
    std::cout << "    Local POSIX Checksum: " << fileData.crc << std::endl;

    // ---------------------------------------------------------------------
    // 9. Send File (Code 828) & Verify Checksum Loop (Codes 900/901/902)
    // ---------------------------------------------------------------------
    bool transferCompleted = false;

    for (int attempt = 1; attempt <= Protocol::MAX_CRC_ATTEMPTS; ++attempt) {
        std::cout << "\n[*] ---> Transmission Attempt " << attempt << " / " << Protocol::MAX_CRC_ATTEMPTS << std::endl;

        // Build and transmit Request 828
        std::vector<uint8_t> filePacket = Protocol::PacketBuilder::buildSendFile(
            clientId,
            fileData.origFileSize,
            1,  // Packet number
            1,  // Total packets
            fileData.fileName,
            fileData.encryptedContent
        );

        if (!client.send(filePacket)) {
            std::cerr << "[-] Transmission failed for Request 828." << std::endl;
            break;
        }

        // Receive Response 1603 (File Received with Checksum)
        headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
        responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

        if (!responseHeader.has_value() || responseHeader->code != Protocol::ResponseCode::FileReceivedWithCrc) {
            std::cerr << "[-] Expected Response 1603, got code: "
                << (responseHeader ? static_cast<uint16_t>(responseHeader->code) : 0) << std::endl;
            break;
        }

        std::vector<uint8_t> crcPayload = client.receiveExact(responseHeader->payloadSize);
        auto crcResponseOpt = Protocol::PacketParser::parseFileCrcPayload(crcPayload);
        if (!crcResponseOpt.has_value()) {
            std::cerr << "[-] Failed to parse Response 1603 payload." << std::endl;
            break;
        }

        const uint32_t serverCrc = crcResponseOpt->cksum;
        std::cout << "[+] <--- Received Response 1603. Server calculated CRC: " << serverCrc << std::endl;

        // Compare server checksum with the local CRC from fileData
        if (serverCrc == fileData.crc) {
            std::cout << "[+] CRC verified successfully! Sending CRC confirmation (Code 900)..." << std::endl;

            // Send Request 900 (CRC Match confirmed)
            std::vector<uint8_t> confirmPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcValid,
                fileData.fileName
            );
            client.send(confirmPacket);

            // Receive Response 1604 (Message Confirmed)
            headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            responseHeader = Protocol::PacketParser::parseHeader(headerBytes);

            if (responseHeader.has_value() && responseHeader->code == Protocol::ResponseCode::MessageConfirmed) {
                client.receiveExact(responseHeader->payloadSize);
                std::cout << "\n=======================================================" << std::endl;
                std::cout << "[SUCCESS] File transfer and verification successfully completed!" << std::endl;
                std::cout << "=======================================================\n" << std::endl;
                transferCompleted = true;
            }
            else {
                std::cerr << "[-] Failed to receive confirmation 1604 from server." << std::endl;
            }
            break;
        }

        // Checksum mismatch
        std::cerr << "[!] Warning: CRC mismatch on attempt " << attempt
            << " (Local: " << fileData.crc << " != Server: " << serverCrc << ")" << std::endl;

        if (attempt < Protocol::MAX_CRC_ATTEMPTS) {
            std::cout << "[*] Sending CRC retry request (Code 901)..." << std::endl;
            std::vector<uint8_t> retryPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcInvalidRetry,
                fileData.fileName
            );
            client.send(retryPacket);
        }
        else {
            std::cerr << "[-] Max retry limit reached. Sending abort notification (Code 902)..." << std::endl;
            std::vector<uint8_t> failPacket = Protocol::PacketBuilder::buildCrcStatus(
                clientId,
                Protocol::RequestCode::CrcInvalidAbort,
                fileData.fileName
            );
            client.send(failPacket);

            // Receive final Response 1604
            headerBytes = client.receiveExact(Protocol::RESPONSE_HEADER_SIZE);
            responseHeader = Protocol::PacketParser::parseHeader(headerBytes);
            if (responseHeader.has_value()) {
                client.receiveExact(responseHeader->payloadSize);
            }
        }
    }

    client.disconnect();

    return 0;
}