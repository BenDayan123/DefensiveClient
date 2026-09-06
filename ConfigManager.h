#ifndef CONFIFMANAGER_H
#define CONFIFMANAGER_H

#include <string>
#include <vector>
#include <array>
#include <optional>
#include <filesystem>
#include <cstdint>
#include "Protocol.h"

/**
 * @brief Utility class for hexadecimal encoding and decoding.
 */
class HexConverter {
public:
    static std::string toHex(const std::array<uint8_t, Protocol::UUID_SIZE>& bytes);
    static std::optional<std::array<uint8_t, Protocol::UUID_SIZE>> toBytes(const std::string& hexStr);
};


/**
 * @brief Domain model representing server connection details.
 */
class TransferInfo {
private:
    std::string ip;
    uint16_t port{ 0 };
    std::string clientName;

public:
    TransferInfo() = default;
    TransferInfo(std::string ip, uint16_t port, std::string clientName);

    [[nodiscard]] const std::string& getIP() const { return ip; }
    [[nodiscard]] uint16_t getPort() const { return port; }
    [[nodiscard]] const std::string& getClientName() const { return clientName; }

    void setIP(const std::string& ip) { this->ip = ip; }
    void setPort(uint16_t port) { this->port = port; }
    void setClientName(const std::string& clientName) { this->clientName = clientName; }
};

/**
 * @brief Object representing local client identity and credentials.
 */
struct ClientInfo {
    std::string name;
    std::array<uint8_t, 16> uuid{};
    std::string privateKeyBase64;

    std::string getUuidHex() const;
};

/**
 * @brief Service responsible for loading, validating, and persisting configuration files.
 */
class ConfigManager
{
private:
    TransferInfo transferInfo;
    ClientInfo clientInfo;

    const std::filesystem::path meInfoPath;
    const std::filesystem::path privKeyPath;

public: 
    ConfigManager(std::filesystem::path meInfoPath = "me.info",
        std::filesystem::path privKeyPath = "priv.key");
    ~ConfigManager() = default;

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    const ClientInfo& getClientInfo() const { return clientInfo; }
    const TransferInfo& getTransferInfo() const { return transferInfo; }

    bool loadTransferInfo(const std::filesystem::path& configPath = "transfer.json");

    bool loadClientInfo();
    bool saveClientInfo(const std::string& name,
                        const std::array<uint8_t, Protocol::UUID_SIZE>& uuid,
                        const std::string& privateKeyBase64);
    bool hasClientInfo();
};


#endif