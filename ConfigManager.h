#ifndef CONFIFMANAGER_H
#define CONFIFMANAGER_H

#include <string>
#include <vector>
#include <array>
#include <optional>
#include <filesystem>
#include <cstdint>

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
 * @brief Domain model representing local client identity and credentials.
 */
class ClientInfo {
private:
    std::string name;
    std::array<uint8_t, 16> uuid{};
    std::string privateKeyBase64;
public:
    ClientInfo() = default;
    ClientInfo(std::string name, const std::array<uint8_t, 16>& uuid, std::string privateKeyBase64);

    const std::string& getName() const { return name; }
    const std::array<uint8_t, 16>& getUUID() const { return uuid; }
    const std::string& getPrivateKeyBase64() const { return privateKeyBase64; }

    void setName(const std::string& name) { this->name = name; }
    void setUUID(const std::array<uint8_t, 16>& uuid) { this->uuid = uuid; }
    void setPrivateKeyBase64(const std::string& key) { privateKeyBase64 = key; }
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
public: 
    ConfigManager(std::filesystem::path meInfoPath = "me.info");
    ~ConfigManager() = default;

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    bool loadTransferInfo(const std::filesystem::path& configPath = "transfer.json");
    const TransferInfo& getTransferInfo() const { return this->transferInfo; }

    bool loadClientInfo();
    bool hasIdentity();

};


#endif