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
class ServerConfig {
private:
    std::string ip;
    uint16_t port{ 0 };
    std::string clientName;

public:
    ServerConfig() = default;
    ServerConfig(std::string ip, uint16_t port, std::string clientName);

    [[nodiscard]] const std::string& getIp() const { return ip; }
    [[nodiscard]] uint16_t getPort() const { return port; }
    [[nodiscard]] const std::string& getClientName() const { return clientName; }

    void setIp(const std::string& ip) { this->ip = ip; }
    void setPort(uint16_t port) { this->port = port; }
    void setClientName(const std::string& clientName) { this->clientName = clientName; }
};

class ConfigManager
{
public: 
    ConfigManager() = default;
    ~ConfigManager() = default;

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    bool loadTransferInfo(const std::filesystem::path& configPath = "transfer.json");
    const ServerConfig& getServerConfig() const { return this->serverConfig; }
private:
    ServerConfig serverConfig;
};


#endif