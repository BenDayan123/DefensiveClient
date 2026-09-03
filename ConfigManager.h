#pragma once

#include <string>
#include <vector>
#include <array>
#include <optional>
#include <filesystem>
#include <cstdint>

class ConfigManager
{
};

/**
 * @brief Domain model representing server connection details.
 */
class ServerConfig {
private:
    std::string ip;
    uint16_t port{ 0 };
    std::string clientName;
    std::filesystem::path targetFilePath;

public:
    ServerConfig() = default;
    ServerConfig(std::string ip, uint16_t port, std::string clientName, std::filesystem::path targetFilePath);

    [[nodiscard]] const std::string& getIp() const { return ip; }
    [[nodiscard]] uint16_t getPort() const { return port; }
    [[nodiscard]] const std::string& getClientName() const { return clientName; }
    [[nodiscard]] const std::filesystem::path& getTargetFilePath() const { return targetFilePath; }

    void setIp(const std::string& ip) { this->ip = ip; }
    void setPort(uint16_t port) { this->port = port; }
    void setClientName(const std::string& clientName) { this->clientName = clientName; }
    void setTargetFilePath(const std::filesystem::path& path) { targetFilePath = path; }
};