#include "ConfigManager.h"

// ==========================================
// ServerConfig Implementation
// ==========================================
ServerConfig::ServerConfig(std::string ip, uint16_t port, std::string clientName, std::filesystem::path targetFilePath)
    : ip(std::move(ip)),
    port(port),
    clientName(std::move(clientName)),
    targetFilePath(std::move(targetFilePath)) {}