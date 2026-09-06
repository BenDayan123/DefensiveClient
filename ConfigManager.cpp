#include "ConfigManager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ==========================================
// HexConverter Implementation
// ==========================================
std::string HexConverter::toHex(const std::array<uint8_t, 16>& bytes){
    std::ostringstream oss;
    for (uint8_t b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

std::optional<std::array<uint8_t, 16>> HexConverter::toBytes(const std::string& hexStr) {
    if (hexStr.length() != 32) {
        return std::nullopt;
    }

    std::array<uint8_t, 16> bytes{};
    for (size_t i = 0; i < 16; ++i) {
        std::string bytesChunk = hexStr.substr(i * 2, 2);
        char* endPtr = nullptr;
        long val = std::strtol(bytesChunk.c_str(), &endPtr, 16);
        if (endPtr != bytesChunk.c_str() + 2 || val < 0 || val > 0xFF) {
            return std::nullopt;
        }
        bytes[i] = static_cast<uint8_t>(val);
    }
    return bytes;
}


// ==========================================
// TransferInfo Implementation
// ==========================================
TransferInfo::TransferInfo(std::string ip, uint16_t port, std::string clientName)
    : ip(std::move(ip)),
    port(port),
    clientName(std::move(clientName)) {}


// ==========================================
// ClientInfo Implementation
// ==========================================
std::string ClientInfo::getUuidHex() const {
    return HexConverter::toHex(this->uuid);
}

// ==========================================
// ConfigManager Implementation
// ==========================================

ConfigManager::ConfigManager(std::filesystem::path meInfoPath, std::filesystem::path privKeyPath)
    : meInfoPath(std::move(meInfoPath)), 
    privKeyPath(std::move(privKeyPath)) {}

/**
 * @brief Parses transfer.json configuration file using nlohmann/json.
 * Validates JSON schema, key types, port boundaries, and string lengths.
 *
 * @param configPath path to the configuration file (default: "transfer.json").
 * @return true if configuration is fully valid and loaded, false otherwise.
 */
bool ConfigManager::loadTransferInfo(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        std::cerr << "[-] [ConfigManager] Error: File not found: " << path << std::endl;
        return false;
    }
    try {
        std::ifstream configFile(path);
        if (!configFile.is_open()) {
            std::cerr << "[-] [ConfigManager] Error: Unable to open file: " << path << std::endl;
            return false;
        }

        // Parse stream into JSON
        json configData = json::parse(configFile);

        // Defensive check: root must be an object containing the "server" object
        if (!configData.is_object() || !configData.contains("server") || !configData["server"].is_object()) {
            std::cerr << "[-] [ConfigManager] Error: Missing or invalid 'server' object in JSON." << std::endl;
            return false;
        }

        const auto& serverSection = configData["server"];

        // Validate existence and primitive types of the fields
        if (!serverSection.contains("ip") || !serverSection["ip"].is_string() ||
            !serverSection.contains("port") || !serverSection["port"].is_number_integer() ||
            !serverSection.contains("client") || !serverSection["client"].is_string()) {
            std::cerr << "[-] [ConfigManager] Error: Schema mismatch inside 'server' object." << std::endl;
            return false;
        }

        const std::string ip = serverSection["ip"].get<std::string>();
        const int rawPort = serverSection["port"].get<int>();
        const std::string clientName = serverSection["client"].get<std::string>();

        // Port boundary validation (1 to 65535)
        if (rawPort <= 0 || rawPort > 65535) {
            std::cerr << "[-] [ConfigManager] Error: Port value out of range (1-65535): " << rawPort << std::endl;
            return false;
        }

        // Client name string is up to 100 characters
        if (clientName.empty() || clientName.length() > 100) {
            std::cerr << "[-] [ConfigManager] Error: Client name must be between 1 and 100 characters." << std::endl;
            return false;
        }

        this->transferInfo.setIP(ip);
        this->transferInfo.setPort(static_cast<uint16_t>(rawPort));
        this->transferInfo.setClientName(clientName);

        return true;
    }
    catch (const json::parse_error& e) {
        std::cerr << "[-] [ConfigManager] Parse Error: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] [ConfigManager] Unexpected Exception: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cerr << "[-] [ConfigManager] Unknown fatal error occurred." << std::endl;
        return false;
    }
}

bool ConfigManager::hasClientInfo() {
    return std::filesystem::exists(meInfoPath);
}

bool ConfigManager::loadClientInfo() {
    if (!hasClientInfo()) {
        return false;
    }
    try {
        std::ifstream infoFile(meInfoPath);
        if (!infoFile.is_open()) {
            return false;
        }

        std::string name, uuid, privateKey;
        if (!std::getline(infoFile, name) || 
            !std::getline(infoFile, uuid) || 
            !std::getline(infoFile, privateKey)) {
            return false;
        }

        auto uuidBytes = HexConverter::toBytes(uuid);
        if (!uuidBytes.has_value()) {
            return false;
        }

        clientInfo.name = std::move(name);
        clientInfo.uuid = *uuidBytes;
        clientInfo.privateKeyBase64 = std::move(privateKey);
        return true;

    } catch (...) {
        return false;
    }
}

bool ConfigManager::saveClientInfo(const std::string& name,
                                const std::array<uint8_t, 16>& uuid,
                                const std::string& privateKeyBase64) {
    try {
        std::ofstream meFile(meInfoPath, std::ios::trunc);
        if (!meFile.is_open()) {
            std::cerr << "[-] Failed to open " << meInfoPath << " for writing." << std::endl;
            return false;
        }

        meFile << name << "\n";
        meFile << HexConverter::toHex(uuid) << "\n";
        meFile << privateKeyBase64 << "\n";
        meFile.close();

        std::ofstream keyFile(privKeyPath, std::ios::trunc | std::ios::binary);
        if (!keyFile.is_open()) {
            std::cerr << "[-] Failed to open " << privKeyPath << " for writing." << std::endl;
            return false;
        }

        keyFile << privateKeyBase64;
        keyFile.close();

        return true;
    }
    catch (...) {
        return false;
    }
}