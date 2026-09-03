#include "ConfigManager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ==========================================
// ServerConfig Implementation
// ==========================================
ServerConfig::ServerConfig(std::string ip, uint16_t port, std::string clientName)
    : ip(std::move(ip)),
    port(port),
    clientName(std::move(clientName)) {}

// ==========================================
// ConfigManager Implementation
// ==========================================

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

        // Validate existence and primitive types of mandatory fields
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

        this->serverConfig.setIP(ip);
        this->serverConfig.setPort(static_cast<uint16_t>(rawPort));
        this->serverConfig.setClientName(clientName);

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