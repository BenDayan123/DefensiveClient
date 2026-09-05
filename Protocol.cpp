#include "Protocol.h"
#include <cstring>
#include <algorithm>

namespace Protocol {

    // ==========================================
    // Internal Endian Utility Functions
    // ==========================================
    static void appendUint16LE(std::vector<uint8_t>& buffer, uint16_t value) {
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    }

    static void appendUint32LE(std::vector<uint8_t>& buffer, uint32_t value) {
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    }

    static uint16_t readUint16LE(const uint8_t* ptr) {
        return static_cast<uint16_t>(ptr[0]) |
            (static_cast<uint16_t>(ptr[1]) << 8);
    }

    static uint32_t readUint32LE(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
            (static_cast<uint32_t>(ptr[1]) << 8) |
            (static_cast<uint32_t>(ptr[2]) << 16) |
            (static_cast<uint32_t>(ptr[3]) << 24);
    }

    /**
     * @brief Appends an ASCII string into a fixed-size buffer padded with null-bytes.
     */
    static void appendFixedString(std::vector<uint8_t>& buffer, const std::string& str, size_t fieldSize) {
        size_t bytesToCopy = (std::min)(str.length(), fieldSize - 1);
        size_t currentSize = buffer.size();
        buffer.resize(currentSize + fieldSize, 0);
        std::memcpy(buffer.data() + currentSize, str.data(), bytesToCopy);
    }

    /**
    * @brief Serializes the 23-byte Request Header:
    * Client ID (16B) | Version (1B) | Code (2B, LE) | Payload Size (4B, LE)
     */
    static void appendRequestHeader(std::vector<uint8_t>& buffer, const RequestHeader& header) {
        buffer.reserve(buffer.size() + REQUEST_HEADER_SIZE + header.payloadSize);
        buffer.insert(buffer.end(), header.clientId.begin(), header.clientId.end());
        buffer.push_back(CLIENT_VERSION);
        appendUint16LE(buffer, static_cast<uint16_t>(header.code));
        appendUint32LE(buffer, header.payloadSize);
    }

    // ==========================================
    // PacketBuilder Implementation
    // ==========================================
    std::vector<uint8_t> PacketBuilder::buildRegistration(const std::string& name) {
        RequestHeader header{};
        header.code = RequestCode::Registration;
        header.payloadSize = static_cast<uint32_t>(NAME_FIELD_SIZE);
        
        std::vector<uint8_t> packet;
        appendRequestHeader(packet, header);
        appendFixedString(packet, name, NAME_FIELD_SIZE);

        return packet;
    }

    // ==========================================
    // PacketParser Implementation
    // ==========================================
    std::optional<ResponseHeader> PacketParser::parseHeader(const std::vector<uint8_t>& headerBuffer) {
        if (headerBuffer.size() < RESPONSE_HEADER_SIZE) {
            return std::nullopt;
        }

        ResponseHeader header;
        header.version = headerBuffer[0];
        header.code = static_cast<ResponseCode>(readUint16LE(&headerBuffer[1]));
        header.payloadSize = readUint32LE(&headerBuffer[3]);

        return header;
    }

    std::optional<std::array<uint8_t, UUID_SIZE>> PacketParser::parseClientIdPayload(const std::vector<uint8_t>& payload) {
        if (payload.size() < UUID_SIZE) {
            return std::nullopt;
        }

        std::array<uint8_t, UUID_SIZE> id{};
        std::memcpy(id.data(), payload.data(), UUID_SIZE);
        return id;
    }
}