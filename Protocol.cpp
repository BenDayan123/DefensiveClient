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

    /**
     * @brief Serializes the 23-byte request header.
     */
    static void appendRequestHeader(std::vector<uint8_t>& buffer, const RequestHeader& header) {
        buffer.reserve(buffer.size() + REQUEST_HEADER_SIZE + header.payloadSize);
        buffer.insert(buffer.end(), header.clientId.begin(), header.clientId.end());
        buffer.push_back(header.version);
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

        return packet;
    }
}