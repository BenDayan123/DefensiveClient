#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <optional>

namespace Protocol {
    // Protocol constants
    const uint8_t CLIENT_VERSION = 3;
    const size_t UUID_SIZE = 16;
    const size_t NAME_FIELD_SIZE = 255;
    const size_t PUBLIC_KEY_SIZE = 160;
    const size_t REQUEST_HEADER_SIZE = 23;  // 16 (UUID) + 1 (ver) + 2 (code) + 4 (size)
    const size_t RESPONSE_HEADER_SIZE = 7;  // 1 (ver) + 2 (code) + 4 (size)
    
    /**
     * @brief Request codes sent from Client to Server.
     */
    enum class RequestCode : uint16_t {
        Registration = 825,
        SendPublicKey = 826,
        Reconnect = 827,
        SendFile = 828,
        CrcValid = 900,
        CrcInvalidRetry = 901,
        CrcInvalidAbort = 902
    };

    /**
     * @brief Response codes received from Server to Client.
     */
    enum class ResponseCode : uint16_t {
        RegistrationSuccess = 1600,
        RegistrationFailed = 1601,
        AesKeyReceived = 1602,
        FileReceivedWithCrc = 1603,
        MessageConfirmed = 1604,
        ReconnectApproved = 1605,
        ReconnectRejected = 1606,
        GeneralError = 1607
    };

    /**
     * @brief Fixed 23-byte header for every client request.
     */
    struct RequestHeader {
        std::array<uint8_t, UUID_SIZE> clientId{};
        uint8_t version{ CLIENT_VERSION };
        RequestCode code{ RequestCode::Registration };
        uint32_t payloadSize{ 0 };
    };

    /**
     * @brief Fixed 7-byte header for every server response.
     */
    struct ResponseHeader {
        uint8_t version{ 0 };
        ResponseCode code{ ResponseCode::GeneralError };
        uint32_t payloadSize{ 0 };
    };

    class PacketBuilder {
    public:
        static std::vector<uint8_t> buildRegistration(const std::string& name);
    };

    /**
     * @brief Parser for incoming server response streams.
     */
    class PacketParser {
    public:
        /**
         * @brief Parses a 7-byte buffer into a ResponseHeader.
         */
        static std::optional<ResponseHeader> parseHeader(const std::vector<uint8_t>& headerBuffer);
        static std::optional<std::array<uint8_t, UUID_SIZE>> parseClientIdPayload(const std::vector<uint8_t>& payload);
    };
};

#endif