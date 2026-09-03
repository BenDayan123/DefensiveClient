#include "NetworkClient.h"

#include <iostream>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

using boost::asio::ip::tcp;

NetworkClient::NetworkClient()
    : socket(ioContext) {}

NetworkClient::~NetworkClient() {
    disconnect();
}


bool NetworkClient::connect(const std::string& host, uint16_t port) {
    try {
        std::cout << "[*] Initializing Client I/O context...\n" << std::endl;

        // Resolve host and port endpoints
        tcp::resolver resolver(ioContext);
        std::string portStr = std::to_string(port);
        auto endpoints = resolver.resolve(host, portStr);

        if (this->isConnected()) {
            socket.close();
        }

        std::cout << "[*] Connecting to (" << host << ":" << portStr << ")..." << std::endl;
        boost::asio::connect(socket, endpoints);
        std::cout << "[+] Connected successfully to server!" << std::endl;

       return true;
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "[!] Exception: " << e.what() << std::endl;
        return false;
    }
}

bool NetworkClient::send(const std::vector<uint8_t>& data) {
    if (!isConnected()) {
        std::cerr << "[NetworkClient] Error: Attempted to send on a closed socket." << std::endl;
        return false;
    }
    if (data.empty()) 
        return true;

    try {
        boost::asio::write(this->socket, boost::asio::buffer(data));
        std::cout << "[>] Sent '" << data.size() << "' bytes to server." << std::endl;
        return true;
    } catch (const boost::system::system_error& e) {
        return false;
    }
}

std::vector<uint8_t> NetworkClient::receiveExact(size_t numberOfBytes) {
    if (!isConnected() || numberOfBytes == 0) {
        return {};
    }

    std::vector<uint8_t> buffer(numberOfBytes);
    boost::system::error_code error;

    size_t bytes_received = boost::asio::read(this->socket, boost::asio::buffer(buffer), error);

    if (error == boost::asio::error::eof) {
        std::cout << "[-] Server closed connection." << std::endl;
    }
    else if (error) {
        throw boost::system::system_error(error);
    }
    else {
        std::string response(buffer.begin(), buffer.begin() + bytes_received);
        std::cout << "[<] Received response (" << bytes_received << " bytes): \"" << response << "\"" << std::endl;
    }
    return buffer;
}


bool NetworkClient::isConnected() const {
    return socket.is_open();
}