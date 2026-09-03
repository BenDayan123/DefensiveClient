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

bool NetworkClient::isConnected() const {
    return socket.is_open();
}