#define _WIN32_WINNT 0x0A00

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include <string>
#include <iostream>

// Specific modular Boost.Asio headers (avoids broken monolithic macro templates)
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include "ConfigManager.h"
#include "NetworkClient.h"

using boost::asio::ip::tcp;

int main() {
    // Initialize and load configuration from transfer.json
    ConfigManager configManager;
    NetworkClient client;

    if (!configManager.loadTransferInfo())
        return 1;

    const auto& serverConfig = configManager.getTransferInfo();
    const std::string serverIP = serverConfig.getIP();
    const auto serverPort = serverConfig.getPort();
    const std::string clientName = serverConfig.getClientName();

    if (!client.connect(serverIP, serverPort)) {
        std::cerr << "[-] Unable to connect to " << serverIP << ":" << serverPort << std::endl;
        return 1;
    }

    client.send({ 0x48, 0x65, 0x6C, 0x6C, 0x6F });
    client.receiveExact(1024);


    return 0;
}