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

using boost::asio::ip::tcp;

int main() {
    const std::string SERVER_IP = "127.0.0.1";
    const std::string SERVER_PORT = "5000";

    try {
        std::cout << "[*] Initializing Client I/O context...\n" << std::endl;
        boost::asio::io_context io_context;

        // Resolve host and port endpoints
        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(SERVER_IP, SERVER_PORT);

        // Setup socket and connect to server
        tcp::socket socket(io_context);
        std::cout << "[*] Connecting to (" << SERVER_IP << ":" << SERVER_PORT << ")..." << std::endl;
        boost::asio::connect(socket, endpoints);
        std::cout << "[+] Connected successfully to server!" << std::endl;

        // Prepare and send test payload
        std::string test_message = "Hello from C++ Client!";
        std::vector<uint8_t> send_buffer(test_message.begin(), test_message.end());

        boost::asio::write(socket, boost::asio::buffer(send_buffer));
        std::cout << "[>] Sent '" << send_buffer.size() << "' bytes to server." << std::endl;

        // Read response from the server
        std::vector<uint8_t> recv_buffer(1024);
        boost::system::error_code error;

        size_t bytes_received = socket.read_some(boost::asio::buffer(recv_buffer), error);

        if (error == boost::asio::error::eof) {
            std::cout << "[-] Server closed connection." << std::endl;
        }
        else if (error) {
            throw boost::system::system_error(error);
        }
        else {
            std::string response(recv_buffer.begin(), recv_buffer.begin() + bytes_received);
            std::cout << "[<] Received response (" << bytes_received << " bytes): \"" << response << "\"" << std::endl;
        }

        // Clean up socket
        socket.close();
        std::cout << "[*] Socket closed cleanly." << std::endl;
    }

    catch (const std::exception& e) {
        std::cerr << "[!] Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}