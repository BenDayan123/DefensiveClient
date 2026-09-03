#pragma once
#ifndef NETWORKCLIENT_H
#define NETWORKCLIENT_H

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>


class NetworkClient
{
private:
	boost::asio::io_context ioContext;
	boost::asio::ip::tcp::socket socket;

public:
	NetworkClient();
	~NetworkClient();
	
	/**
	 * @brief Resolves target address and establishes a TCP connection.
	 * @param host Target IPv4 or hostname.
	 * @param port Target TCP port.
	 * @return true if connected successfully, false otherwise.
	 */
	bool connect(const std::string& host, uint16_t port);

	/**
	 * @brief Transmits a complete binary payload over the active socket.
	 * Guarantees all bytes are sent or an error is raised.
	 * @param data Binary buffer to transmit.
	 * @return true if the full buffer was sent, false otherwise.
	 */
	bool send(const std::vector<uint8_t>& data);

	/**
	 * @brief Blocks until exactly the requested number of bytes are received.
	 * Protects against partial TCP stream delivery.
	 * @param numberOfBytes Total bytes required.
	 * @return Byte buffer of size numberOfBytes, or empty vector on failure/closure.
	 */
	std::vector<uint8_t> receiveExact(size_t numberOfBytes);

	/**
	 * @brief Closes the active socket connection safely.
	 */
	void disconnect();

	/**
	 * @brief Checks whether the socket is currently open.
	 */
	bool isConnected() const;
};

#endif
