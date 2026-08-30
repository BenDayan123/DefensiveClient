#define _WIN32_WINNT 0x0A00
#define BOOST_ASIO_DISABLE_BOOST_COROUTINE
#define BOOST_ASIO_DISABLE_CO_AWAIT
#define BOOST_ASIO_DISABLE_STD_COROUTINE
#define BOOST_ASIO_DISABLE_CONCEPTS

#include <iostream>
#include <boost/asio.hpp>

int main() {
    try {
        boost::asio::io_context io_context;
        std::cout << "Boost.Asio is successfully configured and working!" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}