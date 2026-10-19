#include <iostream>
#include <exception>

#include "TransferClient.h"

int main() {
    try {
        TransferClient client;
        return client.run() ? 0 : 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown error...." << std::endl;
    }
    return 1;
}