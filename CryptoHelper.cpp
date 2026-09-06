#include "CryptoHelper.h"
#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>

// Crypto++ modular headers
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

CryptoHelper::CryptoHelper() = default;

void CryptoHelper::generateRsaKeys() {
    // Generate RSA-1024 parameters
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(this->rng, 1024);

    this->privateKey = std::make_unique<CryptoPP::RSA::PrivateKey>(params);
    this->publicKey = std::make_unique<CryptoPP::RSA::PublicKey>(params);

}

std::vector<uint8_t> CryptoHelper::getPublicKeyDer() const {
    if (!publicKey) {
        return {};
    }

    // Export public key to DER/X.509 byte stream (160 bytes for RSA-1024)
    CryptoPP::ByteQueue queue;
    publicKey->Save(queue);

    size_t keySize = queue.CurrentSize();
    std::vector<uint8_t> pubKeyBuffer(keySize);
    queue.Get(pubKeyBuffer.data(), keySize);

    return pubKeyBuffer;
}

//for testing
void printKeyBuffer(std::vector<uint8_t> buffer) {
    // Loop through each byte in the vector
    for (uint8_t byte : buffer) {
        std::cout << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(byte);
    }
    std::cout << std::endl;
}