#ifndef CRYPTO_H
#define CRYPTO_H

// Crypto++ modular headers
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

class CryptoHelper
{
private:
    CryptoPP::AutoSeededRandomPool rng;
    std::unique_ptr<CryptoPP::RSA::PrivateKey> privateKey;
    std::unique_ptr<CryptoPP::RSA::PublicKey> publicKey;

public:
    CryptoHelper();
    ~CryptoHelper() = default;

    /**
     * @brief Generates an RSA-1024 bit key pair using a cryptographically secure RNG.
     */
    void generateRsaKeys();
};

#endif