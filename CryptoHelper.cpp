#include "CryptoHelper.h"

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