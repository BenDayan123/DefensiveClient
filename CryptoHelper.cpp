#include "CryptoHelper.h"
#include <iostream>
#include <vector>
#include <cstdint>
#include <array>
#include <iomanip>

// Crypto++ modular headers
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

CryptoHelper::CryptoHelper() = default;

void CryptoHelper::generateRsaKeys() {
    // Generate RSA-1024 parameters
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(this->rng, 1024);

    this->privateKey = std::make_unique<CryptoPP::RSA::PrivateKey>(params);
    this->publicKey = std::make_unique<CryptoPP::RSA::PublicKey>(params);
}

std::vector<uint8_t> CryptoHelper::getPublicKeyDER() const {
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

std::string CryptoHelper::getPrivateKeyBase64() const {
    if (!privateKey) {
        return "";
    }

    // Serialize private key to raw bytes
    CryptoPP::ByteQueue queue;
    privateKey->Save(queue);

    // Encode serialized DER bytes to Base64
    std::string base64Str;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64Str), false);
    queue.CopyTo(encoder);
    encoder.MessageEnd();
    
    return base64Str;
}

std::vector<uint8_t> CryptoHelper::decryptAesKey(const std::vector<uint8_t>& cipherText) {
    if (!privateKey || cipherText.empty()) {
        std::cerr << "[-] Error: Private key not loaded or cipher text is empty." << std::endl;
        return {};
    }
    try {
        // Initialize the decryptor object with private key
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(*privateKey);

        std::string decryptedBinaryStr;

        // Pipeline the encrypted bytes through the decryptor filter into a sink string
        CryptoPP::StringSource ss(
            cipherText.data(),
            cipherText.size(),
            true, // pumpAll = true
            new CryptoPP::PK_DecryptorFilter(
                this->rng,
                decryptor,
                new CryptoPP::StringSink(decryptedBinaryStr)
            )
        );

        // Convert the decrypted string into a binary vector of bytes
        return std::vector<uint8_t>(decryptedBinaryStr.begin(), decryptedBinaryStr.end());
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "[-] Decryption failed: " << ex.what() << std::endl;
        return {};
    }
}

// =========================================================================
// AES-256-CBC Encryption Implementation
// =========================================================================
std::vector<uint8_t> CryptoHelper::encryptAesCbc(
    const std::vector<uint8_t>& aesKey,
    const std::vector<uint8_t>& plainText) {

    // AES-256 requires exactly 32 bytes (256 bits)
    if (aesKey.size() != CryptoPP::AES::MAX_KEYLENGTH) {
        std::cerr << "[-] [CryptoHelper] Error: AES-256 requires a 32-byte key (got "
            << aesKey.size() << " bytes)." << std::endl;
        return {};
    }

    try {
        // IV is defined as 16 zero-bytes per protocol specifications
        uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

        // Initialize AES-CBC encryption cipher
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(aesKey.data(), aesKey.size(), iv);

        std::string cipherText;

        // Pipeline plaintext through StreamTransformationFilter with PKCS#7 padding
        CryptoPP::StringSource ss(
            plainText.data(),
            plainText.size(),
            true, // pumpAll = true
            new CryptoPP::StreamTransformationFilter(
                encryptor,
                new CryptoPP::StringSink(cipherText),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return std::vector<uint8_t>(cipherText.begin(), cipherText.end());
    }
    catch (const CryptoPP::Exception& ex) {
        std::cerr << "[-] [CryptoHelper] AES encryption error: " << ex.what() << std::endl;
        return {};
    }
}

//TODO: for testing
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