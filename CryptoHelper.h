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

    /**
     * @brief Exports the public key in standard X.509 DER format (exact 160 bytes).
     * @return Binary vector containing the 160-byte public key.
     */
    std::vector<uint8_t> getPublicKeyDER() const;

    /**FileName
     * @brief Serializes the RSA private key into a single-line Base64 encoded string.
     * @return Base64 of the private key.
     */
    std::string getPrivateKeyBase64() const;

    std::vector<uint8_t> decryptAesKey(const std::vector<uint8_t>& cipherText);

    static std::vector<uint8_t> encryptAesCbc(
        const std::vector<uint8_t>& aesKey,
        const std::vector<uint8_t>& plainText);
};

void printKeyBuffer(std::vector<uint8_t> buffer);

#endif