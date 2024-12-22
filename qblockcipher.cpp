#include <iostream>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

class BlockCipher {
public:
    BlockCipher() {}

    // Generates random salt (random bytes) of given size
    std::vector<unsigned char> generateSalt(const size_t size) {
        std::vector<unsigned char> arr(size);
        if (!RAND_bytes(arr.data(), size)) {
            throw std::runtime_error("Error generating random bytes for salt.");
        }
        return arr;
    }

    // Encrypts data with AES Block Cipher
    std::vector<unsigned char> encryptAesBlockCipher(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key,
                                                      const std::vector<unsigned char>& iv, const std::vector<unsigned char>& password,
                                                      const std::vector<unsigned char>& salt, const int rounds,
                                                      const EVP_CIPHER* cipher, const EVP_MD* md) {
        try {
            // Initialize EVP_CIPHER_CTX
            EVP_CIPHER_CTX* encryptionCipher = EVP_CIPHER_CTX_new();
                       if (!encryptionCipher) {
                           throw std::runtime_error("Couldn't initialize encryption cipher.");
                       }

            // Reinterpret values for multi-use
            unsigned char* m_key = const_cast<unsigned char*>(key.data());
            unsigned char* m_iv = const_cast<unsigned char*>(iv.data());

            // Set data length
            int cipherTextLength = data.size() + AES_BLOCK_SIZE;
            int finalLength = 0;

            // Initialize cipherText. Here encrypted data will be stored
            std::vector<unsigned char> cipherText(cipherTextLength);
            if (cipherText.empty()) {
                throw std::runtime_error("Couldn't allocate memory for 'cipherText'.");
            }

            // Start encryption with password-based encryption routine
            if (!EVP_BytesToKey(cipher, md, salt.data(), password.data(), password.size(), rounds, m_key, m_iv)) {
                throw std::runtime_error("Couldn't start encryption routine.");
            }

            // Initialize encryption operation
            if (!EVP_EncryptInit_ex(encryptionCipher.get(), cipher, nullptr, m_key, m_iv)) {
                throw std::runtime_error("Couldn't initialize encryption operation.");
            }

            // Provide the message to be encrypted and obtain the encrypted output
            if (!EVP_EncryptUpdate(encryptionCipher.get(), cipherText.data(), &cipherTextLength, data.data(), data.size())) {
                throw std::runtime_error("Couldn't provide message to be encrypted.");
            }

            // Finalize the encryption
            if (!EVP_EncryptFinal(encryptionCipher.get(), cipherText.data() + cipherTextLength, &finalLength)) {
                throw std::runtime_error("Couldn't finalize encryption.");
            }

            // Finalize data to be returned
            cipherText.resize(cipherTextLength + finalLength);
            return cipherText;
        } catch (const std::exception& exception) {
            throw;
        } catch (...) {
            throw;
        }
    }

    // Decrypts data with AES Block Cipher
    std::vector<unsigned char> decryptAesBlockCipher(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key,
                                                      const std::vector<unsigned char>& iv, const std::vector<unsigned char>& password,
                                                      const std::vector<unsigned char>& salt, const int rounds,
                                                      const EVP_CIPHER* cipher, const EVP_MD* md) {
        try {
            // Initialize EVP_CIPHER_CTX
            EVP_CIPHER_CTX* encryptionCipher = EVP_CIPHER_CTX_new();
                       if (!encryptionCipher) {
                           throw std::runtime_error("Couldn't initialize encryption cipher.");
                       }

            // Reinterpret values for multi-use
            unsigned char* m_key = const_cast<unsigned char*>(key.data());
            unsigned char* m_iv = const_cast<unsigned char*>(iv.data());

            // Set data length
            int plainTextLength = data.size();
            int finalLength = 0;

            // Initialize plainText. Here decrypted data will be stored
            std::vector<unsigned char> plainText(plainTextLength + AES_BLOCK_SIZE);
            if (plainText.empty()) {
                throw std::runtime_error("Couldn't allocate memory for 'plainText'.");
            }

            // Start encryption with password-based encryption routine
            if (!EVP_BytesToKey(cipher, md, salt.data(), password.data(), password.size(), rounds, m_key, m_iv)) {
                throw std::runtime_error("Couldn't start decryption routine.");
            }

            // Initialize decryption operation
            if (!EVP_DecryptInit_ex(decryptionCipher.get(), cipher, nullptr, m_key, m_iv)) {
                throw std::runtime_error("Couldn't initialize decryption operation.");
            }

            // Provide the message to be decrypted and obtain the plaintext output
            if (!EVP_DecryptUpdate(decryptionCipher.get(), plainText.data(), &plainTextLength, data.data(), data.size())) {
                throw std::runtime_error("Couldn't provide message to be decrypted.");
            }

            // Finalize the decryption
            if (!EVP_DecryptFinal(decryptionCipher.get(), plainText.data() + plainTextLength, &finalLength)) {
                throw std::runtime_error("Couldn't finalize decryption.");
            }

            // Finalize data to be returned
            plainText.resize(plainTextLength + finalLength);
            return plainText;
        } catch (const std::exception& exception) {
            throw;
        } catch (...) {
            throw;
        }
    }
};
