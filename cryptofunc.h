#ifndef CRYPTOFUNC_H
#define CRYPTOFUNC_H

#define RSA_KEYLEN 2048
#define AES_ROUNDS 6
#define AES_KEYLENGHT 256
#define SUCCESS 0
#define FAILURE -1

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>

#include <stdio.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <iomanip> // Для std::hex и std::setw
#include <sstream>
class CryptoFunc
{
public:
    CryptoFunc();
     int AddFileToCont(unsigned char * password, int passwordSize, unsigned char *data,int datasize,std::string saveDataName, std::string directory, std::string containerName);
    bool aes_encrypt(const unsigned char* input, unsigned char* output, const unsigned char* key, const std::string& iv_filename, size_t input_len);
       bool aes_decrypt(const unsigned char* encrypted_data, size_t encrypted_data_len,
       const unsigned char* key, const std::string& iv_filename,
       unsigned char* decrypted_data, size_t& decrypted_len);
        EVP_PKEY* create_rsa_keypair();
        int rsa_encrypt(EVP_PKEY* rsa_key, const unsigned char* input, unsigned char* encrypted);
        int rsa_decrypt(EVP_PKEY* rsa_key, const unsigned char* encrypted, unsigned char* decrypted);
        void sha256(const unsigned char* data, unsigned char* hash);
  bool load_iv_from_file(unsigned char* iv, const std::string& filename);
       bool save_iv_to_file(const unsigned char* iv, const std::string& filename);
};

#endif // CRYPTOFUNC_H
