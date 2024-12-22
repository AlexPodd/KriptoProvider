#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "base64.h"
#include <filesystem>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/md5.h>


#include <unistd.h>
#include <dirent.h>
#ifndef CRYPTO_H
#define CRYPTO_H

#define RSA_KEYLEN 2048
#define AES_ROUNDS 6

#define PSEUDO_CLIENT

//#define USE_PBKDF

#define SUCCESS 0
#define FAILURE -1

#define KEY_SERVER_PRI 0
#define KEY_SERVER_PUB 1
#define KEY_CLIENT_PUB 2
#define KEY_AES        3
#define KEY_AES_IV     4

class Crypto {
public:
    // Конструктор класса Crypto. Инициализирует ключи и контексты.
    Crypto();
    Crypto(unsigned char *remotePubKey, size_t remotePubKeyLen);
    // Деструктор класса Crypto. Освобождает ресурсы, связанные с ключами и контекстами.
    ~Crypto();

    // Шифрует сообщение с помощью RSA и AES. Использует публичный ключ удаленного устройства для шифрования ключа AES.
    // message - входящее сообщение для шифрования.
    // messageLength - длина входящего сообщения.
    // encryptedMessage - указатель на зашифрованное сообщение.
    // encryptedKey - указатель на зашифрованный ключ AES.
    // encryptedKeyLength - длина зашифрованного ключа AES.
    // iv - вектор инициализации для AES.
    // ivLength - длина вектора инициализации.
    int rsaEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage,
                   unsigned char **encryptedKey, size_t *encryptedKeyLength, unsigned char **iv,
                   size_t *ivLength, const std::string &publicKeyFile);

    // Расшифровывает сообщение с помощью RSA и AES, используя зашифрованный ключ и IV.
    // encryptedMessage - зашифрованное сообщение.
    // encryptedMessageLength - длина зашифрованного сообщения.
    // encryptedKey - зашифрованный ключ AES.
    // encryptedKeyLength - длина зашифрованного ключа.
    // iv - вектор инициализации.
    // ivLength - длина вектора инициализации.
    // decryptedMessage - указатель на расшифрованное сообщение.
    int rsaDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char *encryptedKey,
                   size_t encryptedKeyLength, unsigned char *iv, size_t ivLength, unsigned char **decryptedMessage,
                   const unsigned char *privateKeyBuffer, size_t privateKeyBufferSize);

    // Шифрует сообщение с помощью AES.
    // message - входящее сообщение для шифрования.
    // messageLength - длина входящего сообщения.
    // encryptedMessage - указатель на зашифрованное сообщение.
    int aesEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage);

    // Расшифровывает сообщение с помощью AES.
    // encryptedMessage - зашифрованное сообщение.
    // encryptedMessageLength - длина зашифрованного сообщения.
    // decryptedMessage - указатель на расшифрованное сообщение.
    int aesDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char **decryptedMessage);

    // Получает публичный ключ удаленного устройства.
    // publicKey - указатель на переменную для хранения публичного ключа.
    int getRemotePublicKey(unsigned char **publicKey);

    // Устанавливает публичный ключ удаленного устройства.
    // publicKey - публичный ключ удаленного устройства.
    // publicKeyLength - длина публичного ключа.
    int setRemotePublicKey(unsigned char *publicKey, size_t publicKeyLength);

    // Получает публичный ключ локального устройства.
    // publicKey - указатель на переменную для хранения публичного ключа.
    int getLocalPublicKey(unsigned char **publicKey);

    // Получает приватный ключ локального устройства.
    // privateKey - указатель на переменную для хранения приватного ключа.
    int getLocalPrivateKey(unsigned char **privateKey);

    // Получает текущий AES-ключ.
    // aesKey - указатель на переменную для хранения AES-ключа.
    int getAesKey(unsigned char **aesKey);

    // Устанавливает новый AES-ключ.
    // aesKey - новый AES-ключ.
    // aesKeyLen - длина нового AES-ключа.
    int setAesKey(unsigned char *aesKey, size_t aesKeyLen);

    // Получает текущий вектор инициализации (IV) для AES.
    // aesIv - указатель на переменную для хранения IV.
    int getAesIv(unsigned char **aesIv);

    // Устанавливает новый вектор инициализации (IV) для AES.
    // aesIv - новый вектор инициализации.
    // aesIvLen - длина нового IV.
    int setAesIv(unsigned char *aesIv, size_t aesIvLen);

    // Записывает ключ в файл.
    // file - указатель на файл, в который будет записан ключ.
    // key - код ключа для записи (например, приватный ключ сервера, публичный ключ сервера и т.д.)
    int writeKeyToFile(FILE *file, int key);
    int savePrivateKeyToMemory(EVP_PKEY *key, unsigned char **outBuffer, size_t *outLength);
     // Генерация пары ключей RSA
    // keypair - указатель на EVP_PKEY, где будет храниться пара ключей.
    int generateRsaKeypair(EVP_PKEY **keypair);
    void clearKeysAndIv();

    int writeKeyToMemory(unsigned char *buffer, size_t bufferSize, int key);
    // Генерация AES-ключа и вектора инициализации
    // aesKey - указатель на указатель на AES-ключ.
    // aesIv - указатель на указатель на AES-IV.
    int generateAesKey(unsigned char **aesKey, unsigned char **aesIv);
    static EVP_PKEY *localKeypair;
    int generateIv(std::string ivFilePath);
int load_iv_from_file(const std::string& filename);
int AddFileToCont(unsigned char * password, unsigned char *data,int datasize,std::string saveDataName, std::string directory, std::string containerName);
bool save_iv_to_file(const unsigned char* iv, const std::string& filename);
int EncryptFileWithAes(std::string filePath, unsigned char *password, std::string keyName, std::string containerName,  std::string directory);
int ExtractKeyFromContainer(unsigned char *password, std::string containerName, std::string targetFileName, std::string directory, unsigned char **outputBuffer);
int ArchiveDirectory(std::string directoryPath, std::string archivePath);
int DecryptFileWithAes(std::string filePath, unsigned char *password, std::string keyName, std::string containerName, std::string directory);
int createSelfSignedCertificate(std::string privateKeyName, unsigned char *password, std::string csrFilename, std::string containerName, std::string directory);
int signFile(std::string privateKeyName, unsigned char *password, std::string containerName, std::string directory, std::string inputFilename, std::string signatureFilename);
bool verifySignature(std::string certFilename, std::string signatureFilename, std::string dataFilename);
bool createTarArchive(std::string dirPath, std::string archiveName);
int EncryptFileWithRSA(std::string filePath, const std::string &publicKeyPath);
int DecryptFileWithRSA(std::string privateKeyName, unsigned char *password, std::string encryptedFilePath, std::string containerName, std::string directory);
std::string hashFile(const std::string &filePath, const std::string &hashType);
private:
      // Локальная пара ключей (RSA)
    EVP_PKEY *remotePublicKey;      // Публичный ключ удаленного устройства

    EVP_CIPHER_CTX *rsaEncryptContext;  // Контекст для шифрования с использованием RSA
    EVP_CIPHER_CTX *aesEncryptContext;  // Контекст для шифрования с использованием AES

    EVP_CIPHER_CTX *rsaDecryptContext;  // Контекст для расшифровки с использованием RSA
    EVP_CIPHER_CTX *aesDecryptContext;  // Контекст для расшифровки с использованием AES

    unsigned char *aesKey;  // AES-ключ
    unsigned char *aesIv;   // AES-вектор инициализации

    size_t aesKeyLength;    // Длина AES-ключа
    size_t aesIvLength;     // Длина AES-IV

    // Инициализация объектов, генерация ключей и контекстов
    int init();



    // Преобразование данных из BIO в строку
    // bio - BIO, содержащий данные.
    // string - указатель на строку, в которую будут записаны данные.
    int bioToString(BIO *bio, unsigned char **string);
};

#endif
