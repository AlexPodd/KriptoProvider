#include "Crypto.h"

#include <iostream>

using namespace std;

EVP_PKEY* Crypto::localKeypair;

Crypto::Crypto() {
  localKeypair = NULL;
  remotePublicKey = NULL;


  init();
}

Crypto::Crypto(unsigned char *remotePublicKey, size_t remotePublicKeyLength) {
  localKeypair = NULL;
  this->remotePublicKey = NULL;

  setRemotePublicKey(remotePublicKey, remotePublicKeyLength);
  init();
}

Crypto::~Crypto() {
  EVP_PKEY_free(localKeypair);
  EVP_PKEY_free(remotePublicKey);

  EVP_CIPHER_CTX_free(rsaEncryptContext);
  EVP_CIPHER_CTX_free(aesEncryptContext);

  EVP_CIPHER_CTX_free(rsaDecryptContext);
  EVP_CIPHER_CTX_free(aesDecryptContext);

  free(aesKey);
  free(aesIv);
}

int Crypto::init() {
  // Initalize contexts
  rsaEncryptContext = EVP_CIPHER_CTX_new();
  aesEncryptContext = EVP_CIPHER_CTX_new();

  rsaDecryptContext = EVP_CIPHER_CTX_new();
  aesDecryptContext = EVP_CIPHER_CTX_new();

  // Check if any of the contexts initializations failed
  if(rsaEncryptContext == NULL || aesEncryptContext == NULL || rsaDecryptContext == NULL || aesDecryptContext == NULL) {
    return FAILURE;
  }

  /* Don't set key or IV right away; we want to set lengths */
  EVP_CIPHER_CTX_init(aesEncryptContext);
  EVP_CIPHER_CTX_init(aesDecryptContext);

  EVP_CipherInit_ex(aesEncryptContext, EVP_aes_256_cbc(), NULL, NULL, NULL, 1);

  /* Now we can set key and IV lengths */
  aesKeyLength = EVP_CIPHER_CTX_key_length(aesEncryptContext);
  aesIvLength = EVP_CIPHER_CTX_iv_length(aesEncryptContext);

  // Generate RSA and AES keys
  generateRsaKeypair(&localKeypair);
  generateAesKey(&aesKey, &aesIv);

  return SUCCESS;
}

int Crypto::load_iv_from_file(const std::string& filename) {
    std::ifstream in_file(filename, std::ios::binary);
    if (!in_file) {
        std::cerr << "Error opening IV file for reading" << std::endl;
        return FAILURE;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    in_file.read((char*)iv, AES_BLOCK_SIZE);
    in_file.close();

    setAesIv(iv, AES_BLOCK_SIZE);
    return SUCCESS;
}

bool Crypto::save_iv_to_file(const unsigned char* iv, const std::string& filename) {
    std::ofstream out_file(filename, std::ios::binary);
    if (!out_file) {
        std::cerr << "Error opening IV file for writing" << std::endl;
        return false;
    }
    out_file.write((const char*)iv, AES_BLOCK_SIZE);
    out_file.close();
    return true;
}


int Crypto::generateRsaKeypair(EVP_PKEY **keypair) {
    // Проверка, что указатель на ключ не нулевой
    if (keypair == nullptr) {
        std::cerr << "Невалидный указатель на ключ!" << std::endl;
        return FAILURE;
    }

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (context == NULL) {
        std::cerr << "Ошибка при создании контекста для RSA." << std::endl;
        ERR_print_errors_fp(stderr);
        return FAILURE;
    }

    // Инициализация контекста
    if (EVP_PKEY_keygen_init(context) <= 0) {
        std::cerr << "Ошибка при инициализации генератора ключей." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(context);
        return FAILURE;
    }

    // Установка размера ключа RSA
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context, RSA_KEYLEN) <= 0) {
        std::cerr << "Ошибка при установке размера ключа RSA." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(context);
        return FAILURE;
    }

    // Генерация пары ключей
    if (EVP_PKEY_keygen(context, keypair) <= 0) {
        std::cerr << "Ошибка при генерации RSA ключей." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(context);
        return FAILURE;
    }

    // Проверяем, был ли ключ действительно сгенерирован
    if (*keypair == nullptr) {
        std::cerr << "Ошибка: ключ не был сгенерирован!" << std::endl;
        EVP_PKEY_CTX_free(context);
        return FAILURE;
    }

    // Выводим информацию о сгенерированном ключе
    std::cout << "RSA ключи успешно сгенерированы!" << std::endl;

    // Освобождаем контекст
    EVP_PKEY_CTX_free(context);
    return SUCCESS;
}

void Crypto::clearKeysAndIv() {
    // Очистка данных AES
    if (aesKey != NULL) {
        OPENSSL_cleanse(aesKey, aesKeyLength);  // Перезаписываем память ключа AES
        free(aesKey);  // Освобождаем память
        aesKey = NULL;
    }

    if (aesIv != NULL) {
        OPENSSL_cleanse(aesIv, aesIvLength);  // Перезаписываем память IV
        free(aesIv);  // Освобождаем память
        aesIv = NULL;
    }

    // Очистка данных RSA (для localKeypair)
    if (localKeypair != NULL) {
        // Прямо очищать ключ с помощью OPENSSL_cleanse невозможно для EVP_PKEY,
        // поэтому мы просто освобождаем память
        EVP_PKEY_free(localKeypair);  // Освобождаем память для локального ключа
        localKeypair = NULL;
    }

    // Очистка данных удаленного публичного ключа (remotePublicKey)
    if (remotePublicKey != NULL) {
        // Аналогично, нельзя использовать OPENSSL_cleanse для структуры EVP_PKEY
        EVP_PKEY_free(remotePublicKey);  // Освобождаем память для удаленного публичного ключа
        remotePublicKey = NULL;
    }
}


int Crypto::generateAesKey(unsigned char **aesKey, unsigned char **aesIv) {
  *aesKey = (unsigned char*)malloc(aesKeyLength);
  *aesIv = (unsigned char*)malloc(aesIvLength);

  if(*aesKey == NULL || *aesIv == NULL) {
    return FAILURE;
  }

  // For the AES key we have the option of using a PBKDF or just using straight random
  // data for the key and IV. Depending on your use case, you will want to pick one or another.
  #ifdef USE_PBKDF
    unsigned char *aesPass = (unsigned char*)malloc(aesKeyLength);
    unsigned char *aesSalt = (unsigned char*)malloc(8);

    if(aesPass == NULL || aesSalt == NULL) {
      return FAILURE;
    }

    // Get some random data to use as the AES pass and salt
    if(RAND_bytes(aesPass, aesKeyLength) == 0) {
      return FAILURE;
    }

    if(RAND_bytes(aesSalt, 8) == 0) {
      return FAILURE;
    }

    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, aesKeyLength, AES_ROUNDS, *aesKey, *aesIv) == 0) {
      return FAILURE;
    }

    free(aesPass);
    free(aesSalt);
  #else
    if(RAND_bytes(*aesKey, aesKeyLength) == 0) {
      return FAILURE;
    }

    if(RAND_bytes(*aesIv, aesIvLength) == 0) {
      return FAILURE;
    }
  #endif

  return SUCCESS;
}

int Crypto::rsaEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage,
                       unsigned char **encryptedKey, size_t *encryptedKeyLength, unsigned char **iv,
                       size_t *ivLength, const std::string &publicKeyFile) {
    // Загрузка публичного ключа из файла
    FILE *keyFile = fopen(publicKeyFile.c_str(), "r");
    if (!keyFile) {
        std::cerr << "Failed to open public key file: " << publicKeyFile << std::endl;
        return FAILURE;
    }

    EVP_PKEY *publicKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    if (!publicKey) {
        std::cerr << "Failed to read public key from file!" << std::endl;
        return FAILURE;
    }

    // Аллокация памяти для зашифрованного ключа, IV и зашифрованного сообщения
    *encryptedKey = (unsigned char *)malloc(EVP_PKEY_size(publicKey));
    *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
    *ivLength = EVP_MAX_IV_LENGTH;

    if (*encryptedKey == NULL || *iv == NULL) {
        EVP_PKEY_free(publicKey);
        return FAILURE;
    }

    *encryptedMessage = (unsigned char *)malloc(messageLength + EVP_MAX_IV_LENGTH);
    if (*encryptedMessage == NULL) {
        EVP_PKEY_free(publicKey);
        free(*encryptedKey);
        free(*iv);
        return FAILURE;
    }

    size_t encryptedMessageLength = 0;
    size_t blockLength = 0;

    // Инициализация шифрования
    if (!EVP_SealInit(rsaEncryptContext, EVP_aes_256_cbc(), encryptedKey, (int *)encryptedKeyLength, *iv, &publicKey, 1)) {
        EVP_PKEY_free(publicKey);
        free(*encryptedMessage);
        free(*encryptedKey);
        free(*iv);
        return FAILURE;
    }

    if (!EVP_SealUpdate(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, (int *)&blockLength, message, (int)messageLength)) {
        EVP_PKEY_free(publicKey);
        free(*encryptedMessage);
        free(*encryptedKey);
        free(*iv);
        return FAILURE;
    }
    encryptedMessageLength += blockLength;

    if (!EVP_SealFinal(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, (int *)&blockLength)) {
        EVP_PKEY_free(publicKey);
        free(*encryptedMessage);
        free(*encryptedKey);
        free(*iv);
        return FAILURE;
    }
    encryptedMessageLength += blockLength;

    EVP_PKEY_free(publicKey);
    return (int)encryptedMessageLength;
}


int Crypto::rsaDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char *encryptedKey,
                       size_t encryptedKeyLength, unsigned char *iv, size_t ivLength, unsigned char **decryptedMessage,
                       const unsigned char *privateKeyBuffer, size_t privateKeyBufferSize) {
    // Шаг 1: Загружаем приватный ключ из буфера
    BIO *bio = BIO_new_mem_buf(privateKeyBuffer, privateKeyBufferSize);
    if (!bio) {
        std::cerr << "Failed to create BIO for private key!" << std::endl;
        return FAILURE;
    }

    EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!privateKey) {
        std::cerr << "Failed to read private key from buffer!" << std::endl;
        return FAILURE;
    }

    // Шаг 2: Инициализация расшифровки
    size_t decryptedMessageLength = 0;
    size_t blockLength = 0;

    *decryptedMessage = (unsigned char *)malloc(encryptedMessageLength + ivLength);
    if (*decryptedMessage == nullptr) {
        EVP_PKEY_free(privateKey);
        return FAILURE;
    }

    if (!EVP_OpenInit(rsaDecryptContext, EVP_aes_256_cbc(), encryptedKey, encryptedKeyLength, iv, privateKey)) {
        EVP_PKEY_free(privateKey);
        free(*decryptedMessage);
        return FAILURE;
    }

    // Шаг 3: Обновляем и расшифровываем сообщение
    if (!EVP_OpenUpdate(rsaDecryptContext, *decryptedMessage + decryptedMessageLength, (int *)&blockLength, encryptedMessage, (int)encryptedMessageLength)) {
        EVP_PKEY_free(privateKey);
        free(*decryptedMessage);
        return FAILURE;
    }
    decryptedMessageLength += blockLength;

    if (!EVP_OpenFinal(rsaDecryptContext, *decryptedMessage + decryptedMessageLength, (int *)&blockLength)) {
        EVP_PKEY_free(privateKey);
        free(*decryptedMessage);
        return FAILURE;
    }
    decryptedMessageLength += blockLength;

    // Шаг 4: Освобождаем ресурсы
    EVP_PKEY_free(privateKey);
    return (int)decryptedMessageLength;
}

int Crypto::aesEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage) {
  // Allocate memory for everything
  size_t blockLength = 0;
  size_t encryptedMessageLength = 0;

  *encryptedMessage = (unsigned char*)malloc(messageLength + AES_BLOCK_SIZE);
  if(encryptedMessage == NULL) {
    return FAILURE;
  }

  // Encrypt it!
  if(!EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_EncryptUpdate(aesEncryptContext, *encryptedMessage, (int*)&blockLength, (unsigned char*)message, messageLength)) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  if(!EVP_EncryptFinal_ex(aesEncryptContext, *encryptedMessage + encryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }
    std::cout<<"AES KEY (encrypt): "<<aesKey<<endl;
    std::cout<<"AES IV (encrypt): "<<aesIv<<endl;
    std::cout<<"Length (before encrypt) : "<<messageLength<<endl;

  return encryptedMessageLength + blockLength;
}

int Crypto::aesDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char **decryptedMessage) {
  // Allocate memory for everything
  size_t decryptedMessageLength = 0;
  size_t blockLength = 0;

  std::cout<<"AES KEY (decrypt): "<<aesKey<<endl;
  std::cout<<"AES IV (decrypt): "<<aesIv<<endl;
  std::cout<<"Length (encrypted) : "<<encryptedMessageLength<<endl;

  *decryptedMessage = (unsigned char*)malloc(encryptedMessageLength);
  if(*decryptedMessage == NULL) {
    return FAILURE;
  }

  // Decrypt it!
  if(!EVP_DecryptInit_ex(aesDecryptContext, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_DecryptUpdate(aesDecryptContext, (unsigned char*)*decryptedMessage, (int*)&blockLength, encryptedMessage, (int)encryptedMessageLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  if(!EVP_DecryptFinal_ex(aesDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  return (int)decryptedMessageLength;
}


int Crypto::generateIv(std::string ivFilePath){
    unsigned char iv[AES_BLOCK_SIZE];
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            return FAILURE;  // Return failure if the IV generation fails
        }
    setAesIv(iv, AES_BLOCK_SIZE);
    save_iv_to_file(iv, ivFilePath);
    return SUCCESS;
}


int Crypto::getRemotePublicKey(unsigned char **publicKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, remotePublicKey);
  return bioToString(bio, publicKey);
}

int Crypto::setRemotePublicKey(unsigned char *publicKey, size_t publicKeyLength) {
  BIO *bio = BIO_new(BIO_s_mem());

  if(BIO_write(bio, publicKey, publicKeyLength) != (int)publicKeyLength) {
    return FAILURE;
  }

  PEM_read_bio_PUBKEY(bio, &remotePublicKey, NULL, NULL);
  BIO_free_all(bio);

  return SUCCESS;
}

int Crypto::getLocalPublicKey(unsigned char **publicKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, localKeypair);
  return bioToString(bio, publicKey);
}

int Crypto::getLocalPrivateKey(unsigned char **privateKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, localKeypair, NULL, NULL, 0, 0, NULL);
  return bioToString(bio, privateKey);
}

int Crypto::getAesKey(unsigned char **aesKey) {
  *aesKey = this->aesKey;
  return aesKeyLength;
}

int Crypto::setAesKey(unsigned char *aesKey, size_t aesKeyLength) {
    // Ensure the new key is the proper size
    if(aesKeyLength != this->aesKeyLength) {  // Убедитесь, что переменная длины правильно передается
        return FAILURE;
    }

    if (this->aesKey == NULL) {
        // Память уже освобождена, инициализируем новый буфер
        this->aesKey = static_cast<unsigned char*>(malloc(aesKeyLength));
        if (!this->aesKey) {
            throw std::runtime_error("Failed to allocate memory for AES key");
        }
    }

    // Копируем данные ключа в выделенную память
    memcpy(this->aesKey, aesKey, aesKeyLength);

    return SUCCESS;
}

int Crypto::getAesIv(unsigned char **aesIv) {
  *aesIv = this->aesIv;
  return aesIvLength;
}

int Crypto::setAesIv(unsigned char *aesIv, size_t aesIvLengthgth) {
  // Ensure the new IV is the proper size
  if(aesIvLengthgth != aesIvLength) {
    return FAILURE;
  }
  if (this->aesIv == NULL) {
      // Память уже освобождена, инициализируйте новый буфер
      this->aesIv = static_cast<unsigned char*>(malloc(aesIvLength));
      if (!this->aesIv) {
          throw std::runtime_error("Failed to allocate memory for IV");
      }
  }
  memcpy(this->aesIv, aesIv, aesIvLength);
  return SUCCESS;
}

int Crypto::writeKeyToFile(FILE *file, int key) {
  switch(key) {
    case KEY_SERVER_PRI:
      if(!PEM_write_PrivateKey(file, localKeypair, NULL, NULL, 0, 0, NULL)) {
        return FAILURE;
      }
      break;

    case KEY_SERVER_PUB:
      if(!PEM_write_PUBKEY(file, localKeypair)) {
        return FAILURE;
      }
      break;

    case KEY_CLIENT_PUB:
      if(!PEM_write_PUBKEY(file, remotePublicKey)) {
        return FAILURE;
      }
      break;

    case KEY_AES:
      fwrite(aesKey, 1, aesKeyLength * 8, file);
      break;

    case KEY_AES_IV:
      fwrite(aesIv, 1, aesIvLength * 8, file);
      break;

    default:
      return FAILURE;
  }

  return SUCCESS;
}


int Crypto::savePrivateKeyToMemory(EVP_PKEY *key, unsigned char **outBuffer, size_t *outLength) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        return FAILURE;
    }

    // Запись ключа в BIO
    if (!PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Failed to write private key to BIO" << std::endl;
        BIO_free(bio);
        return FAILURE;
    }

    // Получение содержимого из BIO
    char *bioData;
    long bioLength = BIO_get_mem_data(bio, &bioData);
    if (bioLength <= 0) {
        std::cerr << "Failed to get BIO data" << std::endl;
        BIO_free(bio);
        return FAILURE;
    }

    // Копирование данных в буфер
    *outBuffer = (unsigned char *)malloc(bioLength + 1);
    if (!(*outBuffer)) {
        std::cerr << "Failed to allocate memory" << std::endl;
        BIO_free(bio);
        return FAILURE;
    }

    memcpy(*outBuffer, bioData, bioLength);
    (*outBuffer)[bioLength] = '\0'; // Завершающий символ строки
    *outLength = (size_t)bioLength;

    BIO_free(bio);
    return SUCCESS;
}


int Crypto::writeKeyToMemory(unsigned char *buffer, size_t bufferSize, int key) {
    size_t offset = 0;

    switch(key) {
        case KEY_SERVER_PRI:
            {
                unsigned char *privKeyBuffer = nullptr;
                int privKeySize = i2d_PrivateKey(localKeypair, &privKeyBuffer);
                if (privKeySize <= 0 || privKeySize > bufferSize - offset) {
                    return FAILURE;
                }
                memcpy(buffer + offset, privKeyBuffer, privKeySize);
                offset += privKeySize;
                OPENSSL_free(privKeyBuffer);
            }
            break;

        case KEY_SERVER_PUB:
            {
                unsigned char *pubKeyBuffer = nullptr;
                int pubKeySize = i2d_PUBKEY(localKeypair, &pubKeyBuffer);
                if (pubKeySize <= 0 || pubKeySize > bufferSize - offset) {
                    return FAILURE;
                }
                memcpy(buffer + offset, pubKeyBuffer, pubKeySize);
                offset += pubKeySize;
                OPENSSL_free(pubKeyBuffer);
            }
            break;

        case KEY_CLIENT_PUB:
            {
                unsigned char *remotePubKeyBuffer = nullptr;
                int remotePubKeySize = i2d_PUBKEY(remotePublicKey, &remotePubKeyBuffer);
                if (remotePubKeySize <= 0 || remotePubKeySize > bufferSize - offset) {
                    return FAILURE;
                }
                memcpy(buffer + offset, remotePubKeyBuffer, remotePubKeySize);
                offset += remotePubKeySize;
                OPENSSL_free(remotePubKeyBuffer);
            }
            break;

        case KEY_AES:
            {
                if (aesKeyLength * sizeof(unsigned char) > bufferSize - offset) {
                    return FAILURE;
                }
                memcpy(buffer + offset, aesKey, aesKeyLength);
                offset += aesKeyLength * sizeof(unsigned char);
            }
            break;

        case KEY_AES_IV:
            {
                if (aesIvLength * sizeof(unsigned char) > bufferSize - offset) {
                    return FAILURE;
                }
                memcpy(buffer + offset, aesIv, aesIvLength);
                offset += aesIvLength * sizeof(unsigned char);
            }
            break;

        default:
            return FAILURE;
    }

    return SUCCESS;
}


int Crypto::bioToString(BIO *bio, unsigned char **string) {
  size_t bioLength = BIO_pending(bio);
  *string = (unsigned char*)malloc(bioLength + 1);

  if(string == NULL) {
    return FAILURE;
  }

  BIO_read(bio, *string, bioLength);

  // Insert the NUL terminator
  (*string)[bioLength] = '\0';

  BIO_free_all(bio);

  return (int)bioLength;
}

//Передавать с помощью new password
int Crypto::AddFileToCont(unsigned char * password, unsigned char *data,int datasize,std::string saveDataName, std::string directory, std::string containerName) {
    std::string encryptedContainerPath = directory + "/" + containerName;
        std::string decryptedContainerPath = directory + "/" + containerName + "_decrypted.tar";
        std::string ivFilePath = "/home/alex/kripta/iv/"+containerName + "Iv.txt";

        std::ifstream infile(encryptedContainerPath, std::ios::in | std::ios::binary);
        infile.seekg(0, std::ios::end);
        size_t file_size_in_byte = infile.tellg();
        char* xcode = (char*)malloc(sizeof(char) * file_size_in_byte);
        xcode[file_size_in_byte] = '\0';
        infile.seekg(0, std::ios::beg);
        infile.read(xcode, file_size_in_byte);
        infile.close();




            load_iv_from_file(ivFilePath);
            setAesKey(password, aesKeyLength);
            OPENSSL_cleanse(password, aesKeyLength);
\

            unsigned char *decodedData = NULL;
            int lenghtDecodeMessage = base64Decode(xcode, file_size_in_byte, &decodedData);


            unsigned char *decrypted_data = NULL;
        int decryptedLength = aesDecrypt(decodedData, lenghtDecodeMessage, &decrypted_data);
        if(decryptedLength == -1){
            std::cerr << "Failed to decrypt data!" << std::endl;

            free(decrypted_data);
            return FAILURE;
        }
        free(xcode);



        struct archive *archive;
        struct archive_entry *entry;
        int r;



        struct archive *archiveOut = archive_write_new();

        if (archive_write_set_format_pax_restricted(archiveOut) != ARCHIVE_OK) {
                std::cerr << "Ошибка при установке формата архива: " << archive_error_string(archiveOut) << std::endl;
                return 1;
            }


        size_t bufferSize = decryptedLength + datasize+2048;
        void *bufferArchOut = malloc(bufferSize);
        size_t used;
        if (archive_write_open_memory(archiveOut, bufferArchOut, bufferSize, &used) != ARCHIVE_OK) {
            std::cerr << "Failed to open output archive in memory: " << archive_error_string(archiveOut) << std::endl;
            free(bufferArchOut);
            archive_write_free(archiveOut);
            return FAILURE;
        }



        archive = archive_read_new();
        archive_read_support_filter_all(archive);
        archive_read_support_format_all(archive);
        archive_read_support_format_tar(archive);
        r = archive_read_open_memory(archive, decrypted_data, decryptedLength); // Note 1
        if (r != ARCHIVE_OK)
          exit(1);


        int len;
        char buffer[8192];
        while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
                // Заголовок архива (метаданные файла)
                if (archive_write_header(archiveOut, entry) != ARCHIVE_OK) {
                    fprintf(stderr, "Ошибка записи заголовка: %s\n", archive_error_string(archiveOut));
                    break;
                }

                // Чтение данных из исходного архива и запись в новый архив
                while ((len = archive_read_data(archive, buffer, sizeof(buffer))) > 0) {
                    if (archive_write_data(archiveOut, buffer, len) != ARCHIVE_OK) {
                        fprintf(stderr, "Ошибка записи данных: %s\n", archive_error_string(archiveOut));
                        break;
                    }
                }

                // Переход к следующему файлу в исходном архиве
                if (len < 0) {
                    fprintf(stderr, "Ошибка чтения данных: %s\n", archive_error_string(archive));
                    break;
                }
            }



        free( decrypted_data);


        r = archive_read_free(archive);  // Note 3
        if (r != ARCHIVE_OK)
          exit(1);

        struct archive_entry *entryNewFile = archive_entry_new();
        if (!entryNewFile) {
            perror("Failed to create archive entry");
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return EXIT_FAILURE;
        }

        archive_entry_set_pathname(entryNewFile, saveDataName.c_str());
        archive_entry_set_size(entryNewFile, datasize);
        archive_entry_set_filetype(entryNewFile, AE_IFREG);
        archive_entry_set_perm(entryNewFile, 0644);

        if (archive_write_header(archiveOut, entryNewFile) != ARCHIVE_OK) {
            fprintf(stderr, "Error writing header: %s\n", archive_error_string(archiveOut));
            archive_entry_free(entryNewFile);
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return EXIT_FAILURE;
        }

        if (archive_write_data(archiveOut, data, datasize) < 0) {
            fprintf(stderr, "Error writing data: %s\n", archive_error_string(archiveOut));
            archive_entry_free(entryNewFile);
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return EXIT_FAILURE;
        }

        archive_entry_free(entryNewFile);

        if (archive_write_close(archiveOut) != ARCHIVE_OK) {
            fprintf(stderr, "Error closing archive: %s\n", archive_error_string(archiveOut));
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return EXIT_FAILURE;
        }

        archive_write_free(archiveOut);



/*
        // Сохраняем архив в файл
        std::ofstream decryptedCont(decryptedContainerPath, std::ios::binary);
        if (!decryptedCont.is_open()) {
            std::cerr << "Failed to open file for writing!" << std::endl;
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return FAILURE;
        }
        std::string output1_filename = decryptedContainerPath;
            std::ofstream outfile1(output1_filename, std::ios::out | std::ios::binary);
            if (!outfile1.is_open()) {
                delete[] decrypted_data;
                throw std::runtime_error("Failed to open output file: " + output1_filename);
            }
            outfile1.write(reinterpret_cast<const char*>(bufferArchOut), used);
        decryptedCont.close();

        // Проверка успешности записи
        if (!decryptedCont) {
            std::cerr << "Error occurred while writing the archive to disk!" << std::endl;
            archive_write_free(archiveOut);
            free(bufferArchOut);
            return FAILURE;
        }
*/




        unsigned char *EncryptBuffer = NULL;
        size_t encryptedLength = aesEncrypt(reinterpret_cast<unsigned char*>(bufferArchOut), used, &EncryptBuffer);
         free(bufferArchOut);


         char *Base64EncodedMessage = base64Encode(EncryptBuffer,encryptedLength);
        // localKeypair = NULL;
       //  remotePublicKey = NULL;
           clearKeysAndIv();



        std::ofstream encryptedContantainer(encryptedContainerPath, std::ios::binary);
        if (!encryptedContantainer.is_open()) {
            std::cerr << "Failed to open file for writing!" << std::endl;
            free(EncryptBuffer);
            return FAILURE;
        }
        std::string container = encryptedContainerPath;
            std::ofstream Container(container, std::ios::out | std::ios::binary);
            if (!Container.is_open()) {
                delete[] decrypted_data;
                throw std::runtime_error("Failed to open output file: " + container);
            }
            Container.write(reinterpret_cast<const char*>(Base64EncodedMessage), strlen(Base64EncodedMessage));
        Container.close();


        // Освобождаем ресурсы
        free(Base64EncodedMessage);
        free(EncryptBuffer);
        return SUCCESS;
}



int Crypto::ExtractKeyFromContainer(unsigned char *password, std::string containerName, std::string targetFileName, std::string directory, unsigned char **outputBuffer) {

    size_t outputBufferSize = -1;
    std::string encryptedContainerPath = directory + "/" + containerName;
    std::string ivFilePath = "/home/alex/kripta/iv/" + containerName + "Iv.txt";

    // Считываем зашифрованный контейнер
    std::ifstream infile(encryptedContainerPath, std::ios::in | std::ios::binary);
    infile.seekg(0, std::ios::end);
    size_t file_size_in_byte = infile.tellg();
    char* xcode = (char*)malloc(sizeof(char) * file_size_in_byte);
    xcode[file_size_in_byte] = '\0';
    infile.seekg(0, std::ios::beg);
    infile.read(xcode, file_size_in_byte);
    infile.close();

    // Загружаем IV и устанавливаем AES ключ
    load_iv_from_file(ivFilePath);
    setAesKey(password, aesKeyLength);
    OPENSSL_cleanse(password, aesKeyLength);

    // Декодируем данные
    unsigned char *decodedData = NULL;
    int lengthDecodedMessage = base64Decode(xcode, file_size_in_byte, &decodedData);

    unsigned char *decrypted_data = NULL;
    int decryptedLength = aesDecrypt(decodedData, lengthDecodedMessage, &decrypted_data);
    if (decryptedLength == -1) {
        std::cerr << "Failed to decrypt data!" << std::endl;
        free(decodedData);
        return FAILURE;
    }
    free(xcode);

    // Открываем архив
    struct archive *archive = archive_read_new();
    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);
    archive_read_support_format_tar(archive);

    int r = archive_read_open_memory(archive, decrypted_data, decryptedLength);
    if (r != ARCHIVE_OK) {
        std::cerr << "Failed to open decrypted data as archive: " << archive_error_string(archive) << std::endl;
        free(decrypted_data);
        archive_read_free(archive);
        return FAILURE;
    }

    // Ищем файл с заданным именем внутри архива
    struct archive_entry *entry;
    int len;
    char buffer[8192];
    bool fileFound = false;

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        if (std::string(archive_entry_pathname(entry)) == targetFileName) {
            fileFound = true;

            // Определяем размер файла в архиве
            size_t fileSize = archive_entry_size(entry);
            *outputBuffer = (unsigned char*)malloc(fileSize);
            if (*outputBuffer == NULL) {
                std::cerr << "Memory allocation failed!" << std::endl;
                break;
            }

            size_t totalBytesRead = 0;
            // Чтение данных из архива и запись в буфер
            while ((len = archive_read_data(archive, buffer, sizeof(buffer))) > 0) {
                memcpy(*outputBuffer + totalBytesRead, buffer, len);
                totalBytesRead += len;
                if (totalBytesRead >= fileSize) {
                    break;
                }
            }

            outputBufferSize = totalBytesRead;
            break;
        }
    }

    if (!fileFound) {
        std::cerr << "File " << targetFileName << " not found in the archive." << std::endl;
        free(decrypted_data);
        archive_read_free(archive);
        return FAILURE;
    }

    // Освобождаем ресурсы
    free(decrypted_data);
    archive_read_free(archive);
    return outputBufferSize;
}


int Crypto::EncryptFileWithAes(std::string filePath, unsigned char *password, std::string keyName, std::string containerName,  std::string directory) {
    std::string ivFilePath = "/home/alex/kripta/iv/" + keyName + "Iv.txt";
    // 1. Чтение исходного файла
    std::ifstream infile(filePath, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Failed to open input file: " << filePath << std::endl;
        return FAILURE;
    }

    // Определяем размер файла
    infile.seekg(0, std::ios::end);
    size_t fileSize = infile.tellg();
    infile.seekg(0, std::ios::beg);

    // Чтение содержимого файла в память
    unsigned char *fileData = new unsigned char[fileSize];
    infile.read(reinterpret_cast<char*>(fileData), fileSize);
    infile.close();


    unsigned char *outputBuffer = NULL;
            if(ExtractKeyFromContainer(password,containerName, keyName+".bin", directory, &outputBuffer)==-1){
                return FAILURE;
            }



    load_iv_from_file(ivFilePath);
    setAesKey(outputBuffer, aesKeyLength);
    OPENSSL_cleanse(outputBuffer, aesKeyLength);


    // 3. Шифрование данных
    unsigned char *encryptedData = NULL;

    int encryptedSize = aesEncrypt(fileData, fileSize, &encryptedData);

    if (encryptedSize == -1) {
        std::cerr << "Failed to encrypt data!" << std::endl;
        delete [] fileData ;
        free(encryptedData);
        return FAILURE;
    }




    char *Base64EncodedMessage = base64Encode(encryptedData,encryptedSize);

    std::ofstream outfile(filePath, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open output file: " << filePath << std::endl;
        delete [] fileData;
        free(encryptedData);
        return FAILURE;
    }

    // Записываем зашифрованные данные в файл
    outfile.write(reinterpret_cast<char*>(Base64EncodedMessage), strlen(Base64EncodedMessage));
    outfile.close();

    // Освобождаем ресурсы
    free(Base64EncodedMessage);
   delete [] fileData;
    free(encryptedData);

    return SUCCESS;
}




int Crypto::DecryptFileWithAes(std::string filePath, unsigned char *password, std::string keyName, std::string containerName, std::string directory) {
    std::string ivFilePath = "/home/alex/kripta/iv/" + keyName + "Iv.txt";
std::string encryptedContainerPath = directory + "/" + containerName;


std::ifstream infile(filePath, std::ios::in | std::ios::binary);
infile.seekg(0, std::ios::end);
size_t file_size_in_byte = infile.tellg();
char* xcode = (char*)malloc(sizeof(char) * file_size_in_byte);
xcode[file_size_in_byte] = '\0';
infile.seekg(0, std::ios::beg);
infile.read(xcode, file_size_in_byte);
infile.close();



unsigned char *decodedData = NULL;
int decodedSize = base64Decode(xcode, file_size_in_byte, &decodedData);
if (decodedSize == -1) {
    std::cerr << "Failed to decode base64 data!" << std::endl;
    free(xcode);
    return FAILURE;
}


unsigned char *outputBuffer = NULL;
if(ExtractKeyFromContainer(password,containerName, keyName+".bin", directory, &outputBuffer)==-1){
    return FAILURE;
}


    load_iv_from_file(ivFilePath);
    setAesKey(outputBuffer, aesKeyLength);
    OPENSSL_cleanse(outputBuffer, aesKeyLength);

    // 3. Расшифровка данных
    unsigned char *decryptedData = NULL;
    int decryptedSize = aesDecrypt(decodedData, decodedSize, &decryptedData);
    if (decryptedSize == -1) {
        std::cerr << "Failed to decrypt data!" << std::endl;
        free(xcode);
        free(decodedData);
        free(decryptedData);
        return FAILURE;
    }

    // Записываем расшифрованные данные в файл
    std::ofstream outfile(filePath, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open output file: " << filePath << std::endl;
        free(xcode);
        free(decodedData);
        free(decryptedData);
        return FAILURE;
    }

    outfile.write(reinterpret_cast<char*>(decryptedData), decryptedSize);
    outfile.close();

    // Освобождаем ресурсы
    free(xcode);
    free(decodedData);

    return SUCCESS;
}






int Crypto::createSelfSignedCertificate(std::string privateKeyName, unsigned char *password, std::string certificateFilename, std::string containerName, std::string directory) {
    std::string pathToSaveSert = "/home/alex/kripta/Sertificate/"+certificateFilename;

    // Загрузка приватного ключа из массива байтов
    unsigned char* privateKeyData = NULL;

    size_t privateKeySize = ExtractKeyFromContainer(password, containerName, privateKeyName + ".pem", directory, &privateKeyData);
    if (privateKeySize == -1) {
        return FAILURE;
    }

    BIO* bio = BIO_new_mem_buf(privateKeyData, static_cast<int>(privateKeySize));
    if (!bio) {
        std::cerr << "Ошибка создания BIO" << std::endl;
        return FAILURE;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "Ошибка загрузки приватного ключа" << std::endl;
        return FAILURE;
    }

    // Создание нового сертификата
    X509* cert = X509_new();
    if (!cert) {
        std::cerr << "Ошибка создания сертификата" << std::endl;
        EVP_PKEY_free(pkey);
        return FAILURE;
    }

    // Установка срока действия сертификата
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1); // Устанавливаем серийный номер
    X509_gmtime_adj(X509_get_notBefore(cert), 0);     // Действителен с текущего времени
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // Действителен 1 год

    // Установка публичного ключа сертификата
    X509_set_pubkey(cert, pkey);

    // Установка имени субъекта и эмитента (они совпадают для самоподписанного сертификата)
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Some State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char*)"Kirzhach", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)containerName.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Self-Signed Certificate", -1, -1, 0);

    X509_set_issuer_name(cert, name);

    // Подпись сертификата
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        std::cerr << "Ошибка подписи сертификата" << std::endl;
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return FAILURE;
    }

    // Сохранение сертификата в файл
    FILE* certFile = fopen(pathToSaveSert.c_str(), "wb");
    if (!certFile) {
        std::cerr << "Ошибка открытия файла для записи сертификата" << std::endl;
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return FAILURE;
    }
    PEM_write_X509(certFile, cert);
    fclose(certFile);

    // Очистка ресурсов
    X509_free(cert);
    EVP_PKEY_free(pkey);

    std::cout << "Самоподписанный сертификат создан и сохранён в файл: " << pathToSaveSert << std::endl;
    return SUCCESS;
}
//sig 456  keyname 123
int Crypto::signFile(std::string privateKeyName, unsigned char *password, std::string containerName, std::string directory, std::string inputFilename, std::string signatureFilename) {
    std::string pathToSaveSign = "/home/alex/kripta/Sign/"+signatureFilename;

    unsigned char* privateKeyData = NULL;


    size_t privateKeySize= ExtractKeyFromContainer(password,containerName, privateKeyName+".pem", directory, &privateKeyData);
    if(privateKeySize ==-1){
        return FAILURE;
    }



    BIO* bio = BIO_new_mem_buf(privateKeyData, static_cast<int>(privateKeySize));
    if (!bio) {
        std::cerr << "Ошибка создания BIO" << std::endl;
        return FAILURE;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "Ошибка загрузки приватного ключа" << std::endl;
        return FAILURE;
    }

    // Чтение данных из файла
    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Ошибка открытия файла для подписи" << std::endl;
        EVP_PKEY_free(pkey);
        return FAILURE;
    }
    std::string data((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Создание контекста для подписи
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, data.data(), data.size());

    // Вычисление подписи
    unsigned char* sig = new unsigned char[EVP_PKEY_size(pkey)];
    unsigned int sigLen;
    if (EVP_SignFinal(ctx, sig, &sigLen, pkey) != 1) {
        std::cerr << "Ошибка создания подписи" << std::endl;
        delete[] sig;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return FAILURE;
    }

    // Сохранение подписи в файл
    std::ofstream signatureFile(pathToSaveSign, std::ios::binary);
    signatureFile.write(reinterpret_cast<char*>(sig), sigLen);
    signatureFile.close();

    // Очистка ресурсов
    delete[] sig;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    std::cout << "Подпись создана и сохранена в файл: " << pathToSaveSign << std::endl;
    return SUCCESS;
}

bool Crypto::verifySignature(std::string certFilename, std::string signatureFilename, std::string dataFilename) {
    // Открытие сертификата
    FILE* certFile = fopen(certFilename.c_str(), "r");
    if (!certFile) {
        std::cerr << "Ошибка открытия сертификата" << std::endl;
        return false;
    }

    X509* cert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
    fclose(certFile);

    if (!cert) {
        std::cerr << "Ошибка чтения сертификата" << std::endl;
        return false;
    }

    // Извлечение публичного ключа из сертификата
    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    X509_free(cert);  // Освобождаем сертификат после извлечения публичного ключа

    if (!pubKey) {
        std::cerr << "Ошибка извлечения публичного ключа из сертификата" << std::endl;
        return false;
    }

    // Открытие подписи
    std::ifstream signatureFile(signatureFilename, std::ios::binary);
    if (!signatureFile.is_open()) {
        std::cerr << "Ошибка открытия файла подписи" << std::endl;
        EVP_PKEY_free(pubKey);
        return false;
    }
    std::string signature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();

    // Открытие данных для проверки
    std::ifstream dataFile(dataFilename, std::ios::binary);
    if (!dataFile.is_open()) {
        std::cerr << "Ошибка открытия файла данных" << std::endl;
        EVP_PKEY_free(pubKey);
        return false;
    }
    std::string data((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());
    dataFile.close();

    // Создание контекста для проверки подписи
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста EVP" << std::endl;
        EVP_PKEY_free(pubKey);
        return false;
    }

    // Инициализация контекста для проверки
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubKey) != 1) {
        std::cerr << "Ошибка инициализации проверки подписи" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    // Обновление контекста данными для проверки
    if (EVP_DigestVerifyUpdate(ctx, data.c_str(), data.size()) != 1) {
        std::cerr << "Ошибка обновления контекста для подписи" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    // Проверка подписи
    bool isVerified = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size()) == 1;

    // Очистка ресурсов
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubKey);

    return isVerified;
}





void addDirectoryToArchive(struct archive* a, std::string dirPath) {
    // Получаем путь для директории как объект filesystem::path
    std::filesystem::path dirPathObj(dirPath);

    // Рекурсивно добавляем файлы и директории
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPathObj)) {
        // Получаем относительный путь для каждого файла
        std::string relativePath = std::filesystem::relative(entry.path(), dirPathObj).string();

        struct archive_entry* entryToAdd = archive_entry_new();
        archive_entry_set_pathname(entryToAdd, relativePath.c_str());
        archive_entry_set_filetype(entryToAdd, entry.is_directory() ? AE_IFDIR : AE_IFREG);
        archive_entry_set_size(entryToAdd, entry.is_regular_file() ? std::filesystem::file_size(entry.path()) : 0);
        archive_entry_set_perm(entryToAdd, 0755);
        if (archive_write_header(a, entryToAdd) != ARCHIVE_OK) {
            std::cerr << "Ошибка записи заголовка: " << archive_error_string(a) << std::endl;
        } else if (entry.is_regular_file()) {
            // Добавляем данные в архив, если это файл
            std::ifstream fileStream(entry.path(), std::ios::binary);
            char buffer[1024];
            while (fileStream.read(buffer, sizeof(buffer))) {
                archive_write_data(a, buffer, fileStream.gcount());
            }
            archive_write_data(a, buffer, fileStream.gcount());
        }

        archive_entry_free(entryToAdd);
    }
}



bool Crypto::createTarArchive(std::string dirPath, std::string archiveName) {
    // Получаем путь к директории, в которой находится исходная директория
    std::filesystem::path dirPathObj(dirPath);
    std::filesystem::path archivePath = dirPathObj.parent_path() / archiveName;

    struct archive *a = archive_write_new();
    if (!a) {
        std::cerr << "Не удалось создать архив" << std::endl;
        return false;
    }

    // Устанавливаем формат архива (tar)
    if (archive_write_set_format_pax_restricted(a) != ARCHIVE_OK) {
        std::cerr << "Ошибка установки формата архива: " << archive_error_string(a) << std::endl;
        archive_write_free(a);
        return false;
    }

    // Открываем архив для записи
    if (archive_write_open_filename(a, archivePath.c_str()) != ARCHIVE_OK) {
        std::cerr << "Ошибка открытия архива для записи: " << archive_error_string(a) << std::endl;
        archive_write_free(a);
        return false;
    }

    // Добавляем директорию и её содержимое в архив
    addDirectoryToArchive(a, dirPath);

    // Закрываем архив
    if (archive_write_free(a) != ARCHIVE_OK) {
        std::cerr << "Ошибка закрытия архива: " << archive_error_string(a) << std::endl;
        return false;
    }

    std::cout << "Архив успешно создан: " << archivePath << std::endl;
    return true;
}




int Crypto::EncryptFileWithRSA(std::string filePath, const std::string &publicKeyPath) {
    // Шаг 1: Прочитать исходный файл
    std::ifstream infile(filePath, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Failed to open input file: " << filePath << std::endl;
        return FAILURE;
    }

    infile.seekg(0, std::ios::end);
    size_t fileSize = infile.tellg();
    infile.seekg(0, std::ios::beg);

    unsigned char *fileData = new unsigned char[fileSize];
    infile.read(reinterpret_cast<char*>(fileData), fileSize);
    infile.close();

    // Шаг 2: Шифруем данные с использованием RSA
    unsigned char *encryptedMessage = nullptr;
    unsigned char *encryptedKey = nullptr;
    unsigned char *iv = nullptr;
    size_t encryptedKeyLength = 0;
    size_t ivLength = 0;

    int encryptedSize = rsaEncrypt(fileData, fileSize, &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv, &ivLength, publicKeyPath);
    if (encryptedSize == FAILURE) {
        std::cerr << "RSA encryption failed!" << std::endl;
        delete[] fileData;
        return FAILURE;
    }

    // Шаг 3: Записать зашифрованные данные и ключ в файл
    std::ofstream outfile(filePath, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open output file!" << std::endl;
        delete[] fileData;
        free(encryptedMessage);
        free(encryptedKey);
        free(iv);
        return FAILURE;
    }

    // Записываем IV
    outfile.write(reinterpret_cast<char*>(iv), ivLength);

    // Записываем длину и данные зашифрованного ключа
    outfile.write(reinterpret_cast<char*>(&encryptedKeyLength), sizeof(size_t));
    outfile.write(reinterpret_cast<char*>(encryptedKey), encryptedKeyLength);

    // Записываем зашифрованное сообщение
    outfile.write(reinterpret_cast<char*>(encryptedMessage), encryptedSize);

    // Освобождаем ресурсы
    delete[] fileData;
    free(encryptedMessage);
    free(encryptedKey);
    free(iv);

    outfile.close();
    return SUCCESS;
}

int Crypto::DecryptFileWithRSA(std::string privateKeyName, unsigned char *password, std::string encryptedFilePath, std::string containerName, std::string directory) {
    // Шаг 1: Открыть зашифрованный файл
    std::ifstream infile(encryptedFilePath, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Failed to open encrypted file: " << encryptedFilePath << std::endl;
        return FAILURE;
    }

    // Читаем IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    infile.read(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);
    size_t ivLength = EVP_MAX_IV_LENGTH;

    // Читаем длину зашифрованного ключа
    size_t encryptedKeyLength = 0;
    infile.read(reinterpret_cast<char*>(&encryptedKeyLength), sizeof(size_t));

    // Читаем зашифрованный AES-ключ
    unsigned char *encryptedKey = (unsigned char*)malloc(encryptedKeyLength);
    if (encryptedKey == nullptr) {
        std::cerr << "Failed to allocate memory for encrypted key!" << std::endl;
        return FAILURE;
    }
    infile.read(reinterpret_cast<char*>(encryptedKey), encryptedKeyLength);

    // Читаем зашифрованные данные
    infile.seekg(0, std::ios::end);
    size_t encryptedDataLength = static_cast<size_t>(infile.tellg()) -
(EVP_MAX_IV_LENGTH + sizeof(size_t) + encryptedKeyLength);
    infile.seekg(EVP_MAX_IV_LENGTH + sizeof(size_t) + encryptedKeyLength, std::ios::beg);

    unsigned char *encryptedMessage = (unsigned char*)malloc(encryptedDataLength);
    if (encryptedMessage == nullptr) {
        std::cerr << "Failed to allocate memory for encrypted message!" << std::endl;
        free(encryptedKey);
        return FAILURE;
    }
    infile.read(reinterpret_cast<char*>(encryptedMessage), encryptedDataLength);
    infile.close();


    unsigned char* privateKeyData = NULL;

    size_t privateKeySize = ExtractKeyFromContainer(password, containerName, privateKeyName + ".pem", directory, &privateKeyData);

    // Шаг 2: Расшифровка с использованием RSA
    unsigned char *decryptedMessage = nullptr;
    int decryptedMessageLength = rsaDecrypt(
        encryptedMessage,
        encryptedDataLength,
        encryptedKey,
        encryptedKeyLength,
        iv,
        ivLength,
        &decryptedMessage,
        privateKeyData,
        privateKeySize
        );

    if (decryptedMessageLength == FAILURE) {
        std::cerr << "RSA decryption failed!" << std::endl;
        free(encryptedKey);
        free(encryptedMessage);
        return FAILURE;
    }

    // Шаг 3: Записать расшифрованные данные в выходной файл
    std::ofstream outfile(encryptedFilePath, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open output file: " << encryptedFilePath << std::endl;
        free(encryptedKey);
        free(encryptedMessage);
        free(decryptedMessage);
        return FAILURE;
    }

    outfile.write(reinterpret_cast<char*>(decryptedMessage), decryptedMessageLength);
    outfile.close();

    // Освобождаем ресурсы
    free(encryptedKey);
    free(encryptedMessage);
    free(decryptedMessage);

    return SUCCESS;
}







std::string Crypto::hashFile(const std::string &filePath, const std::string &hashType) {
    // Открытие файла для чтения
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return "";
    }

    // Создание буфера для чтения данных из файла
    const size_t bufferSize = 1024;
    unsigned char buffer[bufferSize];

    // Результирующий хэш
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;

    // Выбор хэш-функции
    if (hashType == "SHA-256") {
        SHA256_CTX sha256Context;
        SHA256_Init(&sha256Context);

        while (file.read(reinterpret_cast<char*>(buffer), bufferSize)) {
            SHA256_Update(&sha256Context, buffer, file.gcount());
        }
        SHA256_Final(hash, &sha256Context);
        hashLength = SHA256_DIGEST_LENGTH;

    } else if (hashType == "SHA-512") {
        SHA512_CTX sha512Context;
        SHA512_Init(&sha512Context);

        while (file.read(reinterpret_cast<char*>(buffer), bufferSize)) {
            SHA512_Update(&sha512Context, buffer, file.gcount());
        }
        SHA512_Final(hash, &sha512Context);
        hashLength = SHA512_DIGEST_LENGTH;

    } else if (hashType == "MD5") {
        MD5_CTX md5Context;
        MD5_Init(&md5Context);

        while (file.read(reinterpret_cast<char*>(buffer), bufferSize)) {
            MD5_Update(&md5Context, buffer, file.gcount());
        }
        MD5_Final(hash, &md5Context);
        hashLength = MD5_DIGEST_LENGTH;

    } else {
        std::cerr << "Unsupported hash type: " << hashType << std::endl;
        return "";
    }

    // Преобразуем хэш в строку
    std::ostringstream oss;
    for (unsigned int i = 0; i < hashLength; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return oss.str();
}
