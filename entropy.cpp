#include "entropy.h"
#include "ui_entropy.h"

Entropy::Entropy(QWidget *parent, Crypto *crypto, QString ivPath) :
    QDialog(parent),
    ui(new Ui::Entropy),
    crypto(crypto),
    ivPath(ivPath)
{

    ui->setupUi(this);
    setMouseTracking(true);
}



Entropy::~Entropy()
{
    delete ui;
}

void Entropy::mouseMoveEvent(QMouseEvent *event)
{
    qint64 timeStamp = QTime::currentTime().msecsSinceStartOfDay();
    QString data = QString("%1%2%3").arg(event->x()).arg(event->y()).arg(timeStamp);
    entropyBuffer.append(data);
    data.clear();

    int value = ui->EntropyProgressBar->value();
    value++;
    ui->EntropyProgressBar->setValue(value);
}


QString* Entropy::generatePassword() {
      QCryptographicHash hash(QCryptographicHash::Sha256);
      hash.addData(entropyBuffer.toUtf8());
           QByteArray hashResult = hash.result();
           QString password = hashResult.toHex().left(32);
           return new QString(password);
       }

void Entropy::on_EntropyProgressBar_valueChanged(int value)
{
    if (value >= 100) {
               QString* password = generatePassword();

                if(!createCont(password)){
                    ui->EntropyProgressBar->setValue(0);
                    entropyBuffer.clear();
                    delete password;
                    password = nullptr;
                      emit errorOccurred("Ошибка при создании контейнера");
                }
                else{
                    emit passwordGenerated(password);
                    ui->EntropyProgressBar->setValue(0);
                    entropyBuffer.clear();
                }
           }
}






bool Entropy::createCont(QString* password) {
       size_t containerSize = 1 * 1024 * 1024;
       QString containerPath = dirrectory + "/" + containerName;
       QString encryptedContainerPath = dirrectory + "/" + containerName;
       QString ivFilePath = ivPath+"/iv/" + containerName + "Iv.txt";
       QByteArray randomData(containerSize, 0);

       unsigned char* dataPtr = reinterpret_cast<unsigned char*>(randomData.data());
       for (size_t i = 0; i < containerSize; ++i) {
           dataPtr[i] = static_cast<unsigned char>(QRandomGenerator::global()->bounded(0, 256));
       }

       size_t used;
       size_t alignedSize = ((containerSize+511)/512)*512;
       size_t archiveBufSize = 1024+alignedSize+512;
       char* archive_buf = (char*)malloc(archiveBufSize);

      qDebug() << "Правильный размер архива: " << archiveBufSize;
       struct archive *a = archive_write_new();
       if (!a) {
           perror("Failed to create archive");
           free(archive_buf);
           return EXIT_FAILURE;
       }

       archive_write_set_format_pax_restricted(a); // Note 1

       if (archive_write_open_memory(a, archive_buf, archiveBufSize, &used) != ARCHIVE_OK) {
           fprintf(stderr, "Error opening memory for archive: %s\n", archive_error_string(a));
           archive_write_free(a);
           free(archive_buf);
           return EXIT_FAILURE;
       }

       struct archive_entry *entry = archive_entry_new();
       if (!entry) {
           perror("Failed to create archive entry");
           archive_write_free(a);
           free(archive_buf);
           return EXIT_FAILURE;
       }

       archive_entry_set_pathname(entry, "random.bin");
       archive_entry_set_size(entry, containerSize);
       archive_entry_set_filetype(entry, AE_IFREG);
       archive_entry_set_perm(entry, 0644);

       if (archive_write_header(a, entry) != ARCHIVE_OK) {
           fprintf(stderr, "Error writing header: %s\n", archive_error_string(a));
           archive_entry_free(entry);
           archive_write_free(a);
           free(archive_buf);
           return EXIT_FAILURE;
       }

       if (archive_write_data(a, randomData.data(), randomData.size()) < 0) {
           fprintf(stderr, "Error writing data: %s\n", archive_error_string(a));
           archive_entry_free(entry);
           archive_write_free(a);
           free(archive_buf);
           return EXIT_FAILURE;
       }

       archive_entry_free(entry);

       if (archive_write_close(a) != ARCHIVE_OK) {
           fprintf(stderr, "Error closing archive: %s\n", archive_error_string(a));
           archive_write_free(a);
           free(archive_buf);
           return EXIT_FAILURE;
       }

       archive_write_free(a);
       randomData.clear();

       /*
       // Save archive to disk
       FILE *out_file = fopen("output.tar", "wb");
       if (!out_file) {
           perror("Error opening output file");
           free(archive_buf);
           return EXIT_FAILURE;
       }

       if (fwrite(archive_buf, 1, used, out_file) != used) {
           perror("Error writing archive to file");
           fclose(out_file);
           free(archive_buf);
           return EXIT_FAILURE;
       }
       fclose(out_file);
       printf("Archive successfully created and saved as output.tar.gz\n");
       */

       QByteArray passwordData = password->toUtf8();
       unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());
       size_t aesKeyLength = passwordData.size();



       // Установка ключа AES
       crypto->setAesKey(aesKey, aesKeyLength);

       // Генерация IV и сохранение в файл
       crypto->generateIv(ivFilePath.toStdString());
       passwordData.fill(0);

           // Шифрование данных
           unsigned char *EncryptBuffer = NULL;
           size_t encryptedLength = crypto->aesEncrypt(reinterpret_cast<unsigned char*>(archive_buf), used, &EncryptBuffer);

           crypto->clearKeysAndIv();

           char *Base64EncodedMessage = base64Encode(EncryptBuffer,encryptedLength);
           //free(archive_buf);

           // Запись зашифрованных данных в файл
           QFile encryptedFile(encryptedContainerPath);
           if (!encryptedFile.open(QIODevice::WriteOnly)) {
               std::cerr << "Ошибка при открытии файла для записи зашифрованных данных!" << std::endl;
               free(EncryptBuffer); // Освобождаем память, если файл не открылся
               return false;
           }

           // Запись зашифрованных данных
           encryptedFile.write(reinterpret_cast<char*>(Base64EncodedMessage), strlen(Base64EncodedMessage));
           encryptedFile.close();

           free(Base64EncodedMessage);
           free(EncryptBuffer);            
          //crypto->AddFileToCont(aesKey, aesKeyLength ,TestData, file_size_in_byte_test,"hel1.txt",dirrectory.toStdString(), containerName.toStdString());
    return true;
};





