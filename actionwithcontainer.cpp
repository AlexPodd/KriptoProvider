#include "actionwithcontainer.h"
#include "ui_actionwithcontainer.h"

ActionWithContainer::ActionWithContainer(QWidget *parent, Crypto *crypto, QString ivPath) :
    QDialog(parent),
    ui(new Ui::ActionWithContainer),
  crypto(crypto),
  ivPath(ivPath)
{
    ui->setupUi(this);
}

ActionWithContainer::~ActionWithContainer()
{
    delete ui;
}

void ActionWithContainer::on_CreateDS_clicked()
{

    bool ok;
    QString PrivateKeyName = QInputDialog::getText(this, "Имя", "Введите название ключа:",
                                            QLineEdit::Normal, "", &ok);

    // Проверяем, было ли введено имя
    if (!ok || PrivateKeyName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    QString csrFilename = QInputDialog::getText(this, "Имя", "Введите название для подписи:",
                                                   QLineEdit::Normal, "", &ok);

    // Проверяем, было ли введено имя
    if (!ok || csrFilename.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                             QLineEdit::Normal, "", &ok);

    QByteArray passwordData = password.toUtf8();
    unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

    crypto->createSelfSignedCertificate(PrivateKeyName.toStdString(), aesKey, csrFilename.toStdString(), containerName.toStdString(), dirrectory.toStdString());
}

void ActionWithContainer::on_UseDS_clicked()
{
    bool ok;

    // Запрашиваем имя приватного ключа
    QString PrivateKeyName = QInputDialog::getText(this, "Имя", "Введите название ключа:",
                                                   QLineEdit::Normal, "", &ok);

    // Проверяем, было ли введено имя
    if (!ok || PrivateKeyName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    // Запрашиваем имя для подписи
    QString signatureFilename = QInputDialog::getText(this, "Имя", "Введите название файла подписи:",
                                                      QLineEdit::Normal, "", &ok);

    if (!ok || signatureFilename.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для файла подписи!");
        return;
    }

    // Открываем диалоговое окно для выбора файла
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFile);  // Позволяет выбирать только существующие файлы
    dialog.setViewMode(QFileDialog::List);

    QString fileToSign;
    if (dialog.exec()) {
        QStringList selectedFiles = dialog.selectedFiles();
        if (!selectedFiles.isEmpty()) {
            fileToSign = selectedFiles.first();
        } else {
            QMessageBox::warning(this, "Ошибка", "Вы не выбрали файл для подписи!");
            return;
        }
    }

    // Запрашиваем пароль для контейнера
    QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                             QLineEdit::Password, "", &ok);

    if (!ok || password.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели пароль от контейнера!");
        return;
    }

    // Преобразуем пароль в формат QByteArray
    QByteArray passwordData = password.toUtf8();
    unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

    // Вызываем функцию для создания подписи
    int result = crypto->signFile(
        PrivateKeyName.toStdString(),
        aesKey,
        containerName.toStdString(),
        dirrectory.toStdString(),
        fileToSign.toStdString(),
        signatureFilename.toStdString()
        );

    // Проверяем результат работы функции
    if (result == SUCCESS) {
        QMessageBox::information(this, "Успех", "Файл успешно подписан!");
    } else {
        QMessageBox::critical(this, "Ошибка", "Произошла ошибка при создании подписи.");
    }
}


void ActionWithContainer::on_AddAESKey_clicked()
{
    QString ivFilePath = ivPath+"/iv/" + containerName + "Iv.txt";
    bool ok;
       QString keyName = QInputDialog::getText(this, "Имя", "Введите название для ключа:",
                                                     QLineEdit::Normal, "", &ok);

       // Проверяем, было ли введено имя
       if (!ok || keyName.isEmpty()) {
           QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
           return;
       }
       for (size_t i = 0; i < 32; ++i) {
           entropyBuffer.append(QChar(QRandomGenerator::global()->bounded(0, 256)));
       }

     QString ivFilePathNew = ivPath+"/iv/" + keyName + "Iv.txt";

       QCryptographicHash hash(QCryptographicHash::Sha256);
       hash.addData(entropyBuffer.toUtf8());
            QByteArray hashResult = hash.result();
            QString DATApassword = hashResult.toHex().left(32);

            QByteArray DATApasswordData = DATApassword.toUtf8();
            unsigned char* aesKey = reinterpret_cast<unsigned char*>(DATApasswordData.data());
            size_t aesKeyLength = DATApasswordData.size();


            crypto->setAesKey(aesKey, aesKeyLength);
            crypto->generateIv(ivFilePathNew.toStdString());

            DATApasswordData.fill(0);
            OPENSSL_cleanse(aesKey, aesKeyLength);
            aesKey = nullptr;
            DATApassword.clear();

            size_t bufferSize = aesKeyLength;
            unsigned char* buffer = new unsigned char[bufferSize];



            // Запись ключа в буфер
            int result = crypto->writeKeyToMemory(buffer, bufferSize, KEY_AES);
            if (result == SUCCESS) {
                // Буфер теперь содержит публичный ключ
                // Можете использовать buffer для дальнейших действий

                    crypto->clearKeysAndIv();
                    QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                                                  QLineEdit::Normal, "", &ok);

                    QByteArray passwordData = password.toUtf8();
                    unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());



                    crypto->AddFileToCont( aesKey, buffer, 32, keyName.toStdString()+".bin" , dirrectory.toStdString(), containerName.toStdString());
                    OPENSSL_cleanse(aesKey, aesKeyLength);

            }else {
                // Ошибка записи в буфер


                delete[] buffer;
                return;
            }

            delete[] buffer;
}


void ActionWithContainer::on_AddRSAKey_clicked()
{
    bool ok;
       QString keyName = QInputDialog::getText(this, "Имя", "Введите название для ключа:",
                                                     QLineEdit::Normal, "", &ok);

       // Проверяем, было ли введено имя
       if (!ok || keyName.isEmpty()) {
           QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
           return;
       }

       EVP_PKEY *keyPair = nullptr;
       if(crypto->generateRsaKeypair(&keyPair)==FAILURE){
        return;
       }
       QString filepath = ivPath+"RSAPublic/"+keyName+".pem";
       FILE *fileToPublic = fopen(filepath.toStdString().c_str(), "w");
           if (!fileToPublic) {
               std::cerr << "Не удалось открыть файл для записи" << std::endl;
               EVP_PKEY_free(keyPair);
               return;
           }
           crypto->localKeypair = keyPair;

       if(crypto->writeKeyToFile(fileToPublic, KEY_SERVER_PUB)==FAILURE){
           return;
       }

       fclose(fileToPublic);

       unsigned char *PrivateKeyBuffer = NULL;
       size_t KeySize = 0;
       if(crypto->savePrivateKeyToMemory(keyPair, &PrivateKeyBuffer, &KeySize)==FAILURE){
           return;
       }


       QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                                     QLineEdit::Normal, "", &ok);

       QByteArray passwordData = password.toUtf8();
       unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

       if (crypto->AddFileToCont(aesKey, PrivateKeyBuffer, KeySize,
                                 keyName.toStdString() + ".pem",
                                 dirrectory.toStdString(),
                                 containerName.toStdString()) == FAILURE) {
           OPENSSL_cleanse(PrivateKeyBuffer, KeySize); // Очищаем буфер ключа
           free(PrivateKeyBuffer); // Освобождаем память
           return;
       }
       OPENSSL_cleanse(PrivateKeyBuffer, KeySize); // Очищаем буфер ключа
       free(PrivateKeyBuffer);
}


void ActionWithContainer::on_EncryptFileAES_clicked()
{
    bool ok;
       QString keyName = QInputDialog::getText(this, "Имя", "Введите название для ключа для шифрования:",
                                                     QLineEdit::Normal, "", &ok);


       if (!ok || keyName.isEmpty()) {
           QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
           return;
       }

       QFileDialog dialog(this);
       dialog.setFileMode(QFileDialog::AnyFile);  // Позволяет выбирать и файлы, и директории
       dialog.setViewMode(QFileDialog::List);

       if (dialog.exec()) {
           QStringList selectedFiles = dialog.selectedFiles();

           if (selectedFiles.isEmpty()) {
               return;  // Если ничего не выбрано, выходим
           }

           // Получаем первый выбранный путь
           QString selectedPath = selectedFiles.first();

           qDebug() << "Выбран файл: " << selectedPath;


               QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                                             QLineEdit::Normal, "", &ok);
               QByteArray passwordData = password.toUtf8();
               unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());




               if(crypto->EncryptFileWithAes(selectedPath.toStdString(), aesKey, keyName.toStdString(), containerName.toStdString(), dirrectory.toStdString()) == FAILURE){
                       QMessageBox::information(this, "Неудача", "Не удалось зашифровать файл!");
               }
               else{
                   QMessageBox::information(this, "Успех", "Удалось зашифровать файл!");
               }
               // Обработка файла
               // crypto->EncryptFile(aesKey, selectedPath.toStdString(), keyName.toStdString(), dirrectory.toStdString());

       }
     //  std::cout << crypto->ExtractKeyFromContainer(aesKey, containerName.toStdString(), keyName.toStdString()+".bin", dirrectory.toStdString(), &outputBuffer);
}





void ActionWithContainer::on_EncryptFileRSA_clicked()
{

    QString publicKeyFile = QFileDialog::getOpenFileName(this, tr("Выберите публичный ключ"), "", tr("Public Key Files (*.pem *.pub);;All Files (*)"));
    if (publicKeyFile.isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Публичный ключ не выбран."));
        return;
    }

    // Открытие диалогового окна для выбора файла для шифрования
    QString fileToEncrypt = QFileDialog::getOpenFileName(this, tr("Выберите файл для шифрования"), "", tr("All Files (*)"));
    if (fileToEncrypt.isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("No file selected for encryption."));
        return;
    }

    // Вызов метода шифрования с выбранными файлами
    bool result = crypto->EncryptFileWithRSA(fileToEncrypt.toStdString(), publicKeyFile.toStdString());
    if (result != FAILURE) {
        QMessageBox::information(this, tr("Успех"), tr("Файл успешно зашифрован."));
    } else {
        QMessageBox::warning(this, tr("Ошибка"), tr("Шифрование не удалось."));
    }
}


void ActionWithContainer::on_DecrytFileAES_clicked()
{
    bool ok;
    QString keyName = QInputDialog::getText(this, "Имя", "Введите название для ключа для расшифрования:",
                                             QLineEdit::Normal, "", &ok);

    if (!ok || keyName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::AnyFile);  // Оставляем возможность выбора как файлов, так и директорий
    dialog.setViewMode(QFileDialog::List);  // Список файлов

    if (dialog.exec()) {
        QStringList selectedFiles = dialog.selectedFiles();

        if (selectedFiles.isEmpty()) {
            return;  // Если ничего не выбрано, выходим
        }

        QString selectedPath = selectedFiles.first();

            qDebug() << "Выбран файл: " << selectedPath;

            QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:",
                                                     QLineEdit::Normal, "", &ok);
            QByteArray passwordData = password.toUtf8();
            unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

            // Обработка файла
            crypto->DecryptFileWithAes(selectedPath.toStdString(), aesKey, keyName.toStdString(), containerName.toStdString(), dirrectory.toStdString());

    }
}



void ActionWithContainer::on_DecryptFileRSA_clicked()
{
    bool ok;

    QString keyName = QInputDialog::getText(this, "Имя", "Введите название для ключа для расшифрования:",
                                            QLineEdit::Normal, "", &ok);

    if (!ok || keyName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    QString fileToDecrypt = QFileDialog::getOpenFileName(this, tr("Выберите файл для дешифрования"), "", tr("All Files (*)"));
    if (fileToDecrypt.isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Не выбран файл для дешифрования."));
        return;
    }

    // Запрос пароля для контейнера
    QString password = QInputDialog::getText(this, "Пароль", "Введите пароль от контейнера:", QLineEdit::Password, "", &ok);
    if (!ok || password.isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Пароль не введен."));
        return;
    }

    QByteArray passwordData = password.toUtf8();
    unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

    // Вызов функции дешифрования файла с использованием RSA
    bool result = crypto->DecryptFileWithRSA(keyName.toStdString(), aesKey, fileToDecrypt.toStdString(), containerName.toStdString(), dirrectory.toStdString());
    if (result !=FAILURE) {
        QMessageBox::information(this, tr("Успех"), tr("Файл успешно дешифрован."));
    } else {
        QMessageBox::warning(this, tr("Ошибка"), tr("Не удалось дешифровать файл."));
    }
}


void ActionWithContainer::on_EncryptDirAES_clicked()
{
    bool ok;

    // Запрос имени ключа
    QString keyName = QInputDialog::getText(this, "Имя",
                                            "Введите название для ключа для шифрования:",
                                            QLineEdit::Normal, "", &ok);

    if (!ok || keyName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели название для ключа!");
        return;
    }

    // Запрос директории для архивации
    QString dirPath = QFileDialog::getExistingDirectory(this, "Выберите директорию для шифрования");

    if (dirPath.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не выбрали директорию!");
        return;
    }

    // Запрос имени архива
    QString archiveName = QInputDialog::getText(this, "Имя архива",
                                                "Введите имя архива (с расширением .tar):",
                                                QLineEdit::Normal, "", &ok);

    if (!ok || archiveName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели имя для архива!");
        return;
    }


    // Формирование пути для архива
    QString archivePath = QDir(dirPath).filePath(archiveName);
    qDebug() << "Путь архива: " << archivePath;

    // Создаем архив
    if (!crypto->createTarArchive(dirPath.toStdString(), archivePath.toStdString())) {
        QMessageBox::warning(this, "Ошибка", "Не удалось создать архив!");
        return;
    }

    // Запрос пароля
    QString password = QInputDialog::getText(this, "Пароль",
                                             "Введите пароль от контейнера:",
                                             QLineEdit::Normal, "", &ok);

    if (!ok || password.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели пароль!");
        return;
    }

    QByteArray passwordData = password.toUtf8();
    unsigned char* aesKey = reinterpret_cast<unsigned char*>(passwordData.data());

    // Шифруем архив
    if (crypto->EncryptFileWithAes(archivePath.toStdString(), aesKey,
                                   keyName.toStdString(), containerName.toStdString(),
                                   dirrectory.toStdString()) == FAILURE) {
        QMessageBox::information(this, "Неудача", "Не удалось зашифровать папку!");
    } else {
        QMessageBox::information(this, "Успех", "Папка зашифрована!");
    }
}


void ActionWithContainer::on_EncryptDirRSA_clicked()
{

    bool ok;


    // Запрос директории для архивации
    QString dirPath = QFileDialog::getExistingDirectory(this, "Выберите директорию для шифрования");

    if (dirPath.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не выбрали директорию!");
        return;
    }

    // Запрос имени архива
    QString archiveName = QInputDialog::getText(this, "Имя архива",
                                                "Введите имя архива (с расширением .tar):",
                                                QLineEdit::Normal, "", &ok);

    if (!ok || archiveName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не ввели имя для архива!");
        return;
    }


    // Формирование пути для архива
    QString archivePath = QDir(dirPath).filePath(archiveName);
    qDebug() << "Путь архива: " << archivePath;

    // Создаем архив
    if (!crypto->createTarArchive(dirPath.toStdString(), archivePath.toStdString())) {
        QMessageBox::warning(this, "Ошибка", "Не удалось создать архив!");
        return;
    }

    QString publicKeyFile = QFileDialog::getOpenFileName(this, tr("Выберите публичный ключ"), "", tr("Public Key Files (*.pem *.pub);;All Files (*)"));
    if (publicKeyFile.isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Публичный ключ не выбран."));
        return;
    }


    bool result = crypto->EncryptFileWithRSA(archivePath.toStdString(), publicKeyFile.toStdString());
    if (result != FAILURE) {
        QMessageBox::information(this, tr("Успех"), tr("Файл успешно зашифрован."));
    } else {
        QMessageBox::warning(this, tr("Ошибка"), tr("Шифрование не удалось."));
    }

}



