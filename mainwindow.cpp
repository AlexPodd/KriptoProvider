#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    // Создаем объект crypto
       crypto = new Crypto();

       // Создаем объект entropyWindow с передачей объекта crypto
       entropyWindow = new Entropy(this, crypto, PROJECT_DIRECTORY);
        actionWithContainerWindow = new ActionWithContainer(this, crypto, PROJECT_DIRECTORY);
    ui->setupUi(this);
    connect(entropyWindow, &Entropy::passwordGenerated, this, &MainWindow::onPasswordGenerated);
       connect(entropyWindow, &Entropy::errorOccurred, this, &MainWindow::onErrorOccurred);

}

MainWindow::~MainWindow()
{
    delete ui;
    delete entropyWindow;
    delete actionWithContainerWindow;
}



void MainWindow::on_CreateCont_clicked()
{
            QString dir = QFileDialog::getExistingDirectory(this, "Выберите директорию", QString(),
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);


        if (dir.isEmpty()) {
            QMessageBox::warning(this, "Ошибка", "Вы не выбрали директорию!");
            return;
        }

        bool ok;
           QString containerName = QInputDialog::getText(this, "Имя контейнера", "Введите имя для контейнера:",
                                                         QLineEdit::Normal, "", &ok);

           // Проверяем, было ли введено имя
           if (!ok || containerName.isEmpty()) {
               QMessageBox::warning(this, "Ошибка", "Вы не ввели имя контейнера!");
               return;
           }

           // Устанавливаем директорию и имя контейнера в объект Entropy
           entropyWindow->dirrectory = dir;
           entropyWindow->containerName = containerName;

           // Открываем окно Entropy
           entropyWindow->setModal(true);
           entropyWindow->show();
}

void MainWindow::onPasswordGenerated(QString* password)
{

    QMessageBox msgBox;
       msgBox.setWindowTitle("Generated Password");

       msgBox.setText("Your generated password is: " + *password);

       QPushButton *copyButton = msgBox.addButton("Copy", QMessageBox::ActionRole);
       msgBox.addButton(QMessageBox::Close);

       msgBox.exec();

       if (msgBox.clickedButton() == copyButton) {
           QClipboard *clipboard = QApplication::clipboard();
           clipboard->setText(*password);
       }


       delete password;
       password = nullptr;

        entropyWindow->dirrectory.clear();
        entropyWindow->containerName.clear();
       entropyWindow->close();
   }

void MainWindow::onErrorOccurred(const QString &errorMessage) {
    QMessageBox::warning(this, "Ошибка", errorMessage);
    entropyWindow->dirrectory.clear();
    entropyWindow->containerName.clear();
   entropyWindow->close();

}

void MainWindow::on_OpenCont_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Выберите файл", QString(), "");

      // Проверяем, был ли выбран файл
      if (filePath.isEmpty()) {
          QMessageBox::warning(this, "Ошибка", "Вы не выбрали файл!");
          return;
      }

      // Извлекаем директорию и имя файла
      QFileInfo fileInfo(filePath);
      QString dir = fileInfo.absolutePath();      // Получаем путь до файла
      QString containerName = fileInfo.fileName(); // Получаем имя файла

      // Устанавливаем директорию и имя контейнера в объект Entropy
      actionWithContainerWindow->dirrectory = dir;
      actionWithContainerWindow->containerName = containerName;

      // Открываем окно Entropy
      actionWithContainerWindow->setModal(true);
      actionWithContainerWindow->show();


}


void MainWindow::on_CheckSert_clicked()
{
    QString filePathSert = QFileDialog::getOpenFileName(this, "Выберите сертификат", QString(), "");

    // Проверяем, был ли выбран файл
    if (filePathSert.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не выбрали файл сертификата!");
        return;
    }

    QString filePathFile = QFileDialog::getOpenFileName(this, "Выберите файл для проверки", QString(), "");

    // Проверяем, был ли выбран файл
    if (filePathFile.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не выбрали файл для проверки!");
        return;
    }

    QString filePathSign = QFileDialog::getOpenFileName(this, "Выберите цифровую подпись", QString(), "");

    // Проверяем, был ли выбран файл
    if (filePathSign.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Вы не выбрали файл цифровой подписи!");
        return;
    }

    // Проверка подписи
    bool result = crypto->verifySignature(filePathSert.toStdString(), filePathSign.toStdString(), filePathFile.toStdString());

    if (result) {
        QMessageBox::information(this, "Успех", "Файл успешно прошёл проверку подписи!");
    } else {
        QMessageBox::critical(this, "Ошибка", "Проверка подписи не пройдена! Возможно, подпись или файл изменены.");
    }
}


void MainWindow::on_HashButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Select a file", "", "All Files (*)");
    if (filePath.isEmpty()) {
        return;  // Если файл не выбран, выходим
    }

    // 2. Предоставление выбора типа хеша
    bool ok;
    QStringList hashTypes = {"SHA-256", "SHA-512", "MD5"};
    QString hashType = QInputDialog::getItem(this, "Select Hash Type", "Choose a hash type:", hashTypes, 0, false, &ok);
    if (!ok || hashType.isEmpty()) {
        return;  // Если тип хеша не выбран, выходим
    }

    // 3. Вычисление хеша с помощью функции hashFile

    std::string fileHash = crypto->hashFile(filePath.toStdString(), hashType.toStdString());

    if (fileHash.empty()) {
        QMessageBox::critical(this, "Error", "Failed to calculate hash!");
        return;
    }

    // 4. Отображение результата хеширования
    QMessageBox::information(this, "Hash Result", "Hash of the file:\n\n" + QString::fromStdString(fileHash));

    // 5. Копирование хеша в буфер обмена
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText(QString::fromStdString(fileHash));

    // 6. Информирование пользователя о копировании в буфер обмена
    QMessageBox::information(this, "Hash Copied", "The hash has been copied to the clipboard.");
}


void MainWindow::on_DecryptRSA_clicked()
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
        QMessageBox::information(this, tr("Успех"), tr("Файл успешно расшифрован."));
    } else {
        QMessageBox::warning(this, tr("Ошибка"), tr("Шифрование не удалось."));
    }
}

