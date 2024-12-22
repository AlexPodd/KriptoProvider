#ifndef ENTROPY_H
#define ENTROPY_H

#include <QDialog>
#include <QMouseEvent>
#include <QDebug>
#include <QCryptographicHash>
#include <QTime>
#include "Crypto.h"
#include <iostream>
#include <QRandomGenerator>
#include <libtar.h>
#include <fcntl.h>
#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>
#include <fstream>
#include "base64.h"
#include <QFile>
namespace Ui {
class Entropy;
}

class Entropy : public QDialog
{
    Q_OBJECT

public:

    QString dirrectory;
    QString containerName;
    explicit Entropy(QWidget *parent = nullptr, Crypto *crypto = nullptr, QString ivPath = nullptr);
    ~Entropy();
signals:
    void passwordGenerated(QString* &password);
    void errorOccurred(const QString &errorMessage);
private slots:
    void on_EntropyProgressBar_valueChanged(int value);
    void mouseMoveEvent(QMouseEvent *event) override;
    QString* generatePassword();
private:
    bool decryptCont(QString* password);
    Ui::Entropy *ui;
    QString entropyBuffer;
    Crypto *crypto;
    QString ivPath;
    bool createCont(QString* password);
    bool AddFileToCont(QString* password, unsigned char *data);
};

#endif // ENTROPY_H
