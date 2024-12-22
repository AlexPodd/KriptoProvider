#ifndef ACTIONWITHCONTAINER_H
#define ACTIONWITHCONTAINER_H

#include <QDialog>
#include "Crypto.h"
#include <QInputDialog>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDebug>
#include "base64.h"
#include <QFileDialog>
namespace Ui {
class ActionWithContainer;
}

class ActionWithContainer : public QDialog
{
    Q_OBJECT

public:
    QString dirrectory;
    QString containerName;
    explicit ActionWithContainer(QWidget *parent = nullptr, Crypto *crypto = nullptr, QString ivPath = nullptr);
    ~ActionWithContainer();

private slots:
    void on_CreateDS_clicked();

    void on_UseDS_clicked();

    void on_AddAESKey_clicked();

    void on_AddRSAKey_clicked();

    void on_EncryptFileAES_clicked();

    void on_EncryptFileRSA_clicked();

    void on_DecrytFileAES_clicked();

    void on_DecryptFileRSA_clicked();

    void on_EncryptDirAES_clicked();

    void on_EncryptDirRSA_clicked();



private:
    Ui::ActionWithContainer *ui;
    Crypto *crypto;
    QString entropyBuffer;
    QString ivPath;
};




#endif // ACTIONWITHCONTAINER_H
