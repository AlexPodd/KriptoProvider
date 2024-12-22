#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "entropy.h"
#include "actionwithcontainer.h"
#include <QMessageBox>
#include <QClipboard>
#include <QFileDialog>
#include "Crypto.h"
#include <QInputDialog>
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE




class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QString PROJECT_DIRECTORY = "/home/alex/kripta/";
private slots:
    void onPasswordGenerated(QString* password);
    void on_CreateCont_clicked();
    void onErrorOccurred(const QString &errorMessage);
    void on_OpenCont_clicked();

    void on_CheckSert_clicked();

    void on_HashButton_clicked();

    void on_DecryptRSA_clicked();

private:
    Ui::MainWindow *ui;
    Entropy *entropyWindow;
    ActionWithContainer *actionWithContainerWindow;
    Crypto *crypto;
   // secondokno WidgetOkno;

};
#endif // MAINWINDOW_H
