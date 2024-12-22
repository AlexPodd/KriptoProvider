/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.4.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QPushButton *CreateCont;
    QPushButton *OpenCont;
    QPushButton *CheckSert;
    QPushButton *DecryptRSA;
    QPushButton *HashButton;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(258, 254);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        CreateCont = new QPushButton(centralwidget);
        CreateCont->setObjectName("CreateCont");
        CreateCont->setGeometry(QRect(10, 20, 231, 25));
        OpenCont = new QPushButton(centralwidget);
        OpenCont->setObjectName("OpenCont");
        OpenCont->setGeometry(QRect(10, 60, 231, 25));
        CheckSert = new QPushButton(centralwidget);
        CheckSert->setObjectName("CheckSert");
        CheckSert->setGeometry(QRect(10, 100, 231, 25));
        DecryptRSA = new QPushButton(centralwidget);
        DecryptRSA->setObjectName("DecryptRSA");
        DecryptRSA->setGeometry(QRect(10, 140, 231, 25));
        HashButton = new QPushButton(centralwidget);
        HashButton->setObjectName("HashButton");
        HashButton->setGeometry(QRect(10, 180, 231, 26));
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 258, 23));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        CreateCont->setText(QCoreApplication::translate("MainWindow", "\320\241\320\276\320\267\320\264\320\260\321\202\321\214 \320\272\320\276\320\275\321\202\320\265\320\271\320\275\320\265\321\200", nullptr));
        OpenCont->setText(QCoreApplication::translate("MainWindow", "\320\236\321\202\320\272\321\200\321\213\321\202\321\214 \320\272\320\276\320\275\321\202\320\265\320\271\320\275\320\265\321\200", nullptr));
        CheckSert->setText(QCoreApplication::translate("MainWindow", "\320\237\321\200\320\276\320\262\320\265\321\200\320\270\321\202\321\214 \320\277\320\276\320\264\320\277\320\270\321\201\321\214", nullptr));
        DecryptRSA->setText(QCoreApplication::translate("MainWindow", "\320\240\320\260\321\201\321\210\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214 RSA ", nullptr));
        HashButton->setText(QCoreApplication::translate("MainWindow", "\320\240\320\260\321\201\321\201\321\207\320\270\321\202\320\260\321\202\321\214 hash", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
