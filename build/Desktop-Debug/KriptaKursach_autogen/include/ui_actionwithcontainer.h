/********************************************************************************
** Form generated from reading UI file 'actionwithcontainer.ui'
**
** Created by: Qt User Interface Compiler version 6.4.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ACTIONWITHCONTAINER_H
#define UI_ACTIONWITHCONTAINER_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_ActionWithContainer
{
public:
    QPushButton *CreateDS;
    QPushButton *UseDS;
    QLabel *label;
    QPushButton *EncryptFileAES;
    QPushButton *EncryptFileRSA;
    QPushButton *AddAESKey;
    QPushButton *AddRSAKey;
    QLabel *label_2;
    QLabel *label_3;
    QLabel *label_4;
    QPushButton *DecrytFileAES;
    QPushButton *DecryptFileRSA;
    QLabel *label_6;
    QPushButton *EncryptDirAES;
    QPushButton *EncryptDirRSA;

    void setupUi(QDialog *ActionWithContainer)
    {
        if (ActionWithContainer->objectName().isEmpty())
            ActionWithContainer->setObjectName("ActionWithContainer");
        ActionWithContainer->resize(592, 446);
        CreateDS = new QPushButton(ActionWithContainer);
        CreateDS->setObjectName("CreateDS");
        CreateDS->setGeometry(QRect(10, 60, 261, 41));
        UseDS = new QPushButton(ActionWithContainer);
        UseDS->setObjectName("UseDS");
        UseDS->setGeometry(QRect(310, 60, 261, 41));
        label = new QLabel(ActionWithContainer);
        label->setObjectName("label");
        label->setGeometry(QRect(160, 10, 281, 31));
        EncryptFileAES = new QPushButton(ActionWithContainer);
        EncryptFileAES->setObjectName("EncryptFileAES");
        EncryptFileAES->setGeometry(QRect(10, 220, 261, 41));
        EncryptFileRSA = new QPushButton(ActionWithContainer);
        EncryptFileRSA->setObjectName("EncryptFileRSA");
        EncryptFileRSA->setGeometry(QRect(310, 220, 261, 41));
        AddAESKey = new QPushButton(ActionWithContainer);
        AddAESKey->setObjectName("AddAESKey");
        AddAESKey->setGeometry(QRect(10, 140, 261, 41));
        AddRSAKey = new QPushButton(ActionWithContainer);
        AddRSAKey->setObjectName("AddRSAKey");
        AddRSAKey->setGeometry(QRect(310, 140, 261, 41));
        label_2 = new QLabel(ActionWithContainer);
        label_2->setObjectName("label_2");
        label_2->setGeometry(QRect(140, 190, 331, 20));
        label_3 = new QLabel(ActionWithContainer);
        label_3->setObjectName("label_3");
        label_3->setGeometry(QRect(30, 110, 461, 20));
        label_4 = new QLabel(ActionWithContainer);
        label_4->setObjectName("label_4");
        label_4->setGeometry(QRect(120, 270, 331, 20));
        DecrytFileAES = new QPushButton(ActionWithContainer);
        DecrytFileAES->setObjectName("DecrytFileAES");
        DecrytFileAES->setGeometry(QRect(10, 300, 261, 41));
        DecryptFileRSA = new QPushButton(ActionWithContainer);
        DecryptFileRSA->setObjectName("DecryptFileRSA");
        DecryptFileRSA->setGeometry(QRect(310, 300, 261, 41));
        label_6 = new QLabel(ActionWithContainer);
        label_6->setObjectName("label_6");
        label_6->setGeometry(QRect(140, 350, 331, 20));
        EncryptDirAES = new QPushButton(ActionWithContainer);
        EncryptDirAES->setObjectName("EncryptDirAES");
        EncryptDirAES->setGeometry(QRect(10, 380, 261, 41));
        EncryptDirRSA = new QPushButton(ActionWithContainer);
        EncryptDirRSA->setObjectName("EncryptDirRSA");
        EncryptDirRSA->setGeometry(QRect(310, 380, 261, 41));

        retranslateUi(ActionWithContainer);

        QMetaObject::connectSlotsByName(ActionWithContainer);
    } // setupUi

    void retranslateUi(QDialog *ActionWithContainer)
    {
        ActionWithContainer->setWindowTitle(QCoreApplication::translate("ActionWithContainer", "Dialog", nullptr));
        CreateDS->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\276\320\267\320\264\320\260\321\202\321\214 \321\206\320\270\321\204\321\200\320\276\320\262\321\203\321\216 \320\277\320\276\320\264\320\277\320\270\321\201\321\214", nullptr));
        UseDS->setText(QCoreApplication::translate("ActionWithContainer", "\320\237\320\276\320\264\320\277\320\270\321\201\320\260\321\202\321\214 \321\204\320\260\320\271\320\273", nullptr));
        label->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\276\320\262\320\265\321\200\321\210\320\270\321\202\321\214 \320\264\320\265\320\271\321\201\321\202\320\262\320\270\320\265 \321\201 \320\272\320\276\320\275\321\202\320\265\320\271\320\275\320\265\321\200\320\276\320\274", nullptr));
        EncryptFileAES->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\270\320\274\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(AES)", nullptr));
        EncryptFileRSA->setText(QCoreApplication::translate("ActionWithContainer", "\320\220\321\201\321\201\320\270\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(RSA)", nullptr));
        AddAESKey->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\270\320\274\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(AES)", nullptr));
        AddRSAKey->setText(QCoreApplication::translate("ActionWithContainer", "\320\220\321\201\321\201\320\270\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(RSA)", nullptr));
        label_2->setText(QCoreApplication::translate("ActionWithContainer", "                     \320\227\320\260\321\210\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214 \321\204\320\260\320\271\320\273", nullptr));
        label_3->setText(QCoreApplication::translate("ActionWithContainer", "                      \320\241\320\263\320\265\320\275\320\265\321\200\320\270\321\200\320\276\320\262\320\260\321\202\321\214 \320\272\320\273\321\216\321\207 \320\270 \320\264\320\276\320\261\320\260\320\262\320\270\321\202\321\214 \320\265\320\263\320\276 \320\262 \320\272\320\276\320\275\321\202\320\265\320\271\320\275\320\265\321\200", nullptr));
        label_4->setText(QCoreApplication::translate("ActionWithContainer", "                          \320\240\320\260\321\201\321\210\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214 \321\204\320\260\320\271\320\273", nullptr));
        DecrytFileAES->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\270\320\274\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(AES)", nullptr));
        DecryptFileRSA->setText(QCoreApplication::translate("ActionWithContainer", "\320\220\321\201\321\201\320\270\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(RSA)", nullptr));
        label_6->setText(QCoreApplication::translate("ActionWithContainer", "                     \320\227\320\260\321\210\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214 \320\264\320\270\321\200\320\265\320\272\321\202\320\276\321\200\320\270\321\216", nullptr));
        EncryptDirAES->setText(QCoreApplication::translate("ActionWithContainer", "\320\241\320\270\320\274\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(AES)", nullptr));
        EncryptDirRSA->setText(QCoreApplication::translate("ActionWithContainer", "\320\220\321\201\321\201\320\270\320\274\320\265\321\202\321\200\320\270\321\207\320\275\320\276\320\265 \321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265(RSA)", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ActionWithContainer: public Ui_ActionWithContainer {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ACTIONWITHCONTAINER_H
