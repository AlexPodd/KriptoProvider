/********************************************************************************
** Form generated from reading UI file 'entropy.ui'
**
** Created by: Qt User Interface Compiler version 6.4.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ENTROPY_H
#define UI_ENTROPY_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>

QT_BEGIN_NAMESPACE

class Ui_Entropy
{
public:
    QProgressBar *EntropyProgressBar;
    QLabel *label;

    void setupUi(QDialog *Entropy)
    {
        if (Entropy->objectName().isEmpty())
            Entropy->setObjectName("Entropy");
        Entropy->resize(400, 300);
        EntropyProgressBar = new QProgressBar(Entropy);
        EntropyProgressBar->setObjectName("EntropyProgressBar");
        EntropyProgressBar->setGeometry(QRect(10, 120, 371, 161));
        EntropyProgressBar->setValue(0);
        label = new QLabel(Entropy);
        label->setObjectName("label");
        label->setGeometry(QRect(20, 20, 361, 81));

        retranslateUi(Entropy);

        QMetaObject::connectSlotsByName(Entropy);
    } // setupUi

    void retranslateUi(QDialog *Entropy)
    {
        Entropy->setWindowTitle(QCoreApplication::translate("Entropy", "Dialog", nullptr));
        label->setText(QCoreApplication::translate("Entropy", "      \320\224\320\262\320\270\320\263\320\260\320\271\321\202\320\265 \320\274\321\213\321\210\320\272\320\276\320\271 \320\264\320\273\321\217 \320\263\320\265\320\275\320\265\321\200\320\260\321\206\320\270\320\270 \321\215\320\275\321\202\321\200\320\276\320\277\320\270\320\270", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Entropy: public Ui_Entropy {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ENTROPY_H
