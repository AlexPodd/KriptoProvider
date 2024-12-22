/****************************************************************************
** Meta object code from reading C++ file 'mainwindow.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../mainwindow.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'mainwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_MainWindow_t {
    uint offsetsAndSizes[24];
    char stringdata0[11];
    char stringdata1[20];
    char stringdata2[1];
    char stringdata3[9];
    char stringdata4[9];
    char stringdata5[22];
    char stringdata6[16];
    char stringdata7[13];
    char stringdata8[20];
    char stringdata9[21];
    char stringdata10[22];
    char stringdata11[22];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_MainWindow_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_MainWindow_t qt_meta_stringdata_MainWindow = {
    {
        QT_MOC_LITERAL(0, 10),  // "MainWindow"
        QT_MOC_LITERAL(11, 19),  // "onPasswordGenerated"
        QT_MOC_LITERAL(31, 0),  // ""
        QT_MOC_LITERAL(32, 8),  // "QString*"
        QT_MOC_LITERAL(41, 8),  // "password"
        QT_MOC_LITERAL(50, 21),  // "on_CreateCont_clicked"
        QT_MOC_LITERAL(72, 15),  // "onErrorOccurred"
        QT_MOC_LITERAL(88, 12),  // "errorMessage"
        QT_MOC_LITERAL(101, 19),  // "on_OpenCont_clicked"
        QT_MOC_LITERAL(121, 20),  // "on_CheckSert_clicked"
        QT_MOC_LITERAL(142, 21),  // "on_HashButton_clicked"
        QT_MOC_LITERAL(164, 21)   // "on_DecryptRSA_clicked"
    },
    "MainWindow",
    "onPasswordGenerated",
    "",
    "QString*",
    "password",
    "on_CreateCont_clicked",
    "onErrorOccurred",
    "errorMessage",
    "on_OpenCont_clicked",
    "on_CheckSert_clicked",
    "on_HashButton_clicked",
    "on_DecryptRSA_clicked"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_MainWindow[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   56,    2, 0x08,    1 /* Private */,
       5,    0,   59,    2, 0x08,    3 /* Private */,
       6,    1,   60,    2, 0x08,    4 /* Private */,
       8,    0,   63,    2, 0x08,    6 /* Private */,
       9,    0,   64,    2, 0x08,    7 /* Private */,
      10,    0,   65,    2, 0x08,    8 /* Private */,
      11,    0,   66,    2, 0x08,    9 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_MainWindow.offsetsAndSizes,
    qt_meta_data_MainWindow,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_MainWindow_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MainWindow, std::true_type>,
        // method 'onPasswordGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString *, std::false_type>,
        // method 'on_CreateCont_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onErrorOccurred'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'on_OpenCont_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_CheckSert_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_HashButton_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_DecryptRSA_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MainWindow *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onPasswordGenerated((*reinterpret_cast< std::add_pointer_t<QString*>>(_a[1]))); break;
        case 1: _t->on_CreateCont_clicked(); break;
        case 2: _t->onErrorOccurred((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 3: _t->on_OpenCont_clicked(); break;
        case 4: _t->on_CheckSert_clicked(); break;
        case 5: _t->on_HashButton_clicked(); break;
        case 6: _t->on_DecryptRSA_clicked(); break;
        default: ;
        }
    }
}

const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_MainWindow.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 7;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
