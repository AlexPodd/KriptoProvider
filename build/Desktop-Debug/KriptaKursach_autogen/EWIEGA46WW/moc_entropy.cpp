/****************************************************************************
** Meta object code from reading C++ file 'entropy.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../entropy.h"
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'entropy.h' doesn't include <QObject>."
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
struct qt_meta_stringdata_Entropy_t {
    uint offsetsAndSizes[28];
    char stringdata0[8];
    char stringdata1[18];
    char stringdata2[1];
    char stringdata3[10];
    char stringdata4[9];
    char stringdata5[14];
    char stringdata6[13];
    char stringdata7[35];
    char stringdata8[6];
    char stringdata9[15];
    char stringdata10[13];
    char stringdata11[6];
    char stringdata12[17];
    char stringdata13[9];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_Entropy_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_Entropy_t qt_meta_stringdata_Entropy = {
    {
        QT_MOC_LITERAL(0, 7),  // "Entropy"
        QT_MOC_LITERAL(8, 17),  // "passwordGenerated"
        QT_MOC_LITERAL(26, 0),  // ""
        QT_MOC_LITERAL(27, 9),  // "QString*&"
        QT_MOC_LITERAL(37, 8),  // "password"
        QT_MOC_LITERAL(46, 13),  // "errorOccurred"
        QT_MOC_LITERAL(60, 12),  // "errorMessage"
        QT_MOC_LITERAL(73, 34),  // "on_EntropyProgressBar_valueCh..."
        QT_MOC_LITERAL(108, 5),  // "value"
        QT_MOC_LITERAL(114, 14),  // "mouseMoveEvent"
        QT_MOC_LITERAL(129, 12),  // "QMouseEvent*"
        QT_MOC_LITERAL(142, 5),  // "event"
        QT_MOC_LITERAL(148, 16),  // "generatePassword"
        QT_MOC_LITERAL(165, 8)   // "QString*"
    },
    "Entropy",
    "passwordGenerated",
    "",
    "QString*&",
    "password",
    "errorOccurred",
    "errorMessage",
    "on_EntropyProgressBar_valueChanged",
    "value",
    "mouseMoveEvent",
    "QMouseEvent*",
    "event",
    "generatePassword",
    "QString*"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_Entropy[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   44,    2, 0x06,    1 /* Public */,
       5,    1,   47,    2, 0x06,    3 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       7,    1,   50,    2, 0x08,    5 /* Private */,
       9,    1,   53,    2, 0x08,    7 /* Private */,
      12,    0,   56,    2, 0x08,    9 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, QMetaType::QString,    6,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    8,
    QMetaType::Void, 0x80000000 | 10,   11,
    0x80000000 | 13,

       0        // eod
};

Q_CONSTINIT const QMetaObject Entropy::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_Entropy.offsetsAndSizes,
    qt_meta_data_Entropy,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_Entropy_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<Entropy, std::true_type>,
        // method 'passwordGenerated'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString * &, std::false_type>,
        // method 'errorOccurred'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'on_EntropyProgressBar_valueChanged'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'mouseMoveEvent'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QMouseEvent *, std::false_type>,
        // method 'generatePassword'
        QtPrivate::TypeAndForceComplete<QString *, std::false_type>
    >,
    nullptr
} };

void Entropy::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Entropy *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->passwordGenerated((*reinterpret_cast< std::add_pointer_t<QString*&>>(_a[1]))); break;
        case 1: _t->errorOccurred((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->on_EntropyProgressBar_valueChanged((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 3: _t->mouseMoveEvent((*reinterpret_cast< std::add_pointer_t<QMouseEvent*>>(_a[1]))); break;
        case 4: { QString* _r = _t->generatePassword();
            if (_a[0]) *reinterpret_cast< QString**>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Entropy::*)(QString * & );
            if (_t _q_method = &Entropy::passwordGenerated; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Entropy::*)(const QString & );
            if (_t _q_method = &Entropy::errorOccurred; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 1;
                return;
            }
        }
    }
}

const QMetaObject *Entropy::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Entropy::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Entropy.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int Entropy::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 5;
    }
    return _id;
}

// SIGNAL 0
void Entropy::passwordGenerated(QString * & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Entropy::errorOccurred(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
