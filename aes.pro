TARGET = aestest
TEMPLATE = app

DESTDIR = ../bin

SOURCES += main.cpp \
    ead_aes.cpp

HEADERS += \
    ead_aes.h

QT += widgets
