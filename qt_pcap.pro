#-------------------------------------------------
#
# Project created by QtCreator 2014-10-16T14:01:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qt_pcap
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    frame_parser.cpp \
    pcapthread.cpp \
    pcapqtools.cpp \
    hexdecode.cpp \
    setdevicedialog.cpp

HEADERS  += mainwindow.h \
    frame_parser.h \
    pcapthread.h \
    pcapqtools.h \
    hexdecode.h \
    setdevicedialog.h

FORMS    += mainwindow.ui \
    hexdecode.ui \
    setdevicedialog.ui

unix|win32: LIBS += -lpcap
