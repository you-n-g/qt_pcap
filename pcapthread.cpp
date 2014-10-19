#include "pcapthread.h"

PcapThread::PcapThread(QObject *parent) :
    QThread(parent)
{
}

void PcapThread::run() Q_DECL_OVERRIDE {
        QString result="test";
        /* ... here is the expensive or blocking operation ... */
        emit resultReady(result);
}
