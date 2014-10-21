#ifndef PCAPTHREAD_H
#define PCAPTHREAD_H

#include <QThread>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "frame_parser.h"
#include <QDebug>
#include <QtCore>

class PcapThread : public QThread
{
    Q_OBJECT
    void run() Q_DECL_OVERRIDE;
public:
    explicit PcapThread(QObject *parent = 0);
    void stopWork();
signals:
    void resultReady(const QByteArray &data);
public slots:

private:
    void initDevice();
    pcap_t *handle;
    bool workOn;
};

#endif // PCAPTHREAD_H
