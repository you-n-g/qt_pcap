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

class PcapThread : public QThread
{
    Q_OBJECT
    void run() Q_DECL_OVERRIDE;
public:
    explicit PcapThread(QObject *parent = 0);

signals:
    void resultReady(const QString &s);
public slots:
};

#endif // PCAPTHREAD_H
