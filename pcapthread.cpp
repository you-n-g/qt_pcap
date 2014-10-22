#include "pcapthread.h"

PcapThread::PcapThread(QObject *parent) :
    QThread(parent)
{
    setArgs("", "");
}

void PcapThread::initDevice() {
    // Open the default device
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    QByteArray dev_data, filter_data;

    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(2);
    }
    qDebug("Device: %s\n", dev);
    */

    // Open the device to sniff
    dev_data = selected_device.toLatin1();
    dev = dev_data.data();
    qDebug() << "We begin capture" << dev;
    handle = pcap_open_live(dev, BUFSIZ, 1, 500, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    // Check if the device support Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        exit(2);
    }

    // get net and mask
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // set the sniffer filter expression
    struct bpf_program fp;		// The compiled filter expression
    filter_data = filter_rule.toLatin1();
    char * filter_exp = filter_data.data();
    qDebug()<< "The filter is" << filter_exp;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_compile(handle, &fp, "", 0, net);
        qDebug("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        emit popMsg(QString("The filter is invalid!!!"));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        qDebug("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
}


void PcapThread::run() Q_DECL_OVERRIDE {
        initDevice();
        struct pcap_pkthdr header;  /* The header that pcap gives us */
        const u_char *packet;		/* The actual packet */
        workOn = true;
        while(true) {
            if (!workOn) break;
            packet = pcap_next(handle, &header);
            qDebug("Jacked a packet with length of [%d]\n", header.len);
            QByteArray qba((char *)packet, (int)header.len);
            emit resultReady(qba);
        }
        qDebug() << "finish run!!!";
}


void PcapThread::stopWork() {
    workOn = false;
}

void PcapThread::setArgs(QString device, QString filter)
{
    this->selected_device = device;
    this->filter_rule = filter;
}
