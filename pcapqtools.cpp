#include "pcapqtools.h"

PcapQTreeWidgetItem::PcapQTreeWidgetItem(QTreeWidget *view, PackParser * ppsr):
    QTreeWidgetItem(view)
{
    this->ppsr = ppsr;
}


QStringList get_devices()
{
    QStringList qsl;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    //  use this man pcap_findalldevs
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    // remove the pseudo device 'any' 'nflog' and 'nfqueue'
    QStringList pseudo_devs;
    pseudo_devs << "any" << "nflog" << "nfqueue";
    for(pcap_if_t *d = alldevs; d != NULL; d= d->next)
        if(!pseudo_devs.contains(d->name))
            qsl.append(d->name);

    pcap_freealldevs(alldevs);
    return qsl;
}
