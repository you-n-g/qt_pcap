#ifndef PCAPQTOOLS_H
#define PCAPQTOOLS_H

#include <QTreeWidgetItem>
#include <QStringList>
#include <pcap.h>
#include "frame_parser.h"

class PcapQTreeWidgetItem : public QTreeWidgetItem
{
public:
    PcapQTreeWidgetItem(QTreeWidget * view, PackParser * ppsr);
    PackParser * ppsr;
private:
};

QStringList get_devices();

#endif // PCAPQTOOLS_H
