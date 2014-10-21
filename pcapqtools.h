#ifndef PCAPQTOOLS_H
#define PCAPQTOOLS_H

#include <QTreeWidgetItem>
#include "frame_parser.h"

class PcapQTreeWidgetItem : public QTreeWidgetItem
{
public:
    PcapQTreeWidgetItem(QTreeWidget * view, PackParser * ppsr);
    PackParser * ppsr;
private:
};

#endif // PCAPQTOOLS_H
