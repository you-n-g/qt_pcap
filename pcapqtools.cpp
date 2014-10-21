#include "pcapqtools.h"

PcapQTreeWidgetItem::PcapQTreeWidgetItem(QTreeWidget *view, PackParser * ppsr):
    QTreeWidgetItem(view)
{
    this->ppsr = ppsr;
}
