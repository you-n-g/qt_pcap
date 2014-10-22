#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    pcapThread = NULL;
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::startPcapThread()
{
    qDebug() << "startPcapThread()";
    if (pcapThread == NULL) {
        pcapThread = new PcapThread(this);
        connect(pcapThread, &PcapThread::resultReady, this, &MainWindow::handleResults);
        connect(pcapThread, &PcapThread::finished, pcapThread, &QObject::deleteLater);
        pcapThread->start();
    }
    ui->menuOperation->actions().at(0)->setEnabled(false);
    ui->menuOperation->actions().at(1)->setEnabled(true);
}

void MainWindow::stopPcapThread()
{
    if(pcapThread != NULL) {
        pcapThread->stopWork();
        pcapThread = NULL;
    }
    ui->menuOperation->actions().at(1)->setEnabled(false);
    ui->menuOperation->actions().at(0)->setEnabled(true);
}


void MainWindow::handleResults(const QByteArray &qba) {
    qDebug() << "qba length" << qba.length();
    if (qba.length() > 0) {
        PackParser * ppsr = new PackParser(qba);
        PcapQTreeWidgetItem *item = new PcapQTreeWidgetItem(ui->allWidgetTreeWidget, ppsr);
        item->setText(0, EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_shost()));
        item->setText(1, EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_dhost()));
        item->setText(2, ppsr->get_highest_protocol());
        item->setText(3, QString::number(ppsr->qba.length()));
        ui->allWidgetTreeWidget->addTopLevelItem(item);
        ui->allWidgetTreeWidget->scrollToBottom();
    }
}

void MainWindow::on_actionStopPcap_triggered()
{
    stopPcapThread();
}

void MainWindow::on_actionBeginPcap_triggered()
{
    startPcapThread();
}

void MainWindow::on_allWidgetTreeWidget_itemClicked(QTreeWidgetItem *item, int column)
{
    PcapQTreeWidgetItem * pitem = (PcapQTreeWidgetItem *) item;
    qDebug() << pitem->ppsr->get_highest_protocol();
    ((HexDecode *) (ui->hexDecodeWidget))->display_pack_data(pitem->ppsr);
    display_pack_trees(pitem->ppsr);
}

void MainWindow::display_pack_trees(PackParser *ppsr)
{
    ui->singlePackageTreeWidget->clear();
    if (ppsr->ehp != NULL)
        build_ether_tree(ppsr);
    if (ppsr->ahp != NULL)
        build_arp_tree(ppsr);
    if (ppsr->ihp != NULL)
        build_ip_tree(ppsr);
}

QTreeWidgetItem* MainWindow::fast_add_child(QTreeWidgetItem *item, const QString &qstr)
{
    QTreeWidgetItem * child = new QTreeWidgetItem();
    child->setText(0, qstr);
    item->addChild(child);
    return child;
}

void MainWindow::build_ether_tree(PackParser *ppsr)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, QString("Ethernet II, Src: %0 , Dst: %1").arg(
                                         EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_shost())).arg(
                                         EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_dhost())));

    fast_add_child(item, QString("Destination: %0").arg(EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_dhost())));
    fast_add_child(item, QString("Source: %0").arg(EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_shost())));
    fast_add_child(item, QString("Type: %0 (%1)").arg(
           ppsr->ehp->get_string_type()).arg(QString().sprintf("0x%04X", ppsr->ehp->get_type())));
    // TODO CRC check
}

void MainWindow::build_arp_tree(PackParser *ppsr)
{
    ARPHeaderParser * ahp =  ppsr->ahp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, QString("Address Resolution Protocol (%0)").arg(ahp->get_qstring_oper()));
    fast_add_child(item, QString("Hardware type: %1 (%2)").arg(ahp->get_qstring_htype()).arg(ahp->get_uint_htype()));
    fast_add_child(item, QString("Protocol type: %1 (0x%2)").arg(
       ahp->get_qstring_ptype()).arg(QString().sprintf("%04X", ahp->get_uint_ptype())));
    fast_add_child(item, QString("Hardware size: %0").arg(ahp->get_hsize()));
    fast_add_child(item, QString("Protocol size: %0").arg(ahp->get_psize()));
    fast_add_child(item, QString("Opcode: %0 (%1)").arg(ahp->get_qstring_oper()).arg(ahp->get_uint_oper()));
    fast_add_child(item, QString("Sender MAC address: %0").arg(ahp->get_sha()));
    fast_add_child(item, QString("Sender IP address: %0").arg(ahp->get_spa()));
    fast_add_child(item, QString("Sender MAC address: %0").arg(ahp->get_tha()));
    fast_add_child(item, QString("Sender IP address: %0").arg(ahp->get_tpa()));
}

void MainWindow::build_ip_tree(PackParser *ppsr)
{
    IpHeaderParser * ihp =  ppsr->ihp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget), *flag_item;
    item->setText(0, QString("Internet Protocol Version 4, Src: %1 , Dst: %2")
      .arg(ihp->get_qstring_saddr()).arg(ihp->get_qstring_daddr()));
    fast_add_child(item, QString("Version: 4"));
    fast_add_child(item, QString("Header Length: %1 bytes").arg(ihp->get_ip_byte_len()));
    fast_add_child(item, QString("Total Length: %1").arg(ihp->get_total_length()));
    fast_add_child(item, QString("Identification: 0x%1 (%2)").arg(QString().sprintf("%04X",ihp->get_id())).arg(ihp->get_id()));
    flag_item = fast_add_child(item, QString("Flags:"));
    fast_add_child(flag_item, QString("X... .... = Reserved bit: %1Set").arg(ihp->is_rf_set()?"":"Not "));
    fast_add_child(flag_item, QString(".X.. .... = Don't fragment: %1Set").arg(ihp->is_df_set()?"":"Not "));
    fast_add_child(flag_item, QString("..X. .... = More fragments: %1Set").arg(ihp->is_mf_set()?"":"Not "));
    fast_add_child(item, QString("Fragment offset: %1").arg(ihp->get_offset()));
    fast_add_child(item, QString("Time to live: %1").arg(ihp->get_ttl()));
    fast_add_child(item, QString("Protocol: %1 (%2)").arg(ihp->get_qstring_protocol()).arg(ihp->get_uint_protocol()));
    fast_add_child(item, QString("Header checksum: 0x%1 ").arg(QString().sprintf("%04X", ihp->get_checksum())));
    fast_add_child(item, QString("Source: %1").arg(ihp->get_qstring_saddr()));
    fast_add_child(item, QString("Destination: %1").arg(ihp->get_qstring_daddr()));
//            TODO: flags
//
}
