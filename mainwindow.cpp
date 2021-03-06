#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    pcapThread = NULL;
    selected_device = QString("");
    filter_rule = QString("");
    ui->setupUi(this);
    ui->menuOperation->actions().at(0)->setEnabled(false); // start pcap
    ui->menuOperation->actions().at(1)->setEnabled(false); // stop pcap
    ui->menuOperation->actions().at(2)->setEnabled(true); // set device  TODO  why am I wrong
    updateStatusMessage();
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
        pcapThread->setArgs(selected_device, filter_rule);
        connect(pcapThread, &PcapThread::resultReady, this, &MainWindow::handleResults);
        connect(pcapThread, &PcapThread::finished, pcapThread, &QObject::deleteLater);
        connect(pcapThread, &PcapThread::popMsg, this, &MainWindow::popMsg);
        pcapThread->start();
    }
}

void MainWindow::stopPcapThread()
{
    if(pcapThread != NULL) {
        pcapThread->stopWork();
        pcapThread = NULL;
    }
}

void MainWindow::setArgs(QString dev, QString filter_rule){
    selected_device=dev;
    this->filter_rule = filter_rule;
    qDebug() << "Reciving Device is set to" << dev;
    ui->menuOperation->actions().at(0)->setEnabled(selected_device.isEmpty() ? false : true); // start pcap
    ui->menuOperation->actions().at(1)->setEnabled(false); // stop pcap
    ui->menuOperation->actions().at(2)->setEnabled(true); // set device
    updateStatusMessage();
}

void MainWindow::popMsg(QString msg)
{
    QMessageBox::information(this, "Info", msg);
}


void MainWindow::handleResults(const QByteArray &qba) {
    qDebug() << "qba length" << qba.length();
    if (qba.length() > 0) {
        PackParser * ppsr = new PackParser(qba);
        PcapQTreeWidgetItem *item = new PcapQTreeWidgetItem(ui->allPackTreeWidget, ppsr);
        item->setText(0, ppsr->get_source());
        item->setText(1, ppsr->get_destination());
        item->setText(2, ppsr->get_highest_protocol());
        item->setText(3, QString::number(ppsr->qba.length()));
        item->setText(4, ppsr->get_description());
        ui->allPackTreeWidget->addTopLevelItem(item);
        ui->allPackTreeWidget->scrollToBottom();
    }
}

void MainWindow::on_actionStopPcap_triggered()
{
    ui->menuOperation->actions().at(0)->setEnabled(true); // start pcap
    ui->menuOperation->actions().at(1)->setEnabled(false); // stop pcap
    ui->menuOperation->actions().at(2)->setEnabled(true); // set device
    stopPcapThread();
}

void MainWindow::on_actionBeginPcap_triggered()
{
    ui->menuOperation->actions().at(0)->setEnabled(false); // start pcap
    ui->menuOperation->actions().at(1)->setEnabled(true); // stop pcap
    ui->menuOperation->actions().at(2)->setEnabled(false); // set device
    startPcapThread();
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
    if (ppsr->ichp != NULL)
        build_icmp_tree(ppsr);
    if (ppsr->uhp != NULL)
        build_udp_tree(ppsr);
    if (ppsr->thp != NULL)
        build_tcp_tree(ppsr);
}

QTreeWidgetItem* MainWindow::fast_add_child(QTreeWidgetItem *item, const QString &qstr)
{
    QTreeWidgetItem * child = new QTreeWidgetItem();
    child->setText(0, qstr);
    item->addChild(child);
    return child;
}

void MainWindow::updateStatusMessage()
{
    QString msg("");

    if (selected_device.isEmpty())
        msg.append("你还没有选择网卡");
    else
        msg.append(QString("你选择的网卡为:%1").arg(selected_device));
    msg.append(" || ");

    if (filter_rule.isEmpty())
        msg.append("未设置过滤规则");
    else
        msg.append(QString("当前的过滤规则为:%1").arg(filter_rule));

    ui->statusBar->showMessage(msg);
}

QMap<QString, int> MainWindow::do_statistics()
{
    QMap<QString, int> map;
    QString protocol;
    for (int i = 0; i < ui->allPackTreeWidget->topLevelItemCount(); ++i) {
        protocol = ((PcapQTreeWidgetItem *) (ui->allPackTreeWidget->topLevelItem(i)))->ppsr->get_highest_protocol();
        map.insert(protocol, map.value(protocol, 0) + 1);
    }
    qDebug() << map;
    return map;
}

void MainWindow::build_ether_tree(PackParser *ppsr)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, ppsr->ehp->get_description());
    fast_add_child(item, QString("Destination: %0").arg(EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_dhost())));
    fast_add_child(item, QString("Source: %0").arg(EtherHeaderParser::byte_to_mac_addr(ppsr->ehp->get_ether_shost())));
    fast_add_child(item, QString("Type: %0 (%1)").arg(
           ppsr->ehp->get_qstring_type()).arg(QString().sprintf("0x%04X", ppsr->ehp->get_type())));
    // TODO CRC check
}

void MainWindow::build_arp_tree(PackParser *ppsr)
{
    ARPHeaderParser * ahp =  ppsr->ahp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, ahp->get_description());
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
    item->setText(0, ihp->get_description());
    fast_add_child(item, QString("Version: 4"));
    fast_add_child(item, QString("Header Length: %1 bytes").arg(ihp->get_header_byte_len()));
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
}

void MainWindow::build_udp_tree(PackParser *ppsr)
{
    UDPHeaderParser * uhp =  ppsr->uhp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, uhp->get_description());
    fast_add_child(item, QString("Source Port: %0").arg(uhp->get_src_port()));
    fast_add_child(item, QString("Destination Port: %0").arg(uhp->get_dst_port()));
    fast_add_child(item, QString("Length: %0").arg(uhp->get_len()));
    fast_add_child(item, QString("Checksum: 0x%0").arg(QString().sprintf("%02x", uhp->get_checksum())));
}

void MainWindow::build_tcp_tree(PackParser *ppsr)
{
    TCPHeaderParser * thp =  ppsr->thp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, thp->get_description());
    fast_add_child(item, QString("Source Port: %0").arg(thp->get_src_port()));
    fast_add_child(item, QString("Destination Port: %0").arg(thp->get_dst_port()));
    fast_add_child(item, QString("Sequence number: %0").arg(thp->get_tcp_seq()));
    fast_add_child(item, QString("Acknowlegment number: %0").arg(thp->get_tcp_ack()));
    fast_add_child(item, QString("Header Length: %0 bytes").arg(thp->get_header_len()));
    fast_add_child(item, QString("FIN:%0 SYN:%1 RST:%2 PSH:%3 ACK:%4 URG:%5")
       .arg(thp->is_FIN_set()).arg(thp->is_SYN_set()).arg(thp->is_RST_set())
       .arg(thp->is_PSH_set()).arg(thp->is_ACK_set()).arg(thp->is_URG_set()));
    fast_add_child(item, QString("Window size value: %0").arg(thp->get_window_size()));
    fast_add_child(item, QString("Checksum: 0x%0").arg(QString().sprintf("%04x", thp->get_window_size())));
    fast_add_child(item, QString("Urgent pointer: %0").arg(thp->get_urp()));
}

void MainWindow::build_icmp_tree(PackParser *ppsr)
{
    ICMPHeaderParser * ichp =  ppsr->ichp;
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->singlePackageTreeWidget);
    item->setText(0, ichp->get_description());
    fast_add_child(item,QString("Type: %0 (%1)").arg(ichp->get_uint_type()).arg(ichp->get_qstring_type()));
    fast_add_child(item,QString("Code: %0").arg(ichp->get_code()));
    fast_add_child(item,QString("Checksum: 0x%0")
                   .arg(QString().sprintf("%04x", ichp->get_checksum())));
    fast_add_child(item,QString("Identifier: %0 (0x%1)")
                   .arg(ichp->get_id()).arg(QString().sprintf("%04x", ichp->get_id())));
    fast_add_child(item,QString("Sequence number: %0 (0x%1)")
                   .arg(ichp->get_seq()).arg(QString().sprintf("%04x", ichp->get_seq())));
}

void MainWindow::on_actionSetDevice_triggered()
{
    sdd = new SetDeviceDialog(this);
    sdd->setModal(true);
    sdd->show();
    connect(sdd, SIGNAL(setArgs(QString, QString)), this, SLOT(setArgs(QString, QString)));
}

void MainWindow::on_actionDisplayChart_triggered()
{
    pchart = new PcapChart(this);
    pchart->setModal(true);
    pchart->show();
    pchart->setModel(do_statistics());
}

void MainWindow::on_allPackTreeWidget_itemClicked(QTreeWidgetItem *item, int column)
{
    PcapQTreeWidgetItem * pitem = (PcapQTreeWidgetItem *) item;
    ((HexDecode *) (ui->hexDecodeWidget))->display_pack_data(pitem->ppsr);
    display_pack_trees(pitem->ppsr);
}
