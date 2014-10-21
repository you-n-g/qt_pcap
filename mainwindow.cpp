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
    qDebug() << "BEGIN----------the data";
    //qDebug() << qba;
    qDebug() << qba.length();
    qDebug() << "END  ----------the data";
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
    ((HexDecode *) (ui->hexDecodeWidget))->display_pack(pitem->ppsr);
}
