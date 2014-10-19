#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::startPcapThread()
{
    PcapThread *pcapThread = new PcapThread(this);
    connect(pcapThread, &PcapThread::resultReady, this, &MainWindow::handleResults);
    connect(pcapThread, &PcapThread::finished, pcapThread, &QObject::deleteLater);
    pcapThread->start();
}

void MainWindow::handleResults(const QString &s) {
    qDebug() << s;
}

void MainWindow::on_action_triggered()
{
    startPcapThread();
}
