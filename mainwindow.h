#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>
#include <stdlib.h>
#include <QMainWindow>
#include <QtCore>
#include <QTreeWidgetItem>
#include <QThread>
#include <QMessageBox>
#include "pcapthread.h"
#include <QtDebug>
#include "frame_parser.h"
#include "pcapqtools.h"
#include "hexdecode.h"
#include "setdevicedialog.h"
#include <QStringList>
#include "pcapchart.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void setupThread(QThread &);
    void startPcapThread();
    void stopPcapThread();

public slots:
    void handleResults(const QByteArray &s);
    void setArgs(QString dev, QString filter_rule);
    void popMsg(QString);

private slots:

    void on_actionStopPcap_triggered();

    void on_actionBeginPcap_triggered();

    void on_actionSetDevice_triggered();

    void on_actionDisplayChart_triggered();

    void on_allPackTreeWidget_itemClicked(QTreeWidgetItem *item, int column);

private:
    Ui::MainWindow *ui;
    PcapThread *pcapThread;
    void display_pack_trees(PackParser *ppsr);
    void build_ether_tree(PackParser *ppsr);
    void build_arp_tree(PackParser *ppsr);
    void build_ip_tree(PackParser *ppsr);
    QTreeWidgetItem *fast_add_child(QTreeWidgetItem *item, const QString &qstr);
    SetDeviceDialog *sdd;
    PcapChart *pchart;
    QString selected_device;
    QString filter_rule;
    void updateStatusMessage();
    QMap<QString, int> do_statistics();
};

#endif // MAINWINDOW_H
