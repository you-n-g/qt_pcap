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

private slots:

    void on_actionStopPcap_triggered();

    void on_actionBeginPcap_triggered();

    void on_allWidgetTreeWidget_itemClicked(QTreeWidgetItem *item, int column);

private:
    Ui::MainWindow *ui;
    PcapThread * pcapThread;
};

#endif // MAINWINDOW_H
