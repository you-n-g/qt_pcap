#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtCore>
#include <QThread>
#include <QMessageBox>
#include <stdio.h>
#include <stdlib.h>
#include "pcapthread.h"
#include <QtDebug>


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

public slots:
    void handleResults(const QString &s);

private slots:
    void on_action_triggered();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
