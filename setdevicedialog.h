#ifndef SETDEVICEDIALOG_H
#define SETDEVICEDIALOG_H

#include <QDialog>
#include "pcapqtools.h"

class MainWindow;

namespace Ui {
class SetDeviceDialog;
}

class SetDeviceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SetDeviceDialog(QWidget *parent = 0);
    ~SetDeviceDialog();

signals:
    void setArgs(QString, QString);

private slots:
    void on_SetDeviceDialog_accepted();

private:
    Ui::SetDeviceDialog *ui;
    //MainWindow * mw;
};

#endif // SETDEVICEDIALOG_H
