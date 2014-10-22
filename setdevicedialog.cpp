#include "setdevicedialog.h"
#include "ui_setdevicedialog.h"

SetDeviceDialog::SetDeviceDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SetDeviceDialog)
{
    ui->setupUi(this);
    if (parent) {
        ui->comboBox->addItems(get_devices());
    }
}

SetDeviceDialog::~SetDeviceDialog()
{
    delete ui;
}

void SetDeviceDialog::on_SetDeviceDialog_accepted()
{
    //ui->comboBox->currentText().hhh
    qDebug() << "emitting" <<ui->comboBox->currentText();
    emit setArgs(ui->comboBox->currentText(), ui->lineEdit->text());
}
