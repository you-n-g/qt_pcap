#include "hexdecode.h"
#include "ui_hexdecode.h"

HexDecode::HexDecode(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::hexdecode)
{
    ui->setupUi(this);
}

HexDecode::~HexDecode()
{
    delete ui;
}

void HexDecode::display_pack_data(PackParser * ppsr)
{
    ui->textOffset->clear();
    ui->textOutput->clear();
    ui->textAscii->clear();
    QString *offset, *output, *ascii;

    offset = new QString();
    for (int i = 0; i < (ppsr->qba.length() - 1) / 16 + 1; ++i)
        offset->append(QString().sprintf("%04X\n", i * 16));
    ui->textOffset->setText(*offset);
    output = ppsr->to_hex_qstring();
    ui->textOutput->setText(*output);
    ascii = ppsr->to_ascii_qstring();
    ui->textAscii->setText(*ascii);
}
