#ifndef HEXDECODE_H
#define HEXDECODE_H

#include <QWidget>
#include <frame_parser.h>

namespace Ui {
class hexdecode;
}

class HexDecode : public QWidget
{
    Q_OBJECT

public:
    explicit HexDecode(QWidget *parent = 0);
    ~HexDecode();
    void display_pack_data(PackParser *ppsr);

private:
    Ui::hexdecode *ui;
};

#endif // HEXDECODE_H
