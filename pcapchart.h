#ifndef PCAPCHART_H
#define PCAPCHART_H

#include <QDialog>
#include <QtGui>
#include <QGridLayout>
#include <QTableView>
#include "pieview.h"
#include <QStandardItemModel>

namespace Ui {
class PcapChart;
}

class PcapChart : public QDialog
{
    Q_OBJECT

public:
    explicit PcapChart(QWidget *parent = 0); // data format is ["Label1", "value", "Label2", "value2", ....]
    ~PcapChart();
    void initModel();
    void setModel(QMap<QString, int> statistics);
    void setView();
    static u_int32_t const COLOR_N = 7;
    static u_int32_t const COLORS[7];
    static u_int32_t get_uint32_color(int i) {return COLORS[i % COLOR_N];}
private:
    Ui::PcapChart *ui;
    QAbstractItemModel *model;
};

#endif // PCAPCHART_H
