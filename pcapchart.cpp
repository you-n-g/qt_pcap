#include "pcapchart.h"
#include "ui_pcapchart.h"

PcapChart::PcapChart(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PcapChart)
{
    ui->setupUi(this);

    initModel();
    setView();
}

PcapChart::~PcapChart()
{
    delete ui;
}

u_int32_t const PcapChart::COLORS[]={0x808A87, 0xFFE384, 0x87CEEB, 0xFFFFCD, 0x87CEEB, 0x87CEEB, 0xDDA0DD};

void PcapChart::initModel()
{
    model = new QStandardItemModel(8, 2, this);
    model->setHeaderData(0, Qt::Horizontal, tr("Protocol"));
    model->setHeaderData(1, Qt::Horizontal, tr("Quantity"));
}

void PcapChart::setModel(QMap<QString, int> statistics)
{
    int row = 0;

    QMapIterator<QString, int> itr(statistics);
    while (itr.hasNext()) {
        itr.next();
        model->insertRows(row, 1, QModelIndex());
        model->setData(model->index(row, 0, QModelIndex()),
           itr.key());
        model->setData(model->index(row, 1, QModelIndex()),
           itr.value());
        model->setData(model->index(row, 0, QModelIndex()),
           QColor(get_uint32_color(row)), Qt::DecorationRole);
        row++;
    }
}

void PcapChart::setView()
{
    ui->tableView->setModel(model);
    ui->pieview->setModel(model);

    QItemSelectionModel *selectionModel = new QItemSelectionModel(model);
    ui->tableView->setSelectionModel(selectionModel);
    ui->pieview->setSelectionModel(selectionModel);

    QHeaderView *headerView = ui->tableView->horizontalHeader();
    headerView->setStretchLastSection(true);
}
