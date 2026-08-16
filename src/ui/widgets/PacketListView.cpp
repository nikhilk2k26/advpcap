#include "ui/widgets/PacketListView.h"

namespace pcap_analyzer::ui {

PacketListView::PacketListView(QWidget* parent)
    : QTableView(parent)
{
    setAlternatingRowColors(true);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSortingEnabled(true);
    horizontalHeader()->setStretchLastSection(true);
    verticalHeader()->setVisible(false);
    setShowGrid(false);
    setFocusPolicy(Qt::StrongFocus);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    // Set default column widths
    setColumnWidth(static_cast<int>(PacketListColumn::Number), 60);
    setColumnWidth(static_cast<int>(PacketListColumn::Time), 100);
    setColumnWidth(static_cast<int>(PacketListColumn::Delta), 80);
    setColumnWidth(static_cast<int>(PacketListColumn::Source), 140);
    setColumnWidth(static_cast<int>(PacketListColumn::Destination), 140);
    setColumnWidth(static_cast<int>(PacketListColumn::Protocol), 70);
    setColumnWidth(static_cast<int>(PacketListColumn::Length), 60);
}

PacketListView::~PacketListView() = default;

void PacketListView::setModel(QAbstractItemModel* model)
{
    QTableView::setModel(model);
    
    // Set header resize mode
    horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    horizontalHeader()->setSortIndicatorShown(true);
}

} // namespace pcap_analyzer::ui
