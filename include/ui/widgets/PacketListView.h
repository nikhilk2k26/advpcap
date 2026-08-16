#pragma once

#include <QTableView>
#include <QHeaderView>
#include "ui/models/PacketTableModel.h"

namespace pcap_analyzer::ui {

/**
 * @brief Specialized table view for packet list display
 * 
 * Provides optimized configuration for displaying large packet lists.
 */
class PacketListView : public QTableView
{
    Q_OBJECT

public:
    explicit PacketListView(QWidget* parent = nullptr);
    ~PacketListView() override;

    void setModel(QAbstractItemModel* model) override;
};

} // namespace pcap_analyzer::ui
