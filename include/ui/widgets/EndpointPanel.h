#pragma once

#include <QWidget>
#include <QTableView>
#include <QStandardItemModel>
#include <QVBoxLayout>

namespace pcap_analyzer::ui {

/**
 * @brief Panel for displaying network endpoints
 * 
 * Shows a table of endpoints with traffic statistics.
 */
class EndpointPanel : public QWidget
{
    Q_OBJECT

public:
    explicit EndpointPanel(QWidget* parent = nullptr);
    ~EndpointPanel() override;

    /**
     * @brief Clear all endpoint data
     */
    void clear();

private:
    void setupUi();

    QTableView* m_tableView = nullptr;
    QStandardItemModel* m_model = nullptr;
};

} // namespace pcap_analyzer::ui
