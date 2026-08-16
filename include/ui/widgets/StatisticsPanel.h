#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QTreeView>
#include <QTableView>
#include <QStandardItemModel>
#include <QString>

namespace pcap_analyzer::ui {

/**
 * @brief Panel for displaying capture statistics
 * 
 * Contains tabs for summary, protocol hierarchy, endpoints, and conversations.
 */
class StatisticsPanel : public QWidget
{
    Q_OBJECT

public:
    explicit StatisticsPanel(QWidget* parent = nullptr);
    ~StatisticsPanel() override;

    /**
     * @brief Update the summary text
     */
    void updateSummary(const QString& summaryText);

    /**
     * @brief Clear all statistics displays
     */
    void clearAll();

private:
    void setupUi();

    QTabWidget* m_tabWidget = nullptr;
    
    // Summary tab
    QTextEdit* m_summaryText = nullptr;
    
    // Protocol hierarchy tab
    QTreeView* m_protocolTree = nullptr;
    QStandardItemModel* m_protocolModel = nullptr;
    
    // Endpoints tab
    QTableView* m_endpointsTable = nullptr;
    QStandardItemModel* m_endpointsModel = nullptr;
    
    // Conversations tab
    QTableView* m_conversationsTable = nullptr;
    QStandardItemModel* m_conversationsModel = nullptr;
};

} // namespace pcap_analyzer::ui
