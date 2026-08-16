#pragma once

#include <QWidget>
#include <QTableView>
#include <QStandardItemModel>
#include <QVBoxLayout>

namespace pcap_analyzer::ui {

/**
 * @brief Panel for displaying network conversations
 * 
 * Shows a table of conversations between endpoints.
 */
class ConversationPanel : public QWidget
{
    Q_OBJECT

public:
    explicit ConversationPanel(QWidget* parent = nullptr);
    ~ConversationPanel() override;

    /**
     * @brief Clear all conversation data
     */
    void clear();

private:
    void setupUi();

    QTableView* m_tableView = nullptr;
    QStandardItemModel* m_model = nullptr;
};

} // namespace pcap_analyzer::ui
