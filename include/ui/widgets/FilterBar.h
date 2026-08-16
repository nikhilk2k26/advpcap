#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>

namespace pcap_analyzer::ui {

/**
 * @brief Widget for entering and applying packet filters
 * 
 * Provides a text input for filter expressions with apply/clear buttons.
 */
class FilterBar : public QWidget
{
    Q_OBJECT

public:
    explicit FilterBar(QWidget* parent = nullptr);
    ~FilterBar() override;

    /**
     * @brief Get current filter text
     */
    [[nodiscard]] QString filterText() const;

    /**
     * @brief Set filter text
     */
    void setFilterText(const QString& text);

    /**
     * @brief Set status message (error or info)
     */
    void setStatusMessage(const QString& message, bool isError = false);

    /**
     * @brief Clear status message
     */
    void clearStatus();

signals:
    /**
     * @brief Emitted when filter text changes
     */
    void filterChanged(const QString& filterText);

    /**
     * @brief Emitted when Apply button is clicked or Enter is pressed
     */
    void filterApplied(const QString& filterText);

    /**
     * @brief Emitted when Clear button is clicked
     */
    void filterCleared();

private slots:
    void onFilterTextChanged(const QString& text);
    void applyFilter();
    void clearFilter();

private:
    void setupUi();

    QLabel* m_label = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_applyButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QLabel* m_statusLabel = nullptr;
};

} // namespace pcap_analyzer::ui
