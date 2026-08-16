#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QGroupBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace pcap_analyzer::ui {

/**
 * @brief Dialog for opening capture files with options
 */
class OpenCaptureDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OpenCaptureDialog(QWidget* parent = nullptr);
    ~OpenCaptureDialog() override;

    /**
     * @brief Get selected file path
     */
    [[nodiscard]] QString filePath() const;

    /**
     * @brief Check if index-only mode is selected
     */
    [[nodiscard]] bool indexOnly() const;

    /**
     * @brief Check if persistent index creation is requested
     */
    [[nodiscard]] bool createPersistentIndex() const;

    /**
     * @brief Check if existing index should be used
     */
    [[nodiscard]] bool useExistingIndex() const;

private slots:
    void onBrowseClicked();

private:
    void setupUi();

    QLineEdit* m_fileEdit = nullptr;
    QCheckBox* m_indexOnlyCheckbox = nullptr;
    QCheckBox* m_createPersistentIndexCheckbox = nullptr;
    QCheckBox* m_useExistingIndexCheckbox = nullptr;
};

} // namespace pcap_analyzer::ui
