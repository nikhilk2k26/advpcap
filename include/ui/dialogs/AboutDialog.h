#pragma once

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace pcap_analyzer::ui {

/**
 * @brief About dialog showing application information
 */
class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget* parent = nullptr);
    ~AboutDialog() override;

private:
    void setupUi();
};

} // namespace pcap_analyzer::ui
