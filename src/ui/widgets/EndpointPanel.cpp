#include "ui/widgets/EndpointPanel.h"

namespace pcap_analyzer::ui {

EndpointPanel::EndpointPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

EndpointPanel::~EndpointPanel() = default;

void EndpointPanel::setupUi()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    m_tableView = new QTableView(this);
    m_model = new QStandardItemModel(m_tableView);
    m_tableView->setModel(m_model);
    m_tableView->setAlternatingRowColors(true);
    m_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableView->horizontalHeader()->setStretchLastSection(true);
    m_tableView->horizontalHeader()->setSortIndicatorShown(true);
    m_tableView->setSortingEnabled(true);
    
    // Set column headers
    QStringList headers = {"Address", "Packets Sent", "Packets Received", 
                          "Bytes Sent", "Bytes Received", "First Seen", "Last Seen"};
    m_model->setColumnCount(headers.size());
    m_model->setHorizontalHeaderLabels(headers);
    
    layout->addWidget(m_tableView);
}

void EndpointPanel::clear()
{
    m_model->removeRows(0, m_model->rowCount());
}

} // namespace pcap_analyzer::ui
