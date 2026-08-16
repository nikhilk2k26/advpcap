#include "ui/widgets/StatisticsPanel.h"

namespace pcap_analyzer::ui {

StatisticsPanel::StatisticsPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

StatisticsPanel::~StatisticsPanel() = default;

void StatisticsPanel::setupUi()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(8);
    
    // Create tab widget for different statistics views
    m_tabWidget = new QTabWidget(this);
    
    // Summary tab
    auto* summaryWidget = new QWidget();
    auto* summaryLayout = new QVBoxLayout(summaryWidget);
    m_summaryText = new QTextEdit(summaryWidget);
    m_summaryText->setReadOnly(true);
    m_summaryText->setFont(QFont("Courier New", 10));
    summaryLayout->addWidget(m_summaryText);
    m_tabWidget->addTab(summaryWidget, tr("Summary"));
    
    // Protocol hierarchy tab
    auto* protoWidget = new QWidget();
    auto* protoLayout = new QVBoxLayout(protoWidget);
    m_protocolTree = new QTreeView(protoWidget);
    m_protocolModel = new QStandardItemModel(m_protocolTree);
    m_protocolTree->setModel(m_protocolModel);
    m_protocolTree->header()->setStretchLastSection(true);
    protoLayout->addWidget(m_protocolTree);
    m_tabWidget->addTab(protoWidget, tr("Protocol Hierarchy"));
    
    // Endpoints tab
    auto* endpointsWidget = new QWidget();
    auto* endpointsLayout = new QVBoxLayout(endpointsWidget);
    m_endpointsTable = new QTableView(endpointsWidget);
    m_endpointsModel = new QStandardItemModel(m_endpointsTable);
    m_endpointsTable->setModel(m_endpointsModel);
    m_endpointsTable->horizontalHeader()->setStretchLastSection(true);
    m_endpointsTable->setAlternatingRowColors(true);
    endpointsLayout->addWidget(m_endpointsTable);
    m_tabWidget->addTab(endpointsWidget, tr("Endpoints"));
    
    // Conversations tab
    auto* conversationsWidget = new QWidget();
    auto* conversationsLayout = new QVBoxLayout(conversationsWidget);
    m_conversationsTable = new QTableView(conversationsWidget);
    m_conversationsModel = new QStandardItemModel(m_conversationsTable);
    m_conversationsTable->setModel(m_conversationsModel);
    m_conversationsTable->horizontalHeader()->setStretchLastSection(true);
    m_conversationsTable->setAlternatingRowColors(true);
    conversationsLayout->addWidget(m_conversationsTable);
    m_tabWidget->addTab(conversationsWidget, tr("Conversations"));
    
    layout->addWidget(m_tabWidget);
}

void StatisticsPanel::updateSummary(const QString& summaryText)
{
    m_summaryText->setPlainText(summaryText);
}

void StatisticsPanel::clearAll()
{
    m_summaryText->clear();
    m_protocolModel->clear();
    m_endpointsModel->clear();
    m_conversationsModel->clear();
}

} // namespace pcap_analyzer::ui
