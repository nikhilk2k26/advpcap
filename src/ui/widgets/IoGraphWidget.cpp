#include "ui/widgets/IoGraphWidget.h"

namespace pcap_analyzer::ui {

IoGraphWidget::IoGraphWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

IoGraphWidget::~IoGraphWidget() = default;

void IoGraphWidget::setupUi()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(8);
    
    // Toolbar for graph options
    auto* toolbar = new QHBoxLayout();
    
    toolbar->addWidget(new QLabel(tr("Interval:"), this));
    m_intervalCombo = new QComboBox(this);
    m_intervalCombo->addItem(tr("1 second"), 1);
    m_intervalCombo->addItem(tr("10 seconds"), 10);
    m_intervalCombo->addItem(tr("1 minute"), 60);
    m_intervalCombo->addItem(tr("5 minutes"), 300);
    connect(m_intervalCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &IoGraphWidget::onIntervalChanged);
    toolbar->addWidget(m_intervalCombo);
    
    toolbar->addStretch();
    
    m_packetsCheckbox = new QCheckBox(tr("Packets"), this);
    m_packetsCheckbox->setChecked(true);
    connect(m_packetsCheckbox, &QCheckBox::toggled, this, &IoGraphWidget::updateGraph);
    toolbar->addWidget(m_packetsCheckbox);
    
    m_bytesCheckbox = new QCheckBox(tr("Bytes"), this);
    m_bytesCheckbox->setChecked(true);
    connect(m_bytesCheckbox, &QCheckBox::toggled, this, &IoGraphWidget::updateGraph);
    toolbar->addWidget(m_bytesCheckbox);
    
    layout->addLayout(toolbar);
    
    // Placeholder for actual graph widget
    // In production, would use QCustomPlot or similar
    m_graphPlaceholder = new QLabel(this);
    m_graphPlaceholder->setAlignment(Qt::AlignCenter);
    m_graphPlaceholder->setText(tr("IO Graph\n(Implementation requires QCustomPlot or Qt Charts)\n\nPackets/Bytes over time will be displayed here."));
    m_graphPlaceholder->setStyleSheet("QLabel { background-color: #f0f0f0; border: 1px solid #ccc; }");
    m_graphPlaceholder->setMinimumHeight(200);
    layout->addWidget(m_graphPlaceholder);
}

void IoGraphWidget::setData(const QVector<IoGraphDataPoint>& data)
{
    m_data = data;
    updateGraph();
}

void IoGraphWidget::clear()
{
    m_data.clear();
    m_graphPlaceholder->setText(tr("IO Graph\nNo data available"));
}

void IoGraphWidget::updateGraph()
{
    if (m_data.isEmpty()) {
        return;
    }
    
    // TODO: Implement actual graph rendering with QCustomPlot or Qt Charts
    // For now, just show summary info
    int interval = m_intervalCombo->currentData().toInt();
    QString info = tr("IO Graph - %1 data points\nInterval: %2 seconds\n")
        .arg(m_data.size())
        .arg(interval);
    
    if (m_packetsCheckbox->isChecked()) {
        info += tr("Showing: Packets\n");
    }
    if (m_bytesCheckbox->isChecked()) {
        info += tr("Showing: Bytes\n");
    }
    
    m_graphPlaceholder->setText(info);
}

void IoGraphWidget::onIntervalChanged()
{
    updateGraph();
    emit intervalChanged(m_intervalCombo->currentData().toInt());
}

} // namespace pcap_analyzer::ui
