#include "ui/widgets/FilterBar.h"

namespace pcap_analyzer::ui {

FilterBar::FilterBar(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

FilterBar::~FilterBar() = default;

void FilterBar::setupUi()
{
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(8);
    
    // Filter label
    m_label = new QLabel(tr("Filter:"), this);
    layout->addWidget(m_label);
    
    // Filter expression input
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText(tr("Enter filter expression (e.g., ip.addr == 192.168.1.1 or tcp.port == 80)"));
    m_filterEdit->setClearButtonEnabled(true);
    connect(m_filterEdit, &QLineEdit::textChanged, this, &FilterBar::onFilterTextChanged);
    connect(m_filterEdit, &QLineEdit::returnPressed, this, &FilterBar::applyFilter);
    layout->addWidget(m_filterEdit, 1);
    
    // Apply button
    m_applyButton = new QPushButton(tr("Apply"), this);
    connect(m_applyButton, &QPushButton::clicked, this, &FilterBar::applyFilter);
    layout->addWidget(m_applyButton);
    
    // Clear button
    m_clearButton = new QPushButton(tr("Clear"), this);
    connect(m_clearButton, &QPushButton::clicked, this, &FilterBar::clearFilter);
    layout->addWidget(m_clearButton);
    
    // Status label
    m_statusLabel = new QLabel(this);
    m_statusLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    layout->addWidget(m_statusLabel);
}

QString FilterBar::filterText() const
{
    return m_filterEdit->text().trimmed();
}

void FilterBar::setFilterText(const QString& text)
{
    m_filterEdit->setText(text);
}

void FilterBar::setStatusMessage(const QString& message, bool isError)
{
    m_statusLabel->setText(message);
    if (isError) {
        m_statusLabel->setStyleSheet("color: red;");
    } else {
        m_statusLabel->setStyleSheet("");
    }
}

void FilterBar::clearStatus()
{
    m_statusLabel->clear();
    m_statusLabel->setStyleSheet("");
}

void FilterBar::onFilterTextChanged(const QString& text)
{
    emit filterChanged(text.trimmed());
}

void FilterBar::applyFilter()
{
    QString text = filterText();
    emit filterApplied(text);
}

void FilterBar::clearFilter()
{
    m_filterEdit->clear();
    clearStatus();
    emit filterCleared();
}

} // namespace pcap_analyzer::ui
