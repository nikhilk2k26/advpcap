#include "ui/dialogs/AboutDialog.h"

namespace pcap_analyzer::ui {

AboutDialog::AboutDialog(QWidget* parent)
    : QDialog(parent)
{
    setupUi();
}

AboutDialog::~AboutDialog() = default;

void AboutDialog::setupUi()
{
    setWindowTitle(tr("About LargeScale Pcap Analyzer"));
    setMinimumSize(400, 300);
    
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(16);
    
    // Logo/icon placeholder
    auto* iconLabel = new QLabel(this);
    iconLabel->setAlignment(Qt::AlignCenter);
    iconLabel->setText(tr("📊"));
    iconLabel->setStyleSheet("font-size: 48px;");
    layout->addWidget(iconLabel);
    
    // Title
    auto* titleLabel = new QLabel(tr("<h2>LargeScale Pcap Analyzer</h2>"), this);
    titleLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel);
    
    // Version
    auto* versionLabel = new QLabel(tr("Version 0.1.0 (Phase 2)"), this);
    versionLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(versionLabel);
    
    // Description
    auto* descLabel = new QLabel(
        tr("<p>A high-performance offline packet capture analyzer for "
           "large pcap/pcapng files.</p>"
           "<p>Built with Qt 6 and C++20 for analyzing multi-million packet captures.</p>"),
        this);
    descLabel->setAlignment(Qt::AlignCenter);
    descLabel->setWordWrap(true);
    layout->addWidget(descLabel);
    
    // Tech stack
    auto* techLabel = new QLabel(
        tr("<p><b>Technology Stack:</b></p>"
           "<ul>"
           "<li>C++20</li>"
           "<li>Qt 6 Widgets</li>"
           "<li>PcapPlusPlus</li>"
           "<li>SQLite</li>"
           "</ul>"),
        this);
    techLabel->setWordWrap(true);
    layout->addWidget(techLabel);
    
    // Copyright
    auto* copyrightLabel = new QLabel(tr("<p>© 2024 PcapAnalyzer Project</p>"), this);
    copyrightLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(copyrightLabel);
    
    layout->addStretch();
    
    // OK button
    auto* okButton = new QPushButton(tr("OK"), this);
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(okButton);
}

} // namespace pcap_analyzer::ui
