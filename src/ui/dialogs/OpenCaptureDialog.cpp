#include "ui/dialogs/OpenCaptureDialog.h"

namespace pcap_analyzer::ui {

OpenCaptureDialog::OpenCaptureDialog(QWidget* parent)
    : QDialog(parent)
{
    setupUi();
}

OpenCaptureDialog::~OpenCaptureDialog() = default;

void OpenCaptureDialog::setupUi()
{
    setWindowTitle(tr("Open Capture File"));
    setMinimumWidth(500);
    
    auto* layout = new QVBoxLayout(this);
    
    // File selection
    auto* fileLayout = new QHBoxLayout();
    m_fileEdit = new QLineEdit(this);
    m_fileEdit->setPlaceholderText(tr("Select a pcap or pcapng file..."));
    fileLayout->addWidget(m_fileEdit);
    
    auto* browseButton = new QPushButton(tr("Browse..."), this);
    connect(browseButton, &QPushButton::clicked, this, &OpenCaptureDialog::onBrowseClicked);
    fileLayout->addWidget(browseButton);
    
    layout->addLayout(fileLayout);
    
    // Options group
    auto* optionsGroup = new QGroupBox(tr("Options"), this);
    auto* optionsLayout = new QVBoxLayout(optionsGroup);
    
    m_indexOnlyCheckbox = new QCheckBox(tr("Build index only (don't load packets)"), this);
    m_indexOnlyCheckbox->setChecked(false);
    optionsLayout->addWidget(m_indexOnlyCheckbox);
    
    m_createPersistentIndexCheckbox = new QCheckBox(tr("Create persistent index file"), this);
    m_createPersistentIndexCheckbox->setChecked(true);
    optionsLayout->addWidget(m_createPersistentIndexCheckbox);
    
    m_useExistingIndexCheckbox = new QCheckBox(tr("Use existing index if available"), this);
    m_useExistingIndexCheckbox->setChecked(true);
    optionsLayout->addWidget(m_useExistingIndexCheckbox);
    
    layout->addWidget(optionsGroup);
    
    // Buttons
    auto* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        Qt::Horizontal, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttonBox);
}

QString OpenCaptureDialog::filePath() const
{
    return m_fileEdit->text();
}

bool OpenCaptureDialog::indexOnly() const
{
    return m_indexOnlyCheckbox->isChecked();
}

bool OpenCaptureDialog::createPersistentIndex() const
{
    return m_createPersistentIndexCheckbox->isChecked();
}

bool OpenCaptureDialog::useExistingIndex() const
{
    return m_useExistingIndexCheckbox->isChecked();
}

void OpenCaptureDialog::onBrowseClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Open Capture File"),
        QString(),
        tr("PCAP/PCAP-NG Files (*.pcap *.pcapng *.cap);;All Files (*)")
    );
    
    if (!filePath.isEmpty()) {
        m_fileEdit->setText(filePath);
    }
}

} // namespace pcap_analyzer::ui
