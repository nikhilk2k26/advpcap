#include "ui/MainWindow.h"
#include "core/CaptureFileReader.h"
#include <QApplication>
#include <QDesktopServices>
#include <QUrl>

namespace pcap_analyzer::ui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_indexBuilder(new core::IndexBuilder(this))
{
    setupUi();
    loadSettings();
    
    // Connect indexing signals
    connect(m_indexBuilder, &core::IndexBuilder::progressUpdated,
            this, &MainWindow::onIndexingProgress);
    connect(m_indexBuilder, &core::IndexBuilder::indexingComplete,
            this, &MainWindow::onIndexingComplete);
    connect(m_indexBuilder, &core::IndexBuilder::indexingFailed,
            this, &MainWindow::onIndexingFailed);
    connect(m_indexBuilder, &core::IndexBuilder::indexingCancelled,
            this, &MainWindow::onIndexingCancelled);
}

MainWindow::~MainWindow()
{
    saveSettings();
    if (m_isIndexing && m_indexBuilder) {
        m_indexBuilder->cancel();
    }
}

void MainWindow::setupUi()
{
    setWindowTitle(tr("LargeScale Pcap Analyzer"));
    resize(1400, 900);
    
    setupMenus();
    setupToolBar();
    setupStatusBar();
    setupCentralWidget();
}

void MainWindow::setupMenus()
{
    // File menu
    m_fileMenu = menuBar()->addMenu(tr("&File"));
    
    auto* openAction = m_fileMenu->addAction(tr("&Open..."), this, &MainWindow::onOpenCapture);
    openAction->setShortcut(QKeySequence::Open);
    
    m_recentFilesMenu = m_fileMenu->addMenu(tr("Open &Recent"));
    updateRecentFilesMenu();
    
    m_fileMenu->addSeparator();
    
    auto* exitAction = m_fileMenu->addAction(tr("E&xit"), this, &MainWindow::onExit);
    exitAction->setShortcut(QKeySequence::Quit);
    
    // Edit menu
    m_editMenu = menuBar()->addMenu(tr("&Edit"));
    
    auto* copyAction = m_editMenu->addAction(tr("&Copy"), QKeySequence::Copy, nullptr, nullptr);
    copyAction->setEnabled(false); // TODO: Implement
    
    auto* copyCsvAction = m_editMenu->addAction(tr("Copy as &CSV"), nullptr);
    copyCsvAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
    
    m_editMenu->addSeparator();
    
    auto* goToAction = m_editMenu->addAction(tr("&Go to Packet..."), this, &MainWindow::onGoToPacket);
    goToAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
    
    // View menu
    m_viewMenu = menuBar()->addMenu(tr("&View"));
    
    // Analyze menu
    m_analyzeMenu = menuBar()->addMenu(tr("&Analyze"));
    
    auto* protocolHierarchyAction = m_analyzeMenu->addAction(tr("&Protocol Hierarchy"), nullptr);
    auto* endpointsAction = m_analyzeMenu->addAction(tr("&Endpoints"), nullptr);
    auto* conversationsAction = m_analyzeMenu->addAction(tr("&Conversations"), nullptr);
    auto* ioGraphAction = m_analyzeMenu->addAction(tr("&IO Graph"), nullptr);
    
    m_analyzeMenu->addSeparator();
    
    auto* tcpAnalysisAction = m_analyzeMenu->addAction(tr("&TCP Analysis"), nullptr);
    auto* dnsAnalysisAction = m_analyzeMenu->addAction(tr("&DNS Analysis"), nullptr);
    auto* httpAnalysisAction = m_analyzeMenu->addAction(tr("&HTTP Analysis"), nullptr);
    auto* tlsAnalysisAction = m_analyzeMenu->addAction(tr("&TLS Analysis"), nullptr);
    
    // Help menu
    m_helpMenu = menuBar()->addMenu(tr("&Help"));
    
    auto* aboutAction = m_helpMenu->addAction(tr("&About"), this, &MainWindow::onAbout);
}

void MainWindow::setupToolBar()
{
    m_mainToolBar = addToolBar(tr("Main Toolbar"));
    m_mainToolBar->setMovable(false);
    
    auto* openButton = new QPushButton(tr("Open"), this);
    connect(openButton, &QPushButton::clicked, this, &MainWindow::onOpenCapture);
    m_mainToolBar->addWidget(openButton);
    
    m_mainToolBar->addSeparator();
    
    // Filter bar in toolbar
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText(tr("Enter filter expression (e.g., ip.addr == 192.168.1.1 or tcp.port == 80)"));
    m_filterEdit->setMinimumWidth(400);
    connect(m_filterEdit, &QLineEdit::textChanged, this, &MainWindow::onFilterTextChanged);
    m_mainToolBar->addWidget(m_filterEdit);
    
    m_filterButton = new QPushButton(tr("Apply"), this);
    m_mainToolBar->addWidget(m_filterButton);
    
    m_filterStatusLabel = new QLabel(this);
    m_filterStatusLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_mainToolBar->addWidget(m_filterStatusLabel);
}

void MainWindow::setupStatusBar()
{
    m_statusLabel = new QLabel(tr("Ready"), this);
    statusBar()->addWidget(m_statusLabel, 1);
    
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setMaximumWidth(200);
    statusBar()->addPermanentWidget(m_progressBar);
    
    m_packetCountLabel = new QLabel(tr("Packets: 0"), this);
    statusBar()->addPermanentWidget(m_packetCountLabel);
}

void MainWindow::setupCentralWidget()
{
    // Create main vertical splitter
    m_verticalSplitter = new QSplitter(Qt::Vertical, this);
    m_verticalSplitter->setOpaqueResize(true);
    
    // Create horizontal splitter for packet list and details
    m_horizontalSplitter = new QSplitter(Qt::Horizontal, this);
    
    // Packet list view
    m_packetListView = new QTableView(this);
    m_packetListView->setAlternatingRowColors(true);
    m_packetListView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_packetListView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetListView->setSortingEnabled(true);
    m_packetListView->horizontalHeader()->setStretchLastSection(true);
    m_packetListView->verticalHeader()->setVisible(false);
    m_packetListView->setShowGrid(false);
    m_packetListView->setFocusPolicy(Qt::StrongFocus);
    
    // Create table model
    m_packetTableModel = new PacketTableModel(this);
    m_packetListView->setModel(m_packetTableModel);
    
    // Connect selection changes
    connect(m_packetListView->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &MainWindow::onPacketSelected);
    
    // Packet detail view (protocol tree)
    m_packetDetailView = new PacketDetailView(this);
    
    // Hex view
    m_hexView = new HexView(this);
    
    // Add widgets to splitters
    m_horizontalSplitter->addWidget(m_packetListView);
    m_horizontalSplitter->addWidget(m_packetDetailView);
    
    m_verticalSplitter->addWidget(m_horizontalSplitter);
    
    // Create container for hex view
    auto* hexContainer = new QWidget(this);
    auto* hexLayout = new QVBoxLayout(hexContainer);
    hexLayout->setContentsMargins(0, 0, 0, 0);
    hexLayout->addWidget(m_hexView);
    
    m_verticalSplitter->addWidget(hexContainer);
    
    // Set initial sizes (50% list/details, then 60%/40% for hex)
    m_horizontalSplitter->setSizes({700, 500});
    m_verticalSplitter->setSizes({500, 300});
    
    setCentralWidget(m_verticalSplitter);
}

void MainWindow::updateWindowTitle()
{
    if (m_currentFilePath.isEmpty()) {
        setWindowTitle(tr("LargeScale Pcap Analyzer"));
    } else {
        QString fileName = QFileInfo(m_currentFilePath).fileName();
        setWindowTitle(tr("%1 - LargeScale Pcap Analyzer").arg(fileName));
    }
}

void MainWindow::addRecentFile(const QString& filePath)
{
    m_recentFiles.removeAll(filePath);
    m_recentFiles.prepend(filePath);
    
    while (m_recentFiles.size() > MaxRecentFiles) {
        m_recentFiles.removeLast();
    }
    
    updateRecentFilesMenu();
}

void MainWindow::updateRecentFilesMenu()
{
    m_recentFilesMenu->clear();
    
    if (m_recentFiles.isEmpty()) {
        auto* noFilesAction = m_recentFilesMenu->addAction(tr("(No recent files)"));
        noFilesAction->setEnabled(false);
        return;
    }
    
    for (int i = 0; i < m_recentFiles.size(); ++i) {
        const QString& filePath = m_recentFiles[i];
        QString displayText = QString("&%1 %2").arg(i + 1).arg(QFileInfo(filePath).fileName());
        
        auto* action = m_recentFilesMenu->addAction(displayText, this, [this, filePath]() {
            openCaptureFile(filePath);
        });
        action->setData(filePath);
        action->setToolTip(filePath);
    }
    
    m_recentFilesMenu->addSeparator();
    auto* clearAction = m_recentFilesMenu->addAction(tr("Clear Recent Files"), this, [this]() {
        m_recentFiles.clear();
        updateRecentFilesMenu();
    });
}

void MainWindow::loadSettings()
{
    QSettings settings;
    restoreGeometry(settings.value("mainWindow/geometry").toByteArray());
    restoreState(settings.value("mainWindow/windowState").toByteArray());
    
    m_recentFiles = settings.value("recentFiles").toStringList();
    updateRecentFilesMenu();
    
    // Restore splitter positions
    if (!settings.value("splitters/main").isNull()) {
        m_verticalSplitter->restoreState(settings.value("splitters/main").toByteArray());
    }
    if (!settings.value("splitters/detail").isNull()) {
        m_horizontalSplitter->restoreState(settings.value("splitters/detail").toByteArray());
    }
}

void MainWindow::saveSettings()
{
    QSettings settings;
    settings.setValue("mainWindow/geometry", saveGeometry());
    settings.setValue("mainWindow/windowState", saveState());
    settings.setValue("recentFiles", m_recentFiles);
    settings.setValue("splitters/main", m_verticalSplitter->saveState());
    settings.setValue("splitters/detail", m_horizontalSplitter->saveState());
}

bool MainWindow::maybeSaveAnnotations()
{
    // TODO: Implement annotation saving
    return true;
}

void MainWindow::openCaptureFile(const QString& filePath)
{
    if (!QFileInfo::exists(filePath)) {
        QMessageBox::critical(this, tr("Error"), tr("File not found: %1").arg(filePath));
        return;
    }
    
    // Cancel any ongoing indexing
    if (m_isIndexing && m_indexBuilder) {
        m_indexBuilder->cancel();
    }
    
    // Try to open the file
    m_packetSource = core::createPacketSource(filePath.toStdString());
    if (!m_packetSource) {
        QMessageBox::critical(this, tr("Error"), 
                              tr("Failed to open capture file:\n%1\n\nUnsupported or invalid file format.")
                                  .arg(filePath));
        return;
    }
    
    m_currentFilePath = filePath;
    addRecentFile(filePath);
    updateWindowTitle();
    
    // Create new index
    m_packetIndex = std::make_shared<core::PacketIndex>(this);
    m_packetTableModel->setPacketIndex(m_packetIndex);
    
    // Update status
    m_statusLabel->setText(tr("Indexing %1...").arg(QFileInfo(filePath).fileName()));
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_isIndexing = true;
    
    // Start background indexing
    m_indexBuilder->buildIndexAsync(m_packetSource, m_packetIndex);
}

void MainWindow::onOpenCapture()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Open Capture File"),
        QString(),
        tr("PCAP/PCAP-NG Files (*.pcap *.pcapng *.cap);;All Files (*)")
    );
    
    if (filePath.isEmpty()) {
        return;
    }
    
    openCaptureFile(filePath);
}

void MainWindow::onRecentFileTriggered()
{
    auto* action = qobject_cast<QAction*>(sender());
    if (action) {
        QString filePath = action->data().toString();
        openCaptureFile(filePath);
    }
}

void MainWindow::onExit()
{
    close();
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, tr("About LargeScale Pcap Analyzer"),
        tr("<h2>LargeScale Pcap Analyzer</h2>"
           "<p>A high-performance offline packet capture analyzer for large pcap/pcapng files.</p>"
           "<p>Version 0.1.0 (Phase 2)</p>"
           "<p>Built with Qt 6 and C++20</p>"));
}

void MainWindow::onFilterTextChanged()
{
    // TODO: Implement filter engine integration
    QString filterText = m_filterEdit->text().trimmed();
    
    if (filterText.isEmpty()) {
        m_filterStatusLabel->clear();
        return;
    }
    
    // For now, just show that filtering is not yet implemented
    m_filterStatusLabel->setText(tr("(Filter not yet implemented)"));
}

void MainWindow::onGoToPacket()
{
    // TODO: Implement go-to-packet dialog
    QMessageBox::information(this, tr("Go to Packet"),
                             tr("Go to Packet feature coming in Phase 4."));
}

void MainWindow::onPacketSelected(const QModelIndex& current, const QModelIndex& previous)
{
    Q_UNUSED(previous);
    
    if (!current.isValid() || !m_packetTableModel) {
        return;
    }
    
    const auto* entry = m_packetTableModel->getEntryAtRow(current.row());
    if (!entry) {
        m_packetDetailView->clear();
        m_hexView->clear();
        return;
    }
    
    // Display packet details
    m_packetDetailView->displayPacket(entry, current.row());
    
    // Read and display packet bytes (simplified - would use packet source in real impl)
    // For now, just show placeholder data
    QVector<uint8_t> dummyData(entry->capturedLength, 0);
    m_hexView->setPacketData(dummyData.constData(), entry->capturedLength);
}

void MainWindow::onIndexingProgress(const core::IndexingProgress& progress)
{
    m_progressBar->setVisible(true);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(static_cast<int>(progress.percentComplete));
    
    QString statusText;
    switch (progress.stage) {
    case core::IndexingStage::ReadingHeaders:
        statusText = tr("Reading packet headers...");
        break;
    case core::IndexingStage::BuildingIndex:
        statusText = tr("Building packet index...");
        break;
    case core::IndexingStage::Finalizing:
        statusText = tr("Finalizing index...");
        break;
    default:
        statusText = tr("Processing...");
        break;
    }
    
    m_statusLabel->setText(QString("%1 %2 / %3 (%4%)")
        .arg(statusText)
        .arg(progress.packetsProcessed)
        .arg(progress.totalPackets > 0 ? progress.totalPackets : QVariant(tr("unknown")).toInt())
        .arg(progress.percentComplete, 0, 'f', 1));
    
    // Update packet count label incrementally
    m_packetCountLabel->setText(tr("Packets: %1").arg(progress.packetsProcessed));
}

void MainWindow::onIndexingComplete(const core::CaptureFileMetadata& metadata, uint64_t packetCount)
{
    m_isIndexing = false;
    m_progressBar->setVisible(false);
    
    m_statusLabel->setText(tr("Ready - %1 packets").arg(packetCount));
    m_packetCountLabel->setText(tr("Packets: %1").arg(packetCount));
    
    // Notify model of new data
    if (packetCount > 0 && m_packetIndex) {
        emit m_packetIndex->entriesAdded(0, packetCount);
    }
    
    // Get first visible row's packet for detail display
    if (packetCount > 0) {
        auto* firstEntry = m_packetIndex->getEntryByIndex(0);
        if (firstEntry) {
            m_packetDetailView->displayPacket(firstEntry, 0);
        }
    }
}

void MainWindow::onIndexingFailed(const QString& error)
{
    m_isIndexing = false;
    m_progressBar->setVisible(false);
    
    m_statusLabel->setText(tr("Indexing failed"));
    
    QMessageBox::critical(this, tr("Indexing Failed"),
                          tr("Failed to index capture file:\n%1").arg(error));
    
    m_packetIndex.reset();
    m_packetTableModel->setPacketIndex(nullptr);
    m_packetCountLabel->setText(tr("Packets: 0"));
}

void MainWindow::onIndexingCancelled()
{
    m_isIndexing = false;
    m_progressBar->setVisible(false);
    
    m_statusLabel->setText(tr("Indexing cancelled"));
    m_packetCountLabel->setText(tr("Packets: 0"));
}

void MainWindow::onIndexEntriesAdded(std::size_t startIndex, std::size_t count)
{
    Q_UNUSED(startIndex);
    Q_UNUSED(count);
    
    // Model will be updated via the index's signal connection
    // This slot is for additional UI updates if needed
}

} // namespace pcap_analyzer::ui
