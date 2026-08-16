#include <QMainWindow>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QSplitter>
#include <QTableView>
#include <QTreeView>
#include <QDockWidget>
#include <QLabel>
#include <QProgressBar>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QFileDialog>
#include <QCloseEvent>
#include <QSettings>
#include <memory>
#include "ui/models/PacketTableModel.h"
#include "ui/widgets/PacketDetailView.h"
#include "ui/widgets/HexView.h"
#include "core/IndexBuilder.h"
#include "core/PacketIndex.h"
#include "core/IPacketSource.h"

namespace pcap_analyzer::ui {

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    
private slots:
    void onOpenCapture();
    void onRecentFileTriggered();
    void onExit();
    void onAbout();
    void onFilterTextChanged();
    void onGoToPacket();
    void onPacketSelected(const QModelIndex& current, const QModelIndex& previous);
    void onIndexingProgress(const core::IndexingProgress& progress);
    void onIndexingComplete(const core::CaptureFileMetadata& metadata, uint64_t packetCount);
    void onIndexingFailed(const QString& error);
    void onIndexingCancelled();
    void onIndexEntriesAdded(std::size_t startIndex, std::size_t count);
    
private:
    void setupUi();
    void setupMenus();
    void setupToolBar();
    void setupStatusBar();
    void setupCentralWidget();
    void updateWindowTitle();
    void addRecentFile(const QString& filePath);
    void updateRecentFilesMenu();
    void loadSettings();
    void saveSettings();
    bool maybeSaveAnnotations();
    void openCaptureFile(const QString& filePath);
    
    // UI components
    QMenu* m_fileMenu = nullptr;
    QMenu* m_editMenu = nullptr;
    QMenu* m_viewMenu = nullptr;
    QMenu* m_analyzeMenu = nullptr;
    QMenu* m_helpMenu = nullptr;
    QMenu* m_recentFilesMenu = nullptr;
    
    QToolBar* m_mainToolBar = nullptr;
    
    // Central widgets
    QSplitter* m_verticalSplitter = nullptr;
    QSplitter* m_horizontalSplitter = nullptr;
    
    QTableView* m_packetListView = nullptr;
    PacketDetailView* m_packetDetailView = nullptr;
    HexView* m_hexView = nullptr;
    
    // Filter bar
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_filterButton = nullptr;
    QLabel* m_filterStatusLabel = nullptr;
    
    // Status bar
    QLabel* m_statusLabel = nullptr;
    QProgressBar* m_progressBar = nullptr;
    QLabel* m_packetCountLabel = nullptr;
    
    // Core components
    std::shared_ptr<core::PacketIndex> m_packetIndex;
    std::shared_ptr<core::IPacketSource> m_packetSource;
    core::IndexBuilder* m_indexBuilder = nullptr;
    
    // Models
    PacketTableModel* m_packetTableModel = nullptr;
    
    QString m_currentFilePath;
    QStringList m_recentFiles;
    bool m_isIndexing = false;
    
    static constexpr int MaxRecentFiles = 10;
};

} // namespace pcap_analyzer::ui
