#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QStyleFactory>
#include <QDir>
#include <QDebug>
#include "ui/MainWindow.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    
    // Set application metadata
    QCoreApplication::setOrganizationName("PcapAnalyzer");
    QCoreApplication::setOrganizationDomain("pcapanalyzer.org");
    QCoreApplication::setApplicationName("LargeScalePcapAnalyzer");
    QCoreApplication::setApplicationVersion("0.1.0");
    
    // Enable high DPI scaling
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
    
    // Set up command line parser
    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Production-quality offline packet capture analyzer for large pcap/pcapng files");
    parser.addHelpOption();
    parser.addVersionOption();
    
    // Positional argument: capture file to open
    parser.addPositionalArgument("file", "Capture file to open (.pcap or .pcapng)", "[file]");
    
    // Options
    QCommandLineOption darkModeOption(QStringList() << "d" << "dark-mode", 
                                       "Use dark theme");
    parser.addOption(darkModeOption);
    
    QCommandLineOption indexOnlyOption(QStringList() << "i" << "index-only",
                                        "Only build index, don't open GUI");
    parser.addOption(indexOnlyOption);
    
    parser.process(app);
    
    // Apply dark mode if requested
    if (parser.isSet(darkModeOption)) {
        app.setStyle(QStyleFactory::create("Fusion"));
        
        // Dark palette
        QPalette darkPalette;
        darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::WindowText, Qt::white);
        darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
        darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
        darkPalette.setColor(QPalette::ToolTipText, Qt::white);
        darkPalette.setColor(QPalette::Text, Qt::white);
        darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ButtonText, Qt::white);
        darkPalette.setColor(QPalette::BrightText, Qt::black);
        darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::HighlightedText, Qt::black);
        
        app.setPalette(darkPalette);
    }
    
    // Check for index-only mode
    if (parser.isSet(indexOnlyOption)) {
        qWarning() << "Index-only mode not yet implemented - use pcap-cli tool instead";
        return 1;
    }
    
    // Create and show main window
    pcap_analyzer::ui::MainWindow mainWindow;
    
    // Open file if provided
    const auto positionalArgs = parser.positionalArguments();
    if (!positionalArgs.isEmpty()) {
        const QString filePath = positionalArgs.first();
        if (QFile::exists(filePath)) {
            // TODO: Call method on MainWindow to open file
            // mainWindow.openCapture(filePath);
            qDebug() << "Would open file:" << filePath;
        } else {
            qWarning() << "File not found:" << filePath;
        }
    }
    
    mainWindow.show();
    
    return app.exec();
}
