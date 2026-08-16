/**
 * @file cli_index_tool.cpp
 * @brief Command-line tool for testing pcap/pcapng file indexing
 * 
 * This tool demonstrates the core indexing functionality without GUI.
 * It can be used for:
 * - Testing file readers
 * - Benchmarking indexing performance
 * - Generating statistics about capture files
 * - Validating index correctness
 */

#include "core/CaptureFileReader.h"
#include "core/PacketIndex.h"
#include "core/IndexBuilder.h"
#include "core/utils/TimestampUtils.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QElapsedTimer>
#include <QTextStream>
#include <QFileInfo>
#include <QDebug>
#include <memory>
#include <cstdio>

using namespace pcap_analyzer::core;

/**
 * @brief Print progress callback
 */
void printProgress(const IndexingProgress& progress, bool force = false)
{
    static int lastPercent = -1;
    const int currentPercent = static_cast<int>(progress.percentComplete);
    
    if (force || currentPercent != lastPercent) {
        QTextStream out(stdout);
        out << "\rIndexing: " << QString::number(progress.percentComplete, 'f', 1) << "% "
            << "(" << progress.packetsIndexed << " packets, "
            << progress.bytesProcessed / (1024 * 1024) << " MB)";
        out.flush();
        lastPercent = currentPercent;
    }
}

/**
 * @brief Print packet index entry in human-readable format
 */
void printPacketEntry(const PacketIndexEntry& entry, int displayNumber)
{
    QTextStream out(stdout);
    
    char srcIpStr[64], dstIpStr[64];
    
    // Format IP addresses
    if (entry.ipVersion == 4) {
        snprintf(srcIpStr, sizeof(srcIpStr), "%d.%d.%d.%d",
                 entry.srcIp[0], entry.srcIp[1], entry.srcIp[2], entry.srcIp[3]);
        snprintf(dstIpStr, sizeof(dstIpStr), "%d.%d.%d.%d",
                 entry.dstIp[0], entry.dstIp[1], entry.dstIp[2], entry.dstIp[3]);
    } else if (entry.ipVersion == 6) {
        snprintf(srcIpStr, sizeof(srcIpStr), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 entry.srcIp[0], entry.srcIp[1], entry.srcIp[2], entry.srcIp[3],
                 entry.srcIp[4], entry.srcIp[5], entry.srcIp[6], entry.srcIp[7],
                 entry.srcIp[8], entry.srcIp[9], entry.srcIp[10], entry.srcIp[11],
                 entry.srcIp[12], entry.srcIp[13], entry.srcIp[14], entry.srcIp[15]);
        snprintf(dstIpStr, sizeof(dstIpStr), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 entry.dstIp[0], entry.dstIp[1], entry.dstIp[2], entry.dstIp[3],
                 entry.dstIp[4], entry.dstIp[5], entry.dstIp[6], entry.dstIp[7],
                 entry.dstIp[8], entry.dstIp[9], entry.dstIp[10], entry.dstIp[11],
                 entry.dstIp[12], entry.dstIp[13], entry.dstIp[14], entry.dstIp[15]);
    } else {
        strcpy(srcIpStr, "-");
        strcpy(dstIpStr, "-");
    }
    
    // Get protocol name
    const char* protoName = "UNK";
    switch (static_cast<ProtocolSummary>(entry.protocolSummary)) {
        case ProtocolSummary::Ethernet: protoName = "ETH"; break;
        case ProtocolSummary::Arp: protoName = "ARP"; break;
        case ProtocolSummary::Ipv4: protoName = "IPv4"; break;
        case ProtocolSummary::Ipv6: protoName = "IPv6"; break;
        case ProtocolSummary::Tcp: protoName = "TCP"; break;
        case ProtocolSummary::Udp: protoName = "UDP"; break;
        case ProtocolSummary::Dns: protoName = "DNS"; break;
        case ProtocolSummary::Http: protoName = "HTTP"; break;
        case ProtocolSummary::Tls: protoName = "TLS"; break;
        case ProtocolSummary::Icmp: protoName = "ICMP"; break;
        case ProtocolSummary::Icmpv6: protoName = "ICMPv6"; break;
        default: break;
    }
    
    // Format timestamp
    char timeStr[32];
    const auto [secs, nsecs] = nanosecondsToSeconds(entry.timestampNs);
    if (secs > 0) {
        const time_t t = static_cast<time_t>(secs);
        struct tm tm_buf;
        gmtime_r(&t, &tm_buf);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm_buf);
    } else {
        strcpy(timeStr, "00:00:00.000000");
    }
    
    // TCP flags
    char tcpFlagsStr[16] = "";
    if (entry.transportProtocol == 6) {  // TCP
        if (entry.tcpFlags & 0x02) strcat(tcpFlagsStr, "S");  // SYN
        if (entry.tcpFlags & 0x10) strcat(tcpFlagsStr, "A");  // ACK
        if (entry.tcpFlags & 0x04) strcat(tcpFlagsStr, "R");  // RST
        if (entry.tcpFlags & 0x01) strcat(tcpFlagsStr, "F");  // FIN
        if (entry.tcpFlags & 0x08) strcat(tcpFlagsStr, "P");  // PSH
        if (entry.tcpFlags & 0x20) strcat(tcpFlagsStr, "U");  // URG
    }
    
    out << QString("%1 %2 %-20s %-20s %-8s %-6s %s %5u %s\n")
               .arg(displayNumber, 6)
               .arg(timeStr)
               .arg(srcIpStr)
               .arg(dstIpStr)
               .arg(protoName)
               .arg(tcpFlagsStr)
               .arg(entry.srcPort, 5)
               .arg(entry.dstPort, 5)
               .arg(entry.capturedLength, 6);
}

/**
 * @brief Print summary statistics
 */
void printSummary(const CaptureFileMetadata& metadata, 
                  const PacketIndex& index,
                  quint64 indexingTimeMs)
{
    QTextStream out(stdout);
    
    out << "\n\n";
    out << "================================================================================\n";
    out << "                           INDEXING SUMMARY\n";
    out << "================================================================================\n\n";
    
    out << "File Information:\n";
    out << "  File Path:      " << metadata.filePath << "\n";
    out << "  File Size:      " << metadata.fileSize << " bytes ("
        << QString::number(static_cast<double>(metadata.fileSize) / (1024 * 1024), 'f', 2) << " MB)\n";
    out << "  File Type:      " << (metadata.isPcapNg ? "PCAP-NG" : "PCAP") << "\n";
    out << "  Link Type:      " << metadata.linkType << "\n";
    out << "  Snap Length:    " << metadata.snapLen << "\n";
    
    if (!metadata.applicationName.isEmpty()) {
        out << "  Application:    " << metadata.applicationName << "\n";
    }
    
    out << "\nIndexing Performance:\n";
    out << "  Time Taken:     " << QString::number(indexingTimeMs / 1000.0, 'f', 3) << " seconds\n";
    out << "  Packets/sec:    " << QString::number(index.packetsCount() * 1000.0 / indexingTimeMs, 'f', 0) << "\n";
    out << "  MB/sec:         " << QString::number(metadata.fileSize * 1000.0 / (indexingTimeMs * 1024 * 1024), 'f', 2) << "\n";
    
    out << "\nPacket Statistics:\n";
    out << "  Total Packets:  " << index.packetCount() << "\n";
    
    if (auto firstTs = index.getFirstTimestamp()) {
        if (auto span = index.getTimeSpanNs()) {
            const double durationSecs = static_cast<double>(*span) / 1e9;
            out << "  Duration:       " << QString::number(durationSecs, 'f', 3) << " seconds\n";
            if (durationSecs > 0) {
                out << "  Packets/sec:    " << QString::number(index.packetCount() / durationSecs, 'f', 2) << "\n";
            }
        }
    }
    
    // Protocol distribution
    out << "\nProtocol Distribution (top protocols):\n";
    std::map<uint8_t, uint64_t> protoCounts;
    for (std::size_t i = 0; i < index.packetCount(); ++i) {
        if (const auto* entry = index.getEntryByIndex(i)) {
            protoCounts[entry->protocolSummary]++;
        }
    }
    
    // Sort by count
    std::vector<std::pair<uint8_t, uint64_t>> sortedProtos(protoCounts.begin(), protoCounts.end());
    std::sort(sortedProtos.begin(), sortedProtos.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& [proto, count] : sortedProtos) {
        const double pct = static_cast<double>(count) / index.packetCount() * 100.0;
        out << "  " << protocolSummaryToString(static_cast<ProtocolSummary>(proto)).toStdString()
            << ": " << count << " (" << QString::number(pct, 'f', 2) << "%)\n";
    }
    
    // IP version distribution
    uint64_t ipv4Count = 0, ipv6Count = 0, otherCount = 0;
    for (std::size_t i = 0; i < index.packetCount(); ++i) {
        if (const auto* entry = index.getEntryByIndex(i)) {
            if (entry->ipVersion == 4) ipv4Count++;
            else if (entry->ipVersion == 6) ipv6Count++;
            else otherCount++;
        }
    }
    
    out << "\nIP Version Distribution:\n";
    out << "  IPv4:           " << ipv4Count << " (" 
        << QString::number(static_cast<double>(ipv4Count) / index.packetCount() * 100.0, 'f', 2) << "%)\n";
    out << "  IPv6:           " << ipv6Count << " ("
        << QString::number(static_cast<double>(ipv6Count) / index.packetCount() * 100.0, 'f', 2) << "%)\n";
    out << "  Other/Unknown:  " << otherCount << "\n";
    
    // Transport protocol distribution
    uint64_t tcpCount = 0, udpCount = 0, otherTransportCount = 0;
    for (std::size_t i = 0; i < index.packetCount(); ++i) {
        if (const auto* entry = index.getEntryByIndex(i)) {
            if (entry->transportProtocol == 6) tcpCount++;
            else if (entry->transportProtocol == 17) udpCount++;
            else otherTransportCount++;
        }
    }
    
    out << "\nTransport Protocol Distribution:\n";
    out << "  TCP:            " << tcpCount << "\n";
    out << "  UDP:            " << udpCount << "\n";
    out << "  Other:          " << otherTransportCount << "\n";
    
    out << "\n================================================================================\n";
}

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("pcap-cli");
    QCoreApplication::setApplicationVersion("0.1.0");
    
    QTextStream out(stdout);
    
    QCommandLineParser parser;
    parser.setApplicationDescription("Command-line tool for indexing pcap/pcapng files");
    parser.addHelpOption();
    parser.addVersionOption();
    
    // Positional argument: input file
    parser.addPositionalArgument("input", "Input pcap or pcapng file", "<input>");
    
    // Options
    QCommandLineOption outputOption(QStringList() << "o" << "output",
                                    "Output index to file (optional)", "filename");
    parser.addOption(outputOption);
    
    QCommandLineOption verboseOption(QStringList() << "v" << "verbose",
                                     "Show detailed packet listing");
    parser.addOption(verboseOption);
    
    QCommandLineOption limitOption(QStringList() << "l" << "limit",
                                   "Limit number of packets to process", "count");
    parser.addOption(limitOption);
    
    QCommandLineOption statsOnlyOption(QStringList() << "s" << "stats",
                                       "Show only statistics, no packet listing");
    parser.addOption(statsOnlyOption);
    
    parser.process(app);
    
    const auto args = parser.positionalArguments();
    if (args.isEmpty()) {
        out << "Error: No input file specified.\n";
        out << "Usage: " << argv[0] << " [options] <input.pcap|input.pcapng>\n";
        out << "Run with --help for more information.\n";
        return 1;
    }
    
    const QString inputFile = args.first();
    const bool verbose = parser.isSet(verboseOption);
    const bool statsOnly = parser.isSet(statsOnlyOption);
    const int limit = parser.isSet(limitOption) ? parser.value(limitOption).toInt() : -1;
    
    // Check file exists
    QFileInfo fileInfo(inputFile);
    if (!fileInfo.exists()) {
        out << "Error: File not found: " << inputFile << "\n";
        return 1;
    }
    
    out << "LargeScalePcapAnalyzer CLI Tool v0.1.0\n";
    out << "======================================\n\n";
    out << "Opening file: " << inputFile << "\n";
    
    // Create packet source
    QString error;
    auto packetSource = createPacketSource(inputFile, error);
    if (!packetSource) {
        out << "Error: " << error << "\n";
        return 1;
    }
    
    // Open the file
    if (!packetSource->open(error)) {
        out << "Error opening file: " << error << "\n";
        return 1;
    }
    
    const auto metadata = packetSource->getMetadata();
    out << "File type: " << (metadata.isPcapNg ? "PCAP-NG" : "PCAP") << "\n";
    out << "File size: " << metadata.fileSize << " bytes\n";
    out << "Link type: " << metadata.linkType << "\n\n";
    
    // Create index and indexer
    auto index = std::make_shared<PacketIndex>();
    IndexBuilder indexer;
    
    QElapsedTimer timer;
    timer.start();
    
    // Connect progress signal
    QObject::connect(&indexer, &IndexBuilder::progressUpdated,
                     [&printProgress](const IndexingProgress& progress) {
        printProgress(progress);
    });
    
    QObject::connect(&indexer, &IndexBuilder::indexingComplete,
                     [&out](const CaptureFileMetadata& meta, uint64_t packetCount) {
        Q_UNUSED(meta);
        Q_UNUSED(packetCount);
        // Completion handled in main loop
    });
    
    QObject::connect(&indexer, &IndexBuilder::indexingFailed,
                     [&out](const QString& errorMsg) {
        out << "\nError during indexing: " << errorMsg << "\n";
        QCoreApplication::exit(1);
    });
    
    out << "Starting indexing...\n";
    
    // Start indexing (this runs in background thread)
    if (!indexer.startIndexing(std::move(packetSource), index)) {
        out << "Error: Failed to start indexing\n";
        return 1;
    }
    
    // Wait for completion (in real app this would be event-driven)
    while (indexer.isIndexing()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    }
    
    const quint64 indexingTimeMs = timer.elapsed();
    printProgress(indexer.getProgress(), true);
    
    out << "\n\nIndexing complete!\n";
    
    // Print summary
    printSummary(metadata, *index, indexingTimeMs);
    
    // Print packet listing if requested
    if (verbose && !statsOnly) {
        out << "\nPacket Listing (first 100 packets):\n";
        out << "--------------------------------------------------------------------------------\n";
        out << QString().sprintf("%6s %-20s %-20s %-20s %-6s %6s %6s %6s\n",
                                 "No.", "Time", "Source", "Destination", "Proto", "Sport", "Dport", "Len");
        out << "--------------------------------------------------------------------------------\n";
        
        const int maxPackets = (limit > 0) ? std::min(limit, 100) : 100;
        for (int i = 0; i < std::min(static_cast<int>(index->packetCount()), maxPackets); ++i) {
            if (const auto* entry = index->getEntryByIndex(i)) {
                printPacketEntry(*entry, i + 1);
            }
        }
        
        if (index->packetCount() > static_cast<std::size_t>(maxPackets)) {
            out << "... and " << (index->packetCount() - maxPackets) << " more packets\n";
        }
    }
    
    // Save index to file if requested
    if (parser.isSet(outputOption)) {
        const QString outputFile = parser.value(outputOption);
        out << "\nSaving index to: " << outputFile << "\n";
        // TODO: Implement PersistentIndexStore
        out << "Note: Index persistence not yet implemented in this demo.\n";
    }
    
    return 0;
}
