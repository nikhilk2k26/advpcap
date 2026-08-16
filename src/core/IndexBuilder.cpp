#include "core/IndexBuilder.h"
#include <QFile>
#include <QElapsedTimer>
#include <QtConcurrent>

namespace pcap_analyzer::core {

IndexBuilder::IndexBuilder(QObject* parent)
    : QObject(parent)
{
}

IndexBuilder::~IndexBuilder()
{
    cancel();
}

bool IndexBuilder::startIndexing(
    std::unique_ptr<IPacketSource> packetSource,
    std::shared_ptr<PacketIndex> index)
{
    if (!packetSource || !index) {
        return false;
    }
    
    if (m_isIndexing.load()) {
        return false;  // Already indexing
    }
    
    m_packetSource = std::move(packetSource);
    m_index = index;
    m_cancelRequested.store(0);
    
    // Reset progress
    m_progress = IndexingProgress{};
    m_progress.currentStatus = "Initializing...";
    
    m_isIndexing.store(1);
    
    // Start background indexing using QtConcurrent
    QtConcurrent::run([this]() {
        runIndexing();
    });
    
    return true;
}

void IndexBuilder::cancel()
{
    m_cancelRequested.store(1);
}

bool IndexBuilder::isIndexing() const
{
    return m_isIndexing.load();
}

bool IndexBuilder::wasCancelled() const
{
    return m_progress.wasCancelled;
}

IndexingProgress IndexBuilder::getProgress() const
{
    return m_progress;
}

void IndexBuilder::setBatchSize(int batchSize)
{
    if (batchSize > 0) {
        m_batchSize = batchSize;
    }
}

uint64_t IndexBuilder::estimatePacketCount(uint64_t fileSize, uint16_t linkType)
{
    // Rough estimate based on average packet sizes
    // Ethernet packets average around 500-600 bytes including headers
    // PCAP adds 16 bytes per packet header
    // PCAP-NG adds more overhead (~32-40 bytes per packet)
    
    constexpr uint64_t AveragePacketSize = 550;
    constexpr uint64_t PcapHeaderOverhead = 16;
    constexpr uint64_t PcapNgHeaderOverhead = 40;
    
    const uint64_t overhead = (linkType == 0) ? PcapNgHeaderOverhead : PcapHeaderOverhead;
    const uint64_t totalPerPacket = AveragePacketSize + overhead;
    
    if (totalPerPacket == 0) {
        return 0;
    }
    
    return fileSize / totalPerPacket;
}

void IndexBuilder::runIndexing()
{
    QElapsedTimer timer;
    timer.start();
    
    QString error;
    if (!m_packetSource->open(error)) {
        m_progress.errorMessage = error;
        m_progress.wasCancelled = false;
        m_progress.isComplete = true;
        m_isIndexing.store(0);
        emit indexingFailed(error);
        return;
    }
    
    const auto metadata = m_packetSource->getMetadata();
    m_progress.totalBytes = metadata.fileSize;
    m_progress.totalPacketsEstimated = estimatePacketCount(metadata.fileSize, 
                                                            static_cast<uint16_t>(metadata.linkType));
    m_progress.currentStatus = "Scanning packets...";
    
    // Reserve space in index for efficiency
    m_index->reserve(static_cast<std::size_t>(m_progress.totalPacketsEstimated * 0.8));
    
    uint64_t offset = 0;
    uint64_t packetId = 0;
    QVector<PacketIndexEntry> batchEntries;
    batchEntries.reserve(m_batchSize);
    
    // Track file position for progress reporting
    uint64_t lastKnownPosition = 0;
    
    while (!m_cancelRequested.load()) {
        PacketHeaderInfo headerInfo;
        
        if (!m_packetSource->readPacketHeader(offset, headerInfo, error)) {
            // End of file or error
            if (!headerInfo.isValid) {
                // Check if it's just end of file (expected)
                if (error.contains("truncated", Qt::CaseInsensitive) || 
                    error.contains("offset", Qt::CaseInsensitive) ||
                    error.contains("seek", Qt::CaseInsensitive)) {
                    // Graceful end - file may be truncated
                    break;
                }
                // Real error during read
                m_progress.errorMessage = error;
                m_progress.wasCancelled = false;
                m_progress.isComplete = true;
                m_isIndexing.store(0);
                emit indexingFailed(error);
                return;
            }
        }
        
        // Read minimal packet data for protocol detection
        QByteArray packetData;
        const size_t minReadSize = std::min(static_cast<size_t>(headerInfo.capturedLength), 
                                             static_cast<size_t>(128));  // First 128 bytes usually enough
        
        if (!m_packetSource->readPacketData(offset, packetData, error)) {
            // Try to continue with partial data
            packetData.clear();
        }
        
        // Build index entry
        PacketIndexEntry entry;
        entry.packetId = ++packetId;
        entry.fileOffset = offset;
        entry.timestampNs = headerInfo.timestampNs;
        entry.capturedLength = headerInfo.capturedLength;
        entry.originalLength = headerInfo.originalLength;
        entry.linkType = headerInfo.linkType;
        entry.interfaceId = headerInfo.interfaceId;
        entry.sectionId = headerInfo.sectionId;
        
        // Detect protocol summary from packet data
        uint8_t ipVersion = 0;
        uint8_t transportProto = 0;
        std::array<uint8_t, 16> srcIp{};
        std::array<uint8_t, 16> dstIp{};
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        uint8_t tcpFlags = 0;
        uint16_t etherType = 0;
        
        entry.protocolSummary = static_cast<uint8_t>(detectProtocolSummary(
            packetData, headerInfo.linkType, ipVersion, transportProto,
            srcIp, dstIp, srcPort, dstPort, tcpFlags, etherType));
        
        entry.ipVersion = ipVersion;
        entry.transportProtocol = transportProto;
        entry.srcIp = srcIp;
        entry.dstIp = dstIp;
        entry.srcPort = srcPort;
        entry.dstPort = dstPort;
        entry.tcpFlags = tcpFlags;
        entry.etherType = etherType;
        
        batchEntries.append(entry);
        
        // Update progress - calculate based on offset and estimated packet size
        lastKnownPosition = offset + sizeof(PacketHeaderInfo) + headerInfo.capturedLength;
        m_progress.bytesProcessed = std::min(lastKnownPosition, m_progress.totalBytes);
        m_progress.packetsIndexed = packetId;
        m_progress.percentComplete = (m_progress.totalBytes > 0)
            ? (static_cast<double>(m_progress.bytesProcessed) / m_progress.totalBytes * 100.0)
            : 0.0;
        
        // Emit progress periodically
        if (packetId % static_cast<uint64_t>(m_batchSize) == 0) {
            m_index->addEntries(batchEntries);
            batchEntries.clear();
            
            emit progressUpdated(m_progress);
        }
        
        // Move to next packet
        // For PCAP: offset += 16 (packet header) + capturedLength
        // For PCAP-NG: offset varies by block type
        // We use a simplified approach - the reader handles the complexity
        offset += 16 + headerInfo.capturedLength;  // PCAP-style calculation as baseline
        
        // Safety check: don't go past file end
        if (offset >= m_progress.totalBytes) {
            break;
        }
    }
    
    // Add remaining entries
    if (!batchEntries.isEmpty()) {
        m_index->addEntries(batchEntries);
    }
    
    // Finalize
    m_progress.isComplete = true;
    m_progress.wasCancelled = m_cancelRequested.load() != 0;
    m_progress.currentStatus = m_progress.wasCancelled ? "Cancelled" : "Complete";
    
    m_isIndexing.store(0);
    
    if (m_progress.wasCancelled) {
        emit indexingCancelled();
    } else {
        emit indexingComplete(metadata, packetId);
    }
}

bool IndexBuilder::buildIndexEntry(
    const PacketHeaderInfo& header,
    const QByteArray& packetData,
    PacketIndexEntry& entry,
    QString& error)
{
    // This method is kept for compatibility but the logic is now inline in runIndexing
    Q_UNUSED(header)
    Q_UNUSED(packetData)
    Q_UNUSED(entry)
    Q_UNUSED(error)
    return true;
}

ProtocolSummary IndexBuilder::detectProtocolSummary(
    const QByteArray& packetData,
    uint16_t linkType,
    uint8_t& ipVersion,
    uint8_t& transportProto,
    std::array<uint8_t, 16>& srcIp,
    std::array<uint8_t, 16>& dstIp,
    uint16_t& srcPort,
    uint16_t& dstPort,
    uint8_t& tcpFlags,
    uint16_t& etherType)
{
    if (packetData.isEmpty()) {
        return ProtocolSummary::Unknown;
    }
    
    const auto* data = reinterpret_cast<const uint8_t*>(packetData.constData());
    const auto len = static_cast<size_t>(packetData.size());
    
    size_t offset = 0;
    
    // Handle different link types
    switch (linkType) {
        case 1:  // DLT_EN10MB (Ethernet)
            if (len < 14) {
                return ProtocolSummary::Unknown;
            }
            etherType = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + 12));
            offset = 14;
            
            // Check for VLAN tagging (802.1Q)
            if (etherType == 0x8100 && len >= 18) {
                etherType = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + 16));
                offset = 18;
            }
            break;
            
        case 102:  // DLT_RAW (Raw IP)
        case 228:  // DLT_IPV4
        case 229:  // DLT_IPV6
            offset = 0;
            break;
            
        default:
            // Unknown link type - try raw IP
            offset = 0;
            break;
    }
    
    // Parse IP header
    if (offset >= len) {
        return ProtocolSummary::Ethernet;
    }
    
    const uint8_t ipFirstByte = data[offset];
    const uint8_t ipVersionLocal = (ipFirstByte >> 4) & 0x0F;
    
    if (ipVersionLocal == 4 && len >= offset + 20) {
        // IPv4
        ipVersion = 4;
        transportProto = data[offset + 9];
        
        // Source and destination IP (4 bytes each)
        std::memcpy(srcIp.data(), data + offset + 12, 4);
        std::memcpy(dstIp.data(), data + offset + 16, 4);
        
        const uint8_t ihl = (ipFirstByte & 0x0F) * 4;
        const size_t ipHeaderEnd = offset + ihl;
        
        if (transportProto == 6 && len >= ipHeaderEnd + 4) {
            // TCP
            srcPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd));
            dstPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd + 2));
            tcpFlags = data[ipHeaderEnd + 13];
            return ProtocolSummary::Tcp;
        } else if (transportProto == 17 && len >= ipHeaderEnd + 4) {
            // UDP
            srcPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd));
            dstPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd + 2));
            
            // Check for DNS (port 53)
            if (srcPort == 53 || dstPort == 53) {
                return ProtocolSummary::Dns;
            }
            return ProtocolSummary::Udp;
        } else if (transportProto == 1) {
            return ProtocolSummary::Icmp;
        }
        
        return ProtocolSummary::Ipv4;
        
    } else if (ipVersionLocal == 6 && len >= offset + 40) {
        // IPv6
        ipVersion = 6;
        transportProto = data[offset + 6];
        
        // Source and destination IP (16 bytes each)
        std::memcpy(srcIp.data(), data + offset + 8, 16);
        std::memcpy(dstIp.data(), data + offset + 24, 16);
        
        const size_t ipHeaderEnd = offset + 40;
        
        if (transportProto == 6 && len >= ipHeaderEnd + 4) {
            // TCP
            srcPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd));
            dstPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd + 2));
            tcpFlags = data[ipHeaderEnd + 13];
            return ProtocolSummary::Tcp;
        } else if (transportProto == 17 && len >= ipHeaderEnd + 4) {
            // UDP
            srcPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd));
            dstPort = qFromBigEndian(*reinterpret_cast<const uint16_t*>(data + ipHeaderEnd + 2));
            
            if (srcPort == 53 || dstPort == 53) {
                return ProtocolSummary::Dns;
            }
            return ProtocolSummary::Udp;
        } else if (transportProto == 58) {
            return ProtocolSummary::Icmpv6;
        }
        
        return ProtocolSummary::Ipv6;
    }
    
    // No valid IP header found
    if (etherType == 0x0800) {
        return ProtocolSummary::Ipv4;
    } else if (etherType == 0x86DD) {
        return ProtocolSummary::Ipv6;
    } else if (etherType == 0x0806) {
        return ProtocolSummary::Arp;
    }
    
    return ProtocolSummary::Ethernet;
}

} // namespace pcap_analyzer::core
