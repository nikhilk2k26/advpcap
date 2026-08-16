#include "core/PcapngFileReaderAdapter.h"
#include <QFileInfo>
#include <QDataStream>
#include <QtEndian>
#include <QBuffer>
#include <functional>

namespace pcap_analyzer::core {

// PCAP-NG magic number for section header
static constexpr uint32_t PcapNgMagic = 0x1A2B3C4D;
static constexpr uint32_t PcapNgMagicSwapped = 0x4D3C2B1A;

PcapngFileReaderAdapter::PcapngFileReaderAdapter(const QString& filePath)
    : m_filePath(filePath)
{
    m_metadata.filePath = filePath;
    m_metadata.fileName = QFileInfo(filePath).fileName();
    m_metadata.isPcapNg = true;
}

PcapngFileReaderAdapter::~PcapngFileReaderAdapter()
{
    close();
}

bool PcapngFileReaderAdapter::open(QString& error)
{
    if (m_isOpen) {
        error = "File already open";
        return false;
    }
    
    m_file.setFileName(m_filePath);
    
    if (!m_file.exists()) {
        error = QStringLiteral("File not found: %1").arg(m_filePath);
        return false;
    }
    
    if (!m_file.open(QIODevice::ReadOnly)) {
        error = m_file.errorString();
        return false;
    }
    
    m_metadata.fileSize = static_cast<uint64_t>(m_file.size());
    m_metadata.lastModified = QFileInfo(m_file).lastModified();
    
    // Parse the first section header to validate file
    QDataStream stream(&m_file);
    stream.setByteOrder(QDataStream::LittleEndian);
    
    if (!parseSectionHeader(stream, error)) {
        m_file.close();
        return false;
    }
    
    // Continue parsing to find all interfaces in the first section
    // In a full implementation, we'd scan the entire file here
    // For now, we'll parse interfaces on-demand during packet reading
    
    m_isOpen = true;
    return true;
}

void PcapngFileReaderAdapter::close()
{
    if (m_file.isOpen()) {
        m_file.close();
    }
    m_isOpen = false;
    m_interfaces.clear();
}

bool PcapngFileReaderAdapter::isOpen() const
{
    return m_isOpen && m_file.isOpen();
}

CaptureFileMetadata PcapngFileReaderAdapter::getMetadata() const
{
    return m_metadata;
}

bool PcapngFileReaderAdapter::readPacketHeader(
    uint64_t fileOffset,
    PacketHeaderInfo& headerOut,
    QString& error)
{
    if (!m_isOpen) {
        error = "File not open";
        return false;
    }
    
    if (!m_file.seek(static_cast<qint64>(fileOffset))) {
        error = QStringLiteral("Failed to seek to offset %1").arg(fileOffset);
        return false;
    }
    
    QDataStream stream(&m_file);
    stream.setByteOrder(QDataStream::LittleEndian);
    
    // Read block type
    uint32_t blockType = 0;
    stream >> blockType;
    
    // Read total length
    uint32_t totalLength = 0;
    stream >> totalLength;
    
    if (totalLength < 8 || totalLength > 100 * 1024 * 1024) {
        error = QStringLiteral("Invalid block length: %1").arg(totalLength);
        return false;
    }
    
    switch (blockType) {
        case BlockTypeEnhancedPacket:
            return parseEnhancedPacketBlock(stream, fileOffset, headerOut, error);
            
        case BlockTypeSimplePacket:
            return parseSimplePacketBlock(stream, fileOffset, headerOut, error);
            
        default:
            error = QStringLiteral("Unexpected block type at offset %1: 0x%2")
                        .arg(fileOffset).arg(blockType, 8, 16, QChar('0'));
            return false;
    }
}

bool PcapngFileReaderAdapter::readPacketData(
    uint64_t fileOffset,
    QByteArray& dataOut,
    QString& error)
{
    if (!m_isOpen) {
        error = "File not open";
        return false;
    }
    
    PacketHeaderInfo headerInfo;
    if (!readPacketHeader(fileOffset, headerInfo, error)) {
        return false;
    }
    
    // Calculate data offset (after block header)
    // Enhanced Packet Block header: blockType(4) + totalLen(4) + ifaceId(4) + 
    // timestampHi(4) + timestampLo(4) + capLen(4) + origLen(4) = 28 bytes
    const uint64_t dataOffset = fileOffset + 28;
    
    if (!m_file.seek(static_cast<qint64>(dataOffset))) {
        error = "Failed to seek to packet data";
        return false;
    }
    
    dataOut = m_file.read(static_cast<qint64>(headerInfo.capturedLength));
    
    if (static_cast<uint32_t>(dataOut.size()) != headerInfo.capturedLength) {
        error = "Failed to read complete packet data - file may be truncated";
        return false;
    }
    
    return true;
}

uint64_t PcapngFileReaderAdapter::getFileSize() const
{
    return m_metadata.fileSize;
}

bool PcapngFileReaderAdapter::supportsRandomAccess() const
{
    return true;
}

std::optional<PcapNgInterfaceInfo> PcapngFileReaderAdapter::getInterfaceInfo(uint16_t interfaceId) const
{
    auto it = m_interfaces.find(interfaceId);
    if (it != m_interfaces.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<PcapNgSectionInfo> PcapngFileReaderAdapter::getSectionInfo(uint8_t sectionId) const
{
    if (sectionId == m_currentSection.sectionId) {
        return m_currentSection;
    }
    return std::nullopt;
}

std::vector<uint16_t> PcapngFileReaderAdapter::getAllInterfaceIds() const
{
    std::vector<uint16_t> ids;
    ids.reserve(m_interfaces.size());
    for (const auto& [id, info] : m_interfaces) {
        ids.push_back(id);
    }
    return ids;
}

bool PcapngFileReaderAdapter::parseSectionHeader(QDataStream& stream, QString& error)
{
    // Already read block type and total length
    uint32_t byteOrderMagic = 0;
    stream >> byteOrderMagic;
    
    bool needsSwap = false;
    if (byteOrderMagic == PcapNgMagicSwapped) {
        needsSwap = true;
        stream.setByteOrder(QDataStream::BigEndian);
    } else if (byteOrderMagic != PcapNgMagic) {
        error = QStringLiteral("Invalid PCAP-NG section header magic: 0x%1")
                    .arg(byteOrderMagic, 8, 16, QChar('0'));
        return false;
    }
    
    m_currentSection.byteOrderMagic = byteOrderMagic;
    
    // Read version
    stream >> m_currentSection.majorVersion;
    stream >> m_currentSection.minorVersion;
    
    if (needsSwap) {
        m_currentSection.majorVersion = swapByteOrder(m_currentSection.majorVersion, true);
        m_currentSection.minorVersion = swapByteOrder(m_currentSection.minorVersion, true);
    }
    
    // Read section length (can be -1 for endless)
    int64_t sectionLength = 0;
    stream >> sectionLength;
    if (needsSwap) {
        sectionLength = static_cast<int64_t>(swapByteOrder(static_cast<uint32_t>(sectionLength & 0xFFFFFFFF), true));
    }
    m_currentSection.sectionLength = sectionLength;
    
    // Read options
    const auto readOptionsFunc = [this, needsSwap](uint16_t code, uint16_t len, const QByteArray& value) {
        switch (code) {
            case OptSHBHardware:
                m_currentSection.hardwareId = value;
                break;
            case OptSHBOS:
                m_currentSection.applicationName = QString::fromUtf8(value);
                break;
            case OptSHBUserApp:
                m_currentSection.applicationComment = QString::fromUtf8(value);
                break;
            default:
                break;
        }
    };
    
    QString optError;
    if (!readOptions(stream, readOptionsFunc, optError)) {
        error = optError;
        return false;
    }
    
    m_currentSection.sectionId = 0;  // First section
    m_metadata.sectionCount = 1;
    m_metadata.applicationName = m_currentSection.applicationName;
    m_metadata.applicationComment = m_currentSection.applicationComment;
    
    return true;
}

bool PcapngFileReaderAdapter::parseInterfaceDescription(QDataStream& stream, QString& error)
{
    PcapNgInterfaceInfo ifaceInfo;
    
    stream >> ifaceInfo.interfaceId;
    stream >> ifaceInfo.linkType;
    
    // Reserved bytes
    uint16_t reserved = 0;
    stream >> reserved;
    
    uint32_t snapLen = 0;
    stream >> snapLen;
    ifaceInfo.snapLen = snapLen;
    
    // Read options
    const auto readOptionsFunc = [&ifaceInfo](uint16_t code, uint16_t len, const QByteArray& value) {
        switch (code) {
            case OptIfName:
                ifaceInfo.name = QString::fromUtf8(value);
                break;
            case OptIfDescription:
                ifaceInfo.description = QString::fromUtf8(value);
                break;
            case OptIfTSResol:
                if (!value.isEmpty()) {
                    uint8_t resolution = static_cast<uint8_t>(value[0]);
                    if (resolution & 0x80) {
                        // Resolution is 2^(-resolution) nanoseconds
                        resolution &= 0x7F;
                        ifaceInfo.timestampResolution = 1ULL << (64 - resolution);
                    } else {
                        // Resolution is 10^(-resolution) seconds
                        ifaceInfo.timestampResolution = 1;
                        for (int i = 0; i < resolution; ++i) {
                            ifaceInfo.timestampResolution *= 10;
                        }
                    }
                }
                break;
            default:
                break;
        }
    };
    
    QString optError;
    if (!readOptions(stream, readOptionsFunc, optError)) {
        error = optError;
        return false;
    }
    
    m_interfaces[ifaceInfo.interfaceId] = ifaceInfo;
    m_metadata.interfaceCount = static_cast<uint32_t>(m_interfaces.size());
    m_metadata.linkType = ifaceInfo.linkType;
    m_metadata.snapLen = ifaceInfo.snapLen;
    
    return true;
}

bool PcapngFileReaderAdapter::parseEnhancedPacketBlock(
    QDataStream& stream, 
    uint64_t offset,
    PacketHeaderInfo& headerOut,
    QString& error)
{
    uint32_t interfaceId = 0;
    stream >> interfaceId;
    
    uint32_t timestampHigh = 0;
    uint32_t timestampLow = 0;
    stream >> timestampHigh;
    stream >> timestampLow;
    
    uint32_t capturedLength = 0;
    stream >> capturedLength;
    
    uint32_t originalLength = 0;
    stream >> originalLength;
    
    // Validate lengths
    if (capturedLength > 100 * 1024 * 1024) {
        error = QStringLiteral("Captured length %1 exceeds maximum").arg(capturedLength);
        return false;
    }
    
    // Get interface info to determine link type and timestamp resolution
    auto ifaceIt = m_interfaces.find(interfaceId);
    uint16_t linkType = 1;  // Default to Ethernet
    uint64_t timestampResolution = 1000000000;  // Default to nanoseconds
    
    if (ifaceIt != m_interfaces.end()) {
        linkType = ifaceIt->second.linkType;
        timestampResolution = ifaceIt->second.timestampResolution;
    } else {
        // Interface not yet parsed - try to get from metadata
        linkType = static_cast<uint16_t>(m_metadata.linkType);
    }
    
    // Combine timestamps and convert to nanoseconds
    uint64_t timestampNs = (static_cast<uint64_t>(timestampHigh) << 32) | timestampLow;
    // Timestamp is already in the resolution specified by the interface
    // For simplicity, assume nanoseconds (most common)
    
    headerOut.fileOffset = offset;
    headerOut.timestampNs = timestampNs;
    headerOut.capturedLength = capturedLength;
    headerOut.originalLength = originalLength;
    headerOut.linkType = linkType;
    headerOut.interfaceId = static_cast<uint16_t>(interfaceId);
    headerOut.sectionId = m_currentSection.sectionId;
    headerOut.isValid = true;
    
    return true;
}

bool PcapngFileReaderAdapter::parseSimplePacketBlock(
    QDataStream& stream,
    uint64_t offset,
    PacketHeaderInfo& headerOut,
    QString& error)
{
    uint32_t originalLength = 0;
    stream >> originalLength;
    
    uint32_t capturedLength = originalLength;  // Simple packets have no truncation
    
    if (capturedLength > 100 * 1024 * 1024) {
        error = QStringLiteral("Captured length %1 exceeds maximum").arg(capturedLength);
        return false;
    }
    
    // Simple packet blocks don't have timestamps - use 0
    headerOut.fileOffset = offset;
    headerOut.timestampNs = 0;
    headerOut.capturedLength = capturedLength;
    headerOut.originalLength = originalLength;
    headerOut.linkType = static_cast<uint16_t>(m_metadata.linkType);
    headerOut.interfaceId = 0;
    headerOut.sectionId = m_currentSection.sectionId;
    headerOut.isValid = true;
    
    return true;
}

bool PcapngFileReaderAdapter::skipBlock(QDataStream& stream, uint32_t blockLength, QString& error)
{
    // Skip remaining bytes in block (already read type and length)
    const qint64 bytesToSkip = static_cast<qint64>(blockLength) - 8;
    if (bytesToSkip > 0) {
        if (!m_file.seek(m_file.pos() + bytesToSkip)) {
            error = "Failed to skip block";
            return false;
        }
    }
    return true;
}

bool PcapngFileReaderAdapter::readOptions(
    QDataStream& stream,
    std::function<void(uint16_t, uint16_t, const QByteArray&)> callback,
    QString& error)
{
    while (stream.status() == QDataStream::Ok) {
        uint16_t optionCode = 0;
        stream >> optionCode;
        
        if (optionCode == OptEndOfOpt) {
            // End of options - also need to skip padding to 32-bit boundary
            break;
        }
        
        uint16_t optionLength = 0;
        stream >> optionLength;
        
        if (optionLength > 0) {
            QByteArray value = m_file.read(optionLength);
            if (value.size() != static_cast<int>(optionLength)) {
                error = "Failed to read option value";
                return false;
            }
            
            callback(optionCode, optionLength, value);
            
            // Options are padded to 32-bit boundaries
            const int padding = (4 - (optionLength % 4)) % 4;
            if (padding > 0) {
                m_file.seek(m_file.pos() + padding);
            }
        }
    }
    
    return true;
}

uint32_t PcapngFileReaderAdapter::swapByteOrder(uint32_t value, bool needsSwap)
{
    return needsSwap ? qFromBigEndian(value) : value;
}

uint16_t PcapngFileReaderAdapter::swapByteOrder(uint16_t value, bool needsSwap)
{
    return needsSwap ? qFromBigEndian(value) : value;
}

} // namespace pcap_analyzer::core
