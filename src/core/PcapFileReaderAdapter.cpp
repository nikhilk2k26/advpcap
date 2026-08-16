#include "core/PcapFileReaderAdapter.h"
#include <QFileInfo>
#include <QDataStream>
#include <QtEndian>

namespace pcap_analyzer::core {

// PCAP magic numbers
static constexpr uint32_t MagicNative = 0xA1B2C3D4;      // Native byte order
static constexpr uint32_t MagicSwapped = 0xD4C3B2A1;     // Swapped byte order
static constexpr uint32_t MagicNativeMicro = 0xA1B23C4D; // Nanosecond resolution (native)
static constexpr uint32_t MagicSwappedMicro = 0x4D3CB2A1;// Nanosecond resolution (swapped)

PcapFileReaderAdapter::PcapFileReaderAdapter(const QString& filePath)
    : m_filePath(filePath)
{
    m_metadata.filePath = filePath;
    m_metadata.fileName = QFileInfo(filePath).fileName();
}

PcapFileReaderAdapter::~PcapFileReaderAdapter()
{
    close();
}

bool PcapFileReaderAdapter::open(QString& error)
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
    
    // Read and validate global header
    bool isSwapped = false;
    auto header = readGlobalHeader(m_file, isSwapped, error);
    if (!error.isEmpty()) {
        m_file.close();
        return false;
    }
    
    m_metadata.fileSize = static_cast<uint64_t>(m_file.size());
    m_metadata.linkType = header.network;
    m_metadata.snapLen = header.snapLen;
    m_metadata.isPcapNg = false;
    m_metadata.lastModified = QFileInfo(m_file).lastModified();
    
    // Store timezone info
    if (header.thisZone != 0) {
        // TODO: Convert timezone offset to string
        m_metadata.timezone = "UTC+/-" + QString::number(header.thisZone / 3600);
    }
    
    m_isOpen = true;
    return true;
}

void PcapFileReaderAdapter::close()
{
    if (m_file.isOpen()) {
        m_file.close();
    }
    m_isOpen = false;
}

bool PcapFileReaderAdapter::isOpen() const
{
    return m_isOpen && m_file.isOpen();
}

CaptureFileMetadata PcapFileReaderAdapter::getMetadata() const
{
    return m_metadata;
}

bool PcapFileReaderAdapter::readPacketHeader(
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
    
    PcapPacketHeader pktHeader;
    if (m_file.read(reinterpret_cast<char*>(&pktHeader), sizeof(pktHeader)) != sizeof(pktHeader)) {
        error = "Failed to read packet header - file may be truncated";
        headerOut.isValid = false;
        return false;
    }
    
    // Note: We don't swap here - byte order is determined by global header
    // For a full implementation, we'd need to track byte order per file
    
    headerOut.fileOffset = fileOffset;
    headerOut.timestampNs = (static_cast<uint64_t>(pktHeader.tsSec) * 1000000000ULL) 
                          + (static_cast<uint64_t>(pktHeader.tsUsec) * 1000ULL);
    headerOut.capturedLength = pktHeader.inclLen;
    headerOut.originalLength = pktHeader.origLen;
    headerOut.linkType = static_cast<uint16_t>(m_metadata.linkType);
    headerOut.interfaceId = 0;  // PCAP doesn't have interface IDs
    headerOut.sectionId = 0;
    headerOut.isValid = true;
    
    return true;
}

bool PcapFileReaderAdapter::readPacketData(
    uint64_t fileOffset,
    QByteArray& dataOut,
    QString& error)
{
    if (!m_isOpen) {
        error = "File not open";
        return false;
    }
    
    // First read the packet header to get the length
    PacketHeaderInfo headerInfo;
    if (!readPacketHeader(fileOffset, headerInfo, error)) {
        return false;
    }
    
    // Seek past the header to the packet data
    const auto dataOffset = fileOffset + sizeof(PcapPacketHeader);
    if (!m_file.seek(static_cast<qint64>(dataOffset))) {
        error = "Failed to seek to packet data";
        return false;
    }
    
    // Sanity check on packet length
    if (headerInfo.capturedLength > 100 * 1024 * 1024) {  // 100 MB max
        error = QStringLiteral("Packet length %1 exceeds maximum").arg(headerInfo.capturedLength);
        return false;
    }
    
    dataOut = m_file.read(static_cast<qint64>(headerInfo.capturedLength));
    
    if (static_cast<uint32_t>(dataOut.size()) != headerInfo.capturedLength) {
        error = "Failed to read complete packet data - file may be truncated";
        return false;
    }
    
    return true;
}

uint64_t PcapFileReaderAdapter::getFileSize() const
{
    return m_metadata.fileSize;
}

bool PcapFileReaderAdapter::supportsRandomAccess() const
{
    return true;  // PCAP files support random access by offset
}

bool PcapFileReaderAdapter::isLittleEndian() const
{
    union {
        uint32_t i;
        char c[4];
    } test = {0x01020304};
    return test.c[0] == 0x04;
}

bool PcapFileReaderAdapter::validateMagicNumber(uint32_t magic) const
{
    return (magic == MagicNative || magic == MagicSwapped ||
            magic == MagicNativeMicro || magic == MagicSwappedMicro);
}

PcapFileReaderAdapter::PcapGlobalHeader PcapFileReaderAdapter::readGlobalHeader(
    QIODevice& device, bool& isSwapped, QString& error)
{
    PcapGlobalHeader header{};
    
    if (device.read(reinterpret_cast<char*>(&header.magicNumber), sizeof(header.magicNumber)) 
        != sizeof(header.magicNumber)) {
        error = "Failed to read PCAP magic number - file may be empty or corrupted";
        return header;
    }
    
    // Check magic number and determine byte order
    if (header.magicNumber == MagicNative || header.magicNumber == MagicNativeMicro) {
        isSwapped = false;
    } else if (header.magicNumber == MagicSwapped || header.magicNumber == MagicSwappedMicro) {
        isSwapped = true;
    } else {
        error = QStringLiteral("Invalid PCAP magic number: 0x%1").arg(header.magicNumber, 8, 16, QChar('0'));
        return header;
    }
    
    // Read remaining header fields
    const auto remainingSize = sizeof(PcapGlobalHeader) - sizeof(header.magicNumber);
    if (device.read(reinterpret_cast<char*>(&header.versionMajor), remainingSize) 
        != static_cast<qint64>(remainingSize)) {
        error = "Failed to read PCAP global header - file may be truncated";
        return header;
    }
    
    // Swap bytes if needed
    if (isSwapped) {
        header.versionMajor = qFromBigEndian(header.versionMajor);
        header.versionMinor = qFromBigEndian(header.versionMinor);
        header.thisZone = qFromBigEndian(header.thisZone);
        header.sigFigs = qFromBigEndian(header.sigFigs);
        header.snapLen = qFromBigEndian(header.snapLen);
        header.network = qFromBigEndian(header.network);
    }
    
    // Validate version
    if (header.versionMajor != 2 || header.versionMinor > 4) {
        error = QStringLiteral("Unsupported PCAP version: %1.%2")
                    .arg(header.versionMajor)
                    .arg(header.versionMinor);
        return header;
    }
    
    return header;
}

} // namespace pcap_analyzer::core
