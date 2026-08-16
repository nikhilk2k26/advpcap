#pragma once

#include <QObject>
#include <QString>
#include <QDateTime>
#include <memory>
#include <optional>
#include "core/ProtocolSummary.h"

namespace pcap_analyzer::core {

class PacketIndex;

/**
 * @brief Metadata about a loaded capture file
 */
struct CaptureFileMetadata
{
    QString filePath;
    QString fileName;
    uint64_t fileSize = 0;
    QDateTime lastModified;
    
    // Capture-specific metadata
    uint32_t linkType = 0;
    uint32_t snapLen = 65535;
    std::string timezone = "UTC";
    
    // PCAP-NG specific
    bool isPcapNg = false;
    uint32_t sectionCount = 0;
    uint32_t interfaceCount = 0;
    QString applicationName;      // From pcapng Section Header
    QString applicationComment;   // From pcapng Section Header
    
    // Statistics
    uint64_t packetCount = 0;
    uint64_t totalBytes = 0;
    std::optional<uint64_t> firstTimestampNs;
    std::optional<uint64_t> lastTimestampNs;
    
    // Validation
    QByteArray fileHash;          // SHA-256 or partial hash
    QString hashAlgorithm = "sha256";
};

/**
 * @brief Abstract interface for packet sources (offline files or future live capture)
 */
class IPacketSource
{
public:
    virtual ~IPacketSource() = default;
    
    /**
     * @brief Open the packet source
     * @param error Output parameter for error message
     * @return True if successful
     */
    [[nodiscard]] virtual bool open(QString& error) = 0;
    
    /**
     * @brief Close the packet source
     */
    virtual void close() = 0;
    
    /**
     * @brief Check if source is open
     */
    [[nodiscard]] virtual bool isOpen() const = 0;
    
    /**
     * @brief Get metadata about the capture file
     */
    [[nodiscard]] virtual CaptureFileMetadata getMetadata() const = 0;
    
    /**
     * @brief Read packet header at specified offset
     * @param fileOffset Byte offset in file
     * @param headerOut Output parameter for packet header info
     * @param error Output parameter for error message
     * @return True if successful
     */
    [[nodiscard]] virtual bool readPacketHeader(
        uint64_t fileOffset,
        struct PacketHeaderInfo& headerOut,
        QString& error) = 0;
    
    /**
     * @brief Read full packet data at specified offset
     * @param fileOffset Byte offset in file
     * @param dataOut Output buffer for packet data
     * @param error Output parameter for error message
     * @return True if successful
     */
    [[nodiscard]] virtual bool readPacketData(
        uint64_t fileOffset,
        QByteArray& dataOut,
        QString& error) = 0;
    
    /**
     * @brief Get file size
     */
    [[nodiscard]] virtual uint64_t getFileSize() const = 0;
    
    /**
     * @brief Check if random access by offset is supported
     */
    [[nodiscard]] virtual bool supportsRandomAccess() const = 0;
};

/**
 * @brief Factory function to create appropriate packet source based on file type
 * @param filePath Path to capture file
 * @param error Output parameter for error message
 * @return Unique pointer to IPacketSource, or nullptr on failure
 */
[[nodiscard]] std::unique_ptr<IPacketSource> createPacketSource(const QString& filePath, QString& error);

/**
 * @brief Packet header information extracted from file
 */
struct PacketHeaderInfo
{
    uint64_t fileOffset = 0;
    uint64_t timestampNs = 0;
    uint32_t capturedLength = 0;
    uint32_t originalLength = 0;
    uint16_t linkType = 0;
    uint16_t interfaceId = 0;      // For PCAP-NG
    uint8_t sectionId = 0;         // For PCAP-NG
    bool isValid = false;
    QString errorMessage;
};

} // namespace pcap_analyzer::core
