#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <memory>
#include "core/PacketIndex.h"
#include "core/CaptureFileReader.h"

namespace pcap_analyzer::core {

/**
 * @brief Persistent index storage using SQLite
 * 
 * Saves and loads packet indexes to/from disk.
 * Validates index against source file using hash and metadata.
 */
class PersistentIndexStore : public QObject
{
    Q_OBJECT
    
public:
    explicit PersistentIndexStore(QObject* parent = nullptr);
    ~PersistentIndexStore() override;
    
    /**
     * @brief Get the default index file path for a capture file
     * @param captureFilePath Path to the capture file
     * @return Path to the index file
     */
    [[nodiscard]] static QString getDefaultIndexPath(const QString& captureFilePath);
    
    /**
     * @brief Check if a valid persisted index exists for a capture file
     * @param captureFilePath Path to the capture file
     * @param captureFileSize Size of the capture file
     * @param captureFileHash Hash of the capture file
     * @return True if valid index exists
     */
    [[nodiscard]] bool hasValidIndex(
        const QString& captureFilePath,
        uint64_t captureFileSize,
        const QByteArray& captureFileHash) const;
    
    /**
     * @brief Load index from persistent storage
     * @param indexPath Path to the index file
     * @param index Output index to populate
     * @param error Output parameter for error message
     * @return True if successful
     */
    [[nodiscard]] bool loadIndex(
        const QString& indexPath,
        std::shared_ptr<PacketIndex> index,
        QString& error) const;
    
    /**
     * @brief Save index to persistent storage
     * @param indexPath Path to the index file
     * @param index Index to save
     * @param metadata Source file metadata
     * @param error Output parameter for error message
     * @return True if successful
     */
    [[nodiscard]] bool saveIndex(
        const QString& indexPath,
        const PacketIndex& index,
        const CaptureFileMetadata& metadata,
        QString& error) const;
    
    /**
     * @brief Delete persisted index
     * @param indexPath Path to the index file
     * @return True if deleted or didn't exist
     */
    [[nodiscard]] static bool deleteIndex(const QString& indexPath);
    
    /**
     * @brief Compute SHA-256 hash of a file (first 1MB + last 1MB for large files)
     * @param filePath Path to file
     * @return File hash
     */
    [[nodiscard]] static QByteArray computeFileHash(const QString& filePath);
    
    /**
     * @brief Get index format version
     */
    [[nodiscard]] static constexpr int getIndexFormatVersion() { return 1; }
    
private:
    struct IndexHeader
    {
        uint32_t magic = 0x50434150;  // "PCAP"
        uint32_t version = 1;
        uint64_t timestamp = 0;
        uint64_t sourceFileSize = 0;
        uint32_t packetCount = 0;
        char sourceFileName[256] = {};
        char sourceFileHash[64] = {};
        char appVersion[32] = {};
        uint32_t checksum = 0;
    };
    
    [[nodiscard]] static uint32_t calculateChecksum(const IndexHeader& header);
    [[nodiscard]] bool validateChecksum(const IndexHeader& header) const;
};

} // namespace pcap_analyzer::core
