#pragma once

#include <QObject>
#include <QAtomicInt>
#include <memory>
#include "core/PacketIndex.h"
#include "core/CaptureFileReader.h"

namespace pcap_analyzer::core {

/**
 * @brief Progress information for indexing operations
 */
struct IndexingProgress
{
    uint64_t packetsIndexed = 0;
    uint64_t totalPacketsEstimated = 0;
    uint64_t bytesProcessed = 0;
    uint64_t totalBytes = 0;
    double percentComplete = 0.0;
    QString currentStatus;
    bool isComplete = false;
    bool wasCancelled = false;
    QString errorMessage;
};

/**
 * @brief Background indexer for capture files
 * 
 * Scans capture file sequentially, builds packet index without loading
 * full packet payloads. Runs in background thread.
 */
class IndexBuilder : public QObject
{
    Q_OBJECT
    
public:
    explicit IndexBuilder(QObject* parent = nullptr);
    ~IndexBuilder() override;
    
    /**
     * @brief Start indexing a capture file
     * @param packetSource Packet source to read from
     * @param index Output index to populate
     * @return True if indexing started successfully
     */
    [[nodiscard]] bool startIndexing(
        std::unique_ptr<IPacketSource> packetSource,
        std::shared_ptr<PacketIndex> index);
    
    /**
     * @brief Cancel ongoing indexing operation
     */
    void cancel();
    
    /**
     * @brief Check if indexing is currently running
     */
    [[nodiscard]] bool isIndexing() const;
    
    /**
     * @brief Check if indexing was cancelled
     */
    [[nodiscard]] bool wasCancelled() const;
    
    /**
     * @brief Get current progress
     */
    [[nodiscard]] IndexingProgress getProgress() const;
    
    /**
     * @brief Set batch size for progress updates
     * @param batchSize Number of packets to process before emitting progress
     */
    void setBatchSize(int batchSize);
    
    /**
     * @brief Estimate packet count from file size (rough estimate)
     */
    [[nodiscard]] static uint64_t estimatePacketCount(uint64_t fileSize, uint16_t linkType);
    
signals:
    /**
     * @brief Emitted periodically with progress updates
     */
    void progressUpdated(const IndexingProgress& progress);
    
    /**
     * @brief Emitted when indexing completes successfully
     * @param metadata File metadata
     * @param packetCount Total packets indexed
     */
    void indexingComplete(const CaptureFileMetadata& metadata, uint64_t packetCount);
    
    /**
     * @brief Emitted when indexing fails
     * @param error Error message
     */
    void indexingFailed(const QString& error);
    
    /**
     * @brief Emitted when indexing is cancelled
     */
    void indexingCancelled();
    
private:
    std::unique_ptr<IPacketSource> m_packetSource;
    std::shared_ptr<PacketIndex> m_index;
    QAtomicInt m_isIndexing{0};
    QAtomicInt m_cancelRequested{0};
    IndexingProgress m_progress;
    int m_batchSize = 1000;
    
    void runIndexing();
    [[nodiscard]] bool buildIndexEntry(
        const PacketHeaderInfo& header,
        const QByteArray& packetData,
        PacketIndexEntry& entry,
        QString& error);
    
    [[nodiscard]] ProtocolSummary detectProtocolSummary(
        const QByteArray& packetData,
        uint16_t linkType,
        uint8_t& ipVersion,
        uint8_t& transportProto,
        std::array<uint8_t, 16>& srcIp,
        std::array<uint8_t, 16>& dstIp,
        uint16_t& srcPort,
        uint16_t& dstPort,
        uint8_t& tcpFlags,
        uint16_t& etherType);
};

} // namespace pcap_analyzer::core
