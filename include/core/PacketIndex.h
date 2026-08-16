#pragma once

#include <QObject>
#include <QVector>
#include <QReadWriteLock>
#include <QDateTime>
#include <memory>
#include <optional>
#include "core/ProtocolSummary.h"

namespace pcap_analyzer::core {

/**
 * @brief In-memory packet index for fast access and filtering
 * 
 * Thread-safe container for packet metadata. Does not store packet payloads.
 * Supports incremental updates during indexing.
 */
class PacketIndex : public QObject
{
    Q_OBJECT
    
public:
    explicit PacketIndex(QObject* parent = nullptr);
    ~PacketIndex() override = default;
    
    // Disable copying, enable moving
    PacketIndex(const PacketIndex&) = delete;
    PacketIndex& operator=(const PacketIndex&) = delete;
    PacketIndex(PacketIndex&& other) noexcept;
    PacketIndex& operator=(PacketIndex&& other) noexcept;
    
    /**
     * @brief Reserve capacity for expected number of packets
     * @param count Expected packet count
     */
    void reserve(std::size_t count);
    
    /**
     * @brief Add a packet entry to the index
     * @param entry Packet index entry
     * @return Index of added entry
     */
    std::size_t addEntry(const PacketIndexEntry& entry);
    
    /**
     * @brief Add multiple entries in batch
     * @param entries Vector of entries
     */
    void addEntries(const QVector<PacketIndexEntry>& entries);
    
    /**
     * @brief Get entry by internal packet ID
     * @param packetId Internal packet ID
     * @return Pointer to entry, or nullptr if not found
     */
    [[nodiscard]] const PacketIndexEntry* getEntryByPacketId(uint64_t packetId) const;
    
    /**
     * @brief Get entry by display packet number (1-based)
     * @param packetNumber Display packet number (1-based)
     * @return Pointer to entry, or nullptr if invalid
     */
    [[nodiscard]] const PacketIndexEntry* getEntryByPacketNumber(std::size_t packetNumber) const;
    
    /**
     * @brief Get entry by index in the vector
     * @param index Zero-based index
     * @return Pointer to entry, or nullptr if out of bounds
     */
    [[nodiscard]] const PacketIndexEntry* getEntryByIndex(std::size_t index) const;
    
    /**
     * @brief Get total packet count
     */
    [[nodiscard]] std::size_t packetCount() const;
    
    /**
     * @brief Check if index is empty
     */
    [[nodiscard]] bool isEmpty() const;
    
    /**
     * @brief Clear all entries
     */
    void clear();
    
    /**
     * @brief Get all entries (read-only access)
     * @note Caller must hold read lock if accessing from multiple threads
     */
    [[nodiscard]] const QVector<PacketIndexEntry>& getAllEntries() const;
    
    /**
     * @brief Get entries in range [start, end)
     * @param start Start index (inclusive)
     * @param end End index (exclusive)
     * @return Vector of entries in range
     */
    [[nodiscard]] QVector<PacketIndexEntry> getEntriesInRange(std::size_t start, std::size_t end) const;
    
    /**
     * @brief Find packets by source IP
     * @param ipBytes IP address bytes (4 for IPv4, 16 for IPv6)
     * @param isIpv6 True if IPv6, false if IPv4
     * @return Vector of packet indices matching the IP
     */
    [[nodiscard]] QVector<std::size_t> findBySourceIp(const std::array<uint8_t, 16>& ipBytes, bool isIpv6) const;
    
    /**
     * @brief Find packets by destination IP
     */
    [[nodiscard]] QVector<std::size_t> findByDestIp(const std::array<uint8_t, 16>& ipBytes, bool isIpv6) const;
    
    /**
     * @brief Find packets by port
     * @param port Port number
     * @param isSource True to search source ports, false for destination
     * @return Vector of packet indices
     */
    [[nodiscard]] QVector<std::size_t> findByPort(uint16_t port, bool isSource) const;
    
    /**
     * @brief Find packets by protocol
     */
    [[nodiscard]] QVector<std::size_t> findByProtocol(ProtocolSummary proto) const;
    
    /**
     * @brief Find packets by transport protocol number
     */
    [[nodiscard]] QVector<std::size_t> findByTransportProtocol(uint8_t protoNum) const;
    
    /**
     * @brief Find packets with TCP flags set
     * @param flags Required TCP flags (all must be set)
     * @return Vector of packet indices
     */
    [[nodiscard]] QVector<std::size_t> findByTcpFlags(uint8_t flags) const;
    
    /**
     * @brief Find packets in time range
     * @param startNs Start timestamp in nanoseconds
     * @param endNs End timestamp in nanoseconds
     * @return Vector of packet indices
     */
    [[nodiscard]] QVector<std::size_t> findByTimeRange(uint64_t startNs, uint64_t endNs) const;
    
    /**
     * @brief Find packets with length greater than threshold
     */
    [[nodiscard]] QVector<std::size_t> findByMinLength(uint32_t minLength) const;
    
    /**
     * @brief Get first timestamp in index
     */
    [[nodiscard]] std::optional<uint64_t> getFirstTimestamp() const;
    
    /**
     * @brief Get last timestamp in index
     */
    [[nodiscard]] std::optional<uint64_t> getLastTimestamp() const;
    
    /**
     * @brief Get time range span in nanoseconds
     */
    [[nodiscard]] std::optional<uint64_t> getTimeSpanNs() const;
    
    /**
     * @brief Sort index by timestamp (stable sort)
     */
    void sortByTimestamp();
    
    /**
     * @brief Sort index by packet ID
     */
    void sortByPacketId();
    
    /**
     * @brief Check if index is sorted by packet ID
     */
    [[nodiscard]] bool isSortedByPacketId() const;
    
    /**
     * @brief Acquire read lock for thread-safe access
     */
    void lockForRead() const;
    
    /**
     * @brief Release read lock
     */
    void unlock() const;
    
    /**
     * @brief Acquire write lock
     */
    void lockForWrite();
    
signals:
    /**
     * @brief Emitted when entries are added
     * @param startIndex Start index of new entries
     * @param count Number of entries added
     */
    void entriesAdded(std::size_t startIndex, std::size_t count);
    
    /**
     * @brief Emitted when index is cleared
     */
    void indexCleared();
    
    /**
     * @brief Emitted when indexing completes
     */
    void indexingComplete();
    
private:
    QVector<PacketIndexEntry> m_entries;
    mutable QReadWriteLock m_lock;
    bool m_isSortedByPacketId = true;
    
    // Cached statistics
    mutable std::optional<uint64_t> m_firstTimestamp;
    mutable std::optional<uint64_t> m_lastTimestamp;
    mutable bool m_timestampsCached = false;
    
    void invalidateTimestampCache();
};

} // namespace pcap_analyzer::core
