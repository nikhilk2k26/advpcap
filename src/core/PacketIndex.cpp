#include "core/PacketIndex.h"
#include <algorithm>
#include <cstring>

namespace pcap_analyzer::core {

PacketIndex::PacketIndex(QObject* parent)
    : QObject(parent)
{
    m_entries.reserve(10000);  // Initial reservation
}

PacketIndex::PacketIndex(PacketIndex&& other) noexcept
    : QObject(std::move(other))
    , m_entries(std::move(other.m_entries))
    , m_isSortedByPacketId(other.m_isSortedByPacketId)
    , m_firstTimestamp(other.m_firstTimestamp)
    , m_lastTimestamp(other.m_lastTimestamp)
    , m_timestampsCached(other.m_timestampsCached)
{
    other.m_isSortedByPacketId = true;
    other.m_timestampsCached = false;
    other.m_firstTimestamp.reset();
    other.m_lastTimestamp.reset();
}

PacketIndex& PacketIndex::operator=(PacketIndex&& other) noexcept
{
    if (this != &other) {
        m_entries = std::move(other.m_entries);
        m_isSortedByPacketId = other.m_isSortedByPacketId;
        m_firstTimestamp = other.m_firstTimestamp;
        m_lastTimestamp = other.m_lastTimestamp;
        m_timestampsCached = other.m_timestampsCached;
        
        other.m_isSortedByPacketId = true;
        other.m_timestampsCached = false;
        other.m_firstTimestamp.reset();
        other.m_lastTimestamp.reset();
    }
    return *this;
}

void PacketIndex::reserve(std::size_t count)
{
    QWriteLocker locker(&m_lock);
    m_entries.reserve(static_cast<int>(count));
}

std::size_t PacketIndex::addEntry(const PacketIndexEntry& entry)
{
    QWriteLocker locker(&m_lock);
    
    const auto index = static_cast<std::size_t>(m_entries.size());
    m_entries.append(entry);
    
    invalidateTimestampCache();
    
    // Emit signal outside lock scope to avoid potential deadlocks
    locker.unlock();
    emit entriesAdded(index, 1);
    
    return index;
}

void PacketIndex::addEntries(const QVector<PacketIndexEntry>& entries)
{
    if (entries.isEmpty()) {
        return;
    }
    
    QWriteLocker locker(&m_lock);
    
    const auto startIndex = static_cast<std::size_t>(m_entries.size());
    const auto count = static_cast<std::size_t>(entries.size());
    
    m_entries.reserve(m_entries.size() + entries.size());
    m_entries.append(entries);
    
    invalidateTimestampCache();
    
    locker.unlock();
    emit entriesAdded(startIndex, count);
}

const PacketIndexEntry* PacketIndex::getEntryByPacketId(uint64_t packetId) const
{
    QReadLocker locker(&m_lock);
    
    if (packetId == 0 || packetId > static_cast<uint64_t>(m_entries.size())) {
        return nullptr;
    }
    
    return &m_entries[static_cast<int>(packetId - 1)];
}

const PacketIndexEntry* PacketIndex::getEntryByPacketNumber(std::size_t packetNumber) const
{
    // Display packet number is 1-based, same as packetId in our scheme
    return getEntryByPacketId(packetNumber);
}

const PacketIndexEntry* PacketIndex::getEntryByIndex(std::size_t index) const
{
    QReadLocker locker(&m_lock);
    
    if (index >= static_cast<std::size_t>(m_entries.size())) {
        return nullptr;
    }
    
    return &m_entries[static_cast<int>(index)];
}

std::size_t PacketIndex::packetCount() const
{
    QReadLocker locker(&m_lock);
    return static_cast<std::size_t>(m_entries.size());
}

bool PacketIndex::isEmpty() const
{
    QReadLocker locker(&m_lock);
    return m_entries.isEmpty();
}

void PacketIndex::clear()
{
    QWriteLocker locker(&m_lock);
    m_entries.clear();
    invalidateTimestampCache();
    
    locker.unlock();
    emit indexCleared();
}

const QVector<PacketIndexEntry>& PacketIndex::getAllEntries() const
{
    // Caller must hold read lock if accessing from multiple threads
    return m_entries;
}

QVector<PacketIndexEntry> PacketIndex::getEntriesInRange(std::size_t start, std::size_t end) const
{
    QReadLocker locker(&m_lock);
    
    const auto actualStart = std::min(start, static_cast<std::size_t>(m_entries.size()));
    const auto actualEnd = std::min(end, static_cast<std::size_t>(m_entries.size()));
    
    if (actualStart >= actualEnd) {
        return {};
    }
    
    const int beginIdx = static_cast<int>(actualStart);
    const int count = static_cast<int>(actualEnd - actualStart);
    
    return m_entries.mid(beginIdx, count);
}

QVector<std::size_t> PacketIndex::findBySourceIp(
    const std::array<uint8_t, 16>& ipBytes, bool isIpv6) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    results.reserve(m_entries.size() / 10);  // Estimate 10% match
    
    for (int i = 0; i < m_entries.size(); ++i) {
        const auto& entry = m_entries[i];
        if (entry.ipVersion == (isIpv6 ? 6 : 4)) {
            bool matches = true;
            if (!isIpv6) {
                // IPv4: compare first 4 bytes
                for (int j = 0; j < 4; ++j) {
                    if (entry.srcIp[j] != ipBytes[j]) {
                        matches = false;
                        break;
                    }
                }
            } else {
                // IPv6: compare all 16 bytes
                matches = (entry.srcIp == ipBytes);
            }
            
            if (matches) {
                results.append(static_cast<std::size_t>(i));
            }
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByDestIp(
    const std::array<uint8_t, 16>& ipBytes, bool isIpv6) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        const auto& entry = m_entries[i];
        if (entry.ipVersion == (isIpv6 ? 6 : 4)) {
            bool matches = true;
            if (!isIpv6) {
                for (int j = 0; j < 4; ++j) {
                    if (entry.dstIp[j] != ipBytes[j]) {
                        matches = false;
                        break;
                    }
                }
            } else {
                matches = (entry.dstIp == ipBytes);
            }
            
            if (matches) {
                results.append(static_cast<std::size_t>(i));
            }
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByPort(uint16_t port, bool isSource) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        const auto& entry = m_entries[i];
        if (isSource && entry.srcPort == port) {
            results.append(static_cast<std::size_t>(i));
        } else if (!isSource && entry.dstPort == port) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByProtocol(ProtocolSummary proto) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    const auto protoVal = static_cast<uint8_t>(proto);
    
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i].protocolSummary == protoVal) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByTransportProtocol(uint8_t protoNum) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i].transportProtocol == protoNum) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByTcpFlags(uint8_t flags) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        const auto& entry = m_entries[i];
        if ((entry.tcpFlags & flags) == flags) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByTimeRange(uint64_t startNs, uint64_t endNs) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        const auto ts = m_entries[i].timestampNs;
        if (ts >= startNs && ts <= endNs) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

QVector<std::size_t> PacketIndex::findByMinLength(uint32_t minLength) const
{
    QReadLocker locker(&m_lock);
    QVector<std::size_t> results;
    
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i].capturedLength >= minLength) {
            results.append(static_cast<std::size_t>(i));
        }
    }
    
    return results;
}

std::optional<uint64_t> PacketIndex::getFirstTimestamp() const
{
    if (m_entries.isEmpty()) {
        return std::nullopt;
    }
    
    if (m_timestampsCached) {
        return m_firstTimestamp;
    }
    
    QReadLocker locker(&m_lock);
    
    uint64_t minTs = std::numeric_limits<uint64_t>::max();
    for (const auto& entry : m_entries) {
        if (entry.timestampNs < minTs) {
            minTs = entry.timestampNs;
        }
    }
    
    m_firstTimestamp = (minTs == std::numeric_limits<uint64_t>::max()) 
                       ? std::nullopt 
                       : std::optional<uint64_t>(minTs);
    m_timestampsCached = true;
    
    return m_firstTimestamp;
}

std::optional<uint64_t> PacketIndex::getLastTimestamp() const
{
    if (m_entries.isEmpty()) {
        return std::nullopt;
    }
    
    if (m_timestampsCached) {
        return m_lastTimestamp;
    }
    
    QReadLocker locker(&m_lock);
    
    uint64_t maxTs = 0;
    for (const auto& entry : m_entries) {
        if (entry.timestampNs > maxTs) {
            maxTs = entry.timestampNs;
        }
    }
    
    m_lastTimestamp = std::optional<uint64_t>(maxTs);
    m_timestampsCached = true;
    
    return m_lastTimestamp;
}

std::optional<uint64_t> PacketIndex::getTimeSpanNs() const
{
    const auto first = getFirstTimestamp();
    const auto last = getLastTimestamp();
    
    if (!first.has_value() || !last.has_value()) {
        return std::nullopt;
    }
    
    return *last - *first;
}

void PacketIndex::sortByTimestamp()
{
    QWriteLocker locker(&m_lock);
    
    std::stable_sort(m_entries.begin(), m_entries.end(),
        [](const PacketIndexEntry& a, const PacketIndexEntry& b) {
            return a.timestampNs < b.timestampNs;
        });
    
    m_isSortedByPacketId = false;
    invalidateTimestampCache();
}

void PacketIndex::sortByPacketId()
{
    QWriteLocker locker(&m_lock);
    
    std::sort(m_entries.begin(), m_entries.end());
    m_isSortedByPacketId = true;
}

bool PacketIndex::isSortedByPacketId() const
{
    return m_isSortedByPacketId;
}

void PacketIndex::lockForRead() const
{
    m_lock.lockForRead();
}

void PacketIndex::unlock() const
{
    m_lock.unlock();
}

void PacketIndex::lockForWrite()
{
    m_lock.lockForWrite();
}

void PacketIndex::invalidateTimestampCache()
{
    m_timestampsCached = false;
    m_firstTimestamp.reset();
    m_lastTimestamp.reset();
}

} // namespace pcap_analyzer::core
