#include <gtest/gtest.h>
#include "core/PacketIndex.h"
#include <thread>
#include <chrono>

using namespace pcap_analyzer::core;

class PacketIndexTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_index = std::make_shared<PacketIndex>();
    }
    
    std::shared_ptr<PacketIndex> m_index;
};

TEST_F(PacketIndexTest, EmptyIndex)
{
    EXPECT_TRUE(m_index->isEmpty());
    EXPECT_EQ(m_index->packetCount(), 0u);
}

TEST_F(PacketIndexTest, AddSingleEntry)
{
    PacketIndexEntry entry;
    entry.packetId = 1;
    entry.fileOffset = 0;
    entry.timestampNs = 1000000000ULL;
    entry.capturedLength = 64;
    entry.originalLength = 64;
    
    auto index = m_index->addEntry(entry);
    
    EXPECT_EQ(index, 0u);
    EXPECT_FALSE(m_index->isEmpty());
    EXPECT_EQ(m_index->packetCount(), 1u);
}

TEST_F(PacketIndexTest, AddMultipleEntries)
{
    QVector<PacketIndexEntry> entries;
    for (int i = 0; i < 100; ++i) {
        PacketIndexEntry entry;
        entry.packetId = static_cast<uint64_t>(i + 1);
        entry.fileOffset = static_cast<uint64_t>(i * 100);
        entry.timestampNs = static_cast<uint64_t>(1000000000ULL + i * 1000000ULL);
        entry.capturedLength = 64;
        entries.append(entry);
    }
    
    m_index->addEntries(entries);
    
    EXPECT_EQ(m_index->packetCount(), 100u);
}

TEST_F(PacketIndexTest, GetEntryByPacketId)
{
    PacketIndexEntry entry;
    entry.packetId = 42;
    entry.fileOffset = 1000;
    
    m_index->addEntry(entry);
    
    const auto* retrieved = m_index->getEntryByPacketId(42);
    ASSERT_NE(retrieved, nullptr);
    EXPECT_EQ(retrieved->packetId, 42u);
    EXPECT_EQ(retrieved->fileOffset, 1000u);
}

TEST_F(PacketIndexTest, GetInvalidEntry)
{
    const auto* retrieved = m_index->getEntryByPacketId(999);
    EXPECT_EQ(retrieved, nullptr);
}

TEST_F(PacketIndexTest, ThreadSafety)
{
    const int threadCount = 4;
    const int entriesPerThread = 1000;
    
    std::vector<std::thread> threads;
    
    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([this, t, entriesPerThread]() {
            for (int i = 0; i < entriesPerThread; ++i) {
                PacketIndexEntry entry;
                entry.packetId = static_cast<uint64_t>(t * entriesPerThread + i + 1);
                entry.fileOffset = static_cast<uint64_t>(i);
                entry.timestampNs = static_cast<uint64_t>(i * 1000000ULL);
                m_index->addEntry(entry);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(m_index->packetCount(), static_cast<std::size_t>(threadCount * entriesPerThread));
}

TEST_F(PacketIndexTest, FindBySourceIp)
{
    // Add IPv4 entries
    PacketIndexEntry entry1;
    entry1.packetId = 1;
    entry1.ipVersion = 4;
    entry1.srcIp = {{192, 168, 1, 10}};
    m_index->addEntry(entry1);
    
    PacketIndexEntry entry2;
    entry2.packetId = 2;
    entry2.ipVersion = 4;
    entry2.srcIp = {{10, 0, 0, 1}};
    m_index->addEntry(entry2);
    
    PacketIndexEntry entry3;
    entry3.packetId = 3;
    entry3.ipVersion = 4;
    entry3.srcIp = {{192, 168, 1, 10}};
    m_index->addEntry(entry3);
    
    std::array<uint8_t, 16> searchIp = {{192, 168, 1, 10}};
    auto results = m_index->findBySourceIp(searchIp, false);
    
    EXPECT_EQ(results.size(), 2);
}

TEST_F(PacketIndexTest, FindByPort)
{
    PacketIndexEntry entry1;
    entry1.packetId = 1;
    entry1.transportProtocol = 6;  // TCP
    entry1.srcPort = 12345;
    entry1.dstPort = 443;
    m_index->addEntry(entry1);
    
    PacketIndexEntry entry2;
    entry2.packetId = 2;
    entry2.transportProtocol = 6;
    entry2.srcPort = 54321;
    entry2.dstPort = 443;
    m_index->addEntry(entry2);
    
    PacketIndexEntry entry3;
    entry3.packetId = 3;
    entry3.transportProtocol = 6;
    entry3.srcPort = 443;
    entry3.dstPort = 8080;
    m_index->addEntry(entry3);
    
    auto results = m_index->findByPort(443, false);  // Destination port
    EXPECT_EQ(results.size(), 2);
    
    results = m_index->findByPort(443, true);  // Source port
    EXPECT_EQ(results.size(), 1);
}

TEST_F(PacketIndexTest, SortByTimestamp)
{
    // Add entries out of order
    PacketIndexEntry entry1;
    entry1.packetId = 1;
    entry1.timestampNs = 3000000000ULL;
    m_index->addEntry(entry1);
    
    PacketIndexEntry entry2;
    entry2.packetId = 2;
    entry2.timestampNs = 1000000000ULL;
    m_index->addEntry(entry2);
    
    PacketIndexEntry entry3;
    entry3.packetId = 3;
    entry3.timestampNs = 2000000000ULL;
    m_index->addEntry(entry3);
    
    m_index->sortByTimestamp();
    
    // Verify sorted order
    const auto* first = m_index->getEntryByIndex(0);
    const auto* second = m_index->getEntryByIndex(1);
    const auto* third = m_index->getEntryByIndex(2);
    
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    ASSERT_NE(third, nullptr);
    
    EXPECT_EQ(first->timestampNs, 1000000000ULL);
    EXPECT_EQ(second->timestampNs, 2000000000ULL);
    EXPECT_EQ(third->timestampNs, 3000000000ULL);
}

TEST_F(PacketIndexTest, TimeRange)
{
    const auto firstTs = m_index->getFirstTimestamp();
    EXPECT_FALSE(firstTs.has_value());
    
    PacketIndexEntry entry;
    entry.packetId = 1;
    entry.timestampNs = 1000000000ULL;
    m_index->addEntry(entry);
    
    entry.packetId = 2;
    entry.timestampNs = 5000000000ULL;
    m_index->addEntry(entry);
    
    auto first = m_index->getFirstTimestamp();
    auto last = m_index->getLastTimestamp();
    
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(last.has_value());
    
    EXPECT_EQ(*first, 1000000000ULL);
    EXPECT_EQ(*last, 5000000000ULL);
    
    auto span = m_index->getTimeSpanNs();
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(*span, 4000000000ULL);
}

TEST_F(PacketIndexTest, ClearIndex)
{
    for (int i = 0; i < 100; ++i) {
        PacketIndexEntry entry;
        entry.packetId = static_cast<uint64_t>(i + 1);
        m_index->addEntry(entry);
    }
    
    EXPECT_EQ(m_index->packetCount(), 100u);
    
    m_index->clear();
    
    EXPECT_TRUE(m_index->isEmpty());
    EXPECT_EQ(m_index->packetCount(), 0u);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
