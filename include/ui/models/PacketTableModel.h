#pragma once

#include <QAbstractTableModel>
#include <QVector>
#include <memory>
#include "core/PacketIndex.h"

namespace pcap_analyzer::ui {

/**
 * @brief Column identifiers for packet list
 */
enum class PacketListColumn
{
    Number = 0,
    Time,
    Delta,
    Source,
    Destination,
    Protocol,
    Length,
    Info,
    
    ColumnCount
};

/**
 * @brief Qt table model for displaying packet list
 * 
 * Implements virtualized model for millions of packets.
 * Only generates display strings for visible rows.
 * Reads data from PacketIndex on demand.
 */
class PacketTableModel : public QAbstractTableModel
{
    Q_OBJECT
    
public:
    explicit PacketTableModel(QObject* parent = nullptr);
    ~PacketTableModel() override;
    
    /**
     * @brief Set the packet index to display
     */
    void setPacketIndex(std::shared_ptr<core::PacketIndex> index);
    
    /**
     * @brief Get the packet index
     */
    [[nodiscard]] std::shared_ptr<core::PacketIndex> getPacketIndex() const;
    
    // QAbstractItemModel interface
    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    [[nodiscard]] Qt::ItemFlags flags(const QModelIndex& index) const override;
    
    /**
     * @brief Sort by column
     */
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
    
    /**
     * @brief Get packet entry at row
     */
    [[nodiscard]] const core::PacketIndexEntry* getEntryAtRow(int row) const;
    
    /**
     * @brief Get packet number (1-based) at row
     */
    [[nodiscard]] uint64_t getPacketNumberAtRow(int row) const;
    
signals:
    /**
     * @brief Emitted when a packet is selected
     */
    void packetSelected(uint64_t packetId, int row);
    
private:
    std::shared_ptr<core::PacketIndex> m_packetIndex;
    QVector<int> m_rowMapping;  // For filtered/sorted view
    bool m_useRowMapping = false;
    
    [[nodiscard]] QString formatTimestamp(uint64_t timestampNs, int row) const;
    [[nodiscard]] QString formatTimeDelta(uint64_t currentTs, int row) const;
    [[nodiscard]] QString formatIpAddress(const std::array<uint8_t, 16>& ip, uint8_t version) const;
    [[nodiscard]] QString formatProtocol(uint8_t protoSummary) const;
    [[nodiscard]] QString formatInfo(const core::PacketIndexEntry& entry) const;
    
    static constexpr const char* ColumnNames[] = {
        "No.", "Time", "Delta", "Source", "Destination", "Protocol", "Length", "Info"
    };
};

} // namespace pcap_analyzer::ui
