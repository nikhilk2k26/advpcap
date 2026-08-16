#pragma once

#include <QWidget>
#include <QTreeView>
#include <QStandardItemModel>
#include <memory>
#include "core/PacketIndex.h"
#include "core/IPacketSource.h"

namespace pcap_analyzer::ui {

/**
 * @brief Widget for displaying packet protocol tree details
 * 
 * Shows hierarchical protocol dissection when a packet is selected.
 * Uses lazy loading - only decodes the selected packet.
 */
class PacketDetailView : public QWidget
{
    Q_OBJECT

public:
    explicit PacketDetailView(QWidget* parent = nullptr);
    ~PacketDetailView() override;

    /**
     * @brief Set the packet source for reading packet data
     * @param source Shared pointer to packet source
     */
    void setPacketSource(std::shared_ptr<core::IPacketSource> source);

    /**
     * @brief Display details for a specific packet
     * @param entry Packet index entry
     * @param row Row number in the packet list
     */
    void displayPacket(const core::PacketIndexEntry* entry, int row);

    /**
     * @brief Clear the detail view
     */
    void clear();

signals:
    /**
     * @brief Emitted when byte range is highlighted in hex view
     * @param startOffset Start byte offset in packet
     * @param length Number of bytes
     */
    void byteRangeHighlighted(int startOffset, int length);

private:
    QTreeView* m_treeView;
    QStandardItemModel* m_treeModel;
    std::shared_ptr<core::IPacketSource> m_packetSource;
    
    // Build protocol tree from packet data
    void buildProtocolTree(const core::PacketIndexEntry* entry);
    
    // Helper to add nodes to tree
    QStandardItem* addTreeNode(QStandardItem* parent, 
                               const QString& protocolName,
                               const QString& summary,
                               int startOffset = -1,
                               int length = 0);
};

} // namespace pcap_analyzer::ui
