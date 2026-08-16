#include "ui/widgets/PacketDetailView.h"
#include <QVBoxLayout>
#include <QHeaderView>

namespace pcap_analyzer::ui {

PacketDetailView::PacketDetailView(QWidget* parent)
    : QWidget(parent)
    , m_treeView(new QTreeView(this))
    , m_treeModel(new QStandardItemModel(this))
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    
    m_treeView->setModel(m_treeModel);
    m_treeView->setHeaderHidden(true);
    m_treeView->setRootIsDecorated(true);
    m_treeView->setItemsExpandable(true);
    m_treeView->setExpandsOnDoubleClick(false);
    m_treeView->setSelectionMode(QAbstractItemView::SingleSelection);
    
    // Set column for tree
    m_treeView->header()->setStretchLastSection(true);
    
    layout->addWidget(m_treeView);
}

PacketDetailView::~PacketDetailView() = default;

void PacketDetailView::setPacketSource(std::shared_ptr<core::IPacketSource> source)
{
    m_packetSource = std::move(source);
}

void PacketDetailView::displayPacket(const core::PacketIndexEntry* entry, int row)
{
    Q_UNUSED(row);
    
    if (!entry || !m_packetSource) {
        clear();
        return;
    }
    
    // Clear existing model
    m_treeModel->clear();
    
    // Build protocol tree based on index metadata
    buildProtocolTree(entry);
    
    // Expand all nodes by default
    m_treeView->expandAll();
}

void PacketDetailView::clear()
{
    m_treeModel->clear();
}

void PacketDetailView::buildProtocolTree(const core::PacketIndexEntry* entry)
{
    if (!entry) {
        return;
    }
    
    // Frame node (root)
    auto* frameNode = new QStandardItem(QString("Frame %1: %2 bytes")
        .arg(entry->displayPacketNumber)
        .arg(entry->capturedLength));
    frameNode->setData(QVariant::fromValue(qMakePair(0, static_cast<int>(entry->capturedLength))), 
                       Qt::UserRole);
    m_treeModel->appendRow(frameNode);
    
    // Ethernet layer
    auto* ethNode = addTreeNode(frameNode, "Ethernet II", 
                                QString("Src: %1, Dst: %2")
                                    .arg(formatMacFromEntry(entry->srcIp, true))
                                    .arg(formatMacFromEntry(entry->dstIp, true)));
    
    // IP layer
    if (entry->ipVersion == 4) {
        auto* ipv4Node = addTreeNode(ethNode, "Internet Protocol Version 4",
                                     QString("Src: %1, Dst: %2")
                                         .arg(formatIpAddress(entry->srcIp, 4))
                                         .arg(formatIpAddress(entry->dstIp, 4)));
        
        // Transport layer
        if (entry->transportProtocol == 6) { // TCP
            auto* tcpNode = addTreeNode(ipv4Node, "Transmission Control Protocol",
                                        QString("Src Port: %1, Dst Port: %2, Seq: %3, Ack: %4, Flags: %5")
                                            .arg(entry->srcPort)
                                            .arg(entry->dstPort)
                                            .arg(0) // TODO: Get from packet
                                            .arg(0)
                                            .arg(formatTcpFlags(entry->tcpFlags)));
            
            // Application layer detection
            detectAndAddAppLayer(tcpNode, entry);
            
        } else if (entry->transportProtocol == 17) { // UDP
            auto* udpNode = addTreeNode(ipv4Node, "User Datagram Protocol",
                                        QString("Src Port: %1, Dst Port: %2")
                                            .arg(entry->srcPort)
                                            .arg(entry->dstPort));
            
            detectAndAddAppLayer(udpNode, entry);
        }
        
    } else if (entry->ipVersion == 6) {
        auto* ipv6Node = addTreeNode(ethNode, "Internet Protocol Version 6",
                                     QString("Src: %1, Dst: %2")
                                         .arg(formatIpAddress(entry->srcIp, 6))
                                         .arg(formatIpAddress(entry->dstIp, 6)));
        
        // Similar transport handling for IPv6
        if (entry->transportProtocol == 6) { // TCP
            auto* tcpNode = addTreeNode(ipv6Node, "Transmission Control Protocol",
                                        QString("Src Port: %1, Dst Port: %2")
                                            .arg(entry->srcPort)
                                            .arg(entry->dstPort));
            detectAndAddAppLayer(tcpNode, entry);
        }
    }
}

QStandardItem* PacketDetailView::addTreeNode(QStandardItem* parent,
                                              const QString& protocolName,
                                              const QString& summary,
                                              int startOffset,
                                              int length)
{
    auto* node = new QStandardItem(QString("%1 (%2)").arg(protocolName).arg(summary));
    node->setEditable(false);
    
    if (startOffset >= 0 && length > 0) {
        node->setData(QVariant::fromValue(qMakePair(startOffset, length)), Qt::UserRole);
    }
    
    parent->appendRow(node);
    return node;
}

void PacketDetailView::detectAndAddAppLayer(QStandardItem* parentNode, 
                                             const core::PacketIndexEntry* entry)
{
    using core::ProtocolSummary;
    
    switch (entry->protocolSummary) {
    case ProtocolSummary::Dns:
        addTreeNode(parentNode, "Domain Name System", "DNS Query/Response");
        break;
    case ProtocolSummary::Http:
        addTreeNode(parentNode, "Hypertext Transfer Protocol", "HTTP Request/Response");
        break;
    case ProtocolSummary::Tls:
        addTreeNode(parentNode, "Transport Layer Security", "TLS Record");
        break;
    case ProtocolSummary::Ssh:
        addTreeNode(parentNode, "Secure Shell", "SSH Protocol");
        break;
    case ProtocolSummary::Dhcp:
        addTreeNode(parentNode, "Dynamic Host Configuration Protocol", "DHCP Message");
        break;
    default:
        break;
    }
}

// Helper formatting functions (would ideally be in utils)
QString PacketDetailView::formatIpAddress(const std::array<uint8_t, 16>& ip, uint8_t version) const
{
    if (version == 4) {
        return QString("%1.%2.%3.%4")
            .arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
    } else if (version == 6) {
        // Simplified IPv6 formatting
        return QString("%1:%2:%3:%4:%5:%6:%7:%8")
            .arg(ip[0], 2, 16, QChar('0'))
            .arg(ip[1], 2, 16, QChar('0'))
            .arg(ip[2], 2, 16, QChar('0'))
            .arg(ip[3], 2, 16, QChar('0'))
            .arg(ip[4], 2, 16, QChar('0'))
            .arg(ip[5], 2, 16, QChar('0'))
            .arg(ip[6], 2, 16, QChar('0'))
            .arg(ip[7], 2, 16, QChar('0'));
    }
    return QString();
}

QString PacketDetailView::formatMacFromEntry(const std::array<uint8_t, 16>& ip, bool isMac) const
{
    Q_UNUSED(isMac);
    // For now, just format first 6 bytes as MAC (simplified)
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(ip[0], 2, 16, QChar('0'))
        .arg(ip[1], 2, 16, QChar('0'))
        .arg(ip[2], 2, 16, QChar('0'))
        .arg(ip[3], 2, 16, QChar('0'))
        .arg(ip[4], 2, 16, QChar('0'))
        .arg(ip[5], 2, 16, QChar('0'));
}

QString PacketDetailView::formatTcpFlags(uint8_t flags) const
{
    QString result;
    if (flags & 0x02) result += "SYN ";
    if (flags & 0x10) result += "ACK ";
    if (flags & 0x01) result += "FIN ";
    if (flags & 0x04) result += "RST ";
    if (flags & 0x08) result += "PSH ";
    if (flags & 0x20) result += "URG ";
    return result.trimmed();
}

} // namespace pcap_analyzer::ui
