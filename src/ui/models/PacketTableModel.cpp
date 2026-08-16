#include "ui/models/PacketTableModel.h"
#include "core/utils/TimestampUtils.h"
#include "core/utils/ByteUtils.h"
#include <QBrush>
#include <QFont>

namespace pcap_analyzer::ui {

PacketTableModel::PacketTableModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

PacketTableModel::~PacketTableModel() = default;

void PacketTableModel::setPacketIndex(std::shared_ptr<core::PacketIndex> index)
{
    beginResetModel();
    m_packetIndex = std::move(index);
    m_useRowMapping = false;
    m_rowMapping.clear();
    endResetModel();
}

std::shared_ptr<core::PacketIndex> PacketTableModel::getPacketIndex() const
{
    return m_packetIndex;
}

int PacketTableModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid() || !m_packetIndex) {
        return 0;
    }
    
    if (m_useRowMapping) {
        return static_cast<int>(m_rowMapping.size());
    }
    
    return static_cast<int>(m_packetIndex->packetCount());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    return static_cast<int>(PacketListColumn::ColumnCount);
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || !m_packetIndex) {
        return QVariant();
    }
    
    const int row = index.row();
    const auto column = static_cast<PacketListColumn>(index.column());
    
    // Get entry
    const core::PacketIndexEntry* entry = nullptr;
    if (m_useRowMapping) {
        if (row >= static_cast<int>(m_rowMapping.size())) {
            return QVariant();
        }
        entry = m_packetIndex->getEntryByIndex(m_rowMapping[row]);
    } else {
        entry = m_packetIndex->getEntryByIndex(row);
    }
    
    if (!entry) {
        return QVariant();
    }
    
    switch (role) {
    case Qt::DisplayRole:
        switch (column) {
        case PacketListColumn::Number:
            return QVariant::fromValue(entry->displayPacketNumber);
            
        case PacketListColumn::Time:
            return formatTimestamp(entry->timestampNs, row);
            
        case PacketListColumn::Delta:
            return formatTimeDelta(entry->timestampNs, row);
            
        case PacketListColumn::Source:
            return formatIpAddress(entry->srcIp, entry->ipVersion);
            
        case PacketListColumn::Destination:
            return formatIpAddress(entry->dstIp, entry->ipVersion);
            
        case PacketListColumn::Protocol:
            return formatProtocol(static_cast<uint8_t>(entry->protocolSummary));
            
        case PacketListColumn::Length:
            return QVariant::fromValue(entry->capturedLength);
            
        case PacketListColumn::Info:
            return formatInfo(*entry);
            
        default:
            return QVariant();
        }
        
    case Qt::TextAlignmentRole:
        if (column == PacketListColumn::Number || 
            column == PacketListColumn::Length) {
            return Qt::AlignRight;
        }
        return Qt::AlignLeft;
        
    case Qt::ForegroundRole:
        if (column == PacketListColumn::Protocol) {
            // Color-code protocols
            switch (entry->protocolSummary) {
            case core::ProtocolSummary::Tcp:
                return QColor(0x2E, 0x86, 0xAB); // Blue
            case core::ProtocolSummary::Udp:
                return QColor(0x5C, 0xA3, 0x4A); // Green
            case core::ProtocolSummary::Dns:
                return QColor(0xB1, 0x5D, 0xCF); // Purple
            case core::ProtocolSummary::Http:
                return QColor(0xD9, 0x77, 0x06); // Orange
            case core::ProtocolSummary::Tls:
                return QColor(0x8B, 0x5C, 0xF6); // Violet
            case core::ProtocolSummary::Icmp:
            case core::ProtocolSummary::Icmpv6:
                return QColor(0x88, 0x88, 0x88); // Gray
            default:
                break;
            }
        }
        return QVariant();
        
    case Qt::FontRole:
        if (column == PacketListColumn::Number) {
            QFont font;
            font.setFamily("Courier New");
            font.setPointSize(10);
            return font;
        }
        return QVariant();
        
    default:
        return QVariant();
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        if (section >= 0 && section < static_cast<int>(PacketListColumn::ColumnCount)) {
            return QString(ColumnNames[section]);
        }
    }
    return QAbstractTableModel::headerData(section, orientation, role);
}

Qt::ItemFlags PacketTableModel::flags(const QModelIndex& index) const
{
    if (!index.isValid()) {
        return Qt::NoItemFlags;
    }
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsUserCheckable;
}

void PacketTableModel::sort(int column, Qt::SortOrder order)
{
    if (!m_packetIndex || m_packetIndex->packetCount() == 0) {
        return;
    }
    
    // TODO: Implement proper sorting with stable indices
    // For now, just emit sort signal - actual sorting done in PacketIndex
    emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
}

const core::PacketIndexEntry* PacketTableModel::getEntryAtRow(int row) const
{
    if (!m_packetIndex || row < 0) {
        return nullptr;
    }
    
    if (m_useRowMapping) {
        if (row >= static_cast<int>(m_rowMapping.size())) {
            return nullptr;
        }
        return m_packetIndex->getEntryByIndex(m_rowMapping[row]);
    }
    
    return m_packetIndex->getEntryByIndex(row);
}

uint64_t PacketTableModel::getPacketNumberAtRow(int row) const
{
    const auto* entry = getEntryAtRow(row);
    return entry ? entry->displayPacketNumber : 0;
}

QString PacketTableModel::formatTimestamp(uint64_t timestampNs, int row) const
{
    Q_UNUSED(row);
    
    if (!m_packetIndex) {
        return QString();
    }
    
    // Get first timestamp for relative calculation
    const auto firstTs = m_packetIndex->getFirstTimestamp();
    if (!firstTs) {
        return QString("0.000000");
    }
    
    const uint64_t deltaNs = timestampNs - *firstTs;
    const double deltaSec = static_cast<double>(deltaNs) / 1e9;
    
    return QString::number(deltaSec, 'f', 6);
}

QString PacketTableModel::formatTimeDelta(uint64_t currentTs, int row) const
{
    if (!m_packetIndex || row <= 0) {
        return QString();
    }
    
    const core::PacketIndexEntry* prevEntry = nullptr;
    if (m_useRowMapping && row > 0 && row < static_cast<int>(m_rowMapping.size())) {
        prevEntry = m_packetIndex->getEntryByIndex(m_rowMapping[row - 1]);
    } else if (!m_useRowMapping && row > 0) {
        prevEntry = m_packetIndex->getEntryByIndex(row - 1);
    }
    
    if (!prevEntry) {
        return QString();
    }
    
    const uint64_t deltaNs = currentTs - prevEntry->timestampNs;
    const double deltaSec = static_cast<double>(deltaNs) / 1e9;
    
    return QString::number(deltaSec, 'f', 6);
}

QString PacketTableModel::formatIpAddress(const std::array<uint8_t, 16>& ip, uint8_t version) const
{
    if (version == 4) {
        // IPv4
        return QString("%1.%2.%3.%4")
            .arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
    } else if (version == 6) {
        // IPv6
        return core::ByteUtils::formatIpv6Address(ip);
    }
    
    return QString();
}

QString PacketTableModel::formatProtocol(uint8_t protoSummary) const
{
    using core::ProtocolSummary;
    
    switch (static_cast<ProtocolSummary>(protoSummary)) {
    case ProtocolSummary::Ethernet: return "ETH";
    case ProtocolSummary::Arp: return "ARP";
    case ProtocolSummary::Ipv4: return "IPv4";
    case ProtocolSummary::Ipv6: return "IPv6";
    case ProtocolSummary::Icmp: return "ICMP";
    case ProtocolSummary::Icmpv6: return "ICMPv6";
    case ProtocolSummary::Tcp: return "TCP";
    case ProtocolSummary::Udp: return "UDP";
    case ProtocolSummary::Dns: return "DNS";
    case ProtocolSummary::Http: return "HTTP";
    case ProtocolSummary::Tls: return "TLS";
    case ProtocolSummary::Quic: return "QUIC";
    case ProtocolSummary::Smb: return "SMB";
    case ProtocolSummary::Dhcp: return "DHCP";
    case ProtocolSummary::Ntp: return "NTP";
    case ProtocolSummary::Ssh: return "SSH";
    case ProtocolSummary::Unknown:
    default:
        return "???";
    }
}

QString PacketTableModel::formatInfo(const core::PacketIndexEntry& entry) const
{
    QString info;
    
    switch (entry.protocolSummary) {
    case core::ProtocolSummary::Arp:
        if (entry.transportProtocol == 1) { // ARP request
            info = "Who has ";
        } else {
            info = "Tell ";
        }
        break;
        
    case core::ProtocolSummary::Tcp:
        {
            QString flags;
            if (entry.tcpFlags & 0x02) flags += "[SYN] ";
            if (entry.tcpFlags & 0x10) flags += "[ACK] ";
            if (entry.tcpFlags & 0x01) flags += "[FIN] ";
            if (entry.tcpFlags & 0x04) flags += "[RST] ";
            if (entry.tcpFlags & 0x08) flags += "[PSH] ";
            if (entry.tcpFlags & 0x20) flags += "[URG] ";
            
            info = QString("%1:%2 → %3:%4 %5")
                .arg(formatIpAddress(entry.srcIp, entry.ipVersion))
                .arg(entry.srcPort)
                .arg(formatIpAddress(entry.dstIp, entry.ipVersion))
                .arg(entry.dstPort)
                .arg(flags.trimmed());
        }
        break;
        
    case core::ProtocolSummary::Udp:
        info = QString("%1:%2 → %3:%4")
            .arg(formatIpAddress(entry.srcIp, entry.ipVersion))
            .arg(entry.srcPort)
            .arg(formatIpAddress(entry.dstIp, entry.ipVersion))
            .arg(entry.dstPort);
        break;
        
    case core::ProtocolSummary::Dns:
        info = "DNS Query/Response";
        break;
        
    case core::ProtocolSummary::Http:
        info = "HTTP Request/Response";
        break;
        
    case core::ProtocolSummary::Icmp:
    case core::ProtocolSummary::Icmpv6:
        info = "ICMP Message";
        break;
        
    default:
        if (entry.ipVersion == 4 || entry.ipVersion == 6) {
            info = QString("%1 → %2")
                .arg(formatIpAddress(entry.srcIp, entry.ipVersion))
                .arg(formatIpAddress(entry.dstIp, entry.ipVersion));
        } else {
            info = "Packet";
        }
        break;
    }
    
    return info;
}

} // namespace pcap_analyzer::ui
