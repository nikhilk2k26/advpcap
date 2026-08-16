#include "filter/FilterEvaluator.h"
#include <QByteArray>

namespace pcapanalyzer::filter {

FilterEvaluator::FilterEvaluator() = default;

bool FilterEvaluator::evaluate(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    switch (node.type) {
        case NodeType::Value:
            return toBool(node.value);
        
        case NodeType::Field:
            return evaluateField(node, entry);
        
        case NodeType::Unary:
            return evaluateUnary(node, entry);
        
        case NodeType::Binary:
            return evaluateBinary(node, entry);
        
        case NodeType::Protocol:
            return evaluateProtocol(node, entry);
        
        case NodeType::Error:
            return false;
    }
    
    return false;
}

bool FilterEvaluator::evaluateField(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    QVariant fieldValue = getField(node.protocolName, node.fieldName, entry);
    
    if (!fieldValue.isValid()) {
        return false;
    }
    
    // For field references without comparison, check if field exists
    return true;
}

bool FilterEvaluator::evaluateUnary(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    if (!node.left) return false;
    
    bool operand = evaluate(*node.left, entry);
    
    switch (node.op) {
        case FilterOp::Not:
            return !operand;
        default:
            return false;
    }
}

bool FilterEvaluator::evaluateBinary(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    if (!node.left || !node.right) return false;
    
    switch (node.op) {
        case FilterOp::And:
            return evaluate(*node.left, entry) && evaluate(*node.right, entry);
        
        case FilterOp::Or:
            return evaluate(*node.left, entry) || evaluate(*node.right, entry);
        
        case FilterOp::Equal:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) == 0;
        
        case FilterOp::NotEqual:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) != 0;
        
        case FilterOp::Greater:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) > 0;
        
        case FilterOp::Less:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) < 0;
        
        case FilterOp::GreaterEqual:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) >= 0;
        
        case FilterOp::LessEqual:
            return compareValues(getNodeValue(*node.left, entry), node.right->value) <= 0;
        
        case FilterOp::Contains: {
            QString strVal = getNodeValue(*node.left, entry).toString();
            QString searchStr = node.right->value.toString();
            return strVal.contains(searchStr, Qt::CaseInsensitive);
        }
        
        case FilterOp::StartsWith: {
            QString strVal = getNodeValue(*node.left, entry).toString();
            QString prefix = node.right->value.toString();
            return strVal.startsWith(prefix, Qt::CaseInsensitive);
        }
        
        case FilterOp::EndsWith: {
            QString strVal = getNodeValue(*node.left, entry).toString();
            QString suffix = node.right->value.toString();
            return strVal.endsWith(suffix, Qt::CaseInsensitive);
        }
        
        default:
            return false;
    }
}

bool FilterEvaluator::evaluateProtocol(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    QString proto = node.protocolName.toLower();
    
    // Check against protocol summary or transport protocol
    if (proto == "tcp") return entry.transportProtocol == 6;
    if (proto == "udp") return entry.transportProtocol == 17;
    if (proto == "icmp") return entry.transportProtocol == 1;
    if (proto == "ipv4") return entry.ipVersion == 4;
    if (proto == "ipv6") return entry.ipVersion == 6;
    if (proto == "arp") return entry.etherType == 0x0806;
    if (proto == "dns") return (entry.srcPort == 53 || entry.dstPort == 53);
    if (proto == "http") return (entry.srcPort == 80 || entry.dstPort == 80);
    if (proto == "https" || proto == "tls") return (entry.srcPort == 443 || entry.dstPort == 443);
    
    return false;
}

QVariant FilterEvaluator::getField(const QString& protocol, const QString& field, 
                                    const core::PacketIndexEntry& entry) {
    QString proto = protocol.toLower();
    QString fld = field.toLower();
    
    if (proto == "frame" || proto == "eth") {
        if (fld == "len" || fld == "length") return static_cast<qlonglong>(entry.capturedLength);
    }
    
    if (proto == "ip" || proto == "ipv4") {
        if (fld == "src" || fld == "source") {
            return formatIpv4(entry.srcIp);
        }
        if (fld == "dst" || fld == "destination") {
            return formatIpv4(entry.dstIp);
        }
        if (fld == "addr" || fld == "address") {
            // Check both src and dst
            return formatIpv4(entry.srcIp);  // Simplified - would need special handling
        }
    }
    
    if (proto == "ipv6") {
        if (fld == "src" || fld == "source") {
            return formatIpv6(entry.srcIp);
        }
        if (fld == "dst" || fld == "destination") {
            return formatIpv6(entry.dstIp);
        }
    }
    
    if (proto == "tcp") {
        if (fld == "srcport" || fld == "sport") return static_cast<qlonglong>(entry.srcPort);
        if (fld == "dstport" || fld == "dport") return static_cast<qlonglong>(entry.dstPort);
        if (fld == "port") {
            return static_cast<qlonglong>(entry.srcPort);  // Simplified
        }
        if (fld == "flags") return static_cast<qlonglong>(entry.tcpFlags);
        if (fld == "syn") return (entry.tcpFlags & 0x02) != 0;
        if (fld == "ack") return (entry.tcpFlags & 0x10) != 0;
        if (fld == "fin") return (entry.tcpFlags & 0x01) != 0;
        if (fld == "rst") return (entry.tcpFlags & 0x04) != 0;
    }
    
    if (proto == "udp") {
        if (fld == "srcport" || fld == "sport") return static_cast<qlonglong>(entry.srcPort);
        if (fld == "dstport" || fld == "dport") return static_cast<qlonglong>(entry.dstPort);
        if (fld == "port") return static_cast<qlonglong>(entry.srcPort);
    }
    
    return QVariant();
}

QVariant FilterEvaluator::getNodeValue(const FilterAstNode& node, const core::PacketIndexEntry& entry) {
    if (node.type == NodeType::Value) {
        return node.value;
    } else if (node.type == NodeType::Field) {
        return getField(node.protocolName, node.fieldName, entry);
    }
    return QVariant();
}

int FilterEvaluator::compareValues(const QVariant& left, const QVariant& right) {
    // Handle numeric comparisons
    if (left.canConvert<qlonglong>() && right.canConvert<qlonglong>()) {
        qlonglong l = left.toLongLong();
        qlonglong r = right.toLongLong();
        if (l < r) return -1;
        if (l > r) return 1;
        return 0;
    }
    
    // Handle double comparisons
    if (left.canConvert<double>() && right.canConvert<double>()) {
        double l = left.toDouble();
        double r = right.toDouble();
        if (l < r) return -1;
        if (l > r) return 1;
        return 0;
    }
    
    // String comparison
    QString l = left.toString();
    QString r = right.toString();
    return l.compare(r, Qt::CaseInsensitive);
}

QString FilterEvaluator::formatIpv4(const std::array<uint8_t, 16>& ip) {
    // IPv4 is stored in the last 4 bytes
    return QString("%1.%2.%3.%4")
        .arg(ip[12]).arg(ip[13]).arg(ip[14]).arg(ip[15]);
}

QString FilterEvaluator::formatIpv6(const std::array<uint8_t, 16>& ip) {
    return QString("%1:%2:%3:%4:%5:%6:%7:%8")
        .arg((ip[0] << 8) | ip[1], 4, 16, QChar('0'))
        .arg((ip[2] << 8) | ip[3], 4, 16, QChar('0'))
        .arg((ip[4] << 8) | ip[5], 4, 16, QChar('0'))
        .arg((ip[6] << 8) | ip[7], 4, 16, QChar('0'))
        .arg((ip[8] << 8) | ip[9], 4, 16, QChar('0'))
        .arg((ip[10] << 8) | ip[11], 4, 16, QChar('0'))
        .arg((ip[12] << 8) | ip[13], 4, 16, QChar('0'))
        .arg((ip[14] << 8) | ip[15], 4, 16, QChar('0'));
}

bool FilterEvaluator::toBool(const QVariant& val) {
    if (val.canConvert<bool>()) return val.toBool();
    if (val.canConvert<int>()) return val.toInt() != 0;
    if (val.canConvert<QString>()) return !val.toString().isEmpty();
    return val.isValid();
}

} // namespace pcapanalyzer::filter
