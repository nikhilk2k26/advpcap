#include "proto/dissectors/Ipv6Dissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool Ipv6Dissector::canDissect(const PacketContext& context) const {
    if (context.length < HEADER_SIZE) {
        return false;
    }
    
    // Check version field (first nibble should be 6)
    uint8_t version = (context.data[context.offset] >> 4) & 0x0F;
    return version == 6;
}

DissectionResult Ipv6Dissector::dissect(PacketContext& context) {
    if (context.length < HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for IPv6 header");
    }
    
    const auto* data = context.data + context.offset;
    
    uint32_t verTrafficClassFlowLabel = qFromBigEndian<uint32_t>(data);
    uint8_t version = (verTrafficClassFlowLabel >> 28) & 0x0F;
    uint16_t payloadLength = qFromBigEndian<uint16_t>(data + 4);
    uint8_t nextHeader = data[6];
    uint8_t hopLimit = data[7];
    
    // Source and destination IPv6 addresses (16 bytes each)
    std::array<uint8_t, 16> srcIp;
    std::array<uint8_t, 16> dstIp;
    std::memcpy(srcIp.data(), data + 8, 16);
    std::memcpy(dstIp.data(), data + 24, 16);
    
    // Format IPv6 addresses (simplified - full compression would be more complex)
    QString srcIpStr = QString("%1:%2:%3:%4:%5:%6:%7:%8")
        .arg((srcIp[0] << 8) | srcIp[1], 4, 16, QChar('0'))
        .arg((srcIp[2] << 8) | srcIp[3], 4, 16, QChar('0'))
        .arg((srcIp[4] << 8) | srcIp[5], 4, 16, QChar('0'))
        .arg((srcIp[6] << 8) | srcIp[7], 4, 16, QChar('0'))
        .arg((srcIp[8] << 8) | srcIp[9], 4, 16, QChar('0'))
        .arg((srcIp[10] << 8) | srcIp[11], 4, 16, QChar('0'))
        .arg((srcIp[12] << 8) | srcIp[13], 4, 16, QChar('0'))
        .arg((srcIp[14] << 8) | srcIp[15], 4, 16, QChar('0'));
    
    QString dstIpStr = QString("%1:%2:%3:%4:%5:%6:%7:%8")
        .arg((dstIp[0] << 8) | dstIp[1], 4, 16, QChar('0'))
        .arg((dstIp[2] << 8) | dstIp[3], 4, 16, QChar('0'))
        .arg((dstIp[4] << 8) | dstIp[5], 4, 16, QChar('0'))
        .arg((dstIp[6] << 8) | dstIp[7], 4, 16, QChar('0'))
        .arg((dstIp[8] << 8) | dstIp[9], 4, 16, QChar('0'))
        .arg((dstIp[10] << 8) | dstIp[11], 4, 16, QChar('0'))
        .arg((dstIp[12] << 8) | dstIp[13], 4, 16, QChar('0'))
        .arg((dstIp[14] << 8) | dstIp[15], 4, 16, QChar('0'));
    
    // Next header name
    QString protoName;
    QString nextProto;
    switch (nextHeader) {
        case 6:
            protoName = "TCP";
            nextProto = "tcp";
            break;
        case 17:
            protoName = "UDP";
            nextProto = "udp";
            break;
        case 58:
            protoName = "ICMPv6";
            nextProto = "icmpv6";
            break;
        case 0:
            protoName = "Hop-by-Hop Options";
            nextProto = "ipv6_opts";
            break;
        case 43:
            protoName = "Routing";
            nextProto = "ipv6_routing";
            break;
        case 44:
            protoName = "Fragment";
            nextProto = "ipv6_frag";
            break;
        default:
            protoName = QString("Next Header %1").arg(nextHeader);
            break;
    }
    
    QString summary = QString("%1 → %2, %3").arg(srcIpStr.left(15), dstIpStr.left(15), protoName);
    
    DissectionResult result = DissectionResult::createSuccess("Internet Protocol Version 6", "ipv6", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Version", QString::number(version), 0, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Traffic Class", QString("0x%1").arg((verTrafficClassFlowLabel >> 20) & 0xFF, 2, 16, QChar('0')), 0, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Flow Label", QString("0x%1").arg(verTrafficClassFlowLabel & 0xFFFFF, 5, 16, QChar('0')), 1, 3));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Payload Length", QString::number(payloadLength), 4, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Next Header", QString("%1 (%2)").arg(nextHeader).arg(protoName), 6, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Hop Limit", QString::number(hopLimit), 7, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Source Address", srcIpStr, 8, 16));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Destination Address", dstIpStr, 24, 16));
    
    // Set up next layer
    m_nextProtocol = nextProto;
    result.nextLayerOffset = static_cast<int>(context.offset + HEADER_SIZE);
    result.nextProtocol = nextProto;
    
    // Update context with parsed info
    context.ipVersion = 6;
    context.transportProtocol = nextHeader;
    context.srcIp = srcIp;
    context.dstIp = dstIp;
    
    return result;
}

} // namespace pcapanalyzer::core
