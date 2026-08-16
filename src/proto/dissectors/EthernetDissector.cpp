#include "proto/dissectors/EthernetDissector.h"
#include <QByteArray>
#include <QString>

namespace pcapanalyzer::core {

bool EthernetDissector::canDissect(const PacketContext& context) const {
    // Can dissect if we have at least Ethernet header size and link type is Ethernet
    return context.length >= HEADER_SIZE && 
           (context.linkType == 1 || context.linkType == 0); // DLT_EN10MB or unknown
}

DissectionResult EthernetDissector::dissect(PacketContext& context) {
    if (context.length < HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for Ethernet header");
    }
    
    const auto* data = context.data + context.offset;
    
    // Parse Ethernet header (big-endian for ether type)
    const uint8_t* dstMac = data;
    const uint8_t* srcMac = data + 6;
    uint16_t etherType = qFromBigEndian<uint16_t>(data + 12);
    
    // Format MAC addresses
    QString dstMacStr = QString("%1:%2:%3:%4:%5:%6")
        .arg(dstMac[0], 2, 16, QChar('0'))
        .arg(dstMac[1], 2, 16, QChar('0'))
        .arg(dstMac[2], 2, 16, QChar('0'))
        .arg(dstMac[3], 2, 16, QChar('0'))
        .arg(dstMac[4], 2, 16, QChar('0'))
        .arg(dstMac[5], 2, 16, QChar('0'));
    
    QString srcMacStr = QString("%1:%2:%3:%4:%5:%6")
        .arg(srcMac[0], 2, 16, QChar('0'))
        .arg(srcMac[1], 2, 16, QChar('0'))
        .arg(srcMac[2], 2, 16, QChar('0'))
        .arg(srcMac[3], 2, 16, QChar('0'))
        .arg(srcMac[4], 2, 16, QChar('0'))
        .arg(srcMac[5], 2, 16, QChar('0'));
    
    // Determine next protocol based on EtherType
    QString nextProto;
    QString protoName;
    switch (etherType) {
        case 0x0800:
            nextProto = "ipv4";
            protoName = "IPv4";
            break;
        case 0x86DD:
            nextProto = "ipv6";
            protoName = "IPv6";
            break;
        case 0x0806:
            nextProto = "arp";
            protoName = "ARP";
            break;
        case 0x8100:
            nextProto = "vlan";
            protoName = "802.1Q VLAN";
            break;
        default:
            protoName = QString("Unknown (0x%1)").arg(etherType, 4, 16, QChar('0'));
            break;
    }
    
    QString summary = QString("%1 → %2, %3").arg(srcMacStr, dstMacStr, protoName);
    
    DissectionResult result = DissectionResult::createSuccess("Ethernet II", "eth", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Destination MAC", dstMacStr, 0, 6));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Source MAC", srcMacStr, 6, 6));
    result.fields.push_back(DissectionResult::FieldInfo(
        "EtherType", QString("0x%1 (%2)").arg(etherType, 4, 16, QChar('0'), protoName), 12, 2));
    
    // Set up next layer
    m_nextProtocol = nextProto;
    result.nextLayerOffset = static_cast<int>(context.offset + HEADER_SIZE);
    result.nextProtocol = nextProto;
    
    return result;
}

} // namespace pcapanalyzer::core
