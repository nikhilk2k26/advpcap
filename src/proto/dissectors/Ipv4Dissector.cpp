#include "proto/dissectors/Ipv4Dissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool Ipv4Dissector::canDissect(const PacketContext& context) const {
    // Check if we have enough data and either:
    // 1. EtherType indicates IPv4, or
    // 2. Link type is raw IP, or
    // 3. Index metadata says IPv4
    if (context.length < MIN_HEADER_SIZE) {
        return false;
    }
    
    // Check version field (first nibble should be 4)
    uint8_t version = (context.data[context.offset] >> 4) & 0x0F;
    return version == 4;
}

DissectionResult Ipv4Dissector::dissect(PacketContext& context) {
    if (context.length < MIN_HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for IPv4 header");
    }
    
    const auto* data = context.data + context.offset;
    
    uint8_t versionIhl = data[0];
    uint8_t version = (versionIhl >> 4) & 0x0F;
    uint8_t ihl = (versionIhl & 0x0F) * 4;  // Header length in bytes
    
    if (version != 4) {
        return DissectionResult::createError("Invalid IPv4 version");
    }
    
    if (context.length < ihl) {
        return DissectionResult::createError("Packet too short for IPv4 header with options");
    }
    
    uint8_t dscpEcn = data[1];
    uint16_t totalLength = qFromBigEndian<uint16_t>(data + 2);
    uint16_t identification = qFromBigEndian<uint16_t>(data + 4);
    uint16_t flagsFragment = qFromBigEndian<uint16_t>(data + 6);
    uint8_t ttl = data[8];
    uint8_t protocol = data[9];
    uint16_t checksum = qFromBigEndian<uint16_t>(data + 10);
    
    // Source and destination IP
    std::array<uint8_t, 4> srcIp;
    std::array<uint8_t, 4> dstIp;
    std::memcpy(srcIp.data(), data + 12, 4);
    std::memcpy(dstIp.data(), data + 16, 4);
    
    QString srcIpStr = QString("%1.%2.%3.%4")
        .arg(srcIp[0]).arg(srcIp[1]).arg(srcIp[2]).arg(srcIp[3]);
    QString dstIpStr = QString("%1.%2.%3.%4")
        .arg(dstIp[0]).arg(dstIp[1]).arg(dstIp[2]).arg(dstIp[3]);
    
    // Protocol name
    QString protoName;
    QString nextProto;
    switch (protocol) {
        case 6:
            protoName = "TCP";
            nextProto = "tcp";
            break;
        case 17:
            protoName = "UDP";
            nextProto = "udp";
            break;
        case 1:
            protoName = "ICMP";
            nextProto = "icmp";
            break;
        default:
            protoName = QString("Protocol %1").arg(protocol);
            break;
    }
    
    // Flags
    bool dontFragment = (flagsFragment & 0x4000) != 0;
    bool moreFragments = (flagsFragment & 0x2000) != 0;
    uint16_t fragmentOffset = flagsFragment & 0x1FFF;
    
    QString summary = QString("%1 → %2, %3").arg(srcIpStr, dstIpStr, protoName);
    
    DissectionResult result = DissectionResult::createSuccess("Internet Protocol Version 4", "ipv4", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Version", QString::number(version), 0, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Header Length", QString("%1 bytes").arg(ihl), 0, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Differentiated Services Field", QString("0x%1").arg(dscpEcn, 2, 16, QChar('0')), 1, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Total Length", QString::number(totalLength), 2, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Identification", QString("0x%1").arg(identification, 4, 16, QChar('0')), 4, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Flags", 
        QString("0x%1 (Don't Fragment: %2, More Fragments: %3)")
            .arg((flagsFragment >> 13) & 0x7, 1, 2, QChar('0'))
            .arg(dontFragment ? "Yes" : "No")
            .arg(moreFragments ? "Yes" : "No"),
        6, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Fragment Offset", fragmentOffset == 0 ? "0" : QString::number(fragmentOffset * 8), 6, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Time to Live", QString::number(ttl), 8, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Protocol", QString("%1 (%2)").arg(protocol).arg(protoName), 9, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Header Checksum", QString("0x%1").arg(checksum, 4, 16, QChar('0')), 10, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Source Address", srcIpStr, 12, 4));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Destination Address", dstIpStr, 16, 4));
    
    // Set up next layer
    m_nextProtocol = nextProto;
    result.nextLayerOffset = static_cast<int>(context.offset + ihl);
    result.nextProtocol = nextProto;
    
    // Update context with parsed info
    context.ipVersion = 4;
    context.transportProtocol = protocol;
    std::copy(srcIp.begin(), srcIp.end(), context.srcIp.begin() + 12);
    std::copy(dstIp.begin(), dstIp.end(), context.dstIp.begin() + 12);
    
    return result;
}

} // namespace pcapanalyzer::core
