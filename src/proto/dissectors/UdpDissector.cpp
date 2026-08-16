#include "proto/dissectors/UdpDissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool UdpDissector::canDissect(const PacketContext& context) const {
    // Check if transport protocol is UDP (17) or if we have enough data
    if (context.transportProtocol == 17) {
        return context.length >= HEADER_SIZE;
    }
    
    // Heuristic: check minimum size
    return context.length >= HEADER_SIZE;
}

DissectionResult UdpDissector::dissect(PacketContext& context) {
    if (context.length < HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for UDP header");
    }
    
    const auto* data = context.data + context.offset;
    
    uint16_t srcPort = qFromBigEndian<uint16_t>(data);
    uint16_t dstPort = qFromBigEndian<uint16_t>(data + 2);
    uint16_t length = qFromBigEndian<uint16_t>(data + 4);
    uint16_t checksum = qFromBigEndian<uint16_t>(data + 6);
    
    // Determine application protocol based on port
    QString appProto;
    QString protoName;
    if (srcPort == 53 || dstPort == 53) {
        appProto = "dns";
        protoName = "DNS";
    } else if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) {
        appProto = "dhcp";
        protoName = "DHCP";
    } else if (srcPort == 123 || dstPort == 123) {
        appProto = "ntp";
        protoName = "NTP";
    } else if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) {
        appProto = "snmp";
        protoName = "SNMP";
    } else if (srcPort == 514 || dstPort == 514) {
        appProto = "syslog";
        protoName = "Syslog";
    } else if (srcPort == 500 || dstPort == 500) {
        appProto = "ike";
        protoName = "IKE";
    } else if (srcPort == 4500 || dstPort == 4500) {
        appProto = "ipsec_nat";
        protoName = "IPSec NAT-T";
    }
    
    m_nextProtocol = appProto;
    
    QString summary;
    if (!protoName.isEmpty()) {
        summary = QString("%1 %2 → %3").arg(protoName).arg(srcPort).arg(dstPort);
    } else {
        summary = QString("%1 → %2, Length: %3").arg(srcPort).arg(dstPort).arg(length);
    }
    
    DissectionResult result = DissectionResult::createSuccess("User Datagram Protocol", "udp", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Source Port", QString::number(srcPort), 0, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Destination Port", QString::number(dstPort), 2, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Length", QString::number(length), 4, 2));
    
    QString checksumStr = checksum == 0 ? "0x0000 (not calculated)" 
                                        : QString("0x%1").arg(checksum, 4, 16, QChar('0'));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Checksum", checksumStr, 6, 2));
    
    // Set up next layer
    result.nextLayerOffset = static_cast<int>(context.offset + HEADER_SIZE);
    result.nextProtocol = appProto;
    
    // Update context with parsed info
    context.srcPort = srcPort;
    context.dstPort = dstPort;
    
    return result;
}

} // namespace pcapanalyzer::core
