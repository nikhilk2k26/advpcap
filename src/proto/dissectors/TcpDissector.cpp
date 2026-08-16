#include "proto/dissectors/TcpDissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool TcpDissector::canDissect(const PacketContext& context) const {
    // Check if transport protocol is TCP (6) or if we have enough data and port-like structure
    if (context.transportProtocol == 6) {
        return context.length >= MIN_HEADER_SIZE;
    }
    
    // Heuristic: check if we have enough data and the ports look reasonable
    if (context.length < MIN_HEADER_SIZE) {
        return false;
    }
    
    // This is a weak heuristic - should primarily rely on transportProtocol
    return true;
}

DissectionResult TcpDissector::dissect(PacketContext& context) {
    if (context.length < MIN_HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for TCP header");
    }
    
    const auto* data = context.data + context.offset;
    
    uint16_t srcPort = qFromBigEndian<uint16_t>(data);
    uint16_t dstPort = qFromBigEndian<uint16_t>(data + 2);
    uint32_t seqNum = qFromBigEndian<uint32_t>(data + 4);
    uint32_t ackNum = qFromBigEndian<uint32_t>(data + 8);
    uint8_t dataOffsetFlags = data[12];
    uint8_t dataOffset = ((dataOffsetFlags >> 4) & 0x0F) * 4;
    uint8_t flags = data[13];
    uint16_t windowSize = qFromBigEndian<uint16_t>(data + 14);
    uint16_t checksum = qFromBigEndian<uint16_t>(data + 16);
    uint16_t urgentPointer = qFromBigEndian<uint16_t>(data + 18);
    
    // Parse flags
    bool fin = (flags & 0x01) != 0;
    bool syn = (flags & 0x02) != 0;
    bool rst = (flags & 0x04) != 0;
    bool psh = (flags & 0x08) != 0;
    bool ack = (flags & 0x10) != 0;
    bool urg = (flags & 0x20) != 0;
    bool ece = (flags & 0x40) != 0;
    bool cwr = (flags & 0x80) != 0;
    
    // Build flags string
    QStringList flagList;
    if (fin) flagList << "FIN";
    if (syn) flagList << "SYN";
    if (rst) flagList << "RST";
    if (psh) flagList << "PSH";
    if (ack) flagList << "ACK";
    if (urg) flagList << "URG";
    if (ece) flagList << "ECE";
    if (cwr) flagList << "CWR";
    
    QString flagsStr = flagList.isEmpty() ? "None" : flagList.join(", ");
    
    // Determine application protocol based on port
    QString appProto;
    if (srcPort == 80 || dstPort == 80) {
        appProto = "http";
    } else if (srcPort == 443 || dstPort == 443) {
        appProto = "tls";
    } else if (srcPort == 53 || dstPort == 53) {
        appProto = "dns";
    } else if (srcPort == 22 || dstPort == 22) {
        appProto = "ssh";
    } else if (srcPort == 21 || dstPort == 21) {
        appProto = "ftp";
    } else if (srcPort == 25 || dstPort == 25) {
        appProto = "smtp";
    }
    
    m_nextProtocol = appProto;
    
    QString summary;
    if (syn && !ack) {
        summary = QString("[SYN] %1 → %2").arg(srcPort).arg(dstPort);
    } else if (syn && ack) {
        summary = QString("[SYN, ACK] %1 → %2").arg(srcPort).arg(dstPort);
    } else if (fin) {
        summary = QString("[FIN] %1 → %2").arg(srcPort).arg(dstPort);
    } else if (rst) {
        summary = QString("[RST] %1 → %2").arg(srcPort).arg(dstPort);
    } else {
        summary = QString("%1 → %2 [%3]").arg(srcPort).arg(dstPort).arg(flagsStr);
    }
    
    DissectionResult result = DissectionResult::createSuccess("Transmission Control Protocol", "tcp", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Source Port", QString::number(srcPort), 0, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Destination Port", QString::number(dstPort), 2, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Sequence Number", QString::number(seqNum), 4, 4));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Acknowledgment Number", ack ? QString::number(ackNum) : "0 (not valid)", 8, 4));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Header Length", QString("%1 bytes").arg(dataOffset), 12, 1));
    
    // Flags field with detailed breakdown
    QString flagsDetail = QString("0x%1 (%2)").arg(flags, 2, 16, QChar('0'), flagsStr);
    DissectionResult::FieldInfo flagsField("Flags", flagsDetail, 13, 1);
    flagsField.children.push_back(DissectionResult::FieldInfo("FIN", fin ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("SYN", syn ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("RST", rst ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("PSH", psh ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("ACK", ack ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("URG", urg ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("ECE", ece ? "Set" : "Not set"));
    flagsField.children.push_back(DissectionResult::FieldInfo("CWR", cwr ? "Set" : "Not set"));
    result.fields.push_back(flagsField);
    
    result.fields.push_back(DissectionResult::FieldInfo(
        "Window Size", QString::number(windowSize), 14, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Checksum", QString("0x%1").arg(checksum, 4, 16, QChar('0')), 16, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Urgent Pointer", urgentPointer ? QString::number(urgentPointer) : "0", 18, 2));
    
    // Set up next layer
    result.nextLayerOffset = static_cast<int>(context.offset + dataOffset);
    result.nextProtocol = appProto;
    
    // Update context with parsed info
    context.srcPort = srcPort;
    context.dstPort = dstPort;
    context.tcpFlags = flags;
    
    return result;
}

} // namespace pcapanalyzer::core
