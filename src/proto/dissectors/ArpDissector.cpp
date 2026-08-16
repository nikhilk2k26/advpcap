#include "proto/dissectors/ArpDissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool ArpDissector::canDissect(const PacketContext& context) const {
    // Check EtherType for ARP (0x0806) or if link type indicates ARP
    if (context.length < MIN_HEADER_SIZE) {
        return false;
    }
    
    // For Ethernet, check if EtherType at offset 12 is 0x0806
    if (context.linkType == 1 && context.length >= 14) {
        uint16_t etherType = qFromBigEndian<uint16_t>(context.data + 12);
        return etherType == 0x0806;
    }
    
    return false;
}

DissectionResult ArpDissector::dissect(PacketContext& context) {
    // Skip Ethernet header if present
    size_t arpOffset = context.offset;
    if (context.linkType == 1 && context.length >= 14) {
        uint16_t etherType = qFromBigEndian<uint16_t>(context.data + 12);
        if (etherType == 0x0806) {
            arpOffset = context.offset + 14;
        }
    }
    
    if (context.length < arpOffset + MIN_HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for ARP");
    }
    
    const auto* data = context.data + arpOffset;
    
    uint16_t hardwareType = qFromBigEndian<uint16_t>(data);
    uint16_t protocolType = qFromBigEndian<uint16_t>(data + 2);
    uint8_t hardwareSize = data[4];
    uint8_t protocolSize = data[5];
    uint16_t opcode = qFromBigEndian<uint16_t>(data + 6);
    
    // Validate basic ARP parameters
    if (hardwareType != 1 || protocolType != 0x0800) {
        // Non-Ethernet or non-IPv4 ARP - handle generically
    }
    
    if (hardwareSize != 6 || protocolSize != 4) {
        return DissectionResult::createError("Unsupported ARP address sizes");
    }
    
    // Extract addresses
    std::array<uint8_t, 6> senderHwAddr;
    std::array<uint8_t, 4> senderProtoAddr;
    std::array<uint8_t, 6> targetHwAddr;
    std::array<uint8_t, 4> targetProtoAddr;
    
    std::memcpy(senderHwAddr.data(), data + 8, 6);
    std::memcpy(senderProtoAddr.data(), data + 14, 4);
    std::memcpy(targetHwAddr.data(), data + 18, 6);
    std::memcpy(targetProtoAddr.data(), data + 24, 4);
    
    // Format addresses
    QString senderHwStr = QString("%1:%2:%3:%4:%5:%6")
        .arg(senderHwAddr[0], 2, 16, QChar('0'))
        .arg(senderHwAddr[1], 2, 16, QChar('0'))
        .arg(senderHwAddr[2], 2, 16, QChar('0'))
        .arg(senderHwAddr[3], 2, 16, QChar('0'))
        .arg(senderHwAddr[4], 2, 16, QChar('0'))
        .arg(senderHwAddr[5], 2, 16, QChar('0'));
    
    QString senderProtoStr = QString("%1.%2.%3.%4")
        .arg(senderProtoAddr[0])
        .arg(senderProtoAddr[1])
        .arg(senderProtoAddr[2])
        .arg(senderProtoAddr[3]);
    
    QString targetHwStr = QString("%1:%2:%3:%4:%5:%6")
        .arg(targetHwAddr[0], 2, 16, QChar('0'))
        .arg(targetHwAddr[1], 2, 16, QChar('0'))
        .arg(targetHwAddr[2], 2, 16, QChar('0'))
        .arg(targetHwAddr[3], 2, 16, QChar('0'))
        .arg(targetHwAddr[4], 2, 16, QChar('0'))
        .arg(targetHwAddr[5], 2, 16, QChar('0'));
    
    QString targetProtoStr = QString("%1.%2.%3.%4")
        .arg(targetProtoAddr[0])
        .arg(targetProtoAddr[1])
        .arg(targetProtoAddr[2])
        .arg(targetProtoAddr[3]);
    
    // Opcode interpretation
    QString opcodeStr;
    switch (opcode) {
        case 1:
            opcodeStr = "Request";
            break;
        case 2:
            opcodeStr = "Reply";
            break;
        case 3:
            opcodeStr = "RARP Request";
            break;
        case 4:
            opcodeStr = "RARP Reply";
            break;
        default:
            opcodeStr = QString("Unknown (%1)").arg(opcode);
            break;
    }
    
    QString summary = QString("%1, %2 → %3").arg(opcodeStr).arg(senderProtoStr, targetProtoStr);
    
    DissectionResult result = DissectionResult::createSuccess("Address Resolution Protocol", "arp", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Hardware Type", 
        hardwareType == 1 ? "Ethernet (1)" : QString("Unknown (%1)").arg(hardwareType),
        0, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Protocol Type",
        protocolType == 0x0800 ? "IPv4 (0x0800)" : QString("0x%1").arg(protocolType, 4, 16, QChar('0')),
        2, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Hardware Size", QString::number(hardwareSize), 4, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Protocol Size", QString::number(protocolSize), 5, 1));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Opcode", QString("%1 (%2)").arg(opcode).arg(opcodeStr), 6, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Sender MAC Address", senderHwStr, 8, 6));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Sender IP Address", senderProtoStr, 14, 4));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Target MAC Address", 
        targetHwAddr[0] == 0 && targetHwAddr[1] == 0 && targetHwAddr[2] == 0 &&
        targetHwAddr[3] == 0 && targetHwAddr[4] == 0 && targetHwAddr[5] == 0
            ? "00:00:00:00:00:00 (ignored in request)"
            : targetHwStr,
        18, 6));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Target IP Address", targetProtoStr, 24, 4));
    
    result.nextLayerOffset = static_cast<int>(arpOffset + 28);
    
    return result;
}

} // namespace pcapanalyzer::core
