#include "proto/dissectors/DnsDissector.h"
#include <QByteArray>

namespace pcapanalyzer::core {

bool DnsDissector::canDissect(const PacketContext& context) const {
    // Check if we're on DNS port or if previous dissector indicated DNS
    if (context.srcPort == 53 || context.dstPort == 53) {
        return context.length >= MIN_HEADER_SIZE;
    }
    
    // Could also check if nextProtocol from UDP was "dns"
    return false;
}

DissectionResult DnsDissector::dissect(PacketContext& context) {
    if (context.length < MIN_HEADER_SIZE) {
        return DissectionResult::createError("Packet too short for DNS header");
    }
    
    const auto* data = context.data + context.offset;
    
    uint16_t transactionId = qFromBigEndian<uint16_t>(data);
    uint16_t flags = qFromBigEndian<uint16_t>(data + 2);
    uint16_t questionCount = qFromBigEndian<uint16_t>(data + 4);
    uint16_t answerCount = qFromBigEndian<uint16_t>(data + 6);
    uint16_t authorityCount = qFromBigEndian<uint16_t>(data + 8);
    uint16_t additionalCount = qFromBigEndian<uint16_t>(data + 10);
    
    // Parse flags
    bool isResponse = (flags & 0x8000) != 0;
    uint8_t opcode = (flags >> 11) & 0x0F;
    bool authoritativeAnswer = (flags & 0x0400) != 0;
    bool truncated = (flags & 0x0200) != 0;
    bool recursionDesired = (flags & 0x0100) != 0;
    bool recursionAvailable = (flags & 0x0080) != 0;
    uint8_t responseCode = flags & 0x000F;
    
    // Determine message type
    QString msgType = isResponse ? "Response" : "Query";
    
    // Opcode names
    static const char* opcodeNames[] = {
        "QUERY", "IQUERY", "STATUS", "Reserved",
        "NOTIFY", "UPDATE", "Reserved", "Reserved",
        "Reserved", "Reserved", "Reserved", "Reserved",
        "Reserved", "Reserved", "Reserved", "Reserved"
    };
    QString opcodeStr = opcode < 16 ? opcodeNames[opcode] : QString("Unknown(%1)").arg(opcode);
    
    // Response code names (for responses)
    static const char* rcodeNames[] = {
        "No Error", "Format Error", "Server Failure", "Name Error",
        "Not Implemented", "Refused", "YXDomain", "YXRRSet",
        "NXRRSet", "Not Auth", "Not Zone", "Reserved",
        "Reserved", "Reserved", "Reserved", "Reserved"
    };
    QString rcodeStr = responseCode < 16 ? rcodeNames[responseCode] : QString("Unknown(%1)").arg(responseCode);
    
    // Try to parse the first query name (simplified - full DNS parsing is complex)
    QString queryName;
    uint16_t queryType = 0;
    uint16_t queryClass = 0;
    
    if (questionCount > 0 && context.length > MIN_HEADER_SIZE) {
        // Simple attempt to extract domain name
        size_t pos = MIN_HEADER_SIZE;
        QByteArray nameBytes;
        
        while (pos < context.length && data[pos] != 0) {
            uint8_t labelLen = data[pos];
            
            // Check for compression pointer
            if ((labelLen & 0xC0) == 0xC0) {
                // Compression pointer - skip for now
                break;
            }
            
            if (labelLen > 63) {
                // Invalid label length
                break;
            }
            
            if (pos + 1 + labelLen >= context.length) {
                break;
            }
            
            if (!nameBytes.isEmpty()) {
                nameBytes.append('.');
            }
            nameBytes.append(reinterpret_cast<const char*>(data + pos + 1), labelLen);
            pos += 1 + labelLen;
        }
        
        if (!nameBytes.isEmpty()) {
            queryName = QString::fromUtf8(nameBytes);
            
            // Try to read query type and class
            if (pos + 4 < context.length) {
                queryType = qFromBigEndian<uint16_t>(data + pos + 1);
                queryClass = qFromBigEndian<uint16_t>(data + pos + 3);
            }
        }
    }
    
    // Query type names
    QString qtypeStr;
    switch (queryType) {
        case 1: qtypeStr = "A"; break;
        case 2: qtypeStr = "NS"; break;
        case 5: qtypeStr = "CNAME"; break;
        case 6: qtypeStr = "SOA"; break;
        case 12: qtypeStr = "PTR"; break;
        case 15: qtypeStr = "MX"; break;
        case 16: qtypeStr = "TXT"; break;
        case 28: qtypeStr = "AAAA"; break;
        case 33: qtypeStr = "SRV"; break;
        case 255: qtypeStr = "ANY"; break;
        default: qtypeStr = queryType ? QString::number(queryType) : "";
    }
    
    // Build summary
    QString summary;
    if (isResponse) {
        summary = QString("Response, %1, %2").arg(rcodeStr).arg(queryName.isEmpty() ? "" : queryName);
    } else {
        summary = QString("%1, %2 %3").arg(msgType).arg(qtypeStr).arg(queryName);
    }
    
    DissectionResult result = DissectionResult::createSuccess("Domain Name System", "dns", summary);
    
    // Add fields
    result.fields.push_back(DissectionResult::FieldInfo(
        "Transaction ID", QString("0x%1").arg(transactionId, 4, 16, QChar('0')), 0, 2));
    
    // Flags breakdown
    QString flagsDetail = QString("0x%1").arg(flags, 4, 16, QChar('0'));
    DissectionResult::FieldInfo flagsField("Flags", flagsDetail, 2, 2);
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Response", isResponse ? "Yes" : "No"));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Opcode", opcodeStr));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Authoritative Answer", authoritativeAnswer ? "Yes" : "No"));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Truncated", truncated ? "Yes" : "No"));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Recursion Desired", recursionDesired ? "Yes" : "No"));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Recursion Available", recursionAvailable ? "Yes" : "No"));
    flagsField.children.push_back(DissectionResult::FieldInfo(
        "Response Code", rcodeStr));
    result.fields.push_back(flagsField);
    
    result.fields.push_back(DissectionResult::FieldInfo(
        "Questions", QString::number(questionCount), 4, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Answers", QString::number(answerCount), 6, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Authority RRs", QString::number(authorityCount), 8, 2));
    result.fields.push_back(DissectionResult::FieldInfo(
        "Additional RRs", QString::number(additionalCount), 10, 2));
    
    if (!queryName.isEmpty()) {
        result.fields.push_back(DissectionResult::FieldInfo(
            "Queries", queryName, 12, static_cast<int>(pos)));
        if (!qtypeStr.isEmpty()) {
            result.fields.back().children.push_back(
                DissectionResult::FieldInfo("Type", qtypeStr));
        }
    }
    
    result.nextLayerOffset = static_cast<int>(context.offset + MIN_HEADER_SIZE);
    
    return result;
}

} // namespace pcapanalyzer::core
