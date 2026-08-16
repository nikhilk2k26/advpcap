#include "core/utils/ByteUtils.h"

namespace pcap_analyzer::core {

QString formatMacAddress(const uint8_t* macBytes)
{
    if (!macBytes) {
        return QStringLiteral("00:00:00:00:00:00");
    }
    
    return QStringLiteral("%1:%2:%3:%4:%5:%6")
        .arg(macBytes[0], 2, 16, QChar('0'))
        .arg(macBytes[1], 2, 16, QChar('0'))
        .arg(macBytes[2], 2, 16, QChar('0'))
        .arg(macBytes[3], 2, 16, QChar('0'))
        .arg(macBytes[4], 2, 16, QChar('0'))
        .arg(macBytes[5], 2, 16, QChar('0'));
}

QString formatIpv4Address(const uint8_t* ipBytes)
{
    if (!ipBytes) {
        return QStringLiteral("0.0.0.0");
    }
    
    return QStringLiteral("%1.%2.%3.%4")
        .arg(ipBytes[0])
        .arg(ipBytes[1])
        .arg(ipBytes[2])
        .arg(ipBytes[3]);
}

QString formatIpv6Address(const uint8_t* ipBytes)
{
    if (!ipBytes) {
        return QStringLiteral("::");
    }
    
    // Simple formatting without compression
    return QStringLiteral("%1%2:%3%4:%5%6:%7%8:%9%10:%11%12:%13%14:%15%16")
        .arg(ipBytes[0], 2, 16, QChar('0'))
        .arg(ipBytes[1], 2, 16, QChar('0'))
        .arg(ipBytes[2], 2, 16, QChar('0'))
        .arg(ipBytes[3], 2, 16, QChar('0'))
        .arg(ipBytes[4], 2, 16, QChar('0'))
        .arg(ipBytes[5], 2, 16, QChar('0'))
        .arg(ipBytes[6], 2, 16, QChar('0'))
        .arg(ipBytes[7], 2, 16, QChar('0'))
        .arg(ipBytes[8], 2, 16, QChar('0'))
        .arg(ipBytes[9], 2, 16, QChar('0'))
        .arg(ipBytes[10], 2, 16, QChar('0'))
        .arg(ipBytes[11], 2, 16, QChar('0'))
        .arg(ipBytes[12], 2, 16, QChar('0'))
        .arg(ipBytes[13], 2, 16, QChar('0'))
        .arg(ipBytes[14], 2, 16, QChar('0'))
        .arg(ipBytes[15], 2, 16, QChar('0'));
}

QString formatHexDump(const uint8_t* data, size_t length, const QString& separator)
{
    if (!data || length == 0) {
        return QString();
    }
    
    QString result;
    result.reserve(length * 3);
    
    for (size_t i = 0; i < length; ++i) {
        if (i > 0) {
            result += separator;
        }
        result += QString::number(data[i], 16).toUpper().rightJustified(2, '0');
    }
    
    return result;
}

QString formatHexAsciiDump(const QByteArray& data, size_t maxBytes)
{
    if (data.isEmpty()) {
        return QString();
    }
    
    const size_t len = (maxBytes > 0) ? std::min(static_cast<size_t>(data.size()), maxBytes) 
                                       : static_cast<size_t>(data.size());
    
    QString result;
    result.reserve(len * 4);
    
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0 && i > 0) {
            result += QStringLiteral("\n");
        }
        
        const uint8_t byte = static_cast<uint8_t>(data[static_cast<int>(i)]);
        result += QString::number(byte, 16).toUpper().rightJustified(2, '0');
        result += QStringLiteral(" ");
        
        if (i % 16 == 7) {
            result += QStringLiteral("  ");
        }
    }
    
    // Add ASCII representation
    result += QStringLiteral("  |");
    for (size_t i = 0; i < len; ++i) {
        const char c = data[static_cast<int>(i)];
        if (c >= 32 && c < 127) {
            result += QChar(c);
        } else {
            result += QStringLiteral(".");
        }
    }
    result += QStringLiteral("|");
    
    return result;
}

uint16_t calculateChecksum(const uint8_t* data, size_t length)
{
    if (!data || length == 0) {
        return 0;
    }
    
    uint32_t sum = 0;
    size_t i = 0;
    
    // Sum 16-bit words
    while (i + 1 < length) {
        sum += (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
        i += 2;
    }
    
    // Add remaining byte if odd length
    if (i < length) {
        sum += static_cast<uint16_t>(data[i]) << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return static_cast<uint16_t>(~sum);
}

bool verifyChecksum(const uint8_t* data, size_t length, uint16_t expected)
{
    return calculateChecksum(data, length) == expected;
}

} // namespace pcap_analyzer::core
