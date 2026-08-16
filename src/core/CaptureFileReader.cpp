#include "core/CaptureFileReader.h"
#include "core/PcapFileReaderAdapter.h"
#include "core/PcapngFileReaderAdapter.h"
#include <QFile>

namespace pcap_analyzer::core {

/**
 * @brief Factory function to create appropriate packet source based on file type
 * @param filePath Path to capture file
 * @param error Output parameter for error message
 * @return Unique pointer to IPacketSource, or nullptr on failure
 */
std::unique_ptr<IPacketSource> createPacketSource(const QString& filePath, QString& error)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        error = QStringLiteral("Cannot open file: %1").arg(file.errorString());
        return nullptr;
    }
    
    // Read first 4 bytes to detect file type
    QByteArray magic = file.read(4);
    file.close();
    
    if (magic.size() < 4) {
        error = "File too small to be a valid capture file";
        return nullptr;
    }
    
    const uint32_t magicNum = *reinterpret_cast<const uint32_t*>(magic.constData());
    
    // PCAP magic numbers:
    // 0xA1B2C3D4 - Native byte order, microsecond resolution
    // 0xD4C3B2A1 - Swapped byte order, microsecond resolution  
    // 0xA1B23C4D - Native byte order, nanosecond resolution
    // 0x4D3CB2A1 - Swapped byte order, nanosecond resolution
    if (magicNum == 0xA1B2C3D4 || magicNum == 0xD4C3B2A1 ||
        magicNum == 0xA1B23C4D || magicNum == 0x4D3CB2A1) {
        return std::make_unique<PcapFileReaderAdapter>(filePath);
    }
    
    // PCAP-NG magic number:
    // 0x1A2B3C4D - Native byte order
    // 0x4D3C2B1A - Swapped byte order
    if (magicNum == 0x1A2B3C4D || magicNum == 0x4D3C2B1A) {
        return std::make_unique<PcapngFileReaderAdapter>(filePath);
    }
    
    error = QStringLiteral("Unknown file format - magic number: 0x%1")
                .arg(magicNum, 8, 16, QChar('0'));
    return nullptr;
}

} // namespace pcap_analyzer::core
