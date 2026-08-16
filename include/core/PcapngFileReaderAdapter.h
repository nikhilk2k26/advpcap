#pragma once

#include "core/CaptureFileReader.h"
#include <QFile>
#include <vector>
#include <unordered_map>

namespace pcap_analyzer::core {

/**
 * @brief Interface description for PCAP-NG
 */
struct PcapNgInterfaceInfo
{
    uint16_t interfaceId = 0;
    uint16_t linkType = 0;
    uint32_t snapLen = 65535;
    QString name;
    QString description;
    uint64_t timestampResolution = 1000000000; // nanoseconds by default
};

/**
 * @brief Section information for PCAP-NG files
 */
struct PcapNgSectionInfo
{
    uint8_t sectionId = 0;
    uint32_t byteOrderMagic = 0x1A2B3C4D;
    uint16_t majorVersion = 1;
    uint16_t minorVersion = 0;
    int64_t sectionLength = -1; // -1 means unknown/endless
    QString applicationName;
    QString applicationComment;
    QByteArray hardwareId;
};

/**
 * @brief Adapter for reading PCAP-NG files
 * 
 * Handles multiple sections, interfaces, and various block types.
 * Implements proper byte order handling and option parsing.
 */
class PcapngFileReaderAdapter : public IPacketSource
{
public:
    explicit PcapngFileReaderAdapter(const QString& filePath);
    ~PcapngFileReaderAdapter() override;
    
    // Disable copying
    PcapngFileReaderAdapter(const PcapngFileReaderAdapter&) = delete;
    PcapngFileReaderAdapter& operator=(const PcapngFileReaderAdapter&) = delete;
    
    [[nodiscard]] bool open(QString& error) override;
    void close() override;
    [[nodiscard]] bool isOpen() const override;
    [[nodiscard]] CaptureFileMetadata getMetadata() const override;
    
    [[nodiscard]] bool readPacketHeader(
        uint64_t fileOffset,
        PacketHeaderInfo& headerOut,
        QString& error) override;
    
    [[nodiscard]] bool readPacketData(
        uint64_t fileOffset,
        QByteArray& dataOut,
        QString& error) override;
    
    [[nodiscard]] uint64_t getFileSize() const override;
    [[nodiscard]] bool supportsRandomAccess() const override;
    
    /**
     * @brief Get interface information by ID
     */
    [[nodiscard]] std::optional<PcapNgInterfaceInfo> getInterfaceInfo(uint16_t interfaceId) const;
    
    /**
     * @brief Get section information by ID
     */
    [[nodiscard]] std::optional<PcapNgSectionInfo> getSectionInfo(uint8_t sectionId) const;
    
    /**
     * @brief Get all interface IDs
     */
    [[nodiscard]] std::vector<uint16_t> getAllInterfaceIds() const;
    
private:
    QString m_filePath;
    QFile m_file;
    bool m_isOpen = false;
    CaptureFileMetadata m_metadata;
    
    // Current section state
    PcapNgSectionInfo m_currentSection;
    std::unordered_map<uint16_t, PcapNgInterfaceInfo> m_interfaces;
    
    // Block type constants
    static constexpr uint16_t BlockTypeSectionHeader = 0x0A0D0D0A;
    static constexpr uint16_t BlockTypeInterfaceDesc = 0x00000001;
    static constexpr uint16_t BlockTypeEnhancedPacket = 0x00000006;
    static constexpr uint16_t BlockTypeSimplePacket = 0x00000003;
    static constexpr uint16_t BlockTypeInterfaceStats = 0x00000005;
    static constexpr uint16_t BlockTypeNameResolution = 0x00000004;
    static constexpr uint16_t BlockTypeCustom = 0x00000BAD;
    static constexpr uint16_t BlockTypeDecryptionSecrets = 0x00000007;
    
    // Option codes
    static constexpr uint16_t OptEndOfOpt = 0;
    static constexpr uint16_t OptComment = 1;
    
    // Interface description options
    static constexpr uint16_t OptIfName = 2;
    static constexpr uint16_t OptIfDescription = 3;
    static constexpr uint16_t OptIfIPv4Addr = 4;
    static constexpr uint16_t OptIfIPv6Addr = 5;
    static constexpr uint16_t OptIfMACAddr = 6;
    static constexpr uint16_t OptIfEuiAddr = 7;
    static constexpr uint16_t OptIfTSResol = 9;
    static constexpr uint16_t OptIfFilter = 10;
    static constexpr uint16_t OptIfOS = 11;
    static constexpr uint16_t OptIfTsoffset = 12;
    
    // Section header options
    static constexpr uint16_t OptSHBHardware = 2;
    static constexpr uint16_t OptSHBOS = 3;
    static constexpr uint16_t OptSHBUserApp = 4;
    
    [[nodiscard]] bool parseSectionHeader(QDataStream& stream, QString& error);
    [[nodiscard]] bool parseInterfaceDescription(QDataStream& stream, QString& error);
    [[nodiscard]] bool parseEnhancedPacketBlock(QDataStream& stream, uint64_t offset, PacketHeaderInfo& headerOut, QString& error);
    [[nodiscard]] bool parseSimplePacketBlock(QDataStream& stream, uint64_t offset, PacketHeaderInfo& headerOut, QString& error);
    [[nodiscard]] bool skipBlock(QDataStream& stream, uint32_t blockLength, QString& error);
    [[nodiscard]] bool readOptions(QDataStream& stream, std::function<void(uint16_t, uint16_t, const QByteArray&)> callback, QString& error);
    
    [[nodiscard]] static uint32_t swapByteOrder(uint32_t value, bool needsSwap);
    [[nodiscard]] static uint16_t swapByteOrder(uint16_t value, bool needsSwap);
};

} // namespace pcap_analyzer::core
