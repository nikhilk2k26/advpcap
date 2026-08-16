#pragma once

#include "core/CaptureFileReader.h"
#include <QFile>
#include <memory>
#include <vector>

namespace pcap_analyzer::core {

/**
 * @brief Adapter for reading legacy PCAP files using PcapPlusPlus
 * 
 * Wraps PcapPlusPlus IFileReader to provide uniform interface.
 * Supports both regular PCAP and compressed PCAP files if PcapPlusPlus supports them.
 */
class PcapFileReaderAdapter : public IPacketSource
{
public:
    explicit PcapFileReaderAdapter(const QString& filePath);
    ~PcapFileReaderAdapter() override;
    
    // Disable copying
    PcapFileReaderAdapter(const PcapFileReaderAdapter&) = delete;
    PcapFileReaderAdapter& operator=(const PcapFileReaderAdapter&) = delete;
    
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
     * @brief Get the underlying PcapPlusPlus reader
     * @note Use with caution - ties implementation to PcapPlusPlus
     */
    // TODO: Consider removing this method to maintain abstraction
    // void* getPcapPlusPlusReader() const;
    
private:
    QString m_filePath;
    QFile m_file;
    bool m_isOpen = false;
    CaptureFileMetadata m_metadata;
    
    // PcapPlusPlus reader - using void* to avoid direct dependency in header
    // TODO: Use proper PcapPlusPlus include when available
    void* m_pcapReader = nullptr;
    
    struct PcapGlobalHeader
    {
        uint32_t magicNumber;
        uint16_t versionMajor;
        uint16_t versionMinor;
        int32_t  thisZone;
        uint32_t sigFigs;
        uint32_t snapLen;
        uint32_t network;
    };
    
    struct PcapPacketHeader
    {
        uint32_t tsSec;
        uint32_t tsUsec;
        uint32_t inclLen;
        uint32_t origLen;
    };
    
    [[nodiscard]] bool isLittleEndian() const;
    [[nodiscard]] bool validateMagicNumber(uint32_t magic) const;
    [[nodiscard]] static PcapGlobalHeader readGlobalHeader(QIODevice& device, bool& isSwapped, QString& error);
};

} // namespace pcap_analyzer::core
