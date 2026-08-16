#pragma once

#include <QString>
#include <QByteArray>
#include <array>
#include <memory>
#include <vector>
#include <QReadWriteLock>

namespace pcapanalyzer::core {

/**
 * @brief Context passed to dissectors during packet parsing
 */
struct PacketContext {
    const uint8_t* data{nullptr};
    size_t length{0};
    uint16_t linkType{0};
    uint64_t timestampNs{0};
    uint32_t capturedLength{0};
    uint32_t originalLength{0};
    
    // Parsed metadata from index (if available)
    uint8_t ipVersion{0};
    uint8_t transportProtocol{0};
    std::array<uint8_t, 16> srcIp{};
    std::array<uint8_t, 16> dstIp{};
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    uint8_t tcpFlags{0};
    
    // For multi-layer dissection
    size_t offset{0};
};

/**
 * @brief Result of a dissection operation
 */
struct DissectionResult {
    struct FieldInfo {
        QString name;
        QString value;
        QString summary;
        int offset{0};
        int length{0};
        bool expanded{false};
        std::vector<FieldInfo> children;
        
        FieldInfo() = default;
        FieldInfo(const QString& n, const QString& v, int o = 0, int l = 0)
            : name(n), value(v), offset(o), length(l) {}
    };
    
    QString protocolName;
    QString protocolId;
    QString summaryText;
    std::vector<FieldInfo> fields;
    bool success{false};
    QString errorMessage;
    int nextLayerOffset{0};
    QString nextProtocol;
    
    static DissectionResult createSuccess(const QString& proto, const QString& protoId, const QString& summary) {
        DissectionResult result;
        result.protocolName = proto;
        result.protocolId = protoId;
        result.summaryText = summary;
        result.success = true;
        return result;
    }
    
    static DissectionResult createError(const QString& msg) {
        DissectionResult result;
        result.errorMessage = msg;
        result.success = false;
        return result;
    }
};

/**
 * @brief Interface for protocol dissectors
 */
class IDissector {
public:
    virtual ~IDissector() = default;
    
    /**
     * @brief Returns the human-readable name of this dissector
     */
    virtual QString name() const = 0;
    
    /**
     * @brief Returns the protocol identifier (e.g., "tcp", "http")
     */
    virtual QString protocolId() const = 0;
    
    /**
     * @brief Checks if this dissector can handle the given context
     */
    virtual bool canDissect(const PacketContext& context) const = 0;
    
    /**
     * @brief Dissects the packet data and returns structured results
     */
    virtual DissectionResult dissect(PacketContext& context) = 0;
    
    /**
     * @brief Returns the next-layer protocol ID if known
     */
    virtual QString nextProtocol() const { return {}; }
    
    /**
     * @brief Register sub-dissector for next layer
     */
    void setNextDissector(const QString& protocolId);
    
protected:
    QString m_nextProtocol;
};

/**
 * @brief Registry for managing and selecting protocol dissectors
 */
class DissectorRegistry {
public:
    static DissectorRegistry& instance();
    
    void registerDissector(std::unique_ptr<IDissector> dissector);
    IDissector* getDissector(const QString& protocolId) const;
    IDissector* findDissector(const PacketContext& context) const;
    IDissector* findDissectorByEtherType(uint16_t etherType) const;
    IDissector* findDissectorByIpProtocol(uint8_t protocol) const;
    
    const std::vector<std::unique_ptr<IDissector>>& allDissectors() const {
        return m_dissectors;
    }
    
    void initializeBuiltInDissectors();
    
private:
    std::vector<std::unique_ptr<IDissector>> m_dissectors;
    mutable QReadWriteLock m_lock;
    std::unordered_map<uint16_t, QString> m_etherTypeMap;
    std::unordered_map<uint8_t, QString> m_ipProtocolMap;
};

} // namespace pcapanalyzer::core
