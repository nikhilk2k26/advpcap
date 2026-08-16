#pragma once

#include "proto/Dissector.h"
#include <vector>
#include <memory>

namespace pcapanalyzer::core {

/**
 * @brief Decodes packets using registered dissectors
 */
class PacketDecoder {
public:
    PacketDecoder();
    
    /**
     * @brief Fully decode a packet into a protocol tree
     * @param data Raw packet data
     * @param length Data length
     * @param linkType Link-layer type (e.g., 1 for Ethernet)
     * @param timestampNs Packet timestamp in nanoseconds
     * @return Vector of dissection results (one per layer)
     */
    std::vector<DissectionResult> decodePacket(
        const uint8_t* data,
        size_t length,
        uint16_t linkType,
        uint64_t timestampNs = 0);
    
    /**
     * @brief Get the top-level summary text for a packet
     */
    QString getPacketSummary(const std::vector<DissectionResult>& layers) const;
    
    /**
     * @brief Initialize built-in dissectors
     */
    void initializeDissectors();
    
private:
    DissectorRegistry& m_registry;
};

} // namespace pcapanalyzer::core
