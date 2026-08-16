#pragma once

#include "proto/Dissector.h"
#include <cstdint>

namespace pcapanalyzer::core {

/**
 * @brief Dissector for Ethernet II frames
 */
class EthernetDissector : public IDissector {
public:
    QString name() const override { return "Ethernet"; }
    QString protocolId() const override { return "eth"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t HEADER_SIZE = 14;
    
private:
    struct EthernetHeader {
        uint8_t dstMac[6];
        uint8_t srcMac[6];
        uint16_t etherType;
    };
};

} // namespace pcapanalyzer::core
