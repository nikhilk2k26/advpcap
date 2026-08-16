#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for ARP packets
 */
class ArpDissector : public IDissector {
public:
    QString name() const override { return "ARP"; }
    QString protocolId() const override { return "arp"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t MIN_HEADER_SIZE = 28;  // Ethernet + ARP minimum
};

} // namespace pcapanalyzer::core
