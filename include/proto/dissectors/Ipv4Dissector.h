#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for IPv4 packets
 */
class Ipv4Dissector : public IDissector {
public:
    QString name() const override { return "IPv4"; }
    QString protocolId() const override { return "ipv4"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t MIN_HEADER_SIZE = 20;
};

} // namespace pcapanalyzer::core
