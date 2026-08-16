#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for IPv6 packets
 */
class Ipv6Dissector : public IDissector {
public:
    QString name() const override { return "IPv6"; }
    QString protocolId() const override { return "ipv6"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t HEADER_SIZE = 40;
};

} // namespace pcapanalyzer::core
