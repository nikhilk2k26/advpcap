#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for UDP datagrams
 */
class UdpDissector : public IDissector {
public:
    QString name() const override { return "UDP"; }
    QString protocolId() const override { return "udp"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t HEADER_SIZE = 8;
};

} // namespace pcapanalyzer::core
