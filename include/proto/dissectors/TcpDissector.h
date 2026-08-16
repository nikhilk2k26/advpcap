#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for TCP segments
 */
class TcpDissector : public IDissector {
public:
    QString name() const override { return "TCP"; }
    QString protocolId() const override { return "tcp"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t MIN_HEADER_SIZE = 20;
};

} // namespace pcapanalyzer::core
