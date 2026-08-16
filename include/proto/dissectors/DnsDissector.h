#pragma once

#include "proto/Dissector.h"

namespace pcapanalyzer::core {

/**
 * @brief Dissector for DNS messages
 */
class DnsDissector : public IDissector {
public:
    QString name() const override { return "DNS"; }
    QString protocolId() const override { return "dns"; }
    
    bool canDissect(const PacketContext& context) const override;
    DissectionResult dissect(PacketContext& context) override;
    
    static constexpr size_t MIN_HEADER_SIZE = 12;
};

} // namespace pcapanalyzer::core
