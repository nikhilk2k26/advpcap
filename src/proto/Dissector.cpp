#include "proto/Dissector.h"
#include "proto/dissectors/EthernetDissector.h"
#include "proto/dissectors/Ipv4Dissector.h"
#include "proto/dissectors/Ipv6Dissector.h"
#include "proto/dissectors/TcpDissector.h"
#include "proto/dissectors/UdpDissector.h"
#include "proto/dissectors/DnsDissector.h"
#include "proto/dissectors/ArpDissector.h"
#include <QWriteLocker>
#include <QReadLocker>

namespace pcapanalyzer::core {

void IDissector::setNextDissector(const QString& protocolId) {
    m_nextProtocol = protocolId;
}

DissectorRegistry& DissectorRegistry::instance() {
    static DissectorRegistry instance;
    return instance;
}

void DissectorRegistry::registerDissector(std::unique_ptr<IDissector> dissector) {
    QWriteLocker locker(&m_lock);
    
    if (!dissector) {
        return;
    }
    
    // Register ether type mapping if applicable
    if (auto* ethDisc = dynamic_cast<EthernetDissector*>(dissector.get())) {
        // Ethernet doesn't map to ether types, it handles them
    }
    
    m_dissectors.push_back(std::move(dissector));
}

IDissector* DissectorRegistry::getDissector(const QString& protocolId) const {
    QReadLocker locker(&m_lock);
    
    for (const auto& dissector : m_dissectors) {
        if (dissector->protocolId() == protocolId) {
            return dissector.get();
        }
    }
    
    return nullptr;
}

IDissector* DissectorRegistry::findDissector(const PacketContext& context) const {
    QReadLocker locker(&m_lock);
    
    // Try to find based on transport protocol first
    if (context.transportProtocol > 0) {
        auto it = m_ipProtocolMap.find(context.transportProtocol);
        if (it != m_ipProtocolMap.end()) {
            for (const auto& dissector : m_dissectors) {
                if (dissector->protocolId() == it->second && dissector->canDissect(context)) {
                    return dissector.get();
                }
            }
        }
    }
    
    // Try all dissectors
    for (const auto& dissector : m_dissectors) {
        if (dissector->canDissect(context)) {
            return dissector.get();
        }
    }
    
    return nullptr;
}

IDissector* DissectorRegistry::findDissectorByEtherType(uint16_t etherType) const {
    QReadLocker locker(&m_lock);
    
    auto it = m_etherTypeMap.find(etherType);
    if (it != m_etherTypeMap.end()) {
        return getDissector(it->second);
    }
    
    return nullptr;
}

IDissector* DissectorRegistry::findDissectorByIpProtocol(uint8_t protocol) const {
    QReadLocker locker(&m_lock);
    
    auto it = m_ipProtocolMap.find(protocol);
    if (it != m_ipProtocolMap.end()) {
        return getDissector(it->second);
    }
    
    return nullptr;
}

void DissectorRegistry::initializeBuiltInDissectors() {
    // Register built-in dissectors in order of specificity
    registerDissector(std::make_unique<ArpDissector>());
    registerDissector(std::make_unique<EthernetDissector>());
    registerDissector(std::make_unique<Ipv4Dissector>());
    registerDissector(std::make_unique<Ipv6Dissector>());
    registerDissector(std::make_unique<TcpDissector>());
    registerDissector(std::make_unique<UdpDissector>());
    registerDissector(std::make_unique<DnsDissector>());
    
    // Set up protocol mappings
    m_etherTypeMap[0x0800] = "ipv4";
    m_etherTypeMap[0x86DD] = "ipv6";
    m_etherTypeMap[0x0806] = "arp";
    
    m_ipProtocolMap[6] = "tcp";   // TCP
    m_ipProtocolMap[17] = "udp";  // UDP
    m_ipProtocolMap[1] = "icmp";  // ICMP
    m_ipProtocolMap[58] = "icmpv6"; // ICMPv6
}

} // namespace pcapanalyzer::core
