#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <chrono>

namespace pcap_analyzer::core {

/**
 * @brief Compact protocol summary identifier for packet index
 */
enum class ProtocolSummary : uint16_t
{
    Unknown = 0,
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Dns,
    Http,
    Tls,
    Quic,
    Smb,
    Dhcp,
    Ntp,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Snmp,
    Rtp,
    Mdns,
    Llmnr,
    Netbios,
    Custom = 0xFFFE,
    MultiProtocol = 0xFFFF
};

/**
 * @brief Convert protocol summary to human-readable string
 */
[[nodiscard]] QString protocolSummaryToString(ProtocolSummary proto);

/**
 * @brief Parse protocol summary from string
 */
[[nodiscard]] ProtocolSummary protocolSummaryFromString(const QString& str);

/**
 * @brief Bit flags for TCP flags
 */
enum class TcpFlags : uint8_t
{
    None = 0x00,
    Fin = 0x01,
    Syn = 0x02,
    Rst = 0x04,
    Psh = 0x08,
    Ack = 0x10,
    Urg = 0x20,
    Ece = 0x40,
    Cwr = 0x80
};

Q_DECLARE_FLAGS(TcpFlagsEnum, TcpFlags)
Q_DECLARE_OPERATORS_FOR_FLAGS(TcpFlagsEnum)

/**
 * @brief Error flags for malformed packets
 */
enum class ErrorFlags : uint16_t
{
    None = 0x0000,
    Truncated = 0x0001,
    InvalidLength = 0x0002,
    InvalidChecksum = 0x0004,
    InvalidHeader = 0x0008,
    UnknownLinkType = 0x0010,
    MalformedEthernet = 0x0020,
    MalformedIp = 0x0040,
    MalformedTcp = 0x0080,
    MalformedUdp = 0x0100,
    MalformedDns = 0x0200,
    IpVersionMismatch = 0x0400,
    LengthMismatch = 0x0800
};

Q_DECLARE_FLAGS(ErrorFlagsEnum, ErrorFlags)
Q_DECLARE_OPERATORS_FOR_FLAGS(ErrorFlagsEnum)

/**
 * @brief Link layer type identifiers
 */
enum class LinkType : uint16_t
{
    Unknown = 0,
    Ethernet = 1,      // DLT_EN10MB
    TokenRing = 6,     // DLT_IEEE802
    ArcNet = 7,        // DLT_ARCNET
    Slip = 8,          // DLT_SLIP
    Ppp = 9,           // DLT_PPP
    Fddi = 10,         // DLT_FDDI
    AtmRfc1483 = 101,  // DLT_ATM_RFC1483
    RawIp = 102,       // DLT_RAW
    PppHdlc = 50,      // DLT_PPP_HDLC
    PppEther = 51,     // DLT_PPP_ETHER
    LinuxSll = 113,    // DLT_LINUX_SLL
    IPv4 = 228,        // DLT_IPV4
    IPv6 = 229         // DLT_IPV6
};

/**
 * @brief Transport protocol identifiers
 */
enum class TransportProtocol : uint8_t
{
    Unknown = 0,
    HopOpt = 0,     // IPv6 Hop-by-Hop Options
    Icmp = 1,
    Igmp = 2,
    Ggp = 3,
    Tcp = 6,
    Egp = 8,
    Pup = 12,
    Udp = 17,
    Idp = 22,
    Rdp = 27,
    Ipv6Route = 43,
    Ipv6Frag = 44,
    Rsvp = 46,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    Ipv6NoNxt = 59,
    Ipv6Opts = 60,
    AnyHostInternal = 61,
    Cftp = 62,
    SatExpak = 64,
    Ipvx = 77,
    Vines = 82,
    Rspf = 89,
    Eigrp = 88,
    Ospfigp = 89,
    L2tp = 115,
    Sctp = 132,
    Fc = 133,
    Mh = 135,
    UdpLite = 136,
    MplsInIp = 137,
    Shim6 = 140
};

/**
 * @brief IP version identifier
 */
enum class IpVersion : uint8_t
{
    None = 0,
    IPv4 = 4,
    IPv6 = 6
};

/**
 * @brief Compact packet index entry - 96 bytes total
 * 
 * Designed for minimal memory footprint while supporting:
 * - Sorting by various fields
 * - Filtering without full packet decode
 * - Statistics computation
 * - Conversation analysis
 */
struct PacketIndexEntry
{
    // Core identification (16 bytes)
    uint64_t packetId;        // Internal sequential packet ID
    uint64_t fileOffset;      // Byte offset in capture file
    
    // Timing (8 bytes)
    uint64_t timestampNs;     // Normalized nanosecond timestamp since epoch
    
    // Lengths (8 bytes)
    uint32_t capturedLength;  // Captured packet length
    uint32_t originalLength;  // Original packet length on wire
    
    // Network layer info (36 bytes)
    std::array<uint8_t, 16> srcIp;   // Source IP (IPv4 in first 4 bytes, or full IPv6)
    std::array<uint8_t, 16> dstIp;   // Destination IP
    
    // Ports and protocols (8 bytes)
    uint16_t srcPort;         // Source port (0 if not applicable)
    uint16_t dstPort;         // Destination port
    uint16_t etherType;       // Ethernet type (0 if not Ethernet or no ethertype)
    uint16_t linkType;        // Link layer type
    
    // Protocol summary (4 bytes)
    uint8_t ipVersion;        // IP version (0, 4, or 6)
    uint8_t transportProtocol; // Transport protocol number
    uint8_t protocolSummary;  // ProtocolSummary enum value
    uint8_t sectionId;        // PCAP-NG section ID (0 for PCAP)
    
    // Flags and metadata (4 bytes)
    uint8_t tcpFlags;         // TCP flags if TCP packet
    uint8_t interfaceId;      // Interface ID (for PCAP-NG)
    ErrorFlagsEnum errorFlags; // Error indicators
    uint8_t reserved;         // Alignment padding
    
    // Constructors
    PacketIndexEntry() 
        : packetId(0)
        , fileOffset(0)
        , timestampNs(0)
        , capturedLength(0)
        , originalLength(0)
        , srcIp{}
        , dstIp{}
        , srcPort(0)
        , dstPort(0)
        , etherType(0)
        , linkType(0)
        , ipVersion(0)
        , transportProtocol(0)
        , protocolSummary(static_cast<uint8_t>(ProtocolSummary::Unknown))
        , sectionId(0)
        , tcpFlags(0)
        , interfaceId(0)
        , errorFlags(ErrorFlags::None)
        , reserved(0)
    {}
    
    // Comparison operators for sorting
    [[nodiscard]] bool operator<(const PacketIndexEntry& other) const
    {
        return packetId < other.packetId;
    }
    
    [[nodiscard]] bool operator==(const PacketIndexEntry& other) const
    {
        return packetId == other.packetId;
    }
    
    /**
     * @brief Check if this entry has valid IP addresses
     */
    [[nodiscard]] bool hasValidIp() const
    {
        return ipVersion == 4 || ipVersion == 6;
    }
    
    /**
     * @brief Check if this is a TCP packet
     */
    [[nodiscard]] bool isTcp() const
    {
        return transportProtocol == static_cast<uint8_t>(TransportProtocol::Tcp);
    }
    
    /**
     * @brief Check if this is a UDP packet
     */
    [[nodiscard]] bool isUdp() const
    {
        return transportProtocol == static_cast<uint8_t>(TransportProtocol::Udp);
    }
    
    /**
     * @brief Get source IP as string (for display purposes)
     */
    [[nodiscard]] std::string getSrcIpString() const;
    
    /**
     * @brief Get destination IP as string
     */
    [[nodiscard]] std::string getDstIpString() const;
    
    /**
     * @brief Check if packet has errors
     */
    [[nodiscard]] bool hasErrors() const
    {
        return errorFlags != ErrorFlags::None;
    }
};

static_assert(sizeof(PacketIndexEntry) == 96, "PacketIndexEntry must be 96 bytes for cache efficiency");

} // namespace pcap_analyzer::core
