#pragma once

#include <cstdint>
#include <QString>
#include <QByteArray>

namespace pcap_analyzer::core {

/**
 * @brief Utility functions for byte manipulation and formatting
 */

/**
 * @brief Format a MAC address as human-readable string
 * @param macBytes 6-byte MAC address
 * @return Formatted string (e.g., "00:1A:2B:3C:4D:5E")
 */
[[nodiscard]] QString formatMacAddress(const uint8_t* macBytes);

/**
 * @brief Format IPv4 address as human-readable string
 * @param ipBytes 4-byte IPv4 address
 * @return Formatted string (e.g., "192.168.1.1")
 */
[[nodiscard]] QString formatIpv4Address(const uint8_t* ipBytes);

/**
 * @brief Format IPv6 address as human-readable string
 * @param ipBytes 16-byte IPv6 address
 * @return Formatted string (e.g., "2001:db8::1")
 */
[[nodiscard]] QString formatIpv6Address(const uint8_t* ipBytes);

/**
 * @brief Format raw bytes as hex string
 * @param data Pointer to byte array
 * @param length Number of bytes
 * @param separator Separator between bytes (default: space)
 * @return Formatted hex string (e.g., "0A 1B 2C 3D")
 */
[[nodiscard]] QString formatHexDump(const uint8_t* data, size_t length, const QString& separator = QStringLiteral(" "));

/**
 * @brief Format raw bytes as hex string with ASCII representation
 * @param data QByteArray containing bytes
 * @param maxBytes Maximum number of bytes to show (0 = no limit)
 * @return Formatted string with hex and ASCII side by side
 */
[[nodiscard]] QString formatHexAsciiDump(const QByteArray& data, size_t maxBytes = 0);

/**
 * @brief Calculate simple checksum (one's complement sum)
 * @param data Pointer to byte array
 * @param length Number of bytes
 * @return One's complement checksum
 */
[[nodiscard]] uint16_t calculateChecksum(const uint8_t* data, size_t length);

/**
 * @brief Verify checksum against expected value
 * @param data Pointer to byte array
 * @param length Number of bytes
 * @param expected Expected checksum value
 * @return True if checksum matches
 */
[[nodiscard]] bool verifyChecksum(const uint8_t* data, size_t length, uint16_t expected);

} // namespace pcap_analyzer::core
