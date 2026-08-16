#pragma once

#include <QString>
#include <cstdint>
#include <utility>

namespace pcap_analyzer::core {

/**
 * @brief Convert nanoseconds since epoch to seconds and nanoseconds components
 * @param timestampNs Timestamp in nanoseconds since Unix epoch
 * @return Pair of (seconds, nanoseconds)
 */
[[nodiscard]] std::pair<uint64_t, uint32_t> nanosecondsToSeconds(uint64_t timestampNs);

/**
 * @brief Format timestamp as human-readable string
 * @param timestampNs Timestamp in nanoseconds since Unix epoch
 * @param showDate If true, include date; if false, show time only
 * @return Formatted timestamp string (e.g., "2024-01-15 14:30:45.123456")
 */
[[nodiscard]] QString formatTimestamp(uint64_t timestampNs, bool showDate = true);

/**
 * @brief Format time delta between two timestamps
 * @param deltaNs Delta in nanoseconds
 * @return Formatted delta string (e.g., "0.001234" or "1.234 ms")
 */
[[nodiscard]] QString formatTimeDelta(uint64_t deltaNs);

/**
 * @brief Get current system time as nanoseconds since epoch
 */
[[nodiscard]] uint64_t getCurrentTimestampNs();

} // namespace pcap_analyzer::core
