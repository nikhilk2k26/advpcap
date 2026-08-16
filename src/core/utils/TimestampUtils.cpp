#include "core/utils/TimestampUtils.h"
#include <QDateTime>
#include <ctime>

namespace pcap_analyzer::core {

std::pair<uint64_t, uint32_t> nanosecondsToSeconds(uint64_t timestampNs)
{
    const uint64_t secs = timestampNs / 1000000000ULL;
    const uint32_t nsecs = static_cast<uint32_t>(timestampNs % 1000000000ULL);
    return {secs, nsecs};
}

QString formatTimestamp(uint64_t timestampNs, bool showDate)
{
    const auto [secs, nsecs] = nanosecondsToSeconds(timestampNs);
    
    if (secs == 0 && nsecs == 0) {
        return QStringLiteral("0.000000");
    }
    
    const QDateTime dt = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(secs), Qt::UTC);
    
    if (showDate) {
        // Format: "2024-01-15 14:30:45.123456"
        QString baseStr = dt.toString("yyyy-MM-dd hh:mm:ss");
        return QStringLiteral("%1.%1").arg(baseStr).arg(nsecs / 1000, 6, 10, QChar('0'));
    } else {
        // Format: "14:30:45.123456"
        QString baseStr = dt.toString("hh:mm:ss");
        return QStringLiteral("%1.%1").arg(baseStr).arg(nsecs / 1000, 6, 10, QChar('0'));
    }
}

QString formatTimeDelta(uint64_t deltaNs)
{
    if (deltaNs == 0) {
        return QStringLiteral("0.000000");
    }
    
    const double deltaSecs = static_cast<double>(deltaNs) / 1e9;
    
    if (deltaSecs < 0.001) {
        // Show in microseconds
        return QStringLiteral("%1 µs").arg(deltaNs / 1000.0, 0, 'f', 2);
    } else if (deltaSecs < 1.0) {
        // Show in milliseconds
        return QStringLiteral("%1 ms").arg(deltaSecs * 1000.0, 0, 'f', 3);
    } else {
        // Show in seconds
        return QStringLiteral("%1 s").arg(deltaSecs, 0, 'f', 6);
    }
}

uint64_t getCurrentTimestampNs()
{
    const auto now = std::chrono::system_clock::now();
    const auto epoch = now.time_since_epoch();
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(epoch);
    return static_cast<uint64_t>(ns.count());
}

} // namespace pcap_analyzer::core
