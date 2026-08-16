#pragma once

#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QVector>
#include <cstdint>

namespace pcap_analyzer::ui {

/**
 * @brief Data point for IO graph
 */
struct IoGraphDataPoint {
    uint64_t timestampMs;  // Timestamp in milliseconds
    quint64 packetCount;   // Number of packets in interval
    quint64 byteCount;     // Number of bytes in interval
};

/**
 * @brief Widget for displaying IO graph over time
 * 
 * Shows packets/bytes per time interval.
 * Note: Full implementation requires QCustomPlot or Qt Charts.
 */
class IoGraphWidget : public QWidget
{
    Q_OBJECT

public:
    explicit IoGraphWidget(QWidget* parent = nullptr);
    ~IoGraphWidget() override;

    /**
     * @brief Set graph data
     */
    void setData(const QVector<IoGraphDataPoint>& data);

    /**
     * @brief Clear graph data
     */
    void clear();

signals:
    /**
     * @brief Emitted when interval setting changes
     */
    void intervalChanged(int intervalSeconds);

private slots:
    void updateGraph();
    void onIntervalChanged();

private:
    void setupUi();

    QComboBox* m_intervalCombo = nullptr;
    QCheckBox* m_packetsCheckbox = nullptr;
    QCheckBox* m_bytesCheckbox = nullptr;
    QLabel* m_graphPlaceholder = nullptr;
    
    QVector<IoGraphDataPoint> m_data;
};

} // namespace pcap_analyzer::ui
