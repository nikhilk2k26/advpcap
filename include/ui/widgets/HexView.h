#pragma once

#include <QWidget>
#include <QScrollBar>
#include <QColor>
#include <memory>
#include "core/PacketIndex.h"

namespace pcap_analyzer::ui {

/**
 * @brief Widget for displaying packet bytes in hexadecimal and ASCII format
 * 
 * Shows offset, hex bytes (16 per row), and ASCII representation.
 * Supports highlighting specific byte ranges.
 */
class HexView : public QWidget
{
    Q_OBJECT

public:
    explicit HexView(QWidget* parent = nullptr);
    ~HexView() override;

    /**
     * @brief Set the packet data to display
     * @param data Pointer to packet bytes
     * @param length Length of packet data
     */
    void setPacketData(const uint8_t* data, int length);

    /**
     * @brief Clear the hex view
     */
    void clear();

    /**
     * @brief Highlight a range of bytes
     * @param startOffset Start byte offset (0-based)
     * @param length Number of bytes to highlight
     */
    void highlightByteRange(int startOffset, int length);

    /**
     * @brief Clear any highlighting
     */
    void clearHighlight();

    /**
     * @brief Set the highlight color
     * @param color Color for highlighted bytes
     */
    void setHighlightColor(const QColor& color);

    /**
     * @brief Get current highlight color
     */
    [[nodiscard]] QColor highlightColor() const { return m_highlightColor; }

    /**
     * @brief Set bytes per row (default 16)
     * @param bytesPerRow Number of bytes per row
     */
    void setBytesPerRow(int bytesPerRow);

    /**
     * @brief Get current bytes per row
     */
    [[nodiscard]] int bytesPerRow() const { return m_bytesPerRow; }

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    QByteArray m_packetData;
    int m_bytesPerRow = 16;
    int m_rowHeight = 16;
    int m_hexColumnWidth = 48;   // Width of hex section
    int m_asciiColumnWidth = 17; // Width of ASCII section
    int m_offsetColumnWidth = 60; // Width of offset column
    
    int m_highlightStart = -1;
    int m_highlightLength = 0;
    QColor m_highlightColor = QColor(255, 255, 0, 100); // Semi-transparent yellow
    
    int m_firstVisibleRow = 0;
    int m_hoveredByteOffset = -1;
    
    // Calculate visible rows based on widget height
    [[nodiscard]] int visibleRows() const;
    
    // Calculate total rows needed for current data
    [[nodiscard]] int totalRows() const;
    
    // Get byte position from mouse event
    int byteFromPosition(const QPoint& pos) const;
    
    // Draw a single row
    void drawRow(QPainter& painter, int rowIndex, int y);
};

} // namespace pcap_analyzer::ui
