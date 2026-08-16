#include "ui/widgets/HexView.h"
#include <QPainter>
#include <QFontMetrics>
#include <QWheelEvent>
#include <QMouseEvent>
#include <QToolTip>
#include <algorithm>

namespace pcap_analyzer::ui {

HexView::HexView(QWidget* parent)
    : QWidget(parent)
{
    setFocusPolicy(Qt::ClickFocus);
    setMouseTracking(true);
    
    // Set fixed font for consistent spacing
    QFont font("Courier New", 10);
    font.setStyleHint(QFont::Monospace);
    setFont(font);
    
    // Calculate metrics
    QFontMetrics fm(font);
    m_rowHeight = fm.height() + 2;
    
    // Calculate column widths based on font
    m_offsetColumnWidth = fm.horizontalAdvance("00000000: ") + 4;
    m_hexColumnWidth = fm.horizontalAdvance("00 ") * m_bytesPerRow + 8;
    m_asciiColumnWidth = fm.horizontalAdvance(QString(m_bytesPerRow, 'W')) + 8;
    
    setMinimumWidth(m_offsetColumnWidth + m_hexColumnWidth + m_asciiColumnWidth + 16);
}

HexView::~HexView() = default;

void HexView::setPacketData(const uint8_t* data, int length)
{
    if (length <= 0) {
        clear();
        return;
    }
    
    m_packetData = QByteArray(reinterpret_cast<const char*>(data), length);
    m_firstVisibleRow = 0;
    m_highlightStart = -1;
    m_highlightLength = 0;
    
    updateGeometry();
    update();
}

void HexView::clear()
{
    m_packetData.clear();
    m_firstVisibleRow = 0;
    m_highlightStart = -1;
    m_highlightLength = 0;
    m_hoveredByteOffset = -1;
    QToolTip::hideText();
    update();
}

void HexView::highlightByteRange(int startOffset, int length)
{
    if (startOffset < 0 || length <= 0 || startOffset >= m_packetData.size()) {
        clearHighlight();
        return;
    }
    
    m_highlightStart = std::min(startOffset, m_packetData.size() - 1);
    m_highlightLength = std::min(length, m_packetData.size() - m_highlightStart);
    update();
}

void HexView::clearHighlight()
{
    m_highlightStart = -1;
    m_highlightLength = 0;
    update();
}

void HexView::setHighlightColor(const QColor& color)
{
    m_highlightColor = color;
    update();
}

void HexView::setBytesPerRow(int bytesPerRow)
{
    if (bytesPerRow <= 0 || bytesPerRow > 32) {
        return;
    }
    
    m_bytesPerRow = bytesPerRow;
    
    // Recalculate widths
    QFontMetrics fm(font());
    m_hexColumnWidth = fm.horizontalAdvance("00 ") * m_bytesPerRow + 8;
    m_asciiColumnWidth = fm.horizontalAdvance(QString(m_bytesPerRow, 'W')) + 8;
    
    updateGeometry();
    update();
}

int HexView::visibleRows() const
{
    return height() / m_rowHeight + 1;
}

int HexView::totalRows() const
{
    if (m_packetData.isEmpty()) {
        return 0;
    }
    return (m_packetData.size() + m_bytesPerRow - 1) / m_bytesPerRow;
}

int HexView::byteFromPosition(const QPoint& pos) const
{
    if (pos.x() < m_offsetColumnWidth || pos.x() > m_offsetColumnWidth + m_hexColumnWidth) {
        return -1;
    }
    
    const int row = pos.y() / m_rowHeight + m_firstVisibleRow;
    if (row >= totalRows()) {
        return -1;
    }
    
    const int hexX = pos.x() - m_offsetColumnWidth;
    const int byteInRow = hexX / (fontMetrics().horizontalAdvance("00 ") );
    
    if (byteInRow < 0 || byteInRow >= m_bytesPerRow) {
        return -1;
    }
    
    const int byteOffset = row * m_bytesPerRow + byteInRow;
    if (byteOffset >= m_packetData.size()) {
        return -1;
    }
    
    return byteOffset;
}

void HexView::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);
    
    QPainter painter(this);
    painter.fillRect(rect(), palette().base());
    
    if (m_packetData.isEmpty()) {
        painter.setPen(palette().color(QPalette::PlaceholderText));
        painter.drawText(rect(), Qt::AlignCenter, tr("No packet data"));
        return;
    }
    
    painter.setFont(font());
    painter.setPen(palette().color(QPalette::Text));
    
    const int startRow = m_firstVisibleRow;
    const int endRow = std::min(startRow + visibleRows() + 1, totalRows());
    
    for (int row = startRow; row < endRow; ++row) {
        const int y = (row - m_firstVisibleRow) * m_rowHeight;
        drawRow(painter, row, y);
    }
}

void HexView::drawRow(QPainter& painter, int rowIndex, int y)
{
    const int rowStart = rowIndex * m_bytesPerRow;
    if (rowStart >= m_packetData.size()) {
        return;
    }
    
    const int rowEnd = std::min(rowStart + m_bytesPerRow, m_packetData.size());
    
    // Draw offset
    const QString offsetStr = QString("%1:").arg(rowStart, 8, 16, QChar('0'));
    painter.drawText(2, y + fontMetrics().ascent(), offsetStr);
    
    int x = m_offsetColumnWidth;
    const int byteWidth = fontMetrics().horizontalAdvance("00 ");
    
    // Draw hex bytes
    for (int i = rowStart; i < rowEnd; ++i) {
        const int byteInRow = i - rowStart;
        const bool isHighlighted = (i >= m_highlightStart && 
                                     i < m_highlightStart + m_highlightLength);
        
        if (isHighlighted) {
            // Draw highlight background
            QRect bgRect(x, y, byteWidth - 1, m_rowHeight - 1);
            painter.fillRect(bgRect, m_highlightColor);
        }
        
        // Draw byte value
        const QString byteStr = QString("%1").arg(m_packetData[i] & 0xFF, 2, 16, QChar('0'));
        
        if (i == m_hoveredByteOffset) {
            painter.setPen(Qt::blue);
            painter.drawText(x + 1, y + fontMetrics().ascent(), byteStr);
            painter.setPen(palette().color(QPalette::Text));
        } else {
            painter.drawText(x + 1, y + fontMetrics().ascent(), byteStr);
        }
        
        x += byteWidth;
    }
    
    // Fill remaining hex space
    for (int i = rowEnd - rowStart; i < m_bytesPerRow; ++i) {
        x += byteWidth;
    }
    
    // Draw ASCII representation
    x += 8; // Gap between hex and ASCII
    QString asciiStr;
    for (int i = rowStart; i < rowEnd; ++i) {
        const char c = static_cast<char>(m_packetData[i]);
        if (c >= 32 && c < 127) {
            asciiStr += c;
        } else {
            asciiStr += '.';
        }
        
        // Highlight ASCII if corresponding byte is highlighted
        if (i >= m_highlightStart && i < m_highlightStart + m_highlightLength) {
            const int charWidth = fontMetrics().horizontalAdvance("W");
            QRect bgRect(x, y, charWidth, m_rowHeight - 1);
            painter.fillRect(bgRect, m_highlightColor);
        }
        
        x += fontMetrics().horizontalAdvance("W");
    }
    
    // Redraw ASCII text
    x = m_offsetColumnWidth + m_hexColumnWidth + 8;
    painter.drawText(x, y + fontMetrics().ascent(), asciiStr);
}

void HexView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    // Adjust first visible row if needed
    const int maxFirstRow = std::max(0, totalRows() - visibleRows());
    if (m_firstVisibleRow > maxFirstRow) {
        m_firstVisibleRow = maxFirstRow;
        update();
    }
}

void HexView::wheelEvent(QWheelEvent* event)
{
    const int delta = event->angleDelta().y();
    const int rowsToScroll = std::abs(delta) / (8 * 15); // Standard wheel scroll
    
    if (delta > 0) {
        // Scroll up
        m_firstVisibleRow = std::max(0, m_firstVisibleRow - rowsToScroll);
    } else {
        // Scroll down
        const int maxRow = std::max(0, totalRows() - visibleRows());
        m_firstVisibleRow = std::min(maxRow, m_firstVisibleRow + rowsToScroll);
    }
    
    update();
    event->accept();
}

void HexView::mouseMoveEvent(QMouseEvent* event)
{
    const int byteOffset = byteFromPosition(event->pos());
    
    if (byteOffset >= 0 && byteOffset < m_packetData.size()) {
        m_hoveredByteOffset = byteOffset;
        setCursor(Qt::IBeamCursor);
        
        // Show tooltip with byte info
        const uint8_t byteVal = static_cast<uint8_t>(m_packetData[byteOffset]);
        const QString tooltip = tr("Offset: %1\nHex: %2\nDec: %3\nBin: %4")
            .arg(byteOffset, 8, 16, QChar('0'))
            .arg(byteVal, 2, 16, QChar('0'))
            .arg(byteVal)
            .arg(byteVal, 8, 2, QChar('0'));
        QToolTip::showText(event->globalPos(), tooltip, this);
    } else {
        m_hoveredByteOffset = -1;
        setCursor(Qt::ArrowCursor);
        QToolTip::hideText();
    }
    
    update();
    QWidget::mouseMoveEvent(event);
}

void HexView::leaveEvent(QEvent* event)
{
    m_hoveredByteOffset = -1;
    QToolTip::hideText();
    update();
    QWidget::leaveEvent(event);
}

} // namespace pcap_analyzer::ui
