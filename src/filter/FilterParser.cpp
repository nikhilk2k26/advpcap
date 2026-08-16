#include "filter/FilterParser.h"
#include <QRegularExpression>

namespace pcapanalyzer::filter {

FilterParser::FilterParser() = default;

FilterAstNode FilterParser::parse(const QString& expression, ParseError* error) {
    m_pos = 0;
    m_expression = expression.trimmed();
    
    if (error) {
        error->message.clear();
        error->position = 0;
    }
    
    try {
        FilterAstNode result = parseExpression();
        
        if (m_pos < m_expression.length()) {
            if (error) {
                error->message = QString("Unexpected character '%1' at position %2")
                    .arg(m_expression[m_pos]).arg(m_pos);
                error->position = static_cast<int>(m_pos);
            }
            return FilterAstNode::createError("Unexpected trailing characters");
        }
        
        return result;
    } catch (const ParseException& e) {
        if (error) {
            error->message = e.message;
            error->position = e.position;
        }
        return FilterAstNode::createError(e.message);
    }
}

FilterAstNode FilterParser::parseExpression() {
    skipWhitespace();
    FilterAstNode left = parseOrExpression();
    
    return left;
}

FilterAstNode FilterParser::parseOrExpression() {
    skipWhitespace();
    FilterAstNode left = parseAndExpression();
    
    while (true) {
        skipWhitespace();
        
        if (matchKeyword("or") || matchToken("|")) {
            advance();
            skipWhitespace();
            FilterAstNode right = parseAndExpression();
            left = FilterAstNode::createBinary(FilterOp::Or, std::move(left), std::move(right));
        } else {
            break;
        }
    }
    
    return left;
}

FilterAstNode FilterParser::parseAndExpression() {
    skipWhitespace();
    FilterAstNode left = parseComparison();
    
    while (true) {
        skipWhitespace();
        
        // Check for implicit AND (space between expressions)
        if (matchKeyword("and") || matchToken("&")) {
            advance();
            skipWhitespace();
            FilterAstNode right = parseComparison();
            left = FilterAstNode::createBinary(FilterOp::And, std::move(left), std::move(right));
        } else if (!isAtEnd() && !matchToken(')')) {
            // Implicit AND - just whitespace between valid expressions
            size_t savedPos = m_pos;
            skipWhitespace();
            if (!isAtEnd() && !matchToken(')')) {
                m_pos = savedPos;
                FilterAstNode right = parseComparison();
                left = FilterAstNode::createBinary(FilterOp::And, std::move(left), std::move(right));
            } else {
                m_pos = savedPos;
                break;
            }
        } else {
            break;
        }
    }
    
    return left;
}

FilterAstNode FilterParser::parseComparison() {
    skipWhitespace();
    FilterAstNode left = parsePrimary();
    
    skipWhitespace();
    
    // Check for comparison operators
    if (matchString("==") || matchString("=")) {
        if (matchString("==")) advance(2);
        else advance(1);
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::Equal, std::move(left), std::move(right));
    }
    
    if (matchString("!=") || matchString("<>")) {
        advance(2);
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::NotEqual, std::move(left), std::move(right));
    }
    
    if (matchString(">=")) {
        advance(2);
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::GreaterEqual, std::move(left), std::move(right));
    }
    
    if (matchString("<=")) {
        advance(2);
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::LessEqual, std::move(left), std::move(right));
    }
    
    if (matchToken('>')) {
        advance();
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::Greater, std::move(left), std::move(right));
    }
    
    if (matchToken('<')) {
        advance();
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::Less, std::move(left), std::move(right));
    }
    
    if (matchKeyword("contains")) {
        advance();
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::Contains, std::move(left), std::move(right));
    }
    
    if (matchKeyword("starts") || matchKeyword("begins")) {
        advance();
        skipWhitespace();
        if (matchKeyword("with")) advance();
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::StartsWith, std::move(left), std::move(right));
    }
    
    if (matchKeyword("ends")) {
        advance();
        skipWhitespace();
        if (matchKeyword("with")) advance();
        skipWhitespace();
        FilterAstNode right = parseValue();
        return FilterAstNode::createBinary(FilterOp::EndsWith, std::move(left), std::move(right));
    }
    
    return left;
}

FilterAstNode FilterParser::parsePrimary() {
    skipWhitespace();
    
    if (matchToken('(')) {
        advance();
        skipWhitespace();
        FilterAstNode expr = parseExpression();
        skipWhitespace();
        if (!matchToken(')')) {
            throw ParseException("Expected ')'", static_cast<int>(m_pos));
        }
        advance();
        return expr;
    }
    
    if (matchKeyword("not") || matchToken('!')) {
        advance();
        skipWhitespace();
        FilterAstNode operand = parsePrimary();
        return FilterAstNode::createUnary(FilterOp::Not, std::move(operand));
    }
    
    // Check for protocol existence (e.g., "tcp", "dns")
    if (isIdentifierChar(currentChar())) {
        size_t start = m_pos;
        QString ident = parseIdentifier();
        
        skipWhitespace();
        
        // If followed by a dot, it's a field reference
        if (matchToken('.')) {
            advance();
            QString field = parseIdentifier();
            
            skipWhitespace();
            
            // Check for nested fields (e.g., ip.addr)
            while (matchToken('.')) {
                advance();
                QString nestedField = parseIdentifier();
                field += "." + nestedField;
                skipWhitespace();
            }
            
            return FilterAstNode::createField(ident, field);
        }
        
        // Otherwise it's a protocol existence check
        return FilterAstNode::createProtocol(ident);
    }
    
    throw ParseException(QString("Unexpected character '%1'").arg(currentChar()), 
                         static_cast<int>(m_pos));
}

FilterAstNode FilterParser::parseValue() {
    skipWhitespace();
    
    if (matchToken('"') || matchToken('\'')) {
        return parseStringLiteral();
    }
    
    if (isDigit(currentChar()) || (matchToken('-') && isDigit(peek(1)))) {
        return parseNumberLiteral();
    }
    
    if (isIdentifierChar(currentChar())) {
        QString ident = parseIdentifier();
        return FilterAstNode::createValue(ident);
    }
    
    throw ParseException("Expected value", static_cast<int>(m_pos));
}

FilterAstNode FilterParser::parseStringLiteral() {
    QChar quote = currentChar();
    advance();
    
    QString value;
    while (!isAtEnd() && currentChar() != quote) {
        if (currentChar() == '\\' && peek(1) != QChar()) {
            advance();
            QChar escaped = currentChar();
            switch (escaped.toLatin1()) {
                case 'n': value += '\n'; break;
                case 't': value += '\t'; break;
                case 'r': value += '\r'; break;
                case '\\': value += '\\'; break;
                case '"': value += '"'; break;
                case '\'': value += '\''; break;
                default: value += escaped; break;
            }
        } else {
            value += currentChar();
        }
        advance();
    }
    
    if (matchToken(quote)) {
        advance();
    }
    
    return FilterAstNode::createValue(value);
}

FilterAstNode FilterParser::parseNumberLiteral() {
    size_t start = m_pos;
    
    bool negative = false;
    if (matchToken('-')) {
        negative = true;
        advance();
    }
    
    // Check for hex
    if (matchString("0x") || matchString("0X")) {
        advance(2);
        while (isHexDigit(currentChar())) {
            advance();
        }
        QString hexStr = m_expression.mid(static_cast<int>(start), m_pos - start);
        bool ok;
        qint64 value = hexStr.toLongLong(&ok, 16);
        if (negative) value = -value;
        return FilterAstNode::createValue(value);
    }
    
    // Decimal number
    while (isDigit(currentChar())) {
        advance();
    }
    
    // Check for decimal point
    if (matchToken('.') && isDigit(peek(1))) {
        advance();
        while (isDigit(currentChar())) {
            advance();
        }
        QString numStr = m_expression.mid(static_cast<int>(start), m_pos - start);
        double value = numStr.toDouble();
        if (negative) value = -value;
        return FilterAstNode::createValue(value);
    }
    
    QString intStr = m_expression.mid(static_cast<int>(start), m_pos - start);
    bool ok;
    qint64 value = intStr.toLongLong(&ok);
    if (negative) value = -value;
    return FilterAstNode::createValue(value);
}

QString FilterParser::parseIdentifier() {
    size_t start = m_pos;
    
    while (!isAtEnd() && isIdentifierChar(currentChar())) {
        advance();
    }
    
    return m_expression.mid(static_cast<int>(start), m_pos - start);
}

void FilterParser::skipWhitespace() {
    while (!isAtEnd() && currentChar().isSpace()) {
        advance();
    }
}

bool FilterParser::matchString(const QString& str) {
    if (m_pos + str.length() > m_expression.length()) {
        return false;
    }
    return m_expression.midRef(static_cast<int>(m_pos), str.length()) == str;
}

bool FilterParser::matchKeyword(const QString& keyword) {
    if (!matchString(keyword)) {
        return false;
    }
    
    // Make sure it's not part of a larger identifier
    size_t endPos = m_pos + keyword.length();
    if (endPos < m_expression.length() && isIdentifierChar(m_expression[static_cast<int>(endPos)])) {
        return false;
    }
    
    return true;
}

bool FilterParser::matchToken(QChar ch) {
    return !isAtEnd() && currentChar() == ch;
}

void FilterParser::advance(int count) {
    m_pos += count;
}

QChar FilterParser::currentChar() const {
    if (isAtEnd()) return QChar();
    return m_expression[static_cast<int>(m_pos)];
}

QChar FilterParser::peek(int offset) const {
    size_t pos = m_pos + offset;
    if (pos >= m_expression.length()) return QChar();
    return m_expression[static_cast<int>(pos)];
}

bool FilterParser::isAtEnd() const {
    return m_pos >= m_expression.length();
}

bool FilterParser::isIdentifierChar(QChar ch) const {
    return ch.isLetterOrNumber() || ch == '_' || ch == '.';
}

bool FilterParser::isDigit(QChar ch) const {
    return ch.isDigit();
}

bool FilterParser::isHexDigit(QChar ch) const {
    return ch.isDigit() || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

} // namespace pcapanalyzer::filter
