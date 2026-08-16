#pragma once

#include "filter/FilterAst.h"
#include <QString>
#include <cstddef>

namespace pcapanalyzer::filter {

class FilterParser {
public:
    FilterParser();
    
    /**
     * @brief Parse a filter expression string into an AST
     * @param expression The filter expression to parse
     * @param error Optional output parameter for parse errors
     * @return The parsed AST node, or an error node if parsing failed
     */
    FilterAstNode parse(const QString& expression, ParseError* error = nullptr);
    
private:
    FilterAstNode parseExpression();
    FilterAstNode parseOrExpression();
    FilterAstNode parseAndExpression();
    FilterAstNode parseComparison();
    FilterAstNode parsePrimary();
    FilterAstNode parseValue();
    FilterAstNode parseStringLiteral();
    FilterAstNode parseNumberLiteral();
    QString parseIdentifier();
    
    void skipWhitespace();
    bool matchString(const QString& str);
    bool matchKeyword(const QString& keyword);
    bool matchToken(QChar ch);
    void advance(int count = 1);
    QChar currentChar() const;
    QChar peek(int offset) const;
    bool isAtEnd() const;
    bool isIdentifierChar(QChar ch) const;
    bool isDigit(QChar ch) const;
    bool isHexDigit(QChar ch) const;
    
    size_t m_pos{0};
    QString m_expression;
};

} // namespace pcapanalyzer::filter
