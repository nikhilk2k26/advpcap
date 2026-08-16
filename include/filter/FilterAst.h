#pragma once

#include <QString>
#include <QVariant>
#include <memory>
#include <vector>

namespace pcapanalyzer::filter {

enum class FilterOp {
    None,
    And,
    Or,
    Not,
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
    Contains,
    StartsWith,
    EndsWith,
    Exists  // Protocol existence check
};

enum class NodeType {
    Value,
    Field,
    Unary,
    Binary,
    Protocol,
    Error
};

struct FilterAstNode {
    NodeType type{NodeType::Value};
    FilterOp op{FilterOp::None};
    QVariant value;
    QString fieldName;
    QString protocolName;
    std::unique_ptr<FilterAstNode> left;
    std::unique_ptr<FilterAstNode> right;
    bool valid{true};
    QString errorMessage;
    
    static FilterAstNode createValue(const QVariant& val) {
        FilterAstNode node;
        node.type = NodeType::Value;
        node.value = val;
        return node;
    }
    
    static FilterAstNode createField(const QString& prefix, const QString& field) {
        FilterAstNode node;
        node.type = NodeType::Field;
        node.protocolName = prefix;
        node.fieldName = field;
        return node;
    }
    
    static FilterAstNode createUnary(FilterOp op, FilterAstNode operand) {
        FilterAstNode node;
        node.type = NodeType::Unary;
        node.op = op;
        node.left = std::make_unique<FilterAstNode>(std::move(operand));
        return node;
    }
    
    static FilterAstNode createBinary(FilterOp op, FilterAstNode leftNode, FilterAstNode rightNode) {
        FilterAstNode node;
        node.type = NodeType::Binary;
        node.op = op;
        node.left = std::make_unique<FilterAstNode>(std::move(leftNode));
        node.right = std::make_unique<FilterAstNode>(std::move(rightNode));
        return node;
    }
    
    static FilterAstNode createProtocol(const QString& name) {
        FilterAstNode node;
        node.type = NodeType::Protocol;
        node.protocolName = name;
        node.op = FilterOp::Exists;
        return node;
    }
    
    static FilterAstNode createError(const QString& msg) {
        FilterAstNode node;
        node.valid = false;
        node.errorMessage = msg;
        return node;
    }
};

struct ParseError {
    QString message;
    int position{0};
};

class ParseException {
public:
    QString message;
    int position{0};
    
    ParseException(const QString& msg, int pos) : message(msg), position(pos) {}
};

} // namespace pcapanalyzer::filter
