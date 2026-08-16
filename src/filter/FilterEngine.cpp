#include "filter/FilterEngine.h"
#include "filter/FilterEvaluator.h"

namespace pcapanalyzer::filter {

FilterEngine::FilterEngine() = default;

bool FilterEngine::compile(const QString& expression) {
    ParseError error;
    m_ast = m_parser.parse(expression, &error);
    
    if (!m_ast.valid) {
        m_lastError = error.message;
        return false;
    }
    
    m_compiled = true;
    return true;
}

bool FilterEngine::evaluate(const core::PacketIndexEntry& entry) const {
    if (!m_compiled || !m_ast.valid) {
        return false;
    }
    
    FilterEvaluator evaluator;
    return evaluator.evaluate(m_ast, entry);
}

QString FilterEngine::lastError() const {
    return m_lastError;
}

void FilterEngine::clear() {
    m_ast = FilterAstNode();
    m_compiled = false;
    m_lastError.clear();
}

bool FilterEngine::isCompiled() const {
    return m_compiled && m_ast.valid;
}

} // namespace pcapanalyzer::filter
