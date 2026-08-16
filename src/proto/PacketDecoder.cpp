#include "proto/PacketDecoder.h"

namespace pcapanalyzer::core {

PacketDecoder::PacketDecoder() 
    : m_registry(DissectorRegistry::instance()) {
}

void PacketDecoder::initializeDissectors() {
    m_registry.initializeBuiltInDissectors();
}

std::vector<DissectionResult> PacketDecoder::decodePacket(
    const uint8_t* data,
    size_t length,
    uint16_t linkType,
    uint64_t timestampNs) {
    
    std::vector<DissectionResult> layers;
    
    if (!data || length == 0) {
        return layers;
    }
    
    // Initialize context
    PacketContext context;
    context.data = data;
    context.length = length;
    context.linkType = linkType;
    context.timestampNs = timestampNs;
    context.offset = 0;
    
    // Iterate through layers
    int maxLayers = 20;  // Prevent infinite loops
    while (maxLayers-- > 0 && context.offset < static_cast<int>(length)) {
        IDissector* dissector = m_registry.findDissector(context);
        
        if (!dissector) {
            // No more dissectors found - create generic layer for remaining data
            if (context.offset < static_cast<int>(length)) {
                DissectionResult result = DissectionResult::createSuccess(
                    "Data", "data",
                    QString("%1 bytes of uninterpreted data").arg(length - context.offset));
                result.fields.push_back(DissectionResult::FieldInfo(
                    "Payload", 
                    QString("0x%1...").arg(data[context.offset], 2, 16, QChar('0')),
                    context.offset, 
                    static_cast<int>(length - context.offset)));
                layers.push_back(result);
            }
            break;
        }
        
        DissectionResult result = dissector->dissect(context);
        
        if (!result.success) {
            // Dissection failed - add error layer and stop
            result.protocolName = "Error";
            layers.push_back(result);
            break;
        }
        
        layers.push_back(result);
        
        // Move to next layer
        if (!result.nextProtocol.isEmpty()) {
            context.offset = result.nextLayerOffset;
        } else {
            break;
        }
    }
    
    return layers;
}

QString PacketDecoder::getPacketSummary(const std::vector<DissectionResult>& layers) const {
    if (layers.empty()) {
        return "Empty packet";
    }
    
    QStringList summaries;
    for (const auto& layer : layers) {
        if (layer.success && !layer.summaryText.isEmpty()) {
            summaries << layer.summaryText;
        }
    }
    
    return summaries.join(" / ");
}

} // namespace pcapanalyzer::core
