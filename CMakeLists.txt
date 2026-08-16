cmake_minimum_required(VERSION 3.25)
project(LargeScalePcapAnalyzer 
    VERSION 0.1.0
    DESCRIPTION "Production-quality offline packet capture analyzer"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Build options
option(ENABLE_DUCKDB "Enable DuckDB analytics engine" OFF)
option(ENABLE_TESTS "Enable unit tests" ON)
option(ENABLE_SANITIZERS "Enable sanitizers for debug builds" OFF)
option(BUILD_CLI_TOOL "Build CLI indexing tool" ON)

# Compiler warnings
include(cmake/CompilerWarnings.cmake)

# Find dependencies
find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent Sql)
find_package(PcapPlusPlus REQUIRED)
find_package(SQLite3 REQUIRED)

if(ENABLE_DUCKDB)
    find_package(DuckDB REQUIRED)
endif()

if(ENABLE_TESTS)
    find_package(GTest REQUIRED)
endif()

# Core library
add_library(pcap_analyzer_core STATIC)
target_sources(pcap_analyzer_core PRIVATE
    # Core types and index
    src/core/PacketIndex.cpp
    src/core/CaptureFileReader.cpp
    src/core/PcapFileReaderAdapter.cpp
    src/core/PcapngFileReaderAdapter.cpp
    src/core/IndexBuilder.cpp
    src/core/PersistentIndexStore.cpp
    
    # Protocol dissection
    src/proto/Dissector.cpp
    src/proto/PacketDecoder.cpp
    src/proto/dissectors/EthernetDissector.cpp
    src/proto/dissectors/Ipv4Dissector.cpp
    src/proto/dissectors/Ipv6Dissector.cpp
    src/proto/dissectors/TcpDissector.cpp
    src/proto/dissectors/UdpDissector.cpp
    src/proto/dissectors/DnsDissector.cpp
    src/proto/dissectors/ArpDissector.cpp
    
    # Filter engine
    src/filter/FilterEngine.cpp
    src/filter/FilterParser.cpp
    src/filter/FilterAst.cpp
    src/filter/FilterEvaluator.cpp
    
    # Analysis modules
    src/analysis/AnalysisEngine.cpp
    src/analysis/TcpAnalysisModule.cpp
    src/analysis/DnsAnalysisModule.cpp
    src/analysis/HttpAnalysisModule.cpp
    src/analysis/TlsAnalysisModule.cpp
    src/analysis/ConversationAnalyzer.cpp
    src/analysis/EndpointAnalyzer.cpp
    src/analysis/ProtocolHierarchyAnalyzer.cpp
    src/analysis/IoGraphAnalyzer.cpp
    
    # Statistics
    src/statistics/StatisticsEngine.cpp
    src/statistics/CaptureStats.cpp
    src/statistics/EndpointStats.cpp
    src/statistics/ConversationStats.cpp
    
    # Utils
    src/core/utils/ByteUtils.cpp
    src/core/utils/TimestampUtils.cpp
)

target_include_directories(pcap_analyzer_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pcap_analyzer_core PUBLIC
    Qt6::Core
    Qt6::Concurrent
    PcapPlusPlus::PcapPlusPlus
    SQLite::SQLite3
)

if(ENABLE_DUCKDB)
    target_link_libraries(pcap_analyzer_core PUBLIC DuckDB::DuckDB)
    target_compile_definitions(pcap_analyzer_core PUBLIC ENABLE_DUCKDB)
endif()

set_target_warnings(pcap_analyzer_core)

# UI library
add_library(pcap_analyzer_ui STATIC)
target_sources(pcap_analyzer_ui PRIVATE
    src/ui/MainWindow.cpp
    src/ui/models/PacketTableModel.cpp
    src/ui/models/PacketDetailModel.cpp
    src/ui/models/ConversationTableModel.cpp
    src/ui/models/EndpointTableModel.cpp
    src/ui/widgets/PacketListView.cpp
    src/ui/widgets/PacketDetailView.cpp
    src/ui/widgets/HexView.cpp
    src/ui/widgets/FilterBar.cpp
    src/ui/widgets/StatisticsPanel.cpp
    src/ui/widgets/IoGraphWidget.cpp
    src/ui/widgets/ConversationPanel.cpp
    src/ui/widgets/EndpointPanel.cpp
    src/ui/dialogs/OpenCaptureDialog.cpp
    src/ui/dialogs/AboutDialog.cpp
)

target_include_directories(pcap_analyzer_ui PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/ui
)

target_link_libraries(pcap_analyzer_ui PUBLIC
    pcap_analyzer_core
    Qt6::Widgets
    Qt6::Sql
)

set_target_warnings(pcap_analyzer_ui)

# Main application
add_executable(pcap_analyzer_app WIN32 MACOSX_BUNDLE
    src/ui/main.cpp
)

target_link_libraries(pcap_analyzer_app PRIVATE
    pcap_analyzer_core
    pcap_analyzer_ui
)

set_target_warnings(pcap_analyzer_app)

# Set application properties
set_target_properties(pcap_analyzer_app PROPERTIES
    OUTPUT_NAME "PcapAnalyzer"
    MACOSX_BUNDLE_BUNDLE_NAME "PcapAnalyzer"
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.pcapanalyzer.app"
    MACOSX_BUNDLE_ICON_FILE "app_icon.icns"
)

# CLI tool
if(BUILD_CLI_TOOL)
    add_executable(pcap_cli_tool
        tools/cli_index_tool.cpp
    )
    
    target_link_libraries(pcap_cli_tool PRIVATE
        pcap_analyzer_core
    )
    
    set_target_warnings(pcap_cli_tool)
    set_target_properties(pcap_cli_tool PROPERTIES
        OUTPUT_NAME "pcap-cli"
    )
endif()

# Tests
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install rules
install(TARGETS pcap_analyzer_app
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

install(DIRECTORY resources/icons
    DESTINATION share/pcap_analyzer
)

# Print configuration summary
message(STATUS "")
message(STATUS "=== LargeScalePcapAnalyzer Configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Qt Version: ${Qt6_VERSION}")
message(STATUS "PcapPlusPlus Version: ${PcapPlusPlus_VERSION}")
message(STATUS "Enable DuckDB: ${ENABLE_DUCKDB}")
message(STATUS "Enable Tests: ${ENABLE_TESTS}")
message(STATUS "Enable Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "Build CLI Tool: ${BUILD_CLI_TOOL}")
message(STATUS "=============================================")
message(STATUS "")
