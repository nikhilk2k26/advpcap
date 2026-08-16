cmake_minimum_required(VERSION 3.25)

# Test configuration for LargeScalePcapAnalyzer
project(PcapAnalyzerTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Test)

# Core tests
add_executable(pcap_analyzer_core_tests
    test_PacketIndex.cpp
    test_FilterParser.cpp
    test_ProtocolSummary.cpp
)

target_link_libraries(pcap_analyzer_core_tests PRIVATE
    pcap_analyzer_core
    GTest::gtest_main
    Qt6::Core
    Qt6::Test
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(pcap_analyzer_core_tests)

# Add test data directory
configure_file(
    ${CMAKE_SOURCE_DIR}/tests/data/test_captures/
    ${CMAKE_CURRENT_BINARY_DIR}/test_data/
    COPYONLY
)

# Print test configuration
message(STATUS "Tests enabled - building test executables")
