# LargeScalePcapAnalyzer

A production-quality, cross-platform, offline packet capture analyzer for large pcap and pcapng files.

## Features

- **Large File Support**: Open and analyze multi-gigabyte capture files without loading them entirely into memory
- **Fast Indexing**: Background indexing with progress reporting and cancellation support
- **Virtualized Packet List**: Display millions of packets using Qt Model/View architecture
- **Advanced Filtering**: Wireshark-like display filter syntax
- **Protocol Analysis**: TCP, DNS, HTTP, TLS analysis modules
- **Statistics**: Protocol hierarchy, endpoints, conversations, IO graphs
- **Persistent Index**: Optional disk-based index for faster reopening of large files

## Technology Stack

- **C++20** - Modern C++ with coroutines and concepts
- **Qt 6 Widgets** - Cross-platform native GUI
- **CMake** - Modern build system
- **PcapPlusPlus** - Packet parsing library
- **SQLite** - Persistent metadata storage
- **DuckDB** (optional) - Advanced analytics engine
- **GoogleTest** - Unit testing

## Building

### Prerequisites

#### Linux (Ubuntu/Debian)

```bash
# Install Qt 6
sudo apt-get install qt6-base-dev qt6-tools-dev libqt6sql6-sqlite

# Install PcapPlusPlus
sudo apt-get install libpcapplusplus-dev

# Install other dependencies
sudo apt-get install libsqlite3-dev cmake g++ clang-format
```

#### macOS

```bash
# Install via Homebrew
brew install qt@6 pcapplusplus sqlite3 cmake

# Link Qt
brew link --force qt@6
```

#### Windows

```powershell
# Install vcpkg dependencies
vcpkg install qt6-base:x64-windows qt6-tools:x64-windows qt6-sql:x64-windows
vcpkg install pcapplusplus:x64-windows sqlite3:x64-windows

# Or use the provided vcpkg manifest
```

### Build Instructions

```bash
# Clone repository
git clone https://github.com/yourusername/LargeScalePcapAnalyzer.git
cd LargeScalePcapAnalyzer

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --parallel

# Run tests (optional)
ctest --output-on-failure

# Install (optional)
cmake --install . --prefix ../install
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_DUCKDB` | OFF | Enable DuckDB analytics engine |
| `ENABLE_TESTS` | ON | Build unit tests |
| `ENABLE_SANITIZERS` | OFF | Enable address/UB sanitizers (debug only) |
| `BUILD_CLI_TOOL` | ON | Build command-line indexing tool |

Example:

```bash
cmake .. -DENABLE_DUCKDB=ON -DENABLE_SANITIZERS=ON
```

## Usage

### GUI Application

```bash
# Run the application
./PcapAnalyzer

# Or with a file
./PcapAnalyzer capture.pcap
```

### CLI Tool

```bash
# Index a capture file
./pcap-cli index capture.pcap

# Show index statistics
./pcap-cli stats capture.pcap

# Export filtered packets
./pcap-cli export --filter "tcp.port == 443" capture.pcap output.pcap
```

## Project Structure

```
LargeScalePcapAnalyzer/
├── CMakeLists.txt          # Main CMake configuration
├── cmake/                  # CMake modules
│   └── CompilerWarnings.cmake
├── include/                # Public headers
│   ├── core/               # Core data structures
│   ├── filter/             # Filter engine
│   ├── analysis/           # Analysis modules
│   ├── proto/              # Protocol dissectors
│   ├── statistics/         # Statistics engines
│   └── ui/                 # UI components
├── src/                    # Implementation
│   ├── core/
│   ├── filter/
│   ├── analysis/
│   ├── proto/
│   ├── statistics/
│   └── ui/
├── tools/                  # CLI tools
├── tests/                  # Unit tests
├── resources/              # Icons, themes
└── README.md
```

## Architecture

### Core Components

1. **IPacketSource** - Abstract interface for packet sources (files, future live capture)
2. **PcapFileReaderAdapter** - Legacy PCAP file reader
3. **PcapngFileReaderAdapter** - PCAP-NG file reader with multi-section support
4. **PacketIndex** - In-memory packet metadata index (96 bytes per entry)
5. **IndexBuilder** - Background indexer with progress reporting
6. **PersistentIndexStore** - SQLite-based index persistence
7. **PacketDecoder** - On-demand packet dissection
8. **DissectorRegistry** - Protocol dissector management

### Filter Engine

- **FilterLexer/Parser** - Parse filter expressions
- **FilterAst** - Abstract syntax tree representation
- **FilterEvaluator** - Evaluate filters against index entries

### Analysis Modules

- **TcpAnalysisModule** - Retransmissions, duplicate ACKs, window analysis
- **DnsAnalysisModule** - Query/response pairing, latency
- **HttpAnalysisModule** - Request/response correlation
- **TlsAnalysisModule** - Handshake summary, SNI extraction
- **ConversationAnalyzer** - Bidirectional flow tracking
- **EndpointAnalyzer** - Per-host statistics
- **IoGraphAnalyzer** - Time-series packet/byte rates

## Performance Guidelines

The application is designed for large files:

- **Memory Efficiency**: 96-byte index entries, no payload storage in index
- **Lazy Loading**: Packets decoded only when selected
- **Background Indexing**: Non-blocking with progress updates
- **Virtualized Lists**: Qt Model/View for millions of rows
- **Random Access**: File offset-based packet retrieval
- **Batched Updates**: Minimize UI thread crossings

## Testing

```bash
# Run all tests
ctest

# Run specific test category
ctest -R filter

# Run with verbose output
ctest --verbose

# Generate test captures (requires Python + Scapy)
python tests/data/generate_test_captures.py
```

## Known Limitations

1. **Multi-section PCAP-NG**: Full multi-section support planned for future release
2. **Name Resolution Block**: Not yet implemented in PCAP-NG reader
3. **Compressed Files**: gzip-compressed captures not yet supported
4. **Live Capture**: Planned for future milestone

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run clang-format on all changes
4. Ensure all tests pass
5. Submit a pull request

```bash
# Format code
clang-format -i src/**/*.cpp include/**/*.h

# Run tests
cd build && ctest
```

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) - Packet parsing library
- [Qt](https://www.qt.io/) - Cross-platform framework
- [Wireshark](https://www.wireshark.org/) - Inspiration for UI design
