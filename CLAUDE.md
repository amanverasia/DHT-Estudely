# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DHT-Estudely is a pure Python 3 BitTorrent DHT exploration toolkit with no external dependencies. It implements DHT crawling, peer discovery, and torrent metadata fetching using the BitTorrent protocol specifications (BEPs). The main script runs continuously to collect infohashes, peer networks, and torrent metadata from the BitTorrent DHT.

## Folder Structure

**Root level (core modules):**
- **dht_collect_and_metadata.py**: Main entry point - optimized continuous DHT crawler with automatic metadata.txt output
- **dht_bencode.py**: Foundation module providing bencode/bdecode functionality  
- **dht_krpc.py**: DHT client implementing KRPC protocol with find_node, get_peers, and BEP-51 sample_infohashes
- **bt_metadata.py**: BitTorrent peer protocol implementation for metadata retrieval via BEP-9 (ut_metadata extension)
- **test_metadata_fetch.py**: Test script for verifying metadata fetching with specific infohashes/peers

**Organized folders:**
- **legacy/**: Two-step pipeline scripts (dht_crawler_min.py, dht_fetch_metadata_batch.py)
- **examples/**: Test and example scripts (test_fetch_one.py)

## Common Commands

### Running the Continuous DHT Crawler

**Main continuous operation (recommended):**
```bash
python3 dht_collect_and_metadata.py
```
- Runs indefinitely collecting infohashes and metadata
- Automatically saves all data to `metadata.txt`
- Shows live output to stdout as well
- Use Ctrl+C to stop gracefully

**Run in background and monitor:**
```bash
python3 dht_collect_and_metadata.py &
tail -f metadata.txt
```

**Legacy two-step mode:**
```bash
# Step 1: Crawl and collect peers
python3 legacy/dht_crawler_min.py > peers_stream.csv

# Step 2: Fetch metadata from collected peers
python3 legacy/dht_fetch_metadata_batch.py peers.csv > metadata.csv
```

**Testing metadata fetch:**
```bash
python3 examples/test_fetch_one.py
python3 test_metadata_fetch.py
```

### File Management

**Generated files:**
- `metadata.txt`: Main output file with infohashes, peer data, and metadata (auto-created)
- `peers.csv`: Legacy peer data (append mode, gitignored)

**CSV Format (metadata.txt):**
```
infohash,name,file_count,total_bytes,piece_length,peer_ip,peer_port,metadata_ok
```

### Configuration

**Built-in settings (in dht_collect_and_metadata.py):**
- `MAX_INFOHASHES`: 999999 (effectively unlimited)
- `PEERS_PER_INFOHASH`: 20
- `METADATA_PEER_ATTEMPTS`: 5
- `OVERALL_TIMEOUT`: 86400.0 (24 hours)

## Key Implementation Details

### Protocol Stack
1. **Bootstrap**: Uses public DHT routers (router.bittorrent.com, dht.transmissionbt.com, router.utorrent.com)
2. **DHT Traversal**: Prioritizes BEP-51 sample_infohashes for fast random sampling, falls back to iterative find_node
3. **Peer Discovery**: Uses get_peers queries with bounded peer lists per infohash
4. **Metadata Fetching**: BitTorrent handshake + extended handshake (BEP-10) + ut_metadata exchange (BEP-9)

### Key Optimizations Applied
- **Efficient data structures**: Sets for O(1) membership tests instead of lists
- **Caching**: DNS resolution cache and compact node parsing cache with thread safety
- **Optimized bencode/bdecode**: Pre-compiled constants, reduced allocations, better bounds checking
- **Sequential processing**: Simplified from threading to avoid race conditions and timeouts
- **Smart timeouts**: Optimized timeout distribution for different operations
- **Memory optimizations**: F-string IP conversion, reduced string operations

### Module Dependencies
- dht_krpc.py imports dht_bencode
- bt_metadata.py imports dht_bencode  
- Main script inlines all dependencies for portability
- No external package dependencies (pure Python 3 stdlib)

### Data Flow
The continuous crawler (dht_collect_and_metadata.py) follows this flow:
1. Bootstrap → DHT sampling → Peer discovery → Metadata fetching → Dual output (stdout + metadata.txt)
2. Bounded data structures prevent memory issues during long runs
3. Line-buffered CSV output for real-time data availability
4. Progress reporting every 10 infohashes processed
5. Graceful shutdown handling (Ctrl+C/signals)

### Metadata Retrieval Reality
- **Success Rate**: Metadata retrieval has naturally low success rates (5-20% typical)
- **Common Issues**: Many peers don't support ut_metadata extension, connection failures, timeouts
- **Normal Behavior**: `metadata_ok=False` entries are expected and normal
- **Value**: Even failed attempts provide valuable peer network mapping data

## Safety Considerations

- Conservative rate limiting to avoid overwhelming random peers
- No persistent state between runs - each execution is fresh  
- Graceful signal handling for clean shutdown
- Educational/research use only - respect network etiquette
- Built-in bounds on concurrent operations and timeouts

## Troubleshooting

### Common Issues
- **No metadata success**: Normal - try running longer, many peers don't support metadata exchange
- **Connection timeouts**: Expected with random peers on the internet
- **Low infohash discovery**: Check network connectivity to DHT bootstrap nodes

### Monitoring Progress
```bash
# Watch live output
tail -f metadata.txt

# Count total entries
wc -l metadata.txt

# Check for successful metadata
grep ",True$" metadata.txt | wc -l

# Monitor unique infohashes
cut -d',' -f1 metadata.txt | sort -u | wc -l
```