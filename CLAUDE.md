# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DHT-Estudely is an educational BitTorrent DHT exploration toolkit built to understand how torrenting works. It's a learning playground - read the code, experiment, and learn the protocols.

Pure Python 3 with no external dependencies.

## Protocol Stack (4 Layers)

This repo implements the full BitTorrent protocol stack:

```
Layer 4: Peer Wire (bt_metadata.py)
    └─ TCP: handshake → extended handshake → ut_metadata (BEP-9)

Layer 3: DHT Routing (dht_krpc.py)
    └─ Kademlia: find_node, get_peers, sample_infohashes (BEP-51)

Layer 2: KRPC (dht_krpc.py)
    └─ UDP: bencoded query/response messages

Layer 1: Bencode (dht_bencode.py)
    └─ Serialization: int, bytes, list, dict
```

## File Structure

```
dht_bencode.py              # Layer 1: bencode/bdecode
dht_krpc.py                 # Layer 2-3: KRPC + DHT client
bt_metadata.py              # Layer 4: peer wire + BEP-9
dht_collect_and_metadata.py # Main: ties all layers together

docs/
  PROTOCOLS.md              # Detailed protocol documentation

examples/
  test_fetch_one.py         # Example: full metadata fetch flow

legacy/                     # Older two-step scripts
  dht_crawler_min.py
  dht_fetch_metadata_batch.py
```

## Running

```bash
# Main crawler - discover + fetch metadata
python3 dht_collect_and_metadata.py

# DHT bootstrap demo
python3 dht_krpc.py

# Test metadata fetch
python3 examples/test_fetch_one.py
```

## Key Concepts

- **Infohash**: 40-char hex SHA1 identifying a torrent
- **Bencode**: Simple serialization (i=integer, s=string, l=list, d=dict)
- **KRPC**: UDP-based RPC for DHT messages
- **BEP-51 sample_infohashes**: Fast random sampling of DHT
- **ut_metadata (BEP-9)**: Extension to fetch .torrent metadata from peers

## Important BEPs

| BEP | Purpose |
|-----|---------|
| BEP-5 | DHT Protocol |
| BEP-9 | Metadata Exchange |
| BEP-10 | Extended Messages |
| BEP-51 | Sample Infohashes |

## Educational Tips

- Start by reading dht_bencode.py to understand serialization
- Then dht_krpc.py to see the DHT protocol
- Then bt_metadata.py for peer wire protocol
- Finally dht_collect_and_metadata.py to see the full system
