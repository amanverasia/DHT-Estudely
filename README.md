# DHT-Estudely

An educational BitTorrent DHT exploration toolkit. Learn how torrenting works by exploring a working implementation.

> **Purpose:** This is a learning playground to understand BitTorrent protocols, not a production tool.

This repo is best used as an educational sandbox. The goal is not just to run a crawler, but to understand how BitTorrent clients:
- encode messages with bencode
- discover nodes and peers through the DHT
- connect to peers over TCP
- fetch torrent metadata with BEP-9 / BEP-10

## What is this?

This repository contains a pure Python 3 implementation of:
- **Bencode** - The serialization format used in BitTorrent
- **DHT (Distributed Hash Table)** - Find peers without trackers
- **Peer Wire Protocol** - Connect to peers and exchange data

No external dependencies - just Python 3 standard library.

---

## Quick Start

```bash
# Offline-first learning path
python3 examples/01_bencode_demo.py
python3 -m unittest test_offline_regressions.py
python3 dht_krpc.py
python3 examples/test_fetch_one.py
```

Recommended progression:
1. `examples/01_bencode_demo.py` - understand the data format used everywhere
2. `test_offline_regressions.py` - verify key parser/client behavior without relying on the public network
3. `dht_krpc.py` - bootstrap into the DHT and discover nodes
4. `examples/test_fetch_one.py` - connect to a peer and fetch torrent metadata
5. `dht_collect_and_metadata.py` - run the full end-to-end pipeline after you understand the smaller pieces

If you want to jump straight to the full crawler:

```bash
python3 dht_collect_and_metadata.py
```

That script will:
1. Bootstrap to public DHT nodes
2. Discover torrent infohashes
3. Find peers sharing those torrents
4. Fetch metadata (torrent name, file list, size)
5. Output results to stdout and `metadata.txt`

Press `Ctrl+C` to stop.

---

## What You'll Learn

By working through this repo, you should come away understanding:

- what an **infohash** is and why it identifies torrent metadata
- what the **DHT** does and how it differs from a tracker
- why BitTorrent uses **UDP** for DHT traffic and **TCP** for peer traffic
- how peers advertise metadata support with **BEP-10**
- how torrent metadata is fetched in pieces with **BEP-9**
- how the implementation maps cleanly onto the protocol layers

---

## Learning Path

### Step 1: Bencode

Start with:

```bash
python3 examples/01_bencode_demo.py
```

Focus on:
- BitTorrent messages are serialized bytes, not JSON
- `bdecode()` returns string-like values as `bytes`
- dictionaries are sorted during bencoding

Relevant files:
- `dht_bencode.py`
- `examples/01_bencode_demo.py`

### Step 2: DHT / KRPC

Then run:

```bash
python3 dht_krpc.py
```

Focus on:
- DHT nodes communicate with compact UDP messages
- `find_node` discovers more nodes
- `get_peers` asks for peers for a specific infohash
- `sample_infohashes` is a BEP-51 optimization for discovering random torrents

Relevant files:
- `dht_krpc.py`
- `docs/PROTOCOLS.md`

### Step 3: Peer Wire + Metadata

Then try:

```bash
python3 examples/test_fetch_one.py
```

Focus on:
- DHT only gives you peer addresses, not metadata or file contents
- the BitTorrent handshake happens before extension negotiation
- peers can expose `ut_metadata` through the extended handshake
- metadata is transferred in pieces and parsed as a torrent `info` dictionary

Relevant files:
- `bt_metadata.py`
- `examples/test_fetch_one.py`

### Step 4: Full Pipeline

Finally:

```bash
python3 dht_collect_and_metadata.py
```

Focus on:
- how bootstrap, peer discovery, and metadata fetching compose together
- where reliability problems show up in the real network
- why public DHT/peer behavior is inherently noisy and unstable

Relevant files:
- `dht_collect_and_metadata.py`
- `legacy/dht_crawler_min.py`
- `legacy/dht_fetch_metadata_batch.py`

---

## The Protocol Stack

BitTorrent uses 4 layers. This repo implements each one:

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: Peer Wire Protocol (bt_metadata.py)       │
│  TCP connections, handshakes, BEP-9/BEP-10          │
├─────────────────────────────────────────────────────┤
│  Layer 3: DHT Routing (dht_krpc.py)                  │
│  Kademlia-like lookup, find_node, get_peers         │
├─────────────────────────────────────────────────────┤
│  Layer 2: KRPC (dht_krpc.py)                         │
│  UDP messages, bencoded queries/responses            │
├─────────────────────────────────────────────────────┤
│  Layer 1: Bencode (dht_bencode.py)                   │
│  Serialization: int, string, list, dict              │
└─────────────────────────────────────────────────────┘
```

**Learn more:** See `docs/PROTOCOLS.md` for detailed protocol documentation.

---

## Key Concepts

- **Infohash**: a 20-byte SHA-1 digest, usually shown as 40 hex characters, derived from the torrent `info` dictionary
- **Tracker**: a central service that tells clients which peers are available for a torrent
- **DHT**: a decentralized alternative to trackers for finding peers
- **Metadata**: the torrent structure describing file names, sizes, piece length, and piece hashes
- **Peer**: a BitTorrent client participating in sharing or downloading a torrent
- **Node ID**: a 20-byte identifier used by a DHT node

Common misconception to avoid:
- The infohash identifies the torrent metadata, not the raw file bytes directly

---

## Learning Examples

### 1. Bencode Basics
```bash
python3 -c "
from dht_bencode import bencode, bdecode
# Encode
print(bencode({'name': 'test', 'size': 1234}))
# Decode
print(bdecode(b'd4:name4:testi1234ee')[0])
"
```

### 2. DHT Bootstrap
```bash
python3 dht_krpc.py
```
Connects to bootstrap nodes and discovers other DHT nodes.

### 3. Fetch Metadata from a Peer
```bash
python3 examples/test_fetch_one.py
```
Shows the full flow: DHT → get_peers → connect → handshake → get metadata.

---

## File Structure

```
dht_bencode.py          # Layer 1: Bencode encoding/decoding
dht_krpc.py             # Layer 2-3: KRPC + DHT client
bt_metadata.py          # Layer 4: Peer wire protocol
dht_collect_and_metadata.py  # Main crawler
test_offline_regressions.py  # Offline regression tests

docs/
  PROTOCOLS.md          # Protocol documentation
  LEARNING.md           # Learning guide

examples/
  01_bencode_demo.py    # Example: bencode basics
  02_dht_bootstrap_demo.py  # Example: bootstrap into the DHT
  03_dht_get_peers_demo.py  # Example: get_peers and sample_infohashes
  04_peer_metadata_demo.py  # Example: peer wire / metadata overview
  test_fetch_one.py     # Example: fetch metadata from a peer

legacy/
  dht_crawler_min.py    # Legacy: just crawl DHT
  dht_fetch_metadata_batch.py  # Legacy: batch metadata fetch
```

---

## Output Format

The crawler outputs CSV with columns:

| Column | Description |
|--------|-------------|
| infohash | 40-character hex SHA1 |
| name | Torrent name (if metadata obtained) |
| file_count | Number of files |
| total_bytes | Total size in bytes |
| piece_length | Piece size |
| peer_ip, peer_port | Peer we connected to |
| metadata_ok | True if metadata fetch succeeded |

---

## Configuration

Edit constants in `dht_collect_and_metadata.py`:

```python
MAX_INFOHASHES = 999999   # How many to discover
PEERS_PER_INFOHASH = 20   # Max peers per infohash
METADATA_PEER_ATTEMPTS = 5 # How many peers to try
```

---

## Offline Checks

Before relying on live network demos, run:

```bash
python3 -m unittest test_offline_regressions.py
```

This validates a few important invariants locally, including metadata parsing behavior and DHT response handling.

---

## Understanding DHT

### What is DHT?
DHT (Distributed Hash Table) lets BitTorrent clients find peers **without a central tracker**. Each client participates as a node in a P2P network.

### How it works (simplified):
1. Each torrent has a unique 160-bit **infohash**
2. Each DHT node has a 160-bit **node ID**
3. Nodes store mappings: infohash → peer list
4. To find peers for a torrent, you query nodes "closer" to the infohash

### Key DHT operations:
- **find_node**: Find nodes closer to a target ID
- **get_peers**: Get peers for a specific infohash
- **sample_infohashes (BEP-51)**: Get random infohashes from a node (faster!)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No nodes found | UDP port 6881 may be blocked |
| Low metadata success | Normal - many peers don't support metadata exchange |
| Script exits quickly | Try increasing timeout or running longer |

---

## References

- [BEP-5: DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)
- [BEP-9: Metadata Exchange](https://www.bittorrent.org/beps/bep_0009.html)
- [BEP-10: Extended Messages](https://www.bittorrent.org/beps/bep_0010.html)
- [BEP-51: Sample Infohashes](https://www.bittorrent.org/beps/bep_0051.html)

---

**Happy learning!** Read the code, experiment, and understand how torrenting works.
