# DHT-Estudely

An educational BitTorrent DHT exploration toolkit. Learn how torrenting works by exploring a working implementation.

> **Purpose:** This is a learning playground to understand BitTorrent protocols, not a production tool.

## What is this?

This repository contains a pure Python 3 implementation of:
- **Bencode** - The serialization format used in BitTorrent
- **DHT (Distributed Hash Table)** - Find peers without trackers
- **Peer Wire Protocol** - Connect to peers and exchange data

No external dependencies - just Python 3 standard library.

---

## Quick Start

```bash
# See DHT in action - discover peers and fetch metadata
python3 dht_collect_and_metadata.py
```

This will:
1. Bootstrap to public DHT nodes
2. Discover torrent infohashes
3. Find peers sharing those torrents
4. Fetch metadata (torrent name, file list, size)
5. Output results to stdout and `metadata.txt`

Press `Ctrl+C` to stop.

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

## Learning Examples

### 1. Bencode Basics
```bash
python3 -c "
from dht_bencode import bencode, bdecode
# Encode
print(bencode({'name': 'test', 'size': 1234}))
# Decode
print(bdecode(b'd4:name4:testi1234ee'))
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

docs/
  PROTOCOLS.md          # Protocol documentation

examples/
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
