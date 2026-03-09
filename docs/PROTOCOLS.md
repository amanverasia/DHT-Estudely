# BitTorrent DHT Protocol Education

Learn how BitTorrent's Distributed Hash Table works by exploring this codebase.

## Protocol Layers

This repo implements 4 layers of the BitTorrent protocol stack:

### Layer 1: Bencode (Serialization)
**File:** `dht_bencode.py`

Bencode is the serialization format used throughout BitTorrent. It's simpler than JSON but less human-readable.

```
Integer:  i42e          → 42
String:   4:spam        → "spam"
List:     l4:spami42ee  → ["spam", 42]
Dict:     d3:foo3:bari42ee → {"foo": "bar", "i": 42}
```

**Learn by reading:** `dht_bencode.py:bencode()` and `dht_bencode.py:bdecode()`

---

### Layer 2: KRPC (DHT Messaging)
**File:** `dht_krpc.py`

KRPC is a simple UDP-based RPC mechanism for DHT communication. All messages are bencoded dictionaries.

**Message types:**
- `ping` - Check if a node is alive
- `find_node` - Find nodes closer to a target ID
- `get_peers` - Get peers sharing a specific infohash
- `sample_infohashes` - BEP-51: Get random infohashes from a node

**Message format:**
```
Query:   {t: <tid>, y: q, q: <method>, a: <args>}
Response:{t: <tid>, y: r, r: <response>}
Error:   {t: <tid>, y: e, e: [<code>, <message>]}
```

**Learn by reading:** `dht_krpc.py:DHTClient` class

---

### Layer 3: DHT (Kademlia-style Routing)
**File:** `dht_krpc.py`

The DHT uses a Kademlia-like algorithm where:
- Each node has a 160-bit ID
- Each infohash is also 160-bit
- Nodes store routing tables to find peers for any infohash

**Key concepts:**
- **Routing table:** Nodes organized by XOR distance
- **find_node:** Recursive lookup to find closest nodes
- **get_peers:** Returns peers sharing an infohash OR more nodes
- **sample_infohashes (BEP-51):** Fast random sampling of the DHT

**Bootstrap nodes:**
```
router.bittorrent.com:6881
dht.transmissionbt.com:6881
router.utorrent.com:6881
```

---

### Layer 4: Peer Wire Protocol (Metadata)
**File:** `bt_metadata.py`

Once you have peer addresses from DHT, you connect via TCP to exchange data.

**Protocol flow:**
1. **Handshake:** `[pstrlen][protocol][reserved][infohash][peer_id]`
2. **Extended handshake (BEP-10):** Enable extensions
3. **ut_metadata (BEP-9):** Request torrent metadata

**Message types:**
```
0  = choke
1  = unchoke
2  = interested
3  = not interested
4  = have
5  = bitfield
6  = request
7  = piece
8  = cancel
20 = extended (BEP-10)
```

---

## BitTorrent Enhancement Proposals (BEPs)

| BEP | Title | Implemented |
|-----|-------|--------------|
| BEP-3 | BitTorrent Protocol | ✓ Handshake |
| BEP-5 | DHT Protocol | ✓ KRPC |
| BEP-9 | Extension for Peers to Send Metadata | ✓ bt_metadata.py |
| BEP-10 | Extension for Extended Messages | ✓ bt_metadata.py |
| BEP-51 | Sample Infohashes | ✓ dht_krpc.py |

---

## Learning Path

### Beginner
1. Read `dht_bencode.py` - Understand serialization
2. Run `python3 dht_bencode.py` - Test bencode round-trip
3. Read `dht_krpc.py:main()` - See bootstrap in action

### Intermediate
1. Read `dht_krpc.py:DHTClient` - Understand KRPC
2. Read `bt_metadata.py:bt_handshake()` - Understand peer wire
3. Run `python3 examples/test_fetch_one.py` - Fetch real metadata

### Advanced
1. Read `docs/WORKSHOP.md` - Follow the guided lab in order
2. Read `dht_collect_and_metadata.py` - See how the full crawler orchestrates the lower-level modules
3. Understand BEP-51 sample_infohashes optimization
4. Experiment with DHT crawling parameters

---

## References

- [BEP-5: DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)
- [BEP-9: Extension for Peers to Send Metadata](https://www.bittorrent.org/beps/bep_0009.html)
- [BEP-10: Extension for Extended Messages](https://www.bittorrent.org/beps/bep_0010.html)
- [BEP-51: Sample Infohashes](https://www.bittorrent.org/beps/bep_0051.html)
