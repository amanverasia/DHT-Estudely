# DHT Playground - Learning Guide

This is your playground to understand how BitTorrent DHT and torrenting works.

## How to Use This Repo

1. **Read the code** - Each file is a learning module
2. **Run the examples** - See protocols in action
3. **Experiment** - Modify, break, learn
4. **Read the docs** - Understand the theory

---

## Start Here: Understanding the Stack

### What is DHT?

The **Distributed Hash Table** is like a peer-to-peer phone book for BitTorrent. Instead of one central server, all peers help store information about which peers have which files.

**Analogy:** Imagine a massive community bulletin board where:
- Anyone can post: "I have movie X, come download from me"
- Anyone can ask: "Who has movie X?"
- No single person runs the board - everyone helps

### What is an Infohash?

An infohash is a **SHA-1 hash** (40 hex characters) that uniquely identifies a torrent. It's derived from the torrent's metadata (file names, sizes, piece hashes).

```
infohash = SHA1(bencoded_info_dict)
```

### What is Metadata?

Metadata is the `.torrent` file contents - the info dictionary containing:
- File names and sizes
- Piece length and hashes
- Announce trackers (optional in DHT mode)

With metadata, you can start downloading the actual file content.

---

## Code Exploration Order

### Step 1: Bencode (`dht_bencode.py`)

Bencode is how BitTorrent encodes all data. It's the "language" every component speaks.

**Key functions to study:**
- `bencode(obj)` - Encode Python to bytes
- `bdecode(data)` - Decode bytes to Python

**Try it:**
```python
python3 -c "
from dht_bencode import bencode, bdecode
data = {'info': {'name': 'test', 'length': 1234}}
encoded = bencode(data)
print('Encoded:', encoded)
decoded, _ = bdecode(encoded)
print('Decoded:', decoded)
"
```

---

### Step 2: KRPC (`dht_krpc.py`)

KRPC is the UDP-based messaging system for DHT nodes to talk to each other.

**Key concepts:**
- All messages are bencoded dictionaries
- UDP (connectionless, fast)
- Transaction IDs match queries to responses

**Try it:**
```bash
# Bootstrap and find nodes
python3 dht_krpc.py
```

**Study the DHTClient class:**
- `ping()` - Health check
- `find_node()` - Discover nodes
- `get_peers()` - Find peers with a file
- `sample_infohashes()` - Random sampling (BEP-51)

---

### Step 3: Peer Wire (`bt_metadata.py`)

Once you have peer addresses from DHT, you connect via TCP.

**Key concepts:**
- BitTorrent handshake
- Extended messages (BEP-10)
- ut_metadata for metadata exchange (BEP-9)

**Try it:**
```python
# See examples/test_fetch_one.py for usage
python3 examples/test_fetch_one.py
```

---

### Step 4: The Crawler (`dht_collect_and_metadata.py`)

This ties everything together:

```
Bootstrap → Find Nodes → Sample Infohashes → Get Peers → Fetch Metadata → Output
```

---

## Experiments to Try

### 1. Change the Bencode Format
Modify `dht_bencode.py` to print debugging info. See how different Python types encode.

### 2. Add a New KRPC Query
In `dht_krpc.py`, add a new method to the DHTClient class. Try implementing `announce_peer` (BEP-5).

### 3. Parse Metadata Yourself
In `bt_metadata.py`, add code to print all files in a torrent after fetching metadata.

### 4. Build a Custom Crawler
Modify `dht_collect_and_metadata.py` to:
- Only collect specific types of content
- Store data in a different format (JSON, SQLite)
- Add progress bars

---

## FAQ

### Why does metadata fetch fail so often?

Not all peers support ut_metadata (BEP-9). Many clients disable it for privacy or bandwidth reasons. A 5-20% success rate is normal.

### Why UDP? Why not TCP?

DHT uses UDP because:
- Lower overhead for simple queries
- No connection setup time
- Firewalls often allow outbound UDP

### What's the difference between DHT and trackers?

- **Trackers:** Central servers that tell you about peers
- **DHT:** Decentralized, peer-to-peer version of trackers

### What is BEP-51?

BEP-51 (`sample_infohashes`) lets you randomly sample the DHT keyspace. It's much faster than iterative find_node for discovering new torrents.

---

## What's Next?

1. Read through `docs/PROTOCOLS.md` for detailed protocol specs
2. Experiment with the example scripts
3. Read the actual BEP documents linked in PROTOCOLS.md
4. Try building your own DHT application!
