# DHT Workshop

This workshop is a guided lab for understanding how BitTorrent DHT and metadata exchange work in this repo.

Use it when you want a structured path instead of jumping straight into the crawler.

## Workshop Goal

By the end, you should be able to explain:

1. What an infohash is
2. What the DHT does
3. Why DHT uses UDP but peer transfers use TCP
4. How a client goes from "I know an infohash" to "I can fetch torrent metadata"
5. Which files in this repo implement each protocol layer

## Ground Rules

- Start with the small, local, deterministic steps first
- Do not treat a failed live network demo as a conceptual failure
- After each step, explain the result in your own words before moving on

## Mental Model First

Before running anything, keep this picture in mind:

1. A torrent is identified by an **infohash**
2. The **DHT** helps you find peers that know about that infohash
3. The DHT does not give you the file contents
4. Once you find a peer, you open a TCP connection
5. Then you use BitTorrent extension messages to ask for metadata

In repo terms:

- `dht_bencode.py`: how messages are encoded
- `dht_krpc.py`: how DHT nodes talk
- `bt_metadata.py`: how peers exchange metadata
- `dht_collect_and_metadata.py`: how the whole flow is stitched together

---

## Lab 1: Bencode

Run:

```bash
python3 examples/01_bencode_demo.py
```

Observe:

- integers, strings, lists, and dicts have compact encodings
- decoded string-like values come back as `bytes`
- this is the base format used by both DHT and peer extension messages

Questions:

1. Why is `b'hello'` returned instead of `'hello'`?
2. Why might a protocol prefer compact bytes over JSON?
3. Why do dictionary keys need stable ordering when encoded?

Open next:

- `dht_bencode.py`

Look for:

- `bencode()`
- `_bdecode_any()`
- `bdecode()`

What to understand:

- every higher-level protocol in this repo depends on these functions

---

## Lab 2: Offline Invariants

Run:

```bash
python3 -m unittest test_offline_regressions.py
```

Observe:

- these checks do not rely on live DHT nodes or public peers
- metadata parsing accepts both a bare `info` dict and a wrapped metainfo dict
- DHT clients should only trust replies from the node they queried

Questions:

1. Why is offline verification useful in a network-heavy repo?
2. Why is it dangerous to accept a UDP reply from the wrong sender?
3. Why does it matter that `parse_metainfo()` supports the raw BEP-9 payload shape?

Open next:

- `test_offline_regressions.py`
- `bt_metadata.py`
- `dht_krpc.py`

What to understand:

- protocol code is easier to trust when core assumptions are tested without the public network

---

## Lab 3: DHT Bootstrap

Run:

```bash
python3 dht_krpc.py
```

Expected result:

- your node generates a random node ID
- it contacts one or more bootstrap routers
- if your network allows it, it learns additional nodes

If it fails:

- that usually means UDP traffic is blocked or public nodes did not answer in time
- the conceptual model is still the same

Questions:

1. What is the purpose of a bootstrap node?
2. Why is `find_node` a good first query?
3. What does a "compact node" entry contain?

Open next:

- `dht_krpc.py`

Look for:

- `DHTClient._send_query()`
- `DHTClient._await_response()`
- `find_node()`
- `parse_compact_nodes()`

What to understand:

- DHT traffic is small, stateless, and query/response oriented

---

## Lab 4: Peer Discovery Concepts

Run:

```bash
python3 examples/03_dht_get_peers_demo.py
```

Observe:

- `sample_infohashes` and `get_peers` serve different purposes
- a node may return peers directly, or it may return closer nodes instead

Questions:

1. Why doesn’t `get_peers` always return peers immediately?
2. How is `sample_infohashes` different from asking for peers for a known torrent?
3. Why is DHT lookup an iterative process?

Open next:

- `examples/03_dht_get_peers_demo.py`
- `dht_krpc.py`

What to understand:

- DHT is more like walking a graph of nearby nodes than asking one server for the full answer

---

## Lab 5: Peer Wire and Metadata

Run:

```bash
python3 examples/test_fetch_one.py
```

Expected result:

- if the peer is reachable and supports metadata exchange, you get a torrent name and file list
- if not, you get a failure message

Important:

- success depends on a live public peer
- a failed run does not mean the code path is conceptually wrong

Questions:

1. Why does DHT stop at peer addresses?
2. Why is a TCP handshake needed after DHT discovery?
3. What is the difference between the base BitTorrent handshake and the extended handshake?
4. Why is metadata fetched in pieces?

Open next:

- `bt_metadata.py`

Look for:

- `bt_handshake()`
- `ext_handshake()`
- `fetch_metadata()`
- `parse_metainfo()`

What to understand:

- DHT discovers who to talk to; peer wire determines how you talk to them

---

## Lab 6: Full Pipeline

Run only after the earlier labs make sense:

```bash
python3 dht_collect_and_metadata.py
```

Observe:

- the script composes the lower layers into a pipeline
- it bootstraps, samples infohashes, asks for peers, then tries metadata fetches
- results are noisy because the public network is noisy

Questions:

1. Which parts of this flow are deterministic, and which depend on the public network?
2. Where can timeouts happen?
3. Why does the full crawler become much easier to understand after the smaller labs?

Open next:

- `dht_collect_and_metadata.py`

What to understand:

- the combined script is not a new protocol; it is just orchestration of the lower-level pieces

---

## Map The Files To The Protocol

Use this as your recap:

- `dht_bencode.py`: serialization format
- `dht_krpc.py`: UDP query/response DHT messaging
- `bt_metadata.py`: TCP peer handshake and BEP-9/BEP-10 metadata exchange
- `dht_collect_and_metadata.py`: end-to-end workflow
- `docs/PROTOCOLS.md`: theory and specs
- `docs/LEARNING.md`: broader reading guide

## Common Misconceptions

- "The DHT gives me the file bytes"
  Correction: the DHT helps you find peers, not file contents

- "The infohash is just a hash of the downloaded files"
  Correction: it is derived from the torrent `info` dictionary

- "If a live demo fails, the protocol explanation must be wrong"
  Correction: public peers and nodes are unstable; the model still holds

- "Metadata fetch means downloading the torrent payload"
  Correction: it means downloading the torrent metadata structure

## Suggested Teaching Prompts For Agents

If you are an agent guiding a user through this repo, ask prompts like:

- "What changed between the DHT step and the TCP peer step?"
- "Why do you think DHT uses UDP here?"
- "What exactly does the infohash identify?"
- "Why is the metadata parser designed to accept an `info` dict directly?"

The point is to make the user explain the model back, not just watch commands run.

## Where To Go Next

After this workshop, a good next step is:

1. Read `docs/PROTOCOLS.md`
2. Modify one example script and predict how behavior changes
3. Add a new offline test for a protocol edge case
4. Trace one successful metadata fetch end-to-end through the code
