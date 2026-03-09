# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DHT-Estudely is an educational BitTorrent DHT exploration toolkit built to understand how torrenting works. It's a learning playground - read the code, experiment, and learn the protocols.

Pure Python 3 with no external dependencies.

This repo should be treated as an educational sandbox first and a crawler/tool second.

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
test_offline_regressions.py # Offline regression tests for parser/client behavior
LICENSE                     # Open-source license

docs/
  PROTOCOLS.md              # Detailed protocol documentation
  LEARNING.md               # Broad learning guide
  WORKSHOP.md               # Step-by-step guided lab for users

examples/
  test_fetch_one.py         # Example: full metadata fetch flow
```

## Running

```bash
# Main crawler - discover + fetch metadata
python3 dht_collect_and_metadata.py

# DHT bootstrap demo
python3 dht_krpc.py

# Test metadata fetch
python3 examples/test_fetch_one.py

# Offline regression tests
python3 -m unittest test_offline_regressions.py
```

All scripts under `examples/` are intended to be runnable from the repo root.

## Agent Mission

When working in this repo, optimize for helping the user understand:

1. What DHT is
2. How torrent clients find peers without trackers
3. How metadata is fetched from peers
4. How the code maps onto the protocol

Do not default to "run the crawler and dump output". Default to a guided learning path unless the user explicitly asks for implementation-only work.

## Default Teaching Flow

Future agents should prefer this order:

1. Start with a plain-language explanation of the BitTorrent stack
2. Ground that explanation in one file at a time
3. Use small offline examples before live network activity
4. Only then move to DHT bootstrap, peer discovery, and metadata fetching
5. End by tying the observed behavior back to the BEPs and source files

Recommended progression:

1. `dht_bencode.py`
   Teach: BitTorrent messages are just structured bytes
   Show: encode/decode examples and why decoded strings become `bytes`
2. `dht_krpc.py`
   Teach: DHT nodes talk over UDP using KRPC
   Show: `ping`, `find_node`, `get_peers`, `sample_infohashes`
3. `bt_metadata.py`
   Teach: peers speak TCP and use BEP-10/BEP-9 to exchange metadata
   Show: handshake, extended handshake, piece requests
4. `dht_collect_and_metadata.py`
   Teach: how the full pipeline composes the lower layers
   Show: bootstrap -> sample infohashes -> get peers -> fetch metadata

## Guided Experience Rules

When the user is learning, future agents should:

- Explain the purpose of each command before running it
- Explain what output the user should expect and why it matters
- Prefer `examples/` and offline tests before the main crawler
- Use the docs and code together rather than only paraphrasing one or the other
- Keep answers concrete: define terms like node ID, infohash, peer, tracker, metadata, and compact node format
- Contrast DHT with trackers whenever the user seems unclear
- Emphasize that an infohash identifies torrent metadata, not "the file bytes themselves"
- Clarify that `fetch_metadata()` retrieves the torrent `info` dictionary via BEP-9, not the file contents

Future agents should avoid:

- Jumping straight into raw protocol jargon without a plain-English frame
- Assuming the user already understands SHA-1, bencode, XOR distance, or BEPs
- Treating torrenting as synonymous with piracy; keep explanations protocol-focused and neutral
- Relying entirely on live network demos when an offline explanation would teach the concept better

## Offline-First Learning Mode

If the user asks to learn how the repo works, prefer this sequence:

```bash
python3 examples/01_bencode_demo.py
python3 -m unittest test_offline_regressions.py
python3 dht_krpc.py
python3 examples/test_fetch_one.py
```

How to use that sequence:

- `examples/01_bencode_demo.py`: establish the data format used everywhere
- `test_offline_regressions.py`: show important invariants without depending on the public network
- `dht_krpc.py`: demonstrate node discovery
- `examples/test_fetch_one.py`: demonstrate metadata retrieval from a specific peer

Only recommend `python3 dht_collect_and_metadata.py` after the user understands the smaller pieces.

## What To Explain At Each Layer

### Layer 1: Bencode

Always explain:

- Why BitTorrent uses a compact binary serialization
- Why decoded strings are returned as `bytes`
- How dictionaries are sorted during encoding

### Layer 2-3: KRPC + DHT

Always explain:

- Why DHT uses UDP
- What transaction IDs do
- Why `find_node` and `get_peers` are different
- What `sample_infohashes` adds on top of the base DHT flow

### Layer 4: Peer Wire + Metadata

Always explain:

- Why DHT only gets you peer addresses, not file contents
- Why a TCP handshake is needed after DHT discovery
- The difference between the BitTorrent handshake and the extended handshake
- That metadata is fetched in pieces via `ut_metadata`

## Repo-Specific Guidance For Future Agents

- If the user asks for a walkthrough, use file references and move top-down through the stack
- If the user asks "how torrenting works", answer in protocol terms first, then connect to this repo's files
- If the user asks to run something, prefer the smallest script that demonstrates the concept
- If a live network demo fails, explain that public DHT/peer availability is inherently unstable and continue with an offline explanation
- Mention `docs/PROTOCOLS.md` for theory and the Python modules for implementation
- Prefer `docs/WORKSHOP.md` when the user wants a guided hands-on experience
- Mention `test_offline_regressions.py` when discussing correctness or recent fixes

## Suggested First Response Pattern

When a user asks a broad question like "teach me how this works", future agents should generally respond with:

1. A 3-5 sentence mental model of torrenting and DHT
2. A proposed learning path through 2-4 files/scripts
3. One small first step, usually `examples/01_bencode_demo.py` or reading `dht_bencode.py`

## Data Shape Notes

- `dht_bencode.bdecode()` returns bencoded string values as `bytes`, not Python `str`
- `bt_metadata.fetch_metadata()` returns the raw BEP-9 metadata payload, which is typically the torrent `info` dict rather than a fully wrapped `.torrent` metainfo dict
- `bt_metadata.parse_metainfo()` accepts both shapes

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
