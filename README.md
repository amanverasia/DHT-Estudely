## DHT-Estudely

Small experimental toolkit for exploring the BitTorrent DHT and fetching torrent metadata. Originally a learning sandbox; now includes a minimal crawler, peer discovery, and metadata fetcher merged into a single convenience script.

### Contents

| File | Purpose |
|------|---------|
| `dht_bencode.py` | Minimal bencode encoder/decoder used by all other modules. |
| `dht_krpc.py` | Simple UDP DHT client supporting `find_node`, `get_peers`, and BEP-51 `sample_infohashes`. |
| `bt_metadata.py` | BitTorrent peer handshake + BEP-9 metadata (ut_metadata) retrieval. |
| `dht_crawler_min.py` | Lightweight DHT sampler that outputs discovered `(infohash, peer)` tuples to both stdout and `peers.csv`. |
| `dht_fetch_metadata_batch.py` | Batch metadata fetcher that reads a `peers.csv` produced earlier and outputs basic torrent metadata. |
| `dht_collect_and_metadata.py` | New combined one-shot script: crawl + peer discovery + inline metadata fetch with a single CSV output. |
| `peers.csv` | Accumulated peers discovered (append mode). |

### Quick Start (One-Shot Mode)

If you just want to sample up to 20 infohashes and try to fetch metadata immediately:

```bash
python3 dht_collect_and_metadata.py > metadata_peers.csv
```

This emits a CSV with columns:

```
infohash,name,file_count,total_bytes,piece_length,peer_ip,peer_port,metadata_ok
```

Where:

- `infohash`: 40-char hex SHA1 infohash
- `name`: Torrent name (empty if metadata not obtained)
- `file_count`: Number of files (0 if unknown)
- `total_bytes`: Sum of all file lengths (0 if unknown)
- `piece_length`: Piece size (0 if unknown)
- `peer_ip`, `peer_port`: Peer candidates queried / considered
- `metadata_ok`: `True` if at least one peer returned full metadata

CLI options:

```
--max-infohashes N           (default 20)
--peers-per-infohash N       (default 20)  # max peers we keep per infohash
--metadata-peer-attempts N   (default 5)   # how many peers we try for metadata
--overall-timeout SECONDS    (default 60)
```

Example:

```bash
python3 dht_collect_and_metadata.py \
  --max-infohashes 30 \
  --peers-per-infohash 25 \
  --metadata-peer-attempts 6 \
  --overall-timeout 120 \
  > crawl_out.csv
```

### Two-Step Mode (Legacy Pipeline)

1. Crawl and save peers per infohash:
	```bash
	python3 dht_crawler_min.py > peers_stream.csv
	# Also appends to peers.csv automatically
	```

	Output columns (both stdout and `peers.csv`):
	```
	infohash,peer_ip,peer_port
	```

2. Fetch metadata later from the collected peers:
	```bash
	python3 dht_fetch_metadata_batch.py peers.csv > metadata.csv
	```

	Output columns:
	```
	infohash,name,file_count,total_bytes,piece_length
	```

### How It Works (High Level)

1. **Bootstrap**: Uses public DHT routers (`router.bittorrent.com`, `dht.transmissionbt.com`, `router.utorrent.com`).
2. **Traversal**: Prioritizes BEP-51 `sample_infohashes` where supported (fast random sampling of the keyspace). Falls back to iterative `find_node` lookups to keep discovering nodes.
3. **Peer Discovery**: For each newly sampled infohash, sends `get_peers` to the source node and (if needed) a few closer nodes it returns. Keeps a small bounded peer list per infohash.
4. **Metadata Fetch**: Attempts BitTorrent handshake + extended handshake (BEP-10) + metadata exchange (BEP-9, `ut_metadata`) for a small number of peers until success.
5. **CSV Emission**: Writes structured rows as it proceeds—no state required after termination.

### Safety / Etiquette Notes

- Limits (20 infohashes, 20 peers per infohash, 5 metadata attempts) are intentionally conservative—avoid hammering random peers.
- You can increase limits gradually; be mindful of bandwidth and remote peer load.
- No persistence of node routing tables between runs; each invocation is a fresh crawl.

### Possible Extensions / Ideas

- Add IPv6 support (BEP-32) and compact v6 parsing.
- Persist a small node table between runs for faster warm starts.
- Add filtering (e.g., only metadata above a size threshold).
- Export JSON alongside CSV.
- Parallelize metadata fetches with async IO for throughput (while keeping rate limits).

### Troubleshooting

| Symptom | Likely Cause | Suggestion |
|---------|--------------|------------|
| No nodes discovered | UDP blocked | Try another network / ensure outbound UDP 6881 allowed. |
| Few or zero metadata successes | Random peers without metadata piece support | Increase `--metadata-peer-attempts` or run longer. |
| Script exits quickly with few infohashes | BEP-51 not widely responding in that window | Increase `--overall-timeout` or rely on `find_node` fallback. |
| Unicode issues in names | Non-UTF8 file names in torrent | Current code ignores errors; adjust decoding if needed. |

### Environment

Pure Python 3 standard library; no external dependencies.

### Disclaimer

Educational / research use only. Respect legal and ethical boundaries when interacting with public networks.

---

Happy hacking & learning the DHT!