# dht_fetch_metadata_batch.py
import csv, time, random, sys
from collections import defaultdict
from typing import Dict, List, Tuple
from bt_metadata import fetch_metadata, parse_metainfo

PEERS_PER_INFOHASH_TO_TRY = 5
CONNECT_TIMEOUT = 6.0

def main():
    if len(sys.argv) < 2:
        print("Usage: python dht_fetch_metadata_batch.py peers.csv > metadata.csv", file=sys.stderr)
        sys.exit(1)

    # group peers by infohash
    groups: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    with open(sys.argv[1], newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            ih = row["infohash"].lower()
            ip = row["peer_ip"]
            port = int(row["peer_port"])
            groups[ih].append((ip, port))

    w = csv.writer(sys.stdout)
    w.writerow(["infohash","name","file_count","total_bytes","piece_length"])

    for ih_hex, peers in groups.items():
        random.shuffle(peers)
        peers = peers[:PEERS_PER_INFOHASH_TO_TRY]
        got = False
        for p in peers:
            blob = fetch_metadata(p, bytes.fromhex(ih_hex), timeout=CONNECT_TIMEOUT)
            if not blob:
                continue
            try:
                meta = parse_metainfo(blob)
            except Exception:
                continue

            total_bytes = sum(f["length"] for f in meta["files"])
            w.writerow([
                ih_hex,
                meta["name"],
                len(meta["files"]),
                total_bytes,
                meta["piece_length"],
            ])
            got = True
            break
        # polite pacing to avoid hammering
        time.sleep(0.1)

if __name__ == "__main__":
    main()
