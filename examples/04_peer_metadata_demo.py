#!/usr/bin/env python3
"""
Example 04: Peer Wire Protocol & Metadata Fetch

Learn how to connect to a BitTorrent peer and fetch metadata:
1. TCP handshake
2. Extended handshake (BEP-10)
3. Request metadata pieces (BEP-9: ut_metadata)

Run: python3 examples/04_peer_metadata_demo.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bt_metadata import bt_handshake, ext_handshake, fetch_metadata, parse_metainfo

def main():
    print("=== Peer Wire Protocol Demo ===\n")

    # We'll use a real (but random) infohash and peer for demonstration
    # In practice, you'd get these from the DHT
    infohash = os.urandom(20)
    peer = ("127.0.0.1", 6881)  # Placeholder - won't actually connect

    print("Protocol flow:")
    print("1. TCP Handshake")
    print("   [pstrlen=19][Protocol='BitTorrent protocol'][reserved][infohash][peer_id]")
    print()
    print("2. Extended Handshake (BEP-10)")
    print("   Enable extensions, announce ut_metadata support")
    print()
    print("3. ut_metadata (BEP-9)")
    print("   Request metadata pieces from peer")

    print("\n=== Actual Connection ===")

    # This will likely fail since 127.0.0.1:6881 is a placeholder
    blob = fetch_metadata(peer, infohash, timeout=3.0)

    if blob:
        meta = parse_metainfo(blob)
        print(f"Name: {meta['name']}")
        print(f"Piece length: {meta['piece_length']}")
        print("Files:")
        for f in meta['files'][:5]:
            print(f"  {f['length']:>10} bytes - {f['path']}")
    else:
        print("(Connection failed - expected, using placeholder peer)")
        print("To try for real, use a peer from DHT discovery!")

    print("\n=== Code Walkthrough ===")
    print("bt_metadata.py key functions:")
    print("  bt_handshake()     - TCP connect + protocol handshake")
    print("  ext_handshake()    - BEP-10 extended handshake")
    print("  fetch_metadata()   - Request all metadata pieces")
    print("  parse_metainfo()   - Parse bencoded .torrent data")

    print("\n=== Key BEPs ===")
    print("BEP-10: Extended Messaging")
    print("  - Adds message ID 20 for extended messages")
    print("  - Enables peer extensions like ut_metadata")
    print()
    print("BEP-9: Metadata Exchange")
    print("  - Peers can share .torrent metadata without .torrent file")
    print("  - Metadata is fetched in 16KB pieces")
    print("  - Required for DHT-only torrents (no tracker)")

if __name__ == "__main__":
    main()
