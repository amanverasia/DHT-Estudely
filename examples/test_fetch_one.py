#!/usr/bin/env python3
"""
Fetch metadata from one known peer.

This is intentionally a live-network example, so it may fail if the peer is
offline or no longer supports metadata exchange.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bt_metadata import fetch_metadata, parse_metainfo

IH_HEX = "87a1e5787d6521268aa2b5045137a298f609cade"
PEER = ("120.230.163.151", 25925)

def main() -> None:
    blob = fetch_metadata(PEER, bytes.fromhex(IH_HEX))
    if not blob:
        print("no metadata (peer offline or not supporting ut_metadata)")
        return

    meta = parse_metainfo(blob)
    print("Name:", meta["name"])
    print("Files:")
    for f in meta["files"][:10]:
        print("  ", f["length"], f["path"])


if __name__ == "__main__":
    main()
