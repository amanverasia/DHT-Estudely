#!/usr/bin/env python3
"""
Test script to verify metadata fetching works with known infohashes and peers.
"""
import sys
import os
sys.path.append('.')

from bt_metadata import fetch_metadata, parse_metainfo

# Test with some infohashes and peers from our metadata.txt
test_cases = [
    ("380b4ea958b20dd93f4db5babe0453706850acb8", ("221.145.53.155", 33229)),
    ("380b473568ba3b7999abb04fd5c49d1b4992b8e1", ("39.113.90.81", 40646)),
    ("380b4d2e739ea70afa1e63ee6e008390d445baf9", ("104.234.182.79", 12813)),
]

print("Testing metadata fetching with known infohashes and peers...")

for infohash_hex, peer in test_cases:
    print(f"\nTesting {infohash_hex[:8]}... with peer {peer[0]}:{peer[1]}")
    
    try:
        infohash = bytes.fromhex(infohash_hex)
        blob = fetch_metadata(peer, infohash, timeout=5.0)
        
        if blob:
            try:
                info = parse_metainfo(blob)
                print(f"SUCCESS! Name: '{info['name']}'")
                print(f"Files: {len(info['files'])}")
                print(f"Total size: {sum(f['length'] for f in info['files']):,} bytes")
                print(f"Piece length: {info['piece_length']:,}")
                if len(info['files']) <= 5:
                    for f in info['files']:
                        print(f"  - {f['path']} ({f['length']:,} bytes)")
                else:
                    for f in info['files'][:3]:
                        print(f"  - {f['path']} ({f['length']:,} bytes)")
                    print(f"  ... and {len(info['files']) - 3} more files")
            except Exception as e:
                print(f"ERROR parsing metadata: {e}")
        else:
            print("No metadata returned")
            
    except Exception as e:
        print(f"ERROR: {e}")

print("\nTest complete!")