#!/usr/bin/env python3
"""
Example 01: Bencode Basics

Learn how bencode serialization works - the foundation of all BitTorrent communication.

Bencode types:
  Integer: i42e        -> 42
  String:  4:spam      -> "spam" (length:content)
  List:    l4:spami42ee -> ["spam", 42]
  Dict:    d3:foo3:bari42ee -> {"foo": 42}
"""
from dht_bencode import bencode, bdecode

print("=== Bencode Encoding ===")
print(f"Integer: {bencode(42)}")
print(f"String:  {bencode('spam')}")
print(f"List:    {bencode(['spam', 42])}")
print(f"Dict:    {bencode({'foo': 'bar', 'num': 123})}")

print("\n=== Bencode Decoding ===")
print(f"i123e    -> {bdecode(b'i123e')[0]}")
print(f"5:hello  -> {bdecode(b'5:hello')[0]}")
print(f"li1ei2ei3ee -> {bdecode(b'li1ei2ei3ee')[0]}")
print(f"d3:fooi1e -> {bdecode(b'd3:fooi1ee')[0]}")

print("\n=== Round-trip ===")
original = {"name": "test.torrent", "piece length": 262144, "files": ["a.txt", "b.txt"]}
encoded = bencode(original)
decoded, _ = bdecode(encoded)
print(f"Original: {original}")
print(f"Encoded:  {encoded}")
print(f"Decoded:  {decoded}")
print(f"Match:    {original == decoded}")
