#!/usr/bin/env python3
"""
Example 03: DHT - Get Peers & Sample Infohashes

Learn two key DHT operations:
1. get_peers - Find peers sharing a specific torrent
2. sample_infohashes - Get random infohashes from a node (BEP-51)

Run: python3 examples/03_dht_get_peers_demo.py
"""
import socket
import os
from dht_krpc import DHTClient, BOOTSTRAP, parse_compact_nodes, parse_compact_peers

def find_node_near_target(client, target: bytes) -> tuple:
    """Find a node close to target using bootstrap nodes."""
    for host, port in BOOTSTRAP:
        try:
            addr = (socket.gethostbyname(host), port)
            resp = client.find_node(addr, target)
            if resp:
                r = resp.get(b"r", {})
                nodes_data = r.get(b"nodes", b"")
                nodes = parse_compact_nodes(nodes_data)
                if nodes:
                    # Return first node
                    return nodes[0]
        except:
            pass
    return None

def main():
    print("=== DHT Get Peers Demo ===\n")

    client = DHTClient(timeout=3.0)

    # Demo 1: sample_infohashes - get random infohashes from a node
    print("1. Trying sample_infohashes (BEP-51)...")
    for host, port in BOOTSTRAP:
        try:
            addr = (socket.gethostbyname(host), port)
            resp = client.sample_infohashes(addr)
            if resp:
                samples = client.parse_samples(resp)
                r = resp.get(b"r", {})
                num = r.get(b"num", 0)
                print(f"   {host}: got {len(samples)} sample infohashes (total: {num})")
                if samples:
                    print(f"   First sample: {samples[0].hex()[:20]}...")
                break
        except Exception as e:
            print(f"   {host}: {e}")

    # Demo 2: get_peers - find peers for a specific infohash
    print("\n2. Trying get_peers for a known infohash...")

    # Use a real torrent infohash (example: a popular Ubuntu ISO)
    # This is just for demo - any valid 20-byte infohash works
    demo_infohash = os.urandom(20)  # Random for demo

    # First find a node, then query it for peers
    node = find_node_near_target(client, demo_infohash)
    if node:
        nid, ip, port = node
        print(f"   Querying node {ip}:{port} for peers...")

        resp = client.get_peers((ip, port), demo_infohash)
        if resp:
            r = resp.get(b"r", {})
            # Check for peers (compact format)
            peers_data = r.get(b"values", [])
            if peers_data:
                peers = parse_compact_peers(peers_data)
                print(f"   Found {len(peers)} peers!")
                for p in peers[:3]:
                    print(f"     {p[0]}:{p[1]}")
            else:
                # No peers yet, but got more nodes
                nodes_data = r.get(b"nodes", b"")
                nodes = parse_compact_nodes(nodes_data)
                print(f"   No peers yet, but got {len(nodes)} closer nodes")
        else:
            print("   No response")
    else:
        print("   Could not find initial node")

    client.close()

    print("\n=== Key Concepts ===")
    print("- sample_infohashes: Fast way to discover random torrents")
    print("- get_peers: Given an infohash, find peers sharing that torrent")
    print("- DHT uses XOR distance to find 'close' nodes to a target")

if __name__ == "__main__":
    main()
