#!/usr/bin/env python3
"""
Example 02: DHT Bootstrap & Discovery

Learn how to connect to the DHT network and discover nodes.

This connects to bootstrap nodes and shows:
1. How to send a find_node query
2. How to parse the compact node format
3. How to build a routing table

Run: python3 examples/02_dht_bootstrap_demo.py
"""
import socket
from dht_krpc import DHTClient, BOOTSTRAP, parse_compact_nodes

def main():
    print("=== DHT Bootstrap Demo ===\n")

    client = DHTClient(timeout=3.0)
    print(f"My node ID: {client.node_id.hex()[:16]}...\n")

    print("Connecting to bootstrap nodes...")
    all_nodes = []

    for host, port in BOOTSTRAP:
        try:
            addr = (socket.gethostbyname(host), port)
            print(f"-> {host}:{port}...", end=" ", flush=True)

            # Send find_node to discover more nodes
            resp = client.find_node(addr)
            if resp:
                r = resp.get(b"r", {})
                nodes_data = r.get(b"nodes", b"")
                nodes = parse_compact_nodes(nodes_data)
                print(f"found {len(nodes)} nodes")
                all_nodes.extend(nodes)
            else:
                print("no response")
        except socket.gaierror as e:
            print(f"DNS failed: {e}")
        except Exception as e:
            print(f"error: {e}")

    client.close()

    print(f"\n=== Results ===")
    print(f"Total nodes discovered: {len(all_nodes)}")

    if all_nodes:
        print(f"\nFirst 5 nodes:")
        for i, (nid, ip, port) in enumerate(all_nodes[:5]):
            print(f"  {i+1}. {ip}:{port}  (node_id: {nid.hex()[:12]}...)")

        print(f"\nDHT is working! You can now use these nodes for:")
        print("  - get_peers: Find peers sharing a specific torrent")
        print("  - sample_infohashes: Get random infohashes (BEP-51)")
    else:
        print("\nNo nodes found. Check if UDP port 6881 is blocked.")

if __name__ == "__main__":
    main()
