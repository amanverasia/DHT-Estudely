#!/usr/bin/env python3
"""
Single-pass DHT sampler + metadata fetcher.

This script intentionally reuses the canonical protocol modules instead of
re-implementing them locally:
- dht_krpc.py for DHT/KRPC traffic
- bt_metadata.py for peer wire + metadata exchange

Usage:
    python3 dht_collect_and_metadata.py
    python3 dht_collect_and_metadata.py --output results.csv
"""

from __future__ import annotations

import argparse
import csv
import random
import signal
import socket
import sys
import time
from collections import deque
from pathlib import Path
from typing import Deque, Iterable, Optional

from bt_metadata import fetch_metadata, parse_metainfo
from dht_krpc import BOOTSTRAP, DHTClient, parse_compact_nodes, parse_compact_peers


MAX_INFOHASHES = 999999
PEERS_PER_INFOHASH = 20
METADATA_PEER_ATTEMPTS = 5
OVERALL_TIMEOUT = 86400.0
DEFAULT_OUTPUT = Path("metadata.txt")
CSV_HEADER = [
    "infohash",
    "name",
    "file_count",
    "total_bytes",
    "piece_length",
    "peer_ip",
    "peer_port",
    "metadata_ok",
]


def resolve_bootstrap() -> list[tuple[str, int]]:
    addrs: list[tuple[str, int]] = []
    for host, port in BOOTSTRAP:
        try:
            addrs.append((socket.gethostbyname(host), port))
        except socket.gaierror:
            continue
    return addrs


def query_peers_simple(
    client: DHTClient,
    infohash: bytes,
    nodes: Iterable[tuple[str, int]],
    max_peers: int,
) -> set[tuple[str, int]]:
    """Query a few nodes for peers without spawning worker threads."""
    all_peers: set[tuple[str, int]] = set()
    for node in list(nodes)[:3]:
        if len(all_peers) >= max_peers:
            break
        try:
            resp = client.get_peers(node, infohash)
        except Exception:
            resp = None
        if not resp or resp.get(b"y") != b"r":
            continue
        values = resp.get(b"r", {}).get(b"values")
        if not values:
            continue
        for peer in parse_compact_peers(values):
            all_peers.add(peer)
            if len(all_peers) >= max_peers:
                break
    return all_peers


def fetch_metadata_summary(
    infohash: bytes,
    peers: list[tuple[str, int]],
    attempts: int,
) -> tuple[bool, str, int, int, int]:
    name = ""
    file_count = 0
    total_bytes = 0
    piece_length = 0

    for peer in peers[:attempts]:
        try:
            blob = fetch_metadata(peer, infohash, timeout=4.0)
        except Exception as exc:
            print(f"# Connection failed to {peer[0]}:{peer[1]} - {exc}", file=sys.stderr)
            continue
        if not blob:
            print(f"# No metadata from {peer[0]}:{peer[1]}", file=sys.stderr)
            continue
        try:
            info = parse_metainfo(blob)
        except Exception as exc:
            print(f"# Failed to parse metadata from {peer[0]}:{peer[1]} - {exc}", file=sys.stderr)
            continue

        name = info["name"]
        file_count = len(info["files"])
        total_bytes = sum(f["length"] for f in info["files"])
        piece_length = info["piece_length"]
        print(
            f"# SUCCESS! Got metadata: '{name}' ({file_count} files, {total_bytes:,} bytes)",
            file=sys.stderr,
        )
        return True, name, file_count, total_bytes, piece_length

    return False, name, file_count, total_bytes, piece_length


def crawl_and_fetch(
    max_infohashes: int,
    peers_per_infohash_limit: int,
    metadata_peer_attempts: int,
    overall_timeout: float,
    output_path: Optional[Path],
) -> None:
    client = DHTClient(timeout=2.0)
    print(f"# DHT node ID: {client.node_id.hex()}", file=sys.stderr)

    start = time.time()
    node_q: Deque[tuple[str, int]] = deque()
    seen_nodes: set[tuple[str, int]] = set()
    seen_infohashes: set[bytes] = set()
    processed_count = 0

    for addr in resolve_bootstrap():
        try:
            resp = client.find_node(addr)
        except Exception:
            resp = None
        if not resp:
            continue
        nodes = parse_compact_nodes(resp.get(b"r", {}).get(b"nodes", b""))
        for _, ip, port in nodes:
            node_addr = (ip, port)
            if node_addr in seen_nodes:
                continue
            seen_nodes.add(node_addr)
            node_q.append(node_addr)

    print(f"# Bootstrapped with {len(node_q)} initial nodes", file=sys.stderr)

    stdout_writer = csv.writer(sys.stdout)
    stdout_writer.writerow(CSV_HEADER)

    output_file = None
    file_writer = None
    if output_path is not None:
        output_file = output_path.open("w", newline="", buffering=1)
        file_writer = csv.writer(output_file)
        file_writer.writerow(CSV_HEADER)
        print(f"# Writing a copy to {output_path}", file=sys.stderr)

    try:
        while node_q and len(seen_infohashes) < max_infohashes and (time.time() - start) < overall_timeout:
            ip, port = node_q.popleft()
            try:
                resp = client.sample_infohashes((ip, port))
            except Exception:
                resp = None

            if resp and resp.get(b"y") == b"r":
                r = resp.get(b"r", {})
                nodes = parse_compact_nodes(r.get(b"nodes", b""))
                random.shuffle(nodes)
                for _, nip, nport in nodes[:16]:
                    node_addr = (nip, nport)
                    if node_addr in seen_nodes:
                        continue
                    seen_nodes.add(node_addr)
                    node_q.append(node_addr)

                samples = client.parse_samples(resp)
                random.shuffle(samples)
                for infohash in samples:
                    if len(seen_infohashes) >= max_infohashes:
                        break
                    if infohash in seen_infohashes:
                        continue
                    seen_infohashes.add(infohash)

                    query_nodes = [(ip, port), *list(node_q)[:2]]
                    peer_list = list(query_peers_simple(client, infohash, query_nodes, peers_per_infohash_limit))
                    random.shuffle(peer_list)

                    metadata_ok, name, file_count, total_bytes, piece_length = fetch_metadata_summary(
                        infohash,
                        peer_list,
                        min(metadata_peer_attempts, len(peer_list)),
                    )

                    if peer_list:
                        rows = [
                            [
                                infohash.hex(),
                                name,
                                file_count,
                                total_bytes,
                                piece_length,
                                peer_ip,
                                peer_port,
                                metadata_ok,
                            ]
                            for peer_ip, peer_port in peer_list
                        ]
                    else:
                        rows = [[infohash.hex(), name, file_count, total_bytes, piece_length, "", "", metadata_ok]]

                    for row in rows:
                        stdout_writer.writerow(row)
                        if file_writer is not None:
                            file_writer.writerow(row)

                    processed_count += 1
                    if processed_count % 10 == 0:
                        elapsed = time.time() - start
                        rate = processed_count / elapsed * 60 if elapsed else 0.0
                        print(
                            f"# Progress: {processed_count} infohashes processed, {rate:.1f}/min, {len(node_q)} nodes queued",
                            file=sys.stderr,
                        )
                continue

            try:
                fallback = client.find_node((ip, port))
            except Exception:
                fallback = None
            if not fallback or fallback.get(b"y") != b"r":
                continue
            nodes = parse_compact_nodes(fallback.get(b"r", {}).get(b"nodes", b""))
            random.shuffle(nodes)
            for _, nip, nport in nodes[:16]:
                node_addr = (nip, nport)
                if node_addr in seen_nodes:
                    continue
                seen_nodes.add(node_addr)
                node_q.append(node_addr)

        elapsed = time.time() - start
        print(f"# Final: {processed_count} infohashes processed in {elapsed:.1f}s", file=sys.stderr)
    finally:
        client.close()
        if output_file is not None:
            output_file.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sample the DHT and fetch metadata from discovered peers.")
    parser.add_argument("--max-infohashes", type=int, default=MAX_INFOHASHES)
    parser.add_argument("--peers-per-infohash", type=int, default=PEERS_PER_INFOHASH)
    parser.add_argument("--metadata-peer-attempts", type=int, default=METADATA_PEER_ATTEMPTS)
    parser.add_argument("--overall-timeout", type=float, default=OVERALL_TIMEOUT)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Optional CSV output path for the on-disk copy.",
    )
    parser.add_argument(
        "--stdout-only",
        action="store_true",
        help="Write CSV only to stdout and skip the on-disk copy.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    def signal_handler(signum, _frame):
        print(f"\n# Received signal {signum}, shutting down gracefully...", file=sys.stderr)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    output_path = None if args.stdout_only else args.output

    try:
        crawl_and_fetch(
            max_infohashes=args.max_infohashes,
            peers_per_infohash_limit=args.peers_per_infohash,
            metadata_peer_attempts=args.metadata_peer_attempts,
            overall_timeout=args.overall_timeout,
            output_path=output_path,
        )
    except KeyboardInterrupt:
        print("\n# Interrupted by user", file=sys.stderr)
    except Exception as exc:
        print(f"# Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
