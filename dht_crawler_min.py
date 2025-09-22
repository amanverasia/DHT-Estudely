# dht_crawler_min.py
import socket, time, random, csv, sys
from typing import Deque, Tuple
from collections import deque

from dht_krpc import DHTClient, BOOTSTRAP, parse_compact_nodes, parse_compact_peers

MAX_INFOHASHES = 50          # stop after we collect this many distinct infohashes
PER_INFOHASH_PEERS_LIMIT = 20  # don't spam; collect a few per infohash
SOFT_TIMEOUT_SEC = 25        # overall runtime-ish guard

def resolve_bootstrap():
    out = []
    for host, port in BOOTSTRAP:
        try:
            ip = socket.gethostbyname(host)
            out.append((ip, port))
        except socket.gaierror:
            pass
    random.shuffle(out)
    return out

def main():
    client = DHTClient(timeout=2.0)
    print(f"# my node id: {client.node_id.hex()}", file=sys.stderr)

    try:
        # Seed queue with nodes from bootstraps (via find_node)
        node_q: Deque[Tuple[str, int]] = deque()
        seen_nodes: set[Tuple[str, int]] = set()

        for host, port in BOOTSTRAP:
            try:
                addr = (socket.gethostbyname(host), port)
            except socket.gaierror:
                continue
            resp = client.find_node(addr)
            if not resp:
                continue
            nodes = parse_compact_nodes(resp.get(b"r", {}).get(b"nodes", b""))
            for _, ip, p in nodes:
                if (ip, p) not in seen_nodes:
                    seen_nodes.add((ip, p))
                    node_q.append((ip, p))

        # Caches
        seen_infohashes: set[bytes] = set()

        # CSV writer (stdout)
        writer = csv.writer(sys.stdout)
        writer.writerow(["infohash", "peer_ip", "peer_port"])

        t0 = time.time()

        # Crawl loop
        while node_q and len(seen_infohashes) < MAX_INFOHASHES and (time.time() - t0) < SOFT_TIMEOUT_SEC:
            ip, port = node_q.popleft()

            # Try BEP-51 sampling first
            try:
                resp = client.sample_infohashes((ip, port))
            except Exception:
                resp = None

            if resp and resp.get(b"y") == b"r":
                r = resp.get(b"r", {})
                # enqueue returned nodes to keep walking the space
                nodes = parse_compact_nodes(r.get(b"nodes", b""))
                random.shuffle(nodes)
                for _, nip, nport in nodes[:16]:  # be gentle; enqueue a subset
                    if (nip, nport) not in seen_nodes:
                        seen_nodes.add((nip, nport))
                        node_q.append((nip, nport))

                # harvest samples
                samples = client.parse_samples(resp)
                random.shuffle(samples)
                for ih in samples:
                    if len(seen_infohashes) >= MAX_INFOHASHES:
                        break
                    if ih in seen_infohashes:
                        continue
                    seen_infohashes.add(ih)

                    # ask for peers for this infohash from this node (and maybe a couple extras)
                    peers_written = 0

                    # 1) ask the current node
                    try:
                        gp = client.get_peers((ip, port), ih)
                    except Exception:
                        gp = None

                    def handle_get_peers(gp_resp):
                        nonlocal peers_written
                        if not gp_resp:
                            return []
                        r = gp_resp.get(b"r", {})
                        vals = r.get(b"values")
                        emitted_nodes = []
                        if vals:
                            peers = parse_compact_peers(vals)
                            for pip, pport in peers[:PER_INFOHASH_PEERS_LIMIT - peers_written]:
                                writer.writerow([ih.hex(), pip, pport])
                                peers_written += 1
                                if peers_written >= PER_INFOHASH_PEERS_LIMIT:
                                    break
                        else:
                            # No direct peers, but got closer nodes—enqueue a couple and return them so we can query them for this ih
                            nn = parse_compact_nodes(r.get(b"nodes", b""))
                            for _, nip, nport in nn[:8]:
                                emitted_nodes.append((nip, nport))
                        return emitted_nodes

                    extra_nodes = handle_get_peers(gp)

                    # 2) If we didn’t get peers, try a few of the closer nodes returned
                    random.shuffle(extra_nodes)
                    for en in extra_nodes[:4]:
                        if peers_written >= PER_INFOHASH_PEERS_LIMIT:
                            break
                        try:
                            gp2 = client.get_peers(en, ih)
                        except Exception:
                            gp2 = None
                        handle_get_peers(gp2)

            else:
                # If BEP-51 not supported or failed, do a normal find_node walk so we keep discovering nodes
                try:
                    fresp = client.find_node((ip, port))
                except Exception:
                    fresp = None
                if fresp and fresp.get(b"y") == b"r":
                    nodes = parse_compact_nodes(fresp.get(b"r", {}).get(b"nodes", b""))
                    random.shuffle(nodes)
                    for _, nip, nport in nodes[:16]:
                        if (nip, nport) not in seen_nodes:
                            seen_nodes.add((nip, nport))
                            node_q.append((nip, nport))

        print(f"# collected {len(seen_infohashes)} infohashes", file=sys.stderr)

    finally:
        client.close()

if __name__ == "__main__":
    main()
