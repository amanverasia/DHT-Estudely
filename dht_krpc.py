# dht_krpc.py
import os, random, socket, struct, time
from typing import List, Tuple, Dict, Optional
from dht_bencode import bencode, bdecode
import struct

def parse_compact_peers(values) -> list[tuple[str, int]]:
    """
    'values' is a list of 6-byte compact entries (IPv4 only here):
      ip(4) + port(2 big-endian)
    Returns list of (ip_str, port).
    """
    out: list[tuple[str, int]] = []
    if not values:
        return out
    for v in values:
        if not isinstance(v, (bytes, bytearray)) or len(v) < 6:
            continue
        ip_raw = v[0:4]
        port_raw = v[4:6]
        ip = ".".join(str(b) for b in ip_raw)
        port = struct.unpack("!H", port_raw)[0]
        out.append((ip, port))
    return out

# --- Helpers ---------------------------------------------------------------

def rand_node_id() -> bytes:
    return os.urandom(20)  # 160-bit random ID

def rand_tid(n: int = 2) -> bytes:
    # small transaction id (2 bytes is common)
    return os.urandom(n)

def parse_compact_nodes(data: bytes) -> List[Tuple[bytes, str, int]]:
    """
    Kademlia 'nodes' value is a concatenation of 26-byte entries:
      node_id(20) + IPv4(4) + port(2 big-endian)
    Returns list of (node_id, ip_str, port)
    """
    out = []
    if not data:
        return out
    if len(data) % 26 != 0:
        # Some nodes can send odd data; be defensive
        data = data[: (len(data) // 26) * 26]
    for i in range(0, len(data), 26):
        nid = data[i:i+20]
        ip_raw = data[i+20:i+24]
        port_raw = data[i+24:i+26]
        ip = ".".join(str(b) for b in ip_raw)
        port = struct.unpack("!H", port_raw)[0]
        out.append((nid, ip, port))
    return out

# --- KRPC Client -----------------------------------------------------------

class DHTClient:
    def __init__(self, bind_ip: str = "0.0.0.0", bind_port: int = 0, timeout: float = 2.0):
        self.node_id = rand_node_id()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind_ip, bind_port))
        self.sock.settimeout(timeout)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    # --- Send/receive ---

    def _send_query(self, addr: Tuple[str, int], q: str, args: Dict[bytes, object]) -> bytes:
        """
        Build & send a KRPC query.
        """
        t = rand_tid()
        msg = {b"t": t, b"y": b"q", b"q": q.encode("ascii"), b"a": {**args, b"id": self.node_id}}
        payload = bencode(msg)
        self.sock.sendto(payload, addr)
        return t

    def _recv(self) -> Optional[Tuple[dict, Tuple[str, int]]]:
        """
        Receive one packet and bdecode it.
        """
        try:
            data, src = self.sock.recvfrom(65535)
        except socket.timeout:
            return None
        try:
            obj, used = bdecode(data)
            if used != len(data):
                # ignore trailing junk if any
                pass
            if isinstance(obj, dict):
                return obj, src
        except Exception:
            pass
        return None

    # --- Queries we need ---

    def ping(self, addr: Tuple[str, int]) -> Optional[dict]:
        t = self._send_query(addr, "ping", {})
        deadline = time.time() + 2.0
        while time.time() < deadline:
            pkt = self._recv()
            if not pkt:
                continue
            obj, src = pkt
            if obj.get(b"y") == b"r" and obj.get(b"t") == t:
                return obj
        return None

    def find_node(self, addr: Tuple[str, int], target: Optional[bytes] = None) -> Optional[dict]:
        if target is None:
            target = rand_node_id()
        t = self._send_query(addr, "find_node", {b"target": target})
        deadline = time.time() + 2.0
        while time.time() < deadline:
            pkt = self._recv()
            if not pkt:
                continue
            obj, src = pkt
            if obj.get(b"y") == b"r" and obj.get(b"t") == t:
                return obj
        return None
    
    def get_peers(self, addr: tuple[str, int], infohash: bytes) -> dict | None:
        t = self._send_query(addr, "get_peers", {b"info_hash": infohash})
        deadline = time.time() + 2.0
        while time.time() < deadline:
            pkt = self._recv()
            if not pkt:
                continue
            obj, src = pkt
            if obj.get(b"y") == b"r" and obj.get(b"t") == t:
                return obj
        return None
    
    def sample_infohashes(self, addr: tuple[str, int], target: bytes | None = None) -> dict | None:
        """
        BEP-51: https://www.bittorrent.org/beps/bep_0051.html
        Query: { "q": "sample_infohashes", "a": { "id": <nid>, "target": <20B> } }
        Response contains:
        r.nodes (compact nodes), r.samples (concat of 20B infohashes), r.num (int)
        """
        if target is None:
            target = rand_node_id()
        t = self._send_query(addr, "sample_infohashes", {b"target": target})
        deadline = time.time() + 2.0
        while time.time() < deadline:
            pkt = self._recv()
            if not pkt:
                continue
            obj, src = pkt
            if obj.get(b"y") == b"r" and obj.get(b"t") == t:
                return obj
        return None

    def parse_samples(self, resp: dict) -> list[bytes]:
        r = resp.get(b"r", {})
        raw = r.get(b"samples", b"")
        # samples are concatenated 20-byte infohashes
        out: list[bytes] = []
        if not isinstance(raw, (bytes, bytearray)):
            return out
        for i in range(0, len(raw), 20):
            chunk = raw[i:i+20]
            if len(chunk) == 20:
                out.append(bytes(chunk))
        return out



# --- Demo: bootstrap via public routers ------------------------------------

BOOTSTRAP = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
]

def main():
    client = DHTClient()
    print(f"My node id: {client.node_id.hex()}")
    try:
        # Try find_node on each bootstrap and collect any returned nodes
        collected = []
        for host, port in BOOTSTRAP:
            try:
                addr = (socket.gethostbyname(host), port)
            except socket.gaierror:
                print(f"DNS failed for {host}")
                continue
            print(f"-> find_node to {host}:{port} at {addr[0]}:{addr[1]}")
            resp = client.find_node(addr)
            if not resp:
                print("   (no response)")
                continue
            r = resp.get(b"r", {})
            nodes = r.get(b"nodes", b"")
            parsed = parse_compact_nodes(nodes)
            print(f"   got {len(parsed)} nodes")
            collected.extend(parsed)

        # Show a few nodes we learned about
        print("\nSample of discovered nodes:")
        for nid, ip, port in collected[:20]:
            print(f"{ip}:{port}  nid={nid.hex()[:16]}...")

        if not collected:
            print("\nNo nodes found. Are UDP/6881 packets blocked by your network or ISP?")
    finally:
        client.close()

if __name__ == "__main__":
    main()
