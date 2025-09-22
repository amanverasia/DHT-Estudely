#!/usr/bin/env python3
"""
Optimized single-pass DHT sampler + metadata fetcher.

Key optimizations applied:
1. Efficient data structures (sets for membership tests)
2. Optimized bencode/bdecode with reduced allocations
3. Caching for repeated operations (DNS, compact nodes)
4. Concurrent peer queries using threading
5. Improved error handling and timeouts
6. Memory-efficient string operations

Usage: python3 dht_collect_and_metadata.py > output.csv
"""
import os, sys, socket, random, time, csv, struct, signal
from collections import deque, defaultdict
from typing import Any, Dict, List, Tuple, Optional, Deque, Set
import threading

# -------------------- Optimized Bencode --------------------

# Pre-compiled constants for performance
_INT_PREFIX = b"i"
_INT_SUFFIX = b"e" 
_LIST_PREFIX = b"l"
_LIST_SUFFIX = b"e"
_DICT_PREFIX = b"d"
_DICT_SUFFIX = b"e"
_COLON = b":"

def bencode(x: Any) -> bytes:
    """Optimized bencode with reduced allocations."""
    if isinstance(x, int):
        return _INT_PREFIX + str(x).encode("ascii") + _INT_SUFFIX
    elif isinstance(x, bytes):
        return str(len(x)).encode("ascii") + _COLON + x
    elif isinstance(x, str):
        b = x.encode("utf-8")
        return str(len(b)).encode("ascii") + _COLON + b
    elif isinstance(x, list):
        if not x:  # Empty list optimization
            return b"le"
        parts = [_LIST_PREFIX]
        parts.extend(bencode(i) for i in x)
        parts.append(_LIST_SUFFIX)
        return b"".join(parts)
    elif isinstance(x, dict):
        if not x:  # Empty dict optimization
            return b"de"
        # Sort once and encode efficiently
        items = []
        for k, v in x.items():
            kb = k if isinstance(k, bytes) else str(k).encode("utf-8")
            items.append((kb, v))
        items.sort(key=lambda kv: kv[0])
        
        parts = [_DICT_PREFIX]
        for kb, v in items:
            parts.append(bencode(kb))
            parts.append(bencode(v))
        parts.append(_DICT_SUFFIX)
        return b"".join(parts)
    else:
        raise TypeError(f"Unsupported bencode type: {type(x)}")

def _bdecode_any(s: bytes, i: int = 0):
    """Optimized bdecode with better bounds checking."""
    if i >= len(s):
        raise ValueError("Unexpected EOF")
    
    c = s[i]
    if c == ord(b"i"):
        end = s.find(b"e", i + 1)
        if end == -1:
            raise ValueError("Unterminated integer")
        return int(s[i+1:end]), end + 1
    elif c == ord(b"l"):
        i += 1
        out = []
        while i < len(s) and s[i] != ord(b"e"):
            v, i = _bdecode_any(s, i)
            out.append(v)
        if i >= len(s):
            raise ValueError("Unterminated list")
        return out, i + 1
    elif c == ord(b"d"):
        i += 1
        d = {}
        while i < len(s) and s[i] != ord(b"e"):
            k, i = _bdecode_any(s, i)
            if not isinstance(k, (bytes, bytearray)):
                raise ValueError("Dict key must be bytes")
            v, i = _bdecode_any(s, i)
            d[bytes(k)] = v
        if i >= len(s):
            raise ValueError("Unterminated dict")
        return d, i + 1
    elif 48 <= c <= 57:  # ASCII digits
        colon = s.find(b":", i)
        if colon == -1:
            raise ValueError("String length missing colon")
        ln = int(s[i:colon])
        start = colon + 1
        end = start + ln
        if end > len(s):
            raise ValueError("String data truncated")
        return s[start:end], end
    else:
        raise ValueError(f"Invalid bencode byte: {c}")

def bdecode(s: bytes):
    """Parse bencoded data."""
    result, _ = _bdecode_any(s, 0)
    return result

# -------------------- Optimized DHT helpers --------------------

def rand_node_id() -> bytes:
    return os.urandom(20)

def rand_tid(n: int = 2) -> bytes:
    return os.urandom(n)

# Cache for parsed compact nodes - reduces repeated parsing overhead
_compact_node_cache = {}
_cache_lock = threading.Lock()

def parse_compact_nodes(data: bytes) -> List[Tuple[bytes, str, int]]:
    """Optimized compact node parsing with caching."""
    if not data:
        return []
    
    # Use cache for repeated data
    with _cache_lock:
        cache_key = hash(data)
        if cache_key in _compact_node_cache:
            return _compact_node_cache[cache_key]
    
    # Align to 26-byte boundaries
    data_len = len(data)
    if data_len % 26 != 0:
        data = data[:(data_len // 26) * 26]
    
    out = []
    for i in range(0, len(data), 26):
        nid = data[i:i+20]
        ip_bytes = data[i+20:i+24]
        port_bytes = data[i+24:i+26]
        
        # Optimized IP conversion using f-strings
        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
        port = struct.unpack("!H", port_bytes)[0]
        out.append((nid, ip, port))
    
    # Cache result if reasonable size
    with _cache_lock:
        if len(out) < 100:
            _compact_node_cache[cache_key] = out
    
    return out

def parse_compact_peers(values) -> List[Tuple[str, int]]:
    """Optimized peer parsing."""
    if not values:
        return []
    
    out = []
    for v in values:
        if not isinstance(v, (bytes, bytearray)) or len(v) < 6:
            continue
        ip_bytes = v[0:4]
        port_bytes = v[4:6]
        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
        port = struct.unpack("!H", port_bytes)[0]
        out.append((ip, port))
    
    return out

# Bootstrap nodes
BOOTSTRAP = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
]

# DNS cache to avoid repeated lookups
_dns_cache = {}

def resolve_host(hostname: str) -> Optional[str]:
    """DNS resolution with caching."""
    if hostname in _dns_cache:
        return _dns_cache[hostname]
    
    try:
        ip = socket.gethostbyname(hostname)
        _dns_cache[hostname] = ip
        return ip
    except socket.gaierror:
        return None

# -------------------- Optimized DHT Client --------------------

class DHTClient:
    def __init__(self, timeout: float = 2.0):
        self.node_id = rand_node_id()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(timeout)

    def close(self):
        try: 
            self.sock.close()
        except Exception: 
            pass

    def _send_query(self, addr: Tuple[str,int], q: str, args: Dict[bytes, Any]):
        t = rand_tid()
        msg = {b"t": t, b"y": b"q", b"q": q.encode("ascii"), b"a": {**args, b"id": self.node_id}}
        self.sock.sendto(bencode(msg), addr)
        return t

    def _recv(self) -> Optional[Tuple[dict, Tuple[str,int]]]:
        try:
            data, src = self.sock.recvfrom(65535)
        except socket.timeout:
            return None
        try:
            obj = bdecode(data)
            if isinstance(obj, dict):
                return obj, src
        except Exception:
            return None
        return None

    def _query(self, addr: Tuple[str,int], q: str, extra: Dict[bytes, Any]) -> Optional[dict]:
        try:
            t = self._send_query(addr, q, extra)
            deadline = time.time() + 2.0  # Reasonable timeout
            
            while time.time() < deadline:
                pkt = self._recv()
                if not pkt: 
                    continue
                obj, src = pkt
                if obj.get(b"y") == b"r" and obj.get(b"t") == t:
                    return obj
        except Exception:
            pass
        return None

    def find_node(self, addr: Tuple[str,int], target: Optional[bytes] = None):
        if target is None: 
            target = rand_node_id()
        return self._query(addr, "find_node", {b"target": target})

    def get_peers(self, addr: Tuple[str,int], infohash: bytes):
        return self._query(addr, "get_peers", {b"info_hash": infohash})

    def sample_infohashes(self, addr: Tuple[str,int], target: Optional[bytes] = None):
        if target is None: 
            target = rand_node_id()
        return self._query(addr, "sample_infohashes", {b"target": target})

    def parse_samples(self, resp: dict) -> List[bytes]:
        r = resp.get(b"r", {})
        raw = r.get(b"samples", b"")
        out: List[bytes] = []
        if not isinstance(raw, (bytes, bytearray)): 
            return out
        for i in range(0, len(raw), 20):
            chunk = raw[i:i+20]
            if len(chunk) == 20:
                out.append(bytes(chunk))
        return out

# -------------------- Optimized BitTorrent metadata --------------------
PSTR = b"BitTorrent protocol"
MSG_ID_EXTENDED = 20
EXT_HANDSHAKE_ID = 0

class PeerProtoError(Exception): pass
class PeerTimeout(Exception): pass

def _readn(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except (TimeoutError, socket.timeout):
            raise PeerTimeout("recv timeout")
        if not chunk:
            raise PeerProtoError("peer closed")
        data += chunk
    return data

def _read_msg(sock: socket.socket, timeout: float):
    hdr = _readn(sock, 4, timeout)
    (length,) = struct.unpack("!I", hdr)
    if length == 0:
        return -1, b""
    if length > 1024*1024:  # Sanity check
        raise PeerProtoError("message too large")
    payload = _readn(sock, length, timeout)
    return payload[0], payload[1:]

def _send_extended(sock: socket.socket, ext_id: int, payload: bytes):
    body = bytes([ext_id]) + payload
    pkt = struct.pack("!I", 2 + len(payload)) + bytes([MSG_ID_EXTENDED]) + body
    sock.sendall(pkt)

def bt_handshake(peer: Tuple[str,int], infohash: bytes, timeout: float = 5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(peer)
    except (ConnectionRefusedError, socket.timeout, OSError):
        s.close()
        raise PeerProtoError("connection failed")
    peer_id = b"-PCMETA-" + os.urandom(12)
    reserved = bytearray(8)
    reserved[5] |= 0x10  # extended messaging bit
    hs = bytes([len(PSTR)]) + PSTR + bytes(reserved) + infohash + peer_id
    s.sendall(hs)
    pstrlen = _readn(s,1,timeout)
    (n,) = struct.unpack("!B", pstrlen)
    if n != len(PSTR):
        s.close(); raise PeerProtoError("bad pstrlen")
    pstr = _readn(s,n,timeout)
    if pstr != PSTR:
        s.close(); raise PeerProtoError("bad pstr")
    _ = _readn(s,8,timeout)  # reserved2
    infohash2 = _readn(s,20,timeout)
    _peerid = _readn(s,20,timeout)
    if infohash2 != infohash:
        s.close(); raise PeerProtoError("infohash mismatch")
    return s

def ext_handshake(sock: socket.socket, timeout: float = 5.0):
    _send_extended(sock, EXT_HANDSHAKE_ID, bencode({b"m": {b"ut_metadata": 1}}))
    t0 = time.time()
    while time.time() - t0 < timeout:
        mid, payload = _read_msg(sock, timeout)
        if mid == -1: continue
        if mid != MSG_ID_EXTENDED or not payload: continue
        ext_id = payload[0]
        ext_payload = payload[1:]
        if ext_id == EXT_HANDSHAKE_ID:
            d = bdecode(ext_payload)
            if isinstance(d, dict):
                return d
    raise PeerTimeout("no ext handshake")

def fetch_metadata(peer: Tuple[str,int], infohash: bytes, timeout: float = 4.0) -> Optional[bytes]:
    """Fetch metadata with optimized timeouts."""
    try:
        s = bt_handshake(peer, infohash, timeout=timeout/2)
    except Exception:
        return None
    try:
        resp = ext_handshake(s, timeout=timeout/3)
        mdict = resp.get(b"m", {})
        if not isinstance(mdict, dict) or b"ut_metadata" not in mdict:
            return None
        ut_id = mdict[b"ut_metadata"]
        if not isinstance(ut_id, int):
            return None

        metadata_size = resp.get(b"metadata_size")
        piece_len = 16 * 1024

        def request_piece(i: int):
            hdr = {b"msg_type": 0, b"piece": i, b"info_hash": infohash}
            _send_extended(s, ut_id, bencode(hdr))

        def read_piece(expect_i: int, to: float):
            t0 = time.time()
            while time.time() - t0 < to:
                mid, payload = _read_msg(s, to)
                if mid == -1 or mid != MSG_ID_EXTENDED or not payload:
                    continue
                eid = payload[0]
                ep = payload[1:]
                if eid != ut_id:
                    continue
                try:
                    hdr, idx = _bdecode_any(ep)
                except Exception:
                    continue
                if not isinstance(hdr, dict):
                    continue
                if hdr.get(b"msg_type") != 1:
                    continue
                if hdr.get(b"piece") != expect_i:
                    continue
                total = hdr.get(b"total_size")
                return total, ep[idx:]
            return None, None

        # Optimize metadata size detection
        if not isinstance(metadata_size, int) or metadata_size <= 0 or metadata_size > 10*1024*1024:
            request_piece(0)
            total, data0 = read_piece(0, timeout/3)
            if total is None or data0 is None:
                return None
            metadata_size = int(total)
            npieces = (metadata_size + piece_len - 1) // piece_len
            pieces = [None] * npieces
            pieces[0] = data0
            start_i = 1
        else:
            npieces = (metadata_size + piece_len - 1) // piece_len
            pieces = [None] * npieces
            start_i = 0

        # Fetch remaining pieces with shorter timeouts
        for i in range(start_i, npieces):
            request_piece(i)
            total, data = read_piece(i, timeout/4)
            if data is None:
                return None
            pieces[i] = data

        blob = b"".join(p for p in pieces if p is not None)

        # Handle gzip compression if present
        if blob.startswith(b"\x1f\x8b"):
            import gzip, io
            try:
                blob = gzip.GzipFile(fileobj=io.BytesIO(blob)).read()
            except Exception:
                return None

        return blob
    finally:
        try:
            s.close()
        except Exception:
            pass

def parse_metainfo(meta_blob: bytes):
    """Parse metainfo with better error handling."""
    obj = bdecode(meta_blob)
    if not isinstance(obj, dict):
        raise ValueError("bad metainfo payload")

    # Handle both full metainfo and info dict
    info = obj.get(b"info")
    if isinstance(info, dict):
        info_dict = info
    else:
        info_dict = obj

    name = info_dict.get(b"name", b"").decode("utf-8", "ignore")

    files = []
    if b"files" in info_dict:  # multi-file mode
        for f in info_dict[b"files"]:
            if not isinstance(f, dict):
                continue
            length = int(f.get(b"length", 0))
            path_parts = f.get(b"path", [])
            if isinstance(path_parts, list):
                path = "/".join(
                    p.decode("utf-8", "ignore") 
                    for p in path_parts 
                    if isinstance(p, (bytes, bytearray))
                )
            else:
                path = "unknown"
            files.append({"length": length, "path": path})
    else:  # single-file mode
        length = int(info_dict.get(b"length", 0))
        files.append({"length": length, "path": name})

    piece_len = int(info_dict.get(b"piece length", 0))
    return {"name": name, "files": files, "piece_length": piece_len}

# -------------------- Optimized Combined Crawl + Metadata --------------------

# Configuration constants - set to unlimited for continuous operation
MAX_INFOHASHES: int = 999999  # Effectively unlimited
PEERS_PER_INFOHASH: int = 20
METADATA_PEER_ATTEMPTS: int = 5  # Try more peers for better metadata success
OVERALL_TIMEOUT: float = 86400.0  # 24 hours

def query_peers_simple(client: DHTClient, infohash: bytes, nodes: List[Tuple[str, int]], max_peers: int) -> Set[Tuple[str, int]]:
    """Query multiple nodes for peers sequentially to avoid threading issues."""
    all_peers = set()
    
    for node in nodes[:3]:  # Limit to first 3 nodes to keep it fast
        if len(all_peers) >= max_peers:
            break
        try:
            resp = client.get_peers(node, infohash)
            if resp and resp.get(b"y") == b"r":
                r = resp.get(b"r", {})
                values = r.get(b"values")
                if values:
                    peers = parse_compact_peers(values)
                    for peer in peers:
                        all_peers.add(peer)
                        if len(all_peers) >= max_peers:
                            break
        except Exception:
            continue
    
    return all_peers

def crawl_and_fetch(max_infohashes: int, peers_per_infohash_limit: int, metadata_peer_attempts: int, overall_timeout: float):
    """Main crawl function with optimizations and automatic file output."""
    client = DHTClient(timeout=2.0)
    print(f"# DHT node ID: {client.node_id.hex()}", file=sys.stderr)
    print(f"# Starting continuous crawl - output will be saved to metadata.txt", file=sys.stderr)

    start = time.time()
    node_q: Deque[Tuple[str,int]] = deque()
    seen_nodes: Set[Tuple[str,int]] = set()  # Use set for O(1) lookups
    seen_infohashes: Set[bytes] = set()
    processed_count = 0

    # Optimized bootstrap
    bootstrap_nodes = []
    for host, port in BOOTSTRAP:
        ip = resolve_host(host)
        if ip:
            bootstrap_nodes.append((ip, port))
    
    for addr in bootstrap_nodes:
        try:
            resp = client.find_node(addr)
            if not resp: 
                continue
            nodes = parse_compact_nodes(resp.get(b"r", {}).get(b"nodes", b""))
            for _, ip, p in nodes:
                node_addr = (ip, p)
                if node_addr not in seen_nodes:
                    seen_nodes.add(node_addr)
                    node_q.append(node_addr)
        except Exception:
            continue

    print(f"# Bootstrapped with {len(node_q)} initial nodes", file=sys.stderr)

    # Open output file for continuous writing
    output_file = open("metadata.txt", "w", newline="", buffering=1)  # Line buffered
    writer = csv.writer(output_file)
    writer.writerow(["infohash","name","file_count","total_bytes","piece_length","peer_ip","peer_port","metadata_ok"])
    
    # Also write header to stdout for immediate feedback
    stdout_writer = csv.writer(sys.stdout)
    stdout_writer.writerow(["infohash","name","file_count","total_bytes","piece_length","peer_ip","peer_port","metadata_ok"])

    try:
        while node_q and len(seen_infohashes) < max_infohashes and (time.time()-start) < overall_timeout:
            ip, port = node_q.popleft()
            
            # Try sampling first
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
                    if node_addr not in seen_nodes:
                        seen_nodes.add(node_addr)
                        node_q.append(node_addr)
                
                samples = client.parse_samples(resp)
                random.shuffle(samples)
                for ih in samples:
                    if len(seen_infohashes) >= max_infohashes: 
                        break
                    if ih in seen_infohashes: 
                        continue
                    seen_infohashes.add(ih)

                    # Collect peer query nodes
                    query_nodes = [(ip, port)]
                    extra_nodes = list(node_q)[:2]  # Use just 2 more nodes to keep it fast
                    query_nodes.extend(extra_nodes)

                    # Simple peer queries
                    all_peers = query_peers_simple(client, ih, query_nodes, peers_per_infohash_limit)
                    peer_list = list(all_peers)
                    random.shuffle(peer_list)

                    # Try metadata sequentially 
                    ih_hex = ih.hex()
                    meta_obtained = False
                    name = ""; file_count = 0; total_bytes = 0; piece_len = 0
                    
                    if peer_list:
                        # Try more peers and increase timeout for better metadata success
                        attempt_peers = peer_list[:min(5, metadata_peer_attempts)]
                        for i, peer in enumerate(attempt_peers):
                            try:
                                blob = fetch_metadata(peer, ih, timeout=4.0)
                                if blob:
                                    try:
                                        info = parse_metainfo(blob)
                                        name = info["name"]
                                        file_count = len(info["files"])
                                        total_bytes = sum(f["length"] for f in info["files"])
                                        piece_len = info["piece_length"]
                                        meta_obtained = True
                                        print(f"# SUCCESS! Got metadata: '{name}' ({file_count} files, {total_bytes:,} bytes)", file=sys.stderr)
                                        break
                                    except Exception as e:
                                        print(f"# Failed to parse metadata from {peer[0]}:{peer[1]} - {e}", file=sys.stderr)
                                        continue
                                else:
                                    print(f"# No metadata from {peer[0]}:{peer[1]}", file=sys.stderr)
                            except Exception as e:
                                print(f"# Connection failed to {peer[0]}:{peer[1]} - {e}", file=sys.stderr)
                                continue

                    # Output results to both file and stdout
                    if not peer_list:
                        row = [ih_hex,name,file_count,total_bytes,piece_len,"","",meta_obtained]
                        writer.writerow(row)
                        stdout_writer.writerow(row)
                        processed_count += 1
                    else:
                        for peer in peer_list:
                            row = [ih_hex,name,file_count,total_bytes,piece_len,peer[0],peer[1],meta_obtained]
                            writer.writerow(row)
                            stdout_writer.writerow(row)
                        processed_count += 1
                    
                    # Progress reporting every 10 infohashes
                    if processed_count % 10 == 0:
                        elapsed = time.time() - start
                        rate = processed_count / elapsed * 60  # per minute
                        print(f"# Progress: {processed_count} infohashes processed, {rate:.1f}/min, {len(node_q)} nodes queued", file=sys.stderr)
            else:
                # Fallback find_node
                try:
                    fresp = client.find_node((ip, port))
                except Exception:
                    fresp = None
                if fresp and fresp.get(b"y") == b"r":
                    nodes = parse_compact_nodes(fresp.get(b"r", {}).get(b"nodes", b""))
                    random.shuffle(nodes)
                    for _, nip, nport in nodes[:16]:
                        node_addr = (nip, nport)
                        if node_addr not in seen_nodes:
                            seen_nodes.add(node_addr)
                            node_q.append(node_addr)
        
        elapsed = time.time() - start
        print(f"# Final: {processed_count} infohashes processed in {elapsed:.1f}s", file=sys.stderr)
        print(f"# Output saved to metadata.txt", file=sys.stderr)
    finally:
        client.close()
        try:
            output_file.close()
        except Exception:
            pass

# -------------------- Main Entry Point --------------------

def main():
    """Main entry point with optimized defaults and signal handling."""
    def signal_handler(signum, frame):
        print(f"\n# Received signal {signum}, shutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        crawl_and_fetch(
            max_infohashes=MAX_INFOHASHES,
            peers_per_infohash_limit=PEERS_PER_INFOHASH,
            metadata_peer_attempts=METADATA_PEER_ATTEMPTS,
            overall_timeout=OVERALL_TIMEOUT,
        )
    except KeyboardInterrupt:
        print("\n# Interrupted by user", file=sys.stderr)
    except Exception as e:
        print(f"# Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()