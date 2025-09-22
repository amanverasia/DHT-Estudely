# bt_metadata.py
import socket, struct, time, os
from typing import Optional, Tuple, Dict, Any, List
from dht_bencode import bencode, bdecode

# --- BitTorrent message helpers -------------------------------------------
PSTR = b"BitTorrent protocol"
PSTRLEN = len(PSTR)

# Extended messaging (BEP-10)
MSG_ID_CHOKE         = 0
MSG_ID_UNCHOKE       = 1
MSG_ID_INTERESTED    = 2
MSG_ID_NOT_INTERESTED= 3
MSG_ID_HAVE          = 4
MSG_ID_BITFIELD      = 5
MSG_ID_REQUEST       = 6
MSG_ID_PIECE         = 7
MSG_ID_CANCEL        = 8
MSG_ID_PORT          = 9
MSG_ID_EXTENDED      = 20  # BEP-10

EXT_HANDSHAKE_ID     = 0   # ext msg id for the "extended handshake"

class PeerTimeout(Exception): ...
class PeerProtoError(Exception): ...

def _readn(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise PeerProtoError("peer closed")
        buf += chunk
    return buf

def _read_msg(sock: socket.socket, timeout: float) -> Tuple[int, bytes]:
    """
    Returns (msg_id, payload). For extended messages, msg_id==MSG_ID_EXTENDED,
    payload: first byte is ext_msg_id, rest is ext payload.
    """
    # 4-byte length prefix
    data = _readn(sock, 4, timeout)
    (length,) = struct.unpack("!I", data)
    if length == 0:
        # keep-alive
        return -1, b""
    # read that many bytes
    payload = _readn(sock, length, timeout)
    msg_id = payload[0]
    return msg_id, payload[1:]

def _send_msg(sock: socket.socket, msg_id: int, payload: bytes = b"") -> None:
    data = struct.pack("!I", 1 + len(payload)) + bytes([msg_id]) + payload
    sock.sendall(data)

def _send_extended(sock: socket.socket, ext_id: int, payload: bytes) -> None:
    # extended base ID (20) + one byte ext id + bencoded payload
    body = bytes([ext_id]) + payload
    data = struct.pack("!I", 2 + len(payload)) + bytes([MSG_ID_EXTENDED]) + body
    sock.sendall(data)

def bt_handshake(peer: Tuple[str, int], infohash: bytes, my_peer_id: Optional[bytes] = None, timeout: float = 5.0) -> socket.socket:
    """
    Perform the base BT handshake. Returns a connected socket ready for messages.
    """
    if my_peer_id is None:
        my_peer_id = b"-PC0001-" + os.urandom(12)  # 20 bytes total

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(peer)

    # Build handshake
    reserved = bytearray(8)
    # enable extended messaging bit (BEP-10): bit 20 (from msb) -> 0x0000000000100000
    # In network order, set the 6th byte's 0x10 (counting from 0)
    reserved[5] |= 0x10
    hs = bytes([PSTRLEN]) + PSTR + bytes(reserved) + infohash + my_peer_id
    s.sendall(hs)

    # Read handshake
    pstrlen = _readn(s, 1, timeout)
    (n,) = struct.unpack("!B", pstrlen)
    if n != PSTRLEN:
        s.close()
        raise PeerProtoError("bad pstrlen")
    pstr = _readn(s, n, timeout)
    if pstr != PSTR:
        s.close()
        raise PeerProtoError("bad pstr")
    reserved2 = _readn(s, 8, timeout)
    infohash2 = _readn(s, 20, timeout)
    _peer_id = _readn(s, 20, timeout)

    if infohash2 != infohash:
        s.close()
        raise PeerProtoError("infohash mismatch")

    return s

def ext_handshake(sock: socket.socket, timeout: float = 5.0) -> Dict[bytes, Any]:
    """
    Send/receive the extended handshake to discover ut_metadata and its size.
    Returns the decoded dict from the peer's ext handshake response.
    """
    # Send our ext handshake first (minimal)
    my = {b"m": {b"ut_metadata": 1}}
    _send_extended(sock, EXT_HANDSHAKE_ID, bencode(my))

    # Read messages until we get ext handshake response or timeout
    t0 = time.time()
    while time.time() - t0 < timeout:
        msg_id, payload = _read_msg(sock, timeout)
        if msg_id == -1:  # keep-alive
            continue
        if msg_id != MSG_ID_EXTENDED:
            # ignore non-extended msgs for this mini fetcher
            continue
        if not payload:
            continue
        ext_id = payload[0]
        ext_payload = payload[1:]
        if ext_id == EXT_HANDSHAKE_ID:
            # This is the peer's ext handshake
            d, _ = bdecode(ext_payload)
            return d
        # else: other extended messages, ignore for now
    raise PeerTimeout("no extended handshake received")

def fetch_metadata(peer: Tuple[str, int], infohash: bytes, timeout: float = 8.0) -> Optional[bytes]:
    """
    Returns the raw bencoded metainfo (bytes) or None on failure.
    """
    try:
        s = bt_handshake(peer, infohash, timeout=timeout)
    except Exception:
        return None

    try:
        # Extended handshake
        resp = ext_handshake(s, timeout=timeout)
        mdict = resp.get(b"m", {})
        if not isinstance(mdict, dict) or b"ut_metadata" not in mdict:
            return None
        ut_metadata_id = mdict[b"ut_metadata"]
        if not isinstance(ut_metadata_id, int):
            return None

        metadata_size = resp.get(b"metadata_size")
        if not isinstance(metadata_size, int) or metadata_size <= 0 or metadata_size > (10 * 1024 * 1024):
            # ignore absurd sizes; many torrents are < 2MB of metadata
            return None

        piece_len = 16 * 1024
        num_pieces = (metadata_size + piece_len - 1) // piece_len
        pieces = [None] * num_pieces

        # Request each piece
        for i in range(num_pieces):
            req = {b"msg_type": 0, b"piece": i}  # 0=request
            _send_extended(s, ut_metadata_id, bencode(req))

            # Read until we get the right extended msg with piece i, or time out
            t0 = time.time()
            got_piece = False
            while time.time() - t0 < timeout:
                msg_id, payload = _read_msg(s, timeout)
                if msg_id == -1:
                    continue
                if msg_id != MSG_ID_EXTENDED or not payload:
                    continue
                ext_id = payload[0]
                ext_payload = payload[1:]
                if ext_id != ut_metadata_id:
                    # some other ext message
                    continue
                # metadata message: header (bencoded dict) + piece bytes
                # Format per BEP-9: bencode(dict) + b"piece data"
                # We don’t have a delimiter, so parse dict first, then remainder is data
                try:
                    hdr, idx = bdecode(ext_payload)
                except Exception:
                    continue
                if not isinstance(hdr, dict):
                    continue
                if hdr.get(b"msg_type") != 1:  # 1 = data
                    continue
                piece_index = hdr.get(b"piece")
                if piece_index != i:
                    continue
                piece_data = ext_payload[idx:]
                pieces[i] = piece_data
                got_piece = True
                break

            if not got_piece:
                # Try to continue, but if many pieces fail, bail
                return None

        # Reassemble
        blob = b"".join(p for p in pieces if p is not None)
        if len(blob) != metadata_size:
            # Some peers pad the last piece; often still decodes fine
            pass

        # The raw blob should itself be a bencoded "metainfo" dict
        return blob
    finally:
        try:
            s.close()
        except Exception:
            pass

def parse_metainfo(meta_blob: bytes) -> Dict[str, Any]:
    """
    Returns a friendly dict: name, files (path, length), piece_len, infohash (derived), etc.
    """
    obj, _ = bdecode(meta_blob)
    if not isinstance(obj, dict):
        raise ValueError("bad metainfo")

    # metainfo structure: { 'announce'?, 'info': {...}, 'created by'?, ... }
    info = obj.get(b"info", {})
    name = info.get(b"name", b"").decode("utf-8", "ignore")

    files: List[Dict[str, Any]] = []
    if b"files" in info:  # multi-file mode
        for f in info[b"files"]:
            length = f.get(b"length", 0)
            path = b"/".join(p for p in f.get(b"path", []) if isinstance(p, (bytes, bytearray)))
            files.append({"length": int(length), "path": path.decode("utf-8", "ignore")})
    else:
        length = int(info.get(b"length", 0))
        files.append({"length": length, "path": name})

    piece_len = int(info.get(b"piece length", 0))
    return {
        "name": name,
        "files": files,
        "piece_length": piece_len,
    }
