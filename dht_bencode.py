# dht_bencode.py
from typing import Tuple, Any, Union

def bencode(x: Any) -> bytes:
    """
    Encode Python objects into BitTorrent bencode.
    Supported types: int, bytes, str, list, dict (with str/bytes keys).
    """
    if isinstance(x, int):
        return b"i" + str(x).encode("ascii") + b"e"
    if isinstance(x, bytes):
        return str(len(x)).encode("ascii") + b":" + x
    if isinstance(x, str):
        b = x.encode("utf-8")
        return str(len(b)).encode("ascii") + b":" + b
    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    if isinstance(x, dict):
        # Keys must be bytes in sorted order per bencode rules.
        # We'll accept str keys and utf-8 encode them.
        items = []
        for k, v in x.items():
            kb = k if isinstance(k, bytes) else str(k).encode("utf-8")
            items.append((kb, v))
        items.sort(key=lambda kv: kv[0])
        out = [b"d"]
        for kb, v in items:
            out.append(bencode(kb))
            out.append(bencode(v))
        out.append(b"e")
        return b"".join(out)
    raise TypeError(f"Unsupported type for bencode: {type(x)}")


def _bdecode_any(s: bytes, i: int = 0) -> Tuple[Any, int]:
    """
    Internal: decode one bencoded item starting at index i.
    Returns (obj, next_index).
    """
    if i >= len(s):
        raise ValueError("Unexpected end of data")

    c = s[i:i+1]
    if c == b"i":  # integer: i<digits>e
        j = s.index(b"e", i + 1)
        num = int(s[i+1:j])
        return num, j + 1

    if c == b"l":  # list: l ... e
        i += 1
        lst = []
        while s[i:i+1] != b"e":
            item, i = _bdecode_any(s, i)
            lst.append(item)
        return lst, i + 1

    if c == b"d":  # dict: d ... e
        i += 1
        d = {}
        while s[i:i+1] != b"e":
            key, i = _bdecode_any(s, i)
            if not isinstance(key, (bytes, bytearray)):
                raise ValueError("Dictionary key must be bytes in bencode")
            val, i = _bdecode_any(s, i)
            d[bytes(key)] = val
        return d, i + 1

    if c.isdigit():  # string: <len>:<bytes>
        # parse length
        colon = s.index(b":", i)
        length = int(s[i:colon])
        start = colon + 1
        end = start + length
        if end > len(s):
            raise ValueError("String length exceeds data")
        return s[start:end], end

    raise ValueError(f"Invalid bencode at position {i}: byte {c!r}")


def bdecode(s: Union[bytes, bytearray, memoryview]) -> Tuple[Any, int]:
    """
    Decode a single bencoded object from the start of s.
    Returns (obj, next_index). If you expect exactly one object in s,
    next_index should equal len(s).
    """
    obj, idx = _bdecode_any(bytes(s), 0)
    return obj, idx


if __name__ == "__main__":
    # Quick self-test (round-trips)
    samples = [
        0,
        42,
        b"hello",
        "héllo",  # utf-8
        [1, "two", b"three"],
        {b"y": 1, "x": "str", "k": [b"a", 2]},
    ]

    def _normalize_expected(x: Any) -> Any:
        """Recursively convert any str to UTF-8 bytes, and dict keys to bytes, matching decoder output.

        The decoder always yields bytes for bencoded 'string' primitives (including dict keys). Our samples
        include Python str values/keys for convenience. To compare round-trips we transform the original
        object structure into the shape produced by the decoder.
        """
        if isinstance(x, str):
            return x.encode("utf-8")
        if isinstance(x, bytes):
            return x
        if isinstance(x, int):
            return x
        if isinstance(x, list):
            return [_normalize_expected(i) for i in x]
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                kb = k if isinstance(k, bytes) else str(k).encode("utf-8")
                out[kb] = _normalize_expected(v)
            return out
        return x
    for obj in samples:
        enc = bencode(obj)
        dec, n = bdecode(enc)
        expected = _normalize_expected(obj)
        assert dec == expected and n == len(enc), f"Round-trip mismatch. original={obj!r} expected={expected!r} got={dec!r}"
    print("bencode/bdecode round-trip OK")
