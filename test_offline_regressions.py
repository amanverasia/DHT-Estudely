#!/usr/bin/env python3
import unittest

from bt_metadata import parse_metainfo
from dht_bencode import bencode
from dht_collect_and_metadata import DHTClient as CombinedDHTClient
from dht_krpc import DHTClient


class ParseMetainfoTests(unittest.TestCase):
    def test_parse_metainfo_accepts_bare_info_dict(self):
        blob = bencode({
            b"name": b"test.bin",
            b"length": 12,
            b"piece length": 16384,
        })

        meta = parse_metainfo(blob)

        self.assertEqual(meta["name"], "test.bin")
        self.assertEqual(meta["piece_length"], 16384)
        self.assertEqual(meta["files"], [{"length": 12, "path": "test.bin"}])

    def test_parse_metainfo_accepts_wrapped_metainfo(self):
        blob = bencode({
            b"info": {
                b"name": b"folder",
                b"piece length": 32768,
                b"files": [
                    {b"length": 5, b"path": [b"a.txt"]},
                    {b"length": 7, b"path": [b"sub", b"b.txt"]},
                ],
            }
        })

        meta = parse_metainfo(blob)

        self.assertEqual(meta["name"], "folder")
        self.assertEqual(meta["piece_length"], 32768)
        self.assertEqual(
            meta["files"],
            [
                {"length": 5, "path": "a.txt"},
                {"length": 7, "path": "sub/b.txt"},
            ],
        )


class DHTResponseSourceTests(unittest.TestCase):
    def _assert_filters_wrong_sender(self, client_cls):
        client = object.__new__(client_cls)
        packets = iter([
            ({b"y": b"r", b"t": b"aa", b"r": {b"id": b"x" * 20}}, ("203.0.113.10", 9999)),
            ({b"y": b"r", b"t": b"aa", b"r": {b"id": b"y" * 20}}, ("198.51.100.5", 6881)),
        ])
        client._send_query = lambda addr, q, args: b"aa"
        client._recv = lambda: next(packets, None)

        resp = client.find_node(("198.51.100.5", 6881), b"z" * 20)

        self.assertEqual(resp, {b"y": b"r", b"t": b"aa", b"r": {b"id": b"y" * 20}})

    def test_standalone_client_ignores_wrong_sender(self):
        self._assert_filters_wrong_sender(DHTClient)

    def test_combined_client_ignores_wrong_sender(self):
        self._assert_filters_wrong_sender(CombinedDHTClient)


if __name__ == "__main__":
    unittest.main()
