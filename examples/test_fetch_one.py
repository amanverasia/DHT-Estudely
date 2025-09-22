
from bt_metadata import fetch_metadata, parse_metainfo

ih_hex = "87a1e5787d6521268aa2b5045137a298f609cade"
peer = ("120.230.163.151", 25925)

blob = fetch_metadata(peer, bytes.fromhex(ih_hex))
if not blob:
    print("no metadata (peer offline or not supporting ut_metadata)")
else:
    meta = parse_metainfo(blob)
    print("Name:", meta["name"])
    print("Files:")
    for f in meta["files"][:10]:
        print("  ", f["length"], f["path"])
