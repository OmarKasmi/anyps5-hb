#!/usr/bin/env python3
"""Sony NID computation, mirroring AnyPS5's core/libs/nid/src/NidCompute.cpp (GPL-2.0).

NID = base64ish(SHA1(name + fixed_suffix)[:8] reversed), 11 chars.
Used to name missing imports by brute-matching against public NID databases.
"""
import hashlib

SUFFIX = bytes([0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1,
                0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30])
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"


def compute_nid(name: str) -> str:
    digest = hashlib.sha1(name.encode() + SUFFIX).digest()
    rev = digest[:8][::-1]
    out = []
    for i in range(0, 6, 3):
        t = (rev[i] << 16) | (rev[i + 1] << 8) | rev[i + 2]
        out += [B64[(t >> 18) & 63], B64[(t >> 12) & 63], B64[(t >> 6) & 63], B64[t & 63]]
    tail = (rev[6] << 16) | (rev[7] << 8)
    out += [B64[(tail >> 18) & 63], B64[(tail >> 12) & 63], B64[(tail >> 6) & 63]]
    return "".join(out)


def load_name_db(path: str) -> dict:
    """aerolib.csv: 'NID name' per line -> {nid: name}."""
    db = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split(" ", 1)
            if len(parts) == 2 and len(parts[0]) == 11:
                db[parts[0]] = parts[1]
    return db
