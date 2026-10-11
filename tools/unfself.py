#!/usr/bin/env python3
"""Unwrap plaintext PS5 FSELF containers into clean PS5 ELF executables.

Container geometry (0x20-byte header + 0x20-byte segment entries + ELF header
table + packed segment data + version records) follows the publicly documented
PS4/PS5 plaintext-SELF layout used by homebrew packagers; the constants below
were verified against container bytes directly.

PROVENANCE NOTE: an earlier scratch implementation of this session was derived
from GPL-3.0 code in mihawk-99/PS5_RetroArch (tooling/native/self_container.cpp).
This file was rewritten from the observed container structure and from AnyPS5's
own ELF consumption (GPL-2.0). If a stricter provenance is required, treat this
file as documentation-adjacent and have a maintainer re-derive it.
"""
import struct
import sys
import zlib

MAGICS = {0xEEF51454, 0x1D3D154F}
PT_VERSION_RECORDS = 0x6FFFFF01


def extract(data: bytes) -> bytes:
    magic, = struct.unpack_from("<I", data, 0)
    if magic not in MAGICS:
        raise ValueError(f"not a plaintext FSELF container (magic {magic:#x})")
    segment_count, = struct.unpack_from("<H", data, 0x18)
    table_end = 0x20 + segment_count * 0x20
    segments = [struct.unpack_from("<QQQQ", data, 0x20 + i * 0x20) for i in range(segment_count)]

    program_count, = struct.unpack_from("<H", data, table_end + 0x38)
    headers = data[table_end: table_end + 0x40 + program_count * 0x38]
    phdrs = []
    output_size = len(headers)
    for i in range(program_count):
        at = 0x40 + i * 0x38
        p_type, _flags, p_off, _va, _pa, p_filesz, _msz = struct.unpack_from("<IIQQQQQ", headers, at)
        phdrs.append((p_type, p_off, p_filesz))
        output_size = max(output_size, p_off + p_filesz)

    output = bytearray(output_size)
    blocked = compressed = plain = 0
    for flags, foff, fsize, _msz in segments:
        if not flags & 0x800:  # only "blocked" entries carry data
            continue
        if flags & 0x2:
            raise ValueError("encrypted segment; cannot extract")
        seg_id = (flags >> 20) & 0xFFFF
        if seg_id >= program_count:
            continue
        _pt, p_off, p_filesz = phdrs[seg_id]
        stored = data[foff: foff + fsize]
        if flags & 0x8:
            try:
                payload = zlib.decompress(stored)
            except zlib.error:
                payload = zlib.decompressobj(-15).decompress(stored)
            if len(payload) != p_filesz:
                raise ValueError(f"segment {seg_id}: inflated {len(payload)} != {p_filesz}")
            compressed += 1
        else:
            payload = stored
            plain += 1
        n = min(len(payload), p_filesz)
        output[p_off: p_off + n] = payload[:n]
        blocked += 1

    for p_type, p_off, p_filesz in phdrs:  # version records follow the last segment
        if p_type == PT_VERSION_RECORDS and p_filesz:
            tail = max((foff + fsize for _fl, foff, fsize, _m in segments), default=0)
            output[p_off: p_off + p_filesz] = data[tail: tail + p_filesz]

    output[0: len(headers)] = headers
    e_type, = struct.unpack_from("<H", output, 16)
    print(f"    container: {len(data)} B, {segment_count} entries "
          f"({blocked} blocked: {plain} plain, {compressed} inflated), elf {len(output)} B, type {e_type:#x}")
    return bytes(output)


if __name__ == "__main__":
    out = extract(open(sys.argv[1], "rb").read())
    open(sys.argv[2], "wb").write(out)
