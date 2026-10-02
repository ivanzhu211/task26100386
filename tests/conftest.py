"""Helpers to build synthetic PE images with exact byte layouts."""

from __future__ import annotations

import struct


def build_pe(
    *,
    plus: bool = False,
    sections: list[tuple[int, int, int, bytes]] = (),
    import_rva: int = 0,
    import_size: int = 0,
    size_of_headers: int = 0x200,
    e_lfanew: int = 0x80,
    truncate_to: int | None = None,
) -> bytes:
    """Build a PE image.

    sections: (virtual_address, virtual_size, raw_pointer, raw_bytes).
    SizeOfRawData is len(raw_bytes); virtual_size may exceed it (zero-fill).
    """
    num = len(sections)
    opt_size = 0xF0 if plus else 0xE0
    size = max(e_lfanew + 24 + opt_size + num * 40, size_of_headers)
    for _, _, raw_ptr, raw in sections:
        size = max(size, raw_ptr + len(raw))
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, 0x14C)  # Machine
    struct.pack_into("<H", buf, e_lfanew + 6, num)
    struct.pack_into("<H", buf, e_lfanew + 20, opt_size)
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x20B if plus else 0x10B)
    struct.pack_into("<I", buf, opt + 60, size_of_headers)
    struct.pack_into("<I", buf, opt + (108 if plus else 92), 16)
    dd = opt + (112 if plus else 96)
    struct.pack_into("<II", buf, dd + 8, import_rva, import_size)
    for i, (vaddr, vsize, raw_ptr, raw) in enumerate(sections):
        base = opt + opt_size + i * 40
        buf[base : base + 8] = f".s{i}".encode().ljust(8, b"\0")
        struct.pack_into("<IIII", buf, base + 8, vsize, vaddr, len(raw), raw_ptr)
        buf[raw_ptr : raw_ptr + len(raw)] = raw
    data = bytes(buf)
    if truncate_to is not None:
        data = data[:truncate_to]
    return data


def name_record(hint: int, name: bytes) -> bytes:
    return struct.pack("<H", hint) + name + b"\0"


def descriptor(oft: int, name_rva: int, ft: int) -> bytes:
    return struct.pack("<IIIII", oft, 0, 0, name_rva, ft)


NULL_DESCRIPTOR = b"\0" * 20


def thunks32(values: list[int]) -> bytes:
    return b"".join(struct.pack("<I", v) for v in values)


def thunks64(values: list[int]) -> bytes:
    return b"".join(struct.pack("<Q", v) for v in values)
