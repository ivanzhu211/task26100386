"""Helpers to build synthetic in-memory PE images for tests."""

from __future__ import annotations

import struct

import pytest


def build_pe(
    *,
    is_plus: bool = False,
    sections: list[dict] = (),
    overlays: list[tuple[int, bytes]] = (),
    import_rva: int = 0,
    import_size: int = 0,
    size_of_headers: int = 0x200,
    file_size: int = 0x200,
) -> bytes:
    """Assemble a minimal PE file.

    ``sections`` items: {name, va, vsize, rawptr, rawsize}.
    ``overlays``: (file_offset, bytes) written after the headers, so
    tests can place import structures anywhere in the image.
    """
    opt_magic = 0x20B if is_plus else 0x10B
    opt_size = 0xF0 if is_plus else 0xE0
    pe_off = 0x80
    sec_table = pe_off + 4 + 20 + opt_size
    header_end = sec_table + 40 * len(sections)
    size = max(file_size, header_end)
    for off, blob in overlays:
        size = max(size, off + len(blob))
    image = bytearray(size)

    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_off)
    image[pe_off:pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    struct.pack_into("<H", image, coff + 0, 0x14C if not is_plus else 0x8664)
    struct.pack_into("<H", image, coff + 2, len(sections))
    struct.pack_into("<H", image, coff + 16, opt_size)

    opt = coff + 20
    struct.pack_into("<H", image, opt + 0, opt_magic)
    struct.pack_into("<I", image, opt + 60, size_of_headers)
    dir_base = opt + (112 if is_plus else 96)
    struct.pack_into("<I", image, dir_base + 8, import_rva)
    struct.pack_into("<I", image, dir_base + 12, import_size)

    for index, sec in enumerate(sections):
        base = sec_table + 40 * index
        name = sec["name"].encode()[:8].ljust(8, b"\x00")
        image[base:base + 8] = name
        struct.pack_into("<I", image, base + 8, sec["vsize"])
        struct.pack_into("<I", image, base + 12, sec["va"])
        struct.pack_into("<I", image, base + 16, sec["rawsize"])
        struct.pack_into("<I", image, base + 20, sec["rawptr"])

    for off, blob in overlays:
        image[off:off + len(blob)] = blob
    return bytes(image)


def descriptor(oft: int, name_rva: int, ft: int) -> bytes:
    return struct.pack("<IIIII", oft, 0, 0, name_rva, ft)


@pytest.fixture
def pe_factory():
    return build_pe
