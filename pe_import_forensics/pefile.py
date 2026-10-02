"""Minimal PE/COFF header parsing (PE32 and PE32+)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

UINT32_SPACE = 1 << 32


class PeFormatError(Exception):
    """The file is too damaged to locate the import directory."""


@dataclass
class Section:
    name: bytes
    virtual_address: int
    virtual_size: int
    size_of_raw_data: int
    pointer_to_raw_data: int


@dataclass
class PeHeaders:
    is_pe32_plus: bool
    size_of_headers: int
    import_directory_rva: int
    import_directory_size: int
    sections: list[Section] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise PeFormatError(f"truncated u16 at file offset {off:#x}")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise PeFormatError(f"truncated u32 at file offset {off:#x}")
    return struct.unpack_from("<I", data, off)[0]


def parse_headers(data: bytes) -> PeHeaders:
    """Parse DOS/COFF/optional headers and the section table."""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise PeFormatError("missing MZ signature")
    pe_off = _u32(data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise PeFormatError("missing PE signature")

    coff = pe_off + 4
    number_of_sections = _u16(data, coff + 2)
    size_of_optional = _u16(data, coff + 16)
    opt = coff + 20
    if opt + size_of_optional > len(data):
        raise PeFormatError("truncated optional header")

    magic = _u16(data, opt)
    if magic == 0x10B:
        is_pe32_plus = False
        dir_base = opt + 96
    elif magic == 0x20B:
        is_pe32_plus = True
        dir_base = opt + 112
    else:
        raise PeFormatError(f"unknown optional header magic {magic:#x}")
    if dir_base + 16 > opt + size_of_optional:
        raise PeFormatError("optional header has no import directory")

    size_of_headers = _u32(data, opt + 60)
    import_rva = _u32(data, dir_base + 8)
    import_size = _u32(data, dir_base + 12)

    headers = PeHeaders(
        is_pe32_plus=is_pe32_plus,
        size_of_headers=size_of_headers,
        import_directory_rva=import_rva,
        import_directory_size=import_size,
    )

    sec_off = opt + size_of_optional
    for index in range(number_of_sections):
        base = sec_off + index * 40
        if base + 40 > len(data):
            headers.anomalies.append(
                f"section table truncated at entry {index}"
            )
            break
        name = data[base:base + 8].split(b"\x00", 1)[0]
        virtual_size = _u32(data, base + 8)
        virtual_address = _u32(data, base + 12)
        size_of_raw = _u32(data, base + 16)
        raw_ptr = _u32(data, base + 20)
        span = max(virtual_size, size_of_raw)
        if virtual_address + span > UINT32_SPACE:
            headers.anomalies.append(
                f"section {name!r} exceeds 32-bit address space; excluded"
            )
            continue
        headers.sections.append(
            Section(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                size_of_raw_data=size_of_raw,
                pointer_to_raw_data=raw_ptr,
            )
        )
    return headers
