"""Mapping rules: ambiguity, zero-fill, truncation, 32-bit overflow."""

from __future__ import annotations

import struct

from pe_import_forensics import Status, extract
from pe_import_forensics.mapping import RvaMapper
from pe_import_forensics.pefile import parse_headers

from conftest import build_pe, descriptor


def mapper_for(image: bytes) -> RvaMapper:
    return RvaMapper(parse_headers(image), image)


def test_overlap_is_ambiguous_even_with_identical_bytes():
    # two sections covering the same RVA range and same file content
    overlays = [(0x400, b"ABCDEFGH"), (0x600, b"ABCDEFGH")]
    image = build_pe(
        sections=[
            {"name": ".a", "va": 0x1000, "vsize": 8,
             "rawptr": 0x400, "rawsize": 8},
            {"name": ".b", "va": 0x1000, "vsize": 8,
             "rawptr": 0x600, "rawsize": 8},
        ],
        overlays=overlays,
    )
    mapper = mapper_for(image)
    data, fragments, status = mapper.read(0x1000, 4)
    assert status == "unreadable"
    assert data == b""
    assert fragments == []


def test_header_and_section_overlap_is_ambiguous():
    # section raw data maps over the header range [0, SizeOfHeaders)
    image = build_pe(
        sections=[
            {"name": ".hdr", "va": 0x100, "vsize": 0x40,
             "rawptr": 0x100, "rawsize": 0x40},
        ],
        size_of_headers=0x200,
    )
    mapper = mapper_for(image)
    _, _, status = mapper.read(0x100, 4)
    assert status == "unreadable"
    # bytes outside the overlap stay readable
    data, _, status = mapper.read(0x140, 4)
    assert status == "complete"
    assert data == image[0x140:0x144]


def test_virtual_zero_fill_is_not_real_bytes():
    # VirtualSize > SizeOfRawData: tail is zero-fill, must not terminate
    # strings nor count as bytes
    image = build_pe(
        sections=[
            {"name": ".s", "va": 0x1000, "vsize": 0x100,
             "rawptr": 0x400, "rawsize": 0x10},
        ],
        overlays=[(0x400, b"ABCD"), (0x40E, b"YZ")],
        file_size=0x500,
    )
    mapper = mapper_for(image)
    data, fragments, status = mapper.read(0x1000, 0x20)
    assert status == "partial"
    # 0x10 real file bytes (file content happens to contain zeros),
    # then the zero-fill region stops the read
    assert data == b"ABCD" + bytes(10) + b"YZ"
    assert fragments == [(0x400, 0x10)]
    # a string running into the zero-fill region is not terminated by
    # it: the read stops as partial instead of seeing a NUL
    data, fragments, status = mapper.read_c_string(0x100E)
    assert status == "partial"
    assert data == b"YZ"
    # a string starting inside zero-fill has no bytes at all
    data, fragments, status = mapper.read_c_string(0x1010)
    assert status == "unreadable"
    assert data == b""


def test_file_truncation_yields_no_bytes():
    # section declares raw data past end of file
    image = build_pe(
        sections=[
            {"name": ".s", "va": 0x1000, "vsize": 0x100,
             "rawptr": 0x400, "rawsize": 0x100},
        ],
        overlays=[(0x400, b"XYZ")],
        file_size=0x403,
    )
    mapper = mapper_for(image)
    data, fragments, status = mapper.read(0x1000, 8)
    assert status == "partial"
    assert data == b"XYZ"
    assert fragments == [(0x400, 3)]


def test_section_beyond_32bit_space_is_anomaly_and_unmapped():
    image = build_pe(
        sections=[
            {"name": ".big", "va": 0xFFFFF000, "vsize": 0x2000,
             "rawptr": 0x400, "rawsize": 0x100},
            {"name": ".ok", "va": 0x1000, "vsize": 0x10,
             "rawptr": 0x600, "rawsize": 0x10},
        ],
        overlays=[(0x600, b"0123456789ABCDEF")],
    )
    headers = parse_headers(image)
    assert any("32-bit" in a for a in headers.anomalies)
    assert [s.name for s in headers.sections] == [b".ok"]
    mapper = RvaMapper(headers, image)
    _, _, status = mapper.read(0xFFFFF000, 4)
    assert status == "unreadable"
    data, _, status = mapper.read(0x1000, 4)
    assert status == "complete"
    assert data == b"0123"


def test_reserved_ordinal_bits_flagged_and_kept():
    overlays = [
        (0x400, descriptor(oft=0, name_rva=0x2040, ft=0x2028)),
        (0x414, b"\x00" * 20),
        (0x428, struct.pack("<II", 0x800F0042, 0)),
        (0x440, b"X.dll\x00"),
    ]
    image = build_pe(
        sections=[
            {"name": ".rdata", "va": 0x2000, "vsize": 0x100,
             "rawptr": 0x400, "rawsize": 0x100},
        ],
        overlays=overlays,
        import_rva=0x2000,
        import_size=0x28,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    func = result.dlls[0].functions[0]
    assert func.ordinal == 0x42
    assert any("reserved" in a for a in result.anomalies)
