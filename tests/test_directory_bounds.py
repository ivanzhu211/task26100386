"""Import directory Size bound and PE32+ hint/name RVA validation."""

from __future__ import annotations

import struct

from pe_import_forensics import Status, extract

from conftest import build_pe, descriptor


def _single_dll_overlays() -> list[tuple[int, bytes]]:
    return [
        (0x400, descriptor(oft=0, name_rva=0x2040, ft=0x2028)),
        (0x428, struct.pack("<II", 0x2060, 0)),
        (0x440, b"ONE.dll\x00"),
        (0x460, struct.pack("<H", 1) + b"GoodA\x00"),
    ]


def _sections() -> list[dict]:
    return [
        {"name": ".rdata", "va": 0x2000, "vsize": 0x200,
         "rawptr": 0x400, "rawsize": 0x200},
    ]


def test_boundary_leftover_bytes_marked_unfinished():
    # Size leaves 8 bytes after the first descriptor: not enough for
    # another descriptor, and no null terminator was seen
    image = build_pe(
        sections=_sections(),
        overlays=_single_dll_overlays(),
        import_rva=0x2000,
        import_size=20 + 8,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    assert len(result.dlls) == 1
    assert result.dlls[0].status is Status.COMPLETE
    assert any("short of a descriptor" in a for a in result.anomalies)


def test_missing_terminator_at_boundary():
    # Size covers exactly one descriptor, no null descriptor inside
    image = build_pe(
        sections=_sections(),
        overlays=_single_dll_overlays(),
        import_rva=0x2000,
        import_size=20,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    assert len(result.dlls) == 1
    assert any("without a null descriptor" in a for a in result.anomalies)


def test_names_and_thunks_not_limited_by_directory_size():
    # Size covers only the descriptors, but the thunk table and names
    # live far beyond it and must still be parsed
    image = build_pe(
        sections=_sections(),
        overlays=_single_dll_overlays() + [(0x414, b"\x00" * 20)],
        import_rva=0x2000,
        import_size=0x28,
    )
    result = extract(image)
    assert result.status is Status.COMPLETE
    dll = result.dlls[0]
    assert dll.dll_name == b"ONE.dll"
    assert [f.name for f in dll.functions] == [b"GoodA"]


def test_pe32plus_non_32bit_hint_name_rva():
    overlays = [
        (0x200, descriptor(oft=0, name_rva=0x1040, ft=0x1028)),
        (0x214, b"\x00" * 20),
        # first thunk: hint/name RVA above 4 GiB; second: valid ordinal
        (0x228, struct.pack("<QQ", 0x1_0000_1234, 0x8000000000000007)),
        (0x240, b"X.dll\x00"),
    ]
    image = build_pe(
        is_plus=True,
        sections=[
            {"name": ".rdata", "va": 0x1000, "vsize": 0x100,
             "rawptr": 0x200, "rawsize": 0x100},
        ],
        overlays=overlays,
        import_rva=0x1000,
        import_size=0x28,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    dll = result.dlls[0]
    assert dll.functions[0].status is Status.UNREADABLE
    assert dll.functions[0].name is None
    # the bad entry must not kill the following ordinal import
    assert dll.functions[1].ordinal == 7
    assert any("32-bit RVA" in a for a in result.anomalies)
