"""Damage stays local: bad name between good entries, bad thunk table
between good DLLs, unreadable descriptor stops only its own table."""

from __future__ import annotations

import struct

from pe_import_forensics import Status, extract

from conftest import build_pe, descriptor


def test_bad_name_between_good_entries():
    overlays = [
        (0x400, descriptor(oft=0, name_rva=0x2040, ft=0x2028)),
        (0x414, b"\x00" * 20),
        # thunks: good name, dangling name RVA, good name, terminator
        (0x428, struct.pack("<IIII", 0x2080, 0x2FFC, 0x20A0, 0)),
        (0x440, b"KERNEL32.dll\x00"),
        (0x480, struct.pack("<H", 1) + b"GoodA\x00"),
        (0x4A0, struct.pack("<H", 2) + b"GoodB\x00"),
    ]
    image = build_pe(
        sections=[
            {"name": ".rdata", "va": 0x2000, "vsize": 0x200,
             "rawptr": 0x400, "rawsize": 0x200},
        ],
        overlays=overlays,
        import_rva=0x2000,
        import_size=0x28,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    assert len(result.dlls) == 1
    dll = result.dlls[0]
    assert dll.status is Status.PARTIAL
    assert dll.dll_name == b"KERNEL32.dll"

    # the broken entry must not swallow the entries after it
    assert len(dll.functions) == 3
    assert dll.functions[0].name == b"GoodA"
    assert dll.functions[0].status is Status.COMPLETE
    bad = dll.functions[1]
    assert bad.status is Status.UNREADABLE
    assert bad.name is None
    # thunk entry itself is still traceable evidence
    assert [(f.file_offset, f.length) for f in bad.evidence.fragments] == [
        (0x42C, 4)
    ]
    assert dll.functions[2].name == b"GoodB"
    assert dll.functions[2].status is Status.COMPLETE


def test_bad_thunk_table_between_good_dlls():
    overlays = [
        (0x400, descriptor(oft=0, name_rva=0x2060, ft=0x2050)),
        (0x414, descriptor(oft=0, name_rva=0x2070, ft=0x2FFC)),
        (0x428, descriptor(oft=0, name_rva=0x2080, ft=0x2058)),
        (0x43C, b"\x00" * 20),
        (0x450, struct.pack("<II", 0x20A0, 0)),
        (0x458, struct.pack("<II", 0x20B0, 0)),
        (0x460, b"ONE.dll\x00"),
        (0x470, b"TWO.dll\x00"),
        (0x480, b"THREE.dll\x00"),
        (0x4A0, struct.pack("<H", 1) + b"GoodA\x00"),
        (0x4B0, struct.pack("<H", 3) + b"GoodC\x00"),
    ]
    image = build_pe(
        sections=[
            {"name": ".rdata", "va": 0x2000, "vsize": 0x200,
             "rawptr": 0x400, "rawsize": 0x200},
        ],
        overlays=overlays,
        import_rva=0x2000,
        import_size=0x50,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    assert len(result.dlls) == 3

    one, two, three = result.dlls
    assert one.dll_name == b"ONE.dll"
    assert one.status is Status.COMPLETE
    assert [f.name for f in one.functions] == [b"GoodA"]

    # middle DLL: name readable, thunk table dangling -> partial
    assert two.dll_name == b"TWO.dll"
    assert two.status is Status.PARTIAL
    assert two.functions == []

    # the broken thunk table must not stop later descriptors
    assert three.dll_name == b"THREE.dll"
    assert three.status is Status.COMPLETE
    assert [f.name for f in three.functions] == [b"GoodC"]


def test_unreadable_descriptor_stops_table_but_keeps_evidence():
    overlays = [
        (0x400, descriptor(oft=0, name_rva=0x2100, ft=0x2110)),
        (0x600, b"ONE.dll\x00"),
        (0x610, struct.pack("<II", 0x2120, 0)),
        (0x620, struct.pack("<H", 1) + b"GoodA\x00"),
        # second descriptor would sit at RVA 0x2014, inside the mapping
        # gap between .rdata (ends 0x2014) and .idata (starts 0x2100)
    ]
    image = build_pe(
        sections=[
            {"name": ".rdata", "va": 0x2000, "vsize": 0x14,
             "rawptr": 0x400, "rawsize": 0x14},
            {"name": ".idata", "va": 0x2100, "vsize": 0x100,
             "rawptr": 0x600, "rawsize": 0x100},
        ],
        overlays=overlays,
        import_rva=0x2000,
        import_size=0x100,
    )
    result = extract(image)
    assert result.status is Status.PARTIAL
    assert len(result.dlls) == 1
    dll = result.dlls[0]
    assert dll.status is Status.COMPLETE
    assert dll.dll_name == b"ONE.dll"
    assert [f.name for f in dll.functions] == [b"GoodA"]
    assert any("unreadable" in a for a in result.anomalies)
