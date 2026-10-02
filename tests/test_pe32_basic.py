"""PE32: name and ordinal imports, cross-section objects, exact offsets."""

from __future__ import annotations

import struct

from pe_import_forensics import Status, extract

from conftest import build_pe, descriptor


def make_sample() -> bytes:
    overlays = [
        # import descriptor + null descriptor (RVA 0x2000 -> file 0x400)
        (0x400, descriptor(oft=0, name_rva=0x2040, ft=0x2028)),
        (0x414, b"\x00" * 20),
        # thunk table at RVA 0x2028 (file 0x428)
        (0x428, struct.pack("<IIII", 0x2080, 0x80000042, 0x20FC, 0)),
        # DLL name at RVA 0x2040 (file 0x440)
        (0x440, b"KERNEL32.dll\x00"),
        # hint/name at RVA 0x2080 (file 0x480)
        (0x480, struct.pack("<H", 5) + b"FuncA\x00"),
        # cross-section hint/name at RVA 0x20FC (file 0x4FC), name
        # continues at RVA 0x2100 (file 0x600)
        (0x4FC, struct.pack("<H", 7) + b"Bi"),
        (0x600, b"gFn\x00"),
    ]
    return build_pe(
        sections=[
            {"name": ".text", "va": 0x1000, "vsize": 0x100,
             "rawptr": 0x200, "rawsize": 0x100},
            {"name": ".rdata", "va": 0x2000, "vsize": 0x100,
             "rawptr": 0x400, "rawsize": 0x100},
            {"name": ".idata", "va": 0x2100, "vsize": 0x100,
             "rawptr": 0x600, "rawsize": 0x100},
        ],
        overlays=overlays,
        import_rva=0x2000,
        import_size=0x28,
    )


def test_pe32_name_ordinal_and_cross_section():
    result = extract(make_sample())
    assert result.status is Status.COMPLETE
    assert not result.is_pe32_plus
    assert len(result.dlls) == 1

    dll = result.dlls[0]
    assert dll.status is Status.COMPLETE
    assert dll.dll_name == b"KERNEL32.dll"
    assert [(f.file_offset, f.length) for f in dll.evidence.fragments] == [
        (0x400, 20)
    ]
    assert [(f.file_offset, f.length) for f in dll.dll_name_evidence.fragments] == [
        (0x440, 13)
    ]

    assert len(dll.functions) == 3

    func_a = dll.functions[0]
    assert func_a.status is Status.COMPLETE
    assert func_a.name == b"FuncA"
    assert func_a.hint == 5
    assert func_a.ordinal is None
    assert [(f.file_offset, f.length) for f in func_a.evidence.fragments] == [
        (0x428, 4)
    ]
    assert [
        (f.file_offset, f.length) for f in func_a.name_evidence.fragments
    ] == [(0x480, 2), (0x482, 6)]

    ordinal = dll.functions[1]
    assert ordinal.status is Status.COMPLETE
    assert ordinal.ordinal == 0x42
    assert ordinal.name is None
    assert [(f.file_offset, f.length) for f in ordinal.evidence.fragments] == [
        (0x42C, 4)
    ]

    cross = dll.functions[2]
    assert cross.status is Status.COMPLETE
    assert cross.name == b"BigFn"
    assert cross.hint == 7
    assert [(f.file_offset, f.length) for f in cross.evidence.fragments] == [
        (0x430, 4)
    ]
    # object spans two file locations: all fragments preserved
    assert [
        (f.file_offset, f.length) for f in cross.name_evidence.fragments
    ] == [(0x4FC, 2), (0x4FE, 2), (0x600, 4)]
