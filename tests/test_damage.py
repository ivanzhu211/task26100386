"""Damage containment: partial evidence must survive corrupt neighbours."""

from __future__ import annotations

from pe_imports import Status, extract_imports

from conftest import (
    NULL_DESCRIPTOR,
    build_pe,
    descriptor,
    name_record,
    thunks32,
)


def test_bad_name_between_good_entries():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR
    # Middle thunk points at an unmapped RVA -> bad name record.
    sec[0x40:0x4C] = thunks32([0x10A0, 0x9000, 0x10B0, 0])
    sec[0x80:0x86] = b"x.dll\0"
    sec[0xA0:0xA8] = name_record(1, b"Good1") + b"\0" * 2
    sec[0xB0:0xB8] = name_record(2, b"Good2") + b"\0" * 2
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert not res.complete
    dll = res.dlls[0]
    assert dll.thunks_complete  # zero terminator still reached
    assert len(dll.functions) == 3
    good1, bad, good2 = dll.functions
    assert good1.status is Status.COMPLETE and good1.name == "Good1"
    assert bad.status is Status.UNREADABLE and bad.name is None
    assert bad.thunk_rva == 0x1044
    # Thunk bytes of the bad entry are still preserved as evidence.
    assert bad.evidence[0].data == (0x9000).to_bytes(4, "little")
    assert good2.status is Status.COMPLETE and good2.name == "Good2"


def test_bad_thunk_table_between_good_dlls():
    sec = bytearray(0x100)
    sec[0x00:0x3C] = (
        descriptor(0x1080, 0x10A0, 0)
        + descriptor(0x9000, 0x10B0, 0)  # thunk table in unmapped RVA
        + descriptor(0x10C0, 0x10E0, 0)
    )
    sec[0x3C:0x60] = NULL_DESCRIPTOR + b"\0" * 4
    sec[0x80:0x88] = thunks32([0x80000001, 0])
    sec[0xA0:0xA6] = b"one.dll\0"
    sec[0xB0:0xB6] = b"two.dll\0"
    sec[0xC0:0xC8] = thunks32([0x80000003, 0])
    sec[0xE0:0xE8] = b"three.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=60,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert not res.complete
    assert len(res.dlls) == 3
    one, two, three = res.dlls
    assert one.thunks_complete and [f.ordinal for f in one.functions] == [1]
    assert two.name == "two.dll"  # bad thunk table did not hide the DLL name
    assert not two.thunks_complete and two.functions == []
    assert any("unreadable" in i for i in two.issues)
    assert three.thunks_complete and [f.ordinal for f in three.functions] == [3]


def test_bad_dll_name_does_not_block_thunks():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x9000, 0) + NULL_DESCRIPTOR
    sec[0x40:0x48] = thunks32([0x8000000A, 0])
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert not res.complete
    dll = res.dlls[0]
    assert dll.name is None and dll.name_status is Status.UNREADABLE
    assert dll.thunks_complete
    assert [f.ordinal for f in dll.functions] == [0xA]


def test_unreadable_descriptor_stops_table_keeps_prior():
    sec = bytearray(0x40)
    sec[0x00:0x14] = descriptor(0x1040, 0x1050, 0)
    # The file is truncated inside the second descriptor (file 0x214..0x228),
    # so the descriptor table stops there and keeps the first DLL's evidence.
    sec[0x14:0x28] = descriptor(0x9000, 0x9000, 0)
    sec[0x28:0x40] = NULL_DESCRIPTOR + b"\0" * 4
    sec2 = bytearray(0x20)
    sec2[0x00:0x08] = thunks32([0x80000005, 0])
    sec2[0x10:0x16] = b"y.dll\0"
    # .s1 raw data sits before .s0 in the file so truncation only cuts .s0.
    data = build_pe(
        import_rva=0x1000,
        import_size=60,
        sections=[
            (0x1000, 0x40, 0x240, bytes(sec)),
            (0x1040, 0x20, 0x200, bytes(sec2)),
        ],
        truncate_to=0x25C,  # cut 8 bytes into the second descriptor
    )
    res = extract_imports(data)
    assert not res.complete
    assert len(res.dlls) == 1
    assert res.dlls[0].thunks_complete
    assert [f.ordinal for f in res.dlls[0].functions] == [5]
    assert res.dlls[0].name == "y.dll"
    assert any("descriptor table stopped" in i for i in res.issues)


def test_descriptor_unreadable_mid_table():
    # Only one descriptor fits in mapped memory; the next 20 bytes are a gap.
    sec = bytearray(0x14)
    sec[0x00:0x14] = descriptor(0x1040, 0x1050, 0)
    sec2 = bytearray(0x20)
    sec2[0x00:0x08] = thunks32([0x80000009, 0])
    sec2[0x10:0x16] = b"y.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=60,
        sections=[
            (0x1000, 0x14, 0x200, bytes(sec)),
            (0x1040, 0x20, 0x220, bytes(sec2)),
        ],
    )
    res = extract_imports(data)
    assert not res.complete
    assert len(res.dlls) == 1
    assert res.dlls[0].name == "y.dll"
    assert [f.ordinal for f in res.dlls[0].functions] == [9]
    assert any("descriptor table stopped" in i for i in res.issues)


def test_directory_boundary_without_terminator():
    sec = bytearray(0x28)
    sec[0x00:0x14] = descriptor(0x1040, 0x1080, 0)
    sec[0x14:0x28] = descriptor(0x1040, 0x1080, 0)  # no null descriptor
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x40, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert not res.complete
    assert len(res.dlls) == 2
    assert any("without null descriptor" in i for i in res.issues)


def test_directory_boundary_trailing_bytes():
    sec = bytearray(0x40)
    sec[0x00:0x14] = descriptor(0x1028, 0x1030, 0)
    sec[0x14:0x28] = NULL_DESCRIPTOR
    sec[0x28:0x30] = thunks32([0x80000001, 0])
    sec[0x30:0x36] = b"q.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=0x2C,  # null descriptor terminates before the boundary
        sections=[(0x1000, 0x40, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert res.complete, res.issues
    # Now shrink the size so only 8 bytes remain after the first descriptor.
    data2 = build_pe(
        import_rva=0x1000,
        import_size=0x1C,
        sections=[(0x1000, 0x40, 0x200, bytes(sec))],
    )
    res2 = extract_imports(data2)
    assert not res2.complete
    assert any("trailing" in i for i in res2.issues)


def test_ambiguous_mapping_yields_no_bytes():
    # Two sections cover the same RVA range, pointing at the same file bytes.
    raw = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR + b"\0" * 0x18
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[
            (0x1000, 0x40, 0x200, raw),
            (0x1000, 0x40, 0x200, raw),
        ],
    )
    res = extract_imports(data)
    assert not res.complete
    assert res.dlls == []
    assert any("ambiguous" in i for i in res.issues)


def test_zero_fill_is_not_real_bytes():
    # Thunk table RVA falls into the zero-fill part of a section
    # (VirtualSize > SizeOfRawData). Virtual zeros must not terminate it.
    sec = bytearray(0x40)
    sec[0x00:0x28] = descriptor(0x1080, 0x1030, 0) + NULL_DESCRIPTOR
    sec[0x30:0x36] = b"z.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x200, 0x200, bytes(sec))],  # 0x40 raw, 0x200 vsize
    )
    res = extract_imports(data)
    assert not res.complete
    dll = res.dlls[0]
    assert dll.name == "z.dll"
    assert not dll.thunks_complete
    assert dll.functions == []
    assert any("unreadable" in i for i in dll.issues)


def test_section_beyond_32bit_excluded():
    sec = bytearray(0x28)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[
            (0x1000, 0x40, 0x200, bytes(sec)),
            (0xFFFFF000, 0x2000, 0x300, b"\0" * 0x10),  # wraps past 2^32
        ],
    )
    res = extract_imports(data)
    assert any("exceeds 32-bit" in i for i in res.issues)
    # The good section still resolves; only the anomaly is recorded.
    assert len(res.dlls) == 1


def test_truncated_file_mid_descriptor():
    sec = bytearray(0x40)
    sec[0x00:0x14] = descriptor(0x1040, 0x1080, 0)
    sec[0x14:0x28] = NULL_DESCRIPTOR
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x40, 0x200, bytes(sec))],
        truncate_to=0x218,  # cut 8 bytes into the null descriptor
    )
    res = extract_imports(data)
    assert not res.complete
    assert len(res.dlls) == 1
    assert any("descriptor table stopped" in i for i in res.issues)


def test_non_ascii_name_rejected():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR
    sec[0x40:0x48] = thunks32([0x10A0, 0])
    sec[0x80:0x88] = b"n.dll\0" + b"\0" * 2
    sec[0xA0:0xA8] = name_record(3, b"Bad\xffName")
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert not res.complete
    fn = res.dlls[0].functions[0]
    assert fn.name is None and fn.hint == 3
    assert fn.status is Status.PARTIAL
    assert any("ASCII" in i for i in fn.issues)


def test_no_import_directory():
    data = build_pe(import_rva=0, import_size=0)
    res = extract_imports(data)
    assert res.complete
    assert res.dlls == []


def test_not_a_pe():
    res = extract_imports(b"\x00" * 16)
    assert not res.complete
    assert res.dlls == []
    assert res.issues
