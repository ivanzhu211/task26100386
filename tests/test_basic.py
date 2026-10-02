"""PE32/PE32+ name and ordinal imports, cross-section objects."""

from __future__ import annotations

from pe_imports import Status, extract_imports

from conftest import (
    NULL_DESCRIPTOR,
    build_pe,
    descriptor,
    name_record,
    thunks32,
    thunks64,
)


def test_pe32_name_imports_with_offsets():
    # Section .s0: RVA 0x1000-0x1100 -> file 0x200-0x300.
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0x1060) + NULL_DESCRIPTOR
    sec[0x40:0x4C] = thunks32([0x10A0, 0x10FC, 0])  # OriginalFirstThunk
    sec[0x80:0x8E] = b"kernel32.dll\0"
    sec[0xA0:0xA8] = name_record(7, b"Exit")  # 2 + 4 + 1 = 7 bytes, pad 1
    # Cross-section name record: starts at 0x10FC, 4 bytes in .s0, rest in .s1.
    sec[0xFC:0x100] = name_record(9, b"ReadFile")[:4]
    tail = name_record(9, b"ReadFile")[4:]  # 7 bytes land in .s1 at RVA 0x1100
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[
            (0x1000, 0x100, 0x200, bytes(sec)),
            (0x1100, 0x100, 0x400, tail + b"\0" * (0x100 - len(tail))),
        ],
    )
    res = extract_imports(data)
    assert res.pe_format == "PE32"
    assert res.complete, res.issues
    assert len(res.dlls) == 1
    dll = res.dlls[0]
    assert dll.name == "kernel32.dll"
    assert dll.name_status is Status.COMPLETE
    assert dll.thunks_complete
    # DLL name evidence: file offset 0x280, 13 bytes.
    assert [(f.file_offset, f.data) for f in dll.name_evidence] == [
        (0x280, b"kernel32.dll\0")
    ]
    assert dll.descriptor_evidence[0].file_offset == 0x200
    assert len(dll.functions) == 2

    fn0 = dll.functions[0]
    assert fn0.status is Status.COMPLETE
    assert fn0.name == "Exit" and fn0.hint == 7 and fn0.ordinal is None
    # Thunk at RVA 0x1040 -> file 0x240; name record at 0x10A0 -> file 0x2A0.
    offsets = [f.file_offset for f in fn0.evidence]
    assert offsets == [0x240, 0x2A0]
    assert fn0.evidence[0].data == (0x10A0).to_bytes(4, "little")
    assert fn0.evidence[1].data == name_record(7, b"Exit")

    fn1 = dll.functions[1]
    assert fn1.status is Status.COMPLETE
    assert fn1.name == "ReadFile" and fn1.hint == 9
    # Cross-section evidence: thunk frag, then 4 bytes at 0x2FC, then 7 at 0x400.
    frags = [(f.file_offset, f.data) for f in fn1.evidence]
    assert frags == [
        (0x244, (0x10FC).to_bytes(4, "little")),
        (0x2FC, name_record(9, b"ReadFile")[:4]),
        (0x400, name_record(9, b"ReadFile")[4:]),
    ]


def test_pe32plus_ordinal_and_name_imports():
    sec = bytearray(0x200)
    sec[0x00:0x28] = descriptor(0x1100, 0x1180, 0) + NULL_DESCRIPTOR
    sec[0x100:0x118] = thunks64(
        [0x8000000000000007, 0x8000000000001234, 0x11A0, 0]
    )
    sec[0x180:0x18A] = b"ntdll.dll\0"
    sec[0x1A0:0x1AC] = name_record(0, b"NtClose") + b"\0" * 4
    data = build_pe(
        plus=True,
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x200, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert res.pe_format == "PE32+"
    assert res.complete, res.issues
    dll = res.dlls[0]
    assert dll.name == "ntdll.dll"
    assert len(dll.functions) == 3
    f0, f1, f2 = dll.functions
    assert f0.ordinal == 7 and f0.name is None
    assert f0.status is Status.COMPLETE
    assert f1.ordinal == 0x1234
    # Thunk width is 8 for PE32+.
    assert f0.evidence[0].data == (0x8000000000000007).to_bytes(8, "little")
    assert f2.name == "NtClose" and f2.hint == 0
    assert f2.status is Status.COMPLETE


def test_first_thunk_fallback_when_oft_zero():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0, 0x1080, 0x1040) + NULL_DESCRIPTOR
    sec[0x40:0x48] = thunks32([0x80000042, 0])
    sec[0x80:0x86] = b"a.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert res.complete, res.issues
    dll = res.dlls[0]
    assert [f.ordinal for f in dll.functions] == [0x42]


def test_duplicate_imports_not_merged():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR
    sec[0x40:0x4C] = thunks32([0x10A0, 0x10A0, 0])
    sec[0x80:0x86] = b"b.dll\0"
    sec[0xA0:0xA8] = name_record(1, b"Dup") + b"\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    assert res.complete, res.issues
    assert len(res.dlls[0].functions) == 2
    assert all(f.name == "Dup" for f in res.dlls[0].functions)


def test_reserved_ordinal_bits_flagged():
    sec = bytearray(0x100)
    sec[0x00:0x28] = descriptor(0x1040, 0x1080, 0) + NULL_DESCRIPTOR
    sec[0x40:0x48] = thunks32([0x80010007, 0])
    sec[0x80:0x86] = b"c.dll\0"
    data = build_pe(
        import_rva=0x1000,
        import_size=40,
        sections=[(0x1000, 0x100, 0x200, bytes(sec))],
    )
    res = extract_imports(data)
    fn = res.dlls[0].functions[0]
    assert fn.ordinal == 7
    assert any("reserved" in i for i in fn.issues)
    assert not res.complete
