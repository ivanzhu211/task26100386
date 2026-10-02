"""PE32+: 8-byte thunks, OriginalFirstThunk preference, duplicates kept."""

from __future__ import annotations

import struct

from pe_import_forensics import Status, extract

from conftest import build_pe, descriptor


def make_sample() -> bytes:
    overlays = [
        # descriptor + null descriptor at RVA 0x1000 (file 0x200)
        (0x200, descriptor(oft=0x1030, name_rva=0x10A0, ft=0x1080)),
        (0x214, b"\x00" * 20),
        # OFT thunk table at RVA 0x1030 (file 0x230), 8-byte entries:
        # ReadFile, ReadFile (duplicate), ordinal 16, terminator
        (
            0x230,
            struct.pack(
                "<QQQQ", 0x1050, 0x1050, 0x8000000000000010, 0
            ),
        ),
        # hint/name at RVA 0x1050 (file 0x250)
        (0x250, struct.pack("<H", 0x12) + b"ReadFile\x00"),
        # FirstThunk table at RVA 0x1080 (file 0x280): must be ignored
        # because OriginalFirstThunk is nonzero
        (0x280, struct.pack("<Q", 0)),
        # DLL name at RVA 0x10A0 (file 0x2A0)
        (0x2A0, b"USER32.dll\x00"),
    ]
    return build_pe(
        is_plus=True,
        sections=[
            {"name": ".rdata", "va": 0x1000, "vsize": 0x200,
             "rawptr": 0x200, "rawsize": 0x200},
        ],
        overlays=overlays,
        import_rva=0x1000,
        import_size=0x28,
    )


def test_pe32plus_thunks_oft_preference_and_duplicates():
    result = extract(make_sample())
    assert result.status is Status.COMPLETE
    assert result.is_pe32_plus
    assert len(result.dlls) == 1

    dll = result.dlls[0]
    assert dll.dll_name == b"USER32.dll"
    assert [(f.file_offset, f.length) for f in dll.evidence.fragments] == [
        (0x200, 20)
    ]
    assert [
        (f.file_offset, f.length) for f in dll.dll_name_evidence.fragments
    ] == [(0x2A0, 11)]

    # duplicate name entries are preserved, not merged
    assert len(dll.functions) == 3
    first, second, third = dll.functions
    assert first.name == b"ReadFile" and first.hint == 0x12
    assert second.name == b"ReadFile" and second.hint == 0x12
    assert first is not second
    assert [(f.file_offset, f.length) for f in first.evidence.fragments] == [
        (0x230, 8)
    ]
    assert [(f.file_offset, f.length) for f in second.evidence.fragments] == [
        (0x238, 8)
    ]
    assert [
        (f.file_offset, f.length) for f in first.name_evidence.fragments
    ] == [(0x250, 2), (0x252, 9)]

    assert third.ordinal == 16
    assert third.name is None
    assert [(f.file_offset, f.length) for f in third.evidence.fragments] == [
        (0x240, 8)
    ]
