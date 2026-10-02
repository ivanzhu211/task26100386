"""Import directory / descriptor / thunk parsing."""

from __future__ import annotations

import struct
from typing import Optional

from .mapping import RvaMapper
from .model import (
    Fragment,
    ImportForensics,
    ImportedDll,
    ImportedFunction,
    Status,
)

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_DESCRIPTOR_SIZE = 20
_MAX_DESCRIPTORS = 1 << 16
_MAX_THUNKS = 1 << 20
_MAX_STRING = 1 << 20
_UINT32_SPACE = 1 << 32


def _u16(data: bytes, off: int) -> Optional[int]:
    if off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> Optional[int]:
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


class _Header:
    def __init__(self) -> None:
        self.pe_format: Optional[str] = None
        self.size_of_headers = 0
        self.sections: list[tuple[int, int, int, int]] = []
        self.import_rva = 0
        self.import_size = 0


def _parse_header(data: bytes, result: ImportForensics) -> Optional[_Header]:
    hdr = _Header()
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew is None:
        result.issues.append("truncated DOS header: no e_lfanew")
        return None
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        result.issues.append("missing PE signature")
        return None
    num_sections = _u16(data, e_lfanew + 6)
    opt_size = _u16(data, e_lfanew + 20)
    if num_sections is None or opt_size is None:
        result.issues.append("truncated COFF header")
        return None
    opt_off = e_lfanew + 24
    magic = _u16(data, opt_off)
    if magic == _PE32_MAGIC:
        hdr.pe_format = "PE32"
        dd_base_off, num_dirs_off = 96, 92
    elif magic == _PE32PLUS_MAGIC:
        hdr.pe_format = "PE32+"
        dd_base_off, num_dirs_off = 112, 108
    else:
        result.issues.append(f"unknown optional header magic 0x{magic:x}")
        return None
    result.pe_format = hdr.pe_format
    size_of_headers = _u32(data, opt_off + 60)
    if size_of_headers is None:
        result.issues.append("truncated optional header: no SizeOfHeaders")
        return None
    hdr.size_of_headers = size_of_headers
    sec_off = opt_off + opt_size
    for i in range(num_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            result.issues.append(f"truncated section header #{i}")
            break
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, base + 8
        )
        hdr.sections.append((vaddr, vsize, raw_size, raw_ptr))
    num_dirs = _u32(data, opt_off + num_dirs_off) or 0
    if num_dirs >= 2:
        dd_off = opt_off + dd_base_off + 8  # directory index 1 (import)
        rva = _u32(data, dd_off)
        size = _u32(data, dd_off + 4)
        if rva is None or size is None:
            result.issues.append("truncated import data directory")
            return None
        hdr.import_rva, hdr.import_size = rva, size
    return hdr


def _merge(fragments: list[Fragment], new: list[Fragment]) -> None:
    for frag in new:
        if (
            fragments
            and fragments[-1].file_offset + len(fragments[-1].data)
            == frag.file_offset
        ):
            last = fragments[-1]
            fragments[-1] = Fragment(last.file_offset, last.data + frag.data)
        else:
            fragments.append(frag)


def _read_uint(mapper: RvaMapper, rva: int, size: int):
    """-> (value or None, fragments, issues)"""
    res = mapper.read(rva, size)
    if res.status is not Status.COMPLETE:
        return None, res.fragments, res.issues
    return int.from_bytes(res.data, "little"), res.fragments, res.issues


def _read_c_string(mapper: RvaMapper, rva: int):
    """-> (text or None, Status, fragments, issues)

    Only a real NUL byte terminates; mapping gaps, zero-fill and truncation
    never terminate the string.
    """
    fragments: list[Fragment] = []
    issues: list[str] = []
    data = bytearray()
    for i in range(_MAX_STRING):
        res = mapper.read(rva + i, 1)
        _merge(fragments, res.fragments)
        issues.extend(res.issues)
        if res.status is not Status.COMPLETE:
            issues.append(f"string at RVA 0x{rva:x} unterminated: hit non-real byte")
            status = Status.PARTIAL if data else Status.UNREADABLE
            return None, status, fragments, issues
        byte = res.data[0]
        if byte == 0:
            try:
                text = bytes(data).decode("ascii")
            except UnicodeDecodeError:
                issues.append(f"string at RVA 0x{rva:x} is not ASCII")
                return None, Status.PARTIAL, fragments, issues
            return text, Status.COMPLETE, fragments, issues
        data.append(byte)
    issues.append(f"string at RVA 0x{rva:x} exceeds length limit")
    return None, Status.PARTIAL, fragments, issues


def _parse_thunks(
    mapper: RvaMapper,
    table_rva: int,
    width: int,
    dll: ImportedDll,
) -> None:
    ordinal_flag = 0x80000000 if width == 4 else 0x8000000000000000
    pos = table_rva
    for _ in range(_MAX_THUNKS):
        value, frags, issues = _read_uint(mapper, pos, width)
        if value is None:
            dll.issues.append(
                f"thunk entry at RVA 0x{pos:x} unreadable; thunk table stopped"
            )
            dll.issues.extend(issues)
            return
        if value == 0:
            dll.thunks_complete = True
            return
        entry = ImportedFunction(thunk_rva=pos)
        _merge(entry.evidence, frags)
        if value & ordinal_flag:
            entry.ordinal = value & 0xFFFF
            reserved = value & ~(ordinal_flag | 0xFFFF)
            if reserved:
                entry.issues.append(
                    f"reserved thunk bits set: 0x{reserved:x}"
                )
            entry.status = Status.COMPLETE
        else:
            if value >= _UINT32_SPACE:
                entry.issues.append(
                    f"name RVA 0x{value:x} is not a legal 32-bit RVA"
                )
                entry.status = Status.UNREADABLE
            else:
                hint, hint_frags, hint_issues = _read_uint(mapper, value, 2)
                _merge(entry.evidence, hint_frags)
                entry.issues.extend(hint_issues)
                text, status, name_frags, name_issues = _read_c_string(
                    mapper, value + 2
                )
                _merge(entry.evidence, name_frags)
                entry.issues.extend(name_issues)
                entry.hint = hint
                entry.name = text
                if hint is None and status is Status.UNREADABLE:
                    entry.status = Status.UNREADABLE
                elif hint is not None and status is Status.COMPLETE:
                    entry.status = Status.COMPLETE
                else:
                    entry.status = Status.PARTIAL
        dll.functions.append(entry)
        pos += width
    dll.issues.append("thunk table exceeds entry limit")


def extract_imports(data: bytes) -> ImportForensics:
    """Extract the ordinary import table of a PE32/PE32+ image."""
    result = ImportForensics()
    hdr = _parse_header(data, result)
    if hdr is None:
        return result
    mapper = RvaMapper(data, hdr.size_of_headers, hdr.sections)
    result.issues.extend(mapper.anomalies)
    if hdr.import_rva == 0:
        result.complete = True
        return result
    dir_end = hdr.import_rva + hdr.import_size
    if dir_end > _UINT32_SPACE:
        result.issues.append("import directory range exceeds 32-bit address space")
        dir_end = _UINT32_SPACE
    width = 4 if hdr.pe_format == "PE32" else 8
    pos = hdr.import_rva
    terminated = False
    for _ in range(_MAX_DESCRIPTORS):
        remaining = dir_end - pos
        if remaining <= 0:
            result.issues.append(
                "import directory boundary reached without null descriptor"
            )
            break
        if remaining < _DESCRIPTOR_SIZE:
            result.issues.append(
                f"import directory boundary: {remaining} trailing byte(s) "
                "too short for a descriptor"
            )
            break
        res = mapper.read(pos, _DESCRIPTOR_SIZE)
        if res.status is not Status.COMPLETE:
            result.issues.append(
                f"descriptor at RVA 0x{pos:x} unreadable; descriptor table stopped"
            )
            result.issues.extend(res.issues)
            break
        fields = struct.unpack("<IIIII", res.data)
        if all(v == 0 for v in fields):
            terminated = True
            break
        oft, _timestamp, _chain, name_rva, ft = fields
        dll = ImportedDll(descriptor_rva=pos)
        _merge(dll.descriptor_evidence, res.fragments)
        if name_rva == 0:
            dll.issues.append("descriptor has null Name RVA")
        else:
            text, status, frags, issues = _read_c_string(mapper, name_rva)
            dll.name = text
            dll.name_status = status
            _merge(dll.name_evidence, frags)
            dll.issues.extend(issues)
        table_rva = oft if oft != 0 else ft
        if table_rva == 0:
            dll.issues.append("descriptor has no thunk table RVA")
        else:
            _parse_thunks(mapper, table_rva, width, dll)
        result.dlls.append(dll)
        pos += _DESCRIPTOR_SIZE
    else:
        result.issues.append("descriptor table exceeds entry limit")
    result.complete = terminated and not _has_issues(result)
    return result


def _has_issues(result: ImportForensics) -> bool:
    if result.issues:
        return True
    for dll in result.dlls:
        if dll.issues or not dll.thunks_complete:
            return True
        if dll.name_status is not Status.COMPLETE:
            return True
        for fn in dll.functions:
            if fn.issues or fn.status is not Status.COMPLETE:
                return True
    return False
