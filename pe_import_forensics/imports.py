"""Import directory walker for PE32/PE32+ images."""

from __future__ import annotations

import struct

from .mapping import RvaMapper
from .model import DllImport, Evidence, ImportedFunction, ImportResult, Status
from .pefile import PeHeaders, parse_headers

DESCRIPTOR_SIZE = 20
MAX_DESCRIPTORS = 1 << 16
MAX_THUNKS = 1 << 20


def _evidence(fragments: list[tuple[int, int]]) -> Evidence:
    ev = Evidence()
    for off, length in fragments:
        ev.add(off, length)
    return ev


def _parse_thunks(
    dll: DllImport,
    thunk_rva: int,
    headers: PeHeaders,
    mapper: RvaMapper,
    anomalies: list[str],
) -> None:
    width = 8 if headers.is_pe32_plus else 4
    ordinal_flag = 0x8000000000000000 if headers.is_pe32_plus else 0x80000000
    cursor = thunk_rva
    for _ in range(MAX_THUNKS):
        raw, frags, status = mapper.read(cursor, width)
        if status != "complete":
            dll.status = Status.PARTIAL
            anomalies.append(
                f"thunk table at RVA {thunk_rva:#x} unreadable at entry "
                f"RVA {cursor:#x}"
            )
            return
        value = int.from_bytes(raw, "little")
        entry_ev = _evidence(frags)
        if value == 0:
            return
        if value & ordinal_flag:
            ordinal = value & 0xFFFF
            reserved = value & ~(ordinal_flag | 0xFFFF)
            if reserved:
                anomalies.append(
                    f"thunk at RVA {cursor:#x} has nonzero reserved bits "
                    f"({reserved:#x})"
                )
            dll.functions.append(
                ImportedFunction(
                    status=Status.COMPLETE,
                    evidence=entry_ev,
                    ordinal=ordinal,
                )
            )
        else:
            if value >= (1 << 32):
                anomalies.append(
                    f"hint/name RVA {value:#x} at thunk RVA {cursor:#x} is "
                    f"not a 32-bit RVA"
                )
                dll.functions.append(
                    ImportedFunction(status=Status.UNREADABLE, evidence=entry_ev)
                )
                dll.status = Status.PARTIAL
                cursor += width
                continue
            hint_raw, hint_frags, hint_status = mapper.read(value, 2)
            name, name_frags, name_status = (
                mapper.read_c_string(value + 2)
                if hint_status == "complete"
                else (b"", [], "unreadable")
            )
            entry_status = (
                Status.COMPLETE
                if hint_status == "complete" and name_status == "complete"
                else Status.UNREADABLE
                if hint_status == "unreadable"
                else Status.PARTIAL
            )
            func = ImportedFunction(
                status=entry_status,
                evidence=entry_ev,
                hint=struct.unpack("<H", hint_raw)[0]
                if hint_status == "complete"
                else None,
                name=name if name_status == "complete" else None,
                name_evidence=_evidence(hint_frags + name_frags),
            )
            dll.functions.append(func)
            if entry_status is not Status.COMPLETE:
                dll.status = Status.PARTIAL
        cursor += width
    anomalies.append(f"thunk table at RVA {thunk_rva:#x} exceeds sanity limit")
    dll.status = Status.PARTIAL


def parse_imports(headers: PeHeaders, mapper: RvaMapper) -> ImportResult:
    """Walk the import descriptor table and all referenced structures."""
    result = ImportResult(status=Status.COMPLETE, is_pe32_plus=headers.is_pe32_plus)
    result.anomalies.extend(headers.anomalies)
    if headers.import_directory_rva == 0:
        return result

    table_rva = headers.import_directory_rva
    table_end = table_rva + headers.import_directory_size
    cursor = table_rva
    terminated = False
    for _ in range(MAX_DESCRIPTORS):
        if cursor + DESCRIPTOR_SIZE > table_end:
            if cursor < table_end:
                result.anomalies.append(
                    f"import directory boundary leaves {table_end - cursor} "
                    f"bytes short of a descriptor"
                )
            else:
                result.anomalies.append(
                    "import directory ended without a null descriptor"
                )
            break
        raw, frags, status = mapper.read(cursor, DESCRIPTOR_SIZE)
        if status != "complete":
            result.anomalies.append(
                f"import descriptor at RVA {cursor:#x} unreadable; "
                f"stopping descriptor table"
            )
            break
        if raw == b"\x00" * DESCRIPTOR_SIZE:
            terminated = True
            break
        original_first_thunk, _ts, _fw, name_rva, first_thunk = struct.unpack(
            "<IIIII", raw
        )
        dll = DllImport(status=Status.COMPLETE, evidence=_evidence(frags))
        dll_name, name_frags, name_status = mapper.read_c_string(name_rva)
        dll.dll_name = dll_name if name_status == "complete" else None
        dll.dll_name_evidence = _evidence(name_frags)
        if name_status != "complete":
            dll.status = Status.PARTIAL
        thunk_rva = original_first_thunk or first_thunk
        if thunk_rva:
            _parse_thunks(dll, thunk_rva, headers, mapper, result.anomalies)
        else:
            dll.status = Status.PARTIAL
            result.anomalies.append(
                f"descriptor at RVA {cursor:#x} has no thunk table RVA"
            )
        if (
            dll.status is not Status.COMPLETE
            and dll.dll_name is None
            and not dll.functions
        ):
            dll.status = Status.UNREADABLE
        result.dlls.append(dll)
        cursor += DESCRIPTOR_SIZE
    else:
        result.anomalies.append("import descriptor table exceeds sanity limit")

    if not terminated:
        result.status = Status.PARTIAL if result.dlls else Status.UNREADABLE
    statuses = [dll.status for dll in result.dlls]
    if Status.PARTIAL in statuses or Status.UNREADABLE in statuses:
        result.status = Status.PARTIAL
    if result.anomalies and result.status == Status.COMPLETE:
        result.status = Status.PARTIAL
    return result


def extract(data: bytes) -> ImportResult:
    """Full pipeline: headers -> mapper -> import directory."""
    headers = parse_headers(data)
    mapper = RvaMapper(headers, data)
    return parse_imports(headers, mapper)
