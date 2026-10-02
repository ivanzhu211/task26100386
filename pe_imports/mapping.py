"""RVA -> file-offset mapping with ambiguity, zero-fill and truncation rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Fragment, Status

UINT32_SPACE = 1 << 32

_FILE = "file"
_ZERO = "zero"


@dataclass(frozen=True)
class _Segment:
    """One mapping source over an RVA range."""

    rva_start: int
    rva_end: int  # exclusive
    kind: str  # _FILE or _ZERO
    file_offset: int = 0  # only for _FILE

    def covers(self, rva: int) -> bool:
        return self.rva_start <= rva < self.rva_end


@dataclass
class ReadResult:
    """Outcome of reading a byte range through the RVA mapping."""

    status: Status
    fragments: list[Fragment] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    @property
    def data(self) -> bytes:
        """Real bytes, valid only when the fragments form one contiguous run."""
        return b"".join(f.data for f in self.fragments)


class RvaMapper:
    """Maps RVAs to file bytes according to PE header/section layout.

    - Bytes [0, SizeOfHeaders) come from the start of the file.
    - Each section spans max(VirtualSize, SizeOfRawData) bytes from
      VirtualAddress; the first SizeOfRawData bytes map to PointerToRawData,
      the rest is virtual zero-fill (not real bytes).
    - Sections whose declared range exceeds the 32-bit address space are
      recorded as anomalies and excluded from mapping.
    - A byte covered by more than one mapping source is ambiguous and yields
      no bytes, even if all sources point at the same file offset.
    """

    def __init__(
        self,
        data: bytes,
        size_of_headers: int,
        sections: list[tuple[int, int, int, int]],
    ) -> None:
        """sections: (virtual_address, virtual_size, raw_size, raw_pointer)."""
        self._data = data
        self.anomalies: list[str] = []
        self._segments: list[_Segment] = []
        if 0 < size_of_headers:
            self._segments.append(_Segment(0, size_of_headers, _FILE, 0))
        for va, vs, raw_size, raw_ptr in sections:
            span = max(vs, raw_size)
            if span == 0:
                continue
            if va >= UINT32_SPACE or va + span > UINT32_SPACE:
                self.anomalies.append(
                    f"section at RVA 0x{va:x} span 0x{span:x} exceeds 32-bit "
                    "address space; excluded from mapping"
                )
                continue
            if raw_size:
                self._segments.append(_Segment(va, va + raw_size, _FILE, raw_ptr))
            if vs > raw_size:
                self._segments.append(
                    _Segment(va + raw_size, va + vs, _ZERO)
                )

    def read(self, rva: int, size: int) -> ReadResult:
        """Read [rva, rva+size). Only real file bytes become fragments."""
        issues: list[str] = []
        fragments: list[Fragment] = []
        missing = 0
        cur_offset: int | None = None
        cur = bytearray()
        for pos in range(rva, rva + size):
            hits = [s for s in self._segments if s.covers(pos)]
            real: int | None = None
            if len(hits) > 1:
                issues.append(f"ambiguous RVA 0x{pos:x}: {len(hits)} mapping sources")
            elif len(hits) == 1 and hits[0].kind == _FILE:
                file_off = hits[0].file_offset + (pos - hits[0].rva_start)
                if file_off < len(self._data):
                    real = file_off
            if real is None:
                missing += 1
                if cur:
                    fragments.append(Fragment(cur_offset, bytes(cur)))
                    cur = bytearray()
                    cur_offset = None
                continue
            if cur and cur_offset is not None and cur_offset + len(cur) == real:
                cur += self._data[real : real + 1]
            else:
                if cur:
                    fragments.append(Fragment(cur_offset, bytes(cur)))
                cur_offset = real
                cur = bytearray(self._data[real : real + 1])
        if cur:
            fragments.append(Fragment(cur_offset, bytes(cur)))
        total = sum(len(f.data) for f in fragments)
        if missing == 0 and not issues:
            status = Status.COMPLETE
        elif total == 0:
            status = Status.UNREADABLE
        else:
            status = Status.PARTIAL
        return ReadResult(status=status, fragments=fragments, issues=issues)
