"""RVA -> file-offset mapping with ambiguity and gap detection."""

from __future__ import annotations

from .pefile import PeHeaders


class RvaMapper:
    """Translates RVA ranges into file evidence fragments.

    A byte is ambiguous when more than one mapping source covers it;
    virtual zero-fill and truncated file regions never yield bytes.
    """

    def __init__(self, headers: PeHeaders, data: bytes) -> None:
        self._data = data
        self._intervals: list[tuple[int, int, int]] = []
        header_len = min(headers.size_of_headers, len(data))
        if header_len > 0:
            self._intervals.append((0, header_len, 0))
        for section in headers.sections:
            raw_ptr = section.pointer_to_raw_data
            if raw_ptr >= len(data):
                continue
            raw_len = min(section.size_of_raw_data, len(data) - raw_ptr)
            if raw_len <= 0:
                continue
            self._intervals.append(
                (section.virtual_address, section.virtual_address + raw_len, raw_ptr)
            )

    def _locate(self, rva: int) -> int | None:
        """File offset for one RVA byte, or None for gap/ambiguity."""
        hits = [
            file_start + (rva - rva_start)
            for rva_start, rva_end, file_start in self._intervals
            if rva_start <= rva < rva_end
        ]
        if len(hits) != 1:
            return None
        return hits[0]

    def read(self, rva: int, length: int) -> tuple[bytes, list[tuple[int, int]], str]:
        """Read ``length`` bytes at ``rva``.

        Returns (data, fragments, status): ``data`` holds the contiguous
        readable prefix, fragments are (file_offset, length) pairs
        actually read, and status is "complete", "partial" or
        "unreadable".  Reading stops at the first gap, ambiguous byte,
        virtual zero-fill or file truncation.
        """
        chunks: list[bytes] = []
        fragments: list[tuple[int, int]] = []
        remaining = length
        cursor = rva
        while remaining > 0:
            file_off = self._locate(cursor)
            if file_off is None:
                break
            run_start_file = file_off
            run = 0
            while run < remaining and self._locate(cursor) == file_off + run:
                run += 1
                cursor += 1
            chunks.append(self._data[run_start_file:run_start_file + run])
            fragments.append((run_start_file, run))
            remaining -= run
        data = b"".join(chunks)
        if remaining == 0:
            status = "complete"
        elif data:
            status = "partial"
        else:
            status = "unreadable"
        return data, fragments, status

    def read_c_string(self, rva: int, max_length: int = 4096) -> tuple[bytes, list[tuple[int, int]], str]:
        """Read a NUL-terminated ASCII string starting at ``rva``."""
        out = bytearray()
        fragments: list[tuple[int, int]] = []
        cursor = rva
        terminated = False
        while len(out) < max_length:
            file_off = self._locate(cursor)
            if file_off is None:
                break
            byte = self._data[file_off]
            if fragments and fragments[-1][0] + fragments[-1][1] == file_off:
                fragments[-1] = (fragments[-1][0], fragments[-1][1] + 1)
            else:
                fragments.append((file_off, 1))
            cursor += 1
            if byte == 0:
                terminated = True
                break
            out.append(byte)
        if terminated:
            status = "complete"
        elif out:
            status = "partial"
        else:
            status = "unreadable"
        return bytes(out), fragments, status
