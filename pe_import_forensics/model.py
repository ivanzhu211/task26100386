"""Data model for PE import-table forensic results.

Everything is kept in memory; byte-level evidence is expressed as file
offsets so upstream scanners can trace every conclusion back to the
sample.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Status(enum.Enum):
    """Readability of a single forensic object."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Fragment:
    """One contiguous piece of file evidence.

    An object that spans several file locations yields one Fragment per
    location; fragments are never merged even when adjacent.
    """

    file_offset: int
    length: int


@dataclass
class Evidence:
    """Raw byte evidence backing a parsed object."""

    fragments: list[Fragment] = field(default_factory=list)

    def add(self, file_offset: int, length: int) -> None:
        if length > 0:
            self.fragments.append(Fragment(file_offset, length))


@dataclass
class ImportedFunction:
    """One thunk entry resolved to a name or an ordinal."""

    status: Status
    evidence: Evidence = field(default_factory=Evidence)
    ordinal: int | None = None
    hint: int | None = None
    name: bytes | None = None
    name_evidence: Evidence | None = None


@dataclass
class DllImport:
    """Imports from a single DLL (one import descriptor)."""

    status: Status
    evidence: Evidence = field(default_factory=Evidence)
    dll_name: bytes | None = None
    dll_name_evidence: Evidence | None = None
    functions: list[ImportedFunction] = field(default_factory=list)


@dataclass
class ImportResult:
    """Top-level forensic result for one PE image."""

    status: Status
    is_pe32_plus: bool = False
    dlls: list[DllImport] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
