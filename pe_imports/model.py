"""Data model for PE import-table forensic results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Status(enum.Enum):
    """Readability of a single forensic object."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Fragment:
    """A contiguous run of real bytes recovered from the file."""

    file_offset: int
    data: bytes


@dataclass
class ImportedFunction:
    """One import entry (by name or by ordinal). Duplicates are kept."""

    thunk_rva: int
    ordinal: Optional[int] = None
    hint: Optional[int] = None
    name: Optional[str] = None
    status: Status = Status.UNREADABLE
    evidence: list[Fragment] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class ImportedDll:
    """One import descriptor and its thunk table."""

    descriptor_rva: int
    name: Optional[str] = None
    name_status: Status = Status.UNREADABLE
    name_evidence: list[Fragment] = field(default_factory=list)
    descriptor_evidence: list[Fragment] = field(default_factory=list)
    functions: list[ImportedFunction] = field(default_factory=list)
    thunks_complete: bool = False
    issues: list[str] = field(default_factory=list)


@dataclass
class ImportForensics:
    """Top-level result of an import-table extraction."""

    pe_format: Optional[str] = None  # "PE32" or "PE32+"
    complete: bool = False
    dlls: list[ImportedDll] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
