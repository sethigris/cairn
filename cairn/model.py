"""Domain models for Cairn.

The models are intentionally plain dataclasses. They keep the persistence
format understandable so the project can be inspected without a framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class FileRecord:
    """Immutable observation of one filesystem object."""

    path: str
    size: int
    mtime_ns: int
    sha256: str
    mode: int = 0
    extension: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "sha256": self.sha256,
            "mode": self.mode,
            "extension": self.extension,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FileRecord":
        return cls(
            path=str(data["path"]),
            size=int(data["size"]),
            mtime_ns=int(data["mtime_ns"]),
            sha256=str(data["sha256"]),
            mode=int(data.get("mode", 0)),
            extension=str(data.get("extension", "")),
        )


@dataclass(frozen=True)
class Snapshot:
    """A complete logical state of a scanned root."""

    snapshot_id: str
    root: str
    captured_at: float
    file_count: int
    total_bytes: int
    merkle_root: str
    records: tuple[FileRecord, ...] = field(default_factory=tuple)

    def to_dict(self, include_records: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "snapshot_id": self.snapshot_id,
            "root": self.root,
            "captured_at": self.captured_at,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "merkle_root": self.merkle_root,
        }
        if include_records:
            data["records"] = [record.to_dict() for record in self.records]
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Snapshot":
        records = tuple(FileRecord.from_dict(item) for item in data.get("records", []))
        return cls(
            snapshot_id=str(data["snapshot_id"]),
            root=str(data["root"]),
            captured_at=float(data["captured_at"]),
            file_count=int(data["file_count"]),
            total_bytes=int(data["total_bytes"]),
            merkle_root=str(data["merkle_root"]),
            records=records,
        )


@dataclass(frozen=True)
class LedgerEvent:
    """A single append-only state transition."""

    seq: int
    timestamp: float
    event_type: str
    payload: Mapping[str, Any]
    previous_hash: str
    hash: str

    def body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": dict(self.payload),
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.body()
        data["hash"] = self.hash
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LedgerEvent":
        return cls(
            seq=int(data["seq"]),
            timestamp=float(data["timestamp"]),
            event_type=str(data["event_type"]),
            payload=dict(data.get("payload", {})),
            previous_hash=str(data["previous_hash"]),
            hash=str(data["hash"]),
        )


@dataclass(frozen=True)
class SnapshotDiff:
    """Comparison between two snapshot states."""

    added: tuple[FileRecord, ...]
    removed: tuple[FileRecord, ...]
    modified: tuple[tuple[FileRecord, FileRecord], ...]
    unchanged: int

    @property
    def changed(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)

    @property
    def total(self) -> int:
        return self.changed + self.unchanged


@dataclass(frozen=True)
class Seal:
    """Portable trust anchor for a ledger point and snapshot state."""

    seal_id: str
    created_at: float
    ledger_hash: str
    snapshot_id: str
    merkle_root: str
    statement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seal_id": self.seal_id,
            "created_at": self.created_at,
            "ledger_hash": self.ledger_hash,
            "snapshot_id": self.snapshot_id,
            "merkle_root": self.merkle_root,
            "statement": self.statement,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Seal":
        return cls(
            seal_id=str(data["seal_id"]),
            created_at=float(data["created_at"]),
            ledger_hash=str(data["ledger_hash"]),
            snapshot_id=str(data["snapshot_id"]),
            merkle_root=str(data["merkle_root"]),
            statement=str(data["statement"]),
        )


@dataclass(frozen=True)
class VerificationReport:
    """Summary of structural and content verification."""

    ledger_ok: bool
    snapshots_ok: bool
    seals_ok: bool
    events_checked: int
    snapshots_checked: int
    seals_checked: int
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.ledger_ok and self.snapshots_ok and self.seals_ok and not self.problems


@dataclass(frozen=True)
class ScanSummary:
    """Statistics returned by a filesystem scan."""

    files: int
    bytes: int
    ignored: int
    errors: int
    elapsed: float
