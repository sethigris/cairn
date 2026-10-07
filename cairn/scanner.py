"""Deterministic Windows-friendly filesystem scanner for Cairn."""

from __future__ import annotations

import fnmatch
import os
import stat
import time
from pathlib import Path
from typing import Iterable

from .crypto import hash_file, merkle_leaf, merkle_root
from .model import FileRecord, ScanSummary, Snapshot


DEFAULT_IGNORES = [
    ".cairn",
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "Thumbs.db",
    "desktop.ini",
]


class ScanError(Exception):
    """Raised when the scanner cannot establish a safe root."""


class IgnoreMatcher:
    """Simple ordered glob matcher for relative Windows paths."""

    def __init__(self, patterns: Iterable[str]):
        self.patterns = tuple(p.strip().replace("\\", "/") for p in patterns if p.strip())

    def matches(self, rel: str) -> bool:
        normalized = rel.replace("\\", "/").strip("/")
        for pattern in self.patterns:
            p = pattern.strip("/")
            if fnmatch.fnmatchcase(normalized, p):
                return True
            if normalized.startswith(p + "/"):
                return True
            if fnmatch.fnmatchcase(Path(normalized).name, p):
                return True
        return False


class Scanner:
    """Walk a tree, hash regular files and produce an immutable snapshot."""

    def __init__(self, root: Path, ignore: Iterable[str] = ()):
        self.root = root.resolve()
        self.matcher = IgnoreMatcher([*DEFAULT_IGNORES, *ignore])
        self.ignored = 0
        self.errors = 0

    def scan(self, snapshot_id: str | None = None) -> tuple[Snapshot, ScanSummary]:
        start = time.perf_counter()
        self._validate_root()
        records: list[FileRecord] = []
        self.ignored = 0
        self.errors = 0

        for directory, dirnames, filenames in os.walk(self.root, topdown=True, followlinks=False):
            dir_path = Path(directory)
            dirnames[:] = self._filter_directories(dir_path, dirnames)
            for filename in sorted(filenames, key=lambda item: item.casefold()):
                path = dir_path / filename
                rel = self._relative(path)
                if self.matcher.matches(rel):
                    self.ignored += 1
                    continue
                record = self._record(path, rel)
                if record is not None:
                    records.append(record)

        records.sort(key=lambda item: item.path.casefold())
        root = merkle_root([self._leaf(record) for record in records])
        total_bytes = sum(record.size for record in records)
        snapshot = Snapshot(
            snapshot_id=snapshot_id or self._new_id(),
            root=str(self.root),
            captured_at=time.time(),
            file_count=len(records),
            total_bytes=total_bytes,
            merkle_root=root,
            records=tuple(records),
        )
        elapsed = time.perf_counter() - start
        summary = ScanSummary(
            files=len(records),
            bytes=total_bytes,
            ignored=self.ignored,
            errors=self.errors,
            elapsed=elapsed,
        )
        return snapshot, summary

    def _filter_directories(self, parent: Path, names: list[str]) -> list[str]:
        kept: list[str] = []
        for name in sorted(names, key=lambda item: item.casefold()):
            path = parent / name
            rel = self._relative(path)
            if self.matcher.matches(rel):
                self.ignored += 1
                continue
            try:
                if path.is_symlink():
                    self.ignored += 1
                    continue
            except OSError:
                self.errors += 1
                continue
            kept.append(name)
        return kept

    def _record(self, path: Path, rel: str) -> FileRecord | None:
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                return None
            digest, size = hash_file(path)
            suffix = path.suffix.lower()
            return FileRecord(
                path=rel,
                size=size,
                mtime_ns=info.st_mtime_ns,
                sha256=digest,
                mode=stat.S_IMODE(info.st_mode),
                extension=suffix,
            )
        except (OSError, PermissionError):
            self.errors += 1
            return None

    def _validate_root(self) -> None:
        if not self.root.exists():
            raise ScanError(f"Root does not exist: {self.root}")
        if not self.root.is_dir():
            raise ScanError(f"Root is not a directory: {self.root}")

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    @staticmethod
    def _leaf(record: FileRecord) -> str:
        return merkle_leaf(record.path, record.sha256, record.size)

    @staticmethod
    def _new_id() -> str:
        return time.strftime("%Y%m%d-%H%M%S") + "-" + f"{time.time_ns() % 1_000_000:06d}"
