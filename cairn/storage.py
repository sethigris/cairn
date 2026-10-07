"""Durable storage for Cairn state.

Cairn uses directories, JSON, and JSON Lines rather than a database. This is a
feature for an educational systems project: every byte of persistent state can
be inspected with ordinary Windows tools.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .crypto import canonical_json
from .model import LedgerEvent, Seal, Snapshot


FORMAT_VERSION = 1
STATE_DIR = ".cairn"
LEDGER_FILE = "ledger.jsonl"
CONFIG_FILE = "config.json"
SNAPSHOT_DIR = "snapshots"
SEAL_DIR = "seals"
LOCK_FILE = "write.lock"


class StorageError(Exception):
    """Raised for invalid or inaccessible Cairn state."""


class Storage:
    """Manage one Cairn repository rooted at a working directory."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.state = self.root / STATE_DIR
        self.ledger_path = self.state / LEDGER_FILE
        self.config_path = self.state / CONFIG_FILE
        self.snapshot_dir = self.state / SNAPSHOT_DIR
        self.seal_dir = self.state / SEAL_DIR
        self.lock_path = self.state / LOCK_FILE

    def is_initialized(self) -> bool:
        return self.state.is_dir() and self.config_path.exists() and self.ledger_path.exists()

    def initialize(self, ignore: list[str] | None = None) -> None:
        if self.is_initialized():
            raise StorageError("Cairn is already initialized in this directory")
        self.state.mkdir(parents=True, exist_ok=False)
        self.snapshot_dir.mkdir()
        self.seal_dir.mkdir()
        config = {
            "format_version": FORMAT_VERSION,
            "root": str(self.root),
            "ignore": ignore or [],
        }
        self._atomic_json_write(self.config_path, config)
        self.ledger_path.write_text("", encoding="utf-8", newline="\n")

    def require_initialized(self) -> None:
        if not self.is_initialized():
            raise StorageError("Not a Cairn repository. Run: python cairn.py init")

    def load_config(self) -> dict[str, Any]:
        self.require_initialized()
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"Cannot read Cairn config: {exc}") from exc
        if int(data.get("format_version", -1)) != FORMAT_VERSION:
            raise StorageError("Unsupported Cairn format version")
        return data

    def save_config(self, config: dict[str, Any]) -> None:
        self.require_initialized()
        self._atomic_json_write(self.config_path, config)

    @contextmanager
    def write_lock(self) -> Iterator[None]:
        """Create an exclusive lock file using Windows-safe file creation."""

        self.require_initialized()
        handle = None
        try:
            handle = self.lock_path.open("x", encoding="ascii")
            handle.write(str(os.getpid()))
            handle.flush()
            yield
        except FileExistsError as exc:
            raise StorageError(
                "Cairn is locked by another writer. Delete .cairn\\write.lock "
                "only when you are certain no Cairn process is active."
            ) from exc
        finally:
            if handle is not None:
                handle.close()
            try:
                self.lock_path.unlink(missing_ok=True)
            except OSError:
                pass

    def append_event(self, event: LedgerEvent) -> None:
        self.require_initialized()
        line = json.dumps(
            event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with self.ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def read_events(self) -> list[LedgerEvent]:
        self.require_initialized()
        events: list[LedgerEvent] = []
        with self.ledger_path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    events.append(LedgerEvent.from_dict(data))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    raise StorageError(f"Invalid ledger line {number}: {exc}") from exc
        return events

    def last_event(self) -> LedgerEvent | None:
        events = self.read_events()
        return events[-1] if events else None

    def save_snapshot(self, snapshot: Snapshot) -> Path:
        self.require_initialized()
        path = self.snapshot_dir / f"{snapshot.snapshot_id}.json"
        self._atomic_json_write(path, snapshot.to_dict(include_records=True))
        return path

    def load_snapshot(self, snapshot_id: str) -> Snapshot:
        self.require_initialized()
        path = self.snapshot_dir / f"{snapshot_id}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise StorageError(f"Snapshot not found: {snapshot_id}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"Cannot read snapshot {snapshot_id}: {exc}") from exc
        return Snapshot.from_dict(data)

    def list_snapshot_ids(self) -> list[str]:
        self.require_initialized()
        return sorted(path.stem for path in self.snapshot_dir.glob("*.json"))

    def save_seal(self, seal: Seal) -> Path:
        self.require_initialized()
        path = self.seal_dir / f"{seal.seal_id}.json"
        self._atomic_json_write(path, seal.to_dict())
        return path

    def load_seals(self) -> list[Seal]:
        self.require_initialized()
        seals: list[Seal] = []
        for path in sorted(self.seal_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                seals.append(Seal.from_dict(data))
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise StorageError(f"Cannot read seal {path.name}: {exc}") from exc
        return seals

    @staticmethod
    def _atomic_json_write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(canonical_json(value).decode("utf-8"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
