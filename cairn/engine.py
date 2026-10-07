"""Core Cairn state machine: snapshots, diffs, verification and seals."""

from __future__ import annotations

import math
import os
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .crypto import chain_digest, constant_time_equal, fingerprint_mapping, merkle_root_from_records
from .model import (
    FileRecord,
    LedgerEvent,
    Seal,
    Snapshot,
    SnapshotDiff,
    VerificationReport,
)
from .scanner import DEFAULT_IGNORES, Scanner
from .storage import Storage, StorageError


GENESIS = "0" * 64


class CairnEngine:
    """Application service around the on-disk Cairn state."""

    def __init__(self, root: Path):
        self.storage = Storage(root)

    def init(self, ignore: Iterable[str] = ()) -> None:
        patterns = list(ignore)
        self.storage.initialize(patterns)
        event = self._make_event(
            1,
            "INIT",
            {"root": str(self.storage.root), "ignore": patterns},
            GENESIS,
        )
        self.storage.append_event(event)

    def snapshot(self, note: str = "") -> tuple[Snapshot, Any]:
        self.storage.require_initialized()
        config = self.storage.load_config()
        scanner = Scanner(self.storage.root, config.get("ignore", []))
        snapshot, summary = scanner.scan()
        with self.storage.write_lock():
            self.storage.save_snapshot(snapshot)
            last = self.storage.last_event()
            previous = last.hash if last else GENESIS
            seq = (last.seq + 1) if last else 1
            event = self._make_event(
                seq,
                "SNAPSHOT",
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "merkle_root": snapshot.merkle_root,
                    "file_count": snapshot.file_count,
                    "total_bytes": snapshot.total_bytes,
                    "note": note,
                },
                previous,
            )
            self.storage.append_event(event)
        return snapshot, summary

    def diff(self, older: str, newer: str) -> SnapshotDiff:
        left = self.storage.load_snapshot(older)
        right = self.storage.load_snapshot(newer)
        return self._diff_snapshots(left, right)

    def latest_snapshot(self) -> Snapshot | None:
        snapshots = self.storage.list_snapshot_ids()
        if not snapshots:
            return None
        return self.storage.load_snapshot(snapshots[-1])

    def history(self, limit: int = 20) -> list[LedgerEvent]:
        if limit < 1:
            raise ValueError("limit must be positive")
        events = self.storage.read_events()
        return events[-limit:]

    def verify(self) -> VerificationReport:
        self.storage.require_initialized()
        problems: list[str] = []
        events = self.storage.read_events()
        ledger_ok = True
        expected_previous = GENESIS
        expected_seq = 1
        for event in events:
            if event.seq != expected_seq:
                ledger_ok = False
                problems.append(
                    f"ledger sequence break at event {event.seq}; expected {expected_seq}"
                )
            if not constant_time_equal(event.previous_hash, expected_previous):
                ledger_ok = False
                problems.append(f"ledger predecessor mismatch at event {event.seq}")
            calculated = chain_digest(event.previous_hash, event.body())
            if not constant_time_equal(event.hash, calculated):
                ledger_ok = False
                problems.append(f"ledger hash mismatch at event {event.seq}")
            expected_previous = event.hash
            expected_seq += 1

        snapshots_ok = True
        snapshots = []
        for snapshot_id in self.storage.list_snapshot_ids():
            try:
                snapshot = self.storage.load_snapshot(snapshot_id)
                recalculated = merkle_root_from_records(record.to_dict() for record in snapshot.records)
                if recalculated != snapshot.merkle_root:
                    snapshots_ok = False
                    problems.append(f"snapshot Merkle mismatch: {snapshot_id}")
                if snapshot.file_count != len(snapshot.records):
                    snapshots_ok = False
                    problems.append(f"snapshot file count mismatch: {snapshot_id}")
                if snapshot.total_bytes != sum(record.size for record in snapshot.records):
                    snapshots_ok = False
                    problems.append(f"snapshot byte count mismatch: {snapshot_id}")
                snapshots.append(snapshot)
            except StorageError as exc:
                snapshots_ok = False
                problems.append(str(exc))

        seals_ok = True
        seals = self.storage.load_seals()
        known_snapshots = {snap.snapshot_id: snap for snap in snapshots}
        known_events = {event.hash for event in events}
        for seal in seals:
            if seal.snapshot_id not in known_snapshots:
                seals_ok = False
                problems.append(f"seal references missing snapshot: {seal.seal_id}")
                continue
            snapshot = known_snapshots[seal.snapshot_id]
            if snapshot.merkle_root != seal.merkle_root:
                seals_ok = False
                problems.append(f"seal Merkle mismatch: {seal.seal_id}")
            if seal.ledger_hash not in known_events:
                seals_ok = False
                problems.append(f"seal references missing ledger hash: {seal.seal_id}")

        return VerificationReport(
            ledger_ok=ledger_ok,
            snapshots_ok=snapshots_ok,
            seals_ok=seals_ok,
            events_checked=len(events),
            snapshots_checked=len(snapshots),
            seals_checked=len(seals),
            problems=tuple(problems),
        )

    def seal(self, statement: str = "") -> Seal:
        self.storage.require_initialized()
        latest = self.latest_snapshot()
        if latest is None:
            raise StorageError("Take a snapshot before creating a seal")
        last = self.storage.last_event()
        if last is None:
            raise StorageError("Ledger is empty")
        seal = Seal(
            seal_id=uuid.uuid4().hex,
            created_at=time.time(),
            ledger_hash=last.hash,
            snapshot_id=latest.snapshot_id,
            merkle_root=latest.merkle_root,
            statement=statement or "Cairn trust anchor",
        )
        with self.storage.write_lock():
            self.storage.save_seal(seal)
            event = self._make_event(
                last.seq + 1,
                "SEAL",
                seal.to_dict(),
                last.hash,
            )
            self.storage.append_event(event)
        return seal

    def explain(self, snapshot_id: str) -> dict[str, Any]:
        snapshot = self.storage.load_snapshot(snapshot_id)
        records = list(snapshot.records)
        extensions = Counter((record.extension or "[none]") for record in records)
        largest = sorted(records, key=lambda record: record.size, reverse=True)[:10]
        sizes = [record.size for record in records]
        return {
            "snapshot": snapshot,
            "extensions": extensions,
            "largest": largest,
            "median_bytes": self._median(sizes),
            "entropy_estimate": self._size_entropy(sizes),
        }

    def compare_fingerprint(self, snapshot_id: str, current: Snapshot) -> bool:
        stored = self.storage.load_snapshot(snapshot_id)
        return stored.merkle_root == current.merkle_root

    def change_score(self, diff: SnapshotDiff) -> float:
        """Compute a bounded structural drift score from 0 to 100.

        The score is not a security claim. It is a compact prioritization
        heuristic combining file-count change, byte change and modification
        count. Its formula is deliberately documented in the manual.
        """

        baseline = max(1, diff.total)
        count_component = min(1.0, diff.changed / baseline)
        old_bytes = sum(item.size for item in diff.removed)
        old_bytes += sum(pair[0].size for pair in diff.modified)
        new_bytes = sum(item.size for item in diff.added)
        new_bytes += sum(pair[1].size for pair in diff.modified)
        byte_component = 0.0
        if max(old_bytes, new_bytes):
            byte_component = min(1.0, abs(new_bytes - old_bytes) / max(old_bytes, new_bytes))
        modification_component = min(1.0, len(diff.modified) / baseline)
        score = 100.0 * (0.50 * count_component + 0.30 * modification_component + 0.20 * byte_component)
        return round(score, 2)

    def _make_event(
        self,
        seq: int,
        event_type: str,
        payload: dict[str, Any],
        previous: str,
    ) -> LedgerEvent:
        provisional = {
            "seq": seq,
            "timestamp": time.time(),
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous,
        }
        digest = chain_digest(previous, provisional)
        return LedgerEvent(
            seq=seq,
            timestamp=float(provisional["timestamp"]),
            event_type=event_type,
            payload=payload,
            previous_hash=previous,
            hash=digest,
        )

    @staticmethod
    def _diff_snapshots(left: Snapshot, right: Snapshot) -> SnapshotDiff:
        a = {record.path: record for record in left.records}
        b = {record.path: record for record in right.records}
        added = []
        removed = []
        modified = []
        unchanged = 0
        for path in sorted(a.keys() | b.keys(), key=str.casefold):
            old = a.get(path)
            new = b.get(path)
            if old is None and new is not None:
                added.append(new)
            elif old is not None and new is None:
                removed.append(old)
            elif old is not None and new is not None:
                if old.sha256 != new.sha256 or old.size != new.size:
                    modified.append((old, new))
                else:
                    unchanged += 1
        return SnapshotDiff(tuple(added), tuple(removed), tuple(modified), unchanged)

    @staticmethod
    def _median(values: list[int]) -> float:
        if not values:
            return 0.0
        values = sorted(values)
        middle = len(values) // 2
        if len(values) % 2:
            return float(values[middle])
        return (values[middle - 1] + values[middle]) / 2.0

    @staticmethod
    def _size_entropy(values: list[int]) -> float:
        """Shannon entropy of exact file sizes, measured in bits."""

        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    def export_anchor_text(self, seal: Seal) -> str:
        """Produce a short text representation suitable for printing/storing."""

        return (
            "CAIRN TRUST ANCHOR\n"
            f"seal_id={seal.seal_id}\n"
            f"snapshot_id={seal.snapshot_id}\n"
            f"ledger_hash={seal.ledger_hash}\n"
            f"merkle_root={seal.merkle_root}\n"
            f"statement={seal.statement}\n"
        )

    def anchor_digest(self, seal: Seal) -> str:
        """Return a compact digest of the portable seal statement."""

        return fingerprint_mapping(seal.to_dict())
