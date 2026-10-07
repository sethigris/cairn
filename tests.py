"""Small self-test suite for Cairn.

Run with:
    python tests.py

The tests use only temporary directories and standard-library assertions.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cairn.crypto import sha256_text
from cairn.engine import CairnEngine
from cairn.graph import DependencyGraph


def test_hash_determinism() -> None:
    left = sha256_text("cairn")
    right = sha256_text("cairn")
    assert left == right
    assert left != sha256_text("Cairn")


def test_snapshot_diff_and_verify() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "a.txt").write_text("alpha", encoding="utf-8")
        engine = CairnEngine(root)
        engine.init()
        first, _ = engine.snapshot("baseline")
        (root / "a.txt").write_text("beta", encoding="utf-8")
        (root / "b.txt").write_text("new", encoding="utf-8")
        second, _ = engine.snapshot("changed")
        result = engine.diff(first.snapshot_id, second.snapshot_id)
        assert len(result.added) == 1
        assert len(result.modified) == 1
        assert len(result.removed) == 0
        report = engine.verify()
        assert report.ok, report.problems


def test_tamper_is_detected() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "hello.txt").write_text("hello", encoding="utf-8")
        engine = CairnEngine(root)
        engine.init()
        engine.snapshot()
        ledger = root / ".cairn" / "ledger.jsonl"
        lines = ledger.read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[-1])
        data["payload"]["file_count"] = 999
        lines[-1] = json.dumps(data, separators=(",", ":"), sort_keys=True)
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = engine.verify()
        assert not report.ok
        assert any("ledger hash mismatch" in problem for problem in report.problems)


def test_merkle_snapshot_integrity() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "x.txt").write_text("x", encoding="utf-8")
        engine = CairnEngine(root)
        engine.init()
        snapshot, _ = engine.snapshot()
        path = root / ".cairn" / "snapshots" / f"{snapshot.snapshot_id}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["records"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        report = engine.verify()
        assert not report.snapshots_ok


def test_graph_cycles_and_reachability() -> None:
    graph = DependencyGraph()
    graph.add_edge("a", "b", "ab")
    graph.add_edge("b", "c", "bc")
    graph.add_edge("c", "a", "ca")
    graph.add_edge("c", "d", "cd")
    assert graph.reachable("a") == {"a", "b", "c", "d"}
    components = graph.strongly_connected_components()
    assert any(component.cyclic for component in components)
    assert graph.shortest_path("a", "d") == ["a", "b", "c", "d"]


def test_seal() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "x.txt").write_text("x", encoding="utf-8")
        engine = CairnEngine(root)
        engine.init()
        snapshot, _ = engine.snapshot()
        seal = engine.seal("baseline trust anchor")
        assert seal.snapshot_id == snapshot.snapshot_id
        assert seal.ledger_hash
        assert seal.merkle_root == snapshot.merkle_root
        report = engine.verify()
        assert report.ok, report.problems


def main() -> int:
    tests = [
        test_hash_determinism,
        test_snapshot_diff_and_verify,
        test_tamper_is_detected,
        test_merkle_snapshot_integrity,
        test_graph_cycles_and_reachability,
        test_seal,
    ]
    for test in tests:
        test()
        print(f"PASS  {test.__name__}")
    print(f"\n{len(tests)} tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
