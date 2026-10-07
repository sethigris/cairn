"""Command-line interface for Cairn."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .engine import CairnEngine
from .graph import DependencyAnalyzer, summarize_graph
from .model import FileRecord, LedgerEvent, Seal, Snapshot
from .storage import StorageError


APP_NAME = "Cairn"
VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairn",
        description=(
            "Offline filesystem state, Merkle proofs, and a tamper-evident history ledger."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a Cairn repository in the current folder")
    init.add_argument("--ignore", action="append", default=[], help="extra glob to ignore; repeatable")

    snap = sub.add_parser("snapshot", help="hash the current folder state")
    snap.add_argument("--note", default="", help="human note for this observation")

    diff = sub.add_parser("diff", help="compare two snapshots")
    diff.add_argument("older")
    diff.add_argument("newer")

    history = sub.add_parser("history", help="show the append-only ledger")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="verify ledger, Merkle trees and seals")
    verify.add_argument("--json", action="store_true")

    seal = sub.add_parser("seal", help="create a portable trust anchor from the latest snapshot")
    seal.add_argument("--statement", default="", help="optional human statement")

    show = sub.add_parser("show", help="inspect one snapshot")
    show.add_argument("snapshot_id")
    show.add_argument("--files", action="store_true", help="list all recorded files")

    inspect = sub.add_parser("inspect", help="show useful statistics for one snapshot")
    inspect.add_argument("snapshot_id")

    graph = sub.add_parser("graph", help="infer local source dependencies and analyze the graph")
    graph.add_argument("--path", default=".", help="project folder to analyze")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    engine = CairnEngine(Path.cwd())
    try:
        if args.command == "init":
            engine.init(args.ignore)
            print("Initialized Cairn repository.")
            print(f"Root: {engine.storage.root}")
            return 0
        if args.command == "snapshot":
            return command_snapshot(engine, args.note)
        if args.command == "diff":
            return command_diff(engine, args.older, args.newer)
        if args.command == "history":
            return command_history(engine, args.limit, args.json)
        if args.command == "verify":
            return command_verify(engine, args.json)
        if args.command == "seal":
            return command_seal(engine, args.statement)
        if args.command == "show":
            return command_show(engine, args.snapshot_id, args.files)
        if args.command == "inspect":
            return command_inspect(engine, args.snapshot_id)
        if args.command == "graph":
            return command_graph(Path(args.path).resolve())
        parser.error("unknown command")
        return 2
    except (StorageError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def command_snapshot(engine: CairnEngine, note: str) -> int:
    snapshot, summary = engine.snapshot(note)
    print(f"Snapshot: {snapshot.snapshot_id}")
    print(f"Files:    {summary.files}")
    print(f"Bytes:    {summary.bytes}")
    print(f"Ignored:  {summary.ignored}")
    print(f"Errors:   {summary.errors}")
    print(f"Time:     {summary.elapsed:.3f}s")
    print(f"Merkle:   {snapshot.merkle_root}")
    if note:
        print(f"Note:     {note}")
    return 0 if summary.errors == 0 else 2


def command_diff(engine: CairnEngine, older: str, newer: str) -> int:
    result = engine.diff(older, newer)
    print(f"Added:     {len(result.added)}")
    print(f"Removed:   {len(result.removed)}")
    print(f"Modified:  {len(result.modified)}")
    print(f"Unchanged: {result.unchanged}")
    print(f"Drift:     {engine.change_score(result):.2f}/100")
    if result.added:
        print("\nADDED")
        for record in result.added:
            print(f"+ {record.path} ({record.size} B)")
    if result.removed:
        print("\nREMOVED")
        for record in result.removed:
            print(f"- {record.path} ({record.size} B)")
    if result.modified:
        print("\nMODIFIED")
        for old, new in result.modified:
            print(f"~ {old.path} ({old.size} -> {new.size} B)")
            print(f"  {old.sha256[:16]} -> {new.sha256[:16]}")
    return 0


def command_history(engine: CairnEngine, limit: int, as_json: bool) -> int:
    events = engine.history(limit)
    if as_json:
        print(json.dumps([event.to_dict() for event in events], indent=2, ensure_ascii=False))
        return 0
    for event in events:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
        print(f"#{event.seq:<4} {stamp} {event.event_type:<9} {event.hash[:16]}")
        payload = dict(event.payload)
        if event.event_type == "SNAPSHOT":
            print(
                f"      snapshot={payload.get('snapshot_id')} "
                f"files={payload.get('file_count')} bytes={payload.get('total_bytes')}"
            )
            if payload.get("note"):
                print(f"      note={payload['note']}")
    return 0


def command_verify(engine: CairnEngine, as_json: bool) -> int:
    report = engine.verify()
    if as_json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "ledger_ok": report.ledger_ok,
                    "snapshots_ok": report.snapshots_ok,
                    "seals_ok": report.seals_ok,
                    "events_checked": report.events_checked,
                    "snapshots_checked": report.snapshots_checked,
                    "seals_checked": report.seals_checked,
                    "problems": list(report.problems),
                },
                indent=2,
            )
        )
    else:
        print(f"Ledger:    {'OK' if report.ledger_ok else 'FAIL'}")
        print(f"Snapshots: {'OK' if report.snapshots_ok else 'FAIL'}")
        print(f"Seals:     {'OK' if report.seals_ok else 'FAIL'}")
        print(f"Events:    {report.events_checked}")
        print(f"Snapshots: {report.snapshots_checked}")
        print(f"Seals:     {report.seals_checked}")
        if report.problems:
            print("\nProblems:")
            for problem in report.problems:
                print(f"- {problem}")
        else:
            print("\nIntegrity verification passed.")
    return 0 if report.ok else 3


def command_seal(engine: CairnEngine, statement: str) -> int:
    seal = engine.seal(statement)
    print("Trust anchor created.")
    print(f"Seal:      {seal.seal_id}")
    print(f"Snapshot:  {seal.snapshot_id}")
    print(f"Ledger:    {seal.ledger_hash}")
    print(f"Merkle:    {seal.merkle_root}")
    print(f"Anchor ID: {engine.anchor_digest(seal)}")
    print("\nPortable statement:\n")
    print(engine.export_anchor_text(seal), end="")
    print("\nKeep a copy outside .cairn if the anchor is meant to provide independent trust.")
    return 0


def command_show(engine: CairnEngine, snapshot_id: str, show_files: bool) -> int:
    snapshot = engine.storage.load_snapshot(snapshot_id)
    print(f"Snapshot : {snapshot.snapshot_id}")
    print(f"Root     : {snapshot.root}")
    print(f"Captured : {time.ctime(snapshot.captured_at)}")
    print(f"Files    : {snapshot.file_count}")
    print(f"Bytes    : {snapshot.total_bytes}")
    print(f"Merkle   : {snapshot.merkle_root}")
    if show_files:
        print("\nFILES")
        for record in snapshot.records:
            print(f"{record.path}\t{record.size}\t{record.sha256}")
    return 0


def command_inspect(engine: CairnEngine, snapshot_id: str) -> int:
    info = engine.explain(snapshot_id)
    snapshot: Snapshot = info["snapshot"]
    print(f"Snapshot: {snapshot.snapshot_id}")
    print(f"Median file size: {info['median_bytes']:.1f} B")
    print(f"Size entropy:     {info['entropy_estimate']:.4f} bits")
    print("\nFile types:")
    for extension, count in info["extensions"].most_common():
        print(f"  {extension:<12} {count}")
    print("\nLargest files:")
    for record in info["largest"]:
        print(f"  {record.size:>12} B  {record.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def command_graph(root: Path) -> int:
    analyzer = DependencyAnalyzer(root)
    graph = analyzer.analyze()
    report = summarize_graph(graph)
    print(f"Root:  {root}")
    print(f"Nodes: {report.nodes}")
    print(f"Edges: {report.edges}")
    cyclic = [component for component in report.components if component.cyclic]
    print(f"SCCs:  {len(report.components)}")
    print(f"Cycles:{len(cyclic)}")
    if cyclic:
        print("\nPotential dependency cycles:")
        for component in cyclic[:20]:
            print("  " + " -> ".join(component.members))
    print("\nInfluence ranking:")
    for name, score in report.ranks[:15]:
        print(f"  {score:0.6f}  {name}")
    if report.roots:
        print("\nRoots:")
        for name in report.roots[:15]:
            print(f"  {name}")
    if report.leaves:
        print("\nLeaves:")
        for name in report.leaves[:15]:
            print(f"  {name}")
    return 0
