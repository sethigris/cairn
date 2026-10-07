"""Static dependency inference and graph analysis.

This module intentionally avoids language-specific parsers. It extracts likely
local references using small, conservative lexical rules and then analyzes the
resulting directed graph with classic algorithms: reachability, strongly
connected components, PageRank-style influence, and shortest explanation paths.

The output is a heuristic model, not a compiler-grade semantic dependency
analysis. That distinction is a core part of Cairn's design philosophy.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".c", ".h", ".cc",
    ".cpp", ".hpp", ".java", ".cs", ".swift", ".kt", ".kts", ".php", ".rb",
    ".sh", ".ps1", ".md", ".txt", ".toml", ".yaml", ".yml", ".json",
}


@dataclass(frozen=True)
class DependencyEdge:
    source: str
    target: str
    evidence: str
    line: int


@dataclass(frozen=True)
class Component:
    index: int
    members: tuple[str, ...]
    cyclic: bool


@dataclass(frozen=True)
class GraphReport:
    nodes: int
    edges: int
    components: tuple[Component, ...]
    ranks: tuple[tuple[str, float], ...]
    roots: tuple[str, ...]
    leaves: tuple[str, ...]


class DependencyGraph:
    """Directed graph with deterministic adjacency order."""

    def __init__(self):
        self.nodes: set[str] = set()
        self.edges: dict[str, set[str]] = defaultdict(set)
        self.reverse: dict[str, set[str]] = defaultdict(set)
        self.evidence: dict[tuple[str, str], list[str]] = defaultdict(list)

    def add_node(self, node: str) -> None:
        self.nodes.add(node)
        self.edges.setdefault(node, set())
        self.reverse.setdefault(node, set())

    def add_edge(self, source: str, target: str, evidence: str) -> None:
        self.add_node(source)
        self.add_node(target)
        if target not in self.edges[source]:
            self.edges[source].add(target)
            self.reverse[target].add(source)
        if evidence and evidence not in self.evidence[(source, target)]:
            self.evidence[(source, target)].append(evidence)

    def edge_count(self) -> int:
        return sum(len(targets) for targets in self.edges.values())

    def roots(self) -> list[str]:
        return sorted((node for node in self.nodes if not self.reverse[node]), key=str.casefold)

    def leaves(self) -> list[str]:
        return sorted((node for node in self.nodes if not self.edges[node]), key=str.casefold)

    def reachable(self, source: str) -> set[str]:
        if source not in self.nodes:
            return set()
        seen = {source}
        queue = deque([source])
        while queue:
            current = queue.popleft()
            for target in sorted(self.edges[current], key=str.casefold):
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
        return seen

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        if source not in self.nodes or target not in self.nodes:
            return None
        queue = deque([source])
        parent = {source: None}
        while queue:
            current = queue.popleft()
            if current == target:
                break
            for child in sorted(self.edges[current], key=str.casefold):
                if child not in parent:
                    parent[child] = current
                    queue.append(child)
        if target not in parent:
            return None
        path: list[str] = []
        cursor: str | None = target
        while cursor is not None:
            path.append(cursor)
            cursor = parent[cursor]
        return list(reversed(path))

    def strongly_connected_components(self) -> list[Component]:
        """Tarjan's algorithm, implemented iteratively for educational clarity."""

        index = 0
        indices: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        components: list[tuple[str, ...]] = []

        def visit(start: str) -> None:
            nonlocal index
            frames: list[tuple[str, Iterator[str], str | None]] = []
            indices[start] = index
            low[start] = index
            index += 1
            stack.append(start)
            on_stack.add(start)
            frames.append((start, iter(sorted(self.edges[start], key=str.casefold)), None))

            while frames:
                node, children, parent = frames[-1]
                try:
                    child = next(children)
                except StopIteration:
                    frames.pop()
                    if parent is not None:
                        low[parent] = min(low[parent], low[node])
                    if low[node] == indices[node]:
                        members: list[str] = []
                        while True:
                            member = stack.pop()
                            on_stack.remove(member)
                            members.append(member)
                            if member == node:
                                break
                        components.append(tuple(sorted(members, key=str.casefold)))
                    continue

                if child not in indices:
                    indices[child] = index
                    low[child] = index
                    index += 1
                    stack.append(child)
                    on_stack.add(child)
                    frames[-1] = (node, children, parent)
                    frames.append((child, iter(sorted(self.edges[child], key=str.casefold)), node))
                elif child in on_stack:
                    low[node] = min(low[node], indices[child])

        for node in sorted(self.nodes, key=str.casefold):
            if node not in indices:
                visit(node)

        result: list[Component] = []
        for number, members in enumerate(sorted(components, key=lambda item: item[0].casefold())):
            cyclic = len(members) > 1 or (len(members) == 1 and members[0] in self.edges[members[0]])
            result.append(Component(number, members, cyclic))
        return result

    def influence_ranks(self, rounds: int = 30, damping: float = 0.85) -> list[tuple[str, float]]:
        """Calculate a PageRank-like structural influence score."""

        if not self.nodes:
            return []
        if not 0 < damping < 1:
            raise ValueError("damping must be between zero and one")
        if rounds < 1:
            raise ValueError("rounds must be positive")
        nodes = sorted(self.nodes, key=str.casefold)
        count = len(nodes)
        rank = {node: 1.0 / count for node in nodes}
        base = (1.0 - damping) / count
        for _ in range(rounds):
            next_rank = {node: base for node in nodes}
            dangling = sum(rank[node] for node in nodes if not self.edges[node])
            dangling_share = damping * dangling / count
            for node in nodes:
                next_rank[node] += dangling_share
            for source in nodes:
                targets = sorted(self.edges[source], key=str.casefold)
                if not targets:
                    continue
                share = damping * rank[source] / len(targets)
                for target in targets:
                    next_rank[target] += share
            rank = next_rank
        return sorted(rank.items(), key=lambda item: (-item[1], item[0].casefold()))


class DependencyAnalyzer:
    """Infer local source dependencies from a folder."""

    PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")
    C_INCLUDE = re.compile(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]')
    GO_IMPORT = re.compile(r'^\s*import\s+(?:\"([^\"]+)\"|\(\s*$)')
    RUST_USE = re.compile(r"^\s*(?:use|mod)\s+([\w:]+)")
    JS_IMPORT = re.compile(r"(?:from|import\s*\()\s*[\"']([^\"']+)[\"']")
    JS_REQUIRE = re.compile(r"require\(\s*[\"']([^\"']+)[\"']\s*\)")

    def __init__(self, root: Path, limit_bytes: int = 2_000_000):
        self.root = root.resolve()
        self.limit_bytes = limit_bytes

    def analyze(self) -> DependencyGraph:
        graph = DependencyGraph()
        for path in self._files():
            rel = path.relative_to(self.root).as_posix()
            graph.add_node(rel)
            for line_number, line in self._lines(path):
                for candidate, evidence in self._references(path, line):
                    target = self._resolve(candidate)
                    if target is not None:
                        graph.add_edge(rel, target, f"line {line_number}: {evidence}")
        return graph

    def _files(self) -> list[Path]:
        files = []
        for path in self.root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if ".cairn" in path.parts or ".git" in path.parts:
                continue
            try:
                if path.stat().st_size <= self.limit_bytes and path.suffix.lower() in TEXT_EXTENSIONS:
                    files.append(path)
            except OSError:
                continue
        return sorted(files, key=lambda item: item.relative_to(self.root).as_posix().casefold())

    def _lines(self, path: Path) -> Iterator[tuple[int, str]]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, start=1):
                    yield number, line.rstrip("\n")
        except OSError:
            return

    def _references(self, path: Path, line: str) -> list[tuple[str, str]]:
        suffix = path.suffix.lower()
        matches: list[tuple[str, str]] = []
        if suffix == ".py":
            match = self.PY_IMPORT.search(line)
            if match:
                value = match.group(1) or match.group(2)
                if value:
                    matches.append((value, value))
        elif suffix in {".c", ".h", ".cc", ".cpp", ".hpp"}:
            match = self.C_INCLUDE.search(line)
            if match:
                matches.append((match.group(1), match.group(1)))
        elif suffix == ".go":
            match = self.GO_IMPORT.search(line)
            if match and match.group(1):
                matches.append((match.group(1), match.group(1)))
        elif suffix == ".rs":
            match = self.RUST_USE.search(line)
            if match:
                value = match.group(1).replace("::", "/")
                matches.append((value, value))
        elif suffix in {".js", ".ts", ".jsx", ".tsx"}:
            for regex in (self.JS_IMPORT, self.JS_REQUIRE):
                for match in regex.finditer(line):
                    matches.append((match.group(1), match.group(1)))
        return matches

    def _resolve(self, raw: str) -> str | None:
        candidate = raw.replace("\\", "/")
        if candidate.startswith("."):
            path = Path(candidate)
        else:
            path = Path(candidate.replace(".", "/"))
        candidates = []
        if path.suffix:
            candidates.append(self.root / path)
        else:
            for extension in TEXT_EXTENSIONS:
                candidates.append(self.root / Path(str(path) + extension))
            candidates.append(self.root / path / "index.ts")
            candidates.append(self.root / path / "index.js")
            candidates.append(self.root / path / "mod.rs")
            candidates.append(self.root / path / "__init__.py")
        for item in candidates:
            try:
                if item.is_file():
                    return item.relative_to(self.root).as_posix()
            except (OSError, ValueError):
                pass
        return None


def summarize_graph(graph: DependencyGraph) -> GraphReport:
    components = tuple(graph.strongly_connected_components())
    cyclic = [component for component in components if component.cyclic]
    ranks = tuple(graph.influence_ranks()[:20])
    # Nodes with no incoming edges are architectural roots in the inferred graph.
    roots = tuple(graph.roots()[:20])
    leaves = tuple(graph.leaves()[:20])
    return GraphReport(
        nodes=len(graph.nodes),
        edges=graph.edge_count(),
        components=tuple(components),
        ranks=ranks,
        roots=roots,
        leaves=leaves,
    )
