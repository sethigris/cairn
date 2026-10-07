"""Cryptographic and deterministic primitives used by Cairn.

Cairn deliberately uses only primitives available in Python's standard library.
The goal is not to build a cryptography library; the goal is to make the
integrity rules of the application explicit and auditable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence


HASH_ALGORITHM = "sha256"
CHUNK_SIZE = 1024 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class IntegrityError(Exception):
    """Raised when a stored integrity relation does not hold."""


def canonical_json(value: object) -> bytes:
    """Serialize a JSON-compatible value deterministically.

    Stable serialization is important because a single byte difference would
    otherwise change every later hash in the ledger.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of bytes."""

    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return the SHA-256 digest of UTF-8 encoded text."""

    return sha256_bytes(text.encode("utf-8"))


def hash_file(path: Path, chunk_size: int = CHUNK_SIZE) -> tuple[str, int]:
    """Hash a file incrementally and return ``(digest, bytes_read)``."""

    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total


def event_digest(event_without_hash: Mapping[str, object]) -> str:
    """Hash the canonical event body."""

    return sha256_bytes(canonical_json(event_without_hash))


def chain_digest(previous: str, event_without_hash: Mapping[str, object]) -> str:
    """Compute the digest linking this event to its predecessor."""

    body = canonical_json(event_without_hash)
    link = previous.encode("ascii") + b"\n" + body
    return sha256_bytes(link)


def merkle_leaf(path: str, digest: str, size: int) -> str:
    """Create a leaf digest for one file in a snapshot.

    The relative path is part of the leaf, so replacing one file with another
    file having the same bytes but a different path still changes the tree.
    """

    payload = "file\0{}\0{}\0{}".format(path, digest, size).encode("utf-8")
    return sha256_bytes(payload)


def merkle_root(leaves: Sequence[str]) -> str:
    """Return a deterministic binary Merkle root.

    Leaves are expected to already be in canonical path order. An odd last
    node is duplicated, which keeps the tree binary without inventing a null
    value whose semantics could be confused with an absent file.
    """

    if not leaves:
        return sha256_text("CAIRN:EMPTY-TREE")

    level = list(leaves)
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(sha256_text("node\0" + left + "\0" + right))
        level = next_level
    return level[0]


def merkle_root_from_records(records: Iterable[Mapping[str, object]]) -> str:
    """Build a Merkle root from snapshot record mappings."""

    leaves = []
    for record in records:
        leaves.append(
            merkle_leaf(
                str(record["path"]),
                str(record["sha256"]),
                int(record["size"]),
            )
        )
    return merkle_root(leaves)


def hmac_sha256(key: bytes, data: bytes) -> str:
    """Calculate a SHA-256 HMAC for optional external trust anchors."""

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    """Compare digest strings without ordinary early-exit comparison."""

    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def fingerprint_mapping(mapping: Mapping[str, object]) -> str:
    """Hash an arbitrary JSON-compatible mapping deterministically."""

    return sha256_bytes(canonical_json(mapping))


def short_digest(digest: str, length: int = 12) -> str:
    """Return a display-friendly digest prefix."""

    if length < 1:
        raise ValueError("length must be positive")
    return digest[:length]
