# Cairn — Instruction Manual

## 1. What Cairn is

Cairn is a small offline research/systems utility that models a folder as a mathematical **state**.

A state is the set of observed files. For each file, Cairn records its relative path, byte size, modification timestamp, permission bits when available, and a SHA-256 content digest.

From those file records Cairn computes a **Merkle root**. The root is a compact fingerprint of the whole snapshot. Changing a file's bytes, size, or path changes the corresponding leaf and therefore changes the root.

Snapshots are connected by an **append-only hash-chain ledger**. Each ledger event contains the previous event's digest. Altering one historical event therefore invalidates that event's digest and the chain that follows it.

Cairn also has a lightweight static **dependency graph analyzer**. It heuristically finds local source references and applies graph algorithms including reachability, strongly connected components, and PageRank-like influence ranking.

The project uses only the Python standard library. There are no pip dependencies.

---

## 2. Requirements

- Windows 10 or later.
- Python 3.10+ recommended.
- No administrator privileges required for normal use.
- A writable folder.

Cairn does not need Linux, namespaces, a database server, a browser, or an internet connection.

---

## 3. Project layout

```text
cairn/
    cairn.py                 launcher
    cairn/
        __init__.py
        cli.py                command line interface
        crypto.py             hashes and Merkle primitives
        engine.py             state machine and verification
        graph.py              dependency inference and graph algorithms
        model.py              immutable data models
        scanner.py            deterministic filesystem scanner
        storage.py            JSON/JSONL persistence
    tests.py                 standard-library self tests
    MANUAL.md                this manual
```

The `.cairn` directory is created **inside the folder being tracked**.

---

## 4. First run on Windows 10

Open Command Prompt or PowerShell and move into the folder you want to study.

Example:

```powershell
cd C:\Users\YourName\Documents\MyProject
```

Run:

```powershell
python C:\path\to\cairn.py init
```

Then make the first observation:

```powershell
python C:\path\to\cairn.py snapshot --note "baseline"
```

Cairn will report the snapshot identifier and the Merkle root.

---

## 5. Core workflow

### Initialize

```powershell
python C:\path\to\cairn.py init
```

This creates:

```text
.cairn\
    config.json
    ledger.jsonl
    snapshots\
    seals\
```

Initialization creates the genesis ledger event.

### Take a snapshot

```powershell
python C:\path\to\cairn.py snapshot
```

With a note:

```powershell
python C:\path\to\cairn.py snapshot --note "before refactor"
```

Repeat this whenever you want a new state observation.

### Inspect snapshot history

```powershell
python C:\path\to\cairn.py history
```

The output shows event sequence numbers, event type, timestamp, and hash prefix.

JSON output is available for scripting:

```powershell
python C:\path\to\cairn.py history --json
```

### Show a snapshot

```powershell
python C:\path\to\cairn.py show SNAPSHOT_ID
```

List every recorded file:

```powershell
python C:\path\to\cairn.py show SNAPSHOT_ID --files
```

### Compare two states

```powershell
python C:\path\to\cairn.py diff OLDER_ID NEWER_ID
```

Cairn classifies observations as:

- added
- removed
- modified
- unchanged

It also produces a **drift score** from 0 to 100. The drift score is only a prioritization heuristic, not a security verdict.

---

## 6. How the important mathematics works

### 6.1 File hash

For each file, Cairn calculates:

`H(file) = SHA256(file bytes)`

The file is read in chunks so a large file does not need to be loaded entirely into RAM.

### 6.2 Merkle leaf

A leaf is derived from the path, content digest, and size:

`L = SHA256("file" || path || SHA256(file) || size)`

The path is included deliberately. Two equal files at different paths therefore produce different leaves.

### 6.3 Merkle parent

Two neighboring child hashes form a parent:

`P = SHA256("node" || left || right)`

When there is an odd child at a level, Cairn duplicates the final child.

The final remaining hash is the snapshot's Merkle root.

The important property is that the complete state is compressed into one digest while still being constructed from every recorded file.

### 6.4 Hash-chain ledger

For event `E_n`, Cairn stores the previous event hash `C_(n-1)` and computes:

`C_n = SHA256(C_(n-1) || canonical_json(E_n))`

The canonical JSON representation is sorted and uses fixed separators. This prevents harmless JSON formatting changes from changing the mathematical meaning of an event.

If event 12 is edited, its digest becomes wrong. If someone recalculates event 12 but does not also rebuild every later event, the predecessor relation breaks.

### 6.5 Why a local seal matters

A local hash chain cannot magically detect an attacker who is allowed to rewrite **both the data and every integrity value**.

Cairn therefore supports a trust anchor called a **seal**. A seal records a snapshot Merkle root and a ledger hash in a small statement that can be copied somewhere outside `.cairn`.

The important model is:

`local state + external anchor = independently checkable history point`

The security boundary is the place where the external anchor is kept.

---

## 7. Create a trust anchor

First make a snapshot, then:

```powershell
python C:\path\to\cairn.py seal --statement "release candidate 1"
```

Cairn prints a portable block similar to:

```text
CAIRN TRUST ANCHOR
seal_id=...
snapshot_id=...
ledger_hash=...
merkle_root=...
statement=release candidate 1
```

Copy that block into a separate text file, print it, store it in another repository, or otherwise keep it outside the `.cairn` directory.

The most useful experiment is to intentionally change a file or ledger record and run verification.

---

## 8. Verify integrity

Run:

```powershell
python C:\path\to\cairn.py verify
```

Successful output contains:

```text
Ledger:    OK
Snapshots: OK
Seals:     OK
```

Machine-readable output:

```powershell
python C:\path\to\cairn.py verify --json
```

Verification checks:

1. ledger sequence continuity;
2. previous-hash continuity;
3. event digest correctness;
4. snapshot record count;
5. snapshot byte totals;
6. Merkle root reconstruction;
7. seal-to-snapshot consistency;
8. seal-to-ledger references.

---

## 9. Dependency graph analysis

Cairn can also inspect a source tree without a compiler or external parser.

Run it from any folder:

```powershell
python C:\path\to\cairn.py graph
```

Or specify another folder:

```powershell
python C:\path\to\cairn.py graph --path C:\Users\YourName\Documents\Project
```

The analyzer looks for common local references in Python, JavaScript/TypeScript, Go, Rust, C/C++, and related text formats.

It then computes:

- number of nodes and directed edges;
- strongly connected components;
- potential dependency cycles;
- influential nodes using a PageRank-style iterative calculation;
- graph roots;
- graph leaves.

### Important limitation

This is **heuristic static analysis**, not a compiler. It deliberately trades perfect semantic understanding for being tiny, offline, dependency-free, and easy to audit.

A result such as "cycle" means "the inferred reference graph contains a cycle," not "the language compiler will definitely reject this code."

---

## 10. Snapshot inspection

Use:

```powershell
python C:\path\to\cairn.py inspect SNAPSHOT_ID
```

Cairn reports:

- median file size;
- Shannon entropy of file-size distribution;
- file-type counts;
- largest files.

The entropy here is not cryptographic entropy. It answers a different question: **how diverse are the observed file sizes?**

For file sizes `s_1 ... s_n`, the calculation groups equal sizes and computes:

`H = -sum(p_i log2(p_i))`

where `p_i` is the fraction of files having size class `i`.

---

## 11. Ignore rules

Cairn already ignores common generated metadata such as `.git`, `__pycache__`, `*.pyc`, and `.cairn` itself.

Add a custom rule during initialization:

```powershell
python C:\path\to\cairn.py init --ignore build --ignore dist --ignore "*.tmp"
```

Rules are glob-style patterns.

For an important project, decide the trust boundary before your first snapshot. Ignoring a directory means that directory is outside the observed state.

---

## 12. A practical workflow for software engineering

Suppose you are experimenting with a compiler component.

Start:

```powershell
python C:\path\to\cairn.py init
python C:\path\to\cairn.py snapshot --note "working baseline"
```

Do your changes. Then:

```powershell
python C:\path\to\cairn.py snapshot --note "after parser change"
```

Compare the two snapshots:

```powershell
python C:\path\to\cairn.py history
python C:\path\to\cairn.py diff FIRST_ID SECOND_ID
```

When a state deserves an independent checkpoint:

```powershell
python C:\path\to\cairn.py seal --statement "known-good parser state"
```

Later, run:

```powershell
python C:\path\to\cairn.py verify
```

This gives you a lightweight experimental provenance trail without introducing Git, SQLite, a cloud service, or a third-party package.

---

## 13. Recommended experiments

### Experiment A — prove a one-byte change propagates

Take a snapshot. Change one byte in a file. Take another snapshot. Compare the Merkle roots.

You should observe that one file changes but the root for the entire state changes.

### Experiment B — break the ledger deliberately

Open `.cairn\ledger.jsonl` in a text editor. Change a harmless value in an old payload without rebuilding its hashes.

Run:

```powershell
python C:\path\to\cairn.py verify
```

Verification should fail.

Restore the original repository afterward.

### Experiment C — create a dependency cycle

Create three tiny source files with local references:

`a.py -> b.py -> c.py -> a.py`

Run:

```powershell
python C:\path\to\cairn.py graph
```

The strongly connected component calculation should identify the cycle.

### Experiment D — compare architecture before and after refactoring

Take a snapshot before a refactor and another after. Run both `diff` and `graph`.

The snapshot system answers **what changed on disk**.

The dependency graph answers **what relationships appear to exist in the source tree**.

These are different observations of the same engineering system.

---

## 14. Why Cairn is intentionally small

Cairn is not trying to replace Git, antivirus software, a compiler, or a forensic suite.

Its purpose is to demonstrate a deeper systems idea:

> A practical tool can be built by defining a state precisely, selecting a compact invariant, and making every transition auditable.

The implementation therefore favors:

- deterministic representations;
- explicit data structures;
- standard-library primitives;
- append-only persistence;
- simple failure behavior;
- algorithms that can be read and reasoned about.

---

## 15. Running the tests

From the Cairn project directory:

```powershell
python tests.py
```

You should see six passing tests.

The tests cover:

- deterministic hashing;
- snapshot creation and diffing;
- ledger tamper detection;
- Merkle tamper detection;
- graph cycle/reachability behavior;
- seals.

---

## 16. Safety and limitations

Cairn hashes file contents; it does not make the files immutable.

Cairn is not a replacement for backups.

A snapshot records an observation taken at a particular instant. Files can change while a snapshot is being taken. A later snapshot can reveal that the directory moved between states, but it cannot retroactively make the original observation atomic across the whole Windows filesystem.

The permission and mode information should be treated as supplementary metadata on Windows rather than as a complete NTFS security-descriptor model.

The local lock is deliberately simple. If a process crashes while holding the lock, the lock file may need manual removal after verifying that no Cairn process is writing.

Finally, cryptographic hashes provide integrity evidence; they do not prove authorship, intent, or that a state is "good." Those are separate questions.

---

## 17. Command reference

```text
cairn init [--ignore PATTERN]
cairn snapshot [--note TEXT]
cairn diff OLDER_ID NEWER_ID
cairn history [--limit N] [--json]
cairn verify [--json]
cairn seal [--statement TEXT]
cairn show SNAPSHOT_ID [--files]
cairn inspect SNAPSHOT_ID
cairn graph [--path PATH]
cairn --version
```

That is the complete interface for version 1.0.
