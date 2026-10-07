# Cairn

**Cairn** is a pure-standard-library Python tool for turning a folder into an observable mathematical state.

It provides:

- deterministic filesystem snapshots;
- SHA-256 file fingerprints;
- Merkle roots for whole-folder state;
- an append-only hash-chain history ledger;
- portable trust-anchor seals;
- snapshot-to-snapshot drift analysis;
- heuristic source dependency graphs;
- Tarjan strongly connected components for cycle detection;
- PageRank-style structural influence ranking;
- no external Python packages.

## Windows 10

```powershell
python cairn.py init
python cairn.py snapshot --note "baseline"
python cairn.py verify
```

For a double-click-friendly wrapper, use `run_cairn.bat`.

Read **MANUAL.md** before using the integrity model seriously.

Run the self-tests with:

```powershell
python tests.py
```
