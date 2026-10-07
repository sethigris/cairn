"""Windows-friendly launcher for Cairn.

Usage from the project directory:
    python cairn.py init
    python cairn.py snapshot
    python cairn.py verify
"""

from cairn.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
