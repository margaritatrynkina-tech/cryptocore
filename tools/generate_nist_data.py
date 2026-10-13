from __future__ import annotations

import sys
from pathlib import Path

# Make `src` importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.csprng import generate_random_bytes  # noqa: E402


def generate_file(path: Path, total_bytes: int, chunk_size: int = 65536) -> None:
    written = 0
    with path.open("wb") as f:
        while written < total_bytes:
            chunk = min(chunk_size, total_bytes - written)
            f.write(generate_random_bytes(chunk))
            written += chunk


def main() -> int:
    size_mb = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    total_bytes = size_mb * 1024 * 1024

    root = Path(__file__).resolve().parent.parent
    out = root / "nist_test_data.bin"

    print(f"Generating {total_bytes} bytes ({size_mb} MB) ...")
    generate_file(out, total_bytes)
    print(f"OK → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())