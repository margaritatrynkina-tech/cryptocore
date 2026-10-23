from .sha256 import SHA256
from .sha3_256 import SHA3_256

HASHES = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def get_hasher(name: str):
    if name not in HASHES:
        available = ", ".join(sorted(HASHES))
        raise ValueError(f"Unknown hash algorithm: {name!r}. Available: {available}")
    return HASHES[name]()