from __future__ import annotations

import hashlib


class SHA3_256:

    def __init__(self) -> None:
        self._hasher = hashlib.sha3_256()

    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    def digest(self) -> bytes:
        # We clone the hasher to avoid mutating it
        return self._hasher.copy().digest()

    def hexdigest(self) -> str:
        return self._hasher.copy().hexdigest()