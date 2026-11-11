from __future__ import annotations

from typing import Callable, Any
from src.hash.sha256 import SHA256


class HMAC:
    def __init__(self, key: bytes, hash_cls: Callable = SHA256):
        self.hash_cls = hash_cls
        # For SHA-256 block size is 64 bytes.
        self.block_size = 64

        # MAC-2: Process the key
        self.key = self._process_key(key)

    def _process_key(self, key: bytes) -> bytes:
        if len(key) > self.block_size:
            # Hash the key
            hasher = self.hash_cls()
            hasher.update(key)
            key = hasher.digest()

        if len(key) < self.block_size:
            key = key + b"\x00" * (self.block_size - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")

    def _create_context(self) -> tuple[Any, Any]:
        ipad = self._xor_bytes(self.key, b"\x36" * self.block_size)
        opad = self._xor_bytes(self.key, b"\x5c" * self.block_size)

        inner = self.hash_cls()
        inner.update(ipad)

        outer = self.hash_cls()
        outer.update(opad)

        return inner, outer

    def compute(self, message: bytes) -> bytes:
        inner, outer = self._create_context()
        inner.update(message)
        inner_digest = inner.digest()

        outer.update(inner_digest)
        return outer.digest()

    def hexdigest(self, message: bytes) -> str:
        return self.compute(message).hex()


class HMACStream:
    def __init__(self, key: bytes, hash_cls: Callable = SHA256):
        self._hmac_base = HMAC(key, hash_cls)
        self._inner, self._outer = self._hmac_base._create_context()

    def update(self, data: bytes) -> None:
        self._inner.update(data)

    def digest(self) -> bytes:
        inner_digest = self._inner.digest()
        # We need a fresh outer state, so we re-create it from scratch.
        # (In our implementation, outer is already initialized with opad).
        self._outer.update(inner_digest)
        return self._outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()