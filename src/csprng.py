from __future__ import annotations

import os


BLOCK_SIZE = 16
KEY_SIZE = 16


class CSPRNGError(Exception):
    """Raised when the OS random source fails."""


def generate_random_bytes(num_bytes: int) -> bytes:
    if not isinstance(num_bytes, int) or isinstance(num_bytes, bool):
        raise TypeError(f"num_bytes must be an int, got {type(num_bytes).__name__}")
    if num_bytes < 0:
        raise ValueError(f"num_bytes must be >= 0, got {num_bytes}")
    if num_bytes == 0:
        return b""

    try:
        return os.urandom(num_bytes)
    except OSError as e:
        raise CSPRNGError(
            f"OS random source failed for {num_bytes} bytes: {e}"
        ) from e


def generate_key(key_size: int = KEY_SIZE) -> bytes:
    """Generate a random AES key (16 bytes for AES-128)."""
    return generate_random_bytes(key_size)


def generate_iv() -> bytes:
    """Generate a random 16-byte IV for AES block cipher modes."""
    return generate_random_bytes(BLOCK_SIZE)