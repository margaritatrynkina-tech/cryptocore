from __future__ import annotations

from abc import ABC, abstractmethod


BLOCK_SIZE = 16
KEY_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size < 1 or block_size > 255:
        raise ValueError(f"block_size must be 1..255, got {block_size}")

    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(data) == 0:
        raise ValueError("Empty data")
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block size")

    padding_len = data[-1]
    if padding_len == 0 or padding_len > block_size:
        raise ValueError(f"Invalid padding length: {padding_len}")
    if len(data) < padding_len:
        raise ValueError("Data too short for declared padding")

    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid padding: bytes do not match")

    return data[:-padding_len]


class ModeBase(ABC):

    name: str = "base"
    needs_padding: bool = True
    needs_iv: bool = False

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        """Encrypt plaintext. Returns ciphertext (without IV)."""

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        """Decrypt ciphertext. Returns plaintext (without IV)."""