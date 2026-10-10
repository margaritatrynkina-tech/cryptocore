from __future__ import annotations

from Crypto.Cipher import AES

from .base import ModeBase, BLOCK_SIZE, KEY_SIZE


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _increment_counter(counter: bytes) -> bytes:
    n = int.from_bytes(counter, "big")
    n = (n + 1) % (1 << 128)
    return n.to_bytes(BLOCK_SIZE, "big")


class CTRMode(ModeBase):
    name = "ctr"
    needs_padding = False
    needs_iv = True

    def _xor_with_keystream(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        counter = iv
        output = bytearray()

        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            keystream = cipher.encrypt(counter)
            output.extend(_xor_bytes(block, keystream[:len(block)]))
            counter = _increment_counter(counter)

        return bytes(output)

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("CTR requires a 16-byte IV")

        return self._xor_with_keystream(plaintext, key, iv)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        # CTR is symmetric: decryption = encryption
        return self.encrypt(ciphertext, key, iv)