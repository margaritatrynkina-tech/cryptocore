from __future__ import annotations

from Crypto.Cipher import AES

from .base import ModeBase, BLOCK_SIZE, KEY_SIZE


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


class OFBMode(ModeBase):

    name = "ofb"
    needs_padding = False
    needs_iv = True

    def _xor_with_keystream(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        prev = iv
        output = bytearray()

        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            prev = cipher.encrypt(prev)          # next keystream block
            output.extend(_xor_bytes(block, prev[:len(block)]))

        return bytes(output)

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("OFB requires a 16-byte IV")

        return self._xor_with_keystream(plaintext, key, iv)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        # OFB is symmetric: decryption = encryption
        return self.encrypt(ciphertext, key, iv)