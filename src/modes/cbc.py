from __future__ import annotations

from Crypto.Cipher import AES

from .base import ModeBase, BLOCK_SIZE, KEY_SIZE, pkcs7_pad, pkcs7_unpad


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class CBCMode(ModeBase):

    name = "cbc"
    needs_padding = True
    needs_iv = True

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("CBC requires a 16-byte IV")

        padded = pkcs7_pad(plaintext, BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_ECB)

        prev = iv
        output = bytearray()
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i + BLOCK_SIZE]
            xored = _xor_bytes(block, prev)
            encrypted = cipher.encrypt(xored)
            output.extend(encrypted)
            prev = encrypted  # next iteration XORs with this ciphertext

        return bytes(output)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("CBC requires a 16-byte IV")
        if len(ciphertext) == 0:
            raise ValueError("Empty ciphertext")
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError(
                f"CBC ciphertext length must be a multiple of {BLOCK_SIZE}, "
                f"got {len(ciphertext)}"
            )

        cipher = AES.new(key, AES.MODE_ECB)

        prev = iv
        output = bytearray()
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            decrypted = cipher.decrypt(block)
            xored = _xor_bytes(decrypted, prev)
            output.extend(xored)
            prev = block  # next iteration XORs with this ciphertext block

        return pkcs7_unpad(bytes(output), BLOCK_SIZE)