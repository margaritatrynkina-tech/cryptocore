from __future__ import annotations

from Crypto.Cipher import AES

from .base import ModeBase, BLOCK_SIZE, KEY_SIZE


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


class CFBMode(ModeBase):

    name = "cfb"
    needs_padding = False
    needs_iv = True

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("CFB requires a 16-byte IV")

        cipher = AES.new(key, AES.MODE_ECB)
        prev = iv
        output = bytearray()

        for i in range(0, len(plaintext), BLOCK_SIZE):
            block = plaintext[i:i + BLOCK_SIZE]
            keystream = cipher.encrypt(prev)
            encrypted = _xor_bytes(block, keystream[:len(block)])
            output.extend(encrypted)

            if len(encrypted) == BLOCK_SIZE:
                prev = encrypted
            else:
                # Last (partial) block — pad with zeros for feedback.
                # No more iterations follow, so this doesn't affect output.
                prev = encrypted + b"\x00" * (BLOCK_SIZE - len(encrypted))

        return bytes(output)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("CFB requires a 16-byte IV")

        cipher = AES.new(key, AES.MODE_ECB)
        prev = iv
        output = bytearray()

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            keystream = cipher.encrypt(prev)
            decrypted = _xor_bytes(block, keystream[:len(block)])
            output.extend(decrypted)

            if len(block) == BLOCK_SIZE:
                prev = block  # feedback = ciphertext block
            else:
                prev = block + b"\x00" * (BLOCK_SIZE - len(block))

        return bytes(output)