from __future__ import annotations

from Crypto.Cipher import AES

from .base import ModeBase, BLOCK_SIZE, KEY_SIZE, pkcs7_pad, pkcs7_unpad


class ECBMode(ModeBase):

    name = "ecb"
    needs_padding = True
    needs_iv = False

    def encrypt(self, plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )

        padded = pkcs7_pad(plaintext, BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_ECB)

        # Manual block-by-block encryption
        output = bytearray()
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i + BLOCK_SIZE]
            output.extend(cipher.encrypt(block))

        return bytes(output)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if len(key) != KEY_SIZE:
            raise ValueError(
                f"Key must be {KEY_SIZE} bytes (AES-128), got {len(key)}"
            )
        if len(ciphertext) == 0:
            raise ValueError("Empty ciphertext")
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {BLOCK_SIZE}, "
                f"got {len(ciphertext)}"
            )

        cipher = AES.new(key, AES.MODE_ECB)

        # Manual block-by-block decryption
        output = bytearray()
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            output.extend(cipher.decrypt(block))

        return pkcs7_unpad(bytes(output), BLOCK_SIZE)

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    return ECBMode().encrypt(plaintext, key)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    return ECBMode().decrypt(ciphertext, key)