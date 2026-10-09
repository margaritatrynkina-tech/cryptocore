from Crypto.Cipher import AES
from typing import Tuple


# Константы
BLOCK_SIZE = 16  # Размер блока AES в байтах
KEY_SIZE = 16    # Размер ключа AES-128 в байтах


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size < 1 or block_size > 255:
        raise ValueError(f"Размер блока должен быть от 1 до 255, получено {block_size}")

    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Пустые данные")

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Длина данных должна быть кратна размеру блока")

    padding_len = data[-1]

    # Проверка корректности значения padding
    if padding_len == 0 or padding_len > BLOCK_SIZE:
        raise ValueError(f"Некорректный размер padding: {padding_len}")

    if len(data) < padding_len:
        raise ValueError("Данные слишком короткие для указанного padding")

    # Проверка, что все байты padding одинаковы
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Некорректный padding: байты не совпадают")

    return data[:-padding_len]

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Ключ должен быть {KEY_SIZE} байт (AES-128), получено {len(key)} байт"
        )

    # 1. Дополнить данные до кратности блоку (PKCS#7)
    padded_data = pkcs7_pad(plaintext, BLOCK_SIZE)

    # 2. Создать AES-примитив (MODE_ECB в PyCryptodome = чистый примитив)
    cipher = AES.new(key, AES.MODE_ECB)

    # 3. Вручную разбить на блоки и зашифровать каждый по отдельности
    output = bytearray()
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i + BLOCK_SIZE]
        encrypted_block = cipher.encrypt(block)
        output.extend(encrypted_block)

    return bytes(output)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Ключ должен быть {KEY_SIZE} байт (AES-128), получено {len(key)} байт"
        )

    if len(ciphertext) == 0:
        raise ValueError("Пустой шифротекст")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Длина шифротекста должна быть кратна {BLOCK_SIZE} байт, "
            f"получено {len(ciphertext)} байт"
        )

    # 1. Создать AES-примитив
    cipher = AES.new(key, AES.MODE_ECB)

    # 2. Вручную разбить на блоки и расшифровать каждый
    output = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = cipher.decrypt(block)
        output.extend(decrypted_block)

    # 3. Удалить padding
    plaintext = pkcs7_unpad(bytes(output))
    return plaintext
    # Удалить padding (с проверкой корректности)
    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext