import pytest
import tempfile
import os
from pathlib import Path

from src.modes.ecb import (
    pkcs7_pad, pkcs7_unpad,
    encrypt_ecb, decrypt_ecb,
    BLOCK_SIZE, KEY_SIZE
)
from src.file_io import read_file, write_file, get_default_output_path


class TestPKCS7Padding:
    def test_pad_empty_data(self):
        result = pkcs7_pad(b'', BLOCK_SIZE)
        assert len(result) == BLOCK_SIZE
        assert result == bytes([BLOCK_SIZE] * BLOCK_SIZE)

    def test_pad_1_byte(self):
        result = pkcs7_pad(b'A', BLOCK_SIZE)
        assert len(result) == BLOCK_SIZE
        assert result == b'A' + bytes([15] * 15)

    def test_pad_15_bytes(self):
        data = b'123456789012345'
        result = pkcs7_pad(data, BLOCK_SIZE)
        assert len(result) == BLOCK_SIZE
        assert result == data + bytes([1])

    def test_pad_16_bytes(self):
        data = b'1234567890123456'
        result = pkcs7_pad(data, BLOCK_SIZE)
        assert len(result) == 2 * BLOCK_SIZE
        assert result == data + bytes([BLOCK_SIZE] * BLOCK_SIZE)

    def test_pad_17_bytes(self):
        data = b'A' * 17
        result = pkcs7_pad(data, BLOCK_SIZE)
        assert len(result) == 2 * BLOCK_SIZE
        assert result == data + bytes([15] * 15)

    def test_pad_32_bytes(self):
        data = b'A' * 32
        result = pkcs7_pad(data, BLOCK_SIZE)
        assert len(result) == 3 * BLOCK_SIZE

    def test_unpad_valid_1_byte(self):
        data = b'123456789012345' + bytes([1])
        result = pkcs7_unpad(data)
        assert result == b'123456789012345'

    def test_unpad_valid_full_block(self):
        data = b'1234567890123456' + bytes([BLOCK_SIZE] * BLOCK_SIZE)
        result = pkcs7_unpad(data)
        assert result == b'1234567890123456'

    def test_unpad_empty_raises(self):
        with pytest.raises(ValueError):
            pkcs7_unpad(b'')

    def test_unpad_invalid_zero_raises(self):
        data = b'1234567890123456' + bytes([0])
        with pytest.raises(ValueError):
            pkcs7_unpad(data)

    def test_unpad_invalid_value_raises(self):
        data = b'1234567890123456' + bytes([17])
        with pytest.raises(ValueError):
            pkcs7_unpad(data)

    def test_unpad_inconsistent_bytes_raises(self):
        data = b'123456789012345' + bytes([2, 1])  # Должно быть [2, 2]
        with pytest.raises(ValueError):
            pkcs7_unpad(data)

    def test_pad_unpad_roundtrip(self):
        for size in range(0, 50):
            data = bytes([i % 256 for i in range(size)])
            padded = pkcs7_pad(data, BLOCK_SIZE)
            unpadded = pkcs7_unpad(padded)
            assert unpadded == data, f"Ошибка для размера {size}"

class TestECBEncryption:

    def test_encrypt_decrypt_short_text(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b'Hello, World!'

        ciphertext = encrypt_ecb(plaintext, key)
        decrypted = decrypt_ecb(ciphertext, key)

        assert decrypted == plaintext

    def test_encrypt_decrypt_binary_data(self):
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        plaintext = bytes(range(256))

        ciphertext = encrypt_ecb(plaintext, key)
        decrypted = decrypt_ecb(ciphertext, key)

        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_data(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b''

        ciphertext = encrypt_ecb(plaintext, key)
        decrypted = decrypt_ecb(ciphertext, key)

        assert decrypted == plaintext
        assert len(ciphertext) == BLOCK_SIZE  # Только padding

    def test_encrypt_decrypt_large_data(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b'A' * 10000

        ciphertext = encrypt_ecb(plaintext, key)
        decrypted = decrypt_ecb(ciphertext, key)

        assert decrypted == plaintext

    def test_encrypt_decrypt_exact_block_size(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b'1234567890123456'

        ciphertext = encrypt_ecb(plaintext, key)
        decrypted = decrypt_ecb(ciphertext, key)

        assert decrypted == plaintext
        assert len(ciphertext) == 2 * BLOCK_SIZE  # Данные + блок padding

    def test_ciphertext_differs_from_plaintext(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b'Secret message!'

        ciphertext = encrypt_ecb(plaintext, key)

        assert ciphertext != plaintext
        assert plaintext not in ciphertext

    def test_wrong_key_raises_error(self):
        key1 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        key2 = bytes.fromhex('ff0102030405060708090a0b0c0d0e0f')
        plaintext = b'Test data'

        ciphertext = encrypt_ecb(plaintext, key1)

        with pytest.raises(ValueError):
            decrypt_ecb(ciphertext, key2)

    def test_invalid_key_length_short(self):
        key = b'short'
        plaintext = b'Test'

        with pytest.raises(ValueError):
            encrypt_ecb(plaintext, key)

    def test_invalid_key_length_long(self):
        key = b'a' * 32
        plaintext = b'Test'

        with pytest.raises(ValueError):
            encrypt_ecb(plaintext, key)

    def test_ciphertext_length_is_multiple_of_block(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

        for size in [0, 1, 15, 16, 17, 31, 32, 100, 1000]:
            plaintext = b'A' * size
            ciphertext = encrypt_ecb(plaintext, key)
            assert len(ciphertext) % BLOCK_SIZE == 0

    def test_same_plaintext_same_ciphertext_ecb(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        # Два одинаковых блока по 16 байт
        plaintext = b'A' * 16 + b'A' * 16

        ciphertext = encrypt_ecb(plaintext, key)

        # Первые 16 байт шифротекста должны совпадать со вторыми 16
        assert ciphertext[:BLOCK_SIZE] == ciphertext[BLOCK_SIZE:2*BLOCK_SIZE]

    def test_different_keys_different_ciphertext(self):
        key1 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        key2 = bytes.fromhex('ff0102030405060708090a0b0c0d0e0f')
        plaintext = b'Test message'

        ciphertext1 = encrypt_ecb(plaintext, key1)
        ciphertext2 = encrypt_ecb(plaintext, key2)

        assert ciphertext1 != ciphertext2

    def test_empty_ciphertext_raises(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

        with pytest.raises(ValueError):
            decrypt_ecb(b'', key)

    def test_invalid_ciphertext_length_raises(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

        with pytest.raises(ValueError):
            decrypt_ecb(b'12345', key)

class TestFileIO:

    def test_read_write_binary_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            tmp_path = tmp.name

        try:
            test_data = b'Test binary data \x00\x01\x02\xff'
            write_file(tmp_path, test_data)
            read_data = read_file(tmp_path)
            assert read_data == test_data
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_read_write_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            tmp_path = tmp.name

        try:
            write_file(tmp_path, b'')
            read_data = read_file(tmp_path)
            assert read_data == b''
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_read_nonexistent_file_exits(self):
        with pytest.raises(SystemExit):
            read_file('/nonexistent/path/to/file.txt')

    def test_default_output_path_encrypt(self):
        result = get_default_output_path('test.txt', encrypt=True)
        assert result == 'test.txt.enc'

    def test_default_output_path_decrypt_with_enc(self):
        result = get_default_output_path('test.txt.enc', encrypt=False)
        assert result == 'test.txt.dec'

    def test_default_output_path_decrypt_without_enc(self):
        result = get_default_output_path('test.txt', encrypt=False)
        assert result == 'test.txt.dec'

class TestIntegration:

    def test_full_cycle_with_files(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        original_data = b'This is a test file content!\n' * 100

        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f_in:
            input_path = f_in.name
            f_in.write(original_data)

        encrypted_path = input_path + '.enc'
        decrypted_path = input_path + '.dec'

        try:
            # Шифрование
            input_data = read_file(input_path)
            encrypted_data = encrypt_ecb(input_data, key)
            write_file(encrypted_path, encrypted_data)

            # Расшифрование
            encrypted_data = read_file(encrypted_path)
            decrypted_data = decrypt_ecb(encrypted_data, key)
            write_file(decrypted_path, decrypted_data)

            # Проверка
            final_data = read_file(decrypted_path)
            assert final_data == original_data

        finally:
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_full_cycle_binary_data(self):
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        original_data = bytes(range(256)) * 10

        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f_in:
            input_path = f_in.name
            f_in.write(original_data)

        encrypted_path = input_path + '.enc'
        decrypted_path = input_path + '.dec'

        try:
            # Шифрование
            input_data = read_file(input_path)
            encrypted_data = encrypt_ecb(input_data, key)
            write_file(encrypted_path, encrypted_data)

            # Расшифрование
            encrypted_data = read_file(encrypted_path)
            decrypted_data = decrypt_ecb(encrypted_data, key)
            write_file(decrypted_path, decrypted_data)

            # Проверка
            final_data = read_file(decrypted_path)
            assert final_data == original_data

        finally:
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def test_full_cycle_empty_file(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        original_data = b''

        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f_in:
            input_path = f_in.name
            # Файл уже пустой

        encrypted_path = input_path + '.enc'
        decrypted_path = input_path + '.dec'

        try:
            input_data = read_file(input_path)
            encrypted_data = encrypt_ecb(input_data, key)
            write_file(encrypted_path, encrypted_data)

            encrypted_data = read_file(encrypted_path)
            decrypted_data = decrypt_ecb(encrypted_data, key)
            write_file(decrypted_path, decrypted_data)

            final_data = read_file(decrypted_path)
            assert final_data == original_data

        finally:
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)