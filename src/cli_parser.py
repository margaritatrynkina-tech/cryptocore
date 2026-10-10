from __future__ import annotations

import argparse
import os
import sys

from src.file_io import read_file, write_file, get_default_output_path
from src.modes import get_mode
from src.modes.base import BLOCK_SIZE, KEY_SIZE

def parse_hex_key(hex_string: str) -> bytes:
    """Convert hex string to bytes, with a friendly error message."""
    try:
        return bytes.fromhex(hex_string.strip())
    except ValueError:
        print(
            f"Ошибка: Неверный формат ключа. "
            f"Ожидается hex-строка (символы 0-9, a-f), получено: '{hex_string}'",
            file=sys.stderr,
        )
        sys.exit(1)


def validate_key_length(key_bytes: bytes) -> None:
    if len(key_bytes) != KEY_SIZE:
        print(
            f"Ошибка: Для AES-128 ключ должен быть {KEY_SIZE} байт "
            f"({KEY_SIZE * 2} hex-символов). "
            f"Получено: {len(key_bytes)} байт ({len(key_bytes) * 2} hex-символов)",
            file=sys.stderr,
        )
        sys.exit(1)


def parse_hex_iv(hex_string: str) -> bytes:
    """Convert hex string to 16-byte IV, with a friendly error message."""
    try:
        iv = bytes.fromhex(hex_string.strip())
    except ValueError:
        print(
            f"Ошибка: Неверный формат IV. "
            f"Ожидается hex-строка, получено: '{hex_string}'",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(iv) != BLOCK_SIZE:
        print(
            f"Ошибка: IV должен быть {BLOCK_SIZE} байт "
            f"({BLOCK_SIZE * 2} hex-символов). Получено: {len(iv)} байт",
            file=sys.stderr,
        )
        sys.exit(1)

    return iv


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore — инструмент для шифрования/расшифрования файлов",
        epilog=(
            "Пример: cryptocore --algorithm aes --mode cbc --encrypt "
            "--key 000102030405060708090a0b0c0d0e0f "
            "--input plaintext.txt --output ciphertext.bin"
        ),
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="Алгоритм шифрования (поддерживается: aes)",
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["ecb", "cbc", "cfb", "ofb", "ctr"],
        help="Режим работы шифра",
    )

    op = parser.add_mutually_exclusive_group(required=True)
    op.add_argument("--encrypt", action="store_true", help="Режим шифрования")
    op.add_argument("--decrypt", action="store_true", help="Режим расшифрования")

    parser.add_argument(
        "--key",
        required=True,
        help=f"Ключ в hex-формате ({KEY_SIZE * 2} hex-символов = {KEY_SIZE} байт)",
    )

    parser.add_argument(
        "--iv",
        default=None,
        help=(
            f"IV в hex-формате ({BLOCK_SIZE * 2} hex-символов = {BLOCK_SIZE} байт). "
            "Используется только при расшифровании. "
            "Если не задан — IV читается из первых 16 байт входного файла."
        ),
    )

    parser.add_argument(
        "--input",
        required=True,
        dest="input_file",
        help="Путь к входному файлу",
    )

    parser.add_argument(
        "--output",
        dest="output_file",
        help="Путь к выходному файлу (если не указан — формируется автоматически)",
    )

    return parser

def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    key_bytes = parse_hex_key(args.key)
    validate_key_length(key_bytes)

    mode = get_mode(args.mode)
    iv_from_cli: bytes | None = None

    # --iv is only allowed when decrypting (CLI-3)
    if args.iv is not None:
        if args.encrypt:
            print(
                "Ошибка: --iv не должен использоваться при шифровании "
                "(IV генерируется автоматически).",
                file=sys.stderr,
            )
            sys.exit(1)
        iv_from_cli = parse_hex_iv(args.iv)

    output_path = args.output_file or get_default_output_path(
        args.input_file, encrypt=args.encrypt
    )

    input_data = read_file(args.input_file)

    try:
        if args.encrypt:
            # Generate random IV if the mode requires it
            iv = os.urandom(BLOCK_SIZE) if mode.needs_iv else None
            ciphertext = mode.encrypt(input_data, key_bytes, iv)

            if iv is not None:
                output_data = iv + ciphertext          # IV-2: IV first
            else:
                output_data = ciphertext

            write_file(output_path, output_data)
            print(f"Зашифровано: {args.input_file} -> {output_path}")
            print(f"Режим: {mode.name.upper()}")
            if iv is not None:
                print(f"IV (hex): {iv.hex()}")

        else:
            # Decryption
            if mode.needs_iv:
                if iv_from_cli is not None:
                    iv = iv_from_cli
                    ciphertext = input_data
                else:
                    if len(input_data) < BLOCK_SIZE:
                        print(
                            f"Ошибка: входной файл слишком короткий "
                            f"({len(input_data)} байт), не содержит IV "
                            f"(нужно минимум {BLOCK_SIZE} байт).",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    iv = input_data[:BLOCK_SIZE]
                    ciphertext = input_data[BLOCK_SIZE:]
            else:
                iv = None
                ciphertext = input_data

            plaintext = mode.decrypt(ciphertext, key_bytes, iv)
            write_file(output_path, plaintext)
            print(f"Расшифровано: {args.input_file} -> {output_path}")
            print(f"Режим: {mode.name.upper()}")

    except ValueError as e:
        print(f"Ошибка криптографии: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()