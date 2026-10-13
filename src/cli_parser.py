from __future__ import annotations

import argparse
import sys

from src.csprng import generate_iv, generate_key
from src.file_io import read_file, write_file, get_default_output_path
from src.modes import get_mode
from src.modes.base import BLOCK_SIZE, KEY_SIZE


def parse_hex_key(hex_string: str) -> bytes:
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


def is_weak_key(key: bytes) -> tuple[bool, str]:
    if len(key) == 0:
        return True, "пустой ключ"

    # All bytes identical (all zeros, all 0xFF, etc.)
    if len(set(key)) == 1:
        return True, f"все байты одинаковые (0x{key[0]:02x})"

    # Sequential bytes (00 01 02 ... or ff fe fd ...)
    is_ascending = all((key[i + 1] - key[i]) % 256 == 1 for i in range(len(key) - 1))
    is_descending = all((key[i] - key[i + 1]) % 256 == 1 for i in range(len(key) - 1))
    if is_ascending or is_descending:
        return True, "байты идут последовательно"

    return False, ""


def warn_if_weak_key(key: bytes) -> None:
    weak, reason = is_weak_key(key)
    if weak:
        print(
            f"Предупреждение: ключ выглядит слабым ({reason}). "
            f"Для реального использования сгенерируйте случайный ключ "
            f"(не передавайте --key при шифровании).",
            file=sys.stderr,
        )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore — инструмент для шифрования/расшифрования файлов",
        epilog=(
            "Пример: cryptocore --algorithm aes --mode cbc --encrypt "
            "--key 000102030405060708090a0b0c0d0e0f "
            "--input plaintext.txt --output ciphertext.bin\n"
            "Пример без --key (ключ генерируется автоматически): "
            "cryptocore --algorithm aes --mode cbc --encrypt "
            "--input plaintext.txt --output ciphertext.bin"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        default=None,
        help=(
            f"Ключ в hex-формате ({KEY_SIZE * 2} hex-символов). "
            f"При шифровании необязателен: если не задан, "
            f"ключ генерируется и выводится в stdout. "
            f"При расшифровании обязателен."
        ),
    )

    parser.add_argument(
        "--iv",
        default=None,
        help=(
            f"IV в hex-формате ({BLOCK_SIZE * 2} hex-символов). "
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

    if args.encrypt:
        if args.key is not None:
            # CLI-2: use key as provided
            key_bytes = parse_hex_key(args.key)
            validate_key_length(key_bytes)
            warn_if_weak_key(key_bytes)
        else:
            # CLI-3: generate a random key and print it
            key_bytes = generate_key(KEY_SIZE)
            print(f"Сгенерирован случайный ключ: {key_bytes.hex()}")
    else:
        # CLI-4: decryption always requires --key
        if args.key is None:
            print(
                "Ошибка: для расшифрования необходимо указать --key "
                "(ключ нельзя сгенерировать — он должен совпадать "
                "с ключом, использованным при шифровании).",
                file=sys.stderr,
            )
            sys.exit(1)
        key_bytes = parse_hex_key(args.key)
        validate_key_length(key_bytes)
        # No weak-key warning on decryption — user might legitimately
        # be decrypting with a test key.

    mode = get_mode(args.mode)

    iv_from_cli: bytes | None = None
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
            iv = generate_iv() if mode.needs_iv else None
            ciphertext = mode.encrypt(input_data, key_bytes, iv)

            output_data = (iv + ciphertext) if iv is not None else ciphertext

            write_file(output_path, output_data)
            print(f"Зашифровано: {args.input_file} -> {output_path}")
            print(f"Режим: {mode.name.upper()}")
            if iv is not None:
                print(f"IV (hex): {iv.hex()}")

        else:
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