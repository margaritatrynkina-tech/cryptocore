import argparse
import sys

from src.file_io import read_file, write_file, get_default_output_path
from src.modes.ecb import encrypt_ecb, decrypt_ecb, KEY_SIZE


def parse_hex_key(hex_string: str) -> bytes:
    try:
        # Убрать пробелы и привести к нижнему регистру
        hex_string = hex_string.strip().lower()
        return bytes.fromhex(hex_string)
    except ValueError:
        print(
            f"Ошибка: Неверный формат ключа. "
            f"Ожидается hex-строка (только символы 0-9, a-f), получено: '{hex_string}'",
            file=sys.stderr
        )
        sys.exit(1)


def validate_key_length(key_bytes: bytes) -> None:
    if len(key_bytes) != KEY_SIZE:
        print(
            f"Ошибка: Для AES-128 ключ должен быть {KEY_SIZE} байт "
            f"({KEY_SIZE * 2} hex-символов). "
            f"Получено: {len(key_bytes)} байт ({len(key_bytes) * 2} hex-символов)",
            file=sys.stderr
        )
        sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cryptocore',
        description='CryptoCore - инструмент для шифрования/расшифрования файлов',
        epilog='Пример: cryptocore --algorithm aes --mode ecb --encrypt '
               '--key 000102030405060708090a0b0c0d0e0f '
               '--input plaintext.txt --output ciphertext.bin'
    )

    parser.add_argument(
        '--algorithm',
        required=True,
        choices=['aes'],
        help='Алгоритм шифрования (поддерживается: aes)'
    )

    parser.add_argument(
        '--mode',
        required=True,
        choices=['ecb'],
        help='Режим работы шифра (поддерживается: ecb)'
    )

    # Взаимоисключающая группа для encrypt/decrypt
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        '--encrypt',
        action='store_true',
        help='Режим шифрования'
    )
    operation_group.add_argument(
        '--decrypt',
        action='store_true',
        help='Режим расшифрования'
    )

    parser.add_argument(
        '--key',
        required=True,
        help='Ключ шифрования в hex-формате (32 hex-символа = 16 байт для AES-128)'
    )

    parser.add_argument(
        '--input',
        required=True,
        dest='input_file',
        help='Путь к входному файлу'
    )

    parser.add_argument(
        '--output',
        dest='output_file',
        help='Путь к выходному файлу (если не указан, формируется автоматически)'
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    # Преобразовать ключ из hex в байты
    key_bytes = parse_hex_key(args.key)

    # Проверить длину ключа
    validate_key_length(key_bytes)

    # Определить операцию
    encrypt = args.encrypt

    # Определить путь к выходному файлу
    if args.output_file:
        output_path = args.output_file
    else:
        output_path = get_default_output_path(args.input_file, encrypt)

    # Прочитать входной файл
    input_data = read_file(args.input_file)

    try:
        # Выполнить операцию
        if encrypt:
            output_data = encrypt_ecb(input_data, key_bytes)
            operation_name = "Зашифровано"
        else:
            output_data = decrypt_ecb(input_data, key_bytes)
            operation_name = "Расшифровано"

        # Записать выходной файл
        write_file(output_path, output_data)

        # Вывести успешное сообщение в stdout
        print(f"{operation_name}: {args.input_file} -> {output_path}")
        print(f"Размер: {len(input_data)} байт -> {len(output_data)} байт")

    except ValueError as e:
        print(f"Ошибка криптографии: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()