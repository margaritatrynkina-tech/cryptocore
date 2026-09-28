import sys
from pathlib import Path


def read_file(filepath: str) -> bytes:
    try:
        path = Path(filepath)

        if not path.exists():
            print(f"Ошибка: Файл не найден: {filepath}", file=sys.stderr)
            sys.exit(1)

        if not path.is_file():
            print(f"Ошибка: Указанный путь не является файлом: {filepath}", file=sys.stderr)
            sys.exit(1)

        with open(filepath, 'rb') as f:
            return f.read()

    except PermissionError:
        print(f"Ошибка: Нет прав на чтение файла: {filepath}", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Ошибка: Указан каталог вместо файла: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при чтении файла '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)


def write_file(filepath: str, data: bytes) -> None:
    try:
        # Проверить, что родительская директория существует
        path = Path(filepath)
        parent = path.parent
        if not parent.exists():
            print(
                f"Ошибка: Директория не существует: {parent}",
                file=sys.stderr
            )
            sys.exit(1)

        with open(filepath, 'wb') as f:
            f.write(data)

    except PermissionError:
        print(f"Ошибка: Нет прав на запись в файл: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при записи файла '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)


def get_default_output_path(input_path: str, encrypt: bool) -> str:
    if encrypt:
        return f"{input_path}.enc"
    else:
        # Если файл заканчивается на .enc, заменить на .dec
        if input_path.endswith('.enc'):
            return input_path[:-4] + '.dec'
        else:
            return f"{input_path}.dec"