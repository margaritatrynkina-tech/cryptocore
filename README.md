# CryptoCore

Инструмент командной строки для шифрования и расшифрования файлов с использованием блочного шифра AES-128 в режиме ECB с автоматическим дополнением по стандарту PKCS#7.

## Описание

CryptoCore реализует базовые операции блочного шифра AES-128 в режиме ECB (Electronic Codebook). Логика режима ECB и дополнения PKCS#7 реализована вручную, в то время как сам примитив AES берётся из проверенной криптографической библиотеки `pycryptodome`.

## Зависимости

Управляются через `pyproject.toml`:

- **Runtime:** `pycryptodome` (устанавливается через `pip install -e .`)
- **Dev:** `pytest`, `pytest-cov` (устанавливается через `pip install -e ".[dev]"`)

## Требования

- **Python 3.10 или выше**
- **pip** (идёт в комплекте с Python)

## Установка

1. Клонируйте репозиторий и перейдите в папку проекта:
   ```bash
   git clone https://github.com/ВАШ-ЛОГИН/cryptocore.git
   cd cryptocore
   ```
   
2. Создайте и активируйте виртуальное окружение (рекомендуется):
   ```bash
   python -m venv venv
      # Для Windows:
   venv\Scripts\activate
      # Для Linux/macOS:
   source venv/bin/activate
   ```
   
3. Установите зависимости и сам пакет в режиме разработки:
   ```bash
   pip install -e .
   #вместе с dev зависимостями для запуска тестов
   pip install -e ".[dev]"
   ```
   
## Использование

- Шифрование файла
IV генерируется автоматически и записывается в начало выходного файла.
   ```bash
   cryptocore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin
  ```

- Расшифрование файла
По умолчанию IV читается из первых 16 байт входного файла:
   ```bash
  cryptocore --algorithm aes --mode ecb --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin \
    --output decrypted.txt
  ```
-  Поддерживаемые режимы
```bash
| Режим | Padding | IV | Особенности |
|---|---|---|---|
| `ecb` | PKCS#7 | Не нужен | Небезопасен, для учебных целей |
| `cbc` | PKCS#7 | Обязателен | Цепочка блоков |
| `cfb` | Не нужен | Обязателен | Потоковый, 128-битный сегмент |
| `ofb` | Не нужен | Обязателен | Потоковый, симметричен |
| `ctr` | Не нужен | Обязателен | Потоковый, счётчик, симметричен |
```

- Аргументы командной строки
```bash
| Аргумент | Описание |
|---|---|
| `--algorithm` | Алгоритм шифрования (поддерживается: `aes`) |
| `--mode` | Режим работы: `ecb`, `cbc`, `cfb`, `ofb`, `ctr` |
| `--encrypt` | Режим шифрования (взаимоисключающий с `--decrypt`) |
| `--decrypt` | Режим расшифрования (взаимоисключающий с `--encrypt`) |
| `--key` | Ключ в hex-формате (32 hex-символа = 16 байт для AES-128) |
| `--iv` | IV в hex-формате (32 hex-символа). **Только при расшифровании.** Если не задан — читается из первых 16 байт файла |
| `--input` | Путь к входному файлу |
| `--output` | Путь к выходному файлу (опционально) |
```
 
- Формат файла
При шифровании выходной файл имеет формат:

```
<16 байт IV><шифротекст>
```

- **IV** — первые 16 байт (открыто, не секрет)
- **Шифротекст** — остальное

Для ECB (не требует IV) файл состоит только из шифротекста.

## Тестирование и верификация

1. Запуск автоматических тестов
Проект покрыт модульными и интеграционными тестами (проверка PKCS#7 padding, шифрования, файлового I/O). Для их запуска выполните:
    ```bash
    python -m pytest tests/ -v
   ```
Покрывает: PKCS#7, ECB, CBC, CFB, OFB, CTR, реестр режимов, файловый I/O.

2. Проверка полного цикла (Round-trip)
Вы можете проверить, что файл после шифрования и последующего расшифрования полностью идентичен исходному:
    Чтобы убедиться в математической корректности нашей ручной реализации режима ECB и PKCS#7, мы сравниваем результат с утилитой openssl.
    ```bash
       # Создаём тестовый файл
    python -c "open('test.txt', 'wb').write(b'Hello, CryptoCore modes!')"
    
    # Прогоняем каждый режим
    for mode in ecb cbc cfb ofb ctr:
        cryptocore --algorithm aes --mode $mode --encrypt --key 000102030405060708090a0b0c0d0e0f --input test.txt --output test_$mode.enc
        cryptocore --algorithm aes --mode $mode --decrypt --key 000102030405060708090a0b0c0d0e0f --input test_$mode.enc --output test_$mode.dec
    ```
Каждый расшифрованный файл должен совпадать с `test.txt`.
   

3. Сверка с эталонной реализацией OpenSSL

#### CBC (наш инструмент → OpenSSL)

```bash
# 1. Шифруем нашим инструментом
cryptocore --algorithm aes --mode cbc --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plain.txt --output cipher.bin
# В выводе видим: IV (hex): aabbccdd...

# 2. Извлекаем IV (первые 16 байт) и шифротекст (остальное)
python -c "
import sys
data = open('cipher.bin','rb').read()
open('iv.bin','wb').write(data[:16])
open('ct.bin','wb').write(data[16:])
print('IV:', data[:16].hex())
"

# 3. Расшифровываем через OpenSSL
openssl enc -aes-128-cbc -d \
    -K 000102030405060708090a0b0c0d0e0f \
    -iv <IV_из_вывода_выше> \
    -in ct.bin -out decrypted.txt

# 4. Сверяем
diff plain.txt decrypted.txt  # должно быть пусто
```

#### OpenSSL → наш инструмент

```bash
# 1. Шифруем через OpenSSL
openssl enc -aes-128-cbc \
    -K 000102030405060708090a0b0c0d0e0f \
    -iv AABBCCDDEEFF00112233445566778899 \
    -in plain.txt -out openssl_cipher.bin

# 2. Расшифровываем нашим инструментом
cryptocore --algorithm aes --mode cbc --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input openssl_cipher.bin --output decrypted.txt

# 3. Сверяем
diff plain.txt decrypted.txt  # должно быть пусто
```

**Аналогично для `cfb`, `ofb`, `ctr`** — просто замените `cbc` на имя режима в командах.

> **Примечание про OpenSSL:** для потоковых режимов (CFB, OFB, CTR) OpenSSL не добавляет padding, поэтому флаги `-nopad` не нужны. Для CBC — OpenSSL добавляет padding автоматически, что совпадает с нашей реализацией.
   

## Структура проекта
    ```bash
    cryptocore/
    ├── src/
    │   ├── __init__.py
    │   ├── cli_parser.py            # CLI: парсинг аргументов + main
    │   ├── file_io.py               # Чтение/запись файлов, дефолтные имена
    │   └── modes/
    │       ├── __init__.py          # Реестр режимов + get_mode()
    │       ├── base.py              # ModeBase, pkcs7_pad/unpad, BLOCK_SIZE, KEY_SIZE
    │       ├── ecb.py               # ECBMode (ручной, с padding)
    │       ├── cbc.py               # CBCMode (цепочка + padding)
    │       ├── cfb.py               # CFBMode (потоковый, 128-битный сегмент)
    │       ├── ofb.py               # OFBMode (потоковый, симметричен)
    │       └── ctr.py               # CTRMode (потоковый, счётчик)
    ├── tests/
    │   ├── __init__.py
    │   └── test_crypto.py           # 122 теста (все режимы + padding + I/O)
    ├── tools/
    │   └── render_readme.py         # Скрипт для локального preview README
    ├── pyproject.toml               # Метаданные + зависимости (runtime / dev)
    ├── requirements.txt             # Runtime-зависимости (справочно)
    ├── README.md                    # Документация
    └── .gitignore
    ```