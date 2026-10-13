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
- Автоматическая генерация ключа
Если **при шифровании** не указан `--key`, инструмент **сгенерирует случайный 16-байтный ключ** через CSPRNG и выведет его в stdout:
```bash
cryptocore --algorithm aes --mode cbc --encrypt \
    --input plaintext.txt --output ciphertext.bin
```
Пример вывода:
```
Сгенерирован случайный ключ: 0af7830abf30a0bbd4a9f00db4a424ff
Зашифровано: plaintext.txt -> ciphertext.bin
Режим: CBC
IV (hex): 8fd7f33fcb6ab16ee17ddf68512ba184
```
> **Важно:** сохраните выведенный ключ! Без него вы не сможете расшифровать файл. Ключ **не записывается** в выходной файл с шифротекстом.
При **расшифровании** ключ **обязателен** — инструмент не может его угадать:
```bash
cryptocore --algorithm aes --mode cbc --decrypt \
    --key 0af7830abf30a0bbd4a9f00db4a424ff \
    --input ciphertext.bin --output decrypted.txt
```
- Предупреждение о слабом ключе
Если пользователь передал **явно слабый ключ** (например, все нули или последовательные байты `00 01 02 ... 0f`), инструмент **выведет предупреждение в stderr** — но продолжит работу:
```
Предупреждение: ключ выглядит слабым (байты идут последовательно).
Для реального использования сгенерируйте случайный ключ
(не передавайте --key при шифровании).
```
Это сделано для того, чтобы студенты не использовали учебные ключи в продакшене.

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

## Безопасность CSPRNG

Модуль `src/csprng.py` — это **единственный источник случайности** в проекте. Он реализован на базе `os.urandom()`:

- **Linux/macOS:** использует `getrandom(2)` или `/dev/urandom` — системный CSPRNG ядра
- **Windows:** использует `BCryptGenRandom` / `RtlGenRandom` — криптографический API Windows

**Модуль `random` НЕ используется** — его генератор (Mersenne Twister) предсказуем: зная 624 последовательных значения, можно восстановить состояние и предсказать все следующие.

**Гарантии CSPRNG:**
- Вывод неотличим от истинно случайного (статистически)
- Непредсказуем даже при знании алгоритма
- Устойчив к компрометации предыдущих выходов (forward secrecy)

## Тестирование NIST
CryptoCore использует **системный** CSPRNG (`os.urandom`), который уже сертифицирован NIST. Для верификации «случайности» выходных данных можно запустить **NIST Statistical Test Suite** — стандартный набор из 15 тестов.

### Подготовка тестовых данных
```bash
python tools/generate_nist_data.py 10
```
Создаёт файл `nist_test_data.bin` размером 10 МБ, заполненный выводом нашего CSPRNG.
> **Рекомендуемый размер:** от 1 до 100 МБ. Меньшие файлы дают менее надёжную статистику.

### Запуск NIST STS
1. Скачать NIST STS: https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software
2. Собрать C-версию (в архиве есть `makefile`):
   ```bash
   cd sts-2.1.2
   make
   ```
3. Скопировать `nist_test_data.bin` в директорию `sts-2.1.2/`
4. Запустить:
   ```bash
   ./assess 10000000
   ```
5. В интерактивном меню:
   - **Input file:** `nist_test_data.bin`
   - **Number of bitstreams:** `1`
   - **Select tests:** `0` (All tests)
6. Дождаться завершения — результаты в `experiments/AlgorithmTesting/`

### Критерий успеха
Для каждого теста смотрится **p-value**:
- `p-value >= 0.01` → тест пройден 
- `p-value < 0.01` → тест провален
**Норма:** не более 1–2 провалов из 15 (статистически допустимо). Массовые провалы указывают на сломанный генератор.

> **Ожидаемый результат для `os.urandom`:** все 15 тестов проходят.

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