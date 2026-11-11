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

### Хеширование файлов (`dgst`)

Для вычисления контрольных сумм (message digest) используется отдельная подкоманда `dgst`. Она не требует ключей и режимов шифрования.

**Базовое вычисление хеша:**

```bash
cryptocore dgst --algorithm sha256 --input document.pdf
```

Вывод соответствует формату классических `*sum`-утилит:
```text
5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b0b5  document.pdf
```

**Запись хеша в файл** (флаг `--output`):

```bash
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

**Поддерживаемые алгоритмы:**

| Алгоритм | Реализация | Особенности |
|---|---|---|
| `sha256` | **С нуля** (NIST FIPS 180-4) | Merkle–Damgård, 512-битные блоки, 64 раунда |
| `sha3-256` | Через `hashlib` | Согласно HASH-3 (стандартная библиотека) |

**Технические детали:**
- Входной файл читается **бинарно** (`'rb'`) блоками по 8 КБ (постоянное потребление памяти — IO-2)
- Для пустого файла `sha256` возвращает `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- SHA-256 реализован вручную: `src/hash/sha256.py` (константы K, H, ротации, раундовая функция)

**Пример проверки совместимости:**

```bash
# Наш инструмент
cryptocore dgst --algorithm sha256 --input large_file.iso > my_hash.txt

# Системная утилита (Linux/macOS)
sha256sum large_file.iso > system_hash.txt

# Различий быть не должно
diff my_hash.txt system_hash.txt
```

> **Примечание для Windows:** команда `sha256sum` встроена в Git Bash. В PowerShell можно использовать:
> ```powershell
> Get-FileHash large_file.iso -Algorithm SHA256
> ```

### HMAC (аутентификация сообщений)

Помимо обычных хешей, команда `dgst` поддерживает **HMAC-SHA256** (Hash-based Message Authentication Code) по RFC 2104. HMAC позволяет проверить не только целостность данных, но и их **подлинность** — только владелец ключа может сгенерировать корректный MAC.

**Генерация HMAC:**

```bash
cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input message.txt
```

Вывод (формат `HMAC  FILE`):
```text
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7  message.txt
```

**Проверка HMAC (`--verify`):**

```bash
# Сначала сохраняем HMAC
cryptocore dgst --algorithm sha256 --hmac --key ... --input message.txt --output expected.hmac

# Потом проверяем
cryptocore dgst --algorithm sha256 --hmac --key ... --input message.txt --verify expected.hmac
# → [OK] HMAC verification successful (exit code 0)
```

Если файл или ключ изменены:
```text
[ERROR] HMAC verification failed (expected ..., got ...)  (exit code 1)
```

**Свойства HMAC:**
- **Длина ключа:** любая. Ключи > 64 байт хешируются, ключи < 64 байт дополняются нулями.
- **Конструкция:** `HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))`, где `ipad = 0x36`, `opad = 0x5c`.
- **Защита:** устойчив к *length extension attack* (в отличие от наивного `H(K ∥ m)`).
- **Реализация:** `src/mac/hmac.py` — с нуля, по RFC 2104, поверх вашего SHA-256 из `src/hash/sha256.py`.

**Тестовые векторы (RFC 4231):**

| Key | Data | HMAC-SHA256 |
|---|---|---|
| `0b`×20 | `Hi There` | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| `Jefe` | `what do ya want for nothing?` | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` |

## Тестирование и верификация

1. Запуск автоматических тестов
Покрывает: PKCS#7, ECB, CBC, CFB, OFB, CTR, реестр режимов, файловый I/O, CSPRNG (включая 1000 уникальных ключей), SHA-256 (NIST-векторы, лавинный эффект), SHA3-256.
```bash
    python -m pytest tests/ -v
   ```

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
    │   ├── csprng.py                # CSPRNG (os.urandom)
    │   └── modes/
    │   │   ├── __init__.py          # Реестр режимов + get_mode()
    │   │   ├── base.py              # ModeBase, pkcs7_pad/unpad, BLOCK_SIZE, KEY_SIZE
    │   │   ├── ecb.py               # ECBMode (ручной, с padding)
    │   │   ├── cbc.py               # CBCMode (цепочка + padding)
    │   │   ├── cfb.py               # CFBMode (потоковый, 128-битный сегмент)
    │   │   ├── ofb.py               # OFBMode (потоковый, симметричен)
    │   │   └── ctr.py               # CTRMode (потоковый, счётчик)
    │   ├── hash/
    │   │   ├── __init__.py          # Реестр алгоритмов
    │   │   ├── sha256.py            # SHA-256 с нуля (FIPS 180-4)
    │   │   └── sha3_256.py          # SHA3-256 (через hashlib)
    │   └── mac/
    │       ├── __init__.py
    │       └── hmac.py                # HMAC-SHA256 (RFC 2104)
    ├── tests/
    │   ├── __init__.py
    │   ├── test_crypto.py           # 122 теста (все режимы + padding + I/O)
    │   ├── test_csprng.py           # CSPRNG (Sprint 3)
    │   ├── test_hmac.py             # RFC 4231 векторы + edge cases
    │   └── test_hash.py             # Хеши (Sprint 4)
    ├── tools/
    │   └── render_readme.py         # Скрипт для локального preview README
    ├── pyproject.toml               # Метаданные + зависимости (runtime / dev)
    ├── requirements.txt             # Runtime-зависимости (справочно)
    ├── README.md                    # Документация
    └── .gitignore
    ```