# CryptoCore

Инструмент командной строки для шифрования и расшифрования файлов с использованием блочного шифра AES-128 в режиме ECB с автоматическим дополнением по стандарту PKCS#7.

## Описание

CryptoCore реализует базовые операции блочного шифра AES-128 в режиме ECB (Electronic Codebook). Логика режима ECB и дополнения PKCS#7 реализована вручную, в то время как сам примитив AES берётся из проверенной криптографической библиотеки `pycryptodome`.

## Зависимости

- Python 3.8 или выше
- `pycryptodome` >= 3.19.0 (криптографическая библиотека)
- `pytest` >= 7.4.0 (для запуска тестов)
- OpenSSL (опционально, используется для верификации корректности шифрования)

## Установка

1. Клонируйте репозиторий и перейдите в папку проекта:
   ```bash
   cd cryptocore
   
2. Создайте и активируйте виртуальное окружение (рекомендуется):
   ```bash
   python -m venv venv
      # Для Windows:
   venv\Scripts\activate
      # Для Linux/macOS:
   source venv/bin/activate
   
3. Установите зависимости и сам пакет в режиме разработки:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   
## Использование

- Шифрование файла
   ```bash
   cryptocore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin

- Расшифрование файла
   ```bash
  cryptocore --algorithm aes --mode ecb --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin \
    --output decrypted.txt
  - Аргументы командной строки
     ```bash
     --algorithm         #Алгоритм шифрования (поддерживается: aes)
     --mode              #Режим работы шифра (поддерживается: ecb)
     --encrypt           #Режим шифрования (взаимоисключающий с --decrypt)
     --decrypt           #Режим расшифрования (взаимоисключающий с --encrypt)
     --key               #Ключ в hex-формате (32 hex-символа = 16 байт для AES-128)
     --input             #Путь к входному файлу
     --output            #Путь к выходному файлу

## Тестирование и верификация

1. Запуск автоматических тестов
Проект покрыт модульными и интеграционными тестами (проверка PKCS#7 padding, шифрования, файлового I/O). Для их запуска выполните:
    ```bash
   python -m pytest tests/ -v

2. Проверка полного цикла (Round-trip)
Вы можете проверить, что файл после шифрования и последующего расшифрования полностью идентичен исходному:
    Чтобы убедиться в математической корректности нашей ручной реализации режима ECB и PKCS#7, мы сравниваем результат с утилитой openssl.
    # Создаем тестовый файл
    python -c "open('test.txt', 'wb').write(b'Hello, CryptoCore!')"
    
    # Шифруем
    cryptocore --algorithm aes --mode ecb --encrypt \
        --key 000102030405060708090a0b0c0d0e0f \
        --input test.txt --output test.enc
    
    # Расшифровываем
    cryptocore --algorithm aes --mode ecb --decrypt \
        --key 000102030405060708090a0b0c0d0e0f \
        --input test.enc --output test.dec
    
    # Сравниваем хеш-суммы (значения Hash должны абсолютно совпадать)
    Get-FileHash test.txt
    Get-FileHash test.dec

3. Сверка с эталонной реализацией OpenSSL
Чтобы убедиться в математической корректности нашей ручной реализации режима ECB и PKCS#7, мы сравниваем результат с утилитой openssl.
    ```bash
    # 1. Создаем файл ровно из 16 байт
    python -c "open('test16.bin', 'wb').write(b'0123456789ABCDEF')"
    
    # 2. Шифруем НАШИМ инструментом
    cryptocore --algorithm aes --mode ecb --encrypt \
        --key 000102030405060708090a0b0c0d0e0f \
        --input test16.bin --output our_enc.bin
    
    # 3. Шифруем через OpenSSL (отключаем соль и padding)
    python -c "import subprocess; subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-K', '000102030405060708090a0b0c0d0e0f', '-nosalt', '-nopad', '-in', 'test16.bin', '-out', 'openssl_enc.bin'])"
    
    # 4. Сравниваем хеш-суммы (они ДОЛЖНЫ быть абсолютно одинаковыми, что доказывает корректность реализации)
    Get-FileHash our_enc.bin
    Get-FileHash openssl_enc.bin
   
## Структура проекта
    ```bash
    cryptocore/
    ├── src/
    │   ├── __init__.py
    │   ├── cli_parser.py      # Парсер аргументов командной строки
    │   ├── file_io.py         # Бинарный файловый ввод-вывод с обработкой ошибок
    │   └── modes/
    │       ├── __init__.py
    │       └── ecb.py         # Реализация AES-128 ECB и PKCS#7 padding
    ├── tests/
    │   ├── __init__.py
    │   └── test_crypto.py     # Модульные и интеграционные тесты
    ├── requirements.txt       # Зависимости проекта
    ├── setup.py               # Скрипт настройки и сборки пакета
    └── README.md              # Этот файл
