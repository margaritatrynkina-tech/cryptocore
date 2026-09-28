from setuptools import setup, find_packages

setup(
    name='cryptocore',
    version='1.0.0',
    description='CryptoCore - инструмент для шифрования/расшифрования файлов с использованием AES-128 ECB',
    author='Student',
    packages=find_packages(),
    install_requires=[
        'pycryptodome>=3.19.0',
    ],
    entry_points={
        'console_scripts': [
            'cryptocore=src.cli_parser:main',
        ],
    },
    python_requires='>=3.8',
)