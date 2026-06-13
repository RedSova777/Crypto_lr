#!/usr/bin/env python3
"""
Средство извлечения параметров RSA из файла закрытого ключа OpenSSH.

Поддерживаемые входные данные:
    -----BEGIN OPENSSH PRIVATE KEY-----
              ...base64...
    -----END OPENSSH PRIVATE KEY-----

Выходные данные:
    файл json

"""

import argparse
import base64
import binascii
import json
import os
import sys


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Извлечение n, e, d из ключа OpenSSH RSA private key"
    )
    parser.add_argument("input", help="путь к файлу id_rsa в стандартном формате OpenSSH private key")
    parser.add_argument(
        "-o",
        "--output",
        help="путь к выходному файлу; если выходной файл не указан, результат выводится в stdout",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="формат вывода данных: text или json; по умолчанию text",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = parser_arg()
    args = parser.parse_args(argv)

    try:
        binary = load_pem_openssh_private_key(args.input)
        params = parse_openssh_rsa_private_key(binary)
        write_output(params, args.output, args.format)
        return 0
    """
    Чуть позже добавлю класс ParseError для исключений
    
    except ParseError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    """
    except KeyboardInterrupt:
        print("Ошибка: выполнение прервано пользователем", file=sys.stderr)
        return 2
