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
from typing import Optional


OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
AUTH_MAGIC = b"openssh-key-v1\x00"
SUPPORTED_KEY_TYPE = "ssh-rsa"


def load_openssh_private_key(path: str) -> bytes:
    if not os.path.exists(path):
        raise ParseError(f"Входной файл не найден: {path}")
    if not os.path.isfile(path):
        raise ParseError(f"Путь не является обычным файлом: {path}")
    if not os.access(path, os.R_OK):
        raise ParseError(f"Нет прав на чтение входного файла: {path}")

    try:
        with open(path, "r", encoding="ascii") as f:
            lines = [line.strip() for line in f]
    except UnicodeDecodeError as exc:
        raise ParseError("Файл не является OpenSSH private key; не соответствует кодировки ASCII") from exc
    except OSError as exc:
        raise ParseError(f"Не удалось прочитать файл: {exc}") from exc

    non_empty_list_line_openssh = [line for line in lines if line]
    if len(non_empty_list_line_openssh) < 3:
        raise ParseError("Файл слишком короткий для OpenSSH private key")
    if non_empty_list_line_openssh[0] != OPENSSH_BEGIN:
        raise ParseError(f"Ожидался заголовок {OPENSSH_BEGIN}")
    if non_empty_list_line_openssh[-1] != OPENSSH_END:
        raise ParseError(f"Ожидался завершающий маркер {OPENSSH_END}")

    b64_body = "".join(non_empty_list_line_openssh[1:-1])
    if not b64_body:
        raise ParseError("Блок между BEGIN и END не содержит Base64-данных")

    try:
        #print (base64.b64decode(b64_body, validate=True))
        return base64.b64decode(b64_body, validate=True)
    except binascii.Error as exc:
        raise ParseError(f"Некорректные Base64-данные: {exc}") from exc


def parser_arg() -> argparse.ArgumentParser:
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
    #print(args)
    
    try:
        binary = load_openssh_private_key(args.input)
        return 0
    except KeyboardInterrupt:
        print("Ошибка: выполнение прервано пользователем", file=sys.stderr)
        return 2

main()