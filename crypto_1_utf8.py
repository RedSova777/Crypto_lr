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
from dataclasses import dataclass
from typing import Any, Dict, Optional


OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
AUTH_MAGIC = b"openssh-key-v1\x00"
SUPPORTED_KEY_TYPE = "ssh-rsa"


class ParseError(Exception):
    """Входные данные имеют недопустимую или неподдерживаемую структуру"""


class ByteReader:
    """Безопасный считыватель двоичных файлов SSH: uint32 и строка с префиксом длины."""

    def __init__(self, data: bytes, label: str = "buffer") -> None:
        self._data = data
        self._pos = 0
        self._label = label

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _require(self, size: int, what: str) -> None:
        if size < 0:
            raise ParseError(f"Некорректная длина для {what}: {size}")
        if self._pos + size > len(self._data):
            raise ParseError(
                f"Недостаточно данных при чтении {what} в {self._label}: "
                f"нужно {size} байт, доступно {self.remaining}"
            )

    def read_bytes(self, size: int, what: str = "bytes") -> bytes:
        self._require(size, what)
        out = self._data[self._pos : self._pos + size]
        self._pos += size
        return out

    def read_uint32(self, what: str = "uint32") -> int:
        raw = self.read_bytes(4, what)
        return int.from_bytes(raw, byteorder="big", signed=False)

    def read_string(self, what: str = "string") -> bytes:
        length = self.read_uint32(f"длина {what}")
        if length > self.remaining:
            raise ParseError(
                f"Некорректная длина поля {what}: заявлено {length} байт, "
                f"осталось {self.remaining} байт"
            )
        return self.read_bytes(length, what)

    def ensure_consumed(self) -> None:
        if self.remaining != 0:
            raise ParseError(
                f"Лишние данные в {self._label}: {self.remaining} байт после завершения разбора"
            )


@dataclass(frozen=True)
class RsaPrivateParameters:
    key_type: str
    modulus_n: int
    public_exponent_e: int
    private_exponent_d: int
    comment: str
    bits: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_type": self.key_type,
            "bits": self.bits,
            "comment": self.comment,
            "modulus_n": {
                "decimal": str(self.modulus_n),
                "hex": "0x" + format(self.modulus_n, "x"),
            },
            "public_exponent_e": {
                "decimal": str(self.public_exponent_e),
                "hex": "0x" + format(self.public_exponent_e, "x"),
            },
            "private_exponent_d": {
                "decimal": str(self.private_exponent_d),
                "hex": "0x" + format(self.private_exponent_d, "x"),
            },
        }


#WRITE
def write_output(params: RsaPrivateParameters, output_path: Optional[str], output_format: str) -> None:
    if output_format == "json":
        content = json.dumps(params.to_dict(), ensure_ascii=False, indent=2) + "\n"
    else:
        content = format_text(params)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as exc:
            raise ParseError(f"Не удалось записать выходной файл: {exc}") from exc
    else:
        print(content, end="")
        

def format_text(params: RsaPrivateParameters) -> str:
    return "\n".join(
        [
            "OpenSSH RSA private key parameters",
            "==================================",
            f"Key type: {params.key_type}",
            f"Comment: {params.comment}",
            f"Modulus size: {params.bits} bits",
            "",
            "Modulus n:",
            "  decimal: " + str(params.modulus_n),
            "  hex:     0x" + format(params.modulus_n, "x"),
            "",
            "Public exponent e:",
            "  decimal: " + str(params.public_exponent_e),
            "  hex:     0x" + format(params.public_exponent_e, "x"),
            "",
            "Private exponent d:",
            "  decimal: " + str(params.private_exponent_d),
            "  hex:     0x" + format(params.private_exponent_d, "x"),
            "",
        ]
    )
    
    
    





def decode_ascii(raw: bytes, field_name: str) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Поле {field_name} не является ASCII-строкой") from exc


def parse_openssh_rsa_private_key(binary: bytes) -> RsaPrivateParameters:
    if not binary.startswith(AUTH_MAGIC):
        raise ParseError("Некорректный magic-заголовок: ожидалось openssh-key-v1\\0")

    reader = ByteReader(binary[len(AUTH_MAGIC) :], "openssh-key-v1 structure")

    ciphername = decode_ascii(reader.read_string("ciphername"), "ciphername")
    kdfname = decode_ascii(reader.read_string("kdfname"), "kdfname")
    kdfoptions = reader.read_string("kdfoptions")
    nkeys = reader.read_uint32("number of keys")

    if ciphername != "none" or kdfname != "none":
        raise ParseError(
            f"Зашифрованные ключи не поддерживаются этим заданием: "
            f"ciphername={ciphername!r}, kdfname={kdfname!r}"
        )
    if kdfoptions != b"":
        raise ParseError("Для незашифрованного ключа kdfoptions должен быть пустым")
    if nkeys != 1:
        raise ParseError(f"Ожидался ровно один ключ, найдено: {nkeys}")

    public_blob = reader.read_string("public key blob")
    private_blob = reader.read_string("private key blob")
    reader.ensure_consumed()

    public_part = parse_public_rsa_blob(public_blob)
    return parse_private_rsa_blob(
        private_blob=private_blob,
        public_n=public_part["n"],
        public_e=public_part["e"],
    )


def parse_private_rsa_blob(private_blob: bytes, public_n: int, public_e: int) -> RsaPrivateParameters:
    reader = ByteReader(private_blob, "private key blob")

    check1 = reader.read_uint32("checkint 1")
    check2 = reader.read_uint32("checkint 2")
    if check1 != check2:
        raise ParseError(
            "Контрольные значения checkint не совпадают: "
            "ключ повреждён или зашифрован неверным способом"
        )

    key_type = decode_ascii(reader.read_string("private key type"), "private key type")
    if key_type != SUPPORTED_KEY_TYPE:
        raise ParseError(
            f"Неподдерживаемый тип приватного ключа: {key_type}. "
            f"Для задания нужен RSA-ключ типа {SUPPORTED_KEY_TYPE}."
        )

    n = read_positive_mpint(reader, "modulus n")
    e = read_positive_mpint(reader, "public exponent e")
    d = read_positive_mpint(reader, "private exponent d")

    # OpenSSH stores additional RSA CRT parameters after d. They are not required
    # in the task output, but reading them is necessary to reach the comment/padding
    # and verify the private blob structure.
    _iqmp = read_positive_mpint(reader, "iqmp")
    _p = read_positive_mpint(reader, "prime p")
    _q = read_positive_mpint(reader, "prime q")

    try:
        comment = reader.read_string("comment").decode("utf-8", errors="replace")
    except ParseError:
        raise

    padding = reader.read_bytes(reader.remaining, "padding")
    validate_openssh_padding(padding)

    if n != public_n or e != public_e:
        raise ParseError(
            "Публичная и приватная части ключа не совпадают по modulus/public exponent"
        )

    return RsaPrivateParameters(
        key_type=key_type,
        modulus_n=n,
        public_exponent_e=e,
        private_exponent_d=d,
        comment=comment,
        bits=n.bit_length(),
    )


def parse_public_rsa_blob(public_blob: bytes) -> Dict[str, int]:
    reader = ByteReader(public_blob, "public key blob")
    key_type = decode_ascii(reader.read_string("public key type"), "public key type")
    if key_type != SUPPORTED_KEY_TYPE:
        raise ParseError(
            f"Неподдерживаемый тип ключа: {key_type}. "
            f"Для задания нужен RSA-ключ типа {SUPPORTED_KEY_TYPE}."
        )

    e = read_positive_mpint(reader, "public exponent e")
    n = read_positive_mpint(reader, "modulus n")
    reader.ensure_consumed()
    return {"e": e, "n": n}


def read_positive_mpint(reader: ByteReader, name: str) -> int:
    """
    Read SSH mpint stored as a length-prefixed two's-complement integer.
    RSA parameters must be positive, so negative encodings are rejected.
    """
    raw = reader.read_string(name)

    if len(raw) == 0:
        value = 0
    else:
        # In SSH mpint, a positive value with the high bit set must be encoded
        # with a leading zero byte. Without it the value would be negative.
        if raw[0] & 0x80:
            raise ParseError(
                f"Поле {name} закодировано как отрицательное mpint или повреждено"
            )
        # Optional strictness: reject unnecessary leading zeros.
        if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
            raise ParseError(f"Поле {name} содержит неминимальное mpint-кодирование")
        value = int.from_bytes(raw, byteorder="big", signed=False)

    if value <= 0:
        raise ParseError(f"Поле {name} должно быть положительным числом")
    return value


def validate_openssh_padding(padding: bytes) -> None:
    # OpenSSH pads the private block with bytes 1, 2, 3, ...
    for index, byte in enumerate(padding, start=1):
        expected = index & 0xFF
        if byte != expected:
            raise ParseError(
                f"Некорректный padding приватного блока: байт #{index} = {byte}, "
                f"ожидалось {expected}"
            )


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
        params = parse_openssh_rsa_private_key(binary)
        write_output(params, args.output, args.format)
        return 0
    except KeyboardInterrupt:
        print("Ошибка: выполнение прервано пользователем", file=sys.stderr)
        return 2

main()