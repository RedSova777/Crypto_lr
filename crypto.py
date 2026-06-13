#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Парсер закрытых ключей OpenSSH в формате openssh-key-v1.

Поддерживаемые входные данные:
    -----BEGIN OPENSSH PRIVATE KEY-----
              ...base64...
    -----END OPENSSH PRIVATE KEY-----

Поддерживаемые типы ключей:
    - ssh-rsa
    - ecdsa-sha2-nistp256
    - ecdsa-sha2-nistp384
    - ecdsa-sha2-nistp521
    - ssh-ed25519

Выходные форматы:
    - text
    - json

Примечание:
    Для RSA выводятся параметры n, e, d.
    Для ECDSA выводятся curve, публичная точка Q=(x,y) и приватный скаляр d.
    Для Ed25519 выводятся публичный ключ, seed и полный приватный блок OpenSSH.
"""

import argparse
import base64
import binascii
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union


OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
AUTH_MAGIC = b"openssh-key-v1\x00"

RSA_KEY_TYPE = "ssh-rsa"
ED25519_KEY_TYPE = "ssh-ed25519"
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 64

ECDSA_KEY_TYPES = {
    "ecdsa-sha2-nistp256": {"curve": "nistp256", "coord_size": 32, "bits": 256},
    "ecdsa-sha2-nistp384": {"curve": "nistp384", "coord_size": 48, "bits": 384},
    "ecdsa-sha2-nistp521": {"curve": "nistp521", "coord_size": 66, "bits": 521},
}


class ParseError(Exception):
    """Ошибка некорректного или неподдерживаемого формата входных данных."""


class ByteReader:
    """Безопасный считыватель двоичных SSH-структур."""

    def __init__(self, data: bytes, label: str = "buffer") -> None:
        """
        Создаёт считыватель для последовательного чтения байтов.
        """
        self._data = data
        self._pos = 0
        self._label = label

    @property
    def pos(self) -> int:
        """
        Возвращает текущую позицию чтения в буфере.
        """
        return self._pos

    @property
    def remaining(self) -> int:
        """
        Возвращает количество непрочитанных байтов.
        """
        return len(self._data) - self._pos

    def _require(self, size: int, what: str) -> None:
        """
        Проверяет, что в буфере достаточно байтов для чтения поля.

        Входные данные:
            size: требуемый размер поля в байтах.
            what: название поля для диагностического сообщения.

        Выходные данные:
            None. Если данных достаточно, функция ничего не возвращает.

        Исключения:
            ParseError: если размер отрицательный или в буфере недостаточно данных.
        """
        if size < 0:
            raise ParseError(f"Некорректная длина для {what}: {size}")
        if self._pos + size > len(self._data):
            raise ParseError(
                f"Недостаточно данных при чтении {what} в {self._label}: "
                f"нужно {size} байт, доступно {self.remaining}"
            )

    def read_bytes(self, size: int, what: str = "bytes") -> bytes:
        """
        Считывает указанное количество байтов и сдвигает текущую позицию.

        Входные данные:
            size: количество байтов для чтения.
            what: название поля для сообщений об ошибках.

        Выходные данные:
            bytes: прочитанный фрагмент данных.

        Исключения:
            ParseError: если в буфере недостаточно данных.
        """
        self._require(size, what)
        out = self._data[self._pos : self._pos + size]
        self._pos += size
        return out

    def read_uint32(self, what: str = "uint32") -> int:
        """
        Считывает 4-байтовое беззнаковое число в формате big-endian.

        Входные данные:
            what: название поля для сообщений об ошибках.

        Выходные данные:
            int: значение uint32.

        Исключения:
            ParseError: если в буфере недостаточно данных.
        """
        raw = self.read_bytes(4, what)
        return int.from_bytes(raw, byteorder="big", signed=False)

    def read_string(self, what: str = "string") -> bytes:
        """
        Считывает SSH string: uint32-длина + указанное число байтов.

        Входные данные:
            what: название поля для сообщений об ошибках.

        Выходные данные:
            bytes: содержимое SSH string без 4-байтового префикса длины.

        Исключения:
            ParseError: если заявленная длина больше оставшегося размера буфера.
        """
        length = self.read_uint32(f"длина {what}")
        if length > self.remaining:
            raise ParseError(
                f"Некорректная длина поля {what}: заявлено {length} байт, "
                f"осталось {self.remaining} байт"
            )
        return self.read_bytes(length, what)

    def ensure_consumed(self) -> None:
        """
        Проверяет, что буфер полностью разобран.

        Входные данные:
            Нет.

        Выходные данные:
            None. Если буфер прочитан полностью, функция ничего не возвращает.

        Исключения:
            ParseError: если после разбора остались лишние байты.
        """
        if self.remaining != 0:
            raise ParseError(
                f"Лишние данные в {self._label}: {self.remaining} байт после завершения разбора"
            )

###
# конец блока reader, отвечающего за безопасное чтение бинарных SSH-структур
###


###
# начало блока models, отвечающего за структуры выходных данных
###

@dataclass(frozen=True)
class RsaPrivateParameters:
    key_type: str
    modulus_n: int
    public_exponent_e: int
    private_exponent_d: int
    comment: str
    bits: int

    def to_dict(self) -> Dict[str, Any]:
        """
        Преобразует параметры RSA-ключа в словарь для JSON-вывода.

        Входные данные:
            Нет. Используются поля текущего объекта RsaPrivateParameters.

        Выходные данные:
            Dict[str, Any]: словарь с типом ключа, размером, комментарием,
            модулем n, публичной экспонентой e и приватной экспонентой d.
        """
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


@dataclass(frozen=True)
class EcdsaPrivateParameters:
    key_type: str
    curve: str
    public_key_q_hex: str
    public_key_x: int
    public_key_y: int
    private_scalar_d: int
    comment: str
    bits: int

    def to_dict(self) -> Dict[str, Any]:
        """
        Преобразует параметры ECDSA-ключа в словарь для JSON-вывода.

        Входные данные:
            Нет. Используются поля текущего объекта EcdsaPrivateParameters.

        Выходные данные:
            Dict[str, Any]: словарь с типом ключа, кривой, публичной точкой Q,
            координатами X/Y, приватным скаляром d и комментарием.
        """
        return {
            "key_type": self.key_type,
            "bits": self.bits,
            "curve": self.curve,
            "comment": self.comment,
            "public_key_q": {
                "hex": "0x" + self.public_key_q_hex,
            },
            "public_key_x": {
                "decimal": str(self.public_key_x),
                "hex": "0x" + format(self.public_key_x, "x"),
            },
            "public_key_y": {
                "decimal": str(self.public_key_y),
                "hex": "0x" + format(self.public_key_y, "x"),
            },
            "private_scalar_d": {
                "decimal": str(self.private_scalar_d),
                "hex": "0x" + format(self.private_scalar_d, "x"),
            },
        }


@dataclass(frozen=True)
class Ed25519PrivateParameters:
    key_type: str
    public_key_hex: str
    private_seed_hex: str
    private_key_raw_hex: str
    comment: str
    bits: int = 256

    def to_dict(self) -> Dict[str, Any]:
        """
        Преобразует параметры Ed25519-ключа в словарь для JSON-вывода.

        Входные данные:
            Нет. Используются поля текущего объекта Ed25519PrivateParameters.

        Выходные данные:
            Dict[str, Any]: словарь с типом ключа, размером, публичным ключом,
            приватным seed, полным приватным блоком и комментарием.
        """
        return {
            "key_type": self.key_type,
            "bits": self.bits,
            "comment": self.comment,
            "public_key": {
                "hex": "0x" + self.public_key_hex,
            },
            "private_seed": {
                "hex": "0x" + self.private_seed_hex,
            },
            "private_key_raw": {
                "hex": "0x" + self.private_key_raw_hex,
            },
        }


ParsedKey = Union[RsaPrivateParameters, EcdsaPrivateParameters, Ed25519PrivateParameters]

###
# конец блока models, отвечающего за структуры выходных данных
###


###
# начало блока helpers, отвечающего за вспомогательные функции
###

def supported_key_types_text() -> str:
    """
    Формирует строку со списком поддерживаемых типов ключей.

    Входные данные:
        Нет.

    Выходные данные:
        str: строка с типами ключей через запятую.
    """
    return ", ".join([RSA_KEY_TYPE, *ECDSA_KEY_TYPES.keys(), ED25519_KEY_TYPE])


def decode_ascii(raw: bytes, field_name: str) -> str:
    """
    Декодирует байтовое поле как ASCII-строку.

    Входные данные:
        raw: байты, которые нужно декодировать.
        field_name: название поля для сообщения об ошибке.

    Выходные данные:
        str: декодированная ASCII-строка.

    Исключения:
        ParseError: если поле не является корректной ASCII-строкой.
    """
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Поле {field_name} не является ASCII-строкой") from exc


def read_positive_mpint(reader: ByteReader, name: str) -> int:
    """
    Читает положительное SSH mpint.

    SSH mpint хранится как SSH string, внутри которого находится целое число
    в big-endian two's-complement формате. Для параметров ключей в этом
    парсере ожидаются только положительные значения.

    Входные данные:
        reader: объект ByteReader, из которого читается поле.
        name: название поля для сообщения об ошибке.

    Выходные данные:
        int: положительное целое число.

    Исключения:
        ParseError: если mpint отрицательный, нулевой, повреждённый
        или использует неминимальное кодирование.
    """
    raw = reader.read_string(name)

    if len(raw) == 0:
        value = 0
    else:
        if raw[0] & 0x80:
            raise ParseError(f"Поле {name} закодировано как отрицательное mpint или повреждено")
        if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
            raise ParseError(f"Поле {name} содержит неминимальное mpint-кодирование")
        value = int.from_bytes(raw, byteorder="big", signed=False)

    if value <= 0:
        raise ParseError(f"Поле {name} должно быть положительным числом")
    return value


def validate_openssh_padding(padding: bytes) -> None:
    """
    Проверяет padding приватного блока OpenSSH.

    В OpenSSH private blob дополняется байтами 1, 2, 3, ...
    до границы блока. Для незашифрованных ключей это также проверяется.

    Входные данные:
        padding: оставшиеся байты после разбора приватных полей и comment.

    Выходные данные:
        None. Если padding корректный, функция ничего не возвращает.

    Исключения:
        ParseError: если padding не соответствует последовательности 1, 2, 3, ...
    """
    for index, byte in enumerate(padding, start=1):
        expected = index & 0xFF
        if byte != expected:
            raise ParseError(
                f"Некорректный padding приватного блока: байт #{index} = {byte}, "
                f"ожидалось {expected}"
            )

###
# конец блока helpers, отвечающего за вспомогательные функции
###


###
# начало блока read, отвечающего за чтение файла и извлечение бинарного содержимого
###

def load_openssh_private_key(path: str) -> bytes:
    """
    Загружает ASCII-armored файл закрытого ключа OpenSSH и декодирует Base64.

    Функция проверяет наличие BEGIN/END-маркеров, извлекает Base64-содержимое
    между ними и возвращает бинарную структуру openssh-key-v1.

    Входные данные:
        path: путь к файлу закрытого ключа OpenSSH.

    Выходные данные:
        bytes: бинарные данные после Base64-декодирования.

    Исключения:
        ParseError: если файл не найден, недоступен, имеет неправильные маркеры
        или содержит некорректный Base64.
    """
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
        raise ParseError("Файл не является ASCII-armored OpenSSH private key") from exc
    except OSError as exc:
        raise ParseError(f"Не удалось прочитать файл: {exc}") from exc

    non_empty_lines = [line for line in lines if line]
    if len(non_empty_lines) < 3:
        raise ParseError("Файл слишком короткий для OpenSSH private key")
    if non_empty_lines[0] != OPENSSH_BEGIN:
        raise ParseError(f"Ожидался заголовок {OPENSSH_BEGIN}")
    if non_empty_lines[-1] != OPENSSH_END:
        raise ParseError(f"Ожидался завершающий маркер {OPENSSH_END}")

    b64_body = "".join(non_empty_lines[1:-1])
    if not b64_body:
        raise ParseError("Блок между BEGIN и END не содержит Base64-данных")

    try:
        return base64.b64decode(b64_body, validate=True)
    except binascii.Error as exc:
        raise ParseError(f"Некорректные Base64-данные: {exc}") from exc

###
# конец блока read, отвечающего за чтение файла и извлечение бинарного содержимого
###


###
# начало блока parse_public, отвечающего за разбор публичной части ключа
###

def parse_public_key_blob(public_blob: bytes) -> Dict[str, Any]:
    """
    Разбирает public key blob из структуры openssh-key-v1.

    В зависимости от типа ключа функция читает RSA-поля, ECDSA-поля
    или Ed25519-поля и возвращает промежуточное описание публичной части.

    Входные данные:
        public_blob: бинарный SSH string с публичной частью ключа.

    Выходные данные:
        Dict[str, Any]: словарь с полями публичной части:
            - для RSA: key_type, e, n;
            - для ECDSA: key_type, curve, public_q;
            - для Ed25519: key_type, public_key.

    Исключения:
        ParseError: если тип ключа не поддерживается или структура повреждена.
    """
    reader = ByteReader(public_blob, "public key blob")
    key_type = decode_ascii(reader.read_string("public key type"), "public key type")

    if key_type == RSA_KEY_TYPE:
        e = read_positive_mpint(reader, "public exponent e")
        n = read_positive_mpint(reader, "modulus n")
        reader.ensure_consumed()
        return {"key_type": key_type, "e": e, "n": n}

    if key_type in ECDSA_KEY_TYPES:
        curve = decode_ascii(reader.read_string("ecdsa curve name"), "ecdsa curve name")
        public_q = reader.read_string("ecdsa public point Q")
        reader.ensure_consumed()

        expected_curve = ECDSA_KEY_TYPES[key_type]["curve"]
        if curve != expected_curve:
            raise ParseError(
                f"Тип ключа {key_type} не соответствует имени кривой {curve}; "
                f"ожидалось {expected_curve}"
            )

        return {
            "key_type": key_type,
            "curve": curve,
            "public_q": public_q,
        }

    if key_type == ED25519_KEY_TYPE:
        public_key = reader.read_string("ed25519 public key")
        reader.ensure_consumed()

        if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
            raise ParseError(
                f"Некорректная длина публичного ключа Ed25519: {len(public_key)} байт, "
                f"ожидалось {ED25519_PUBLIC_KEY_SIZE}"
            )

        return {
            "key_type": key_type,
            "public_key": public_key,
        }

    raise ParseError(
        f"Неподдерживаемый тип ключа: {key_type}. "
        f"Поддерживаются: {supported_key_types_text()}."
    )


def split_ecdsa_public_point(key_type: str, q: bytes) -> Dict[str, int]:
    """
    Разделяет публичную точку ECDSA на координаты X и Y.

    Функция поддерживает несжатую форму точки:
        0x04 || X || Y

    Входные данные:
        key_type: тип ECDSA-ключа, например ecdsa-sha2-nistp256.
        q: байтовое представление публичной точки.

    Выходные данные:
        Dict[str, int]: словарь с координатами x и y.

    Исключения:
        ParseError: если длина точки некорректна или точка не находится
        в несжатом формате с префиксом 0x04.
    """
    coord_size = ECDSA_KEY_TYPES[key_type]["coord_size"]
    expected_len = 1 + 2 * coord_size

    if len(q) != expected_len:
        raise ParseError(
            f"Некорректная длина публичной точки ECDSA: {len(q)} байт, "
            f"ожидалось {expected_len}"
        )
    if q[0] != 0x04:
        raise ParseError(
            f"Неподдерживаемый формат публичной точки ECDSA: первый байт 0x{q[0]:02x}; "
            f"ожидалась несжатая точка с префиксом 0x04"
        )

    x_raw = q[1 : 1 + coord_size]
    y_raw = q[1 + coord_size :]

    return {
        "x": int.from_bytes(x_raw, byteorder="big", signed=False),
        "y": int.from_bytes(y_raw, byteorder="big", signed=False),
    }

###
# конец блока parse_public, отвечающего за разбор публичной части ключа
###


###
# начало блока parse_private, отвечающего за разбор приватной части ключа
###

def parse_private_blob(private_blob: bytes, public_part: Dict[str, Any]) -> ParsedKey:
    """
    Разбирает private key blob и выбирает обработчик по типу ключа.

    Функция проверяет контрольные значения checkint, сверяет тип публичной
    и приватной части, затем передаёт чтение тела ключа специализированной
    функции: RSA, ECDSA или Ed25519.

    Входные данные:
        private_blob: бинарный private key blob из openssh-key-v1.
        public_part: словарь с уже разобранной публичной частью ключа.

    Выходные данные:
        ParsedKey: объект RsaPrivateParameters, EcdsaPrivateParameters
        или Ed25519PrivateParameters.

    Исключения:
        ParseError: если checkint не совпадают, типы ключа различаются
        или приватный тип ключа не поддерживается.
    """
    reader = ByteReader(private_blob, "private key blob")

    check1 = reader.read_uint32("checkint 1")
    check2 = reader.read_uint32("checkint 2")
    if check1 != check2:
        raise ParseError(
            "Контрольные значения checkint не совпадают: "
            "ключ повреждён или зашифрован неверным способом"
        )

    key_type = decode_ascii(reader.read_string("private key type"), "private key type")
    if key_type != public_part["key_type"]:
        raise ParseError(
            f"Тип публичной части ({public_part['key_type']}) не совпадает "
            f"с типом приватной части ({key_type})"
        )

    if key_type == RSA_KEY_TYPE:
        return parse_private_rsa_body(reader, public_part)

    if key_type in ECDSA_KEY_TYPES:
        return parse_private_ecdsa_body(reader, public_part)

    if key_type == ED25519_KEY_TYPE:
        return parse_private_ed25519_body(reader, public_part)

    raise ParseError(f"Неподдерживаемый тип приватного ключа: {key_type}")


def parse_private_rsa_body(reader: ByteReader, public_part: Dict[str, Any]) -> RsaPrivateParameters:
    """
    Разбирает тело приватной части RSA-ключа.

    Входные данные:
        reader: ByteReader, установленный сразу после поля private key type.
        public_part: словарь с публичными RSA-параметрами n и e.

    Выходные данные:
        RsaPrivateParameters: объект с параметрами RSA n, e, d,
        комментарием и размером ключа.

    Исключения:
        ParseError: если поля повреждены, padding некорректен
        или публичная и приватная части не совпадают по n/e.
    """
    n = read_positive_mpint(reader, "modulus n")
    e = read_positive_mpint(reader, "public exponent e")
    d = read_positive_mpint(reader, "private exponent d")

    # OpenSSH хранит дополнительные RSA CRT-параметры после d.
    # Для вывода n/e/d они не нужны, но их нужно прочитать, чтобы добраться до comment и padding.
    _iqmp = read_positive_mpint(reader, "iqmp")
    _p = read_positive_mpint(reader, "prime p")
    _q = read_positive_mpint(reader, "prime q")

    comment = reader.read_string("comment").decode("utf-8", errors="replace")

    padding = reader.read_bytes(reader.remaining, "padding")
    validate_openssh_padding(padding)

    if n != public_part["n"] or e != public_part["e"]:
        raise ParseError("Публичная и приватная части RSA-ключа не совпадают по n/e")

    return RsaPrivateParameters(
        key_type=RSA_KEY_TYPE,
        modulus_n=n,
        public_exponent_e=e,
        private_exponent_d=d,
        comment=comment,
        bits=n.bit_length(),
    )


def parse_private_ecdsa_body(reader: ByteReader, public_part: Dict[str, Any]) -> EcdsaPrivateParameters:
    """
    Разбирает тело приватной части ECDSA-ключа.

    Входные данные:
        reader: ByteReader, установленный сразу после поля private key type.
        public_part: словарь с публичной ECDSA-частью: curve и public_q.

    Выходные данные:
        EcdsaPrivateParameters: объект с именем кривой, публичной точкой,
        координатами X/Y, приватным скаляром d и комментарием.

    Исключения:
        ParseError: если кривая некорректна, публичная и приватная части
        не совпадают или padding повреждён.
    """
    curve = decode_ascii(reader.read_string("ecdsa curve name"), "ecdsa curve name")
    public_q = reader.read_string("ecdsa public point Q")
    private_d = read_positive_mpint(reader, "ecdsa private scalar d")
    comment = reader.read_string("comment").decode("utf-8", errors="replace")

    padding = reader.read_bytes(reader.remaining, "padding")
    validate_openssh_padding(padding)

    expected_curve = ECDSA_KEY_TYPES[public_part["key_type"]]["curve"]
    if curve != expected_curve:
        raise ParseError(f"Некорректная кривая ECDSA: {curve}; ожидалось {expected_curve}")

    if curve != public_part["curve"] or public_q != public_part["public_q"]:
        raise ParseError("Публичная и приватная части ECDSA-ключа не совпадают")

    point = split_ecdsa_public_point(public_part["key_type"], public_q)

    return EcdsaPrivateParameters(
        key_type=public_part["key_type"],
        curve=curve,
        public_key_q_hex=public_q.hex(),
        public_key_x=point["x"],
        public_key_y=point["y"],
        private_scalar_d=private_d,
        comment=comment,
        bits=ECDSA_KEY_TYPES[public_part["key_type"]]["bits"],
    )


def parse_private_ed25519_body(reader: ByteReader, public_part: Dict[str, Any]) -> Ed25519PrivateParameters:
    """
    Разбирает тело приватной части Ed25519-ключа.

    После строки key_type в private blob идут:
        string public_key    # 32 байта
        string private_key   # 64 байта: seed(32) || public_key(32)
        string comment
        padding

    Входные данные:
        reader: ByteReader, установленный сразу после поля private key type.
        public_part: словарь с публичным Ed25519-ключом из public blob.

    Выходные данные:
        Ed25519PrivateParameters: объект с публичным ключом, приватным seed,
        полным приватным блоком OpenSSH и комментарием.

    Исключения:
        ParseError: если длины Ed25519-полей некорректны, публичная часть
        не совпадает или padding повреждён.
    """
    public_key = reader.read_string("ed25519 public key")
    private_key = reader.read_string("ed25519 private key")
    comment = reader.read_string("comment").decode("utf-8", errors="replace")

    padding = reader.read_bytes(reader.remaining, "padding")
    validate_openssh_padding(padding)

    if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise ParseError(
            f"Некорректная длина публичного ключа Ed25519 в приватном блоке: "
            f"{len(public_key)} байт, ожидалось {ED25519_PUBLIC_KEY_SIZE}"
        )

    if len(private_key) != ED25519_PRIVATE_KEY_SIZE:
        raise ParseError(
            f"Некорректная длина приватного ключа Ed25519: "
            f"{len(private_key)} байт, ожидалось {ED25519_PRIVATE_KEY_SIZE}"
        )

    seed = private_key[:ED25519_PUBLIC_KEY_SIZE]
    public_key_from_private = private_key[ED25519_PUBLIC_KEY_SIZE:]

    if public_key != public_part["public_key"]:
        raise ParseError("Публичная часть Ed25519 в public blob и private blob не совпадает")

    if public_key_from_private != public_key:
        raise ParseError(
            "Приватный блок Ed25519 повреждён: последние 32 байта private_key "
            "не совпадают с публичным ключом"
        )

    return Ed25519PrivateParameters(
        key_type=ED25519_KEY_TYPE,
        public_key_hex=public_key.hex(),
        private_seed_hex=seed.hex(),
        private_key_raw_hex=private_key.hex(),
        comment=comment,
    )

###
# конец блока parse_private, отвечающего за разбор приватной части ключа
###


###
# начало блока parse_main, отвечающего за общий разбор структуры openssh-key-v1
###

def parse_openssh_private_key(binary: bytes) -> ParsedKey:
    """
    Разбирает бинарную структуру openssh-key-v1 целиком.

    Функция проверяет magic-заголовок, параметры шифрования, количество ключей,
    извлекает public key blob и private key blob, затем запускает разбор
    публичной и приватной частей.

    Входные данные:
        binary: бинарные данные после Base64-декодирования OpenSSH private key.

    Выходные данные:
        ParsedKey: объект с параметрами RSA, ECDSA или Ed25519.

    Исключения:
        ParseError: если magic некорректен, ключ зашифрован, количество ключей
        не равно одному или структура повреждена.
    """
    if not binary.startswith(AUTH_MAGIC):
        raise ParseError("Некорректный magic-заголовок: ожидалось openssh-key-v1\\0")

    reader = ByteReader(binary[len(AUTH_MAGIC) :], "openssh-key-v1 structure")

    ciphername = decode_ascii(reader.read_string("ciphername"), "ciphername")
    kdfname = decode_ascii(reader.read_string("kdfname"), "kdfname")
    kdfoptions = reader.read_string("kdfoptions")
    nkeys = reader.read_uint32("number of keys")

    if ciphername != "none" or kdfname != "none":
        raise ParseError(
            f"Зашифрованные ключи не поддерживаются: "
            f"ciphername={ciphername!r}, kdfname={kdfname!r}"
        )
    if kdfoptions != b"":
        raise ParseError("Для незашифрованного ключа kdfoptions должен быть пустым")
    if nkeys != 1:
        raise ParseError(f"Ожидался ровно один ключ, найдено: {nkeys}")

    public_blob = reader.read_string("public key blob")
    private_blob = reader.read_string("private key blob")
    reader.ensure_consumed()

    public_part = parse_public_key_blob(public_blob)
    return parse_private_blob(private_blob, public_part)

###
# конец блока parse_main, отвечающего за общий разбор структуры openssh-key-v1
###


###
# начало блока format, отвечающего за преобразование результата в человекочитаемый текст
###

def format_text(params: ParsedKey) -> str:
    """
    Формирует текстовое представление разобранного ключа.

    Входные данные:
        params: объект RsaPrivateParameters, EcdsaPrivateParameters
        или Ed25519PrivateParameters.

    Выходные данные:
        str: многострочный текст с параметрами ключа.

    Исключения:
        ParseError: если тип объекта результата неизвестен.
    """
    if isinstance(params, RsaPrivateParameters):
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

    if isinstance(params, EcdsaPrivateParameters):
        return "\n".join(
            [
                "OpenSSH ECDSA private key parameters",
                "====================================",
                f"Key type: {params.key_type}",
                f"Curve: {params.curve}",
                f"Curve size: {params.bits} bits",
                f"Comment: {params.comment}",
                "",
                "Public key Q:",
                "  hex:     0x" + params.public_key_q_hex,
                "",
                "Public point X:",
                "  decimal: " + str(params.public_key_x),
                "  hex:     0x" + format(params.public_key_x, "x"),
                "",
                "Public point Y:",
                "  decimal: " + str(params.public_key_y),
                "  hex:     0x" + format(params.public_key_y, "x"),
                "",
                "Private scalar d:",
                "  decimal: " + str(params.private_scalar_d),
                "  hex:     0x" + format(params.private_scalar_d, "x"),
                "",
            ]
        )

    if isinstance(params, Ed25519PrivateParameters):
        return "\n".join(
            [
                "OpenSSH Ed25519 private key parameters",
                "======================================",
                f"Key type: {params.key_type}",
                f"Key size: {params.bits} bits",
                f"Comment: {params.comment}",
                "",
                "Public key:",
                "  hex:     0x" + params.public_key_hex,
                "",
                "Private seed:",
                "  hex:     0x" + params.private_seed_hex,
                "",
                "Private key raw bytes:",
                "  hex:     0x" + params.private_key_raw_hex,
                "",
            ]
        )

    raise ParseError("Неизвестный тип результата разбора")

###
# конец блока format, отвечающего за преобразование результата в человекочитаемый текст
###


###
# начало блока write, отвечающего за запись результата
###

def write_output(params: ParsedKey, output_path: Optional[str], output_format: str) -> None:
    """
    Записывает результат разбора в файл или выводит его в stdout.

    Если выбран JSON, объект параметров преобразуется через to_dict().
    Если выбран text, используется функция format_text().

    Входные данные:
        params: объект с разобранными параметрами ключа.
        output_path: путь к выходному файлу или None для вывода в консоль.
        output_format: строка "json" или "text".

    Выходные данные:
        None. Результат записывается в файл или печатается в stdout.

    Исключения:
        ParseError: если не удалось записать выходной файл.
    """
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

###
# конец блока write, отвечающего за запись результата
###


###
# начало блока cli, отвечающего за аргументы командной строки
###

def parser_arg() -> argparse.ArgumentParser:
    """
    Создаёт и настраивает парсер аргументов командной строки.

    Входные данные:
        Нет.

    Выходные данные:
        argparse.ArgumentParser: объект парсера с аргументами input, output и format.
    """
    parser = argparse.ArgumentParser(
        description="Разбор закрытого ключа OpenSSH: RSA, ECDSA или Ed25519"
    )
    parser.add_argument("input", help="путь к файлу закрытого ключа OpenSSH")
    parser.add_argument(
        "-o",
        "--output",
        help="путь к выходному файлу; если не указан, результат выводится в stdout",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="формат вывода: text или json; по умолчанию text",
    )
    return parser

###
# конец блока cli, отвечающего за аргументы командной строки
###


###
# начало блока main, отвечающего за запуск программы
###

def main(argv: Optional[list[str]] = None) -> int:
    """
    Точка входа программы.

    Функция получает аргументы командной строки, читает файл ключа,
    запускает разбор OpenSSH-структуры и выводит результат в выбранном формате.

    Входные данные:
        argv: список аргументов командной строки без имени программы
        или None, чтобы использовать sys.argv.

    Выходные данные:
        int: код завершения программы:
            0 — успешное выполнение;
            1 — ошибка разбора или ввода-вывода;
            2 — выполнение прервано пользователем.
    """
    parser = parser_arg()
    args = parser.parse_args(argv)

    try:
        binary = load_openssh_private_key(args.input)
        params = parse_openssh_private_key(binary)
        write_output(params, args.output, args.format)
        return 0
    except ParseError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Ошибка: выполнение прервано пользователем", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

###
# конец блока main, отвечающего за запуск программы
###
