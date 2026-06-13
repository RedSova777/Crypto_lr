## 1. Описание основных блоков кода

### 1.1. Блок констант

В начале файла определены постоянные значения:

```python
OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
AUTH_MAGIC = b"openssh-key-v1\x00"

RSA_KEY_TYPE = "ssh-rsa"
ED25519_KEY_TYPE = "ssh-ed25519"
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 64
```

Они используются для проверки формата файла, определения типа ключа и контроля длины полей Ed25519.

Для ECDSA задан словарь:

```python
ECDSA_KEY_TYPES = {
    "ecdsa-sha2-nistp256": {"curve": "nistp256", "coord_size": 32, "bits": 256},
    "ecdsa-sha2-nistp384": {"curve": "nistp384", "coord_size": 48, "bits": 384},
    "ecdsa-sha2-nistp521": {"curve": "nistp521", "coord_size": 66, "bits": 521},
}
```

Он нужен, чтобы понимать, какая кривая соответствует конкретному типу ECDSA-ключа и сколько байт занимает координата точки.

---

### 1.2. Блок ошибок

```python
class ParseError(Exception):
    """Входные данные имеют недопустимую или неподдерживаемую структуру."""
```

Это пользовательское исключение. Через него программа сообщает о проблемах разбора:

- файл не найден;
- неверный заголовок;
- повреждённый Base64;
- неподдерживаемый тип ключа;
- не совпадают публичная и приватная части;
- неверный padding;
- ключ зашифрован.

В `main()` ошибка перехватывается, поэтому пользователь видит понятное сообщение без traceback.

---

### 1.3. Блок `ByteReader`

Класс `ByteReader` используется для безопасного последовательного чтения бинарных данных.

Основные методы:

| Метод | Что делает |
|---|---|
| `_require(size, what)` | Проверяет, что в буфере достаточно байт. |
| `read_bytes(size, what)` | Читает указанное количество байт. |
| `read_uint32(what)` | Читает 4 байта как беззнаковое число big-endian. |
| `read_string(what)` | Читает SSH-строку: сначала длину `uint32`, затем данные. |
| `ensure_consumed()` | Проверяет, что после разбора не осталось лишних данных. |

Формат SSH `string` выглядит так:

```text
uint32 length
byte[length] data
```

Например, если в поле лежит строка `ssh-rsa`, она хранится так:

```text
00 00 00 07 73 73 68 2d 72 73 61
```

где `00 00 00 07` — длина 7 байт, а дальше ASCII-строка `ssh-rsa`.

---

## 2. Разбор RSA-ключа

Для RSA программа извлекает:

- `n` — модуль;
- `e` — публичная экспонента;
- `d` — приватная экспонента;
- `comment` — комментарий ключа;
- `bits` — размер модуля в битах.

Публичный блок RSA содержит:

```text
string "ssh-rsa"
mpint e
mpint n
```

Приватный блок RSA содержит:

```text
uint32 checkint1
uint32 checkint2
string "ssh-rsa"
mpint n
mpint e
mpint d
mpint iqmp
mpint p
mpint q
string comment
padding
```

Функция `parse_private_rsa_body()` читает не только `n`, `e`, `d`, но и дополнительные параметры `iqmp`, `p`, `q`, потому что без их чтения невозможно корректно дойти до поля `comment` и проверить `padding`.

---

## 3. Разбор ECDSA-ключа

Для ECDSA программа извлекает:

- `curve` — имя эллиптической кривой;
- `public_key_q` — публичная точка в hex;
- `public_key_x` — координата X;
- `public_key_y` — координата Y;
- `private_scalar_d` — приватный скаляр;
- `comment` — комментарий ключа;
- `bits` — размер кривой.

Публичный блок ECDSA содержит:

```text
string key_type
string curve
string public_q
```

Приватный блок ECDSA содержит:

```text
uint32 checkint1
uint32 checkint2
string key_type
string curve
string public_q
mpint private_d
string comment
padding
```

Публичная точка `Q` должна быть в несжатом формате:

```text
0x04 || X || Y
```

Функция `split_ecdsa_public_point()` разделяет точку на координаты `X` и `Y`.

---

## 4. Разбор Ed25519-ключа

Для Ed25519 программа извлекает:

- `public_key` — публичный ключ, 32 байта;
- `private_seed` — seed, первые 32 байта приватного блока;
- `private_key_raw` — полный приватный блок, 64 байта;
- `comment` — комментарий ключа;
- `bits` — размер ключа, 256 бит.

Публичный блок Ed25519 содержит:

```text
string "ssh-ed25519"
string public_key
```

Приватный блок Ed25519 содержит:

```text
uint32 checkint1
uint32 checkint2
string "ssh-ed25519"
string public_key
string private_key
string comment
padding
```

Поле `private_key` в OpenSSH для Ed25519 имеет длину 64 байта и состоит из двух частей:

```text
private_key = seed(32 байта) || public_key(32 байта)
```

Поэтому функция `parse_private_ed25519_body()` выполняет проверки:

1. публичный ключ из private blob имеет длину 32 байта;
2. приватный блок имеет длину 64 байта;
3. публичный ключ из public blob совпадает с публичным ключом из private blob;
4. последние 32 байта `private_key` совпадают с публичным ключом.

Если хотя бы одна проверка не проходит, ключ считается повреждённым или неподдерживаемым.

---

## 5. Проверка padding

Функция:

```python
validate_openssh_padding(padding)
```

проверяет завершающее дополнение приватного блока. В формате OpenSSH padding должен иметь вид:

```text
01
01 02
01 02 03
01 02 03 04
...
```

То есть каждый следующий байт должен увеличиваться на 1.

Пример корректного padding:

```text
01 02 03 04
```

Пример некорректного padding:

```text
01 02 FF 04
```

Если padding неправильный, программа выдаёт ошибку. Это помогает обнаружить повреждённый или неправильно разобранный приватный блок.

---

## 6. Форматы вывода

### 6.1. Text

Для RSA:

```text
OpenSSH RSA private key parameters
==================================
Key type: ssh-rsa
Comment: test-key
Modulus size: 4096 bits

Modulus n:
  decimal: ...
  hex:     0x...

Public exponent e:
  decimal: 65537
  hex:     0x10001

Private exponent d:
  decimal: ...
  hex:     0x...
```

Для ECDSA:

```text
OpenSSH ECDSA private key parameters
====================================
Key type: ecdsa-sha2-nistp256
Curve: nistp256
Curve size: 256 bits
Comment: test-key

Public key Q:
  hex:     0x...

Public point X:
  decimal: ...
  hex:     0x...

Public point Y:
  decimal: ...
  hex:     0x...

Private scalar d:
  decimal: ...
  hex:     0x...
```

Для Ed25519:

```text
OpenSSH Ed25519 private key parameters
======================================
Key type: ssh-ed25519
Key size: 256 bits
Comment: test-key

Public key:
  hex:     0x...

Private seed:
  hex:     0x...

Private key raw bytes:
  hex:     0x...
```

### 6.2. JSON

Пример запуска:

```bash
python3 crypto.py --format json openssh.pk
```

Пример структуры:

```json
{
  "key_type": "ssh-ed25519",
  "bits": 256,
  "comment": "test-key",
  "public_key": {
    "hex": "0x..."
  },
  "private_seed": {
    "hex": "0x..."
  },
  "private_key_raw": {
    "hex": "0x..."
  }
}
```

---

## 7. Обработка ошибок

Программа не должна падать с traceback при обычных ошибках входных данных. Ошибки разбора обрабатываются через `ParseError`.

Примеры ошибок:

### Файл не найден

```text
Ошибка: Входной файл не найден: key.pk
```

### Неверный формат файла

```text
Ошибка: Ожидался заголовок -----BEGIN OPENSSH PRIVATE KEY-----
```

### Ключ зашифрован

```text
Ошибка: Зашифрованные ключи не поддерживаются: ciphername='aes256-ctr', kdfname='bcrypt'
```

### Неподдерживаемый тип ключа

```text
Ошибка: Неподдерживаемый тип ключа: ssh-dss. Поддерживаются: ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-ed25519.
```

### Повреждённый приватный блок

```text
Ошибка: Контрольные значения checkint не совпадают: ключ повреждён или зашифрован неверным способом
```

---

## 8. Создание тестовых ключей

### RSA

```bash
ssh-keygen -t rsa -b 4096 -f test_rsa.pk -N "" -C "test-rsa-key"
```

Запуск парсера:

```bash
python3 crypto.py test_rsa.pk
```

### ECDSA nistp256

```bash
ssh-keygen -t ecdsa -b 256 -f test_ecdsa.pk -N "" -C "test-ecdsa-key"
```

Запуск парсера:

```bash
python3 crypto.py test_ecdsa.pk
```

### Ed25519

```bash
ssh-keygen -t ed25519 -f test_ed25519.pk -N "" -C "test-ed25519-key"
```

Запуск парсера:

```bash
python3 crypto.py test_ed25519.pk
```

---

## 9. Ограничения текущей реализации

Скрипт не поддерживает:

- зашифрованные приватные ключи OpenSSH;
- ключи с несколькими private key blob;
- старый PEM-формат вида `-----BEGIN RSA PRIVATE KEY-----`;
- формат PKCS#8 вида `-----BEGIN PRIVATE KEY-----`;
- DSA-ключи `ssh-dss`;
- FIDO/U2F-ключи OpenSSH, например `sk-ssh-ed25519@openssh.com`.

Поддерживается только формат:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

с внутренней структурой:

```text
openssh-key-v1\0
```

---

## 10. Структура результата в коде

Для хранения результата используются `dataclass`-классы.

### RSA

```python
@dataclass(frozen=True)
class RsaPrivateParameters:
    key_type: str
    modulus_n: int
    public_exponent_e: int
    private_exponent_d: int
    comment: str
    bits: int
```

### ECDSA

```python
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
```

### Ed25519

```python
@dataclass(frozen=True)
class Ed25519PrivateParameters:
    key_type: str
    public_key_hex: str
    private_seed_hex: str
    private_key_raw_hex: str
    comment: str
    bits: int = 256
```

Каждый класс имеет метод:

```python
to_dict()
```

Он нужен для преобразования результата в JSON.
