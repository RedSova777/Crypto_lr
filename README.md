# Crypto_lr
Отбор в криптолабораторию
  
# Парсер закрытых ключей OpenSSH `openssh-key-v1`

## 1. Назначение проекта

Скрипт предназначен для разбора файлов закрытых ключей OpenSSH в формате:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
	   ...base64...
-----END OPENSSH PRIVATE KEY-----
```

Программа читает файл закрытого ключа, проверяет его текстовую OpenSSH-обёртку, декодирует Base64-содержимое, разбирает бинарную структуру `openssh-key-v1` и выводит параметры ключа.

Поддерживаются следующие типы ключей:

- `ssh-rsa`;
- `ecdsa-sha2-nistp256`;
- `ecdsa-sha2-nistp384`;
- `ecdsa-sha2-nistp521`;
- `ssh-ed25519`.

Выходные форматы:

- `text` — текстовый вывод в консоль;
- `json` — структурированный JSON.

---

## 2. Требования к среде

Для запуска требуется:
- Python версии 3.8 или выше;

Используемые стандартные модули:

```python
argparse
base64
binascii
json
os
sys
dataclasses
typing
```
---

## 3. Запуск программы

Базовый запуск:

```bash
python3 crypto.py <путь_к_ключу>
```

Пример:

```bash
python3 crypto.py openssh.pk
```

Вывод в формате JSON:

```bash
python3 crypto.py --format json openssh.pk
```

Запись результата в файл:

```bash
python3 crypto.py --format json -o result.json openssh.pk
```

Вывод справки:

```bash
python3 crypto.py --help
```

---

## 4. Формат входных данных

Скрипт ожидает закрытый ключ OpenSSH в текстовой ASCII-armored обёртке:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
 		  Base64-данные
-----END OPENSSH PRIVATE KEY-----
```

После удаления строк `BEGIN` и `END` программа объединяет Base64-строки и декодирует их. В результате получается бинарная структура, которая должна начинаться с magic-строки:

```text
openssh-key-v1\0
```

Далее структура содержит поля:

```text
AUTH_MAGIC
string ciphername
string kdfname
string kdfoptions
uint32 number_of_keys
string public_key_blob
string private_key_blob
```

В текущей реализации поддерживаются только незашифрованные ключи:

```text
ciphername = none
kdfname    = none
kdfoptions = пустая строка
```

Если ключ защищён паролем, программа завершится с ошибкой.

---

## 5. Формат вывода

Вывод содержит все основные парамтеры закрытого  ключа.

### Для SSH RSA: 
 - тип ключа
 - коментарий 
 - размер 
 - n-модуль 
 - e-публичная экспонента
 - d-приватная экспонента

### Для ECDSA:
 - тип ключа
 - размер
 - Curve
 - Curve size
 - коментарий
 - Q-публичный ключ
 - X-публичная точка
 - Y-публичная точка
 - приватеый scalar

### Для Ed25519:
 - тип ключа
 - публичный ключ
 - приватный seed
 - Необработанные байты закрытого ключа

### 5.1. Формат text

Запуск:

```
python3 crypto.py --format text openssh_rsa1.pk
```

Вывод: 

```
OpenSSH ECDSA private key parameters
====================================
Key type: ecdsa-sha2-nistp256
Curve: nistp256
Curve size: 256 bits
Comment: aj@bowie.local

Public key Q:
  hex:     0x047d5993de052be2c6486340e87dc825d7944c7908df4cca1f78089275ae281ff3af7781cf741e66a1211e683061f096a3284bb90aad1c3ee0aa71aac17b2c6bf1

Public point X:
  decimal: 56697376004039328117290297327602340909865563365730954249253129349506800295923
  hex:     0x7d5993de052be2c6486340e87dc825d7944c7908df4cca1f78089275ae281ff3

Public point Y:
  decimal: 79365899220996673820301663588434996454317432122936283723529675612499468905457
  hex:     0xaf7781cf741e66a1211e683061f096a3284bb90aad1c3ee0aa71aac17b2c6bf1

Private scalar d:
  decimal: 3255700586097294360964414310126962365336954946084418946111917506318741409964
  hex:     0x732a94663325d9e239d2b77011cf4ba5e91efd01702be6042a0c09a815e10ac
```

### 5.2. Формат json  

Запуск: 

```
python3 crypto.py --format json openssh.pk
```

Вывод:

```
{
  "key_type": "ecdsa-sha2-nistp256",
  "bits": 256,
  "curve": "nistp256",
  "comment": "aj@bowie.local",
  "public_key_q": {
    "hex": "0x047d5993de052be2c6486340e87dc825d7944c7908df4cca1f78089275ae281ff3af7781cf741e66a1211e683061f096a3284bb90aad1c3ee0aa71aac17b2c6bf1"
  },
  "public_key_x": {
    "decimal": "56697376004039328117290297327602340909865563365730954249253129349506800295923",
    "hex": "0x7d5993de052be2c6486340e87dc825d7944c7908df4cca1f78089275ae281ff3"
  },
  "public_key_y": {
    "decimal": "79365899220996673820301663588434996454317432122936283723529675612499468905457",
    "hex": "0xaf7781cf741e66a1211e683061f096a3284bb90aad1c3ee0aa71aac17b2c6bf1"
  },
  "private_scalar_d": {
    "decimal": "3255700586097294360964414310126962365336954946084418946111917506318741409964",
    "hex": "0x732a94663325d9e239d2b77011cf4ba5e91efd01702be6042a0c09a815e10ac"
  }
}
```

---

## 6. Общий принцип работы алгоритма

Алгоритм работы программы можно разделить на несколько этапов:

1. Разбор аргументов командной строки.
2. Проверка существования входного файла.
3. Чтение текстовой OpenSSH-обёртки.
4. Проверка строк `BEGIN` и `END`.
5. Декодирование Base64.
6. Проверка magic-заголовка `openssh-key-v1\0`.
7. Разбор служебных полей OpenSSH.
8. Разбор публичного блока ключа.
9. Разбор приватного блока ключа.
10. Проверка совпадения публичной и приватной частей.
11. Формирование объекта с параметрами ключа.
12. Вывод результата в `text` или `json`.

---

## 7. Передача данных между функциями

| Этап | Функция | Входные данные | Выходные данные | Назначение |
|---|---|---|---|---|
| 1 | `main(argv)` | `argv` или `None` | код завершения `int` | Главная функция программы. Управляет всем процессом. |
| 2 | `parser_arg()` | нет | `argparse.ArgumentParser` | Создаёт описание аргументов командной строки. |
| 3 | `load_openssh_private_key(path)` | путь к файлу ключа | `binary: bytes` | Проверяет файл, извлекает Base64 и декодирует его. |
| 4 | `parse_openssh_private_key(binary)` | бинарная структура ключа | объект `ParsedKey` | Разбирает общий контейнер `openssh-key-v1`. |
| 5 | `parse_public_key_blob(public_blob)` | публичный блок ключа | словарь `public_part` | Определяет тип ключа и читает публичные параметры. |
| 6 | `parse_private_blob(private_blob, public_part)` | приватный блок и публичные параметры | объект `ParsedKey` | Проверяет `checkint`, тип ключа и вызывает нужный парсер тела. |
| 7 | `parse_private_rsa_body(reader, public_part)` | `ByteReader`, публичные RSA-поля | `RsaPrivateParameters` | Извлекает `n`, `e`, `d` и проверяет совпадение с public blob. |
| 8 | `parse_private_ecdsa_body(reader, public_part)` | `ByteReader`, публичные ECDSA-поля | `EcdsaPrivateParameters` | Извлекает кривую, точку `Q`, скаляр `d`. |
| 9 | `parse_private_ed25519_body(reader, public_part)` | `ByteReader`, публичный Ed25519-ключ | `Ed25519PrivateParameters` | Извлекает публичный ключ, seed и полный приватный блок. |
| 10 | `write_output(params, output_path, output_format)` | объект результата, путь, формат | `None` | Выводит результат в консоль или файл. |

---

## 8. Краткая схема обработки одного файла

```text
Файл ключа
    |
load_openssh_private_key()
    |
bytes после Base64-декодирования
    |
parse_openssh_private_key()
    |
public_blob + private_blob
    |
parse_public_key_blob()
    |
public_part
    |
parse_private_blob()
    |
parse_private_rsa_body()
или parse_private_ecdsa_body()
или parse_private_ed25519_body()
    |
RsaPrivateParameters / EcdsaPrivateParameters / Ed25519PrivateParameters
    |
write_output()
    |
text или json
```

---

## 9. Пример полного сценария проверки

```bash
# 1. Создать тестовый Ed25519-ключ
ssh-keygen -t ed25519 -f test_ed25519.pk -N "" -C "test-ed25519-key"

# 2. Проверить синтаксис скрипта
python3 -m py_compile crypto_1_universal_with_ed25519.py

# 3. Запустить текстовый вывод
python3 crypto.py --format text test_ed25519.pk

# 4. Запустить JSON-вывод
python3 crypto.py --format json test_ed25519.pk

# 5. Записать JSON в файл
python3 crypto.py --format json -o result.json test_ed25519.pk
```

---

## 10. Вывод

Скрипт реализует ручной разбор формата закрытых ключей OpenSSH `openssh-key-v1`. Он последовательно проверяет текстовую обёртку, декодирует Base64, разбирает бинарные SSH-структуры, определяет тип ключа, извлекает параметры RSA/ECDSA/Ed25519 и выводит результат в удобном формате.

Основной поток выполнения выглядит так:

```text
main()
  - parser_arg()
  - load_openssh_private_key()
  - parse_openssh_private_key()
  - parse_public_key_blob()
  - parse_private_blob()
      - parse_private_rsa_body()
      - parse_private_ecdsa_body()
      - parse_private_ed25519_body()
  - write_output()
```
