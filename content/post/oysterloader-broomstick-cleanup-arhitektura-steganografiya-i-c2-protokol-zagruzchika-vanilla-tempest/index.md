---
title: "OysterLoader (Broomstick/CleanUp): архитектура, стеганография и C2-протокол загрузчика Vanilla Tempest"
date: 2026-02-15
draft: false
description: "Как устроен OysterLoader — загрузчик Rhysida ransomware и Vidar: обфускация TextShell, RC4-стеганография в ICO, динамический Base64, IOC и MITRE ATT&CK"
image: "/cdn/blog-cdn/oysterloader-header.svg"
---

## 1. Введение

OysterLoader (Broomstick, CleanUp) — многоступенчатый загрузчик на C++. С момента первого публичного описания в середине 2024 года заметно эволюционировал: архитектура стала модульнее, сетевое взаимодействие — динамичнее, обход детектирования — сложнее.

Распространяется через malvertising-лендинги, имитирующие страницы загрузки администраторских и security-инструментов (PuTTY, WinSCP, Google Authenticator и др.). Жертве предлагается MSI, функционально близкий к легитимному инсталлятору.
Критический элемент кампаний — злоупотребление код-сайнингом. В операциях, связанных с Rhysida, использовались десятки валидных сертификатов (в т.ч. через Microsoft Trusted Signing, а также SSL.com, DigiCert, GlobalSign). В 2025 году задействовано 40+ уникальных сертификатов; позднее Microsoft отозвала более 200 мошеннически полученных. Подпись снижала детектируемость и повышала вероятность обхода SmartScreen и политик контроля приложений.
Связь с Gootloader задокументирована: Huntress выявила идентичный TextShell-обфускатор (Stage 1) в образцах Gootloader и OysterLoader. Оператор Gootloader (Storm-0494) обеспечивает initial access, после чего доступ передаётся Vanilla Tempest для развёртывания вымогателя. Это устоявшаяся партнёрская модель, а не инфраструктурное пересечение.
Атрибуция на февраль 2026 года устойчива: OysterLoader связывается с Vanilla Tempest (ex-Vice Society), входящей в экосистему WIZARD SPIDER / ITG23 / Periwinkle Tempest. Ребрендинг Vice Society → Rhysida произошёл в 2023 году. При этом модель дистрибуции остаётся открытым вопросом: OysterLoader может быть как внутренним инструментом экосистемы Vanilla Tempest, так и сервисом, доступным ограниченному кругу партнёров.

За 2024-2026 годы загрузчик активно дорабатывался: менялись C2-эндпоинты, перерабатывалась структура JSON-фингерпринта, появилась динамическая замена Base64-алфавита, расширялся набор собираемой информации о системе, корректировался механизм beaconing. Проект живой, а не статичный артефакт прошлых кампаний.

Основной механизм доставки в 2025-2026 гг. — malvertising, а не классический фишинг. Злоумышленники выкупают рекламные позиции в Bing Ads, продвигая поддельные страницы загрузки администраторских и security-инструментов (PuTTY, WinSCP, Google Authenticator и др.). Пользователь переходит по рекламной ссылке из поисковой выдачи и получает подписанный MSI-инсталлятор с внедрённым загрузчиком.
Это принципиально отличается от фишинга через email:
нет массовой рассылки;
компрометация инициируется поисковым запросом жертвы;
используется доверие к рекламному блоку поисковой системы.
Таким образом, вектор — malvertising через поисковую рекламу, а не фишинговые письма со ссылками на клоны сайтов.

---

## 2. Общая архитектура заражения

Инфекционная цепочка включает четыре стадии:

```
MSI Installer
   ↓
Stage 1 – TextShell (packer)
   ↓
Stage 2 – Shellcode + custom LZMA
   ↓
Stage 3 – Downloader DLL
   ↓
Stage 4 – Core (COPYING3.dll)
```

Каждая стадия изолирована и выполняет строго определённую функцию, что повышает живучесть всей цепочки.

---

## 3. Stage 1 — TextShell: обфускация и анти-анализ

Первая стадия не содержит финальной вредоносной логики. Её задача — максимально усложнить анализ и подготовить выполнение следующего этапа.

### 3.1 Динамическое разрешение API

Вместо Import Address Table используется собственный hashing-алгоритм. В одном из вариантов используется формула:

```
h = (h * 0x2001 + ord(ch)) & 0xFFFFFFFF
```

Хеши функций сравниваются со значениями, зашитыми в бинарнике.

Динамически разрешаются:

- NtAllocateVirtualMemory
- LdrLoadDll
- LdrGetProcedureAddress
- RtlInitUnicodeString

После чего уже через них подтягиваются:

- LoadLibrary
- GetProcAddress
- ExitProcess
- VirtualProtect
- InternetOpenW
- ShowWindow

Hashing-алгоритм меняется между версиями, что усложняет сигнатурный поиск.

---

### 3.2 API Hammering

Бинарный файл насыщен сотнями вызовов легитимных Windows API:

```
CreateSolidBrush
SetMapMode
GetDC
UnrealizeObject
SetBkColor
OaBuildVersion
```

Эти вызовы:

- не изменяют состояние системы значимым образом
- создают шум в декомпилированном коде
- размывают сигнатуры
- сбивают эвристики

Код выглядит как фрагмент графического приложения.

---

### 3.3 Анти-отладка

Используется примитивная, но эффективная проверка:

```
if (IsDebuggerPresent())
    while(1);
```

Бесконечный цикл блокирует выполнение при обнаружении отладчика.

Также используется:

- динамическое API разрешение
- частичная фрагментация кода
- вставки "мёртвых" ветвлений

---

### 3.4 Структура core

Stage 1 формирует структуру, передаваемую дальше:

- буфер сжатых данных
- указатели на API
- конфигурационный блок
- флаги
- entrypoint

Это изолирует стадии друг от друга и снижает зависимости между ними.

---

## 4. Stage 2 — Shellcode и кастомная LZMA

### 4.1 Кастомное LZMA

Вторая стадия исполняется в виде shellcode и содержит собственный декомпрессор. Здесь применяется модифицированная реализация LZMA, отличающаяся от стандартной структуры. Заголовок потока не содержит привычных сигнатур, параметры могут быть смещены или вычисляться динамически, а сам range decoder подвергнут переработке. Несмотря на сохранение математической основы алгоритма, сигнатурные признаки классической реализации исчезают.

После распаковки shellcode выполняет релокацию: код исполняется в произвольной области памяти, поэтому нужно пересчитать относительные переходы и вызовы. Затем резолвятся импорты, корректируются права памяти и управление передаётся новому entrypoint.

### 4.2 Релокации

После распаковки выполняется сканирование буфера:

- поиск опкодов `E8` (CALL)
- поиск `E9` (JMP)
- перерасчёт относительных адресов

Это необходимо, поскольку код исполняется в произвольной памяти.

### 4.3 Подготовка исполнения

Shellcode:

1. Резолвит импорты.
2. Меняет права памяти через VirtualProtect.
3. Передаёт управление в новый entrypoint.

---

## 5. Stage 3 — Downloader и анти-анализ

Это первая стадия, устанавливающая сетевую активность.

### 5.1 Проверка среды

- Подсчёт процессов через EnumProcesses
- Если менее 60 процессов → выход
- Проверка языка (оставшийся неиспользуемый код — русский язык)
- Создание mutex:

```
h6p#dx!&fse?%AS!
```

Вариации mutex позволяют отслеживать кампании.

---

### 5.2 Timing-анализ

Цикл из 14 повторений:

- Beep (2 секунды)
- Sleep (4.5 секунды)

Сравнивается реальное и ожидаемое время. Если песочница ускоряет sleep — обнаружение.

---

## 6. Первый уровень C2 (delivery layer)

Используется HTTPS.

#### Шаг 1 — регистрация

GET `/reg`

- User-Agent: WordPressAgent
- x-amz-cf-id: случайная строка
- Content-Encoding: ID кампании

#### Шаг 2 — загрузка

GET `/login`

- User-Agent меняется на FingerPrint

Ответ — ICO-файл.

---

### 6.1 Стеганография в ICO

C2 отвечает валидным ICO-файлом, внутри которого скрыта полезная нагрузка.

Структура:

```
[ ICO header ]
[ ICONDIRENTRY ]
[ валидные bitmap-данные ]
[ маркер "endico" ]
[ RC4-encrypted blob ]
```

#### Ключевые технические детали

- **Маркер окончания:** ASCII-строка

    ```
    65 6e 64 69 63 6f
    ```

    что соответствует `"endico"`

- Всё, что следует **после строки `endico`**, интерпретируется как зашифрованный RC4-блок.

#### IOC для детектирования

| Тип | IOC |
| --- | --- |
| HTTP Path | `GET /login` |
| Response Type | `image/x-icon` |
| Static Marker | ASCII `"endico"` |
| Hex Signature | `65 6E 64 69 63 6F` |
| Поведение | ICO + данные после валидного EOF |

Ключ RC4 жёстко зашит в бинарнике.

После дешифрования ожидается PE (MZ).

---

### 6.2 Закрепление

DLL сохраняется в:

```
%APPDATA%\[random]\COPYING3.dll
```

Создаётся scheduled task:

```
schtasks /Create /SC MINUTE /MO 13 /TN "COPYING3"
```

Исполнение:

```
rundll32 COPYING3.dll DllRegisterServer
```

Названия меняются между кампаниями:

- VisualUpdater
- AlphaSecurity
- DetectorSpywareSecurity

---

## 7. Stage 4 — Core и финальный C2

Финальная DLL — полноценный in-memory loader. Снова используются многоуровневая обфускация и динамический API-резолвинг: импорт не фиксируется статически, а резолвится в runtime через хеширование имён функций (kernel32/ntdll/wininet или winhttp), что минимизирует IAT-артефакты. Полезная нагрузка распаковывается кастомным алгоритмом (модифицированная LZ-подобная схема с XOR/поблочным преобразованием), после чего PE маппится вручную: аллокация памяти, копирование секций, обработка релокаций, разрешение импортов, вызов entry point. На диск ничего не пишется.

### C2-коммуникация

Сетевая логика построена как отказоустойчивая:

- список альтернативных C2-узлов (hardcoded + получаемые динамически);
- fallback-переход при недоступности основного узла;
- проверка доступности через предварительный lightweight-запрос (health-check);
- динамическое обновление конфигурации (включая новые адреса C2).

Протокол в поздних версиях расширен:

- введены дополнительные endpoint'ы (регистрация, выдача задач, выгрузка данных, обновление конфигурации);
- динамическая подмена Base64-алфавита (перемешивание символов или таблица замены, передаваемая сервером);
- дополнительный слой симметричного шифрования (ключ генерируется на основе host-fingerprint или nonce от C2);
- фрагментация и выравнивание пакетов для маскировки размера передаваемых данных.

### Fingerprinting

Перед началом сессии бот собирает профиль хоста:

- версия ОС, билд, архитектура;
- доменное членство;
- список установленных AV/EDR;
- перечень установленного ПО (по реестру Uninstall);
- список запущенных процессов;
- объём ОЗУ, число ядер;
- привилегии текущего токена.

Fingerprint используется для:

- решения о продолжении инфекции;
- выбора последующего payload (Vidar / Rhysida);
- определения необходимости эскалации привилегий;
- фильтрации sandbox/VM-сред.

### Инфраструктурная модель

Инфраструктура двухуровневая:

1. **Delivery-tier**
   Хостит MSI/первичный stage. Часто размещается на быстро ротируемых VPS или CDN-узлах. Задача — краткоживущий трафик установки.

2. **C2-tier (control plane)**
   Отдельная управляющая инфраструктура с изолированными серверами. Коммуникация с delivery напрямую не связана.

Разделение даёт следующие преимущества:

- блокировка delivery-домена не раскрывает C2;
- возможна замена управляющих серверов без модификации дроппера;
- усложняется инфраструктурная корреляция при расследовании;
- снижается риск deanonymization всей цепочки при изъятии одного узла.

Такая архитектура рассчитана на устойчивость (resilience engineering) и централизованное управление ботнетом.

---

## 8. C2 протокол (v1)

Коммуникация по HTTP.

Fallback-механизм:

- 3 сервера
- 3 попытки
- 9 секунд интервал

Endpoint'ы:

- `/api/kcehc`
- `/api/jgfnsfnuefcnegfnehjbfncejfh`

---

### 8.1 Кодирование

Используется:

- кастомный Base64-алфавит
- случайный shift
- генерация через Mersenne Twister

Каждое сообщение кодируется уникально.

---

## 9. Обновление до v2

Добавлены endpoint'ы:

- `/api/v2/init`
- `/api/v2/facade`
- `/api/v2/<dynamic>`

Ответ C2 содержит:

```
"tk": новый Base64-алфавит
```

Бот начинает использовать новый алфавит для последующих сообщений.

---

### 9.1 Расширенный fingerprint

Пример полей:

```
t1 – timestamp
t3 – username
t4 – hostname
t7 – domain
t10 – OS version
t11 – installed software
t12 – running processes
```

---

## 10. Инфраструктура

Актуальные домены (2026):

- grandideapay[.]com
- nucleusgate[.]com
- registrywave[.]com
- socialcloudguru[.]com
- coretether[.]com

---

## 11. Общая оценка и вывод

OysterLoader — активно поддерживаемый загрузчик с профессиональной реализацией:

- многоэтапная цепочка исполнения
- кастомная компрессия и шифрование полезной нагрузки
- ручная обработка релокаций при маппинге PE
- сложная и адаптивная C2-логика
- изменяемые схемы кодирования и обфускации
- регулярная ротация инфраструктуры и сертификатов

Качество кода и частота обновлений (C2-протокол, fingerprinting, схемы обхода) говорят о долгосрочной эксплуатации внутри организованной экосистемы. Загрузчик хорошо интегрируется в партнёрские схемы initial access → ransomware, устойчив к анализу и продолжает развиваться. В 2026 году OysterLoader остаётся актуальной угрозой, требующей постоянного мониторинга.

## IOC (с примерами артефактов кампаний 2025-2026)

| Тип | IOC | Пример |
| --- | --- | --- |
| Referrer | Malvertising (Bing Ads) | `https://www.bing.com/aclick?...` |
| Домен (look-alike) | Поддельные загрузочные сайты | `putty-download[.]com` |
| Домен (look-alike) | Клон WinSCP | `winscp-downloads[.]com` |
| MSI Hash (пример) | Signed MSI (OysterLoader stage) | |
| PowerShell Artefact | EncodedCommand | `powershell.exe -enc "base64_encoded_string"` |
| Registry | Run Key Persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService` |
| Scheduled Task | Persistence | `\Microsoft\Windows\Update\SecurityPatch` |
| C2 URI pattern | HTTPS Beacon | `/cdn/api/v3/update?id=` |
| User-Agent | Loader beacon | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` |
| Payload | Vidar drop path | `%AppData%\Local\Temp\svhost.exe` |
| Ransomware | Rhysida note | `CriticalBreachDetected.txt` |

---

## MITRE ATT&CK (кратко)

| Тактика | Technique |
| --- | --- |
| Initial Access | T1189 — Drive-by Compromise |
| Execution | T1204.002 — User Execution (MSI) |
| Execution | T1218.007 — Msiexec Proxy Execution |
| Defense Evasion | T1553.002 — Code Signing Abuse |
| Defense Evasion | T1027 — Obfuscation |
| Persistence | T1053.005 — Scheduled Task |
| C2 | T1071.001 — HTTPS |
| Impact | T1486 — Data Encrypted for Impact |

## Источники

- [Sekoia - OysterLoader Unmasked](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/)
- [Rapid7 - Malvertising Campaign Leads to Oyster Backdoor](https://www.rapid7.com/blog/post/2024/06/17/malvertising-campaign-leads-to-execution-of-oyster-backdoor/)
- [Expel - Certified OysterLoader](https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/)
- [The Hacker News - Microsoft Revokes 200 Certificates](https://thehackernews.com/2025/10/microsoft-revokes-200-fraudulent.html)
- [SC Media - 40+ Code-Signing Certificates](https://www.scworld.com/news/rhysida-oysterloader-malvertising-campaign-leverages-40-code-signing-certificates)
- [Huntress - Gootloader Threat Detection](https://www.huntress.com/blog/gootloader-threat-detection-woff2-obfuscation)
- [Red Canary - Intelligence Insights July 2025](https://redcanary.com/blog/threat-intelligence/intelligence-insights-july-2025/)
