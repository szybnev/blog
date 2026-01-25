---
title: "BlackMatter Ransomware: подробный анализ и рекомендации"
date: 2026-01-23
draft: false
description: "BlackMatter Ransomware: подробный анализ и рекомендации"
image: "/cdn/blog-cdn/large_3_wallpaper_b7dac9c334.webp"
---

##  Происхождение и эволюция  
BlackMatter — это прямой наследник DarkSide и REvil. После громких атак (Colonial Pipeline, Kaseya, JBS) эти банды исчезли с публичного поля, и уже в июле 2021 появилось «новое» имя — BlackMatter. Это типичный ребрендинг: кодовая база, инфраструктура и даже «фирменные ошибки» в криптоалгоритмах указывают на преемственность.

 **Вывод**: BlackMatter = ребрендинг DarkSide с новым PR, но той же кодовой базой.

## Архитектура и модель работы

- **Ransomware-as-a-Service (RaaS)**: операторы создают ядро, «партнёры» проводят атаки.
- **Структура экосистемы**:
    1. Разработчики (ядро, криптология).
    2. Партнёры (phishing, эксплойты, lateral movement).
    3. Платформа переговоров (Tor-чаты).
    4. Сайт «утечек» данных.
        
**Интересно**: BlackMatter активно вербовал на форумах XSS и Exploit, обещая «надежность и поддержку 24/7».

В отличие от многих кибератак, которые для создания плацдарма используют фишинг, BlackMatter, судя по всему, получает первоначальный доступ в первую очередь посредством взлома уязвимых периферийных устройств и злоупотребления корпоративными учетными данными, полученными из других источников.

Хотя в некоторых исключительных случаях возможно использование фишинговых кампаний и вредоносных документов, приводящих к сбрасыванию или загрузке компактной полезной нагрузки BlackMatter размером около 80 КБ, в ходе проведенных нами расследований таких случаев не наблюдалось.

Помимо членов BlackMatter, эксплуатирующих уязвимости инфраструктуры, например, те, что присутствуют в устройствах или серверах удаленного рабочего стола, виртуализации и VPN, операторы первоначального доступа, связанные с группой, вероятно, внесут свои собственные TTP и могут отдавать предпочтение эксплуатации одних уязвимостей перед другими.

### Что можно сказать о полезной нагрузке?

- Высокоэффективный многопоточный исполняемый файл, написанный на языке C, размером всего ~80 КБ.
- Версия 3.0 скрывает конфигурацию в разных местах, что затрудняет ее извлечение и анализ.
- Чтобы скрыть поток выполнения, каждая функция декодируется, загружается в память, выполняется, а затем очищается.
- Использует собственные криптографические библиотеки Windows, что значительно уменьшает полезную нагрузку.
- Шифрует файлы, используя комбинацию ключей Salsa20 и 1024-битного RSA.
- Позволяет исключить определенные расширения файлов и имена файлов из процесса шифрования, часто для того, чтобы гарантировать возможность загрузки Windows.
- Четырехлетний обход ICMLuaUtil  контроля учетных записей пользователей (UAC) на базе COM, влияющий на Windows 7–10, используется для повышения привилегий (поскольку Microsoft считает это «функцией», исправление выпущено не будет), а ранее использовался Darkside и MedusaLocker.
- Конфигурация BlackMatter позволяет указывать ранее полученные учетные данные и потенциально использовать их для обхода UAC.
- Перечисляет и удаляет теневые копии с помощью утилиты командной строки инструментария управления Windows (WMIC): 
  `IWbemServices::ExecQuery - ROOT\CIMV2 : SELECT * FROM Win32_ShadowCopy`
- Идентификатор жертвы, а также имя файла записки с требованием выкупа и расширение зашифрованного файла основаны на `MachineGuid`значении в реестре ( `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`).
- Получившееся зашифрованное расширение файла включает девять буквенно-цифровых символов в смешанном регистре, а также записку с требованием выкупа, сохраненную на рабочем столе жертвы и в `c:\%extension%-README.txt`, что может обойти некоторые методы обнаружения на основе словаря.
- Процесс шифрования включает чтение целевого файла, переименование его с присвоением нового расширения, частичное шифрование и перезапись 1024 КБ данных.
- Перечисляет среды Active Directory с использованием собственных запросов LDAP, в частности встроенную папку компьютеров, `LDAP://CN=Computers`для определения потенциальных целевых машин.
- Обновляет обои рабочего стола жертвы, чтобы информировать ее о ситуации:
![3-wallpaper.webp](/cdn/blog-cdn/large_3_wallpaper_b7dac9c334.webp)

Пример письма с выкупом: 

![4-ransomnote.webp](/cdn/blog-cdn/large_4_ransomnote_e01f6458a7.webp)

С2

Полезная нагрузка будет передаваться в инфраструктуру командования и управления (C2) по протоколу HTTPS с шифрованием AES. Жертва отправляет маячок, содержащий имя компьютера, версию ОС и архитектуру процессора, язык ОС, имя пользователя, доменное имя, размер диска и потенциальные ключи шифрования:

![5-c2comms.webp](/cdn/blog-cdn/large_5_c2comms_b27d0d5fce.webp)

Было обнаружено, что это сообщение выдает себя за следующие строки пользовательского агента, которые могут быть аномальными в некоторых средах:

* Mozilla/5.0 (Windows NT 6.1)
* Firefox/89.0 
* Gecko/20100101
* Edge/91.0.864.37 
* Safari/537.36

Конфигурация payload: 

![6-config.webp](/cdn/blog-cdn/large_6_config_d27f6550eb.webp)

Конфигурация BlackMatter, представляющая собой структуру в формате JSON, позволяет адаптировать полезную нагрузку к конкретной жертве, включая:

* Открытый ключ RSA, который будет использоваться для шифрования ключа шифрования Salsa20.
* Идентификатор компании-жертвы
* Ключ AES, который будет использоваться при инициализации ключа Salsa20 (используется позже при шифровании файлов).
* Версия вредоносного по  с указанием полезной нагрузки.
* Нечетное шифрование больших файлов - для дальнейшего повреждения больших файлов, таких как базы данных.
* Потребуется выполнить вход в систему - будет предпринята попытка аутентификации с использованием учетных данных, указанных в конфигурации.
* Mount units и crypt - попытка смонтировать тома и зашифровать их.
* Ищите общие сетевые ресурсы и рекламные ресурсы, чтобы попытаться зашифровать их.
* Процессы и службы завершают работу до начала шифрования, чтобы обеспечить максимальную эффективность.
* Создаем мьютексы, чтобы избежать обнаружения.
* Подготавливаем данные жертвы и удаляем их.
* После шифрования файлов удаляем уведомления о требовании выкупа.
* Домены C2 для обмена данными по протоколам HTTP или HTTPS.
* Установка уникального требования о выкупе.

Рекомендации: 
* Поддерживайте планы резервного копирования в рабочем состоянии. 
* Применяйте процессы управления исправлениями на внешних устройствах, таких как VPN. Постоянно оценивайте состояние внешней организации при поиске доступных устройств, таких как серверы Exchange и vCenter. 
* Меняйте пароли пользователей, администраторов и учетных записей служб, постоянно проверяя их на предмет утечки учетных данных.
* Подготовьте и отработайте процедуры реагирования на инциденты, связанные с атаками программ-вымогателей. 
* Заблокируйте указанные серверы и IOC.
  
## YARA\IOC

### YARA 

```yara
/*
BlackMatter ransomware
*/

import "elf"

rule DarkSide_BM
{
    meta:
        author = "Andrey Zhdanov"
        company = "Group-IB"
        family = "ransomware.darkside_blackmatter"
        description = "DarkSide/BlackMatter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h2 = { 64 A1 30 00 00 00 8B B0 A4 00 00 00 8B B8 A8 00
                00 00 83 FE 05 75 05 83 FF 01 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (1 of ($h*))
        )
}

rule BlackMatter
{
    meta:
        author = "Andrey Zhdanov"
        company = "Group-IB"
        family = "ransomware.blackmatter.windows"
        description = "BlackMatter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 80 C6 61 80 EE 61 C1 CA 0D 03 D0 }
        $h1 = { 02 F1 2A F1 B9 0D 00 00 00 D3 CA 03 D0 }
        $h2 = { 3C 2B 75 04 B0 78 EB 0E 3C 2F 75 04 B0 69 EB 06
                3C 3D 75 02 B0 7A }
        $h3 = { 33 C0 40 40 8D 0C C5 01 00 00 00 83 7D 0? 00 75
                04 F7 D8 EB 0? }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (1 of ($h*))
        )
}

rule BlackMatter_Linux
{
    meta:
        author = "Andrey Zhdanov"
        company = "Group-IB"
        family = "ransomware.blackmatter.linux"
        description = "BlackMatter ransomware Linux payload"
        severity = 10
        score = 100

    strings:
        $h0 = { 0F B6 10 84 D2 74 19 0F B6 34 0F 40 38 F2 74 10
                48 83 C1 01 31 F2 48 83 F9 20 88 10 49 0F 44 C9
                48 83 C0 01 4C 39 C0 75 D7 }
        $h1 = { 44 42 46 44 C7 4? [1-2] 30 35 35 43 C7 4? [1-2]
                2D 39 43 46 C7 4? [1-2] 32 2D 34 42 C7 4? [1-2]
                42 38 2D 39 C7 4? [1-2] 30 38 45 2D C7 4? [1-2]
                36 44 41 32 C7 4? [1-2] 32 33 32 31 C7 4? [1-2]
                42 46 31 37 }

    condition:
        (uint32(0) == 0x464C457F) and
        (
            (1 of ($h*)) or
            for any i in (0..elf.number_of_sections-2):
            (
                (elf.sections[i].name == ".app.version") and
                (elf.sections[i+1].name == ".cfgETD")
            )
        )
}
```

### IOC 
#### SHA-256
**BlackMatter для Windows v1.2**

072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486   22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6   2c323453e959257c7aa86dc180bb3aaaa5c5ec06fa4e72b632d9e4b817052009   3a03530c732ebe53cdd7c17bee0988896d36c2b632dbd6118613697c2af82117   4ad9432cc817afa905bab2f16d4f713af42ea42f5e4fcf53e6d4b631a7d6da91   6155637f8b98426258f5d4321bce4104df56c7771967813d61362c2118632a7b   668a4a2300f36c9df0f7307cc614be3297f036fa312a424765cdb2c169187fe6   72687c63258efe66b99c2287748d686b6cca2b0eb6f5398d17f31cb46294012c   7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984   c6e2ef30a86baa670590bd21acf5b91822117e0cbe6060060bc5fe0182dace99   c728e3a0d4a293e44314d663945354427848c220d05d5d87cdedd9995fee3dfe   f63c6d08ebfba65173763c61d3767667936851161efa51ff4146c96041a02b20

84af3f15701d259f3729d83beb15ca738028432c261353d1f9242469d791714f

**BlackMatter Decryptor для Windows v1.3**

a6e14988d91f09db44273c79cba51c16b444afafa37ba5968851badb2a62ef27

**BlackMatter для Windows v1.4**

7c642cdeaa55f56c563d82837f4dc630583b516a5d02d5a94b57b65489d74425   cf60d0d6b05bfe2e51ca9dac01a4ae506b90d78d8d9d0fc266e3c01d8d2ba6b7

**BlackMatter для Windows v1.6**

6d4712df42ad0982041ef0e2e109ab5718b43830f2966bd9207a7fac3af883db   86c84c07e27cc8aba129e1cf51215b65c445f178b94f2e8c4c10e6bc110daa94   b824bbc645f15e213b4cb2628f7d383e9e37282059b03f6fe60f7c84ea1fed1f   e4fd947a781611c85ea2e5afa51b186de7f351026c28eb067ad70028acd72cda

**BlackMatter для Windows v1.9**

2466fca0e29b06c78ffa8a44193fb58c30e6bec4e54bbef8e6622349b95cce4c

**BlackMatter для Windows v2.0 (2021-08-16)**
0751c422962dcd500d7cf2cf8bf544ddf5b2fe3465df7dd9b9998f6bba5e08a4
1c63a4fdee1528429886a0de5e89eaa540a058bf27cd378b8d139e045a2f7849
1eea3cbd729d4493c0c0a84efe6840abf1760efe221dc971d32ca5017b5c19c2
20742987e6f743814b25e214f8b2cd43111e2f60a8856a6cca87cafd85422f41
2cdb5edf3039863c30818ca34d9240cb0068ad33128895500721bcdca70c78fd
2e50eb85f6e271001e69c5733af95c34728893145766066c5ff8708dcc0e43b2
3a4bd5288b89aa26fbe39353b93c1205efa671be4f96e50beae0965f45fdcc40
4be85e2083b64838fb66b92195a250228a721cdb5ae91817ea97b37aa53f4a2b
520bd9ed608c668810971dbd51184c6a29819674280b018dc4027bc38fc42e57
5da8d2e1b36be0d661d276ea6523760dbe3fa4f3fdb7e32b144812ce50c483fa
66e6563ecef8f33b1b283a63404a2029550af9a6574b84e0fb3f2c6a8f42e89f
706f3eec328e91ff7f66c8f0a2fb9b556325c153a329a2062dc85879c540839d
8323fdfda08300c691d330badec2607ea050cc10ee39934faeebedf3877df3ac
8f1b0affffb2f2f58b477515d1ce54f4daa40a761d828041603d5536c2d53539
9cf9441554ac727f9d191ad9de1dc101867ffe5264699cafcf2734a4b89d5d6a
b0e929e35c47a60f65e4420389cad46190c26e8cfaabe922efd73747b682776a
b4b9fdf30c017af1a8a3375218e43073117690a71c3f00ac5f6361993471e5e7
cb5a89a31a97f8d815776ff43f22f4fec00b32aae4f580080c7300875d991163
e4a2260bcba8059207fdcc2d59841a8c4ddbe39b6b835feef671bceb95cd232d
e9b24041847844a5d57b033bf0b41dc637eba7664acfb43da5db635ae920a1b4
eaac447d6ae733210a07b1f79e97eda017a442e721d8fafe618e2c789b18234b
eafce6e79a087b26475260afe43f337e7168056616b3e073832891bf18c299c1
f7b3da61cb6a37569270554776dbbd1406d7203718c0419c922aa393c07e9884
496cd9b6b6b96d6e781ab011d1d02ac3fc3532c8bdd07cae5d43286da6e4838d

**BlackMatter для Windows v2.0 (2021-09-26)**

2aad85dbd4c79bd21c6218892552d5c9fb216293a251559ba59d45d56a01437c
4524784688e60313b8fefdebde441ca447c1330d90b86885fb55d099071c6ec9
5236a8753ab103634867289db0ba1f075f0140355925c7bd014de829454a14a0
69e5f8287029bcc65354abefabb6854b4f7183735bd50b2da0624eb3ae252ea8
730f2d6243055c786d737bae0665267b962c64f57132e9ab401d6e7625c3d0a4
8eada5114fbbc73b7d648b38623fc206367c94c0e76cb3b395a33ea8859d2952
ccee26ea662c87a6c3171b091044282849cc8d46d4b9b9da6cf429b8114c4239
ed47e6ecca056bba20f2b299b9df1022caf2f3e7af1f526c1fe3b8bf2d6e7404
fe2b2beeff98cae90f58a5b2f01dab31eaa98d274757a7dd9f70f4dc8432a6e2
26a7146fbed74a17e9f2f18145063de07cc103ce53c75c8d79bbc5560235c345

**BlackMatter для Windows v3.0 (2021-10-22)**

7a223a0aa0f88e84a68da6cde7f7f5c3bb2890049b0bf3269230d87d2b027296
9bae897c19f237c22b6bdc024df27455e739be24bed07ef0d409f2df87eeda58
2f20732aaa3d5ce8d2efeb37fe6fed7e73a29104d8227a1160e8538a3ee27dad
9a8cd3a30e54a2ebb6d73fd7792ba60a6278a7301232321f226bb29fb8d0b3d6

**BlackMatter для Linux v1.6.0.2**

1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f   6a7b7147fea63d77368c73cef205eb75d16ef209a246b05698358a28fd16e502

**BlackMatter Decryptor для Linux v1.6.0.2**

e48c87a1bb47f60080320167d73f30ca3e6e9964c04ce294c20a451ec1dff425

**BlackMatter для Linux v1.6.0.4**

d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82

|                                  |                                                                                                  |
| -------------------------------- | ------------------------------------------------------------------------------------------------ |
| **company_id**                   | **Ссылка TOR**                                                                                   |
| 512478c08dada2af19e49808fbda5b0b | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/7NT6LXKC1XQHW5039BLOV    |
| 5ecf7b9cde33f85a3eec9350275b5c4f | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/OR7OTLBK8D5UVHZ0Q        |
| caa0d21adc7bdc4dc424497512a8f37d | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/8ZHJ2G2FJDX9JSHTA6S      |
| 32bd08ad5e5e881aa2634621d611a1a5 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/OYPF561W4U8HVA0NLVCKJCZB |
| e4aaffc36f5d5b7d597455eb6d497df5 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/5AZHJFLKJNPOJ4F5O5T      |
| b8726db5d916731db5625cfc30c4f7d9 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/5PBOYRSETHVDBDPTL        |
| 0c6ca0532355a106258791f50b66c153 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/RSW33BDOYPLWM78U9A09BZDI |
| 506d1d0f4ed51ecc3e9cf1839a4b21a7 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/6O5KBMY42CFGLLU7L2MW4    |
| 10d51524bc007aa845e77556cdcab174 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/9MDXJ6LXOUEK84ALNT       |
| 879194e26a0ed7cf50f13c681e711c82 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/9YDGH04DC6ZS7RP0085Q     |
| 90a881ffa127b004cec6802588fce307 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/X3452I2VDTHM30QX         |
| 58c572785e542f3750b57601df612fc4 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/YX6RXMC65MRX8LLQ         |
| bab21ee475b52c0c9eb47d23ec9ba1d1 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/GDBJS76DH3D4IKQD2QO7R    |
| 28cc82fd466e0d0976a6359f264775a8 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/EBVCVJNCPM6A3NKJ         |
| 24483508bccfe72e63b26a1233058170 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/0JOA98TDMXLHJ77VDOO      |
| 04bdf8557fa74ea0e3adbd2975efd274 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/A9K0IM6DK7ILWAV908R3     |
| 64139b5d8a3f06921a9364c262989e1f | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/9BEBTCZQN6BQJ94DJXJ      |
| 5791ae39aeab40b5e8e33d8dce465877 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/LEOYRMQLSRHFGFGYWF2T5    |
| d58b3b69acc48f82eaa82076f97763d4 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/O3KTUJZRE6CB4Q1OBR       |
| b0e039b42ef6c19c2189651c9f6c390e | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/LH2WLI60XU9O283RYADW     |
| 6bed8cf959f0a07170c24bb972efd726 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/GBSLNRB4NL0OG6FX         |
| b368c1ee6bca2086d8169628466c0d3b | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/IRCWUUXN0Y4BIFFZW        |
| 14a875a2bd63041b2b3e5c323e8d5eee | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/D4MX4VGFCMO7MFQ6P        |
| d73c69209fbe768d5fa7ffbcad509c66 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/1ILW209PJZUAJJEX         |
| d0e84579a05c8e92e95eee8f5d0000e5 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/5PRYG0PCO2OW528IDWU3VFPE |
| 30f784136940874b4eb68188a3bfb246 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/24HUMRRAZYQNDJ8A         |
| 207aab0afc614ac68359fc63f9665961 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/EWX33VYY3IGOXSG5ZZ2      |
| 3e8e2ab5fbb392508535983b7446ba17 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/S2A4H6RGPHHLU1IJRLNTN    |
| 09c87c28bed23dbe6ff5aa561d38766b | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/Q0DVRYWVDUGDD22V0K7XX    |
| 6e46d36711d8be390c2b8121017ab146 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/HCWB50PNECHW5CRCQF       |
| 6e46d36711d8be390c2b8121017ab146 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/HCWB50PNECHW5CRCQF       |
| 4e591a315c54e8800dae714320555fa5 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/U6H6RKDF6W3B8XOWL        |
| 0361b6a1f37016ed147e7617a3c08300 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/QLA44XK2K4K1RZL9         |
| a77ac611487df21715d824d8ccbf3f6a | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/TMWRS0D3MP750FUKRWCVE    |
| b61fd808b57c1cab3824a887857bf6a8 | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/EXJ0CFHWOZIISIE4NG3LT    |
| 610e4366504d4d2848359d75d84ec295 | http://supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid[.]onion/Z1DHIS62B9LUNC74         |
|                                  | http://supp24maprinktc7uizgfyqhisx7lkszb6ogh6lwdzpac23w3mh4tvyd[.]onion/OERPnbmCxAOFXVsxZMyaWPGg |

## C&C

https://paymenthacks[ . ]com  
http://paymenthacks[ . ]com  
https://mojobiden[ . ]com  
http://mojobiden[ . ]com  
https://nowautomation[ . ]com  
http://nowautomation[ . ]com  
https://fluentzip[ . ]org  
http://fluentzip[ . ]org

## Выводы 

1. BlackMatter — звено между DarkSide и BlackCat**.
2. Сильные стороны: быстрая криптография, гибкость конфигурации.
3. Слабые места: слабое шифрование коммуникаций, ошибки в Salsa20.
4. Индикаторы BlackMatter до сих пор полезны для обнаружения **новых семейств**.
5. Любая крупная атака → уход в ребрендинг.

**Если вам интересно почитать ещё классный контент**, то приглашаю в свой Telegram канал [@poxek](https://t.me/+MYjDCbCNAZoxZGNi)
