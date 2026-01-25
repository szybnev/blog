---
title: "OSINT инструменты для пентеста"
date: 2026-01-23
draft: false
tags: ["osint", "pentest"]
description: "Обзор лучших инструментов для сбора разведывательной информации"
---

OSINT (Open Source Intelligence) — это сбор информации из открытых источников. Важный этап любого пентеста.

## Поиск по доменам

### theHarvester

Собирает email-адреса, поддомены и другую информацию:

```bash
theHarvester -d target.com -b google,bing,linkedin
```

### Subfinder

Быстрый поиск поддоменов:

```bash
subfinder -d target.com -o subdomains.txt
```

## Поиск по людям

### Sherlock

Поиск аккаунтов в социальных сетях по никнейму:

```bash
sherlock username
```

### Holehe

Проверка, где зарегистрирован email:

```bash
holehe test@example.com
```

## Поиск утечек

- **Have I Been Pwned** — проверка email в утечках
- **DeHashed** — поиск по базам утечек
- **Intelligence X** — архив утечек и Tor-сайтов

## Автоматизация

### SpiderFoot

Комбайн для OSINT с веб-интерфейсом:

```bash
python3 sf.py -l 127.0.0.1:5001
```

## Заключение

OSINT — это мощный инструмент, но используйте его этично и в рамках закона.
