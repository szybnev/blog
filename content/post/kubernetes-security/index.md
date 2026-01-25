---
title: "Безопасность Kubernetes: полное руководство"
date: 2026-01-25
draft: false
tags: ["kubernetes", "docker", "pentest"]
description: "Разбираемся с основными уязвимостями Kubernetes и методами их эксплуатации"
---

Kubernetes стал стандартом де-факто для оркестрации контейнеров, но с его популярностью растёт и количество атак на кластеры.

## Основные векторы атак

### 1. Неправильно настроенный RBAC

RBAC (Role-Based Access Control) — это первая линия обороны в Kubernetes. Часто встречаются следующие ошибки:

```yaml
# Плохо: слишком широкие права
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

### 2. Открытый API Server

Никогда не выставляйте API Server в интернет без аутентификации:

```bash
# Проверка доступности API
curl -k https://kubernetes-api:6443/api/v1/pods
```

### 3. Escape из контейнера

Если контейнер запущен с privileged: true, атакующий может выйти на хост:

```bash
# Монтирование файловой системы хоста
mount /dev/sda1 /mnt
chroot /mnt
```

## Инструменты для аудита

- **kube-bench** — проверка соответствия CIS Benchmark
- **trivy** — сканирование образов на уязвимости
- **falco** — runtime-детекция аномалий

## Заключение

Безопасность Kubernetes требует комплексного подхода: от правильной настройки RBAC до мониторинга в runtime.
