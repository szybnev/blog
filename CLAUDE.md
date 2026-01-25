# blog.poxek

## Описание проекта

Блог о кибербезопасности на Hugo с Tailwind CSS. Размещается на GitHub Pages (blog.poxek.cc).

## Команды разработки

```bash
# Локальная разработка (два терминала)
npm run dev           # Tailwind watch-режим
./hugo server -D      # Hugo dev-сервер с черновиками

# Сборка для продакшена
npm run build                              # Tailwind minify
cp assets/css/output.css static/css/       # Копировать CSS
./hugo --gc --minify                       # Hugo сборка
```

Бинарник Hugo находится в корне репозитория (`./hugo`).

## Архитектура

### Стили

- `assets/css/main.css` — исходный Tailwind с CSS-переменными для тем
- `assets/css/output.css` → `static/css/output.css` — скомпилированный CSS
- Темная тема: класс `.dark` на `<html>`, переключение в `layouts/partials/theme-toggle.html`

### Шаблоны Hugo

```bash
layouts/
├── _default/
│   ├── baseof.html    # Базовый layout с подключением CSS/шрифтов
│   ├── list.html      # Главная + списки постов
│   └── single.html    # Отдельный пост
├── page/              # Кастомные страницы (telegram.md)
└── partials/
    ├── header.html    # Навигация
    ├── footer.html    # Подвал с соцсетями
    ├── card.html      # Карточка поста
    └── theme-toggle.html
```

### Контент

- `content/post/*/index.md` — посты с frontmatter (title, date, tags, image, description)
- `content/telegram.md` — статическая страница с layout: telegram

### Конфигурация

- `hugo.toml` — настройки сайта, меню, параметры Telegram-каналов
- `tailwind.config.js` — typography plugin, цвета primary/accent

## CI/CD

GitHub Actions (`.github/workflows/hugo.yaml`):

1. npm ci → npm run build
2. cp assets/css/output.css static/css/
3. hugo --gc --minify
4. Deploy to GitHub Pages
