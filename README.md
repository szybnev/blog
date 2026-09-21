# blog.poxek

Блог о кибербезопасности, пентесте и хакинге.

**Сайт:** <https://blog.poxek.cc>

## Технологии

- [Hugo](https://gohugo.io/) — генератор статических сайтов
- [Tailwind CSS 4](https://tailwindcss.com/) — стили
- GitHub Pages — хостинг

## Разработка

Требуются Node.js 24 LTS и Hugo Extended 0.166.0 (бинарник `./hugo`).

```bash
# Установка зависимостей
npm ci

# Запуск (два терминала)
npm run dev           # Tailwind watch
./hugo server -D      # Hugo сервер
```

## Сборка

```bash
npm run build
cp assets/css/output.css static/css/
./hugo --gc --minify
python3 scripts/check_build.py
```

Результат в папке `public/`.

## Структура

```bash
content/post/   — статьи блога
layouts/        — шаблоны Hugo
assets/css/     — исходные стили Tailwind
static/         — статические файлы (шрифты, иконки, изображения)
```

## Деплой

Автоматический через GitHub Actions при пуше в `main`.
