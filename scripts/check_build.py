"""Проверка основных страниц после сборки Hugo."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

public = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("public")
home = (public / "index.html").read_text(encoding="utf-8")
assert "/post/" in home, "На главной отсутствуют ссылки на статьи"
assert "Все теги" in (public / "tags/index.html").read_text(encoding="utf-8")

posts = list((public / "post").glob("*/index.html"))
assert posts, "Статьи не собраны"
for post in posts:
    assert "<article" in post.read_text(encoding="utf-8"), post

telegram = (public / "telegram/index.html").read_text(encoding="utf-8")
for text in ("@poxek", "@poxek_ai", "@poxek_event", "@poxek_meme", "Присоединяйтесь к сообществу!"):
    assert text in telegram, f"На странице Telegram отсутствует: {text}"

assert (public / "css/output.css").stat().st_size > 0, "CSS пуст"

feed = ET.parse(public / "index.xml").getroot()
items = feed.findall("./channel/item")
assert items, "RSS-лента пуста"
assert len(items) == len(posts), "RSS содержит не все статьи или лишние страницы"
assert all(urlparse(item.findtext("link", "")).scheme == "https" and "/post/" in urlparse(item.findtext("link", "")).path for item in items), "RSS содержит не статью блога"
assert "rel=alternate" in home and "application/rss+xml" in home and "index.xml" in home, "На главной отсутствует RSS autodiscovery"
assert "index.xml" in home and ">RSS</a>" in home, "На главной отсутствует ссылка на RSS"
print(f"Проверены главная, теги, Telegram, CSS, RSS и {len(posts)} статей")
