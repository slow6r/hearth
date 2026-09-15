#!/usr/bin/env python3
"""Импорт наборов стикеров из Telegram в вид, который раздаёт узел.

    python stickers/import-telegram.py <набор> [<набор> ...]

Набор — короткое имя или ссылка t.me/addstickers/<имя>. Токен бота читается из
keys/admin/tg-bot.token (в git не попадает). Результат — stickers/dist/<набор>/:
NNN.webp + pack.json, и общий stickers/dist/index.json.

Что берётся, а что нет. Только статические стикеры: Telegram отдаёт их как WEBP
512×512 с прозрачностью, и приложение шлёт такой файл как есть. Анимированные (TGS —
сжатый Lottie) и видео (WEBM) пропускаются с подсчётом: для них в приложении нет
проигрывателя, а слать человеку файл, который он не увидит, хуже, чем не слать.

Только стандартная библиотека: инструмент должен запускаться на любой машине с Python,
без установки пакетов.
"""
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOKEN_FILE = os.path.join(ROOT, "keys", "admin", "tg-bot.token")
DIST = os.path.join(HERE, "dist")
NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def fail(msg):
    print("!! " + msg, file=sys.stderr)
    sys.exit(1)


def token():
    try:
        with open(TOKEN_FILE, encoding="utf-8-sig") as fh:
            return fh.read().strip()
    except OSError:
        fail("нет токена: %s" % TOKEN_FILE)


def api(tok, method, **params):
    url = "https://api.telegram.org/bot%s/%s" % (tok, method)
    data = urllib.parse.urlencode(params).encode() if params else None
    with urllib.request.urlopen(url, data=data, timeout=60) as r:
        d = json.load(r)
    if not d.get("ok"):
        # В описании ошибки токена нет; URL с токеном сюда не попадает намеренно.
        raise RuntimeError("%s: %s" % (method, d.get("description")))
    return d["result"]


def download(tok, file_path):
    url = "https://api.telegram.org/file/bot%s/%s" % (tok, file_path)
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def set_name(arg):
    m = re.search(r"addstickers/([A-Za-z0-9_]+)", arg)
    name = m.group(1) if m else arg.strip()
    if not NAME_RE.match(name):
        fail("неверное имя набора: %r" % arg)
    return name


def import_set(tok, name):
    s = api(tok, "getStickerSet", name=name)
    out = os.path.join(DIST, name.lower())
    os.makedirs(out, exist_ok=True)
    kept, skipped = [], {"animated": 0, "video": 0}
    for st in s["stickers"]:
        if st.get("is_animated"):
            skipped["animated"] += 1
            continue
        if st.get("is_video"):
            skipped["video"] += 1
            continue
        fp = api(tok, "getFile", file_id=st["file_id"])["file_path"]
        blob = download(tok, fp)
        # Telegram обещает WEBP; проверяем сигнатуру RIFF….WEBP, а не расширение.
        if not (blob[:4] == b"RIFF" and blob[8:12] == b"WEBP"):
            skipped.setdefault("not_webp", 0)
            skipped["not_webp"] += 1
            continue
        idx = len(kept) + 1
        fname = "%03d.webp" % idx
        with open(os.path.join(out, fname), "wb") as fh:
            fh.write(blob)
        kept.append({
            "file": fname,
            "emoji": st.get("emoji") or "",
            "sha256": hashlib.sha256(blob).hexdigest(),
            "bytes": len(blob),
        })
    pack = {
        "v": 1,
        "name": name.lower(),
        "title": s.get("title") or name,
        "source": "telegram:" + name,
        "stickers": kept,
    }
    with open(os.path.join(out, "pack.json"), "w", encoding="utf-8") as fh:
        json.dump(pack, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("  %-24s «%s»: взято %d, пропущено анимированных %d, видео %d%s" % (
        name, pack["title"], len(kept), skipped["animated"], skipped["video"],
        (", не-WEBP %d" % skipped["not_webp"]) if "not_webp" in skipped else ""))
    return pack


def write_index():
    packs = []
    for d in sorted(os.listdir(DIST)) if os.path.isdir(DIST) else []:
        pj = os.path.join(DIST, d, "pack.json")
        if not os.path.isfile(pj):
            continue
        with open(pj, encoding="utf-8") as fh:
            p = json.load(fh)
        if not p.get("stickers"):
            continue
        packs.append({
            "name": p["name"],
            "title": p["title"],
            "count": len(p["stickers"]),
            "cover": p["stickers"][0]["file"],
        })
    index = {"v": 1, "packs": packs}
    with open(os.path.join(DIST, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("index.json: наборов %d, стикеров %d" % (len(packs), sum(p["count"] for p in packs)))


def main(argv):
    if not argv:
        print(__doc__)
        sys.exit(2)
    tok = token()
    os.makedirs(DIST, exist_ok=True)
    print("== импорт")
    for arg in argv:
        try:
            import_set(tok, set_name(arg))
        except RuntimeError as e:
            print("  %-24s ОШИБКА: %s" % (arg, e))
    write_index()


if __name__ == "__main__":
    main(sys.argv[1:])
