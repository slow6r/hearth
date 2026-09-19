#!/usr/bin/env bash
# Выгрузка исходников узла для чтения аудитором (SRC-1).
#
#   hearthd/deploy/publish-src.sh [каталог назначения]
#
# ГДЕ ЗАПУСКАТЬ. На рабочей станции, в клоне репозитория. НЕ на узле: узлу git не
# нужен и не будет.
#
# ЗАЧЕМ. На fels лежал /srv/hearth/src — копия рабочего дерева, положенная руками, без
# .git. Аудитор читал оттуда 14091 файл и не мог сказать ни какому коммиту они
# соответствуют, ни правил ли их кто-то после копирования: контрольных сумм рядом не
# было. Вывод «секретов там нет» был верен для проверенного состояния и переставал
# быть верным при следующем копировании: `cp -r` не отличает keys/admin/owner.key от
# исходника.
#
# ЧТО ЗДЕСЬ ДЕЛАЕТСЯ ИНАЧЕ.
#   1. Гейт чистоты дерева — тот же, что у релизной сборки Android. Выгружать
#      изменённое дерево нечего: его не с чем сопоставить.
#   2. `git archive` вместо `cp -r`. В архив попадают ТОЛЬКО отслеживаемые файлы,
#      поэтому keys/admin/*, target/ и .env не попадают туда физически, а не по
#      договорённости с тем, кто копировал.
#   3. Рядом кладётся манифест: коммит, tree_sha256 (тот же, что печатает
#      `hearthd build-info`), sha256 архива и опись всех файлов с хешами.
#
# ЧТО ЭТО ДОКАЗЫВАЕТ. Что выгрузка — это ровно коммит X. Проверка аудитором сводится к
# одной сверке tree_sha256 с выводом `hearthd build-info` на узле, и git ему для этого
# не нужен.
#
# ЧЕГО НЕ ДОКАЗЫВАЕТ. Что в коммите X нет закладки. Это доказывается чтением кода —
# ради него выгрузка и делается.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$REPO/dist/src}"

# sha256sum на Linux, shasum -a 256 на macOS.
if command -v sha256sum >/dev/null 2>&1; then
    SUM=(sha256sum)
else
    SUM=(shasum -a 256)
fi

cd "$REPO"

git rev-parse --git-dir >/dev/null 2>&1 || {
    echo "$REPO не git-репозиторий: выгружать нечего — сопоставить её будет не с чем" >&2
    exit 1
}

DIRTY="$(git status --porcelain)"
if [ -n "$DIRTY" ]; then
    echo "== рабочее дерево изменено:" >&2
    printf '%s\n' "$DIRTY" >&2
    echo >&2
    echo "Выгрузка из изменённого дерева бессмысленна: аудитор сверит tree_sha256 с" >&2
    echo "узлом и получит расхождение, причину которого восстановить будет нечем." >&2
    echo "Закоммитьте изменения и повторите." >&2
    exit 1
fi

COMMIT="$(git rev-parse HEAD)"
PREFIX="hearth-$COMMIT"
mkdir -p "$OUT"
ARCHIVE="$OUT/hearth-src-$COMMIT.tar.gz"
MANIFEST="$OUT/hearth-src-$COMMIT.manifest.txt"

echo "== 1. архив отслеживаемых файлов коммита $COMMIT"
# --format=tar.gz детерминирован по содержимому: время файлов берётся из коммита.
git archive --format=tar.gz --prefix="$PREFIX/" "$COMMIT" > "$ARCHIVE"

echo "== 2. проверка исключений"
# Не «мы уверены, что их там нет», а проверка. Дешёвая, и ловит тот случай, ради
# которого всё затевалось: закоммиченный по недосмотру ключ.
LEAKED="$(tar tzf "$ARCHIVE" | grep -E '(^|/)(keys/|\.env$)|\.(jks|pass|key|keystore|p8|p12)$' || true)"
if [ -n "$LEAKED" ]; then
    echo "В архив попало то, чего там быть не должно:" >&2
    printf '%s\n' "$LEAKED" >&2
    echo "Это значит, что файл ОТСЛЕЖИВАЕТСЯ git. Разбирайтесь с этим, а не с архивом." >&2
    rm -f "$ARCHIVE"
    exit 1
fi
echo "   ключей и секретов в архиве нет"

echo "== 3. манифест"
# tree_sha256 считается ровно так же, как его считает hearthd/build.rs: по
# нормализованному git'ом содержимому рабочих файлов. Совпадение этих двух чисел и
# есть доказательство «выгрузка — это то, из чего собран работающий демон».
TREE_PATHS="hearthd/src hearthd/build.rs hearthd/Cargo.toml hearthd/Cargo.lock hearthd/rust-toolchain.toml"
# shellcheck disable=SC2086
TREE_SHA256="$(git ls-files -- $TREE_PATHS \
    | LC_ALL=C sort \
    | while read -r p; do printf '%s\0%s\0' "$p" "$(git hash-object "$p")"; done \
    | "${SUM[@]}" | cut -d' ' -f1)"

{
    echo "commit=$COMMIT"
    echo "committed_at=$(git log -1 --format=%cI "$COMMIT")"
    echo "tree_sha256=$TREE_SHA256"
    echo "archive=$(basename "$ARCHIVE")"
    echo "archive_sha256=$("${SUM[@]}" "$ARCHIVE" | cut -d' ' -f1)"
    echo "files=$(git ls-files | wc -l | tr -d ' ')"
    echo
    echo "# опись: <sha256 содержимого по git> <путь>"
    git ls-files | LC_ALL=C sort | while read -r p; do
        printf '%s %s\n' "$(git hash-object "$p")" "$p"
    done
} > "$MANIFEST"

echo "   $MANIFEST"
head -6 "$MANIFEST"

cat <<NEXT

== раскладка на узле (выполняет владелец, root)

   Каталог с коммитом в имени — чтобы выгрузки не перезаписывали друг друга и было
   видно, что именно читает аудитор:

     install -d -m 0755 -o root -g root /srv/hearth/src-$COMMIT
     tar xzf $(basename "$ARCHIVE") -C /srv/hearth/src-$COMMIT --strip-components=1
     cp $(basename "$MANIFEST") /srv/hearth/src-$COMMIT/
     chown -R root:root /srv/hearth/src-$COMMIT
     find /srv/hearth/src-$COMMIT -type d -exec chmod 0755 {} +
     find /srv/hearth/src-$COMMIT -type f -exec chmod 0644 {} +
     setfacl -R -m u:auditor:rX /srv/hearth/src-$COMMIT

   Владелец root, а не fels:fels и не hearth: читать это должны все, менять — никто,
   включая демона. Прежний /srv/hearth/src (копия рабочего дерева без .git) после
   этого убрать: две выгрузки рядом — это вопрос «а какая из них настоящая».

== проверка аудитором (git на узле не нужен)

   1. Хеш дерева, из которого собран работающий демон:
        hearthd build-info | grep tree_sha256
   2. Он же в манифесте выгрузки:
        grep tree_sha256 /srv/hearth/src-$COMMIT/$(basename "$MANIFEST")
   3. Совпали — значит читаемые исходники и есть исходники работающего файла.
      Не совпали — демон собран не из этой выгрузки, и дальше читать её незачем.

NEXT
