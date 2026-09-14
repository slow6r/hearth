#!/usr/bin/env bash
# Ребейз форка на новый upstream-тег (ТЗ §8.1).
#
#   ./rebase-upstream.sh v6.x.y
#
# Ветка форка называется hearth/<upstream-tag>. Каждое изменение — отдельный коммит
# (см. ../patches/README.md), поэтому ребейз должен быть механическим: конфликты
# ожидаются только в точках интеграции, перечисленных в описаниях патчей.
set -euo pipefail

TAG="${1:?usage: rebase-upstream.sh <upstream-tag>}"
FORK_DIR="${FORK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../simplex-chat" && pwd)}"

cd "$FORK_DIR"

git remote get-url upstream >/dev/null 2>&1 \
    || git remote add upstream https://github.com/simplex-chat/simplex-chat.git

echo "== 1. Забираем теги upstream"
git fetch upstream --tags

echo "== 2. Проверяем подпись тега $TAG"
if git verify-tag "$TAG" 2>/dev/null; then
    echo "   подпись тега в порядке"
else
    echo "   !! тег $TAG не подписан или ключ не импортирован."
    echo "      ТЗ §6.1 требует проверенного происхождения. Продолжать только осознанно."
    read -r -p "      Продолжить? [y/N] " answer
    [[ "$answer" == "y" ]] || exit 1
fi

CURRENT="$(git rev-parse --abbrev-ref HEAD)"
NEW_BRANCH="hearth/$TAG"
echo "== 3. $CURRENT -> $NEW_BRANCH"
git switch -c "$NEW_BRANCH"

echo "== 4. Ребейз на $TAG"
if ! git rebase "$TAG"; then
    cat <<'HELP'

   Конфликт. Порядок разрешения:
     1. Открыть описание соответствующего патча в ../patches/.
     2. Перенести НАМЕРЕНИЕ на новый код upstream, а не строки.
     3. git add <файлы> && git rebase --continue

   Если конфликт в Haskell-файле — что-то пошло не так: ТЗ §8.3 запрещает
   любые изменения в Haskell. Скорее всего в форк случайно попал чужой коммит.
HELP
    exit 1
fi

echo "== 5. Проверка размера диффа (цель ТЗ §8.1: < 500 строк, Haskell — только по списку)"
git diff "$TAG..HEAD" --stat | tail -1
# Правка Haskell по-прежнему блокер, кроме файлов из списка. Каждый файл в нём
# появился по ADR (сейчас один — адрес push-сервера для iOS, docs/adr/0016). Файл,
# которого в списке нет, останавливает ребейз, как и раньше.
ALLOWLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/ios/patches/haskell-allowlist.txt"
UNLISTED="$(git diff "$TAG..HEAD" --name-only | grep '\.hs$' \
    | grep -vxF -f <(grep -v '^#' "$ALLOWLIST" | sed '/^$/d') || true)"
if [[ -n "$UNLISTED" ]]; then
    echo "!! Haskell-файлы вне $ALLOWLIST. Это блокер ревью (ТЗ §2.2, §8.3):" >&2
    printf '%s\n' "$UNLISTED" >&2
    exit 1
fi
LISTED="$(git diff "$TAG..HEAD" --name-only | grep '\.hs$' || true)"
if [[ -n "$LISTED" ]]; then
    echo "   Haskell тронут только по списку — дифф прочитать глазами:"
    git diff "$TAG..HEAD" -- $LISTED | sed 's/^/     /'
else
    echo "   Haskell не тронут."
fi

TOTAL="$(git diff "$TAG..HEAD" --numstat | awk '{added+=$1; removed+=$2} END {print added+removed}')"
echo "   Всего изменённых строк: ${TOTAL:-0} (цель < 500)"

cat <<'NEXT'

== Дальше (ТЗ §10.6)
  1. Прочитать changelog: upstream периодически режет совместимость старых версий.
  2. Собрать: ./build-release.sh
  3. ./verify-apk.sh <apk>
  4. Тестовое устройство — сутки на новой версии.
  5. Обновить simplex_chat_tag в hearthd/manifest.toml тем же коммитом.
  6. Потом релей, потом остальные клиенты.
NEXT
